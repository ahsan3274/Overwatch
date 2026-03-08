#!/usr/bin/env python3
"""
Overwatch Alerter Daemon
Watches scored_events.jsonl for flagged events and sends alerts via:
- macOS native notifications
- Terminal notifications (inline)
- Slack webhooks
- Discord webhooks
- Email (SMTP)

Runs continuously in background, tracks already-alerted events.
"""

import json
import os
import sys
import time
import hashlib
import logging
import subprocess
import smtplib
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Try to import yaml for config (optional)
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# Try to import requests for webhooks (optional)
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ── Config ────────────────────────────────────────────────────────────────────

BASE_DIR = Path.home() / "velociraptor-triage"
SCORED_LOG = BASE_DIR / "scored_events.jsonl"
ALERT_LOG = BASE_DIR / "alerts.log"
ALERT_STATE = BASE_DIR / "alert_state.json"
CONFIG_FILE = BASE_DIR / "alert_config.yaml"
LOCK_FILE = BASE_DIR / "alerter.lock"
ALERTER_POSITION = BASE_DIR / "alerter_position.json"  # Track file read position

POLL_INTERVAL_SEC = 5  # Check for new events every 5 seconds

# ── Logging ────────────────────────────────────────────────────────────────────

log = logging.getLogger("alerter_daemon")


def configure_logging():
    """Configure logging handlers."""
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    
    log.setLevel(logging.INFO)
    log.handlers.clear()
    
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    
    # File handler
    file_handler = logging.FileHandler(ALERT_LOG)
    file_handler.setFormatter(formatter)
    log.addHandler(file_handler)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    log.addHandler(console_handler)


# ── Configuration ─────────────────────────────────────────────────────────────

DEFAULT_CONFIG = {
    "channels": {
        "macos_notification": True,
        "terminal": True,
        "slack": False,
        "discord": False,
        "email": False,
    },
    "slack": {
        "webhook_url": "",
        "channel": "#security-alerts",
        "username": "Overwatch",
    },
    "discord": {
        "webhook_url": "",
        "username": "Overwatch",
    },
    "email": {
        "smtp_server": "smtp.gmail.com",
        "smtp_port": 587,
        "username": "",
        "password": "",
        "from_addr": "",
        "to_addrs": [],
        "use_tls": True,
    },
    "thresholds": {
        "min_risk_score": 7,  # Only alert for events >= this score
        "alert_on_levels": ["HIGH", "CRITICAL"],
    },
}


def load_config() -> dict:
    """Load alert configuration from YAML file."""
    if not CONFIG_FILE.exists():
        log.warning(f"Config not found, creating default at {CONFIG_FILE}")
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG
    
    if not HAS_YAML:
        log.error("PyYAML not installed. Using default config.")
        return DEFAULT_CONFIG
    
    try:
        with open(CONFIG_FILE) as f:
            config = yaml.safe_load(f)
        
        # Merge with defaults for any missing keys
        merged = DEFAULT_CONFIG.copy()
        if config:
            for key, value in config.items():
                if isinstance(value, dict) and key in merged:
                    merged[key].update(value)
                else:
                    merged[key] = value
        return merged
    except Exception as e:
        log.error(f"Failed to load config: {e}")
        return DEFAULT_CONFIG


def save_config(config: dict):
    """Save configuration to YAML file."""
    if not HAS_YAML:
        log.error("PyYAML not installed. Cannot save config.")
        # Fallback: write JSON
        with open(CONFIG_FILE.with_suffix('.json'), 'w') as f:
            json.dump(config, f, indent=2)
        return
    
    with open(CONFIG_FILE, 'w') as f:
        yaml.safe_dump(config, f, default_flow_style=False, sort_keys=False)


# ── Alert State Tracking ──────────────────────────────────────────────────────

def load_alert_state() -> set:
    """Load set of already-alerted event fingerprints."""
    if not ALERT_STATE.exists():
        return set()
    try:
        with open(ALERT_STATE) as f:
            return set(line.strip() for line in f if line.strip())
    except Exception:
        return set()


def save_alert_state(fingerprints: set):
    """Save alerted fingerprints to state file."""
    with open(ALERT_STATE, 'w') as f:
        for fp in fingerprints:
            f.write(fp + "\n")


def event_fingerprint(event: dict) -> str:
    """Create unique fingerprint for an event."""
    original = event.get("original_event", {})
    key = f"{original.get('source', '')}{original.get('event_type', '')}{original.get('path', '')}{original.get('timestamp', '')}"
    return hashlib.md5(key.encode()).hexdigest()


# ── Notification Channels ─────────────────────────────────────────────────────

def send_macos_notification(title: str, message: str, urgency: str = "high"):
    """Send macOS native notification using osascript."""
    try:
        # Map urgency to notification urgency
        if urgency == "critical":
            sound = "Glass"
        elif urgency == "high":
            sound = "Hero"
        else:
            sound = "Ping"
        
        script = f'''
        display notification "{message}" with title "{title}" sound name "{sound}"
        '''
        
        subprocess.run(
            ["osascript", "-e", script],
            capture_output=True,
            timeout=5
        )
        log.info(f"✅ macOS notification sent: {title}")
        return True
    except Exception as e:
        log.error(f"Failed to send macOS notification: {e}")
        return False


def send_terminal_notification(title: str, message: str, assessment: dict):
    """Print formatted alert to terminal."""
    risk_score = assessment.get("risk_score", 0)
    risk_level = assessment.get("risk_level", "UNKNOWN")
    category = assessment.get("category", "unknown")
    
    # Color codes for terminal
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    RESET = "\033[0m"
    BOLD = "\033[1m"
    
    color = RED if risk_score >= 8 else YELLOW if risk_score >= 5 else GREEN
    
    print(f"\n{BOLD}{color}🚨 OVERWATCH ALERT 🚨{RESET}")
    print(f"{BOLD}Title:{RESET} {title}")
    print(f"{BOLD}Message:{RESET} {message}")
    print(f"{BOLD}Risk:{RESET} {color}{risk_score}/10 - {risk_level}{RESET}")
    print(f"{BOLD}Category:{RESET} {category}")
    print(f"{BOLD}Time:{RESET} {datetime.now(timezone.utc).isoformat()}")
    print("-" * 60)
    
    log.info(f"✅ Terminal notification sent: {title}")
    return True


def send_slack_alert(title: str, message: str, assessment: dict, config: dict):
    """Send alert to Slack via webhook."""
    if not HAS_REQUESTS:
        log.error("requests not installed. Cannot send Slack alert.")
        return False
    
    webhook_url = config.get("slack", {}).get("webhook_url", "")
    if not webhook_url:
        log.warning("Slack webhook URL not configured")
        return False
    
    risk_score = assessment.get("risk_score", 0)
    risk_level = assessment.get("risk_level", "UNKNOWN")
    category = assessment.get("category", "unknown")
    explanation = assessment.get("explanation", "")
    action = assessment.get("recommended_action", "")
    
    # Color based on risk
    if risk_score >= 8:
        color = "#ff0000"  # Red
    elif risk_score >= 5:
        color = "#ffa500"  # Orange
    else:
        color = "#ffff00"  # Yellow
    
    payload = {
        "channel": config.get("slack", {}).get("channel", "#security-alerts"),
        "username": config.get("slack", {}).get("username", "Overwatch"),
        "icon_emoji": ":shield:",
        "attachments": [
            {
                "color": color,
                "title": title,
                "text": message,
                "fields": [
                    {"title": "Risk Score", "value": f"{risk_score}/10", "short": True},
                    {"title": "Risk Level", "value": risk_level, "short": True},
                    {"title": "Category", "value": category, "short": True},
                    {"title": "Explanation", "value": explanation, "short": False},
                    {"title": "Recommended Action", "value": action, "short": False},
                ],
                "footer": "Overwatch Security Triage",
                "ts": int(time.time()),
            }
        ],
    }
    
    try:
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            log.info(f"✅ Slack alert sent")
            return True
    except Exception as e:
        log.error(f"Failed to send Slack alert: {e}")
        return False


def send_discord_alert(title: str, message: str, assessment: dict, config: dict):
    """Send alert to Discord via webhook."""
    if not HAS_REQUESTS:
        log.error("requests not installed. Cannot send Discord alert.")
        return False
    
    webhook_url = config.get("discord", {}).get("webhook_url", "")
    if not webhook_url:
        log.warning("Discord webhook URL not configured")
        return False
    
    risk_score = assessment.get("risk_score", 0)
    risk_level = assessment.get("risk_level", "UNKNOWN")
    category = assessment.get("category", "unknown")
    explanation = assessment.get("explanation", "")
    action = assessment.get("recommended_action", "")
    
    # Color based on risk
    if risk_score >= 8:
        color = 0xff0000  # Red
    elif risk_score >= 5:
        color = 0xffa500  # Orange
    else:
        color = 0xffff00  # Yellow
    
    payload = {
        "username": config.get("discord", {}).get("username", "Overwatch"),
        "avatar_url": "https://example.com/shield-icon.png",
        "embeds": [
            {
                "title": title,
                "description": message,
                "color": color,
                "fields": [
                    {"name": "Risk Score", "value": f"{risk_score}/10", "inline": True},
                    {"name": "Risk Level", "value": risk_level, "inline": True},
                    {"name": "Category", "value": category, "inline": True},
                    {"name": "Explanation", "value": explanation, "inline": False},
                    {"name": "Recommended Action", "value": action, "inline": False},
                ],
                "footer": {
                    "text": "Overwatch Security Triage",
                    "icon_url": "https://example.com/shield-icon.png",
                },
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ],
    }
    
    try:
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            log.info(f"✅ Discord alert sent")
            return True
    except Exception as e:
        log.error(f"Failed to send Discord alert: {e}")
        return False


def send_email_alert(title: str, message: str, assessment: dict, config: dict):
    """Send alert via email using SMTP."""
    email_config = config.get("email", {})
    
    if not email_config.get("username") or not email_config.get("password"):
        log.warning("Email credentials not configured")
        return False
    
    if not email_config.get("to_addrs"):
        log.warning("No email recipients configured")
        return False
    
    risk_score = assessment.get("risk_score", 0)
    risk_level = assessment.get("risk_level", "UNKNOWN")
    category = assessment.get("category", "unknown")
    explanation = assessment.get("explanation", "")
    action = assessment.get("recommended_action", "")
    
    # Build email
    msg = MIMEMultipart()
    msg['From'] = email_config.get("from_addr", email_config.get("username"))
    msg['To'] = ", ".join(email_config.get("to_addrs", []))
    msg['Subject'] = f"🚨 Overwatch Alert: {risk_level} ({risk_score}/10) - {category}"
    
    body = f"""
OVERWATCH SECURITY ALERT
========================

{title}

{message}

RISK ASSESSMENT
---------------
Risk Score:     {risk_score}/10
Risk Level:     {risk_level}
Category:       {category}
Timestamp:      {datetime.now(timezone.utc).isoformat()}

EXPLANATION
-----------
{explanation}

RECOMMENDED ACTION
------------------
{action}

---
Overwatch Security Triage System
"""
    
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        if email_config.get("use_tls", True):
            server = smtplib.SMTP(email_config.get("smtp_server"), email_config.get("smtp_port", 587))
            server.starttls()
        else:
            server = smtplib.SMTP(email_config.get("smtp_server"), email_config.get("smtp_port", 25))
        
        server.login(email_config.get("username"), email_config.get("password"))
        server.sendmail(
            email_config.get("from_addr", email_config.get("username")),
            email_config.get("to_addrs", []),
            msg.as_string()
        )
        server.quit()
        
        log.info(f"✅ Email alert sent to {email_config.get('to_addrs', [])}")
        return True
    except Exception as e:
        log.error(f"Failed to send email alert: {e}")
        return False


# ── Main Alert Dispatcher ─────────────────────────────────────────────────────

def should_alert(assessment: dict, config: dict) -> bool:
    """Check if event meets alerting thresholds."""
    risk_score = assessment.get("risk_score", 0)
    risk_level = assessment.get("risk_level", "")
    
    thresholds = config.get("thresholds", {})
    min_score = thresholds.get("min_risk_score", 7)
    allowed_levels = thresholds.get("alert_on_levels", ["HIGH", "CRITICAL"])
    
    if risk_score < min_score:
        return False
    
    if risk_level not in allowed_levels:
        return False
    
    return True


def send_alert(scored_event: dict, config: dict):
    """Dispatch alert through all configured channels."""
    assessment = scored_event.get("assessment", {})
    original = scored_event.get("original_event", {})
    flagged = scored_event.get("flagged", False)
    
    if not flagged:
        return
    
    if not should_alert(assessment, config):
        log.info(f"Event below alert threshold (score: {assessment.get('risk_score', 0)})")
        return
    
    # Build alert message
    source = original.get("source", "unknown")
    event_type = original.get("event_type", "unknown")
    path = original.get("path", "unknown")
    process = original.get("process", "unknown")
    
    title = f"🚨 {assessment.get('risk_level', 'ALERT')}: {assessment.get('category', 'Unknown Threat')}"
    message = f"{source} detected {event_type}\nPath: {path}\nProcess: {process}"
    
    risk_score = assessment.get("risk_score", 0)
    urgency = "critical" if risk_score >= 9 else "high" if risk_score >= 7 else "normal"
    
    channels = config.get("channels", {})
    
    # Send through each enabled channel
    if channels.get("terminal"):
        send_terminal_notification(title, message, assessment)
    
    if channels.get("macos_notification"):
        send_macos_notification(title, message, urgency)
    
    if channels.get("slack"):
        send_slack_alert(title, message, assessment, config)
    
    if channels.get("discord"):
        send_discord_alert(title, message, assessment, config)
    
    if channels.get("email"):
        send_email_alert(title, message, assessment, config)


def process_scored_log():
    """Read scored log and alert on new flagged events.
    
    Uses file position tracking to only read new lines since last check.
    """
    if not SCORED_LOG.exists():
        return

    alerted = load_alert_state()
    config = load_config()
    
    # Get last read position
    position = 0
    if ALERTER_POSITION.exists():
        try:
            with open(ALERTER_POSITION) as f:
                position = json.load(f).get("position", 0)
        except (json.JSONDecodeError, IOError):
            position = 0
    
    # Check if file was truncated/rotated
    try:
        file_size = SCORED_LOG.stat().st_size
        if position > file_size:
            log.info("Log file was truncated, reading from start")
            position = 0
    except OSError:
        return
    
    # Read only new lines
    with open(SCORED_LOG) as f:
        f.seek(position)
        new_lines = f.readlines()
        new_position = f.tell()
    
    if not new_lines:
        return
    
    log.debug(f"Processing {len(new_lines)} new lines from scored log")
    
    for line in new_lines:
        line = line.strip()
        if not line:
            continue

        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            log.warning(f"Malformed JSON in scored log: {line[:80]}")
            continue

        fp = event_fingerprint(event)
        if fp in alerted:
            continue

        assessment = event.get("assessment", {})
        should_send = False

        # Alert if flagged (meets threshold)
        if event.get("flagged"):
            should_send = True

        # Also alert on CRITICAL regardless of flagged status
        if assessment.get("risk_level") == "CRITICAL":
            should_send = True

        if should_send:
            send_alert(event, config)
            alerted.add(fp)
    
    # Save state
    save_alert_state(alerted)
    
    # Save position
    try:
        with open(ALERTER_POSITION, 'w') as f:
            json.dump({"position": new_position}, f)
    except IOError as e:
        log.warning(f"Failed to save position: {e}")


# ── Lock File Management ──────────────────────────────────────────────────────

def acquire_lock() -> bool:
    """Acquire lock file using atomic O_CREAT|O_EXCL to prevent race conditions."""
    try:
        fd = os.open(str(LOCK_FILE), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
        return True
    except FileExistsError:
        if LOCK_FILE.exists():
            try:
                age = time.time() - LOCK_FILE.stat().st_mtime
                if age < 300:
                    log.warning("Another alerter instance running. Exiting.")
                    return False
                log.warning("Stale lock removed.")
                LOCK_FILE.unlink()
                return acquire_lock()
            except (OSError, FileNotFoundError):
                return False
        return False


def release_lock():
    """Release the lock file."""
    if LOCK_FILE.exists():
        LOCK_FILE.unlink()


# ── Main Entry Point ──────────────────────────────────────────────────────────

def main():
    """Main entry point for alerter daemon."""
    configure_logging()
    
    log.info("=" * 60)
    log.info("Overwatch Alerter Daemon starting...")
    log.info(f"Watching: {SCORED_LOG}")
    log.info(f"Poll interval: {POLL_INTERVAL_SEC}s")
    
    # Load and display config
    config = load_config()
    enabled = [k for k, v in config.get("channels", {}).items() if v]
    log.info(f"Enabled channels: {', '.join(enabled) if enabled else 'none'}")
    
    if not enabled:
        log.warning("No alert channels enabled! Check alert_config.yaml")
    
    # Acquire lock
    if not acquire_lock():
        log.error("Failed to acquire lock. Exiting.")
        sys.exit(1)
    
    log.info("Lock acquired. Starting watch loop...")
    
    try:
        while True:
            process_scored_log()
            time.sleep(POLL_INTERVAL_SEC)
    except KeyboardInterrupt:
        log.info("Received shutdown signal. Stopping...")
    except Exception as e:
        log.error(f"Unexpected error: {e}")
    finally:
        release_lock()
        log.info("Alerter daemon stopped.")


if __name__ == "__main__":
    main()
