#!/usr/bin/env python3
"""
Velociraptor + FileMonitor + ProcessMonitor → LM Studio Triage Daemon
Reads queued events from all sources, scores via RedSage on LM Studio.
Designed to run as a scheduled launchd job every 10 minutes.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import hashlib
import logging
import subprocess
import requests
from datetime import datetime, timezone
from pathlib import Path

# Try to import psutil for better system monitoring (optional)
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# ── Config ────────────────────────────────────────────────────────────────────

LM_STUDIO_URL  = "http://localhost:1234/v1/chat/completions"
MODEL_NAME     = "redsage-qwen3-8b-dpo"   # match exactly what LM Studio shows

BASE_DIR       = Path.home() / "velociraptor-triage"
EVENT_QUEUE    = BASE_DIR / "event_queue.jsonl"
SCORED_LOG     = BASE_DIR / "scored_events.jsonl"
PROCESSED_LOG  = BASE_DIR / "processed.jsonl"
DEDUP_CACHE    = BASE_DIR / "dedup_cache.jsonl"
LOCK_FILE      = BASE_DIR / "triage.lock"
LOG_FILE       = BASE_DIR / "triage_daemon.log"
LAST_RUN_FILE  = BASE_DIR / "last_run.json"  # Track last successful run time

MAX_EVENTS_PER_RUN  = 40      # Reduced for M1 16GB (fits in 10-min window)
REQUEST_TIMEOUT_SEC = 90      # Increased for slower events
RISK_THRESHOLD      = 7       # >= this score triggers HIGH flag
DEDUP_WINDOW_SEC    = 300     # ignore duplicate events within 5 minutes

# ── LM Studio CLI ─────────────────────────────────────────────────────────────

LM_STUDIO_CLI = "lms"  # LM Studio CLI command
LM_STUDIO_MODEL = MODEL_NAME
LM_STUDIO_STARTUP_TIMEOUT = 30  # Max seconds to wait for LM Studio to start

# ── Intelligent Scheduling ────────────────────────────────────────────────────

# System load thresholds (0-100 scale)
LOAD_THRESHOLD_PROCESS = 40    # Start processing if load < this
LOAD_THRESHOLD_DEFER = 70      # Defer if load > this
MAX_DEFER_TIME_SEC = 1800      # Max defer time (30 min) - forces processing
MIN_IDLE_TIME_SEC = 120        # User must be idle for at least this long

# Dynamic batch sizing
BATCH_MIN = 10                 # Minimum events per run
BATCH_MAX = 60                 # Maximum events per run
BATCH_BASE = 40                # Base batch size for M1 16GB

# Resource thresholds
RAM_MIN_FREE_GB = 4            # Need at least this much free RAM
CPU_MAX_PERCENT = 50           # Don't process if CPU > this

# ── Logging ───────────────────────────────────────────────────────────────────
# Note: Logging is configured in configure_logging() after directory exists
# logging.basicConfig() only works on first call, so we configure it once in main()

log = logging.getLogger("triage_daemon")  # Named logger, configured in main()


def configure_logging():
    """Configure logging handlers. Call once after BASE_DIR exists."""
    # Ensure directory exists
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    
    # Clear any existing handlers
    log.handlers.clear()
    log.setLevel(logging.INFO)
    
    # Create formatter
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    
    # File handler
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setFormatter(formatter)
    log.addHandler(file_handler)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    log.addHandler(console_handler)

# ── System Activity Monitoring ────────────────────────────────────────────────

def get_cpu_usage() -> float:
    """Get current CPU usage percentage."""
    if HAS_PSUTIL:
        return psutil.cpu_percent(interval=0.5)
    else:
        # Fallback: use top command
        try:
            result = subprocess.run(
                ["top", "-l", "1", "-n", "0"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                if "CPU usage:" in line:
                    # Parse "CPU usage: 15.23% user, 5.12% sys, 79.65% idle"
                    parts = line.split(",")
                    if len(parts) >= 3:
                        user = float(parts[0].split("%")[0].split(":")[1].strip())
                        sys_cpu = float(parts[1].split("%")[0].split(":")[1].strip())
                        return user + sys_cpu
        except (subprocess.SubprocessError, ValueError, IndexError):
            pass
        return 50.0  # Default assumption


def get_memory_usage() -> dict:
    """Get memory usage info."""
    if HAS_PSUTIL:
        mem = psutil.virtual_memory()
        return {
            "total_gb": mem.total / (1024**3),
            "available_gb": mem.available / (1024**3),
            "used_percent": mem.percent,
        }
    else:
        # Fallback: use vm_stat on macOS
        try:
            result = subprocess.run(
                ["vm_stat"],
                capture_output=True, text=True, timeout=5
            )
            page_size = 4096  # macOS default
            pages = {}
            for line in result.stdout.split("\n"):
                if ":" in line:
                    key, val = line.split(":")
                    pages[key.strip()] = int(val.strip().rstrip("."))
            
            total = pages.get("Pages active", 0) + pages.get("Pages inactive", 0) + \
                    pages.get("Pages speculative", 0) + pages.get("Pages wired down", 0)
            available = pages.get("Pages inactive", 0) + pages.get("Pages free", 0)
            
            return {
                "total_gb": (total * page_size) / (1024**3),
                "available_gb": (available * page_size) / (1024**3),
                "used_percent": 100 - (available / max(total, 1) * 100),
            }
        except (subprocess.SubprocessError, ValueError, KeyError):
            return {"total_gb": 16, "available_gb": 8, "used_percent": 50}


def get_user_idle_time() -> float:
    """Get seconds since last user activity (keyboard/mouse)."""
    try:
        # Use ioreg to get idle time on macOS
        result = subprocess.run(
            ["ioreg", "-c", "IOHIDSystem"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.split("\n"):
            if "HIDIdleTime" in line:
                # Parse "HIDIdleTime" = 123456789000 (nanoseconds)
                idle_ns = int(line.split("=")[1].strip())
                return idle_ns / 1e9  # Convert to seconds
    except (subprocess.SubprocessError, ValueError, IndexError):
        pass
    
    # Fallback: assume active if we can't determine
    return 0


def get_foreground_app() -> str:
    """Get the name of the current foreground application."""
    try:
        result = subprocess.run(
            ["osascript", "-e", 'tell application "System Events" to get name of first application process whose frontmost is true'],
            capture_output=True, text=True, timeout=3
        )
        return result.stdout.strip()
    except (subprocess.SubprocessError, FileNotFoundError):
        return "unknown"


def is_user_in_fullscreen() -> bool:
    """Check if user is likely in a fullscreen app (video, presentation, etc.)."""
    fullscreen_apps = [
        "Zoom", "Teams", "Webex", "Meet",  # Video calls
        "QuickTime Player", "VLC", "IINA",  # Video players
        "Keynote", "PowerPoint",  # Presentations
        "Steam", "Epic Games",  # Games
    ]
    foreground = get_foreground_app()
    return any(app.lower() in foreground.lower() for app in fullscreen_apps)


def calculate_system_load() -> dict:
    """
    Calculate overall system load score (0-100).
    Higher = busier system, should defer processing.
    """
    cpu = get_cpu_usage()
    mem = get_memory_usage()
    idle_time = get_user_idle_time()
    in_fullscreen = is_user_in_fullscreen()
    foreground_app = get_foreground_app()  # Call once, reuse

    # CPU component (0-40 points)
    cpu_score = min(cpu * 0.4, 40)

    # Memory component (0-30 points)
    mem_score = min(mem["used_percent"] * 0.3, 30)

    # User activity component (0-30 points)
    if idle_time < 30:
        activity_score = 30  # Very active
    elif idle_time < 120:
        activity_score = 20  # Somewhat active
    elif idle_time < 300:
        activity_score = 10  # Lightly active
    else:
        activity_score = 0  # Idle

    # Fullscreen penalty (+20 if in fullscreen app)
    fullscreen_penalty = 20 if in_fullscreen else 0

    total_score = cpu_score + mem_score + activity_score + fullscreen_penalty

    return {
        "score": min(total_score, 100),
        "cpu_percent": cpu,
        "mem_available_gb": mem["available_gb"],
        "mem_used_percent": mem["used_percent"],
        "idle_time_sec": idle_time,
        "foreground_app": foreground_app,
        "in_fullscreen": in_fullscreen,
    }


def should_process_events(last_run_time: float = None) -> tuple[bool, str]:
    """
    Determine if we should process events now or defer.
    Returns (should_process, reason).
    
    Check order:
    1. Max defer time (forces processing regardless of load)
    2. Critical resources (RAM)
    3. User activity (fullscreen, idle time)
    4. Overall load score
    """
    load = calculate_system_load()

    log.info(f"System load: {load['score']:.0f}/100 "
             f"(CPU: {load['cpu_percent']:.0f}%, "
             f"RAM: {load['mem_available_gb']:.1f}GB free, "
             f"idle: {load['idle_time_sec']:.0f}s, "
             f"app: {load['foreground_app']})")

    # 1. FIRST: Check if we've been deferring too long (FORCE PROCESS)
    if last_run_time and (time.time() - last_run_time) > MAX_DEFER_TIME_SEC:
        return True, f"Max defer time ({MAX_DEFER_TIME_SEC}s) reached - forcing processing"

    # 2. Check critical resources (RAM)
    if load["mem_available_gb"] < RAM_MIN_FREE_GB:
        return False, f"Insufficient RAM ({load['mem_available_gb']:.1f}GB < {RAM_MIN_FREE_GB}GB)"

    # 3. Check user activity (fullscreen apps)
    if load["in_fullscreen"]:
        return False, f"User in fullscreen app ({load['foreground_app']})"

    # 4. Check overall load score
    if load["score"] > LOAD_THRESHOLD_DEFER:
        return False, f"System too busy (load {load['score']:.0f} > {LOAD_THRESHOLD_DEFER})"

    # 5. Check if user has been idle long enough
    if load["idle_time_sec"] < MIN_IDLE_TIME_SEC:
        return False, f"User active recently (idle {load['idle_time_sec']:.0f}s < {MIN_IDLE_TIME_SEC}s)"

    # All checks passed - good time to process
    if load["score"] < LOAD_THRESHOLD_PROCESS:
        return True, f"System idle (load {load['score']:.0f} < {LOAD_THRESHOLD_PROCESS})"

    # Marginal - proceed but with reduced batch
    return True, f"System load acceptable ({load['score']:.0f})"


def calculate_dynamic_batch_size(load: dict = None) -> int:
    """
    Calculate optimal batch size based on current system load.
    Returns number of events to process this run.
    """
    if load is None:
        load = calculate_system_load()
    
    # Start with base batch size
    batch = BATCH_BASE
    
    # Reduce for high CPU
    if load["cpu_percent"] > 30:
        batch *= 0.7
    if load["cpu_percent"] > 50:
        batch *= 0.5
    
    # Reduce for low RAM
    if load["mem_available_gb"] < 8:
        batch *= 0.7
    if load["mem_available_gb"] < 6:
        batch *= 0.5
    
    # Increase for very idle system
    if load["idle_time_sec"] > 600:
        batch *= 1.2
    if load["idle_time_sec"] > 1800:
        batch *= 1.5
    
    # Clamp to min/max
    return max(BATCH_MIN, min(int(batch), BATCH_MAX))

# ── Prompt ────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are RedSage, a cybersecurity triage assistant for macOS endpoints.
Analyze the security event and respond ONLY with valid JSON in this exact format:
{
  "risk_score": <integer 1-10>,
  "risk_level": "<LOW|MEDIUM|HIGH|CRITICAL>",
  "category": "<threat category>",
  "explanation": "<one sentence explanation>",
  "recommended_action": "<one sentence action>"
}
Do not include any text outside the JSON object."""

def get_utc_timestamp() -> str:
    """Return current UTC timestamp in ISO format with Z suffix."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def build_prompt(event: dict) -> str:
    return f"""Analyze this macOS security event:

Source: {event.get('source', 'unknown')}
Event type: {event.get('event_type', 'unknown')}
Process: {event.get('process', 'unknown')}
Path: {event.get('path', 'unknown')}
User: {event.get('user', 'unknown')}
Signing status: {event.get('signing_status', 'unknown')}
Timestamp: {event.get('timestamp', 'unknown')}
Raw: {json.dumps(event.get('raw', {}), indent=2)}

Return only the JSON risk assessment."""

# ── Deduplication ─────────────────────────────────────────────────────────────

def event_fingerprint(event: dict) -> str:
    """Hash event_type + path + process to detect duplicates."""
    key = f"{event.get('event_type','')}{event.get('path','')}{event.get('process','')}"
    return hashlib.md5(key.encode()).hexdigest()

def load_dedup_cache() -> dict:
    """Load recent fingerprints and their timestamps."""
    cache = {}
    if not DEDUP_CACHE.exists():
        return cache
    cutoff = time.time() - DEDUP_WINDOW_SEC
    with open(DEDUP_CACHE) as f:
        for line in f:
            try:
                entry = json.loads(line.strip())
                if entry.get("ts", 0) > cutoff:
                    cache[entry["fp"]] = entry["ts"]
            except (json.JSONDecodeError, KeyError):
                pass
    return cache

def save_dedup_cache(cache: dict):
    cutoff = time.time() - DEDUP_WINDOW_SEC
    with open(DEDUP_CACHE, "w") as f:
        for fp, ts in cache.items():
            if ts > cutoff:
                f.write(json.dumps({"fp": fp, "ts": ts}) + "\n")

def deduplicate(events: list[dict]) -> tuple[list[dict], int]:
    """Filter out events whose fingerprints are in the cache.
    
    Returns unique events and count of skipped duplicates.
    Note: Does NOT modify the cache - caller must add fingerprints after successful scoring.
    """
    cache = load_dedup_cache()
    unique, skipped = [], 0
    for event in events:
        fp = event_fingerprint(event)
        if fp in cache:
            skipped += 1
            continue
        unique.append(event)
    return unique, skipped


def add_to_dedup_cache(event: dict):
    """Add an event's fingerprint to the dedup cache after successful scoring.
    
    Note: For better performance, use add_multiple_to_dedup_cache() for batch operations.
    """
    cache = load_dedup_cache()
    now = time.time()
    fp = event_fingerprint(event)
    cache[fp] = now
    save_dedup_cache(cache)


def add_multiple_to_dedup_cache(events: list[dict]):
    """Add multiple event fingerprints to dedup cache in a single write."""
    if not events:
        return
    cache = load_dedup_cache()
    now = time.time()
    for event in events:
        fp = event_fingerprint(event)
        cache[fp] = now
    save_dedup_cache(cache)

# ── Normalizers ───────────────────────────────────────────────────────────────

def normalize_filemonitor(raw: dict) -> dict:
    """Normalize Objective-See FileMonitor JSON output."""
    event = raw.get("event", {})
    process = raw.get("process", {})
    file_info = event.get("file", {}) or event.get("destFile", {})
    return {
        "source":         "filemonitor",
        "timestamp":      get_utc_timestamp(),
        "event_type":     f"file_{raw.get('type','event').lower()}",
        "path":           file_info.get("path", "unknown"),
        "process":        process.get("path", "unknown"),
        "user":           str(process.get("uid", "unknown")),
        "signing_status": process.get("signingInfo", {}).get("signatureStatus", "unknown"),
        "raw":            raw,
    }

def normalize_processmonitor(raw: dict) -> dict:
    """Normalize Objective-See ProcessMonitor JSON output."""
    process = raw.get("process", {})
    return {
        "source":         "processmonitor",
        "timestamp":      get_utc_timestamp(),
        "event_type":     f"process_{raw.get('type','event').lower()}",
        "path":           process.get("path", "unknown"),
        "process":        " ".join(process.get("arguments", [])),
        "user":           str(process.get("uid", "unknown")),
        "signing_status": process.get("signingInfo", {}).get("signatureStatus", "unknown"),
        "raw":            raw,
    }

def normalize_velociraptor(raw: dict) -> dict:
    """Velociraptor events are already in our schema — pass through."""
    return raw

NORMALIZERS = {
    "filemonitor":    normalize_filemonitor,
    "processmonitor": normalize_processmonitor,
    "velociraptor":   normalize_velociraptor,
}

def normalize(event: dict) -> dict:
    source = event.get("source", "velociraptor")
    normalizer = NORMALIZERS.get(source, normalize_velociraptor)
    return normalizer(event)

# ── LM Studio ─────────────────────────────────────────────────────────────────

def is_lm_studio_running() -> bool:
    try:
        r = requests.get("http://localhost:1234/v1/models", timeout=3)
        return r.status_code == 200
    except requests.exceptions.ConnectionError:
        return False


def is_lm_studio_cli_available() -> bool:
    """Check if LM Studio CLI (lms) is installed."""
    try:
        result = subprocess.run(
            [LM_STUDIO_CLI, "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def start_lm_studio_server() -> bool:
    """Start LM Studio server in background using CLI."""
    try:
        log.info("Starting LM Studio server via CLI...")
        # Start server in background (detached)
        subprocess.Popen(
            [LM_STUDIO_CLI, "server", "start", "--port", "1234"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )
        return True
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        log.error(f"Failed to start LM Studio server: {e}")
        return False


def load_lm_studio_model() -> bool:
    """Load the RedSage model into LM Studio."""
    try:
        log.info(f"Loading model '{LM_STUDIO_MODEL}'...")
        # Use 'lms load' command (not 'lms model load')
        result = subprocess.run(
            [LM_STUDIO_CLI, "load", LM_STUDIO_MODEL],
            capture_output=True,
            text=True,
            timeout=LM_STUDIO_STARTUP_TIMEOUT
        )
        if result.returncode == 0:
            log.info("Model loaded successfully")
            return True
        else:
            log.error(f"Failed to load model: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        log.error(f"Model load timed out after {LM_STUDIO_STARTUP_TIMEOUT}s")
        return False
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        log.error(f"Failed to load model: {e}")
        return False


def wait_for_lm_studio(timeout: int = LM_STUDIO_STARTUP_TIMEOUT) -> bool:
    """Wait for LM Studio server to be ready."""
    log.info(f"Waiting for LM Studio to be ready (timeout: {timeout}s)...")
    start = time.time()
    while time.time() - start < timeout:
        if is_lm_studio_running():
            log.info("LM Studio is ready")
            return True
        time.sleep(1)
    log.error(f"LM Studio did not become ready in {timeout}s")
    return False


def stop_lm_studio_server() -> bool:
    """Stop LM Studio server and unload model."""
    try:
        log.info("Stopping LM Studio server...")
        subprocess.run(
            [LM_STUDIO_CLI, "server", "stop"],
            capture_output=True,
            timeout=10
        )
        log.info("LM Studio server stopped")
        return True
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        log.warning(f"Failed to stop LM Studio server: {e}")
        return False


def ensure_lm_studio_ready() -> bool:
    """
    Ensure LM Studio server is running and model is loaded.
    Returns True if ready, False if failed.
    """
    # Check if already running
    if is_lm_studio_running():
        log.info("LM Studio server already running")
        return True
    
    # Check if CLI is available
    if not is_lm_studio_cli_available():
        log.error("LM Studio CLI (lms) not found. Please install LM Studio.")
        log.error("Download from: https://lmstudio.ai")
        return False
    
    # Start server
    if not start_lm_studio_server():
        return False
    
    # Wait for server to be ready
    if not wait_for_lm_studio():
        return False
    
    # Load model
    if not load_lm_studio_model():
        return False
    
    # Wait for model to load (additional time)
    time.sleep(2)
    
    return True

def score_event(event: dict) -> dict | None:
    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": build_prompt(event)},
        ],
        "temperature": 0.1,
        "max_tokens":  256,
    }
    try:
        r = requests.post(LM_STUDIO_URL, json=payload, timeout=REQUEST_TIMEOUT_SEC)
        r.raise_for_status()
        text = r.json()["choices"][0]["message"]["content"].strip()

        # Extract JSON from markdown code blocks if present
        if "```" in text:
            # Try to find JSON between ```json and ``` or just ``` and ```
            json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
            if json_match:
                text = json_match.group(1)
            else:
                # Fallback: extract content between first ``` and last ```
                parts = text.split("```")
                if len(parts) >= 2:
                    text = parts[1].strip()
                    if text.startswith("json"):
                        text = text[4:].strip()

        result = json.loads(text)
        
        # Validate required fields in response
        required_fields = ["risk_score", "risk_level", "category", "explanation", "recommended_action"]
        for field in required_fields:
            if field not in result:
                log.warning(f"LM Studio response missing required field: {field}")
                return None
        
        # Validate risk_score is an integer 1-10
        risk_score = result.get("risk_score")
        if not isinstance(risk_score, int) or risk_score < 1 or risk_score > 10:
            log.warning(f"Invalid risk_score: {risk_score} (expected int 1-10)")
            return None
        
        # Validate risk_level is one of the expected values
        valid_levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        if result.get("risk_level") not in valid_levels:
            log.warning(f"Invalid risk_level: {result.get('risk_level')} (expected {valid_levels})")
            return None
        
        return result
    except requests.exceptions.ConnectionError:
        log.error("LM Studio not reachable at localhost:1234")
        return None
    except (KeyError, json.JSONDecodeError) as e:
        log.warning(f"Failed to parse LM Studio response: {e}")
        return None
    except requests.exceptions.Timeout:
        log.warning(f"LM Studio timed out after {REQUEST_TIMEOUT_SEC}s")
        return None

# ── Queue I/O ─────────────────────────────────────────────────────────────────

def read_queue() -> list[dict]:
    if not EVENT_QUEUE.exists():
        return []
    events = []
    with open(EVENT_QUEUE) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    log.warning(f"Malformed queue line skipped: {line[:80]}")
    return events

def clear_queue(keep: list[dict] = None):
    if keep:
        with open(EVENT_QUEUE, "w") as f:
            for e in keep:
                f.write(json.dumps(e) + "\n")
    else:
        EVENT_QUEUE.write_text("")

def write_scored(event: dict, score: dict):
    result = {
        "scored_at":      get_utc_timestamp(),
        "original_event": event,
        "assessment":     score,
        "flagged":        score.get("risk_score", 0) >= RISK_THRESHOLD,
    }
    with open(SCORED_LOG, "a") as f:
        f.write(json.dumps(result) + "\n")

    risk = score.get("risk_score", 0)
    level = score.get("risk_level", "?")
    cat = score.get("category", "?")
    if result["flagged"]:
        log.warning(f"🚨 [{risk}/10] {level} — {cat} | {score.get('explanation','')}")
    else:
        log.info(f"✅ [{risk}/10] {level} — {cat}")

def archive_events(events: list[dict]):
    with open(PROCESSED_LOG, "a") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")

# ── Lock ──────────────────────────────────────────────────────────────────────

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
                    log.warning("Another run in progress. Exiting.")
                    return False
                log.warning("Stale lock removed.")
                LOCK_FILE.unlink()
                return acquire_lock()
            except (OSError, FileNotFoundError):
                return False
        return False

def release_lock():
    if LOCK_FILE.exists():
        LOCK_FILE.unlink()


# ── Last Run Tracking ─────────────────────────────────────────────────────────

def get_last_run_time() -> float | None:
    """Get timestamp of last successful run."""
    if not LAST_RUN_FILE.exists():
        return None
    try:
        with open(LAST_RUN_FILE) as f:
            data = json.load(f)
            return data.get("timestamp")
    except (json.JSONDecodeError, IOError):
        return None


def save_last_run_time(timestamp: float):
    """Save timestamp of successful run."""
    try:
        with open(LAST_RUN_FILE, "w") as f:
            json.dump({"timestamp": timestamp}, f)
    except IOError as e:
        log.warning(f"Failed to save last run time: {e}")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    # Ensure base directory exists before configuring logging
    BASE_DIR.mkdir(parents=True, exist_ok=True)

    # Configure logging (works on repeated calls)
    configure_logging()

    if not acquire_lock():
        sys.exit(0)

    try:
        # Get last run time for defer tracking
        last_run_time = get_last_run_time()
        
        # Check system load and decide whether to process or defer
        should_process, reason = should_process_events(last_run_time)
        
        if not should_process:
            log.info(f"Deferring processing: {reason}")
            log.info("Events will remain in queue for next run.")
            # Still check if queue is empty
            if EVENT_QUEUE.exists() and EVENT_QUEUE.stat().st_size > 0:
                log.info(f"Queue has events waiting ({EVENT_QUEUE.stat().st_size} bytes)")
            return
        
        log.info(f"Processing approved: {reason}")
        
        raw_events = read_queue()
        if not raw_events:
            log.info("Queue empty. Nothing to do.")
            return

        log.info(f"Read {len(raw_events)} raw event(s) from queue.")

        normalized = [normalize(e) for e in raw_events]
        unique, skipped = deduplicate(normalized)
        log.info(f"After dedup: {len(unique)} unique, {skipped} skipped.")

        # All events were duplicates - they were already processed in previous runs
        if not unique:
            clear_queue()
            log.info("Queue cleared (all events were duplicates).")
            return

        # Calculate dynamic batch size based on current load
        current_load = calculate_system_load()
        dynamic_batch_size = calculate_dynamic_batch_size(current_load)

        log.info(f"Dynamic batch size: {dynamic_batch_size} "
                 f"(base: {BATCH_BASE}, load score: {current_load['score']:.0f})")

        # Check if LM Studio was already running (so we don't stop user's session)
        lm_studio_was_running = is_lm_studio_running()

        # Ensure LM Studio is running and model is loaded
        if not ensure_lm_studio_ready():
            log.error("Failed to start LM Studio. Events preserved in queue for next run.")
            sys.exit(1)

        batch = unique[:dynamic_batch_size]
        succeeded, failed = 0, 0
        remaining_events = []  # Events to keep in queue (failed + overflow)
        scored_events = []     # Track successfully scored events for batch operations

        for i, event in enumerate(batch, 1):
            log.info(f"[{i}/{len(batch)}] {event.get('source','?')} "
                     f"{event.get('event_type','?')} — {event.get('path','?')[:60]}")
            score = score_event(event)
            if score:
                write_scored(event, score)
                scored_events.append(event)  # Batch for dedup cache
                succeeded += 1
            else:
                failed += 1
                remaining_events.append(event)  # Keep failed events for retry

        # Batch operations: add all scored events to dedup cache at once
        add_multiple_to_dedup_cache(scored_events)
        
        # Batch operations: archive all scored events at once
        if scored_events:
            archive_events(scored_events)

        # Add overflow events (not processed this run) to remaining
        overflow = unique[dynamic_batch_size:]
        remaining_events.extend(overflow)

        # Clear queue, keeping only failed and overflow events
        clear_queue(keep=remaining_events if remaining_events else None)

        if overflow:
            log.info(f"{len(overflow)} events deferred to next run.")
        if failed:
            log.warning(f"{failed} events failed scoring - will be retried next run.")

        log.info(f"Done. Scored: {succeeded}, Failed: {failed}, Deferred: {len(overflow)}")

        # Save successful run time
        save_last_run_time(time.time())

        # Only stop LM Studio if we started it (don't interrupt user's session)
        if not lm_studio_was_running:
            stop_lm_studio_server()
        else:
            log.debug("LM Studio was already running - leaving it active")

    finally:
        release_lock()

if __name__ == "__main__":
    main()
