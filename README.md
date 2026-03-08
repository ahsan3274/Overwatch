# Overwatch

**Local AI-powered threat triage for macOS.** Collects security events from three sources, deduplicates them, and scores each one using RedSage running in LM Studio — all on-device, no cloud, no agents phoning home.

---

## Quick Start

```bash
# 1. Install
bash setup.sh

# 2. Download RedSage model (one-time)
lms get redsage-qwen3-8b-dpo

# 3. Done! The daemon runs automatically every 10 minutes.
```

That's it. Overwatch runs in the background, waits for your Mac to be idle, then scores security events using AI. Zero manual intervention needed.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      EVENT SOURCES                              │
│                                                                 │
│  Velociraptor          FileMonitor        ProcessMonitor        │
│  (persistence paths)   (file I/O)         (process launches)    │
│        │                    │                   │               │
└────────┼────────────────────┼───────────────────┼───────────────┘
         │                    │                   │
         └──────────┬─────────┘                   │
                    ▼                             │
         ~/velociraptor-triage/                   │
              event_queue.jsonl ◄─────────────────┘
                    │
         (launchd fires every 10 min)
                    │
                    ▼
         ┌─────────────────────────┐
         │   triage_daemon.py      │
         │  - Check system load    │
         │  - Normalize events     │
         │  - Deduplicate          │
         │  - Dynamic batch sizing │
         └───────────┬─────────────┘
                     │
         ┌───────────▼─────────────┐
         │  LM Studio (auto-start) │
         │  RedSage-Qwen3-8B       │
         └───────────┬─────────────┘
                     │
                     ▼
         scored_events.jsonl
         (flagged: risk ≥ 7)
```

**Key design decisions:**
- ✅ **Zero RAM at rest** — LM Studio loads only when needed
- ✅ **Intelligent scheduling** — defers during peak usage, accelerates when idle
- ✅ **Dynamic batching** — processes 10-60 events based on system load
- ✅ **Shared queue** — all three sources use one dedup layer
- ✅ **All local** — no cloud, no telemetry

---

## Prerequisites

| Tool | Where to get it | Required |
|------|-----------------|----------|
| **LM Studio** | https://lmstudio.ai | ✅ Yes |
| **RedSage model** | `lms get redsage-qwen3-8b-dpo` | ✅ Yes |
| **Python 3.9+** | Pre-installed on macOS 12+ | ✅ Yes |
| **Velociraptor** | https://github.com/Velocidex/velociraptor | ⚠️ Optional |
| **FileMonitor** | https://objective-see.org/products/filemonitor.html | ⚠️ Optional |
| **ProcessMonitor** | https://objective-see.org/products/processmonitor.html | ⚠️ Optional |
| **OSINT Reporter** | https://github.com/ahsan3274/osint-reporter | ⚠️ Optional |



---

## Installation

### Step 1: Run Setup

```bash
cd /path/to/Overwatch
bash setup.sh
```

`setup.sh` will:
1. Create `~/velociraptor-triage/` with all queue and log files
2. Install the triage daemon and pipe scripts
3. Register the launchd job (fires every 10 minutes)
4. Install Python dependencies (`requests`, `psutil`)
5. Patch the VQL artifact with your username

### Step 2: Download RedSage Model

```bash
lms get redsage-qwen3-8b-dpo
```

This downloads the ~5GB model. One-time only.

### Step 3: Verify Installation

```bash
# Check launchd is registered
launchctl list | grep llm-triage

# Test the daemon manually
python3 ~/velociraptor-triage/triage_daemon.py
```

---

## Optional: Event Sources

Overwatch works with just the daemon (queue-based), but you can add real-time event sources:

### FileMonitor (File Events)

```bash
# Install to /Applications/, then run:
bash ~/velociraptor-triage/run_filemonitor.sh
```

Monitors: file create, write, delete operations.

### ProcessMonitor (Process Events)

```bash
# Install to /Applications/, then run:
bash ~/velociraptor-triage/run_processmonitor.sh
```

Monitors: process launches, exec chains.

### Velociraptor (Persistence & Network)

1. Open Velociraptor dashboard at `https://localhost:8889`
2. Go to **Artifacts → Upload New Artifact**
3. Upload `~/velociraptor-triage/velociraptor_artifact.yaml`
4. Start the artifact on your client

> **Note:** Velociraptor may run as root. If you see permission errors writing to the queue:
> ```bash
> chmod 777 ~/velociraptor-triage/
> ```

---

## How It Works

### Intelligent Scheduling

The daemon monitors your system and **dynamically adjusts** when and how much to process:

| Metric | Monitors | Action |
|--------|----------|--------|
| **CPU usage** | `top` / `psutil` | Reduce batch during high CPU |
| **Memory available** | `vm_stat` / `psutil` | Defer if RAM < 4GB |
| **User idle time** | `ioreg HIDIdleTime` | Wait for keyboard/mouse idle |
| **Foreground app** | AppleScript | Detect fullscreen apps |
| **Fullscreen status** | App name matching | Defer during Zoom, games, etc. |

### Load Score (0-100)

```
Load Score = CPU(40pts) + Memory(30pts) + Activity(30pts) + Fullscreen(20pts)
```

**Lower = more idle** | **Higher = more busy**

### Decision Flow

```
launchd fires (every 10 min)
    ↓
Calculate load score
    ↓
Score > 70? ─────────────→ DEFER
    ↓
In Zoom/fullscreen? ─────→ DEFER
    ↓
RAM < 4GB? ──────────────→ DEFER
    ↓
Idle < 2 min? ───────────→ DEFER
    ↓
Last run > 30 min ago? ──→ FORCE PROCESS (safety)
    ↓
Calculate dynamic batch (10-60 events)
    ↓
Start LM Studio → Load model → Score events → Unload model
```

### Example Scenarios

| Scenario | Load Score | Batch Size | Action |
|----------|------------|------------|--------|
| Late night, laptop idle 2 hours | 5 | 60 | Process max batch |
| Working in browser, idle 5 min | 35 | 40 | Process normal batch |
| Video call (Zoom fullscreen) | 85 | — | **Defer** |
| Xcode compiling, CPU 90% | 75 | — | **Defer** |
| 30 min since last run | Any | Any | **Force process** |

---

## Configuration

Edit `~/velociraptor-triage/triage_daemon.py` to customize:

### AI Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `MODEL_NAME` | `redsage-qwen3-8b-dpo` | Must match LM Studio model exactly |
| `RISK_THRESHOLD` | `7` | Score ≥ this triggers HIGH flag |
| `REQUEST_TIMEOUT_SEC` | `90` | LM Studio response timeout |

### Intelligent Scheduling

| Variable | Default | Description |
|----------|---------|-------------|
| `LOAD_THRESHOLD_PROCESS` | `40` | Process if system load < this |
| `LOAD_THRESHOLD_DEFER` | `70` | Defer if system load > this |
| `MAX_DEFER_TIME_SEC` | `1800` | Force processing after 30 min |
| `MIN_IDLE_TIME_SEC` | `120` | Require 2 min idle before processing |
| `RAM_MIN_FREE_GB` | `4` | Minimum free RAM required |

### Dynamic Batching

| Variable | Default | Description |
|----------|---------|-------------|
| `BATCH_BASE` | `40` | Base batch size |
| `BATCH_MIN` | `10` | Minimum events per run |
| `BATCH_MAX` | `60` | Maximum events per run |

### Deduplication

| Variable | Default | Description |
|----------|---------|-------------|
| `DEDUP_WINDOW_SEC` | `300` | Ignore duplicate events within 5 min |

---

## Monitoring

### View Flagged Events (Real-time)

```bash
tail -f ~/velociraptor-triage/scored_events.jsonl | python3 -m json.tool
```

### Filter HIGH/CRITICAL Only

```bash
grep '"flagged": true' ~/velociraptor-triage/scored_events.jsonl | python3 -m json.tool
```

### Check Daemon Logs

```bash
tail -f ~/velociraptor-triage/triage_daemon.log
```

### Check launchd Status

```bash
# See last run time and any errors
log show --predicate 'process == "python3"' --last 1h | grep triage
```

---

## OSINT Integration

Overwatch can optionally integrate with **[OSINT Reporter](https://github.com/ahsan3274/osint-reporter)** to provide real-time threat intelligence context to the AI triage model. This helps the model correlate local events with active global threat campaigns.

> **Note:** This integration is **100% optional**. Overwatch works perfectly without OSINT Reporter — the triage daemon will simply run without external threat context.

### How It Works

```
OSINT Reporter → osint_ingester.py → triage_daemon.py → LM Studio
     │                                      │
     └─→ Cyber events (CVEs, APTs, malware) ─┘
```

The ingester:
1. Reads latest OSINT reports from `~/osint-reporter/output/`
2. Extracts **only cybersecurity content** (ignores geopolitics, finance)
3. Compresses into ~1000 token context (rolling 48h window)
4. Injects into triage prompts for enriched risk scoring

### Setup

```bash
# 1. Install OSINT Reporter (optional)
git clone https://github.com/ahsan3274/osint-reporter
# Configure and run OSINT Reporter per its README

# 2. Copy OSINT ingester to triage directory
cp /path/to/Overwatch/osint_ingester.py ~/velociraptor-triage/

# 3. That's it! Integration is automatic.
#    If osint_ingester.py is not present, triage runs without OSINT context.
```

### Configuration

Edit `osint_ingester.py` to customize:

```python
# Rolling window: how far back to look for intel
INTEL_WINDOW_HOURS = 48  # Last 48 hours

# Compression settings
MAX_INTEL_ITEMS = 20     # Max threat items to include
MAX_CVE_COUNT = 10       # Max CVEs to list
MAX_TOKENS_ESTIMATE = 2000  # Target max tokens

# Categories to include
RELEVANT_CATEGORIES = {"cybersecurity", "tech_ai"}
```

### Example OSINT Context

When the triage daemon runs, it includes context like:

```
═══ OSINT THREAT CONTEXT ═══
Window: Last 48h | Events: 20 | CVEs: 1

ACTIVE THREATS:
  • Threat Actors: APT28, Transparent Tribe
  • Active CVEs: CVE-2025-38617

INTEL SUMMARY: APT28 is running a rapid-iteration implant campaign 
against Ukrainian targets with novel fileless tooling. Transparent 
Tribe has operationalized AI-assisted malware factories...

TOP EVENTS:
  1. [r/netsec] A Race Within A Race: Exploiting CVE-2025-38617...
  2. [r/cybersecurity] Cisco Catalyst SD WAN just got hit...
═══ END OSINT CONTEXT ═══
```

### Benefits

| Without OSINT | With OSINT |
|---------------|------------|
| Scores events in isolation | Correlates with active campaigns |
| Generic threat categories | Specific APT/TTP attribution |
| Static risk assessment | Context-aware scoring (CVE matches boost score) |

### Monitoring

```bash
# View cached OSINT context
cat ~/velociraptor-triage/osint_context.json | python3 -m json.tool

# Check OSINT state (processed events)
cat ~/velociraptor-triage/osint_state.json

# Manual refresh
python3 ~/velociraptor-triage/osint_ingester.py
```

---

## Alerting

Overwatch includes an **alerter daemon** that watches for flagged events and sends real-time notifications via multiple channels.

### Quick Start

```bash
# 1. Install alerting system
bash setup_alerting.sh

# 2. Configure channels
nano ~/velociraptor-triage/alert_config.yaml

# 3. Done! Alerter runs automatically in background.
```

### Supported Channels

| Channel | Description | Setup Required |
|---------|-------------|----------------|
| **macOS Notification** | System notification with sound | None |
| **Terminal** | Inline colored alerts | None |
| **Slack** | Webhook to Slack channel | Webhook URL |
| **Discord** | Webhook to Discord channel | Webhook URL |
| **Email** | SMTP email alerts | SMTP credentials |

### Configuration

Edit `~/velociraptor-triage/alert_config.yaml`:

```yaml
# Enable/disable channels
channels:
  macos_notification: true
  terminal: true
  slack: false
  discord: false
  email: false

# Slack webhook
slack:
  webhook_url: "https://hooks.slack.com/services/XXX"
  channel: "#security-alerts"
  username: "Overwatch"

# Discord webhook
discord:
  webhook_url: "https://discord.com/api/webhooks/XXX"
  username: "Overwatch"

# Email (SMTP)
email:
  smtp_server: "smtp.gmail.com"
  smtp_port: 587
  username: "your-email@gmail.com"
  password: "app-password-here"
  from_addr: "your-email@gmail.com"
  to_addrs:
    - "admin@example.com"
  use_tls: true

# Alert thresholds
thresholds:
  min_risk_score: 7          # Only alert for score >= 7
  alert_on_levels:
    - "HIGH"
    - "CRITICAL"
```

### Getting Webhook URLs

**Slack:**
1. Go to your Slack workspace
2. Create a new incoming webhook: https://your-workspace.slack.com/apps/manage/custom-integrations
3. Choose #security-alerts channel
4. Copy the webhook URL

**Discord:**
1. Go to your Discord server settings
2. Integrations → Webhooks → New Webhook
3. Choose channel and copy URL

**Email (Gmail):**
1. Enable 2FA on your Google account
2. Generate an App Password: https://myaccount.google.com/apppasswords
3. Use the app password (not your regular password)

### Manual Testing

```bash
# Run alerter manually (foreground)
python3 ~/velociraptor-triage/alerter_daemon.py

# Trigger a test alert (add a fake HIGH-risk event)
echo '{"flagged": true, "assessment": {"risk_score": 9, "risk_level": "CRITICAL", "category": "test", "explanation": "Test alert", "recommended_action": "Ignore"}, "original_event": {"source": "test", "event_type": "test", "path": "/test", "timestamp": "2026-03-08T00:00:00Z"}}' >> ~/velociraptor-triage/scored_events.jsonl
```

### View Alert Logs

```bash
# Real-time alert log
tail -f ~/velociraptor-triage/alerts.log

# Check alerter status
launchctl list | grep alerter
```

### Alert Example

When a HIGH-risk event is detected, you'll see:

**Terminal:**
```
🚨 OVERWATCH ALERT 🚨
Title: 🚨 HIGH: Malware Detection
Message: filemonitor detected file_event
Risk: 7/10 - HIGH
Category: malware detection
Time: 2026-03-08T12:34:56Z
```

**macOS Notification:**
- System notification with "Hero" sound
- Title and message displayed

**Slack/Discord:**
- Formatted embed with risk score, level, category
- Explanation and recommended action

---

## File Reference

### Project Files

```
overwatch/
├── setup.sh                          # One-time installer
├── setup_alerting.sh                 # Alerting system installer
├── triage_daemon.py                  # Core scoring daemon
├── alerter_daemon.py                 # Alert notification daemon
├── osint_ingester.py                 # OSINT threat intel ingester
├── run_filemonitor.sh                # FileMonitor → queue pipe
├── run_processmonitor.sh             # ProcessMonitor → queue pipe
├── com.velociraptor.llm-triage.plist # launchd job (10-min schedule)
├── com.velociraptor.alerter.plist    # launchd job for alerter
├── velociraptor_artifact.yaml        # VQL artifact for Velociraptor
└── README.md                         # This file
```

### Runtime Files (created by setup.sh)

```
~/velociraptor-triage/
├── triage_daemon.py                  # Copy of daemon script
├── alerter_daemon.py                 # Copy of alerter script
├── osint_ingester.py                 # Copy of OSINT ingester
├── run_filemonitor.sh                # Copy of FileMonitor pipe
├── run_processmonitor.sh             # Copy of ProcessMonitor pipe
├── velociraptor_artifact.yaml        # Patched copy with your username
├── alert_config.yaml                 # Alerting configuration (YAML)
├── event_queue.jsonl                 # Incoming events (all sources)
├── scored_events.jsonl               # Output: scored + flagged events
├── processed.jsonl                   # Archive of processed events
├── osint_context.json                # Cached OSINT threat context
├── osint_state.json                  # Processed OSINT event hashes
├── dedup_cache.jsonl                 # Fingerprint cache (5-min window)
├── alert_state.json                  # Track already-alerted events
├── last_run.json                     # Timestamp of last successful run
├── triage_daemon.log                 # Daemon run log
├── alerts.log                        # Alerter run log
├── triage.lock                       # Lock file (prevents concurrent runs)
├── alerter.lock                      # Alerter lock file
├── launchd_stdout.log                # launchd stdout (when run as daemon)
├── launchd_stderr.log                # launchd stderr (when run as daemon)
├── alerter_stdout.log                # Alerter stdout
└── alerter_stderr.log                # Alerter stderr
```

---

## Troubleshooting

### "Insufficient RAM" in logs

The daemon detected less than 4GB free RAM and deferred processing. This is normal — it will run when your system is more idle.

To lower the threshold (not recommended):
```python
# Edit ~/velociraptor-triage/triage_daemon.py
RAM_MIN_FREE_GB = 2  # Default: 4
```

### "LM Studio CLI not found"

Make sure LM Studio is installed and the `lms` command is in your PATH:
```bash
lms --version  # Should output version
```

If not found, restart your terminal or run:
```bash
export PATH="$HOME/.lmstudio/bin:$PATH"
```

### Events not being processed

Check the daemon logs:
```bash
tail -20 ~/velociraptor-triage/triage_daemon.log
```

Common reasons for deferral:
- System load > 70 (CPU, memory, or user activity)
- In a fullscreen app (Zoom, games, presentations)
- User idle time < 2 minutes
- Free RAM < 4GB

To force processing for testing:
```bash
python3 ~/velociraptor-triage/triage_daemon.py
```

### Model not loading

Verify the model is downloaded:
```bash
lms ls | grep redsage
```

If not listed, download it:
```bash
lms get redsage-qwen3-8b-dpo
```

---

## Uninstall

```bash
# Stop the daemon
launchctl unload ~/Library/LaunchAgents/com.velociraptor.llm-triage.plist

# Remove files
rm ~/Library/LaunchAgents/com.velociraptor.llm-triage.plist
rm -rf ~/velociraptor-triage
```

---

## Roadmap (Upcoming Features)

These features are in development and will be added in future releases:

| Feature | Description | Priority |
|---------|-------------|----------|
| **Auto-Remediation** | Automated response actions: quarantine files, kill malicious processes, block network connections, remove persistence | 🔥 High |
| **Enrichment Module** | Pre-scoring enrichment: VirusTotal API, code signature validation, entitlements analysis, sandbox detection | High |
| **SIEM Export** | Forward scored events to Splunk, Elastic, syslog, or CSV/JSON for enterprise integration | Medium |
| **Enhanced Deduplication** | Cross-source deduplication with fuzzy matching and event correlation | Medium |
| **Custom Rules Engine** | User-defined rules for auto-escalation, suppression, or custom scoring | Medium |
| **Behavioral Baselines** | Learn normal system behavior to reduce false positives over time | Low |

> **Note:** A **Web Dashboard** with real-time alert viewing, triage queue management, and OSINT visualization is available as a separate private module. Contact for access.

---

## License

MIT License — use at your own risk. This is a security tool that monitors your system; review the code before running.

---

## Credits

- **RedSage-Qwen3-8B-DPO** by RISys-Lab — Cybersecurity LLM
- **LM Studio** — Local LLM runtime
- **Objective-See** — FileMonitor and ProcessMonitor
- **Velociraptor** — Endpoint visibility platform
