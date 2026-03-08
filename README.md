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

> **M1 16GB RAM note:** RedSage at Q4_K_M quantization uses ~6–7 GB of unified memory while running. It is unloaded between triage runs, so your other tools get their memory back.

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
| `BATCH_BASE` | `40` | Base batch size (for M1 16GB) |
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

## File Reference

### Project Files

```
overwatch/
├── setup.sh                          # One-time installer
├── triage_daemon.py                  # Core scoring daemon
├── run_filemonitor.sh                # FileMonitor → queue pipe
├── run_processmonitor.sh             # ProcessMonitor → queue pipe
├── com.velociraptor.llm-triage.plist # launchd job (10-min schedule)
├── velociraptor_artifact.yaml        # VQL artifact for Velociraptor
└── README.md                         # This file
```

### Runtime Files (created by setup.sh)

```
~/velociraptor-triage/
├── triage_daemon.py                  # Copy of daemon script
├── run_filemonitor.sh                # Copy of FileMonitor pipe
├── run_processmonitor.sh             # Copy of ProcessMonitor pipe
├── velociraptor_artifact.yaml        # Patched copy with your username
├── event_queue.jsonl                 # Incoming events (all sources)
├── scored_events.jsonl               # Output: scored + flagged events
├── processed.jsonl                   # Archive of processed events
├── dedup_cache.jsonl                 # Fingerprint cache (5-min window)
├── last_run.json                     # Timestamp of last successful run
├── triage_daemon.log                 # Daemon run log
├── triage.lock                       # Lock file (prevents concurrent runs)
├── launchd_stdout.log                # launchd stdout (when run as daemon)
└── launchd_stderr.log                # launchd stderr (when run as daemon)
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

## License

MIT License — use at your own risk. This is a security tool that monitors your system; review the code before running.

---

## Credits

- **RedSage-Qwen3-8B-DPO** by RISys-Lab — Cybersecurity LLM
- **LM Studio** — Local LLM runtime
- **Objective-See** — FileMonitor and ProcessMonitor
- **Velociraptor** — Endpoint visibility platform
