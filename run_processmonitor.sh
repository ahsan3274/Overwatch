#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# run_processmonitor.sh
# Pipes Objective-See ProcessMonitor output into the triage event queue.
# Run alongside run_filemonitor.sh for full coverage.
#
# Usage: bash ~/velociraptor-triage/run_processmonitor.sh
# ─────────────────────────────────────────────────────────────────────────────

PROCESSMONITOR="/Applications/ProcessMonitor.app/Contents/MacOS/ProcessMonitor"
QUEUE="$HOME/velociraptor-triage/event_queue.jsonl"

if [ ! -f "$PROCESSMONITOR" ]; then
  echo "❌ ProcessMonitor not found at $PROCESSMONITOR"
  echo "   Download from: https://objective-see.org/products/processmonitor.html"
  exit 1
fi

echo "✅ Starting ProcessMonitor → queue pipe"
echo "   Queue: $QUEUE"
echo "   Press Ctrl+C to stop"
echo ""

"$PROCESSMONITOR" -skipApple -json | python3 -c "
import sys, json, logging

QUEUE = '$QUEUE'
logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')
log = logging.getLogger(__name__)

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        obj = json.loads(line)
        obj['source'] = 'processmonitor'
        with open(QUEUE, 'a') as f:
            f.write(json.dumps(obj) + '\n')
    except json.JSONDecodeError:
        pass  # Skip malformed JSON
    except IOError as e:
        log.error(f'Failed to write to queue: {e}')
        sys.exit(1)  # Exit on write failure to alert user
"
