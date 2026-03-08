#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# run_filemonitor.sh
# Pipes Objective-See FileMonitor output into the triage event queue.
# Run this once; it stays running in the background.
#
# Usage: bash ~/velociraptor-triage/run_filemonitor.sh
# ─────────────────────────────────────────────────────────────────────────────

FILEMONITOR="/Applications/FileMonitor.app/Contents/MacOS/FileMonitor"
QUEUE="$HOME/velociraptor-triage/event_queue.jsonl"

if [ ! -f "$FILEMONITOR" ]; then
  echo "❌ FileMonitor not found at $FILEMONITOR"
  echo "   Download from: https://objective-see.org/products/filemonitor.html"
  exit 1
fi

echo "✅ Starting FileMonitor → queue pipe"
echo "   Queue: $QUEUE"
echo "   Press Ctrl+C to stop"
echo ""

# -skipApple filters out Apple-signed system events to reduce noise
"$FILEMONITOR" -skipApple -json | python3 -c "
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
        obj['source'] = 'filemonitor'
        with open(QUEUE, 'a') as f:
            f.write(json.dumps(obj) + '\n')
    except json.JSONDecodeError:
        pass  # Skip malformed JSON
    except IOError as e:
        log.error(f'Failed to write to queue: {e}')
        sys.exit(1)  # Exit on write failure to alert user
"
