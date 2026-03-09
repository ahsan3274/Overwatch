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

# Time-based deduplication window (seconds)
DEDUP_WINDOW = 5  # Skip duplicate events within 5 seconds

# Trusted processes to skip (reduces noise by ~90%)
TRUSTED_PROCESSES = {
    'ProcessMonitor', 'FileMonitor',  # Our own monitors
    'node', 'npm', 'npx',  # Node.js development
    'Python', 'python', 'python3', 'python3.14',  # Python processes
    'Code', 'code',  # VS Code
    'Terminal', 'iTerm2', 'WezTerm',  # Terminals
    'bash', 'zsh', 'sh',  # Shells
    'Finder',  # macOS Finder
    'mds', 'mds_stores',  # Spotlight
    'coreaudiod', 'audioanalysis',  # macOS audio
    'WindowServer',  # macOS windowing
    'loginwindow',  # macOS login
    'distnoted',  # macOS distributed notifications
    'cfprefsd',  # macOS preferences
    'syslogd',  # macOS logging
    'logd',  # macOS logging
    'timequotad',  # macOS time quota
    'networkd',  # macOS network
    'configd',  # macOS config
    'powerd',  # macOS power
    'thermalmonitord',  # macOS thermal
    'locationd',  # macOS location
    'bluetoothd',  # macOS bluetooth
    'usbmuxd',  # macOS USB
    'wifi',  # macOS wifi
    'UserEventAgent',  # macOS user events
    'tccd',  # macOS privacy
    'securityd',  # macOS security
    'trustd',  # macOS trust
    'ocspd',  # macOS OCSP
    'rapportd',  # macOS continuity
    'nsurlsessiond',  # macOS URL sessions
    'netbiosd',  # macOS netbios
    'mDNSResponder',  # macOS DNS
    'discoveryd',  # macOS discovery
    'fseventsd',  # macOS file events
    'diskarbitrationd',  # macOS disk
    'storagekitd',  # macOS storage
    'installd',  # macOS install
    'softwareupdated',  # macOS updates
    'appstore',  # App Store
    'Safari', 'safari',  # Safari (optional)
    'brave', 'Brave Browser',  # Brave (optional)
    'launchd',  # macOS launchd
    'kernel_task',  # macOS kernel
    'kernel',  # macOS kernel
}

# Trusted paths to skip
TRUSTED_PATHS = [
    '/dev/',
    '/bin/',
    '/usr/bin/',
    '/usr/lib/',
    '/System/',
    '/Library/',
    '/var/folders/',
    '/tmp/',
    '/private/var/',
    '/Applications/Xcode.app/',
    '/Applications/Visual Studio Code.app/',
    '/Users/ahsan/.nvm/',
    '/Users/ahsan/.lmstudio/',
    '/Users/ahsan/.qwen/',
    '/Users/ahsan/velociraptor-triage/',
]

# Deduplication cache: {(proc_name, proc_path, event_type): timestamp}
dedup_cache = {}

import time
current_time = time.time()

# Clean old entries from dedup cache
old_keys = [k for k, t in dedup_cache.items() if current_time - t > DEDUP_WINDOW]
for k in old_keys:
    del dedup_cache[k]

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        obj = json.loads(line)
        
        # Extract process info
        process_info = obj.get('process', {})
        proc_name = process_info.get('name', '')
        proc_path = process_info.get('path', '')
        
        # Get event type from process monitor
        event_type = obj.get('type', 'event')
        
        # Skip ProcessMonitor monitoring itself (recursive noise)
        if proc_name in ('ProcessMonitor', 'FileMonitor'):
            continue
        
        # Skip trusted processes
        if proc_name in TRUSTED_PROCESSES:
            continue
        
        # Skip trusted paths
        skip_path = False
        for trusted in TRUSTED_PATHS:
            if proc_path.startswith(trusted):
                skip_path = True
                break
        if skip_path:
            continue
        
        # Deduplication check
        dedup_key = (proc_name, proc_path, event_type)
        if dedup_key in dedup_cache:
            last_seen = dedup_cache[dedup_key]
            if current_time - last_seen < DEDUP_WINDOW:
                continue  # Skip duplicate within window
        
        # Update dedup cache
        dedup_cache[dedup_key] = current_time
        
        obj['source'] = 'processmonitor'
        with open(QUEUE, 'a') as f:
            f.write(json.dumps(obj) + '\n')
    except json.JSONDecodeError:
        pass  # Skip malformed JSON
    except IOError as e:
        log.error(f'Failed to write to queue: {e}')
        sys.exit(1)  # Exit on write failure to alert user
"
