# FileMonitor Setup Guide

## Problem
FileMonitor requires **Full Disk Access** permission to monitor file events on macOS.

## Solution

### Step 1: Grant Full Disk Access

**Manual Method (Recommended):**
1. Open **System Settings** → **Privacy & Security** → **Full Disk Access**
2. Click the **"+"** button
3. Navigate to `/Applications/FileMonitor.app`
4. Select it and click **"Open"**
5. Toggle FileMonitor to **ON**

**Command Line Method:**
```bash
# Reset FileMonitor permissions
sudo tccutil reset All com.objective-see.filemonitor

# Then grant via System Settings as above
```

### Step 2: Move FileMonitor to /Applications (if needed)

If FileMonitor is running from AppTranslocation:
```bash
# Find current location
ps aux | grep FileMonitor

# Move to /Applications
sudo mv /var/folders/*/AppTranslocation/*/d/FileMonitor.app /Applications/
```

### Step 3: Restart FileMonitor Daemon

```bash
# Unload and reload
sudo launchctl unload /Library/LaunchDaemons/com.velociraptor.filemonitor.daemon.plist
sudo launchctl load /Library/LaunchDaemons/com.velociraptor.filemonitor.daemon.plist

# Or force restart
sudo launchctl kickstart -k system/com.velociraptor.filemonitor.daemon
```

### Step 4: Verify

```bash
# Check process is running
ps aux | grep -i filemonitor | grep -v grep

# View logs (should show JSON events)
tail -f ~/velociraptor-triage/filemonitor_stdout.log

# Check for errors
tail -f ~/velociraptor-triage/filemonitor_stderr.log
```

### Expected Output

When working correctly, `filemonitor_stdout.log` should show:
```json
{"event": {...}, "process": {...}, "type": "file_event"}
{"event": {...}, "process": {...}, "type": "file_event"}
```

When files are created/modified, they should appear in the queue:
```bash
# Test by creating a file
touch /tmp/test_file.txt

# Check queue
cat ~/velociraptor-triage/event_queue.jsonl
```

## Troubleshooting

### "ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED"
- FileMonitor doesn't have Full Disk Access
- Grant permission in System Settings

### Process keeps restarting
- Check `filemonitor_stderr.log` for errors
- Ensure FileMonitor.app is in `/Applications/`

### No events in queue
- FileMonitor may be filtering Apple-signed events (normal)
- Test with a non-Apple process creating files
