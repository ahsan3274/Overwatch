#!/bin/bash
# Watch FileMonitor for duplicate instances
# Usage: bash ~/velociraptor-triage/watch_filemonitor.sh

echo "Watching FileMonitor processes (Ctrl+C to stop)..."
echo ""

while true; do
    timestamp=$(date '+%H:%M:%S')
    count=$(ps aux | grep -E "FileMonitor\.app|run_filemonitor" | grep -v grep | wc -l)
    
    echo "$timestamp - Instances: $count"
    
    if [ "$count" -gt 3 ]; then
        echo "⚠️  WARNING: Multiple instances detected!"
        ps aux | grep -E "FileMonitor|filemonitor" | grep -v grep
        echo ""
    fi
    
    sleep 5
done
