#!/bin/bash
# Add BlockBlock Exception for ProcessMonitor
# Run this script to open BlockBlock and add exceptions

echo "=== BlockBlock Exception Setup ==="
echo ""
echo "Opening BlockBlock..."
open -a "BlockBlock Helper"

sleep 2

echo ""
echo "Please add these paths to BlockBlock Exceptions:"
echo ""
echo "  1. Open BlockBlock (should be running)"
echo "  2. Click the gear icon ⚙️ or press Cmd+,"
echo "  3. Go to 'Items' tab"
echo "  4. Find these entries and click 'Ignore' or 'Allow':"
echo ""
echo "     • /Users/ahsan/velociraptor-triage/run_processmonitor.sh"
echo "     • /Users/root/velociraptor-triage/run_processmonitor.sh"
echo "     • /Applications/ProcessMonitor.app"
echo ""
echo "  5. Close preferences"
echo ""
echo "✅ ProcessMonitor will no longer trigger BlockBlock alerts!"
