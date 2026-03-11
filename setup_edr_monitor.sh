#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# setup_edr_monitor.sh — Install EDR database monitoring
# Run from the project root: bash setup_edr_monitor.sh
# ─────────────────────────────────────────────────────────────────────────────
set -e

USERNAME=$(whoami)
HOME_DIR=$(eval echo ~"$USERNAME")
TRIAGE_DIR="$HOME_DIR/velociraptor-triage"
PLIST_SRC="com.velociraptor.edr-monitor.plist"
PLIST_DEST="$HOME_DIR/Library/LaunchAgents/com.velociraptor.edr-monitor.plist"

echo "────────────────────────────────────────────────"
echo "  Overwatch EDR Monitor — Setup"
echo "  User:        $USERNAME"
echo "  Triage dir:  $TRIAGE_DIR"
echo "────────────────────────────────────────────────"

# 1. Ensure triage directory exists
echo "[1/5] Creating triage directory..."
mkdir -p "$TRIAGE_DIR"

# 2. Copy EDR module
echo "[2/5] Installing EDR module..."
mkdir -p "$TRIAGE_DIR/edr"
cp -r overwatch-public/edr/*.py "$TRIAGE_DIR/edr/" 2>/dev/null || {
    echo "   ⚠️  EDR module not found in overwatch-public/edr"
    exit 1
}
echo "   EDR module installed to $TRIAGE_DIR/edr/"

# 3. Copy EDR monitor script
echo "[3/5] Installing EDR monitor script..."
cp edr_monitor.py "$TRIAGE_DIR/edr_monitor.py"
chmod +x "$TRIAGE_DIR/edr_monitor.py"

# 4. Ensure threat_db directory exists
echo "[4/5] Creating threat_db directory..."
mkdir -p "$TRIAGE_DIR/threat_db"

# 5. Copy EDR rules setup script
echo "[5/5] Installing EDR rules setup script..."
cp overwatch-public/setup_edr_rules.sh "$TRIAGE_DIR/setup_edr_rules.sh"
chmod +x "$TRIAGE_DIR/setup_edr_rules.sh"

# 6. Install launchd job
echo "[6/6] Installing launchd job..."
sed "s|YOUR_USERNAME|$USERNAME|g" "$PLIST_SRC" > "$PLIST_DEST"

# Unload existing job if present
launchctl unload "$PLIST_DEST" 2>/dev/null || true

# Load new job
if launchctl load "$PLIST_DEST" 2>/dev/null; then
    echo "   ✓ Launchd job installed successfully"
else
    echo "   ⚠️  launchctl load failed - may need to run from a login session"
    echo "   Manual install: launchctl load $PLIST_DEST"
fi

echo ""
echo "✅ EDR Monitor Setup Complete!"
echo ""
echo "─── What it monitors ─────────────────────────────"
echo ""
echo "• SQLite database integrity (corruption detection)"
echo "• Database lock/busy issues"
echo "• Cache performance and size"
echo "• EDR ingester log errors"
echo "• Hash lookup API failures"
echo ""
echo "─── Monitor manually ─────────────────────────────"
echo "   python3 $TRIAGE_DIR/edr_monitor.py"
echo ""
echo "─── View monitor logs ────────────────────────────"
echo "   tail -f $TRIAGE_DIR/edr_monitor.log"
echo ""
echo "─── Check launchd status ─────────────────────────"
echo "   launchctl list | grep edr-monitor"
echo ""
echo "─── Uninstall ────────────────────────────────────"
echo "   launchctl unload $PLIST_DEST && rm $PLIST_DEST"
echo "   rm -rf $TRIAGE_DIR/edr/"
echo "   rm $TRIAGE_DIR/edr_monitor.py"
echo "   rm $TRIAGE_DIR/setup_edr_rules.sh"
