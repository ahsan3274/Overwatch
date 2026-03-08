#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# setup.sh — one-time installer
# Run from the project root: bash setup.sh
# ─────────────────────────────────────────────────────────────────────────────
set -e

USERNAME=$(whoami)
HOME_DIR=$(eval echo ~"$USERNAME")
TRIAGE_DIR="$HOME_DIR/velociraptor-triage"
PLIST_SRC="com.velociraptor.llm-triage.plist"
PLIST_DEST="$HOME_DIR/Library/LaunchAgents/com.velociraptor.llm-triage.plist"

echo "────────────────────────────────────────────────"
echo "  Velociraptor LLM Triage — Setup"
echo "  User:        $USERNAME"
echo "  Triage dir:  $TRIAGE_DIR"
echo "────────────────────────────────────────────────"

# 1. Create triage directory and empty queue files
echo "[1/5] Creating triage directory..."
mkdir -p "$TRIAGE_DIR"
for f in event_queue.jsonl scored_events.jsonl processed.jsonl dedup_cache.jsonl; do
  touch "$TRIAGE_DIR/$f"
done

# 2. Copy daemon and scripts
echo "[2/5] Installing scripts..."
cp triage_daemon.py "$TRIAGE_DIR/triage_daemon.py"
cp run_filemonitor.sh "$TRIAGE_DIR/run_filemonitor.sh"
cp run_processmonitor.sh "$TRIAGE_DIR/run_processmonitor.sh"
chmod +x "$TRIAGE_DIR/triage_daemon.py"
chmod +x "$TRIAGE_DIR/run_filemonitor.sh"
chmod +x "$TRIAGE_DIR/run_processmonitor.sh"

# 3. Patch and install plist
echo "[3/5] Installing launchd job..."
sed "s|YOUR_USERNAME|$USERNAME|g" "$PLIST_SRC" > "$PLIST_DEST"
launchctl unload "$PLIST_DEST" 2>/dev/null || true
if launchctl load "$PLIST_DEST" 2>/dev/null; then
    echo "   Launchd job installed successfully"
else
    echo "   ⚠️  launchctl load failed - may need to run from a login session"
fi

# 4. Python dependency check
echo "[4/5] Checking Python dependencies..."
python3 -c "import requests" 2>/dev/null && python3 -c "import psutil" 2>/dev/null && echo "   Dependencies already installed" || {
    echo "   Installing dependencies..."
    pip3 install requests psutil --quiet --break-system-packages 2>/dev/null || {
        echo "   ⚠️  Could not install dependencies automatically."
        echo "   Run: pip3 install requests psutil --user"
    }
}
echo "   Dependencies: requests, psutil"

# 5. Patch VQL artifact username
echo "[5/5] Patching VQL artifact..."
sed "s|YOUR_USERNAME|$USERNAME|g" velociraptor_artifact.yaml \
  > "$TRIAGE_DIR/velociraptor_artifact.yaml"

echo ""
echo "✅ Setup complete!"
echo ""
echo "─── What to do next ────────────────────────────────"
echo ""
echo "1. REDSAGE (LM Studio)"
echo "   → Open LM Studio → search 'RedSage' → Download & Load"
echo "   → Ensure server is running on localhost:1234"
echo ""
echo "2. FILEMONITOR"
echo "   → Install FileMonitor.app to /Applications/"
echo "   → Run: bash $TRIAGE_DIR/run_filemonitor.sh"
echo ""
echo "3. PROCESSMONITOR"
echo "   → Install ProcessMonitor.app to /Applications/"
echo "   → Run: bash $TRIAGE_DIR/run_processmonitor.sh"
echo ""
echo "4. VELOCIRAPTOR"
echo "   → Dashboard → Artifacts → Upload New Artifact"
echo "   → Upload: $TRIAGE_DIR/velociraptor_artifact.yaml"
echo ""
echo "5. TEST"
echo "   → python3 $TRIAGE_DIR/triage_daemon.py"
echo ""
echo "─── Monitor scored events ──────────────────────────"
echo "   tail -f $TRIAGE_DIR/scored_events.jsonl | python3 -m json.tool"
echo ""
echo "─── Uninstall ──────────────────────────────────────"
echo "   launchctl unload $PLIST_DEST && rm $PLIST_DEST"
