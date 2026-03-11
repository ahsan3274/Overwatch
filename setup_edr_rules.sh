#!/bin/bash
# Setup EDR rules for Overwatch
# Downloads and installs YARA rules from recommended sources

set -e

EDR_DIR="$HOME/velociraptor-triage/edr"
YARA_RULES_DIR="$EDR_DIR/yara_rules"

echo "========================================"
echo "Overwatch EDR Rules Setup"
echo "========================================"

# Create directories
echo "[1/4] Creating directories..."
mkdir -p "$YARA_RULES_DIR"

# Check for yara-python
echo "[2/4] Checking yara-python..."
if python3 -c "import yara" 2>/dev/null; then
    echo "  ✅ yara-python is installed"
else
    echo "  ⚠️  yara-python not found"
    echo "  Install with: pip install yara-python"
    echo "  YARA scanning will be disabled until installed"
fi

# Download LOKI signatures
echo "[3/4] Downloading LOKI signatures..."
if [ -d "$EDR_DIR/loki" ]; then
    echo "  LOKI already downloaded, updating..."
    cd "$EDR_DIR/loki" && git pull
else
    echo "  Cloning LOKI repository..."
    git clone --depth 1 https://github.com/Neo23x0/Loki.git "$EDR_DIR/loki"
fi

# Copy LOKI signatures
echo "  Copying signatures to $YARA_RULES_DIR..."
if [ -d "$EDR_DIR/loki/signature" ]; then
    cp -r "$EDR_DIR/loki/signature/"* "$YARA_RULES_DIR/" 2>/dev/null || true
    echo "  ✅ LOKI signatures installed"
else
    echo "  ⚠️  LOKI signature directory not found"
fi

# Download VirusTotal YARA rules (optional)
echo "[4/4] Downloading VirusTotal YARA rules..."
if [ -d "$EDR_DIR/vt-yara" ]; then
    echo "  VT YARA already downloaded, updating..."
    cd "$EDR_DIR/vt-yara" && git pull
else
    echo "  Cloning VirusTotal YARA rules..."
    git clone --depth 1 https://github.com/VirusTotal/yara-rules.git "$EDR_DIR/vt-yara"
fi

# Copy VT YARA rules
echo "  Copying VT rules to $YARA_RULES_DIR..."
if [ -d "$EDR_DIR/vt-yara" ]; then
    cp "$EDR_DIR/vt-yara/"*.yar "$YARA_RULES_DIR/" 2>/dev/null || true
    echo "  ✅ VirusTotal YARA rules installed"
fi

# Count installed rules
RULE_COUNT=$(find "$YARA_RULES_DIR" -name "*.yar" -o -name "*.yara" | wc -l | tr -d ' ')
echo ""
echo "========================================"
echo "EDR Setup Complete!"
echo "========================================"
echo "YARA rules installed: $RULE_COUNT"
echo "Location: $YARA_RULES_DIR"
echo ""
echo "To test EDR:"
echo "  python3 ~/velociraptor-triage/edr/edr_ingester.py --test"
echo ""
echo "To update rules later:"
echo "  bash ~/velociraptor-triage/setup_edr_rules.sh"
echo ""
