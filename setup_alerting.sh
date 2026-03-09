#!/bin/bash
# Overwatch Alerting Setup
# Installs alerter daemon and creates configuration

set -e

BASE_DIR=~/velociraptor-triage
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Overwatch Alerting Setup ==="
echo ""

# Ensure base directory exists
mkdir -p "$BASE_DIR"

# Copy alerter daemon
echo "📦 Installing alerter daemon..."
cp "$SCRIPT_DIR/alerter_daemon.py" "$BASE_DIR/alerter_daemon.py"
chmod +x "$BASE_DIR/alerter_daemon.py"

# Install PyYAML if not present
echo "📦 Checking dependencies..."
python3 -c "import yaml" 2>/dev/null || {
    echo "   Installing PyYAML..."
    pip3 install --user pyyaml
}

# Create config if not exists
if [ ! -f "$BASE_DIR/alert_config.yaml" ]; then
    echo "📝 Creating alert configuration..."
    cat > "$BASE_DIR/alert_config.yaml" << 'EOF'
# Overwatch Alerting Configuration
# Edit this file to customize alert behavior

# Enable/disable notification channels
channels:
  macos_notification: true   # macOS system notifications
  terminal: true             # Inline terminal alerts
  slack: false               # Slack webhook alerts
  discord: false             # Discord webhook alerts
  email: false               # Email alerts via SMTP

# Slack configuration
slack:
  webhook_url: ""            # https://hooks.slack.com/services/XXX
  channel: "#security-alerts"
  username: "Overwatch"

# Discord configuration
discord:
  webhook_url: ""            # https://discord.com/api/webhooks/XXX
  username: "Overwatch"

# Email configuration (SMTP)
email:
  smtp_server: "smtp.gmail.com"
  smtp_port: 587
  username: ""               # Your email address
  password: ""               # App password (not regular password)
  from_addr: ""              # Sender address (usually same as username)
  to_addrs:                  # Recipients
    - "admin@example.com"
  use_tls: true

# Alert thresholds
thresholds:
  min_risk_score: 7          # Only alert for events >= this score
  alert_on_levels:           # Which risk levels trigger alerts
    - "HIGH"
    - "CRITICAL"
EOF
    echo "   Created: $BASE_DIR/alert_config.yaml"
else
    echo "✅ Config already exists: $BASE_DIR/alert_config.yaml"
fi

# Create launchd plist for alerter
echo "📝 Creating launchd job for alerter..."
cat > "$BASE_DIR/com.velociraptor.alerter.plist" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!--
  Install:   cp com.velociraptor.alerter.plist ~/Library/LaunchAgents/
             launchctl load ~/Library/LaunchAgents/com.velociraptor.alerter.plist
  Uninstall: launchctl unload ~/Library/LaunchAgents/com.velociraptor.alerter.plist
             rm ~/Library/LaunchAgents/com.velociraptor.alerter.plist
-->
<plist version="1.0">
<dict>

    <key>Label</key>
    <string>com.velociraptor.alerter</string>

    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>/Users/YOUR_USERNAME/velociraptor-triage/alerter_daemon.py</string>
    </array>

    <key>StandardOutPath</key>
    <string>/Users/YOUR_USERNAME/velociraptor-triage/alerter_stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/Users/YOUR_USERNAME/velociraptor-triage/alerter_stderr.log</string>

    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/Users/$USERNAME/.lmstudio/bin:/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin</string>
    </dict>

    <key>KeepAlive</key>
    <true/>

    <key>RunAtLoad</key>
    <true/>

</dict>
</plist>
EOF

# Patch username in plist
USERNAME=$(whoami)
sed -i '' "s|/Users/YOUR_USERNAME/|/Users/$USERNAME/|g" "$BASE_DIR/com.velociraptor.alerter.plist"

# Install launchd job
echo "🔧 Installing launchd job..."
cp "$BASE_DIR/com.velociraptor.alerter.plist" ~/Library/LaunchAgents/
launchctl unload ~/Library/LaunchAgents/com.velociraptor.alerter.plist 2>/dev/null || true
launchctl load ~/Library/LaunchAgents/com.velociraptor.alerter.plist

echo ""
echo "=== Setup Complete ==="
echo ""
echo "✅ Alerter daemon installed: $BASE_DIR/alerter_daemon.py"
echo "✅ Config created: $BASE_DIR/alert_config.yaml"
echo "✅ Launchd job registered: com.velociraptor.alerter"
echo ""
echo "Next steps:"
echo "1. Edit ~/velociraptor-triage/alert_config.yaml to enable channels"
echo "2. For Slack: Add your webhook URL to the config"
echo "3. For Discord: Add your webhook URL to the config"
echo "4. For Email: Add SMTP credentials to the config"
echo ""
echo "To test manually:"
echo "  python3 ~/velociraptor-triage/alerter_daemon.py"
echo ""
echo "To view logs:"
echo "  tail -f ~/velociraptor-triage/alerts.log"
