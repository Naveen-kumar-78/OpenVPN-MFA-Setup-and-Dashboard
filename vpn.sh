#!/bin/bash
# ==========================================
# All-in-One Installer: Zubby VPN MFA Dashboard
# - Deploys modular Flask dashboard from vpn_dashboard/
# - Configures Python virtualenv and dependencies
# - Sets up non-interactive client management delegation via client.sh
# - Configures and enables systemd service (vpn_dashboard.service)
# ==========================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="/root/vpn_dashboard"
TEMPLATES_DIR="$APP_DIR/templates"
STATIC_DIR="$APP_DIR/static"
LOG_DIR="/var/log/openvpn"
DISABLED_LIST="/etc/openvpn/disabled_clients.txt"
SERVICE_FILE="/etc/systemd/system/vpn_dashboard.service"
VENV_DIR="$APP_DIR/venv"
PYTHON_BIN="$VENV_DIR/bin/python"
PIP_BIN="$VENV_DIR/bin/pip"
REQUIREMENTS_FILE="$APP_DIR/requirements.txt"

# Client management delegation
CLIENT_BIN="$APP_DIR/client.sh"
OUTPUT_DIR="/root/ovpn_clients"
QR_DIR="$OUTPUT_DIR/qr"
CLIENT_LOG="/var/log/openvpn/client_activity.log"
CONN_MASTER_LOG="/var/log/openvpn/custom_logs/master_connection_audit.log"

echo "=============================================="
echo "=== Zubby VPN Dashboard Installer Starting ==="
echo "=============================================="
echo "This installer will deploy the Zubby VPN Dashboard app to: $APP_DIR"
echo "Source directory: $SCRIPT_DIR"

if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root."
   exit 1
fi

# 1) Install system packages
echo "=== Updating apt and installing base packages ==="
apt-get update -y
apt-get install -y python3 python3-venv python3-pip curl qrencode git build-essential sqlite3 libsqlite3-dev

echo "=== Ensuring OpenVPN and easy-rsa packages are available ==="
apt-get install -y openvpn easy-rsa || echo "OpenVPN/easy-rsa already installed or managed separately - continuing"

# 2) Create required system directories
echo "=== Creating directories ==="
mkdir -p "$APP_DIR"
mkdir -p "$TEMPLATES_DIR"
mkdir -p "$STATIC_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "/etc/openvpn"
mkdir -p "$OUTPUT_DIR" "$QR_DIR" "/var/log/openvpn/custom_logs"
touch "$CLIENT_LOG" "$CONN_MASTER_LOG" "$DISABLED_LIST"
chmod 664 "$CLIENT_LOG" "$CONN_MASTER_LOG"
chmod 644 "$DISABLED_LIST"

# 3) Create python virtualenv and install python packages
echo "=== Setting up Python virtual environment ==="
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
fi
"$PIP_BIN" install --upgrade pip

if [ -f "$SCRIPT_DIR/vpn_dashboard/requirements.txt" ]; then
    cp "$SCRIPT_DIR/vpn_dashboard/requirements.txt" "$REQUIREMENTS_FILE"
    "$PIP_BIN" install -r "$REQUIREMENTS_FILE"
else
    cat > "$REQUIREMENTS_FILE" <<'REQ'
flask
flask-login
reportlab
psutil
pandas
gunicorn
werkzeug
REQ
    "$PIP_BIN" install -r "$REQUIREMENTS_FILE"
fi

# 4) Deploy Flask application files and templates
echo "=== Deploying application files from vpn_dashboard/ ==="
if [ -f "$SCRIPT_DIR/vpn_dashboard/app.py" ]; then
    cp "$SCRIPT_DIR/vpn_dashboard/app.py" "$APP_DIR/app.py"
else
    echo "Error: $SCRIPT_DIR/vpn_dashboard/app.py not found!"
    exit 1
fi

if [ -d "$SCRIPT_DIR/vpn_dashboard/templates" ]; then
    cp -r "$SCRIPT_DIR/vpn_dashboard/templates/"* "$TEMPLATES_DIR/"
else
    echo "Error: $SCRIPT_DIR/vpn_dashboard/templates directory not found!"
    exit 1
fi

# 5) Deploy client.sh for dashboard delegation
echo "=== Deploying client.sh delegation script ==="
if [ -f "$SCRIPT_DIR/client.sh" ]; then
    cp "$SCRIPT_DIR/client.sh" "$CLIENT_BIN"
    chmod +x "$CLIENT_BIN"
else
    echo "Warning: $SCRIPT_DIR/client.sh not found, checking existing $CLIENT_BIN"
    if [ ! -f "$CLIENT_BIN" ]; then
        echo "Error: client.sh not found in source or target directory!"
        exit 1
    fi
fi

# 6) Configure systemd service
echo "=== Creating systemd service file: $SERVICE_FILE ==="
cat > "$SERVICE_FILE" <<SERVICE
[Unit]
Description=Zubby VPN Dashboard Flask App with Client Management
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$APP_DIR
Environment="PATH=$VENV_DIR/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=$PYTHON_BIN $APP_DIR/app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE

# 7) Fix permissions & ownership
echo "=== Setting file permissions ==="
chmod 750 "$APP_DIR"
chmod 640 "$APP_DIR/app.py"
chmod -R 750 "$TEMPLATES_DIR"
chmod 640 "$REQUIREMENTS_FILE" || true
chmod 644 "$SERVICE_FILE"
chmod +x "$CLIENT_BIN"

# 8) Enable and start systemd service
echo "=== Reloading systemd and restarting service ==="
systemctl daemon-reload
systemctl enable vpn_dashboard.service
systemctl restart vpn_dashboard.service || echo "Service start failed; check journalctl -u vpn_dashboard.service"

echo "=============================================="
echo "=== Zubby VPN Dashboard Installation Done  ==="
echo "=============================================="
echo ""
echo "✓ Dashboard installed to: $APP_DIR"
echo "✓ Templates installed to: $TEMPLATES_DIR"
echo "✓ SQLite Database: /etc/openvpn/zubby_vpn.db"
echo "✓ Delegation client.sh: $CLIENT_BIN"
echo "✓ Service status: systemctl status vpn_dashboard.service"
echo "✓ Service logs: journalctl -u vpn_dashboard.service -f"
echo ""
echo "🌐 Access URL: http://<server-ip>:5000"
echo ""
echo "👤 Default Accounts:"
echo "   admin    / admin123    (full access)"
echo "   operator / operator123 (read-write)"
echo "   viewer   / viewer123   (read-only)"
echo ""
