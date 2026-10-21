#!/bin/bash
# ==========================================
# All-in-One Hardened Installer: Zubby VPN MFA Dashboard
# Security Enhancements:
# - Privilege Separation: Dashboard runs as unprivileged system daemon 'vpnadmin'
# - Linux Group Security: Uses 'openvpn' system group for DB and config sharing
# - Sudoers Whitelist: Strict NOPASSWD access restricted ONLY to /usr/local/bin/client.sh
# - Dedicated Storage: Standard /opt/vpn_dashboard application root
# - Client Profile Vault: /etc/openvpn/clients with group-read permissions
# - Production Gunicorn WSGI service with systemd auto-restart
# ==========================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="/opt/vpn_dashboard"
TEMPLATES_DIR="$APP_DIR/templates"
STATIC_DIR="$APP_DIR/static"
VENV_DIR="$APP_DIR/venv"
GUNICORN_BIN="$VENV_DIR/bin/gunicorn"
PIP_BIN="$VENV_DIR/bin/pip"
REQUIREMENTS_FILE="$APP_DIR/requirements.txt"
SERVICE_FILE="/etc/systemd/system/vpn_dashboard.service"
SUDOERS_FILE="/etc/sudoers.d/vpnadmin"

# System security user & group
VPN_USER="vpnadmin"
VPN_GROUP="openvpn"

# OpenVPN & Storage Directories
OPENVPN_DIR="/etc/openvpn"
DB_FILE="$OPENVPN_DIR/zubby_vpn.db"
CLIENTS_DIR="$OPENVPN_DIR/clients"
QR_DIR="$CLIENTS_DIR/qr"
MFA_DIR="$OPENVPN_DIR/mfa-secrets"
DISABLED_LIST="$OPENVPN_DIR/disabled_clients.txt"
SECRET_KEY_FILE="$OPENVPN_DIR/dashboard_secret.key"

LOG_DIR="/var/log/openvpn"
CLIENT_LOG="$LOG_DIR/client_activity.log"
CONN_MASTER_LOG="$LOG_DIR/custom_logs/master_connection_audit.log"
DASH_ACCESS_LOG="$LOG_DIR/dashboard_access.log"
DASH_ERROR_LOG="$LOG_DIR/dashboard_error.log"
DASH_AUDIT_LOG="$LOG_DIR/dashboard_audit.log"

GLOBAL_CLIENT_BIN="/usr/local/bin/client.sh"

echo "=========================================================="
echo "=== Zubby VPN Hardened Dashboard Installer Starting    ==="
echo "=========================================================="
echo "Target Application Directory: $APP_DIR"
echo "Daemon User: $VPN_USER (Group: $VPN_GROUP)"
echo "Source Directory: $SCRIPT_DIR"

if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root."
   exit 1
fi

# 1) Install system packages
echo "=== [1/9] Installing base system dependencies ==="
apt-get update -y
apt-get install -y python3 python3-venv python3-pip curl qrencode git build-essential sqlite3 libsqlite3-dev sudo

echo "=== Ensuring OpenVPN packages are available ==="
apt-get install -y openvpn easy-rsa || echo "OpenVPN already installed - continuing"

# 2) Create system group and unprivileged daemon user
echo "=== [2/9] Creating unprivileged service account: $VPN_USER ==="
groupadd -f "$VPN_GROUP"

if ! id -u "$VPN_USER" >/dev/null 2>&1; then
    useradd -r -M -s /usr/sbin/nologin -g "$VPN_GROUP" -c "Zubby VPN Dashboard Daemon" "$VPN_USER"
    echo "✓ Created system user '$VPN_USER' with no-login shell"
else
    usermod -aG "$VPN_GROUP" "$VPN_USER"
    echo "✓ User '$VPN_USER' already exists; ensured membership in group '$VPN_GROUP'"
fi

# 3) Setup Sudoers Privilege Delegation (Least Privilege Principle)
echo "=== [3/9] Configuring restricted sudoers whitelist ==="
mkdir -p /etc/sudoers.d
cat > "$SUDOERS_FILE" <<EOF_SUDO
# Security Hardening: Allow dashboard daemon ($VPN_USER) to execute client.sh ONLY
$VPN_USER ALL=(ALL) NOPASSWD: $GLOBAL_CLIENT_BIN
EOF_SUDO
chmod 440 "$SUDOERS_FILE"
if command -v visudo >/dev/null 2>&1; then
    visudo -cf "$SUDOERS_FILE" || { echo "Error: Invalid sudoers syntax in $SUDOERS_FILE"; exit 1; }
fi
echo "✓ Sudoers whitelist verified: $VPN_USER can execute $GLOBAL_CLIENT_BIN with NOPASSWD"

# 4) Deploy client.sh to system binary directory
echo "=== [4/9] Deploying $GLOBAL_CLIENT_BIN ==="
if [ -f "$SCRIPT_DIR/client.sh" ]; then
    cp "$SCRIPT_DIR/client.sh" "$GLOBAL_CLIENT_BIN"
elif [ -f "/root/vpn_dashboard/client.sh" ]; then
    cp "/root/vpn_dashboard/client.sh" "$GLOBAL_CLIENT_BIN"
fi
chmod 755 "$GLOBAL_CLIENT_BIN"
chown root:"$VPN_GROUP" "$GLOBAL_CLIENT_BIN"

# 5) Create required system directories & secure permissions
echo "=== [5/9] Setting up storage directories & group permissions ==="
mkdir -p "$APP_DIR" "$TEMPLATES_DIR" "$STATIC_DIR"
mkdir -p "$OPENVPN_DIR" "$CLIENTS_DIR" "$QR_DIR" "$MFA_DIR"
mkdir -p "$LOG_DIR/custom_logs"

# Symlink /root/ovpn_clients for backwards compatibility with root shell
ln -sfn "$CLIENTS_DIR" /root/ovpn_clients 2>/dev/null || true

# Touch all required files
touch "$CLIENT_LOG" "$CONN_MASTER_LOG" "$DISABLED_LIST"
touch "$DASH_ACCESS_LOG" "$DASH_ERROR_LOG" "$DASH_AUDIT_LOG"
touch "$SECRET_KEY_FILE"

# Grant group ownership to openvpn
chown -R root:"$VPN_GROUP" "$OPENVPN_DIR"
chown -R root:"$VPN_GROUP" "$CLIENTS_DIR" "$MFA_DIR"
chown -R root:"$VPN_GROUP" "$LOG_DIR"

# Directory permissions: openvpn group can traverse and write
chmod 775 "$OPENVPN_DIR"
chmod 775 "$CLIENTS_DIR" "$QR_DIR"
chmod 750 "$MFA_DIR"
chmod 775 "$LOG_DIR" "$LOG_DIR/custom_logs"

# File permissions
chmod 664 "$CLIENT_LOG" "$CONN_MASTER_LOG" "$DISABLED_LIST"
chmod 664 "$DASH_ACCESS_LOG" "$DASH_ERROR_LOG" "$DASH_AUDIT_LOG"

# Give vpnadmin write ownership for dashboard logs and secret key
chown "$VPN_USER":"$VPN_GROUP" "$DASH_ACCESS_LOG" "$DASH_ERROR_LOG" "$DASH_AUDIT_LOG" "$SECRET_KEY_FILE"
chmod 660 "$SECRET_KEY_FILE"

# SQLite DB permissions (allow vpnadmin to read/write without root)
if [ -f "$DB_FILE" ]; then
    chown root:"$VPN_GROUP" "$DB_FILE"* 2>/dev/null || true
    chmod 664 "$DB_FILE"* 2>/dev/null || true
fi

# 6) Ensure OpenVPN management socket and throughput tuning are active
echo "=== [6/9] Verifying OpenVPN server config optimizations ==="
NEED_RESTART=false
for cfg in /etc/openvpn/server/server.conf /etc/openvpn/server.conf; do
    if [ -f "$cfg" ]; then
        if ! grep -q "^management" "$cfg" 2>/dev/null; then
            echo "management 127.0.0.1 7505" >> "$cfg"
            echo "✅ Enabled OpenVPN management interface in $cfg"
            NEED_RESTART=true
        fi
        if ! grep -q "mssfix" "$cfg" 2>/dev/null; then
            echo -e "tun-mtu 1500\nmssfix 1420\nsndbuf 524288\nrcvbuf 524288\npush \"sndbuf 524288\"\npush \"rcvbuf 524288\"\npush \"block-outside-dns\"" >> "$cfg"
            echo "✅ Enabled high-speed MTU and buffer optimizations in $cfg"
            NEED_RESTART=true
        fi
    fi
done

# Ensure TCPMSS clamping rule is present in iptables
iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true

if [ "$NEED_RESTART" = true ]; then
    systemctl restart openvpn-server@server 2>/dev/null || systemctl restart openvpn 2>/dev/null || true
fi

# 7) Setup Python virtual environment & dependencies
echo "=== [7/9] Setting up Python virtual environment ==="
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
fi
"$PIP_BIN" install --upgrade pip

if [ -f "$SCRIPT_DIR/vpn_dashboard/requirements.txt" ]; then
    cp "$SCRIPT_DIR/vpn_dashboard/requirements.txt" "$REQUIREMENTS_FILE"
else
    cat > "$REQUIREMENTS_FILE" <<'REQ'
flask
flask-login
reportlab
psutil
pandas
openpyxl
gunicorn
werkzeug
REQ
fi
"$PIP_BIN" install -r "$REQUIREMENTS_FILE"

# 8) Deploy Flask application files & fix application ownership
echo "=== [8/9] Deploying application files to $APP_DIR ==="
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

# Also place a copy of client.sh in APP_DIR as secondary fallback
cp "$GLOBAL_CLIENT_BIN" "$APP_DIR/client.sh"
chmod 755 "$APP_DIR/client.sh"

# Transfer ownership of /opt/vpn_dashboard to vpnadmin:openvpn
chown -R "$VPN_USER":"$VPN_GROUP" "$APP_DIR"
chmod -R 750 "$APP_DIR"

# 9) Deploy systemd service running as vpnadmin
echo "=== [9/9] Configuring hardened systemd service: $SERVICE_FILE ==="
cat > "$SERVICE_FILE" <<SERVICE
[Unit]
Description=Zubby VPN Dashboard (Hardened WSGI via Gunicorn)
After=network.target openvpn.service openvpn-server@server.service

[Service]
Type=simple
User=$VPN_USER
Group=$VPN_GROUP
WorkingDirectory=$APP_DIR
Environment="PATH=$VENV_DIR/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=$GUNICORN_BIN --workers 3 --bind 0.0.0.0:5000 --timeout 90 --access-logfile $DASH_ACCESS_LOG --error-logfile $DASH_ERROR_LOG app:app
Restart=always
RestartSec=5
# Sudo execution requires NoNewPrivileges=false
NoNewPrivileges=false
ProtectSystem=full

[Install]
WantedBy=multi-user.target
SERVICE

chmod 644 "$SERVICE_FILE"

echo "=== Reloading systemd and restarting service ==="
systemctl daemon-reload
systemctl enable vpn_dashboard.service
systemctl restart vpn_dashboard.service || echo "Service start warning; check journalctl -u vpn_dashboard.service"

echo "=========================================================="
echo "=== Zubby VPN Hardened Dashboard Installation Complete ==="
echo "=========================================================="
echo ""
echo "🔒 Security Hardening Summary:"
echo "   • Service Daemon User  : $VPN_USER (Unprivileged, no-login shell)"
echo "   • Shared Access Group  : $VPN_GROUP"
echo "   • Sudoers Rule         : $VPN_USER ALL=(ALL) NOPASSWD: $GLOBAL_CLIENT_BIN"
echo "   • Application Root     : $APP_DIR (Owned by $VPN_USER:$VPN_GROUP)"
echo "   • Client Profiles Vault: $CLIENTS_DIR (Symlinked to /root/ovpn_clients)"
echo "   • Database Engine      : $DB_FILE (Group read/write enabled)"
echo ""
echo "✓ Service status: systemctl status vpn_dashboard.service"
echo "✓ Service logs  : journalctl -u vpn_dashboard.service -f"
echo ""
echo "🌐 Private Access URL: http://<server-private-or-vpn-ip>:5000"
echo ""
echo "👤 Default Web Admin Accounts:"
echo "   admin    / admin123    (full administrator)"
echo "   operator / operator123 (read-write manager)"
echo "   viewer   / viewer123   (read-only auditor)"
echo ""
