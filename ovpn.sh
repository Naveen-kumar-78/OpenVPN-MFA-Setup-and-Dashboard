#!/bin/bash
# ==========================================
# Script 1: OpenVPN + MFA Production Installation (Corrected)
# - Adds SES config placeholder
# - MFA failure handling: email alert at 3 fails, auto-revoke at 10 fails/day
# - Installs awscli, reportlab dependencies installed later in dashboard script
# ==========================================
set -e

echo "=== OpenVPN + MFA Production Installation Starting ==="

VPN_NET="10.8.0.0"
VPN_MASK="255.255.255.0"
VPN_PORT="1194"
VPN_PROTO="udp"
VPN_DIR="/etc/openvpn/server"
EASYRSA_DIR="$VPN_DIR/easy-rsa"
CLIENT_DIR="/root/ovpn_clients"
HOOKS_DIR="/etc/openvpn/hooks"
LOG_DIR="/var/log/openvpn"
CONN_LOG="$LOG_DIR/connection_audit.log"
MFA_LOG="$LOG_DIR/mfa_attempts.log"
STATUS_LOG="$LOG_DIR/status.log"
MFA_DIR="/etc/openvpn/mfa-secrets"
CLIENT_LOG="/var/log/openvpn/client_activity.log"
DB_FILE="/etc/openvpn/zubby_vpn.db"

DEFAULT_IFACE=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
[ -z "$DEFAULT_IFACE" ] && DEFAULT_IFACE=$(ip route | grep '^default' | awk '{print $5}' | head -n1)

apt-get update -y
apt-get install -y openvpn easy-rsa iptables iptables-persistent curl unzip qrencode oathtool jq sqlite3

# Install AWS CLI non-interactively if not already present
if ! command -v aws >/dev/null 2>&1; then
    echo "=== Installing AWS CLI v2 ==="
    cd /tmp
    curl -s "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip -q -o awscliv2.zip
    ./aws/install --update || ./aws/install
    rm -rf awscliv2.zip aws
else
    echo "=== AWS CLI is already installed ($(aws --version)) ==="
fi

timedatectl set-timezone Asia/Kolkata 2>/dev/null || true

mkdir -p $VPN_DIR $CLIENT_DIR $HOOKS_DIR $LOG_DIR $MFA_DIR

# Initialize SQLite database schema idempotently (WAL mode enabled)
if command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "$DB_FILE" <<'SQL_INIT'
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'readonly',
    email TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT DEFAULT 'system'
);
CREATE TABLE IF NOT EXISTS disabled_clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_name TEXT UNIQUE NOT NULL,
    reason TEXT DEFAULT 'Disabled by admin',
    disabled_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    disabled_by TEXT DEFAULT 'system'
);
CREATE TABLE IF NOT EXISTS connection_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    action TEXT NOT NULL,
    client_name TEXT NOT NULL,
    public_ip TEXT DEFAULT '-',
    vpn_ip TEXT DEFAULT '-',
    location TEXT DEFAULT '-',
    platform TEXT DEFAULT '-',
    duration TEXT DEFAULT '-'
);
CREATE TABLE IF NOT EXISTS mfa_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    username TEXT NOT NULL,
    status TEXT NOT NULL,
    details TEXT DEFAULT '',
    ip TEXT DEFAULT '-'
);
CREATE TABLE IF NOT EXISTS client_activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    action TEXT NOT NULL,
    client_name TEXT NOT NULL,
    details TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    level TEXT NOT NULL DEFAULT 'INFO',
    action TEXT NOT NULL,
    details TEXT DEFAULT '',
    user TEXT DEFAULT 'system'
);
CREATE TABLE IF NOT EXISTS active_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_name TEXT UNIQUE NOT NULL,
    public_ip TEXT DEFAULT '-',
    vpn_ip TEXT DEFAULT '-',
    location TEXT DEFAULT '-',
    platform TEXT DEFAULT '-',
    connected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_conn_time ON connection_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_conn_client ON connection_logs(client_name);
CREATE INDEX IF NOT EXISTS idx_mfa_user_time ON mfa_logs(username, timestamp);
CREATE INDEX IF NOT EXISTS idx_mfa_status ON mfa_logs(status);
CREATE INDEX IF NOT EXISTS idx_client_act_time ON client_activity(timestamp);
PRAGMA journal_mode=WAL;
SQL_INIT
    chmod 660 "$DB_FILE" 2>/dev/null || true
fi

# Enable IP forwarding and kernel network optimizations for high-throughput VPN
mkdir -p /etc/sysctl.d
cat > /etc/sysctl.d/99-openvpn.conf <<'SYSCTL'
net.ipv4.ip_forward = 1
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
SYSCTL
if [ -f /etc/sysctl.conf ]; then
    sed -i 's/^#*net.ipv4.ip_forward=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf || true
fi
sysctl -p /etc/sysctl.d/99-openvpn.conf >/dev/null 2>&1 || sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

# Setup NAT iptables rule and TCPMSS clamping (prevents packet fragmentation & speed drops)
if [ -n "$DEFAULT_IFACE" ]; then
    iptables -t nat -C POSTROUTING -s "$VPN_NET/$VPN_MASK" -o "$DEFAULT_IFACE" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s "$VPN_NET/$VPN_MASK" -o "$DEFAULT_IFACE" -j MASQUERADE

    iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
    iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

    netfilter-persistent save 2>/dev/null || true
fi

# Setup PKI (idempotent - preserves existing keys if already generated)
if [ ! -d "$EASYRSA_DIR" ]; then
    make-cadir $EASYRSA_DIR
fi
cd $EASYRSA_DIR

if [ ! -d "pki" ]; then
    ./easyrsa init-pki
    EASYRSA_BATCH=1 ./easyrsa build-ca nopass
    EASYRSA_BATCH=1 ./easyrsa gen-dh
    EASYRSA_BATCH=1 ./easyrsa build-server-full server nopass
    EASYRSA_BATCH=1 ./easyrsa gen-crl
fi

if [ ! -f "$VPN_DIR/tc.key" ]; then
    openvpn --genkey secret $VPN_DIR/tc.key
fi

# Copy keys
cp -f pki/ca.crt $VPN_DIR/ 2>/dev/null || true
cp -f pki/issued/server.crt $VPN_DIR/ 2>/dev/null || true
cp -f pki/private/server.key $VPN_DIR/ 2>/dev/null || true
cp -f pki/dh.pem $VPN_DIR/ 2>/dev/null || true
cp -f pki/crl.pem $VPN_DIR/ 2>/dev/null || true

# Create server.conf
cat > $VPN_DIR/server.conf <<EOF
port $VPN_PORT
proto $VPN_PROTO
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
cipher AES-256-GCM
tls-crypt tc.key
topology subnet
server $VPN_NET $VPN_MASK
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 1.1.1.1"
keepalive 10 120
inactive 300
persist-key
persist-tun
tun-mtu 1500
mssfix 1420
sndbuf 524288
rcvbuf 524288
push "sndbuf 524288"
push "rcvbuf 524288"
push "block-outside-dns"
management 127.0.0.1 7505
auth-user-pass-verify /etc/openvpn/mfa-verify.sh via-env
script-security 3
verify-client-cert optional
username-as-common-name
status $STATUS_LOG 30
status-version 3
log-append $LOG_DIR/openvpn.log
client-connect $HOOKS_DIR/connect.sh
client-disconnect $HOOKS_DIR/disconnect.sh
verb 3
crl-verify crl.pem
explicit-exit-notify
EOF

# SES config placeholder
SES_CONF="/etc/openvpn/ses_config"
cat > "$SES_CONF" <<'EOF'
# Edit this file with your AWS SES settings.
# Keep file permissions to 600.
# Example:
# AWS_REGION=us-east-1
# AWS_ACCESS_KEY_ID=AKIA...
# AWS_SECRET_ACCESS_KEY=...
# ALERT_FROM=alerts@example.com   # must be a verified SES sender
# ALERT_TO=admin@example.com      # recipient (can be same)

AWS_REGION=
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
ALERT_FROM=
ALERT_TO=
EOF
chmod 600 "$SES_CONF"

# MFA script with SES alert + auto-revoke logic
cat > /etc/openvpn/mfa-verify.sh <<'EOF'
#!/bin/bash
# ==========================================
# MFA Verification + Pre-auth Disabled-User Check
# - Disabled users blocked immediately
# - Send SES alert after 3 fails
# - Disable user after 10 fails within 3 minutes
# - Kick active sessions immediately
# - SQLite integrated with flat-file fallback
# - DRY_RUN mode supported
# ==========================================

USER="$username"
# Sanitize username (remove spaces, force lowercase)
USER=$(echo "$username" | sed 's/[\r\n\t ]//g' | tr '[:upper:]' '[:lower:]')
PASS="$password"
CLIENT_IP="${untrusted_ip:-${trusted_ip:--}}"

DB_FILE="/etc/openvpn/zubby_vpn.db"
SECRET_FILE="/etc/openvpn/mfa-secrets/$USER.secret"
LOG_FILE="/var/log/openvpn/mfa_attempts.log"
SES_CONF="/etc/openvpn/ses_config"
ALERT_LOG="/var/log/openvpn/mfa_alerts.log"
EMAIL_LOG="/var/log/openvpn/mfa_emails.log"
CLEANUP_LOG="/var/log/openvpn/mfa_cleanup.log"
CLIENT_LOG="/var/log/openvpn/client_activity.log"
DISABLED_LIST="/etc/openvpn/disabled_clients.txt"
KICK_CMD="/usr/bin/pkill"  # adjust if needed

# Ensure directories and files exist
mkdir -p "$(dirname "$LOG_FILE")" "$(dirname "$ALERT_LOG")" "$(dirname "$EMAIL_LOG")" "$(dirname "$CLEANUP_LOG")" "$(dirname "$CLIENT_LOG")"
touch "$LOG_FILE" "$ALERT_LOG" "$EMAIL_LOG" "$CLEANUP_LOG" "$CLIENT_LOG" "$DISABLED_LIST"
chmod 600 "$LOG_FILE" "$ALERT_LOG" "$EMAIL_LOG" "$CLEANUP_LOG"
chmod 644 "$DISABLED_LIST"

TIME=$(date '+%Y-%m-%d %H:%M:%S')
DATE_ONLY=$(date +%F)

# Load SES config if exists
if [ -f "$SES_CONF" ]; then
  . "$SES_CONF"
  export AWS_REGION AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY ALERT_FROM ALERT_TO
fi

# -------------------- Function: Escape JSON safely --------------------
json_escape() {
    echo "$1" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read())[1:-1])'
}

# -------------------- Function: Send HTML Email --------------------
send_html_email() {
    local SUBJECT_ESCAPED
    local BODY_ESCAPED
    SUBJECT_ESCAPED=$(json_escape "$1")
    BODY_ESCAPED=$(json_escape "$2")

    local JSON
    JSON=$(cat <<EOF_JSON
{
  "Source": "$ALERT_FROM",
  "Destination": { "ToAddresses": ["$ALERT_TO"] },
  "Message": {
    "Subject": { "Data": "$SUBJECT_ESCAPED" },
    "Body": { "Html": { "Data": "$BODY_ESCAPED" } }
  }
}
EOF_JSON
)

    echo "---- SES JSON ----" >> "$EMAIL_LOG"
    echo "$JSON" >> "$EMAIL_LOG"

    /usr/local/bin/aws ses send-email \
      --region "$AWS_REGION" \
      --cli-input-json "$JSON" >> "$EMAIL_LOG" 2>&1 || true
}

# -------------------- DRY RUN MODE --------------------
if [ "$3" == "DRY_RUN" ]; then
    STATUS="$2"
    echo "$TIME,DRYRUN,$USER,$STATUS" >> "$ALERT_LOG"
    SUBJECT="📢 MFA Dry-Run: $USER $STATUS"
    BODY_HTML="<html><body style='font-family:Arial,sans-serif;'>
    <h2 style='color:#0066cc;'>MFA Dry-Run Notification</h2>
    <p><b>User:</b> $USER</p>
    <p><b>Status:</b> $STATUS</p>
    <p><b>Time:</b> $TIME</p>
    <p style='color:green;'>No action required. This is a test notification.</p>
    </body></html>"
    if [ -n "$ALERT_FROM" ] && [ -n "$ALERT_TO" ]; then
        send_html_email "$SUBJECT" "$BODY_HTML"
    fi
    exit 0
fi

# -------------------- Pre-auth: Block if disabled --------------------
IS_DISABLED=0
if command -v sqlite3 >/dev/null 2>&1 && [ -f "$DB_FILE" ]; then
    IS_DISABLED=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM disabled_clients WHERE client_name='$USER';" 2>/dev/null || echo 0)
fi

if [ "$IS_DISABLED" -gt 0 ] || grep -q "^$USER$" "$DISABLED_LIST" 2>/dev/null; then
    echo "$TIME,$USER,BLOCKED_DISABLED" >> "$LOG_FILE"
    echo "$TIME,LOGIN_BLOCKED,$USER,Disabled user attempted login" >> "$CLIENT_LOG"
    if command -v sqlite3 >/dev/null 2>&1 && [ -f "$DB_FILE" ]; then
        sqlite3 "$DB_FILE" "INSERT INTO mfa_logs (timestamp, username, status, details, ip) VALUES ('$TIME', '$USER', 'BLOCKED_DISABLED', 'Disabled user attempted login', '$CLIENT_IP');" 2>/dev/null || true
        sqlite3 "$DB_FILE" "INSERT INTO client_activity (timestamp, action, client_name, details) VALUES ('$TIME', 'LOGIN_BLOCKED', '$USER', 'Disabled user attempted login');" 2>/dev/null || true
    fi
    exit 1
fi

# -------------------- Normal MFA validation --------------------
if [[ -z "$USER" || -z "$PASS" ]]; then
    echo "$TIME,unknown_user,missing_credentials" >> "$LOG_FILE"
    exit 1
fi

if [[ ! -f "$SECRET_FILE" ]]; then
    echo "$TIME,$USER,user_not_found" >> "$LOG_FILE"
    exit 1
fi

SECRET=$(cat "$SECRET_FILE")

if oathtool --totp -b -w 2 "$SECRET" | grep -qx "$PASS"; then
    echo "$TIME,$USER,SUCCESS" >> "$LOG_FILE"
    echo "$TIME,LOGIN_ALLOWED,$USER,Login permitted" >> "$CLIENT_LOG"
    if command -v sqlite3 >/dev/null 2>&1 && [ -f "$DB_FILE" ]; then
        sqlite3 "$DB_FILE" "INSERT INTO mfa_logs (timestamp, username, status, details, ip) VALUES ('$TIME', '$USER', 'SUCCESS', 'Login permitted', '$CLIENT_IP');" 2>/dev/null || true
        sqlite3 "$DB_FILE" "INSERT INTO client_activity (timestamp, action, client_name, details) VALUES ('$TIME', 'LOGIN_ALLOWED', '$USER', 'Login permitted');" 2>/dev/null || true
    fi
    exit 0
else
    echo "$TIME,$USER,FAIL" >> "$LOG_FILE"
    echo "$TIME,LOGIN_FAIL,$USER,Incorrect MFA" >> "$CLIENT_LOG"
    if command -v sqlite3 >/dev/null 2>&1 && [ -f "$DB_FILE" ]; then
        sqlite3 "$DB_FILE" "INSERT INTO mfa_logs (timestamp, username, status, details, ip) VALUES ('$TIME', '$USER', 'FAIL', 'Incorrect MFA', '$CLIENT_IP');" 2>/dev/null || true
        sqlite3 "$DB_FILE" "INSERT INTO client_activity (timestamp, action, client_name, details) VALUES ('$TIME', 'LOGIN_FAIL', '$USER', 'Incorrect MFA');" 2>/dev/null || true
    fi

    # -------------------- Count fails within 3 minutes --------------------
    RECENT_FAIL_COUNT=0
    if command -v sqlite3 >/dev/null 2>&1 && [ -f "$DB_FILE" ]; then
        RECENT_FAIL_COUNT=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM mfa_logs WHERE username='$USER' AND status='FAIL' AND timestamp >= datetime('now', '-3 minutes');" 2>/dev/null || echo 0)
    fi
    if [[ -z "$RECENT_FAIL_COUNT" || "$RECENT_FAIL_COUNT" -eq 0 ]]; then
        CUTOFF_EPOCH=$(date -d '3 minutes ago' +%s 2>/dev/null || echo 0)
        RECENT_FAIL_COUNT=$(awk -F, -v user="$USER" -v cutoff="$CUTOFF_EPOCH" '
            function toepoch(dt,    cmd,r){ gsub(/^[ \t]+|[ \t]+$/,"",dt); cmd="date -d \"" dt "\" +%s"; cmd | getline r; close(cmd); if(r ~ /^[0-9]+$/) return r; return 0 }
            $2==user && $3=="FAIL"{t=toepoch($1); if(t>=cutoff) count++}
            END{print (count+0)}' "$LOG_FILE")
    fi

    # -------------------- SES Alert after 3 fails today (SQLite SSOT) --------------------
    FAIL_COUNT_TODAY=0
    if command -v sqlite3 >/dev/null 2>&1 && [ -f "$DB_FILE" ]; then
        FAIL_COUNT_TODAY=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM mfa_logs WHERE username='$USER' AND status='FAIL' AND timestamp >= '$DATE_ONLY 00:00:00';" 2>/dev/null || echo 0)
    fi
    if [ "$FAIL_COUNT_TODAY" -eq 0 ] && [ -f "$LOG_FILE" ]; then
        FAIL_COUNT_TODAY=$(grep "^$DATE_ONLY" "$LOG_FILE" 2>/dev/null | grep ",$USER,FAIL" | wc -l || echo 0)
    fi
    if [ "$FAIL_COUNT_TODAY" -eq 3 ]; then
        SUBJECT="⚠️ MFA Alert: $USER failed MFA ($FAIL_COUNT_TODAY times today)"
        BODY_HTML="<html><body style='font-family:Arial,sans-serif;'>
        <h2 style='color:#cc0000;'>&#9888; MFA Alert</h2>
        <p>User <b>$USER</b> failed MFA multiple times.</p>
        <ul>
          <li><b>Failed Attempts Today:</b> $FAIL_COUNT_TODAY</li>
          <li><b>Time:</b> $TIME</li>
        </ul>
        </body></html>"
        [ -n "$ALERT_FROM" ] && [ -n "$ALERT_TO" ] && send_html_email "$SUBJECT" "$BODY_HTML"
        echo "$TIME,$USER,SES_TRIGGER,FAIL_COUNT_TODAY=$FAIL_COUNT_TODAY" >> "$ALERT_LOG"
    fi

    # -------------------- Disable user after 10 fails within 3 minutes --------------------
    if [ "$RECENT_FAIL_COUNT" -ge 10 ]; then
        echo "$TIME,$USER,DISABLE_TRIGGER,RECENT_FAILS=$RECENT_FAIL_COUNT" >> "$ALERT_LOG"
        if ! grep -q "^$USER$" "$DISABLED_LIST"; then
            echo "$USER" >> "$DISABLED_LIST"
            echo "$TIME,DISABLED,$USER" >> "$CLIENT_LOG"
        fi
        if command -v sqlite3 >/dev/null 2>&1 && [ -f "$DB_FILE" ]; then
            sqlite3 "$DB_FILE" "INSERT OR IGNORE INTO disabled_clients (client_name, reason, disabled_at, disabled_by) VALUES ('$USER', 'Exceeded 10 failed MFA attempts within 3 minutes', '$TIME', 'system');" 2>/dev/null || true
            sqlite3 "$DB_FILE" "INSERT INTO client_activity (timestamp, action, client_name, details) VALUES ('$TIME', 'DISABLED', '$USER', 'Auto-disabled due to excessive MFA failures');" 2>/dev/null || true
        fi

        # Kick active sessions via OpenVPN management interface
        python3 -c "import socket; s=socket.socket(); s.settimeout(2); s.connect(('127.0.0.1', 7505)); s.recv(1024); s.sendall(f'kill $USER\r\nquit\r\n'.encode()); s.close()" 2>/dev/null || true
        echo "$TIME,KICKED,$USER" >> "$CLIENT_LOG"
        if command -v sqlite3 >/dev/null 2>&1 && [ -f "$DB_FILE" ]; then
            sqlite3 "$DB_FILE" "DELETE FROM active_sessions WHERE client_name='$USER';" 2>/dev/null || true
            sqlite3 "$DB_FILE" "INSERT INTO client_activity (timestamp, action, client_name, details) VALUES ('$TIME', 'KICKED', '$USER', 'Active sessions terminated');" 2>/dev/null || true
        fi

        SUBJECT="❌ VPN Access Disabled: $USER (auto-disabled)"
        BODY_HTML="<html><body style='font-family:Arial,sans-serif;'>
        <h2 style='color:#cc0000;'>&#9940; VPN Access Disabled</h2>
        <p>User <b>$USER</b> has been <b>disabled</b> after $RECENT_FAIL_COUNT failed MFA attempts within 3 minutes.</p>
        <p><b>Time:</b> $TIME</p>
        <p>This user will remain disabled until manually re-enabled.</p>
        </body></html>"
        [ -n "$ALERT_FROM" ] && [ -n "$ALERT_TO" ] && send_html_email "$SUBJECT" "$BODY_HTML"

        exit 1
    fi

    # Normal failure
    exit 1
fi
EOF
chmod 750 /etc/openvpn/mfa-verify.sh
chown root:root /etc/openvpn/mfa-verify.sh

# Hooks with dual file & SQLite logging
cat > $HOOKS_DIR/connect.sh <<'EOF'
#!/bin/bash
# OpenVPN connect hook — writes to SQLite + master + daily logs
LOG_DIR="/var/log/openvpn/custom_logs"
MASTER_LOG="$LOG_DIR/master_connection_audit.log"
DAILY_LOG="$LOG_DIR/$(date +%F).log"
DB_FILE="/etc/openvpn/zubby_vpn.db"

mkdir -p "$LOG_DIR"

CLIENT="${common_name:--}"
REAL_IP="${trusted_ip:--}"
VPN_IP="${ifconfig_pool_remote_ip:--}"
PLATFORM="${IV_PLAT:--}"
TIME="$(date '+%Y-%m-%d %H:%M:%S')"

LOCATION="-"
if [ -n "$REAL_IP" ] && [ "$REAL_IP" != "-" ]; then
  LOC_RAW=$(curl -s "http://ip-api.com/json/$REAL_IP" 2>/dev/null)
  if command -v jq >/dev/null 2>&1; then
    LOCATION=$(echo "$LOC_RAW" | jq -r '"\(.city)-\(.country)"' 2>/dev/null)
    if [ -z "$LOCATION" ] || [ "$LOCATION" = "null-null" ]; then
      LOCATION="-"
    fi
  else
    LOCATION="-"
  fi
fi

LOG_ENTRY="$TIME,CONNECTED via MFA,$CLIENT,$REAL_IP,$VPN_IP,$LOCATION,$PLATFORM,-"

echo "$LOG_ENTRY" >> "$MASTER_LOG"
echo "$LOG_ENTRY" >> "$DAILY_LOG"
echo "$LOG_ENTRY" >> /var/log/openvpn/connection_audit.log 2>/dev/null || true

# SQLite logging & active session tracking
if command -v sqlite3 >/dev/null 2>&1 && [ -f "$DB_FILE" ]; then
    sqlite3 "$DB_FILE" "INSERT INTO connection_logs (timestamp, action, client_name, public_ip, vpn_ip, location, platform, duration) VALUES ('$TIME', 'CONNECTED via MFA', '$CLIENT', '$REAL_IP', '$VPN_IP', '$LOCATION', '$PLATFORM', '-');" 2>/dev/null || true
    sqlite3 "$DB_FILE" "INSERT OR REPLACE INTO active_sessions (client_name, public_ip, vpn_ip, location, platform, connected_at, last_seen) VALUES ('$CLIENT', '$REAL_IP', '$VPN_IP', '$LOCATION', '$PLATFORM', '$TIME', '$TIME');" 2>/dev/null || true
fi

exit 0
EOF

cat > $HOOKS_DIR/disconnect.sh <<'EOF'
#!/bin/bash
# OpenVPN disconnect hook — calculates duration, writes to SQLite + master + daily logs
LOG_DIR="/var/log/openvpn/custom_logs"
MASTER_LOG="$LOG_DIR/master_connection_audit.log"
DAILY_LOG="$LOG_DIR/$(date +%F).log"
DB_FILE="/etc/openvpn/zubby_vpn.db"

mkdir -p "$LOG_DIR"

CLIENT="${common_name:--}"
REAL_IP="${trusted_ip:--}"
VPN_IP="${ifconfig_pool_remote_ip:--}"
PLATFORM="${IV_PLAT:--}"
TIME="$(date '+%Y-%m-%d %H:%M:%S')"

# Calculate duration using SQLite active_sessions first, falling back to master log
START_TIME=""
if command -v sqlite3 >/dev/null 2>&1 && [ -f "$DB_FILE" ]; then
    START_TIME=$(sqlite3 "$DB_FILE" "SELECT connected_at FROM active_sessions WHERE client_name='$CLIENT' ORDER BY id DESC LIMIT 1;" 2>/dev/null || echo "")
fi
if [ -z "$START_TIME" ]; then
    CONNECT_LINE=$(grep "CONNECTED via MFA,$CLIENT,$REAL_IP,$VPN_IP" "$MASTER_LOG" 2>/dev/null | tail -n 1)
    if [ -n "$CONNECT_LINE" ]; then
        START_TIME=$(echo "$CONNECT_LINE" | cut -d',' -f1)
    fi
fi

if [ -n "$START_TIME" ]; then
    START_TS=$(date -d "$START_TIME" +%s 2>/dev/null || echo "")
    END_TS=$(date -d "$TIME" +%s 2>/dev/null || echo "")
    if [ -n "$START_TS" ] && [ -n "$END_TS" ]; then
        DURATION_SEC=$((END_TS - START_TS))
        DURATION_FMT=$(printf '%02d:%02d:%02d' $((DURATION_SEC/3600)) $((DURATION_SEC%3600/60)) $((DURATION_SEC%60)))
    else
        DURATION_FMT="N/A"
    fi
else
    DURATION_FMT="N/A"
fi

LOG_ENTRY="$TIME,DISCONNECT,$CLIENT,$REAL_IP,$VPN_IP,-,$PLATFORM,$DURATION_FMT"

echo "$LOG_ENTRY" >> "$MASTER_LOG"
echo "$LOG_ENTRY" >> "$DAILY_LOG"
echo "$LOG_ENTRY" >> /var/log/openvpn/connection_audit.log 2>/dev/null || true

# SQLite logging & active session cleanup
if command -v sqlite3 >/dev/null 2>&1 && [ -f "$DB_FILE" ]; then
    sqlite3 "$DB_FILE" "INSERT INTO connection_logs (timestamp, action, client_name, public_ip, vpn_ip, location, platform, duration) VALUES ('$TIME', 'DISCONNECT', '$CLIENT', '$REAL_IP', '$VPN_IP', '-', '$PLATFORM', '$DURATION_FMT');" 2>/dev/null || true
    sqlite3 "$DB_FILE" "DELETE FROM active_sessions WHERE client_name='$CLIENT';" 2>/dev/null || true
fi

exit 0
EOF
# (keeping your connect.sh / disconnect.sh code unchanged)

chmod +x $HOOKS_DIR/*.sh
touch $CONN_LOG $MFA_LOG $CLIENT_LOG
chmod 664 $CONN_LOG $MFA_LOG $CLIENT_LOG

systemctl enable openvpn-server@server || true
systemctl restart openvpn-server@server
systemctl status --no-pager openvpn-server@server || true

echo "=== OpenVPN + MFA Production Setup Completed ==="
echo "IMPORTANT: Edit $SES_CONF with your AWS SES credentials and verified sender/recipient."
