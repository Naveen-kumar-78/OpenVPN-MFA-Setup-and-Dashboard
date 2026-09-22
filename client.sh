#!/bin/bash
# ==========================================
# Script: Zubby VPN Client Management with Access Control & SQLite Integration
# - Uses client-connect script to block disabled users from connecting
# - Updates SQLite database (zubby_vpn.db) and flat files for dual compatibility
# - Supports both interactive menu and non-interactive CLI flags
# ==========================================

EASYRSA_DIR="/etc/openvpn/server/easy-rsa"
OUTPUT_DIR="/root/ovpn_clients"
MFA_DIR="/etc/openvpn/mfa-secrets"
QR_DIR="$OUTPUT_DIR/qr"
DISABLED_LIST="/etc/openvpn/disabled_clients.txt"
CLIENT_CONNECT_SCRIPT="/etc/openvpn/scripts/client-connect.sh"
SCRIPT_DIR="/etc/openvpn/scripts"
SERVER_IP=$(curl -s ifconfig.me || echo "SERVER_IP_HERE")
PORT="1194"
PROTO="udp"
CLIENT_LOG="/var/log/openvpn/client_activity.log"
OPENVPN_CONFIG="/etc/openvpn/server/server.conf"
DB_FILE="/etc/openvpn/zubby_vpn.db"

# Ensure directories and files exist with proper permissions
mkdir -p "$OUTPUT_DIR" "$MFA_DIR" "$QR_DIR" "$SCRIPT_DIR"
touch "$CLIENT_LOG" "$DISABLED_LIST"
chmod 664 "$CLIENT_LOG"
chmod 644 "$DISABLED_LIST"

# Helper for SQLite logging
db_execute() {
    local SQL="$1"
    if command -v sqlite3 >/dev/null 2>&1 && [ -f "$DB_FILE" ]; then
        sqlite3 "$DB_FILE" "$SQL" 2>/dev/null || true
    fi
}

check_expect_available() {
    command -v expect >/dev/null 2>&1
}

# Create the client-connect script that blocks disabled users
setup_client_connect_script() {
    cat > "$CLIENT_CONNECT_SCRIPT" <<'CONNECT_EOF'
#!/bin/bash
# OpenVPN Client Connect Script - Blocks disabled users
DISABLED_LIST="/etc/openvpn/disabled_clients.txt"
LOG_FILE="/var/log/openvpn/client_activity.log"
DB_FILE="/etc/openvpn/zubby_vpn.db"
CLIENT_NAME="$common_name"
TIME=$(date '+%Y-%m-%d %H:%M:%S')

# Check SQLite first if available
IS_DISABLED=0
if command -v sqlite3 >/dev/null 2>&1 && [ -f "$DB_FILE" ]; then
    IS_DISABLED=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM disabled_clients WHERE client_name='$CLIENT_NAME';" 2>/dev/null || echo 0)
fi

if [ "$IS_DISABLED" -gt 0 ] || grep -q "^$CLIENT_NAME$" "$DISABLED_LIST" 2>/dev/null; then
    echo "$TIME,CONNECTION_BLOCKED,$CLIENT_NAME,Disabled user attempted connection" >> "$LOG_FILE"
    if command -v sqlite3 >/dev/null 2>&1 && [ -f "$DB_FILE" ]; then
        sqlite3 "$DB_FILE" "INSERT INTO client_activity (timestamp, action, client_name, details) VALUES ('$TIME', 'CONNECTION_BLOCKED', '$CLIENT_NAME', 'Disabled user attempted connection');" 2>/dev/null || true
    fi
    exit 1
fi

echo "$TIME,CONNECTION_ALLOWED,$CLIENT_NAME,Active user connected" >> "$LOG_FILE"
if command -v sqlite3 >/dev/null 2>&1 && [ -f "$DB_FILE" ]; then
    sqlite3 "$DB_FILE" "INSERT INTO client_activity (timestamp, action, client_name, details) VALUES ('$TIME', 'CONNECTION_ALLOWED', '$CLIENT_NAME', 'Active user connected');" 2>/dev/null || true
fi
exit 0
CONNECT_EOF

    chmod +x "$CLIENT_CONNECT_SCRIPT"

    # Add client-connect and management directives to OpenVPN server config if not already present
    for cfg in /etc/openvpn/server/server.conf /etc/openvpn/server.conf "$OPENVPN_CONFIG"; do
        if [ -f "$cfg" ]; then
            if ! grep -q "^management" "$cfg" 2>/dev/null; then
                echo "management 127.0.0.1 7505" >> "$cfg"
                echo "✅ Added management 127.0.0.1 7505 to $cfg"
            fi
            if ! grep -q "client-connect" "$cfg" 2>/dev/null; then
                echo "script-security 2" >> "$cfg"
                echo "client-connect $CLIENT_CONNECT_SCRIPT" >> "$cfg"
                echo "✅ Added client-connect script to $cfg"
            fi
        fi
    done
}

add_client() {
    if [[ -n "$1" ]]; then
        CLIENT="$1"
        SILENT=true
    else
        read -r -p "Enter client name: " CLIENT
        SILENT=false
    fi

    # Validate client name (alphanumeric, dot, hyphen, underscore)
    if [[ ! "$CLIENT" =~ ^[a-zA-Z0-9._-]+$ ]]; then
        echo "Error: Invalid client name. Use only letters, numbers, dots, hyphens, and underscores."
        return 1
    fi

    # Check if client already exists
    if [[ -f "$OUTPUT_DIR/$CLIENT.ovpn" ]] || [[ -f "$EASYRSA_DIR/pki/issued/$CLIENT.crt" ]]; then
        echo "Error: Client $CLIENT already exists"
        return 1
    fi

    # Remove from disabled list if present
    sed -i "/^$CLIENT$/d" "$DISABLED_LIST" 2>/dev/null || true
    db_execute "DELETE FROM disabled_clients WHERE client_name='$CLIENT';"

    cd "$EASYRSA_DIR" || {
        echo "Error: Cannot access EasyRSA directory $EASYRSA_DIR"
        return 1
    }

    if [[ "$SILENT" == true ]]; then
        if check_expect_available; then
            expect -c "
            spawn ./easyrsa build-client-full $CLIENT nopass
            expect \"Type the word 'yes'\" { send \"yes\r\" }
            expect \"Confirm request details:\" { send \"yes\r\" }
            expect eof
            " >/dev/null 2>&1
        else
            printf "yes\nyes\n" | timeout 60 ./easyrsa build-client-full "$CLIENT" nopass >/dev/null 2>&1
        fi

        if [[ ! -f "$EASYRSA_DIR/pki/issued/$CLIENT.crt" ]]; then
            echo "Error: Certificate creation failed"
            return 1
        fi
    else
        ./easyrsa build-client-full "$CLIENT" nopass || {
            echo "Error: Certificate creation failed"
            return 1
        }
    fi

    CLIENT_FILE="$OUTPUT_DIR/$CLIENT.ovpn"

    if [[ ! -f "$EASYRSA_DIR/pki/ca.crt" ]]; then
        echo "Error: CA certificate not found"
        return 1
    fi

    if [[ ! -f "$EASYRSA_DIR/pki/issued/$CLIENT.crt" ]]; then
        echo "Error: Client certificate not found"
        return 1
    fi

    if [[ ! -f "$EASYRSA_DIR/pki/private/$CLIENT.key" ]]; then
        echo "Error: Client private key not found"
        return 1
    fi

    cat > "$CLIENT_FILE" <<EOF
client
dev tun
proto $PROTO
remote $SERVER_IP $PORT
resolv-retry infinite
nobind
persist-key
persist-tun
tun-mtu 1500
mssfix 1420
remote-cert-tls server
auth SHA512
cipher AES-256-GCM
auth-user-pass
verb 3
<ca>
$(cat "$EASYRSA_DIR/pki/ca.crt")
</ca>
<cert>
$(sed -ne '/BEGIN CERTIFICATE/,$p' "$EASYRSA_DIR/pki/issued/$CLIENT.crt")
</cert>
<key>
$(cat "$EASYRSA_DIR/pki/private/$CLIENT.key")
</key>
EOF

    if [[ -f "/etc/openvpn/server/tc.key" ]]; then
        cat >> "$CLIENT_FILE" <<EOF
<tls-crypt>
$(cat /etc/openvpn/server/tc.key)
</tls-crypt>
EOF
    fi

    chmod 600 "$CLIENT_FILE"

    # Generate MFA secret
    SECRET=$(head /dev/urandom | tr -dc A-Z2-7 | head -c 16)
    echo "$SECRET" > "$MFA_DIR/$CLIENT.secret"
    chmod 600 "$MFA_DIR/$CLIENT.secret"

    # Generate QR code
    if command -v qrencode >/dev/null 2>&1; then
        qrencode -o "$QR_DIR/${CLIENT}_mfa.png" "otpauth://totp/$CLIENT?secret=$SECRET&issuer=ZubbyVPN" 2>/dev/null || true
    fi

    TIME=$(date '+%Y-%m-%d %H:%M:%S')
    echo "$TIME,CREATED,$CLIENT" >> "$CLIENT_LOG"
    db_execute "INSERT INTO client_activity (timestamp, action, client_name, details) VALUES ('$TIME', 'CREATED', '$CLIENT', 'Client created successfully');"

    if [[ "$SILENT" == false ]]; then
        echo "✅ Client added: $CLIENT"
        echo "📂 Config file: $CLIENT_FILE"
        echo "📱 MFA QR code: $QR_DIR/${CLIENT}_mfa.png"
    else
        echo "Client $CLIENT created successfully"
    fi
    return 0
}

revoke_client() {
    if [[ -n "$1" ]]; then
        CLIENT="$1"
        SILENT=true
    else
        read -r -p "Enter client name: " CLIENT
        SILENT=false
    fi

    cd "$EASYRSA_DIR" || {
        echo "Error: Cannot access EasyRSA directory"
        return 1
    }

    if [[ ! -f "$EASYRSA_DIR/pki/issued/$CLIENT.crt" ]]; then
        echo "Error: Client $CLIENT not found"
        return 1
    fi

    if [[ "$SILENT" == true ]]; then
        if check_expect_available; then
            expect -c "
            spawn ./easyrsa revoke $CLIENT
            expect \"Type the word 'yes'\" { send \"yes\r\" }
            expect \"Continue with revocation:\" { send \"yes\r\" }
            expect eof
            " >/dev/null 2>&1
        else
            printf "yes\nyes\n" | timeout 30 ./easyrsa revoke "$CLIENT" >/dev/null 2>&1
        fi
    else
        ./easyrsa revoke "$CLIENT" || {
            echo "Error: Revocation failed"
            return 1
        }
    fi

    ./easyrsa gen-crl >/dev/null 2>&1 || true

    # Remove from disabled list and clean up files
    sed -i "/^$CLIENT$/d" "$DISABLED_LIST" 2>/dev/null || true
    db_execute "DELETE FROM disabled_clients WHERE client_name='$CLIENT';"
    db_execute "DELETE FROM active_sessions WHERE client_name='$CLIENT';"
    rm -f "$OUTPUT_DIR/$CLIENT.ovpn" "$MFA_DIR/$CLIENT.secret" "$QR_DIR/${CLIENT}_mfa.png"

    cp "$EASYRSA_DIR/pki/crl.pem" /etc/openvpn/crl.pem 2>/dev/null || true
    chmod 644 /etc/openvpn/crl.pem 2>/dev/null || true

    TIME=$(date '+%Y-%m-%d %H:%M:%S')
    echo "$TIME,REVOKED,$CLIENT" >> "$CLIENT_LOG"
    db_execute "INSERT INTO client_activity (timestamp, action, client_name, details) VALUES ('$TIME', 'REVOKED', '$CLIENT', 'Client certificate revoked and files deleted');"

    echo "Client $CLIENT revoked successfully"
    return 0
}

disable_client() {
    if [[ -n "$1" ]]; then
        CLIENT="$1"
    else
        read -r -p "Enter client name to disable: " CLIENT
    fi

    if [[ ! -f "$OUTPUT_DIR/$CLIENT.ovpn" ]] && [[ ! -f "$EASYRSA_DIR/pki/issued/$CLIENT.crt" ]]; then
        echo "Error: Client $CLIENT not found"
        return 1
    fi

    TIME=$(date '+%Y-%m-%d %H:%M:%S')
    IS_DIS=0
    if command -v sqlite3 >/dev/null 2>&1 && [[ -f "$DB_FILE" ]]; then
        IS_DIS=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM disabled_clients WHERE client_name='$CLIENT';" 2>/dev/null || echo 0)
    fi
    if [ "$IS_DIS" -eq 0 ] && ! grep -q "^$CLIENT$" "$DISABLED_LIST" 2>/dev/null; then
        echo "$CLIENT" >> "$DISABLED_LIST"
        echo "$TIME,DISABLED,$CLIENT" >> "$CLIENT_LOG"
        db_execute "INSERT OR REPLACE INTO disabled_clients (client_name, reason, disabled_at, disabled_by) VALUES ('$CLIENT', 'Manually disabled via CLI', '$TIME', 'cli');"
        db_execute "INSERT INTO client_activity (timestamp, action, client_name, details) VALUES ('$TIME', 'DISABLED', '$CLIENT', 'Manually disabled via CLI');"
        echo "Client $CLIENT disabled successfully"
    else
        echo "Client $CLIENT is already disabled"
    fi
    return 0
}

enable_client() {
    if [[ -n "$1" ]]; then
        CLIENT="$1"
    else
        read -r -p "Enter client name to enable: " CLIENT
    fi

    TIME=$(date '+%Y-%m-%d %H:%M:%S')
    IS_DIS=0
    if command -v sqlite3 >/dev/null 2>&1 && [[ -f "$DB_FILE" ]]; then
        IS_DIS=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM disabled_clients WHERE client_name='$CLIENT';" 2>/dev/null || echo 0)
    fi
    if [ "$IS_DIS" -gt 0 ] || grep -q "^$CLIENT$" "$DISABLED_LIST" 2>/dev/null; then
        sed -i "/^$CLIENT$/d" "$DISABLED_LIST" 2>/dev/null || true
        echo "$TIME,ENABLED,$CLIENT" >> "$CLIENT_LOG"
        db_execute "DELETE FROM disabled_clients WHERE client_name='$CLIENT';"
        db_execute "INSERT INTO client_activity (timestamp, action, client_name, details) VALUES ('$TIME', 'ENABLED', '$CLIENT', 'Enabled via CLI');"
        echo "Client $CLIENT enabled successfully"
    else
        db_execute "DELETE FROM disabled_clients WHERE client_name='$CLIENT';"
        echo "Client $CLIENT was not disabled"
    fi
    return 0
}

list_clients() {
    ALL_CLIENTS=()
    if [[ -d "$EASYRSA_DIR/pki/issued" ]]; then
        while IFS= read -r -d '' cert_file; do
            client_name=$(basename "$cert_file" .crt)
            [[ "$client_name" != "server" ]] && ALL_CLIENTS+=("$client_name")
        done < <(find "$EASYRSA_DIR/pki/issued" -name "*.crt" -print0 2>/dev/null)
    fi

    DISABLED_CLIENTS=()
    if command -v sqlite3 >/dev/null 2>&1 && [[ -f "$DB_FILE" ]]; then
        while IFS= read -r line; do
            [[ -n "$line" ]] && DISABLED_CLIENTS+=("$line")
        done < <(sqlite3 "$DB_FILE" "SELECT client_name FROM disabled_clients;" 2>/dev/null)
    elif [[ -f "$DISABLED_LIST" ]]; then
        while IFS= read -r line; do
            [[ -n "$line" ]] && DISABLED_CLIENTS+=("$line")
        done < "$DISABLED_LIST"
    fi

    for client in "${ALL_CLIENTS[@]}"; do
        if [[ " ${DISABLED_CLIENTS[*]} " == *" $client "* ]]; then
            echo "$client,DISABLED"
        else
            echo "$client,ACTIVE"
        fi
    done
}

show_client_status() {
    if [[ -n "$1" ]]; then
        CLIENT="$1"
    else
        read -r -p "Enter client name: " CLIENT
    fi

    if [[ -f "$EASYRSA_DIR/pki/issued/$CLIENT.crt" ]]; then
        IS_DIS=0
        if command -v sqlite3 >/dev/null 2>&1 && [[ -f "$DB_FILE" ]]; then
            IS_DIS=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM disabled_clients WHERE client_name='$CLIENT';" 2>/dev/null || echo 0)
        fi
        if [ "$IS_DIS" -gt 0 ] || grep -q "^$CLIENT$" "$DISABLED_LIST" 2>/dev/null; then
            echo "DISABLED"
        else
            echo "ACTIVE"
        fi
    else
        echo "NOT_FOUND"
    fi
}

kick_client() {
    if [[ -n "$1" ]]; then
        CLIENT="$1"
    else
        read -r -p "Enter client name to kick: " CLIENT
    fi

    TIME=$(date '+%Y-%m-%d %H:%M:%S')
    KICKED=false

    # 1. Send kill command to OpenVPN management interface on 127.0.0.1:7505
    if python3 -c "
import socket, sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.5)
    s.connect(('127.0.0.1', 7505))
    s.recv(1024)
    s.sendall(f'kill {sys.argv[1]}\r\nquit\r\n'.encode())
    res = s.recv(1024).decode()
    s.close()
    sys.exit(0 if 'SUCCESS' in res or 'killed' in res.lower() else 1)
except Exception:
    sys.exit(1)
" "$CLIENT" 2>/dev/null; then
        KICKED=true
        echo "✅ OpenVPN session for '$CLIENT' terminated via management socket"
    elif command -v nc >/dev/null 2>&1 && { echo -e "kill $CLIENT\nquit" | nc -w 2 127.0.0.1 7505 2>/dev/null | grep -qi "SUCCESS"; }; then
        KICKED=true
        echo "✅ OpenVPN session for '$CLIENT' terminated via nc"
    fi

    # 2. Block/drop traffic immediately on firewall if VPN IP is known
    if command -v sqlite3 >/dev/null 2>&1 && [[ -f "$DB_FILE" ]]; then
        VPN_IP=$(sqlite3 "$DB_FILE" "SELECT vpn_ip FROM active_sessions WHERE client_name='$CLIENT' LIMIT 1;" 2>/dev/null || echo "")
        if [[ -n "$VPN_IP" && "$VPN_IP" != "-" ]]; then
            iptables -I FORWARD -s "$VPN_IP" -j DROP 2>/dev/null || true
            iptables -I INPUT -s "$VPN_IP" -j DROP 2>/dev/null || true
            (sleep 20 && iptables -D FORWARD -s "$VPN_IP" -j DROP 2>/dev/null && iptables -D INPUT -s "$VPN_IP" -j DROP 2>/dev/null) >/dev/null 2>&1 &
        fi
    fi

    # 3. Clean up active_sessions in SQLite
    db_execute "DELETE FROM active_sessions WHERE client_name='$CLIENT';"
    echo "$TIME,KICKED,$CLIENT" >> "$CLIENT_LOG"
    db_execute "INSERT INTO client_activity (timestamp, action, client_name, details) VALUES ('$TIME', 'KICKED', '$CLIENT', 'Disconnected by admin');"

    if [[ "$KICKED" == true ]]; then
        echo "Client $CLIENT kicked successfully"
    else
        echo "Notice: Active session for $CLIENT cleared and disconnect signal dispatched"
    fi
    return 0
}

# Non-interactive CLI flag parsing
if [[ "${1:-}" == "--create" && -n "${2:-}" ]]; then
    add_client "$2"
    exit $?
elif [[ "${1:-}" == "--revoke" && -n "${2:-}" ]]; then
    revoke_client "$2"
    exit $?
elif [[ "${1:-}" == "--disable" && -n "${2:-}" ]]; then
    disable_client "$2"
    exit $?
elif [[ "${1:-}" == "--enable" && -n "${2:-}" ]]; then
    enable_client "$2"
    exit $?
elif [[ "${1:-}" == "--kick" && -n "${2:-}" ]]; then
    kick_client "$2"
    exit $?
elif [[ "${1:-}" == "--status" && -n "${2:-}" ]]; then
    show_client_status "$2"
    exit $?
elif [[ "${1:-}" == "--list" ]]; then
    list_clients
    exit $?
elif [[ "${1:-}" == "--ensure-hooks" ]]; then
    setup_client_connect_script
    exit $?
fi

# Interactive menu
setup_client_connect_script

echo "🔐 Zubby VPN Client Management with Access Control"
echo "=================================================="
echo "Choose an option:"
echo "1) Add client"
echo "2) Revoke client (permanent)"
echo "3) Disable client (blocks VPN access)"
echo "4) Enable client (allows VPN access)"
echo "5) List all clients with status"
echo "6) Check specific client status"
echo "7) Kick/disconnect client"
echo

read -r -p "Enter your choice (1-7): " OPTION

case $OPTION in
    1) add_client ;;
    2) revoke_client ;;
    3) disable_client ;;
    4) enable_client ;;
    5) list_clients ;;
    6) show_client_status ;;
    7) kick_client ;;
    *) echo "❌ Invalid option. Please choose 1-7." ;;
esac
