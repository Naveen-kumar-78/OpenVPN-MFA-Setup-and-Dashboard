#!/bin/bash
# ==========================================
# Script: OpenVPN Client Management with TRUE disable/enable functionality
# - Uses client-connect script to actually block disabled users from connecting
# - Logs all events to /var/log/openvpn/client_activity.log
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

mkdir -p "$OUTPUT_DIR" "$MFA_DIR" "$QR_DIR" "$SCRIPT_DIR"
touch "$CLIENT_LOG" "$DISABLED_LIST"
chmod 664 "$CLIENT_LOG"
chmod 644 "$DISABLED_LIST"

# Create the client-connect script that actually blocks disabled users
setup_client_connect_script() {
    cat > "$CLIENT_CONNECT_SCRIPT" <<'EOF'
#!/bin/bash
# OpenVPN Client Connect Script - Blocks disabled users
DISABLED_LIST="/etc/openvpn/disabled_clients.txt"
LOG_FILE="/var/log/openvpn/client_activity.log"

# Get the common name (username) from environment
CLIENT_NAME="$common_name"

# Check if client is in disabled list
if grep -q "^$CLIENT_NAME$" "$DISABLED_LIST" 2>/dev/null; then
    echo "$(date '+%Y-%m-%d %H:%M:%S'),CONNECTION_BLOCKED,$CLIENT_NAME,Disabled user attempted connection" >> "$LOG_FILE"
    # Exit with error code to deny connection
    exit 1
fi

# Log successful connection attempt
echo "$(date '+%Y-%m-%d %H:%M:%S'),CONNECTION_ALLOWED,$CLIENT_NAME,Active user connected" >> "$LOG_FILE"
# Exit successfully to allow connection
exit 0
EOF

    chmod +x "$CLIENT_CONNECT_SCRIPT"
    
    # Add client-connect directive to OpenVPN server config if not already present
    if ! grep -q "client-connect" "$OPENVPN_CONFIG" 2>/dev/null; then
        echo "script-security 2" >> "$OPENVPN_CONFIG"
        echo "client-connect $CLIENT_CONNECT_SCRIPT" >> "$OPENVPN_CONFIG"
        echo "âœ… Added client-connect script to OpenVPN server config"
        echo "âš ï¸  You need to restart OpenVPN server: systemctl restart openvpn-server@server"
    fi
}

add_client() {
    read -p "Enter client name: " CLIENT
    
    # Remove from disabled list if present
    sed -i "/^$CLIENT$/d" "$DISABLED_LIST"
    
    cd $EASYRSA_DIR || exit
    ./easyrsa build-client-full "$CLIENT" nopass
    CLIENT_FILE="$OUTPUT_DIR/$CLIENT.ovpn"

    cat > "$CLIENT_FILE" <<EOF
client
dev tun
proto $PROTO
remote $SERVER_IP $PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-GCM
auth-user-pass
verb 3
EOF

    {
        echo "<ca>"
        cat $EASYRSA_DIR/pki/ca.crt
        echo "</ca>"
        echo "<cert>"
        sed -ne '/BEGIN CERTIFICATE/,$p' $EASYRSA_DIR/pki/issued/$CLIENT.crt
        echo "</cert>"
        echo "<key>"
        cat $EASYRSA_DIR/pki/private/$CLIENT.key
        echo "</key>"
        echo "<tls-crypt>"
        cat /etc/openvpn/server/tc.key
        echo "</tls-crypt>"
    } >> "$CLIENT_FILE"

    SECRET=$(head /dev/urandom | tr -dc A-Z2-7 | head -c 16)
    echo "$SECRET" > "$MFA_DIR/$CLIENT.secret"
    chmod 600 "$MFA_DIR/$CLIENT.secret"
    qrencode -o "$QR_DIR/${CLIENT}_mfa.png" "otpauth://totp/$CLIENT?secret=$SECRET&issuer=OpenVPN" >/dev/null 2>&1 || true

    echo "$(date '+%Y-%m-%d %H:%M:%S'),CREATED,$CLIENT" >> "$CLIENT_LOG"
    echo "âœ… Client added: $CLIENT"
    echo "ðŸ“‚ Config file: $CLIENT_FILE"
    echo "ðŸ” MFA QR code: $QR_DIR/${CLIENT}_mfa.png"
}

revoke_client() {
    read -p "Enter client name to revoke: " CLIENT
    cd $EASYRSA_DIR || exit
    ./easyrsa revoke "$CLIENT" || true
    ./easyrsa gen-crl || true
    
    # Remove from disabled list and delete files
    sed -i "/^$CLIENT$/d" "$DISABLED_LIST"
    rm -f "$OUTPUT_DIR/$CLIENT.ovpn" "$MFA_DIR/$CLIENT.secret" "$QR_DIR/${CLIENT}_mfa.png"
    
    cp $EASYRSA_DIR/pki/crl.pem /etc/openvpn/crl.pem 2>/dev/null || true
    chmod 644 /etc/openvpn/crl.pem 2>/dev/null || true
    echo "$(date '+%Y-%m-%d %H:%M:%S'),REVOKED,$CLIENT" >> "$CLIENT_LOG"
    echo "âŒ Client $CLIENT revoked and removed from disabled list"
}

disable_client() {
    read -p "Enter client name to disable: " CLIENT
    
    # Check if client exists
    if [[ ! -f "$OUTPUT_DIR/$CLIENT.ovpn" ]] && [[ ! -f "$EASYRSA_DIR/pki/issued/$CLIENT.crt" ]]; then
        echo "âŒ Client $CLIENT not found"
        return
    fi
    
    # Add to disabled list if not already there
    if ! grep -q "^$CLIENT$" "$DISABLED_LIST"; then
        echo "$CLIENT" >> "$DISABLED_LIST"
        echo "$(date '+%Y-%m-%d %H:%M:%S'),DISABLED,$CLIENT" >> "$CLIENT_LOG"
        echo "ðŸš« Client $CLIENT has been DISABLED"
        echo "   This user will be blocked from connecting to the VPN"
        echo "   Any existing connections will remain active until disconnected"
    else
        echo "âš ï¸  Client $CLIENT is already disabled"
    fi
}

enable_client() {
    read -p "Enter client name to enable: " CLIENT
    
    # Remove from disabled list
    if grep -q "^$CLIENT$" "$DISABLED_LIST"; then
        sed -i "/^$CLIENT$/d" "$DISABLED_LIST"
        echo "$(date '+%Y-%m-%d %H:%M:%S'),ENABLED,$CLIENT" >> "$CLIENT_LOG"
        echo "âœ… Client $CLIENT has been ENABLED"
        echo "   This user can now connect to the VPN"
    else
        echo "âš ï¸  Client $CLIENT was not disabled"
    fi
}

list_clients() {
    echo "ðŸ“œ Client Status Report:"
    echo "========================"
    echo
    
    # Get all clients with certificates
    ALL_CLIENTS=()
    if [[ -d "$EASYRSA_DIR/pki/issued" ]]; then
        while IFS= read -r -d '' cert_file; do
            client_name=$(basename "$cert_file" .crt)
            [[ "$client_name" != "server" ]] && ALL_CLIENTS+=("$client_name")
        done < <(find "$EASYRSA_DIR/pki/issued" -name "*.crt" -print0 2>/dev/null)
    fi
    
    # Read disabled clients
    DISABLED_CLIENTS=()
    if [[ -f "$DISABLED_LIST" ]]; then
        while IFS= read -r line; do
            [[ -n "$line" ]] && DISABLED_CLIENTS+=("$line")
        done < "$DISABLED_LIST"
    fi
    
    echo "ðŸŸ¢ ACTIVE Clients (can connect):"
    active_found=false
    for client in "${ALL_CLIENTS[@]}"; do
        if [[ ! " ${DISABLED_CLIENTS[*]} " =~ " ${client} " ]]; then
            echo "   âœ“ $client"
            active_found=true
        fi
    done
    [[ "$active_found" == false ]] && echo "   (none)"
    
    echo
    echo "ðŸ”´ DISABLED Clients (blocked from connecting):"
    if [[ ${#DISABLED_CLIENTS[@]} -eq 0 ]]; then
        echo "   (none)"
    else
        for client in "${DISABLED_CLIENTS[@]}"; do
            echo "   âœ— $client"
        done
    fi
    
    echo
    echo "ðŸ“Š Recent Activity (last 10 entries):"
    if [[ -f "$CLIENT_LOG" ]]; then
        tail -n 10 "$CLIENT_LOG" | sed 's/^/   /'
    else
        echo "   (no activity logged)"
    fi
}

show_client_status() {
    read -p "Enter client name to check status: " CLIENT
    
    if [[ -f "$EASYRSA_DIR/pki/issued/$CLIENT.crt" ]]; then
        if grep -q "^$CLIENT$" "$DISABLED_LIST"; then
            echo "ðŸ”´ Client $CLIENT is DISABLED (blocked from VPN access)"
        else
            echo "ðŸŸ¢ Client $CLIENT is ACTIVE (can connect to VPN)"
        fi
        
        echo "ðŸ“‚ Files:"
        [[ -f "$OUTPUT_DIR/$CLIENT.ovpn" ]] && echo "   Config: $OUTPUT_DIR/$CLIENT.ovpn"
        [[ -f "$MFA_DIR/$CLIENT.secret" ]] && echo "   MFA Secret: $MFA_DIR/$CLIENT.secret"
        [[ -f "$QR_DIR/${CLIENT}_mfa.png" ]] && echo "   QR Code: $QR_DIR/${CLIENT}_mfa.png"
    else
        echo "âŒ Client $CLIENT not found (no certificate)"
    fi
}

kick_client() {
    read -p "Enter client name to disconnect: " CLIENT
    
    # Kill active OpenVPN connections for this client
    pkill -f "openvpn.*$CLIENT" 2>/dev/null && echo "ðŸ”„ Attempted to disconnect $CLIENT" || echo "âš ï¸  No active connection found for $CLIENT"
    echo "$(date '+%Y-%m-%d %H:%M:%S'),KICKED,$CLIENT" >> "$CLIENT_LOG"
}

# Setup the client-connect script on first run
setup_client_connect_script

# Display menu
echo "ðŸ” OpenVPN Client Management with TRUE Access Control"
echo "===================================================="
echo "Choose an option:"
echo "1) Add client"
echo "2) Revoke client (permanent)"
echo "3) Disable client (blocks VPN access)"
echo "4) Enable client (allows VPN access)"
echo "5) List all clients with status"
echo "6) Check specific client status"
echo "7) Kick/disconnect client"
echo
read -p "Enter your choice (1-7): " OPTION

case $OPTION in
    1) add_client ;;
    2) revoke_client ;;
    3) disable_client ;;
    4) enable_client ;;
    5) list_clients ;;
    6) show_client_status ;;
    7) kick_client ;;
    *) echo "âŒ Invalid option. Please choose 1-7." ;;
esac
