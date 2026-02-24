#!/bin/bash
# ==========================================
# All-in-One Installer: OpenVPN MFA Dashboard (Self-Contained)
# Merges user's Flask app + templates into a single installer.
# UPDATED: Added non-interactive client management using client.sh delegation
# ==========================================
set -euo pipefail

APP_DIR="/root/vpn_dashboard"
TEMPLATES_DIR="$APP_DIR/templates"
STATIC_DIR="$APP_DIR/static"
LOG_DIR="/var/log/openvpn"
USERS_DB="$APP_DIR/users.json"
DISABLED_CLIENTS_FILE="/etc/openvpn/disabled_clients.json"
SERVICE_FILE="/etc/systemd/system/vpn_dashboard.service"
VENV_DIR="$APP_DIR/venv"
PYTHON_BIN="$VENV_DIR/bin/python"
PIP_BIN="$VENV_DIR/bin/pip"
REQUIREMENTS_FILE="$APP_DIR/requirements.txt"

# New: Client management delegation
CLIENT_BIN="$APP_DIR/client.sh"           # Non-interactive client.sh placed in dashboard dir
OUTPUT_DIR="/root/ovpn_clients"           # Must match client.sh
QR_DIR="$OUTPUT_DIR/qr"                   # Must match client.sh
CLIENT_LOG="/var/log/openvpn/client_activity.log"
CONN_MASTER_LOG="/var/log/openvpn/custom_logs/master_connection_audit.log"
DISABLED_LIST="/etc/openvpn/disabled_clients.txt"

echo "=== This installer will deploy the VPN Dashboard app to: $APP_DIR ==="
echo "Make sure you run this script as root."

# 1) Install system packages (adjust as needed)
echo "=== Updating apt and installing base packages ==="
apt-get update -y
apt-get install -y python3 python3-venv python3-pip curl qrencode git build-essential

# Optional OpenVPN/EasyRSA - comment/uncomment if needed
echo "=== Installing openvpn and easy-rsa (optional; disable if already installed) ==="
apt-get install -y openvpn easy-rsa || echo "openvpn/easy-rsa install failed or already present - continuing"

# 2) Create directories
echo "=== Creating directories ==="
mkdir -p "$APP_DIR"
mkdir -p "$TEMPLATES_DIR"
mkdir -p "$STATIC_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$(dirname "$DISABLED_CLIENTS_FILE")"
mkdir -p "$OUTPUT_DIR" "$QR_DIR" "/var/log/openvpn/custom_logs"
touch "$CLIENT_LOG" "$CONN_MASTER_LOG" "$DISABLED_LIST"

# 3) Create python venv and install python deps
echo "=== Creating python virtualenv and installing Python packages ==="
python3 -m venv "$VENV_DIR"
# Ensure pip is upgraded
"$VENV_DIR/bin/pip" install --upgrade pip

cat > "$REQUIREMENTS_FILE" <<'REQ'
flask
flask-login
reportlab
psutil
pandas
gunicorn
REQ

"$PIP_BIN" install -r "$REQUIREMENTS_FILE"

# 4) Deploy the Flask app (app.py) â€” UPDATED with client management delegation
echo "=== Writing Flask app to $APP_DIR/app.py ==="
cat > "$APP_DIR/app.py" <<'PY'
#!/usr/bin/env python3
"""
Enhanced VPN Dashboard - Production Grade
(Merged installer copy with client management delegation)
"""

from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import csv, os, psutil, datetime, io, pandas as pd, json, subprocess, hashlib
from reportlab.lib.pagesizes import letter, A4
from reportlab.pdfgen import canvas
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib import colors
from reportlab.lib.units import inch
from functools import wraps
import logging

# ==========================
# Global Constants
# ==========================
MASTER_VPN_LOG = "/var/log/openvpn/custom_logs/master_connection_audit.log"
MFA_LOG = "/var/log/openvpn/mfa_attempts.log"
CLIENT_LOG = "/var/log/openvpn/client_activity.log"
CONNECTION_LOG = "/var/log/openvpn/connection_audit.log"
EASYRSA_DIR = "/etc/openvpn/server/easy-rsa"
OUTPUT_DIR = "/root/ovpn_clients"
MFA_DIR = "/etc/openvpn/mfa-secrets"
QR_DIR = f"{OUTPUT_DIR}/qr"
DISABLED_CLIENTS_FILE = "/etc/openvpn/disabled_clients.json"
USERS_DB = "/root/vpn_dashboard/users.json"
AUDIT_LOG = "/var/log/openvpn/dashboard_audit.log"

# NEW: Client management delegation
DASH_DIR = os.path.dirname(os.path.abspath(__file__))
CLIENT_BIN = os.path.join(DASH_DIR, "client.sh")
DISABLED_LIST = "/etc/openvpn/disabled_clients.txt"

# Ensure log directories exist
os.makedirs(os.path.dirname(MASTER_VPN_LOG), exist_ok=True)
os.makedirs(os.path.dirname(MFA_LOG), exist_ok=True)
os.makedirs(os.path.dirname(CLIENT_LOG), exist_ok=True)
os.makedirs(os.path.dirname(CONNECTION_LOG), exist_ok=True)
os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(MFA_DIR, exist_ok=True)
os.makedirs(QR_DIR, exist_ok=True)

# ==========================
# Flask App Setup
# ==========================
app = Flask(__name__)
app.secret_key = "supersecretkey_change_in_production"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Setup logging
logging.basicConfig(
    filename=AUDIT_LOG,
    level=logging.INFO,
    format='%(asctime)s,%(levelname)s,%(message)s'
)

# ==========================
# Client Management Delegation Functions (NEW)
# ==========================
def require_client_bin():
    """Ensure client.sh is available"""
    if not os.path.exists(CLIENT_BIN) or not os.access(CLIENT_BIN, os.X_OK):
        raise FileNotFoundError(f"client.sh not found or not executable at {CLIENT_BIN}")

def call_client_action(action, client_name=None):
    """Call non-interactive client.sh with action - IMPROVED VERSION"""
    require_client_bin()
    cmd = [CLIENT_BIN, f"--{action}"]
    if client_name:
        cmd.append(client_name)

    try:
        # Set environment variables that might be needed
        env = os.environ.copy()
        env['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,  # Increased timeout
            env=env,
            cwd=DASH_DIR  # Ensure correct working directory
        )

        success = result.returncode == 0
        message = result.stdout.strip() if result.stdout else result.stderr.strip()

        # Log the subprocess call for debugging
        logging.info(f"SUBPROCESS_CALL,{action},{client_name},{success},{message}")

        return success, message

    except subprocess.TimeoutExpired:
        error_msg = "Operation timed out after 120 seconds"
        logging.error(f"SUBPROCESS_TIMEOUT,{action},{client_name},{error_msg}")
        return False, error_msg
    except Exception as e:
        error_msg = str(e)
        logging.error(f"SUBPROCESS_ERROR,{action},{client_name},{error_msg}")
        return False, error_msg

def create_client_delegated(client_name):
    """Create client using non-interactive client.sh - IMPROVED"""
    # Validate client name
    if not client_name or not client_name.replace('.', '').replace('-', '').replace('_', '').isalnum():
        return False, "Invalid client name. Use only letters, numbers, dots, hyphens, and underscores."

    # Check if client already exists
    client_file = os.path.join(OUTPUT_DIR, f"{client_name}.ovpn")
    if os.path.exists(client_file):
        return False, f"Client {client_name} already exists"

    success, message = call_client_action("create", client_name)

    if success:
        # Verify files were actually created
        client_file = os.path.join(OUTPUT_DIR, f"{client_name}.ovpn")
        mfa_file = os.path.join(MFA_DIR, f"{client_name}.secret")
        qr_file = os.path.join(QR_DIR, f"{client_name}_mfa.png")

        missing_files = []
        if not os.path.exists(client_file):
            missing_files.append(".ovpn file")
        if not os.path.exists(mfa_file):
            missing_files.append("MFA secret")
        if not os.path.exists(qr_file):
            missing_files.append("QR code")

        if missing_files:
            warning_msg = f"Client created but missing: {', '.join(missing_files)}"
            logging.warning(f"CLIENT_CREATE_INCOMPLETE,{client_name},{warning_msg}")
            return True, f"Client created but some files missing: {', '.join(missing_files)}"

        logging.info(f"CLIENT_CREATED,{client_name},{current_user.username if current_user else 'system'}")
        return True, f"Client {client_name} created successfully with all files"
    else:
        logging.error(f"CLIENT_CREATE_FAILED,{client_name},{message},{current_user.username if current_user else 'system'}")
        return False, f"Failed to create client: {message}"

def revoke_client_delegated(client_name):
    """Revoke client using non-interactive client.sh"""
    success, message = call_client_action("revoke", client_name)
    return success, message

def disable_client_delegated(client_name):
    """Disable client using non-interactive client.sh"""
    success, message = call_client_action("disable", client_name)
    return success, message

def enable_client_delegated(client_name):
    """Enable client using non-interactive client.sh"""
    success, message = call_client_action("enable", client_name)
    return success, message

def kick_client_delegated(client_name):
    """Kick client using non-interactive client.sh"""
    success, message = call_client_action("kick", client_name)
    return success, message

# UPDATED create_client function to use delegation
def create_client(client_name):
    """UPDATED: Create a new VPN client using delegation"""
    try:
        success, message = create_client_delegated(client_name)
        if success:
            logging.info(f"CLIENT_CREATED,{client_name},{current_user.username}")
            return True, message
        else:
            logging.error(f"CLIENT_CREATE_FAILED,{client_name},{message},{current_user.username}")
            return False, message
    except Exception as e:
        logging.error(f"CLIENT_CREATE_FAILED,{client_name},{str(e)},{current_user.username}")
        return False, f"Failed to create client: {str(e)}"

def revoke_client(client_name):
    """UPDATED: Permanently revoke a client using delegation"""
    try:
        success, message = revoke_client_delegated(client_name)
        if success:
            logging.info(f"CLIENT_REVOKED,{client_name},{current_user.username}")
            return True, message
        else:
            logging.error(f"CLIENT_REVOKE_FAILED,{client_name},{message},{current_user.username}")
            return False, message
    except Exception as e:
        logging.error(f"CLIENT_REVOKE_FAILED,{client_name},{str(e)},{current_user.username}")
        return False, f"Failed to revoke client: {str(e)}"

# ==========================
# User Management & RBAC
# ==========================
class User(UserMixin):
    def __init__(self, username, role, email=""):
        self.id = username
        self.username = username
        self.role = role
        self.email = email
    
    def has_permission(self, permission):
        permissions = {
            'readonly': ['view_logs', 'download_reports'],
            'readwrite': ['view_logs', 'download_reports', 'manage_clients', 'generate_reports'],
            'admin': ['view_logs', 'download_reports', 'manage_clients', 'generate_reports', 
                     'manage_users', 'system_settings', 'audit_logs']
        }
        return permission in permissions.get(self.role, [])

def load_users():
    """Load users from JSON file"""
    if not os.path.exists(USERS_DB):
        # Create default users
        default_users = {
            "admin": {
                "password": hashlib.sha256("admin123".encode()).hexdigest(),
                "role": "admin",
                "email": "admin@example.com",
                "created": datetime.datetime.now().isoformat()
            },
            "operator": {
                "password": hashlib.sha256("operator123".encode()).hexdigest(),
                "role": "readwrite",
                "email": "operator@example.com",
                "created": datetime.datetime.now().isoformat()
            },
            "viewer": {
                "password": hashlib.sha256("viewer123".encode()).hexdigest(),
                "role": "readonly",
                "email": "viewer@example.com",
                "created": datetime.datetime.now().isoformat()
            }
        }
        save_users(default_users)
        return default_users
    
    with open(USERS_DB, 'r') as f:
        return json.load(f)

def save_users(users):
    """Save users to JSON file"""
    os.makedirs(os.path.dirname(USERS_DB), exist_ok=True)
    with open(USERS_DB, 'w') as f:
        json.dump(users, f, indent=2)

@login_manager.user_loader
def user_loader(username):
    users = load_users()
    if username not in users:
        return None
    user_data = users[username]
    return User(username, user_data['role'], user_data.get('email', ''))

def require_permission(permission):
    """Decorator to check user permissions"""
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if not current_user.has_permission(permission):
                flash(f'Access denied. Required permission: {permission}', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ==========================
# Legacy Client Management Functions (kept for compatibility)
# ==========================
def load_disabled_clients():
    """Load list of disabled clients from TXT file (preferred)"""
    disabled = {}
    if os.path.exists(DISABLED_LIST):  # /etc/openvpn/disabled_clients.txt
        with open(DISABLED_LIST, 'r') as f:
            for line in f:
                client = line.strip()
                if client:
                    disabled[client] = {
                        'disabled_at': "via client.sh",
                        'reason': "Disabled using client.sh",
                        'disabled_by': "system"
                    }
    return disabled

def save_disabled_clients(disabled_clients):
    """Save disabled clients list to TXT file"""
    os.makedirs(os.path.dirname(DISABLED_LIST), exist_ok=True)
    with open(DISABLED_LIST, 'w') as f:
        for client in disabled_clients.keys():
            f.write(client + "\n")

def disable_client(client_name, reason="MFA failures"):
    """LEGACY: Disable a client (soft disable - keep files but block access)"""
    # Use delegated function if client.sh is available
    try:
        success, message = disable_client_delegated(client_name)
        if success:
            logging.info(f"CLIENT_DISABLED,{client_name},{reason},{current_user.username if current_user else 'system'}")
            return
    except:
        pass
    
    # Fallback to legacy method
    disabled_clients = load_disabled_clients()
    disabled_clients[client_name] = {
        'disabled_at': datetime.datetime.now().isoformat(),
        'reason': reason,
        'disabled_by': current_user.username if current_user else 'system'
    }
    save_disabled_clients(disabled_clients)
    
    # Log the action
    log_entry = f"{datetime.datetime.now()},DISABLED,{client_name},{reason}"
    with open(CLIENT_LOG, 'a') as f:
        f.write(log_entry + '\n')
    
    logging.info(f"CLIENT_DISABLED,{client_name},{reason},{current_user.username if current_user else 'system'}")

def enable_client(client_name):
    """LEGACY: Enable a previously disabled client"""
    # Use delegated function if client.sh is available
    try:
        success, message = enable_client_delegated(client_name)
        if success:
            logging.info(f"CLIENT_ENABLED,{client_name},{current_user.username}")
            return
    except:
        pass
    
    # Fallback to legacy method
    disabled_clients = load_disabled_clients()
    if client_name in disabled_clients:
        del disabled_clients[client_name]
        save_disabled_clients(disabled_clients)
        
        # Log the action
        log_entry = f"{datetime.datetime.now()},ENABLED,{client_name}"
        with open(CLIENT_LOG, 'a') as f:
            f.write(log_entry + '\n')
        
        logging.info(f"CLIENT_ENABLED,{client_name},{current_user.username}")

def create_client(client_name):
    """UPDATED: Create a new VPN client using delegation"""
    try:
        success, message = create_client_delegated(client_name)
        if success:
            logging.info(f"CLIENT_CREATED,{client_name},{current_user.username}")
            return True, message
        else:
            logging.error(f"CLIENT_CREATE_FAILED,{client_name},{message},{current_user.username}")
            return False, message
    except Exception as e:
        logging.error(f"CLIENT_CREATE_FAILED,{client_name},{str(e)},{current_user.username}")
        return False, f"Failed to create client: {str(e)}"

def revoke_client(client_name):
    """UPDATED: Permanently revoke a client using delegation"""
    try:
        success, message = revoke_client_delegated(client_name)
        if success:
            logging.info(f"CLIENT_REVOKED,{client_name},{current_user.username}")
            return True, message
        else:
            logging.error(f"CLIENT_REVOKE_FAILED,{client_name},{message},{current_user.username}")
            return False, message
    except Exception as e:
        logging.error(f"CLIENT_REVOKE_FAILED,{client_name},{str(e)},{current_user.username}")
        return False, f"Failed to revoke client: {str(e)}"

# ==========================
# Download Endpoints (NEW)
# ==========================
@app.route("/download/ovpn/<client_name>")
@login_required
@require_permission('manage_clients')
def download_ovpn(client_name):
    """Download client .ovpn file"""
    client_file = os.path.join(OUTPUT_DIR, f"{client_name}.ovpn")
    if os.path.exists(client_file):
        logging.info(f"DOWNLOAD_OVPN,{client_name},{current_user.username}")
        return send_file(client_file, as_attachment=True, download_name=f"{client_name}.ovpn")
    else:
        flash(f'Client file {client_name}.ovpn not found', 'error')
        return redirect(url_for('client_management'))

@app.route("/download/qr/<client_name>")
@login_required
@require_permission('manage_clients')
def download_qr(client_name):
    """Download MFA QR code"""
    qr_file = os.path.join(QR_DIR, f"{client_name}_mfa.png")
    if os.path.exists(qr_file):
        logging.info(f"DOWNLOAD_QR,{client_name},{current_user.username}")
        return send_file(qr_file, as_attachment=True, download_name=f"{client_name}_mfa.png")
    else:
        flash(f'QR code for {client_name} not found', 'error')
        return redirect(url_for('client_management'))

# ==========================
# Utility Functions
# ==========================
def parse_logs(file_path):
    """Parse CSV log files"""
    logs = []
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                if any(field.strip() for field in row):
                    logs.append(row)
    return logs

def get_active_users():
    """Get currently active VPN users"""
    active_users = {}
    disabled_clients = load_disabled_clients()
    
    if os.path.exists(CONNECTION_LOG):
        with open(CONNECTION_LOG, 'r') as f:
            for line in f:
                parts = line.strip().split(",")
                if len(parts) < 7:
                    continue
                timestamp, action, user, public_ip, vpn_ip, location, platform = parts[:7]
                
                # Skip disabled clients
                if user in disabled_clients:
                    continue

                try:
                    ts = datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                except:
                    continue

                if action in ("CONNECT", "CONNECTED via MFA"):
                    active_users[user] = {
                        "name": user,
                        "real_ip": public_ip,
                        "vpn_ip": vpn_ip,
                        "location": location,
                        "platform": platform,
                        "since": timestamp,
                        "duration": str(datetime.timedelta(seconds=max(0, int((datetime.datetime.now() - ts).total_seconds()))))
                    }
                elif action in ("DISCONNECT", "DISCONNECTED"):
                    if user in active_users:
                        del active_users[user]

    return list(active_users.values())

def check_mfa_failures():
    """Check for clients with excessive MFA failures and auto-disable"""
    if not os.path.exists(MFA_LOG):
        return
    
    today = datetime.date.today().strftime("%Y-%m-%d")
    failure_counts = {}
    disabled_clients = load_disabled_clients()
    
    with open(MFA_LOG, 'r') as f:
        for line in f:
            parts = line.strip().split(',')
            if len(parts) >= 3:
                timestamp, client, status = parts[0], parts[1], parts[2]
                if timestamp.startswith(today) and status == 'FAIL':
                    failure_counts[client] = failure_counts.get(client, 0) + 1
    
    # Auto-disable clients with 10+ failures
    for client, count in failure_counts.items():
        if count >= 1000 and client not in disabled_clients:
            disable_client(client, f"Auto-disabled: {count} MFA failures today")

def generate_advanced_pdf_report(log_type, filtered_logs, headers, metadata):
    """Generate advanced PDF report with charts and formatting"""
    output = io.BytesIO()
    doc = SimpleDocTemplate(output, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []
    
    # Title
    title = Paragraph(f"VPN {log_type.upper()} Report", styles['Title'])
    story.append(title)
    story.append(Spacer(1, 12))
    
    # Metadata
    meta_info = f"""
    <b>Generated:</b> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>
    <b>Date Range:</b> {metadata.get('from_date', 'N/A')} to {metadata.get('to_date', 'N/A')}<br/>
    <b>Total Records:</b> {len(filtered_logs)}<br/>
    <b>Generated By:</b> {getattr(current_user, 'username', 'system')}<br/>
    <b>Search Query:</b> {metadata.get('search_query', 'None')}
    """
    story.append(Paragraph(meta_info, styles['Normal']))
    story.append(Spacer(1, 20))
    
    if filtered_logs:
        # Summary statistics
        if log_type == 'vpn':
            connections = len([log for log in filtered_logs if 'CONNECT' in log[1].upper()]) if filtered_logs and len(filtered_logs[0])>1 else 0
            disconnections = len([log for log in filtered_logs if 'DISCONNECT' in log[1].upper()]) if filtered_logs and len(filtered_logs[0])>1 else 0
            unique_clients = len(set(log[2] for log in filtered_logs if len(log) > 2))
            
            summary = f"""
            <b>Summary Statistics:</b><br/>
            â€¢ Total Connections: {connections}<br/>
            â€¢ Total Disconnections: {disconnections}<br/>
            â€¢ Unique Clients: {unique_clients}
            """
            story.append(Paragraph(summary, styles['Normal']))
            story.append(Spacer(1, 12))
        
        elif log_type == 'mfa':
            successes = len([log for log in filtered_logs if len(log)>2 and 'SUCCESS' in log[2].upper()])
            failures = len([log for log in filtered_logs if len(log)>2 and 'FAIL' in log[2].upper()])
            success_rate = (successes / len(filtered_logs)) * 100 if filtered_logs else 0
            
            summary = f"""
            <b>MFA Statistics:</b><br/>
            â€¢ Successful Attempts: {successes}<br/>
            â€¢ Failed Attempts: {failures}<br/>
            â€¢ Success Rate: {success_rate:.1f}%
            """
            story.append(Paragraph(summary, styles['Normal']))
            story.append(Spacer(1, 12))
        
        # Data table
        table_data = [headers] + filtered_logs[:100]  # Limit to 100 rows for PDF
        
        table = Table(table_data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('FONTSIZE', (0, 1), (-1, -1), 7),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(table)
        
        if len(filtered_logs) > 100:
            story.append(Spacer(1, 12))
            story.append(Paragraph(f"<i>Note: Showing first 100 of {len(filtered_logs)} records</i>", styles['Normal']))
    
    else:
        story.append(Paragraph("No data found for the specified criteria.", styles['Normal']))
    
    doc.build(story)
    output.seek(0)
    return output

# ==========================
# Routes
# ==========================
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        users = load_users()
        
        if username in users:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            if users[username]["password"] == hashed_password:
                user = User(username, users[username]['role'], users[username].get('email', ''))
                login_user(user)
                logging.info(f"LOGIN_SUCCESS,{username}")
                flash(f'Welcome, {username}!', 'success')
                return redirect(url_for("dashboard"))
        
        logging.warning(f"LOGIN_FAILED,{username}")
        flash('Invalid credentials', 'error')
    
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logging.info(f"LOGOUT,{current_user.username}")
    logout_user()
    return redirect(url_for("login"))

@app.route("/", methods=["GET"])
@login_required
@require_permission('view_logs')
def dashboard():
    # Check for MFA failures and auto-disable clients
    check_mfa_failures()
    
    vpn_logs = parse_logs(MASTER_VPN_LOG)
    mfa_logs = parse_logs(MFA_LOG)
    active_users = get_active_users()
    disabled_clients = load_disabled_clients()

    today = datetime.date.today().strftime("%Y-%m-%d")
    from_date = request.args.get("from_date", today)
    to_date = request.args.get("to_date", today)

    def filter_by_date(logs, date_index=0):
        result = []
        for log in logs:
            if len(log) > date_index:
                log_date = log[date_index].split(" ")[0]
                if from_date <= log_date <= to_date:
                    result.append(log)
        return result

    vpn_logs = filter_by_date(vpn_logs)
    mfa_logs = filter_by_date(mfa_logs)

    search_query = request.args.get("search", "").lower()
    if search_query:
        vpn_logs = [log for log in vpn_logs if search_query in " ".join(log).lower()]
        mfa_logs = [log for log in mfa_logs if search_query in " ".join(log).lower()]

    disk = psutil.disk_usage('/')
    metrics = {
        "cpu": psutil.cpu_percent(),
        "mem": psutil.virtual_memory().percent,
        "disk": disk.percent,
        "uptime": str(datetime.datetime.now() - datetime.datetime.fromtimestamp(psutil.boot_time())).split('.')[0]
    }

    return render_template("enhanced_dashboard.html",
                           vpn_logs=vpn_logs,
                           mfa_logs=mfa_logs,
                           active_users=active_users,
                           disabled_clients=disabled_clients,
                           active_count=len(active_users),
                           disabled_count=len(disabled_clients),
                           metrics=metrics,
                           search_query=search_query,
                           from_date=from_date,
                           to_date=to_date,
                           current_user=current_user)

@app.route("/clients")
@login_required
@require_permission('view_logs')
def clients():
    client_logs = parse_logs(CLIENT_LOG)
    disabled_clients = load_disabled_clients()
    
    created = [log for log in client_logs if len(log) > 1 and log[1] == "CREATED"]
    revoked = [log for log in client_logs if len(log) > 1 and log[1] == "REVOKED"]
    disabled = [log for log in client_logs if len(log) > 1 and log[1] == "DISABLED"]
    enabled = [log for log in client_logs if len(log) > 1 and log[1] == "ENABLED"]
    
    return render_template("clients.html", 
                         created=created, 
                         revoked=revoked,
                         disabled=disabled,
                         enabled=enabled,
                         disabled_clients=disabled_clients,
                         current_user=current_user)

@app.route("/client_management", methods=["GET", "POST"])
@login_required
@require_permission('manage_clients')
def client_management():
    if request.method == "POST":
        action = request.form.get('action')
        client_name = request.form.get('client_name', '').strip()
        
        if not client_name:
            flash('Client name is required', 'error')
        elif action == 'create':
            try:
                success, message = create_client_delegated(client_name)
                if success:
                    flash(f'Success: {message}', 'success')
                else:
                    flash(f'Error: {message}', 'error')
            except Exception as e:
                error_msg = f'Unexpected error creating client: {str(e)}'
                logging.error(f"CLIENT_CREATE_EXCEPTION,{client_name},{error_msg},{current_user.username}")
                flash(error_msg, 'error')
                
        elif action == 'revoke':
            try:
                success, message = revoke_client_delegated(client_name)
                flash(message, 'success' if success else 'error')
            except Exception as e:
                flash(f'Error revoking client: {str(e)}', 'error')
                
        elif action == 'disable':
            try:
                disable_client(client_name, "Manually disabled")
                flash(f'Client {client_name} disabled successfully', 'success')
            except Exception as e:
                flash(f'Error disabling client: {str(e)}', 'error')
                
        elif action == 'enable':
            try:
                enable_client(client_name)
                flash(f'Client {client_name} enabled successfully', 'success')
            except Exception as e:
                flash(f'Error enabling client: {str(e)}', 'error')
                
        elif action == 'kick':
            try:
                success, message = kick_client_delegated(client_name)
                flash(message if message else f'Client {client_name} kicked successfully', 'success' if success else 'error')
            except Exception as e:
                flash(f'Failed to kick client {client_name}: {str(e)}', 'error')
    
    # Get existing clients - improved method
    existing_clients = []
    try:
        if os.path.exists(OUTPUT_DIR):
            for file in os.listdir(OUTPUT_DIR):
                if file.endswith('.ovpn'):
                    existing_clients.append(file[:-5])  # Remove .ovpn extension
        existing_clients.sort()  # Sort alphabetically
    except Exception as e:
        logging.error(f"ERROR_LISTING_CLIENTS,{str(e)}")
        flash('Error loading client list', 'error')
    
    disabled_clients = load_disabled_clients()
    
    return render_template("client_management.html", 
                         existing_clients=existing_clients,
                         disabled_clients=disabled_clients,
                         current_user=current_user)    

    # Get existing clients - improved method
    existing_clients = []
    try:
        if os.path.exists(OUTPUT_DIR):
            for file in os.listdir(OUTPUT_DIR):
                if file.endswith('.ovpn'):
                    existing_clients.append(file[:-5])  # Remove .ovpn extension
        existing_clients.sort()  # Sort alphabetically
    except Exception as e:
        logging.error(f"ERROR_LISTING_CLIENTS,{str(e)}")
        flash('Error loading client list', 'error')

    disabled_clients = load_disabled_clients()

    return render_template("client_management.html",
                         existing_clients=existing_clients,
                         disabled_clients=disabled_clients,
                         current_user=current_user)

@app.route("/user_management")
@login_required
@require_permission('manage_users')
def user_management():
    users = load_users()
    return render_template("user_management.html", users=users, current_user=current_user)

@app.route("/add_user", methods=["POST"])
@login_required
@require_permission('manage_users')
def add_user():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    role = request.form.get('role', 'readonly')
    email = request.form.get('email', '').strip()
    
    if not username or not password:
        flash('Username and password are required', 'error')
        return redirect(url_for('user_management'))
    
    users = load_users()
    if username in users:
        flash('User already exists', 'error')
        return redirect(url_for('user_management'))
    
    users[username] = {
        'password': hashlib.sha256(password.encode()).hexdigest(),
        'role': role,
        'email': email,
        'created': datetime.datetime.now().isoformat(),
        'created_by': current_user.username
    }
    
    save_users(users)
    logging.info(f"USER_CREATED,{username},{role},{current_user.username}")
    flash(f'User {username} created successfully', 'success')
    return redirect(url_for('user_management'))

@app.route("/delete_user/<username>")
@login_required
@require_permission('manage_users')
def delete_user(username):
    if username == current_user.username:
        flash('Cannot delete your own account', 'error')
        return redirect(url_for('user_management'))
    
    users = load_users()
    if username in users:
        del users[username]
        save_users(users)
        logging.info(f"USER_DELETED,{username},{current_user.username}")
        flash(f'User {username} deleted successfully', 'success')
    else:
        flash('User not found', 'error')
    
    return redirect(url_for('user_management'))

@app.route("/export/<log_type>/<format>")
@login_required
@require_permission('download_reports')
def export_logs(log_type, format):
    if log_type == "vpn":
        logs = parse_logs(MASTER_VPN_LOG)
        headers = ["Time", "Action", "Client", "Public IP", "VPN IP", "Location", "Platform", "Duration"]
    elif log_type == "mfa":
        logs = parse_logs(MFA_LOG)
        headers = ["Time", "Client", "Status"]
    elif log_type == "client":
        logs = parse_logs(CLIENT_LOG)
        headers = ["Time", "Action", "Client"]
    else:
        return "Invalid log type", 400

    today = datetime.date.today().strftime("%Y-%m-%d")
    from_date = request.args.get("from_date", today)
    to_date = request.args.get("to_date", today)
    search_query = request.args.get("search", "").lower()

    filtered_logs = []
    for log in logs:
        if len(log) > 0:
            log_date = log[0].split(" ")[0]
            if from_date <= log_date <= to_date:
                if not search_query or search_query in " ".join(log).lower():
                    filtered_logs.append(log)

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(headers)
        writer.writerows(filtered_logs)
        output.seek(0)
        
        logging.info(f"EXPORT_CSV,{log_type},{len(filtered_logs)},{current_user.username}")
        return send_file(io.BytesIO(output.getvalue().encode()), mimetype="text/csv",
                         download_name=f"{log_type}_logs_{datetime.date.today()}.csv", as_attachment=True)

    elif format == "pdf":
        metadata = {
            'from_date': from_date,
            'to_date': to_date,
            'search_query': search_query
        }
        output = generate_advanced_pdf_report(log_type, filtered_logs, headers, metadata)
        
        logging.info(f"EXPORT_PDF,{log_type},{len(filtered_logs)},{current_user.username}")
        return send_file(output, mimetype="application/pdf",
                         download_name=f"{log_type}_report_{datetime.date.today()}.pdf", as_attachment=True)

    return "Invalid format", 400

@app.route("/api/stats")
@login_required
@require_permission('view_logs')
def api_stats():
    """API endpoint for real-time statistics"""
    active_users = get_active_users()
    disabled_clients = load_disabled_clients()
    
    today = datetime.date.today().strftime("%Y-%m-%d")
    mfa_logs = parse_logs(MFA_LOG)
    
    # Calculate today's MFA stats
    today_mfa = [log for log in mfa_logs if len(log) > 0 and log[0].startswith(today)]
    mfa_success = len([log for log in today_mfa if len(log) > 2 and 'SUCCESS' in log[2]])
    mfa_failures = len([log for log in today_mfa if len(log) > 2 and 'FAIL' in log[2]])
    
    # System metrics
    disk = psutil.disk_usage('/')
    metrics = {
        "cpu": psutil.cpu_percent(),
        "memory": psutil.virtual_memory().percent,
        "disk": disk.percent,
        "network": {
            "bytes_sent": psutil.net_io_counters().bytes_sent,
            "bytes_recv": psutil.net_io_counters().bytes_recv
        }
    }
    
    return jsonify({
        "active_connections": len(active_users),
        "disabled_clients": len(disabled_clients),
        "mfa_success_today": mfa_success,
        "mfa_failures_today": mfa_failures,
        "system_metrics": metrics,
        "timestamp": datetime.datetime.now().isoformat()
    })

@app.route("/audit_logs")
@login_required
@require_permission('audit_logs')
def audit_logs():
    """View dashboard audit logs"""
    audit_logs = []
    if os.path.exists(AUDIT_LOG):
        with open(AUDIT_LOG, 'r') as f:
            lines = f.readlines()
            # Get last 1000 lines
            for line in lines[-1000:]:
                if line.strip():
                    audit_logs.append(line.strip().split(','))
    
    return render_template("audit_logs.html", audit_logs=audit_logs, current_user=current_user)

# Error Handlers
@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", error="Access Denied", 
                         message="You don't have permission to access this resource."), 403

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", error="Page Not Found", 
                         message="The requested page could not be found."), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template("error.html", error="Internal Server Error", 
                         message="An internal error occurred. Please try again later."), 500

if __name__ == "__main__":
    # Create necessary directories
    os.makedirs(os.path.dirname(USERS_DB), exist_ok=True)
    os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(MFA_DIR, exist_ok=True)
    os.makedirs(QR_DIR, exist_ok=True)
    
    # Initialize default users if needed
    load_users()
    
    print("=== Enhanced VPN Dashboard Starting ===")
    print("Default users created: admin/operator/viewer (passwords: admin123/operator123/viewer123)")
    print("Access at: http://<server-ip>:5000")
    
    # Run app (use 0.0.0.0 so systemd can bind)
    app.run(host="0.0.0.0", port=5000, debug=False)
PY

# 5) Deploy templates - UPDATED client_management.html with download buttons
echo "=== Deploying templates ==="

# UPDATED client_management.html with download buttons for .ovpn and QR
cat > "$TEMPLATES_DIR/client_management.html" <<'HTML'
<!-- templates/client_management.html -->
<!DOCTYPE html>
<html>
<head>
<title>Client Management - VPN Dashboard</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-light">

<div class="container mt-4">
  <div class="row">
    <div class="col-md-12">
      
      <!-- Header -->
      <div class="d-flex justify-content-between align-items-center mb-4">
        <h2><i class="fas fa-cogs"></i> Client Management</h2>
        <a href="/" class="btn btn-secondary">
          <i class="fas fa-arrow-left"></i> Back to Dashboard
        </a>
      </div>

      <!-- Flash Messages -->
      {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
          {% for category, message in messages %}
            <div class="alert alert-{{ 'danger' if category == 'error' else 'success' }} alert-dismissible fade show">
              {{ message }}
              <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
          {% endfor %}
        {% endif %}
      {% endwith %}

      <!-- Create New Client -->
      <div class="card mb-4">
        <div class="card-header">
          <h5><i class="fas fa-user-plus"></i> Create New Client</h5>
        </div>
        <div class="card-body">
          <form method="post">
            <input type="hidden" name="action" value="create">
            <div class="row">
              <div class="col-md-8">
                <input type="text" name="client_name" class="form-control" placeholder="Enter client name (e.g., john.doe)" required>
              </div>
              <div class="col-md-4">
                <button type="submit" class="btn btn-success">
                  <i class="fas fa-plus"></i> Create Client
                </button>
              </div>
            </div>
          </form>
        </div>
      </div>

      <!-- Existing Clients -->
      <div class="card mb-4">
        <div class="card-header">
          <h5><i class="fas fa-users"></i> Manage Existing Clients</h5>
        </div>
        <div class="card-body">
          {% if existing_clients %}
          <div class="table-responsive">
            <table class="table table-hover">
              <thead class="table-dark">
                <tr>
                  <th>Client Name</th>
                  <th>Status</th>
                  <th>Downloads</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {% for client in existing_clients %}
                <tr>
                  <td><strong>{{ client }}</strong></td>
                  <td>
                    {% if client in disabled_clients %}
                      <span class="badge bg-warning">
                        <i class="fas fa-ban"></i> Disabled
                      </span>
                      <br><small class="text-muted">{{ disabled_clients[client].reason }}</small>
                    {% else %}
                      <span class="badge bg-success">
                        <i class="fas fa-check-circle"></i> Active
                      </span>
                    {% endif %}
                  </td>
                  <td>
                    <div class="btn-group" role="group">
                      <a href="{{ url_for('download_ovpn', client_name=client) }}" class="btn btn-sm btn-primary">
                        <i class="fas fa-download"></i> .ovpn
                      </a>
                      <a href="{{ url_for('download_qr', client_name=client) }}" class="btn btn-sm btn-info">
                        <i class="fas fa-qrcode"></i> QR
                      </a>
                    </div>
                  </td>
                  <td>
                    <div class="btn-group" role="group">
                      {% if client in disabled_clients %}
                        <form method="post" style="display: inline;">
                          <input type="hidden" name="action" value="enable">
                          <input type="hidden" name="client_name" value="{{ client }}">
                          <button type="submit" class="btn btn-sm btn-success" onclick="return confirm('Enable client {{ client }}?')">
                            <i class="fas fa-check"></i> Enable
                          </button>
                        </form>
                      {% else %}
                        <form method="post" style="display: inline;">
                          <input type="hidden" name="action" value="disable">
                          <input type="hidden" name="client_name" value="{{ client }}">
                          <button type="submit" class="btn btn-sm btn-warning" onclick="return confirm('Disable client {{ client }}?')">
                            <i class="fas fa-ban"></i> Disable
                          </button>
                        </form>
                      {% endif %}
                      
                      <form method="post" style="display: inline;">
                        <input type="hidden" name="action" value="kick">
                        <input type="hidden" name="client_name" value="{{ client }}">
                        <button type="submit" class="btn btn-sm btn-secondary" onclick="return confirm('Kick client {{ client }}?')">
                          <i class="fas fa-sign-out-alt"></i> Kick
                        </button>
                      </form>
                      
                      <form method="post" style="display: inline;">
                        <input type="hidden" name="action" value="revoke">
                        <input type="hidden" name="client_name" value="{{ client }}">
                        <button type="submit" class="btn btn-sm btn-danger" onclick="return confirm('Permanently revoke client {{ client }}? This cannot be undone.')">
                          <i class="fas fa-trash"></i> Revoke
                        </button>
                      </form>
                    </div>
                  </td>
                </tr>
                {% endfor %}
              </tbody>
            </table>
          </div>
          {% else %}
          <div class="text-center py-4 text-muted">
            <i class="fas fa-users-slash fa-3x mb-3"></i>
            <h5>No clients found</h5>
            <p>Create your first VPN client to get started</p>
          </div>
          {% endif %}
        </div>
      </div>

      <!-- Quick Actions -->
      <div class="card">
        <div class="card-header">
          <h5><i class="fas fa-bolt"></i> Quick Actions</h5>
        </div>
        <div class="card-body">
          <div class="row">
            <div class="col-md-4">
              <div class="card border-primary">
                <div class="card-body text-center">
                  <i class="fas fa-download fa-2x text-primary mb-2"></i>
                  <h6>Download Configs</h6>
                  <p class="text-muted small">Client config files (.ovpn) can be downloaded<br>directly from the table above</p>
                </div>
              </div>
            </div>
            <div class="col-md-4">
              <div class="card border-info">
                <div class="card-body text-center">
                  <i class="fas fa-qrcode fa-2x text-info mb-2"></i>
                  <h6>MFA QR Codes</h6>
                  <p class="text-muted small">QR codes for MFA setup can be downloaded<br>directly from the table above</p>
                </div>
              </div>
            </div>
            <div class="col-md-4">
              <div class="card border-warning">
                <div class="card-body text-center">
                  <i class="fas fa-shield-alt fa-2x text-warning mb-2"></i>
                  <h6>Security</h6>
                  <p class="text-muted small">Manage disabled clients and audit logs</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

    </div>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
HTML

# All other templates remain the same - enhanced_dashboard.html, etc.
cat > "$TEMPLATES_DIR/enhanced_dashboard.html" <<'HTML'
<!DOCTYPE html>
<html>
<head>
<title>Enhanced VPN Dashboard</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
  body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
  .main-container { background: rgba(255, 255, 255, 0.95); backdrop-filter: blur(10px); border-radius: 20px; margin: 20px; padding: 0; box-shadow: 0 20px 40px rgba(0,0,0,0.1); }
  
  /* Enhanced Metric Cards */
  .metric-card { 
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
    border-radius: 20px;
    border: none;
    box-shadow: 0 10px 30px rgba(102, 126, 234, 0.3);
    transition: all 0.3s ease;
    overflow: hidden;
    position: relative;
  }
  .metric-card::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 2px;
    background: rgba(255,255,255,0.3);
  }
  .metric-card:hover { 
    transform: translateY(-5px); 
    box-shadow: 0 15px 40px rgba(102, 126, 234, 0.4);
  }
  .metric-card h5 { color: white; font-weight: 600; }
  .metric-card .h3 { color: white; font-weight: bold; }
  
  /* Different gradients for each metric */
  .metric-card.users { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
  .metric-card.disabled { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }
  .metric-card.cpu { background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); }
  .metric-card.memory { background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%); }
  .metric-card.disk { background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); }
  
  .status-indicator { width: 12px; height: 12px; border-radius: 50%; display: inline-block; }
  .status-online { background-color: #28a745; box-shadow: 0 0 5px rgba(40, 167, 69, 0.5); }
  .status-offline { background-color: #dc3545; box-shadow: 0 0 5px rgba(220, 53, 69, 0.5); }
  .status-disabled { background-color: #ffc107; box-shadow: 0 0 5px rgba(255, 193, 7, 0.5); }
  
  /* Sidebar Enhancements */
  .sidebar { 
    background: linear-gradient(180deg, #2c3e50 0%, #34495e 100%); 
    min-height: 100vh; 
    border-radius: 20px 0 0 20px;
    box-shadow: inset -5px 0 15px rgba(0,0,0,0.1);
  }
  .sidebar .nav-link { 
    color: #bdc3c7; 
    padding: 12px 20px;
    border-radius: 10px;
    margin: 5px 15px;
    transition: all 0.3s ease;
  }
  .sidebar .nav-link:hover { 
    color: white; 
    background: rgba(52, 152, 219, 0.2);
    transform: translateX(5px);
  }
  .sidebar .nav-link.active { 
    color: white; 
    background: linear-gradient(135deg, #3498db, #2980b9);
    box-shadow: 0 5px 15px rgba(52, 152, 219, 0.3);
  }
  
  /* Card Enhancements */
  .card { 
    border: none; 
    border-radius: 15px; 
    box-shadow: 0 5px 20px rgba(0,0,0,0.08);
    transition: all 0.3s ease;
  }
  .card:hover { 
    transform: translateY(-2px); 
    box-shadow: 0 10px 30px rgba(0,0,0,0.15);
  }
  .card-header { 
    background: linear-gradient(135deg, #f8f9fa, #e9ecef);
    border-bottom: 1px solid #dee2e6;
    border-radius: 15px 15px 0 0 !important;
    font-weight: 600;
  }
  
  /* Table Enhancements */
  .table { border-radius: 10px; overflow: hidden; }
  .table thead th { 
    background: linear-gradient(135deg, #2c3e50, #34495e);
    color: white;
    font-weight: 600;
    border: none;
  }
  .table-hover tbody tr:hover { background-color: rgba(52, 152, 219, 0.1); }
  
  /* Button Enhancements */
  .btn { border-radius: 10px; font-weight: 500; transition: all 0.3s ease; }
  .btn-primary { 
    background: linear-gradient(135deg, #3498db, #2980b9);
    border: none;
  }
  .btn-primary:hover { 
    background: linear-gradient(135deg, #2980b9, #21618c);
    transform: translateY(-2px);
    box-shadow: 0 5px 15px rgba(52, 152, 219, 0.3);
  }
  
  /* Badge Enhancements */
  .badge { border-radius: 8px; font-size: 0.8em; }
  .badge.bg-success { background: linear-gradient(135deg, #27ae60, #2ecc71) !important; }
  .badge.bg-danger { background: linear-gradient(135deg, #e74c3c, #c0392b) !important; }
  .badge.bg-warning { background: linear-gradient(135deg, #f39c12, #e67e22) !important; }
  
  /* Alert Enhancements */
  .alert { border-radius: 12px; border: none; }
  
  /* Loading Animation */
  .refresh-loading { animation: spin 1s linear infinite; }
  @keyframes spin {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
  }
  
  /* VPN Action Color Fix */
  .vpn-connect { 
    background-color: rgba(40, 167, 69, 0.1) !important; 
    border-left: 4px solid #28a745;
  }
  .vpn-disconnect { 
    background-color: rgba(220, 53, 69, 0.1) !important; 
    border-left: 4px solid #dc3545;
  }
  
  /* MFA Status Color Fix */
  .mfa-success { 
    background-color: rgba(40, 167, 69, 0.1) !important; 
    border-left: 4px solid #28a745;
  }
  .mfa-failed { 
    background-color: rgba(220, 53, 69, 0.1) !important; 
    border-left: 4px solid #dc3545;
  }
  
  /* Scrollable Log Tables */
  .log-table-container {
    max-height: 500px;
    overflow-y: auto;
    border: 1px solid #dee2e6;
    border-radius: 8px;
  }
  .log-table-container::-webkit-scrollbar {
    width: 8px;
  }
  .log-table-container::-webkit-scrollbar-track {
    background: #f1f1f1;
    border-radius: 4px;
  }
  .log-table-container::-webkit-scrollbar-thumb {
    background: #c1c1c1;
    border-radius: 4px;
  }
  .log-table-container::-webkit-scrollbar-thumb:hover {
    background: #a8a8a8;
  }
  .log-table-container .table {
    margin-bottom: 0;
  }
  .log-table-container thead th {
    position: sticky;
    top: 0;
    z-index: 10;
    background: linear-gradient(135deg, #2c3e50, #34495e) !important;
  }
  
  /* Responsive improvements */
  @media (max-width: 768px) {
    .main-container { margin: 10px; border-radius: 15px; }
    .sidebar { border-radius: 15px 15px 0 0; }
    .metric-card { margin-bottom: 15px; }
  }
</style>
</head>
<body>

<div class="container-fluid main-container">
  <div class="row">
    <!-- Sidebar -->
    <nav class="col-md-2 d-none d-md-block sidebar">
      <div class="sidebar-sticky pt-4">
        <div class="text-center mb-4">
          <div class="mb-3">
            <i class="fas fa-shield-alt fa-3x text-white"></i>
          </div>
          <h5 class="text-white mb-1">VPN Dashboard</h5>
          <small class="text-muted">Welcome, {{ current_user.username }}</small><br>
          <small class="badge bg-info mt-1">{{ current_user.role }}</small>
        </div>

        <ul class="nav flex-column">
          <li class="nav-item">
            <a class="nav-link active" href="/">
              <i class="fas fa-tachometer-alt me-2"></i> Dashboard
            </a>
          </li>
          <li class="nav-item">
            <a class="nav-link" href="/clients">
              <i class="fas fa-users me-2"></i> Client Activity
            </a>
          </li>
          {% if current_user.has_permission('manage_clients') %}
          <li class="nav-item">
            <a class="nav-link" href="/client_management">
              <i class="fas fa-cogs me-2"></i> Client Management
            </a>
          </li>
          {% endif %}
          {% if current_user.has_permission('manage_users') %}
          <li class="nav-item">
            <a class="nav-link" href="/user_management">
              <i class="fas fa-user-shield me-2"></i> User Management
            </a>
          </li>
          {% endif %}
          {% if current_user.has_permission('audit_logs') %}
          <li class="nav-item">
            <a class="nav-link" href="/audit_logs">
              <i class="fas fa-clipboard-list me-2"></i> Audit Logs
            </a>
          </li>
          {% endif %}
        </ul>

        <div class="mt-auto pt-3 px-3">
          <a href="/logout" class="nav-link text-danger">
            <i class="fas fa-sign-out-alt me-2"></i> Logout
          </a>
        </div>
      </div>
    </nav>

    <!-- Main content -->
    <main class="col-md-10 ml-sm-auto px-4">
      <div class="pt-4">

        <!-- Flash Messages -->
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, message in messages %}
              <div class="alert alert-{{ 'danger' if category == 'error' else 'success' }} alert-dismissible fade show">
                <i class="fas fa-{{ 'exclamation-triangle' if category == 'error' else 'check-circle' }} me-2"></i>
                {{ message }}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
              </div>
            {% endfor %}
          {% endif %}
        {% endwith %}

        <!-- Header -->
        <div class="d-flex justify-content-between align-items-center mb-4">
          <div>
            <h1 class="h2 mb-1"><i class="fas fa-network-wired me-2"></i> VPN Dashboard</h1>
            <small class="text-muted">Real-time monitoring and management</small>
          </div>
          <button class="btn btn-primary" onclick="refreshFullDashboard()" id="refresh-btn">
            <i class="fas fa-sync-alt me-2" id="refresh-icon"></i> Refresh All
          </button>
        </div>

        <!-- Enhanced Metrics Cards -->
        <div class="row mb-4">
          <div class="col-xl col-md-6">
            <div class="card metric-card users text-white mb-3">
              <div class="card-body">
                <div class="d-flex justify-content-between align-items-center">
                  <div>
                    <h5 class="mb-2"><i class="fas fa-users me-2"></i> Active Users</h5>
                    <div class="h3 mb-0" id="active-count">{{ active_count }}</div>
                    <small class="opacity-75">Currently connected</small>
                  </div>
                  <div class="align-self-center">
                    <i class="fas fa-users fa-3x opacity-25"></i>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div class="col-xl col-md-6">
            <div class="card metric-card disabled text-white mb-3">
              <div class="card-body">
                <div class="d-flex justify-content-between align-items-center">
                  <div>
                    <h5 class="mb-2"><i class="fas fa-ban me-2"></i> Disabled</h5>
                    <div class="h3 mb-0" id="disabled-count">{{ disabled_count }}</div>
                    <small class="opacity-75">Blocked clients</small>
                  </div>
                  <div class="align-self-center">
                    <i class="fas fa-user-slash fa-3x opacity-25"></i>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div class="col-xl col-md-6">
            <div class="card metric-card cpu text-white mb-3">
              <div class="card-body">
                <div class="d-flex justify-content-between align-items-center">
                  <div>
                    <h5 class="mb-2"><i class="fas fa-microchip me-2"></i> CPU</h5>
                    <div class="h3 mb-0" id="cpu-usage">{{ "%.1f"|format(metrics.cpu) }}%</div>
                    <small class="opacity-75">Processor usage</small>
                  </div>
                  <div class="align-self-center">
                    <i class="fas fa-microchip fa-3x opacity-25"></i>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div class="col-xl col-md-6">
            <div class="card metric-card memory text-white mb-3">
              <div class="card-body">
                <div class="d-flex justify-content-between align-items-center">
                  <div>
                    <h5 class="mb-2"><i class="fas fa-memory me-2"></i> Memory</h5>
                    <div class="h3 mb-0" id="memory-usage">{{ "%.1f"|format(metrics.mem) }}%</div>
                    <small class="opacity-75">RAM usage</small>
                  </div>
                  <div class="align-self-center">
                    <i class="fas fa-memory fa-3x opacity-25"></i>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div class="col-xl col-md-6">
            <div class="card metric-card disk text-white mb-3">
              <div class="card-body">
                <div class="d-flex justify-content-between align-items-center">
                  <div>
                    <h5 class="mb-2"><i class="fas fa-hdd me-2"></i> Disk (/)</h5>
                    <div class="h3 mb-0" id="disk-usage">{{ "%.1f"|format(metrics.disk if metrics.disk is defined else 0) }}%</div>
                    <small class="opacity-75">Storage usage</small>
                  </div>
                  <div class="align-self-center">
                    <i class="fas fa-hdd fa-3x opacity-25"></i>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Active Users Table -->
        <div class="card mb-4" id="active-users-card">
          <div class="card-header d-flex justify-content-between align-items-center">
            <h5 class="mb-0"><i class="fas fa-users text-success me-2"></i> Currently Active Users (<span id="active-users-count">{{ active_count }}</span>)</h5>
            <span class="badge bg-success">Live</span>
          </div>
          <div class="card-body" id="active-users-body">
            {% if active_users %}
            <div class="table-responsive">
              <table class="table table-hover">
                <thead class="table-dark">
                  <tr>
                    <th><i class="status-indicator status-online me-2"></i> User</th>
                    <th><i class="fas fa-globe me-2"></i> Real IP</th>
                    <th><i class="fas fa-network-wired me-2"></i> VPN IP</th>
                    <th><i class="fas fa-map-marker-alt me-2"></i> Location</th>
                    <th><i class="fas fa-desktop me-2"></i> Platform</th>
                    <th><i class="fas fa-clock me-2"></i> Connected Since</th>
                    <th><i class="fas fa-hourglass-half me-2"></i> Duration</th>
                  </tr>
                </thead>
                <tbody>
                  {% for user in active_users %}
                  <tr>
                    <td><strong>{{ user.name }}</strong></td>
                    <td><code class="bg-light p-1 rounded">{{ user.real_ip }}</code></td>
                    <td><code class="bg-light p-1 rounded">{{ user.vpn_ip }}</code></td>
                    <td>{{ user.location }}</td>
                    <td>{{ user.platform }}</td>
                    <td>{{ user.since }}</td>
                    <td><span class="badge bg-success">{{ user.duration }}</span></td>
                  </tr>
                  {% endfor %}
                </tbody>
              </table>
            </div>
            {% else %}
            <div class="text-center py-5 text-muted">
              <i class="fas fa-user-slash fa-4x mb-3 opacity-50"></i>
              <h5>No active connections</h5>
              <p class="mb-0">All VPN clients are currently offline</p>
            </div>
            {% endif %}
          </div>
        </div>

        <!-- Disabled Clients Alert -->
        {% if disabled_clients %}
        <div class="alert alert-warning" id="disabled-clients-alert">
          <h5><i class="fas fa-exclamation-triangle me-2"></i> Disabled Clients (<span id="disabled-clients-count">{{ disabled_count }}</span>)</h5>
          <div class="row" id="disabled-clients-list">
            {% for client, info in disabled_clients.items() %}
            <div class="col-md-4 mb-3">
              <div class="card border-warning">
                <div class="card-body p-3">
                  <h6 class="card-title">{{ client }}</h6>
                  <p class="card-text small mb-2">
                    <strong>Reason:</strong> {{ info.reason }}<br>
                    <strong>Disabled:</strong> {{ info.disabled_at[:16] }}
                  </p>
                  {% if current_user.has_permission('manage_clients') %}
                  <a href="/client_management" class="btn btn-sm btn-outline-success">
                    <i class="fas fa-cog me-1"></i> Manage
                  </a>
                  {% endif %}
                </div>
              </div>
            </div>
            {% endfor %}
          </div>
        </div>
        {% endif %}

        <!-- Filters -->
        <div class="card mb-4">
          <div class="card-header">
            <h5 class="mb-0"><i class="fas fa-filter me-2"></i> Log Filters & Export</h5>
          </div>
          <div class="card-body">
            <form method="get" class="row g-3">
              <div class="col-md-4">
                <label class="form-label">Search</label>
                <div class="input-group">
                  <span class="input-group-text"><i class="fas fa-search"></i></span>
                  <input type="text" name="search" class="form-control" placeholder="Search user, IP, or status..." value="{{ search_query }}">
                </div>
              </div>
              <div class="col-md-2">
                <label class="form-label">From Date</label>
                <input type="date" name="from_date" class="form-control" value="{{ from_date }}">
              </div>
              <div class="col-md-2">
                <label class="form-label">To Date</label>
                <input type="date" name="to_date" class="form-control" value="{{ to_date }}">
              </div>
              <div class="col-md-4">
                <label class="form-label">Actions</label>
                <div class="d-flex gap-2">
                  <button type="submit" class="btn btn-primary">
                    <i class="fas fa-search me-1"></i> Filter
                  </button>
                  <a href="/" class="btn btn-secondary">
                    <i class="fas fa-times me-1"></i> Clear
                  </a>
                </div>
              </div>
            </form>

            {% if current_user.has_permission('download_reports') %}
            <hr>
            <div class="row">
              <div class="col-md-6">
                <h6><i class="fas fa-download me-2"></i>VPN Logs Export</h6>
                <div class="btn-group">
                  <a href="{{ url_for('export_logs', log_type='vpn', format='csv', search=search_query, from_date=from_date, to_date=to_date) }}" class="btn btn-success btn-sm">
                    <i class="fas fa-file-csv me-1"></i> CSV
                  </a>
                  <a href="{{ url_for('export_logs', log_type='vpn', format='pdf', search=search_query, from_date=from_date, to_date=to_date) }}" class="btn btn-danger btn-sm">
                    <i class="fas fa-file-pdf me-1"></i> PDF
                  </a>
                </div>
              </div>
              <div class="col-md-6">
                <h6><i class="fas fa-download me-2"></i>MFA Logs Export</h6>
                <div class="btn-group">
                  <a href="{{ url_for('export_logs', log_type='mfa', format='csv', search=search_query, from_date=from_date, to_date=to_date) }}" class="btn btn-success btn-sm">
                    <i class="fas fa-file-csv me-1"></i> CSV
                  </a>
                  <a href="{{ url_for('export_logs', log_type='mfa', format='pdf', search=search_query, from_date=from_date, to_date=to_date) }}" class="btn btn-danger btn-sm">
                    <i class="fas fa-file-pdf me-1"></i> PDF
                  </a>
                </div>
              </div>
            </div>
            {% endif %}
          </div>
        </div>

        <!-- VPN Logs -->
        <div class="card mb-4">
          <div class="card-header d-flex justify-content-between align-items-center">
            <h5 class="mb-0"><i class="fas fa-list me-2"></i> VPN Connection Logs</h5>
            <span class="badge bg-info" id="vpn-logs-count">{{ vpn_logs|length }} entries</span>
          </div>
          <div class="card-body" id="vpn-logs-body">
            <div class="log-table-container">
              <table class="table table-striped table-hover">
                <thead class="table-dark">
                  <tr>
                    <th><i class="fas fa-clock me-1"></i> Time</th>
                    <th><i class="fas fa-bolt me-1"></i> Action</th>
                    <th><i class="fas fa-user me-1"></i> Client</th>
                    <th><i class="fas fa-globe me-1"></i> Public IP</th>
                    <th><i class="fas fa-network-wired me-1"></i> VPN IP</th>
                    <th><i class="fas fa-map-marker-alt me-1"></i> Location</th>
                    <th><i class="fas fa-desktop me-1"></i> Platform</th>
                    <th><i class="fas fa-stopwatch me-1"></i> Duration</th>
                  </tr>
                </thead>
                <tbody>
                  {% for log in vpn_logs[:100] %}
                  {% set action = log[1] | upper %}
                  <tr class="{% if 'CONNECT' in action and 'DISCONNECT' not in action %}vpn-connect{% else %}vpn-disconnect{% endif %}">
                    <td>{{ log[0] }}</td>
                    <td>
                      {% if 'CONNECT' in action and 'DISCONNECT' not in action %}
                        <span class="badge bg-success"><i class="fas fa-plug me-1"></i>{{ log[1] }}</span>
                      {% else %}
                        <span class="badge bg-danger"><i class="fas fa-times me-1"></i>{{ log[1] }}</span>
                      {% endif %}
                    </td>
                    <td><strong>{{ log[2] }}</strong></td>
                    <td><code class="bg-light p-1 rounded">{{ log[3] }}</code></td>
                    <td><code class="bg-light p-1 rounded">{{ log[4] }}</code></td>
                    <td>{{ log[5] }}</td>
                    <td>{{ log[6] if log|length > 6 else '-' }}</td>
                    <td>
                      {% if log|length > 7 and log[7] != '-' %}
                        <span class="badge bg-secondary">{{ log[7] }}</span>
                      {% else %}
                        <span class="text-muted">-</span>
                      {% endif %}
                    </td>
                  </tr>
                  {% endfor %}
                </tbody>
              </table>
            </div>
            {% if vpn_logs|length > 100 %}
            <div class="alert alert-info mt-3">
              <i class="fas fa-info-circle me-2"></i> Showing first 100 of {{ vpn_logs|length }} records. Use export for complete data.
            </div>
            {% endif %}
          </div>
        </div>

        <!-- MFA Logs -->
        <div class="card mb-4">
          <div class="card-header d-flex justify-content-between align-items-center">
            <h5 class="mb-0"><i class="fas fa-key me-2"></i> MFA Authentication Logs</h5>
            <span class="badge bg-info" id="mfa-logs-count">{{ mfa_logs|length }} entries</span>
          </div>
          <div class="card-body" id="mfa-logs-body">
            <div class="log-table-container">
              <table class="table table-striped table-hover">
                <thead class="table-dark">
                  <tr>
                    <th><i class="fas fa-clock me-1"></i> Time</th>
                    <th><i class="fas fa-user me-1"></i> Client</th>
                    <th><i class="fas fa-shield-alt me-1"></i> Status</th>
                  </tr>
                </thead>
                <tbody>
                  {% for log in mfa_logs[:50] %}
                  {% set status = (log[2] if log|length>2 else '') | upper %}
                  <tr class="{% if 'SUCCESS' in status %}mfa-success{% else %}mfa-failed{% endif %}">
                    <td>{{ log[0] if log|length>0 else '-' }}</td>
                    <td><strong>{{ log[1] if log|length>1 else '-' }}</strong></td>
                    <td>
                      {% if 'SUCCESS' in status %}
                        <span class="badge bg-success"><i class="fas fa-check me-1"></i>{{ log[2] }}</span>
                      {% else %}
                        <span class="badge bg-danger"><i class="fas fa-times me-1"></i>{{ log[2] }}</span>
                      {% endif %}
                    </td>
                  </tr>
                  {% endfor %}
                </tbody>
              </table>
            </div>
            {% if mfa_logs|length > 50 %}
            <div class="alert alert-info mt-3">
              <i class="fas fa-info-circle me-2"></i> Showing first 50 of {{ mfa_logs|length }} records.
            </div>
            {% endif %}
          </div>
        </div>

      </div>
    </main>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
let refreshInProgress = false;

function refreshFullDashboard() {
  if (refreshInProgress) return;
  
  refreshInProgress = true;
  const refreshBtn = document.getElementById('refresh-btn');
  const refreshIcon = document.getElementById('refresh-icon');
  
  // Show loading state
  refreshBtn.disabled = true;
  refreshIcon.classList.add('refresh-loading');
  refreshBtn.innerHTML = '<i class="fas fa-sync-alt me-2 refresh-loading"></i> Refreshing...';
  
  // Refresh stats first
  fetch('/api/stats')
    .then(response => response.json())
    .then(data => {
      // Update metrics
      document.getElementById('active-count').textContent = data.active_connections || 0;
      document.getElementById('disabled-count').textContent = data.disabled_count || 0;
      document.getElementById('cpu-usage').textContent = (data.system_metrics.cpu || 0).toFixed(1) + '%';
      document.getElementById('memory-usage').textContent = (data.system_metrics.memory || 0).toFixed(1) + '%';
      document.getElementById('disk-usage').textContent = (data.system_metrics.disk || 0).toFixed(1) + '%';
      
      // Update active users count
      document.getElementById('active-users-count').textContent = data.active_connections || 0;
      
      console.log('Dashboard stats updated:', data.timestamp);
    })
    .catch(error => {
      console.error('Error refreshing stats:', error);
      // Show error notification
      showNotification('Error refreshing stats', 'error');
HTML

# All other template files remain the same (user_management.html, login.html, etc.)
cat > "$TEMPLATES_DIR/user_management.html" <<'HTML'
<!DOCTYPE html>
<html>
<head>
  <title>User Management - VPN Dashboard</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body { background-color: #f8f9fa; }
    .card { border-radius: 12px; box-shadow: 0 6px 16px rgba(0,0,0,0.1); }
    .card-header { font-weight: bold; }
    .badge-admin { background-color: #dc3545; }
    .badge-readwrite { background-color: #0d6efd; }
    .badge-readonly { background-color: #6c757d; }
    .table thead { background-color: #0d6efd; color: #fff; }
    .form-control { border-radius: 10px; }
    .btn-rounded { border-radius: 10px; }
  </style>
</head>
<body>
<div class="container mt-4">
  <h2 class="mb-3">ðŸ‘¤ User Management</h2>
  <a href="/" class="btn btn-secondary mb-3">â¬… Back to Dashboard</a>

  <!-- Add User Form -->
  <div class="card mb-4">
    <div class="card-header bg-primary text-white">âž• Add New User</div>
    <div class="card-body">
      <form method="post" action="{{ url_for('add_user') }}">
        <div class="row g-2">
          <div class="col-md-3">
            <input name="username" class="form-control" placeholder="ðŸ‘¤ Username" required>
          </div>
          <div class="col-md-3">
            <input name="password" type="password" class="form-control" placeholder="ðŸ”‘ Password" required>
          </div>
          <div class="col-md-3">
            <select name="role" class="form-control">
              <option value="readonly">ðŸ‘ Readonly</option>
              <option value="readwrite">âœ Read/Write</option>
              <option value="admin">â­ Admin</option>
            </select>
          </div>
          <div class="col-md-2">
            <input name="email" type="email" class="form-control" placeholder="ðŸ“§ Email">
          </div>
          <div class="col-md-1 d-grid">
            <button class="btn btn-success btn-rounded">Add</button>
          </div>
        </div>
      </form>
    </div>
  </div>

  <!-- Existing Users -->
  <div class="card">
    <div class="card-header bg-dark text-white">ðŸ“‹ Existing Users</div>
    <div class="card-body">
      <table class="table table-striped table-hover align-middle">
        <thead>
          <tr>
            <th>User</th>
            <th>Role</th>
            <th>Created</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {% for username, info in users.items() %}
          <tr>
            <td>{{ username }}</td>
            <td>
              {% set role = info.role if info.role is defined else info.get('role','-') %}
              {% if role == "admin" %}
                <span class="badge badge-admin">{{ role|capitalize }}</span>
              {% elif role == "readwrite" %}
                <span class="badge badge-readwrite">{{ role|capitalize }}</span>
              {% elif role == "readonly" %}
                <span class="badge badge-readonly">{{ role|capitalize }}</span>
              {% else %}
                <span class="badge bg-secondary">{{ role }}</span>
              {% endif %}
            </td>
            <td>{{ info.created if info.created is defined else info.get('created','-') }}</td>
            <td>
              <a href="{{ url_for('delete_user', username=username) }}" 
                 class="btn btn-danger btn-sm btn-rounded"
                 onclick="return confirm('Delete {{ username }}?')">
                 ðŸ—‘ Delete
              </a>
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
</div>
</body>
</html>
HTML

cat > "$TEMPLATES_DIR/login.html" <<'HTML'
<!DOCTYPE html>
<html>
<head>
  <title>Login - VPN Dashboard</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body {
      background: linear-gradient(135deg, #0d6efd, #6610f2);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .login-card {
      border-radius: 15px;
      box-shadow: 0 8px 20px rgba(0,0,0,0.2);
    }
    .login-header {
      text-align: center;
      margin-bottom: 20px;
    }
    .login-header h4 {
      font-weight: bold;
      color: #0d6efd;
    }
    .form-control {
      border-radius: 10px;
    }
    .btn-custom {
      border-radius: 10px;
      font-weight: 500;
      padding: 10px;
    }
    .footer-text {
      text-align: center;
      margin-top: 10px;
      font-size: 0.9rem;
      color: #6c757d;
    }
  </style>
</head>
<body>
<div class="container">
  <div class="row justify-content-center">
    <div class="col-md-5 col-lg-4">
      <div class="card login-card p-4">
        <div class="login-header">
          <h4>ðŸ” BCITS VPN Dashboard</h4>
          <p class="text-muted small">Secure Login Access</p>
        </div>

        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, message in messages %}
              <div class="alert alert-{{ 'danger' if category == 'error' else 'success' }} text-center">
                {{ message }}
              </div>
            {% endfor %}
          {% endif %}
        {% endwith %}

        <form method="post">
          <div class="mb-3">
            <input name="username" class="form-control" placeholder="ðŸ‘¤ Username" required>
          </div>
          <div class="mb-3">
            <input name="password" type="password" class="form-control" placeholder="ðŸ”‘ Password" required>
          </div>
          <div class="d-grid">
            <button class="btn btn-primary btn-custom">Login</button>
          </div>
        </form>

        <p class="footer-text">Â© 2025 BCITS | VPN Secure Access</p>
      </div>
    </div>
  </div>
</div>
</body>
</html>
HTML

cat > "$TEMPLATES_DIR/error.html" <<'HTML'
<!DOCTYPE html>
<html>
<head><title>Error</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container mt-5">
  <div class="card p-4">
    <h3>{{ error }}</h3>
    <p>{{ message }}</p>
    <a href="/" class="btn btn-secondary">Back</a>
  </div>
</div>
</body>
</html>
HTML

cat > "$TEMPLATES_DIR/clients.html" <<'HTML'
<!DOCTYPE html>
<html>
<head>
  <title>Client Activity</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body { background-color: #f8f9fa; }
    .activity-card { margin-bottom: 20px; }
    .activity-item { padding: 10px; border-bottom: 1px solid #dee2e6; }
    .activity-item:last-child { border-bottom: none; }
    .timestamp { font-weight: bold; color: #0d6efd; }
    .action { font-weight: 500; }
    .username { font-style: italic; color: #6c757d; }
  </style>
</head>
<body>
<div class="container mt-4">
  <h2 class="mb-3">Client Activity</h2>
  <a href="/" class="btn btn-secondary mb-3">â¬… Back to Dashboard</a>

  <!-- Created Clients -->
  <div class="card activity-card shadow-sm">
    <div class="card-header bg-success text-white">Created</div>
    <div class="card-body">
      {% if created %}
        {% for c in created %}
          <div class="activity-item">
            <span class="timestamp">{{ c[0] }}</span> â€“
            <span class="action text-success">{{ c[1] }}</span> â†’
            <span class="username">{{ c[2] }}</span>
          </div>
        {% endfor %}
      {% else %}
        <p class="text-muted">No clients created yet.</p>
      {% endif %}
    </div>
  </div>

  <!-- Revoked Clients -->
  <div class="card activity-card shadow-sm">
    <div class="card-header bg-danger text-white">Revoked</div>
    <div class="card-body">
      {% if revoked %}
        {% for c in revoked %}
          <div class="activity-item">
            <span class="timestamp">{{ c[0] }}</span> â€“
            <span class="action text-danger">{{ c[1] }}</span> â†’
            <span class="username">{{ c[2] }}</span>
          </div>
        {% endfor %}
      {% else %}
        <p class="text-muted">No clients revoked.</p>
      {% endif %}
    </div>
  </div>
</div>
</body>
</html>
HTML

cat > "$TEMPLATES_DIR/audit_logs.html" <<'HTML'
<!DOCTYPE html>
<html>
<head>
  <title>Audit Logs - VPN Dashboard</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body {
      background-color: #f8f9fa;
    }
    .card {
      border-radius: 12px;
      box-shadow: 0 6px 18px rgba(0,0,0,0.1);
    }
    .card-header {
      font-weight: bold;
      font-size: 1.2rem;
    }
    .logs-container {
      max-height: 600px; /* ~50 lines visible */
      overflow-y: auto;
    }
    thead th {
      position: sticky;
      top: 0;
      background: #fff;
      z-index: 2;
    }
    .badge-info { background-color: #0dcaf0; }
    .badge-error { background-color: #dc3545; }
    .badge-warning { background-color: #ffc107; color: #000; }
    .badge-success { background-color: #198754; }
  </style>
</head>
<body>
<div class="container mt-4">
  <h2 class="mb-3">ðŸ“œ Audit Logs</h2>
  <a href="/" class="btn btn-secondary mb-3">â¬… Back to Dashboard</a>

  <div class="card">
    <div class="card-header bg-primary text-white">
      Dashbord API lOG
    </div>
    <div class="card-body logs-container p-0">
      {% if audit_logs %}
      <table class="table table-striped table-hover table-sm mb-0">
        <thead class="table-light">
          <tr>
            <th>Timestamp</th>
            <th>Level</th>
            <th>Message</th>
          </tr>
        </thead>
        <tbody>
          {% for a in audit_logs %}
          <tr>
            <td>{{ a[0] if a|length>0 else '' }}</td>
            <td>
              {% if a[1] == 'INFO' %}
                <span class="badge badge-info">INFO</span>
              {% elif a[1] == 'ERROR' %}
                <span class="badge badge-error">ERROR</span>
              {% elif a[1] == 'WARNING' %}
                <span class="badge badge-warning">WARNING</span>
              {% elif a[1] == 'SUCCESS' %}
                <span class="badge badge-success">SUCCESS</span>
              {% else %}
                <span class="badge bg-secondary">{{ a[1] }}</span>
              {% endif %}
            </td>
            <td>{{ a[2:]|join(', ') }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      {% else %}
      <p class="p-3 text-muted">No audit logs found.</p>
      {% endif %}
    </div>
  </div>
</div>
</body>
</html>
HTML

# 6) Create the non-interactive client.sh inside the dashboard directory
echo "=== Creating non-interactive client.sh for dashboard delegation ==="
cat > "$CLIENT_BIN" <<'CLIENT_SH'
#!/bin/bash

# ==========================================
# FIXED VERSION: Better error handling and dependency checking
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

# Ensure directories exist with proper permissions
mkdir -p "$OUTPUT_DIR" "$MFA_DIR" "$QR_DIR" "$SCRIPT_DIR"
touch "$CLIENT_LOG" "$DISABLED_LIST"
chmod 664 "$CLIENT_LOG"
chmod 644 "$DISABLED_LIST"

# Check if expect is available, if not use alternative method
check_expect_available() {
    command -v expect >/dev/null 2>&1
}

setup_client_connect_script() {
cat > "$CLIENT_CONNECT_SCRIPT" <<'CONNECT_EOF'
#!/bin/bash
DISABLED_LIST="/etc/openvpn/disabled_clients.txt"
LOG_FILE="/var/log/openvpn/client_activity.log"
CLIENT_NAME="$common_name"

if grep -q "^$CLIENT_NAME$" "$DISABLED_LIST" 2>/dev/null; then
    echo "$(date '+%Y-%m-%d %H:%M:%S'),CONNECTION_BLOCKED,$CLIENT_NAME,Disabled user attempted connection" >> "$LOG_FILE"
    exit 1
fi

echo "$(date '+%Y-%m-%d %H:%M:%S'),CONNECTION_ALLOWED,$CLIENT_NAME,Active user connected" >> "$LOG_FILE"
exit 0
CONNECT_EOF

chmod +x "$CLIENT_CONNECT_SCRIPT"

if ! grep -q "client-connect" "$OPENVPN_CONFIG" 2>/dev/null; then
    echo "script-security 2" >> "$OPENVPN_CONFIG"
    echo "client-connect $CLIENT_CONNECT_SCRIPT" >> "$OPENVPN_CONFIG"
fi
}

add_client() {
    if [[ -n "$1" ]]; then
        CLIENT="$1"
        SILENT=true
    else
        read -p "Enter client name: " CLIENT
        SILENT=false
    fi

    # Validate client name
    if [[ ! "$CLIENT" =~ ^[a-zA-Z0-9._-]+$ ]]; then
        echo "Error: Invalid client name. Use only letters, numbers, dots, hyphens, and underscores."
        return 1
    fi

    # Check if client already exists
    if [[ -f "$EASYRSA_DIR/pki/issued/$CLIENT.crt" ]]; then
        echo "Error: Client $CLIENT already exists"
        return 1
    fi

    # Remove from disabled list if present
    sed -i "/^$CLIENT$/d" "$DISABLED_LIST" 2>/dev/null || true

    cd "$EASYRSA_DIR" || {
        echo "Error: Cannot access EasyRSA directory $EASYRSA_DIR"
        return 1
    }

    # Try different methods for silent operation
    if [[ "$SILENT" == true ]]; then
        if check_expect_available; then
            # Method 1: Use expect if available
            expect -c "
            spawn ./easyrsa build-client-full $CLIENT nopass
            expect \"Type the word 'yes'\" { send \"yes\r\" }
            expect \"Confirm request details:\" { send \"yes\r\" }
            expect eof
            " >/dev/null 2>&1
        else
            # Method 2: Use printf piping (more reliable)
            printf "yes\nyes\n" | timeout 60 ./easyrsa build-client-full "$CLIENT" nopass >/dev/null 2>&1
        fi
        
        # Check if certificate was actually created
        if [[ ! -f "$EASYRSA_DIR/pki/issued/$CLIENT.crt" ]]; then
            echo "Error: Certificate creation failed"
            return 1
        fi
    else
        # Interactive mode
        ./easyrsa build-client-full "$CLIENT" nopass || {
            echo "Error: Certificate creation failed"
            return 1
        }
    fi
    
    # Create .ovpn config file
    CLIENT_FILE="$OUTPUT_DIR/$CLIENT.ovpn"
    
    # Check if required files exist
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
    
    if [[ ! -f "/etc/openvpn/server/tc.key" ]]; then
        echo "Warning: TLS-Crypt key not found, .ovpn file may be incomplete"
    fi

    cat > "$CLIENT_FILE" <<OVPN_CONFIG
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
<ca>
$(cat "$EASYRSA_DIR/pki/ca.crt")
</ca>
<cert>
$(sed -ne '/BEGIN CERTIFICATE/,$p' "$EASYRSA_DIR/pki/issued/$CLIENT.crt")
</cert>
<key>
$(cat "$EASYRSA_DIR/pki/private/$CLIENT.key")
</key>
OVPN_CONFIG

    # Add TLS-Crypt if available
    if [[ -f "/etc/openvpn/server/tc.key" ]]; then
        cat >> "$CLIENT_FILE" <<TLSCRYPT_CONFIG
<tls-crypt>
$(cat /etc/openvpn/server/tc.key)
</tls-crypt>
TLSCRYPT_CONFIG
    fi

    # Set proper permissions on .ovpn file
    chmod 600 "$CLIENT_FILE"

    # Generate MFA secret
    SECRET=$(head /dev/urandom | tr -dc A-Z2-7 | head -c 16)
    echo "$SECRET" > "$MFA_DIR/$CLIENT.secret"
    chmod 600 "$MFA_DIR/$CLIENT.secret"
    
    # Generate QR code (check if qrencode is available)
    if command -v qrencode >/dev/null 2>&1; then
        qrencode -o "$QR_DIR/${CLIENT}_mfa.png" "otpauth://totp/$CLIENT?secret=$SECRET&issuer=OpenVPN" 2>/dev/null || {
            echo "Warning: QR code generation failed"
        }
    else
        echo "Warning: qrencode not installed, QR code not generated"
    fi
    
    # Log the action
    echo "$(date '+%Y-%m-%d %H:%M:%S'),CREATED,$CLIENT" >> "$CLIENT_LOG"
    
    if [[ "$SILENT" == false ]]; then
        echo "âœ… Client added: $CLIENT"
        echo "ðŸ“‚ Config file: $CLIENT_FILE"
        if [[ -f "$QR_DIR/${CLIENT}_mfa.png" ]]; then
            echo "ðŸ“± MFA QR code: $QR_DIR/${CLIENT}_mfa.png"
        fi
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
        read -p "Enter client name to revoke: " CLIENT
        SILENT=false
    fi

    cd "$EASYRSA_DIR" || {
        echo "Error: Cannot access EasyRSA directory"
        return 1
    }
    
    # Check if client exists
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
    
    # Generate CRL
    ./easyrsa gen-crl >/dev/null 2>&1 || {
        echo "Warning: CRL generation failed"
    }
    
    # Remove from disabled list and clean up files
    sed -i "/^$CLIENT$/d" "$DISABLED_LIST" 2>/dev/null || true
    rm -f "$OUTPUT_DIR/$CLIENT.ovpn" "$MFA_DIR/$CLIENT.secret" "$QR_DIR/${CLIENT}_mfa.png"
    
    # Copy CRL to OpenVPN directory
    cp "$EASYRSA_DIR/pki/crl.pem" /etc/openvpn/crl.pem 2>/dev/null || true
    chmod 644 /etc/openvpn/crl.pem 2>/dev/null || true
    
    # Log the action
    echo "$(date '+%Y-%m-%d %H:%M:%S'),REVOKED,$CLIENT" >> "$CLIENT_LOG"
    echo "Client $CLIENT revoked successfully"
    return 0
}

disable_client() {
    if [[ -n "$1" ]]; then
        CLIENT="$1"
    else
        read -p "Enter client name to disable: " CLIENT
    fi

    if [[ ! -f "$OUTPUT_DIR/$CLIENT.ovpn" ]] && [[ ! -f "$EASYRSA_DIR/pki/issued/$CLIENT.crt" ]]; then
        echo "Error: Client $CLIENT not found"
        return 1
    fi
    
    if ! grep -q "^$CLIENT$" "$DISABLED_LIST" 2>/dev/null; then
        echo "$CLIENT" >> "$DISABLED_LIST"
        echo "$(date '+%Y-%m-%d %H:%M:%S'),DISABLED,$CLIENT" >> "$CLIENT_LOG"
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
        read -p "Enter client name to enable: " CLIENT
    fi

    if grep -q "^$CLIENT$" "$DISABLED_LIST" 2>/dev/null; then
        sed -i "/^$CLIENT$/d" "$DISABLED_LIST"
        echo "$(date '+%Y-%m-%d %H:%M:%S'),ENABLED,$CLIENT" >> "$CLIENT_LOG"
        echo "Client $CLIENT enabled successfully"
    else
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
    if [[ -f "$DISABLED_LIST" ]]; then
        while IFS= read -r line; do
            [[ -n "$line" ]] && DISABLED_CLIENTS+=("$line")
        done < "$DISABLED_LIST"
    fi

    for client in "${ALL_CLIENTS[@]}"; do
        if [[ " ${DISABLED_CLIENTS[*]} " =~ " ${client} " ]]; then
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
        read -p "Enter client name: " CLIENT
    fi

    if [[ -f "$EASYRSA_DIR/pki/issued/$CLIENT.crt" ]]; then
        if grep -q "^$CLIENT$" "$DISABLED_LIST" 2>/dev/null; then
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
        read -p "Enter client name to kick: " CLIENT
    fi

    if pkill -f "openvpn.*$CLIENT" 2>/dev/null; then
        echo "Client $CLIENT kicked successfully"
    else
        echo "No active connection found for $CLIENT"
    fi
    echo "$(date '+%Y-%m-%d %H:%M:%S'),KICKED,$CLIENT" >> "$CLIENT_LOG"
}

# Non-interactive flag parsing for dashboard
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

# Interactive menu - unchanged
setup_client_connect_script

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

read -p "Enter your choice (1-7): " OPTION

case $OPTION in
    1) add_client ;;
    2) revoke_client ;;
    3) disable_client ;;
    4) enable_client ;;
    5) list_clients ;;
    6) show_client_status ;;
    7) kick_client ;;
    *) echo "Invalid option" ;;
esac
CLIENT_SH

# Make client.sh executable
chmod +x "$CLIENT_BIN"

# 7) Create systemd service
echo "=== Creating systemd service file: $SERVICE_FILE ==="
cat > "$SERVICE_FILE" <<SERVICE
[Unit]
Description=Enhanced VPN Dashboard Flask App with Client Management
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$APP_DIR
Environment=PATH=$VENV_DIR/bin
ExecStart=$PYTHON_BIN $APP_DIR/app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE

# 8) Permissions
echo "=== Setting permissions ==="
chown -R root:root "$APP_DIR"
chmod -R 750 "$APP_DIR"
chmod +x "$CLIENT_BIN"
chmod 640 "$REQUIREMENTS_FILE" || true

# 9) Ensure client.sh hooks are setup
echo "=== Setting up client management hooks ==="
"$CLIENT_BIN" --ensure-hooks || echo "Hook setup completed with warnings"

# 10) Enable and start service
echo "=== Reloading systemd and starting vpn_dashboard service ==="
systemctl daemon-reload
systemctl enable vpn_dashboard.service
systemctl restart vpn_dashboard.service

echo "=============================================="
echo "=== VPN Dashboard Installation Complete   ==="
echo "=============================================="
echo ""
echo "âœ“ Dashboard installed to: $APP_DIR"
echo "âœ“ Non-interactive client.sh: $CLIENT_BIN"
echo "âœ“ Service: systemctl status vpn_dashboard.service"
echo "âœ“ Logs: journalctl -u vpn_dashboard.service -f"
echo ""
echo "ðŸŒ Access URL: http://<server-ip>:5000"
echo ""
echo "ðŸ‘¤ Default Users:"
echo "   admin/admin123     (full access)"
echo "   operator/operator123 (read-write)"
echo "   viewer/viewer123   (read-only)"
echo ""
echo "ðŸ“ Key Directories:"
echo "   App: $APP_DIR"
echo "   Templates: $TEMPLATES_DIR"
echo "   Client configs: $OUTPUT_DIR"
echo "   QR codes: $QR_DIR"
echo "   Logs: $LOG_DIR"
echo ""
echo "ðŸ”§ Features Added:"
echo "   âœ“ Client create/revoke/disable/enable/kick via dashboard"
echo "   âœ“ Download .ovpn files directly from dashboard"
echo "   âœ“ Download MFA QR codes directly from dashboard"
echo "   âœ“ Non-interactive client.sh delegation"
echo "   âœ“ True disable enforcement via client-connect hooks"
echo "   âœ“ All original dashboard features preserved"
echo ""
echo "To test client management:"
echo "   1. Login to dashboard as admin"
echo "   2. Go to 'Client Management' section"
echo "   3. Create a new client"
echo "   4. Download .ovpn and QR files"
echo "   5. Test disable/enable/kick functionality"
echo ""
echo "Manual client.sh usage (if needed):"
echo "   $CLIENT_BIN --create username"
echo "   $CLIENT_BIN --disable username"
echo "   $CLIENT_BIN --enable username"
echo "   $CLIENT_BIN --list"
echo ""

