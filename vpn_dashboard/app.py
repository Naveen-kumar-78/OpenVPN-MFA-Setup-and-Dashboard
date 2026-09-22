#!/usr/bin/env python3
"""
Zubby VPN Dashboard - Production Grade
Features: SQLite storage, salted passwords, persistent secret key, RBAC,
real-time dashboard refresh, client delegation, and robust auditing.
"""

import os
import re
import io
import csv
import json
import psutil
import sqlite3
import datetime
import subprocess
import logging
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib import colors

# ==========================
# Global Constants & Paths
# ==========================
DB_PATH = "/etc/openvpn/zubby_vpn.db"
LEGACY_USERS_JSON = "/root/vpn_dashboard/users.json"
SECRET_KEY_FILE = "/etc/openvpn/dashboard_secret.key"

MASTER_VPN_LOG = "/var/log/openvpn/custom_logs/master_connection_audit.log"
MFA_LOG = "/var/log/openvpn/mfa_attempts.log"
CLIENT_LOG = "/var/log/openvpn/client_activity.log"
CONNECTION_LOG = "/var/log/openvpn/connection_audit.log"
DISABLED_LIST = "/etc/openvpn/disabled_clients.txt"
AUDIT_LOG = "/var/log/openvpn/dashboard_audit.log"
STATUS_LOG = "/var/log/openvpn/status.log"

EASYRSA_DIR = "/etc/openvpn/server/easy-rsa"
OUTPUT_DIR = "/etc/openvpn/clients" if os.path.exists("/etc/openvpn/clients") else "/root/ovpn_clients"
MFA_DIR = "/etc/openvpn/mfa-secrets"
QR_DIR = os.path.join(OUTPUT_DIR, "qr")

DASH_DIR = os.path.dirname(os.path.abspath(__file__))
CLIENT_BIN = "/usr/local/bin/client.sh" if os.path.exists("/usr/local/bin/client.sh") else os.path.join(DASH_DIR, "client.sh")

# Ensure required directories exist when possible
for p in [os.path.dirname(DB_PATH), os.path.dirname(MASTER_VPN_LOG),
          OUTPUT_DIR, MFA_DIR, QR_DIR, os.path.dirname(AUDIT_LOG)]:
    try:
        os.makedirs(p, exist_ok=True)
    except Exception:
        pass

# ==========================
# Flask App Setup & Security
# ==========================
app = Flask(__name__)

def get_or_create_secret_key():
    """Load or generate a persistent 32-byte cryptographic secret key"""
    if os.path.exists(SECRET_KEY_FILE):
        try:
            with open(SECRET_KEY_FILE, "r") as f:
                key = f.read().strip()
                if len(key) >= 32:
                    return key
        except Exception:
            pass
    key = os.urandom(32).hex()
    try:
        with open(SECRET_KEY_FILE, "w") as f:
            f.write(key)
        os.chmod(SECRET_KEY_FILE, 0o600)
    except Exception:
        pass
    return key

app.secret_key = get_or_create_secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(hours=12)
)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@app.context_processor
def inject_theme():
    return {'current_theme': request.cookies.get('zubby_theme', 'dark')}

try:
    logging.basicConfig(
        filename=AUDIT_LOG,
        level=logging.INFO,
        format='%(asctime)s,%(levelname)s,%(message)s'
    )
except Exception:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s,%(levelname)s,%(message)s'
    )

# ==========================
# In-Memory IP Login Rate Limiter
# ==========================
LOGIN_ATTEMPTS = {}
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_WINDOW = 300  # 5 minutes in seconds

def is_ip_rate_limited(ip):
    """Check if client IP has exceeded maximum failed login attempts within window"""
    now = datetime.datetime.now().timestamp()
    attempts = LOGIN_ATTEMPTS.get(ip, [])
    valid_attempts = [t for t in attempts if now - t < LOGIN_LOCKOUT_WINDOW]
    LOGIN_ATTEMPTS[ip] = valid_attempts
    return len(valid_attempts) >= MAX_LOGIN_ATTEMPTS

def record_login_failure(ip):
    """Record a failed login attempt for the given IP"""
    now = datetime.datetime.now().timestamp()
    if ip not in LOGIN_ATTEMPTS:
        LOGIN_ATTEMPTS[ip] = []
    LOGIN_ATTEMPTS[ip].append(now)

def clear_login_failures(ip):
    """Reset failed login attempts upon successful authentication"""
    LOGIN_ATTEMPTS.pop(ip, None)

# ==========================
# SQLite Database Layer
# ==========================
def get_db():
    """Return a thread-safe connection to SQLite with WAL mode enabled"""
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
    except Exception:
        pass
    return conn

def log_audit(level, action, details, username=None):
    """Log audit trail to SQLite and audit log file"""
    user = username or (current_user.username if current_user and hasattr(current_user, 'username') else 'system')
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO audit_logs (timestamp, level, action, details, user) VALUES (?, ?, ?, ?, ?)",
                (now_str, level, action, details, user)
            )
            conn.commit()
    except Exception as e:
        logging.error(f"Failed to record audit in DB: {e}")
    logging.info(f"{level},{action},{details},{user}")

def init_db():
    """Initialize database tables, indexes, and migrate legacy flat files if present"""
    try:
        with get_db() as conn:
            conn.executescript("""
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
            """)

            # 1. Seed or migrate users
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users")
            if cursor.fetchone()[0] == 0:
                migrated = False
                if os.path.exists(LEGACY_USERS_JSON):
                    try:
                        with open(LEGACY_USERS_JSON, 'r') as f:
                            old_users = json.load(f)
                        for u, data in old_users.items():
                            pwd = data.get('password', '')
                            cursor.execute(
                                "INSERT OR IGNORE INTO users (username, password_hash, role, email, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?)",
                                (u, pwd, data.get('role', 'readonly'), data.get('email', ''), data.get('created', datetime.datetime.now().isoformat()), 'migration')
                            )
                        conn.commit()
                        migrated = True
                    except Exception as e:
                        logging.warning(f"Error migrating legacy users.json: {e}")

                if not migrated:
                    defaults = [
                        ("admin", generate_password_hash("admin123"), "admin", "admin@example.com", "system"),
                        ("operator", generate_password_hash("operator123"), "readwrite", "operator@example.com", "system"),
                        ("viewer", generate_password_hash("viewer123"), "readonly", "viewer@example.com", "system"),
                    ]
                    cursor.executemany("INSERT OR IGNORE INTO users (username, password_hash, role, email, created_by) VALUES (?, ?, ?, ?, ?)", defaults)
                    conn.commit()

            # 2. Migrate disabled clients from text file
            if os.path.exists(DISABLED_LIST):
                try:
                    with open(DISABLED_LIST, 'r') as f:
                        for line in f:
                            cl = line.strip()
                            if cl:
                                cursor.execute(
                                    "INSERT OR IGNORE INTO disabled_clients (client_name, reason, disabled_by) VALUES (?, ?, ?)",
                                    (cl, "Imported from disabled_clients.txt", "system")
                                )
                    conn.commit()
                except Exception as e:
                    logging.warning(f"Error migrating disabled clients: {e}")

            # 3. Migrate historical connection logs if empty
            cursor.execute("SELECT COUNT(*) FROM connection_logs")
            if cursor.fetchone()[0] == 0 and os.path.exists(MASTER_VPN_LOG):
                try:
                    with open(MASTER_VPN_LOG, 'r') as f:
                        reader = csv.reader(f)
                        for row in reader:
                            if len(row) >= 7:
                                ts = row[0].strip()
                                act = row[1].strip()
                                cl = row[2].strip()
                                pub_ip = row[3].strip() if len(row) > 3 else '-'
                                vpn_ip = row[4].strip() if len(row) > 4 else '-'
                                loc = row[5].strip() if len(row) > 5 else '-'
                                plat = row[6].strip() if len(row) > 6 else '-'
                                dur = row[7].strip() if len(row) > 7 else '-'
                                cursor.execute(
                                    "INSERT INTO connection_logs (timestamp, action, client_name, public_ip, vpn_ip, location, platform, duration) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                    (ts, act, cl, pub_ip, vpn_ip, loc, plat, dur)
                                )
                    conn.commit()
                except Exception as e:
                    logging.warning(f"Error migrating historical connection logs: {e}")

            # 4. Migrate MFA attempts if empty
            cursor.execute("SELECT COUNT(*) FROM mfa_logs")
            if cursor.fetchone()[0] == 0 and os.path.exists(MFA_LOG):
                try:
                    with open(MFA_LOG, 'r') as f:
                        reader = csv.reader(f)
                        for row in reader:
                            if len(row) >= 3:
                                ts, u, st = row[0].strip(), row[1].strip(), row[2].strip()
                                dt = row[3].strip() if len(row) > 3 else ''
                                cursor.execute("INSERT INTO mfa_logs (timestamp, username, status, details) VALUES (?, ?, ?, ?)", (ts, u, st, dt))
                    conn.commit()
                except Exception as e:
                    logging.warning(f"Error migrating MFA attempts: {e}")

            # 5. Ensure mfa_logs has ip column
            try:
                cursor.execute("ALTER TABLE mfa_logs ADD COLUMN ip TEXT DEFAULT '-'")
                conn.commit()
            except Exception:
                pass
    except Exception as e:
        logging.error(f"init_db error: {e}")

# ==========================
# User Model & Authentication
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
            'operator': ['view_logs', 'download_reports', 'manage_clients', 'generate_reports'],
            'readwrite': ['view_logs', 'download_reports', 'manage_clients', 'generate_reports'],
            'admin': ['view_logs', 'download_reports', 'manage_clients', 'generate_reports',
                      'manage_users', 'system_settings', 'audit_logs']
        }
        return permission in permissions.get(self.role, [])

def verify_user_password(stored_hash, password):
    """Verify password against scrypt/pbkdf2 hash, with fallback to legacy SHA256"""
    if stored_hash.startswith("scrypt:") or stored_hash.startswith("pbkdf2:"):
        return check_password_hash(stored_hash, password)
    # Legacy SHA256 check (64 hex characters)
    import hashlib
    legacy_hash = hashlib.sha256(password.encode()).hexdigest()
    return stored_hash == legacy_hash

@login_manager.user_loader
def user_loader(username):
    try:
        with get_db() as conn:
            row = conn.execute("SELECT username, role, email FROM users WHERE username = ?", (username,)).fetchone()
            if row:
                return User(row["username"], row["role"], row["email"] or "")
    except Exception as e:
        logging.error(f"user_loader error: {e}")
    return None

def require_permission(permission):
    """Decorator to enforce role-based access control"""
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
# Client Management Delegation
# ==========================
def sanitize_client_name(name):
    """Ensure client name contains only safe alphanumeric, dash, dot, and underscore characters"""
    if not name or not re.match(r'^[a-zA-Z0-9._-]+$', name):
        return None
    cleaned = secure_filename(name)
    return cleaned if cleaned == name else None

def require_client_bin():
    if not os.path.exists(CLIENT_BIN) or not os.access(CLIENT_BIN, os.X_OK):
        raise FileNotFoundError(f"client.sh not found or not executable at {CLIENT_BIN}")

def call_client_action(action, client_name=None):
    """Call client.sh script non-interactively with parameters (using sudo if unprivileged)"""
    require_client_bin()
    if os.geteuid() != 0:
        cmd = ["sudo", "-n", CLIENT_BIN, f"--{action}"]
    else:
        cmd = [CLIENT_BIN, f"--{action}"]
    if client_name:
        cmd.append(client_name)

    try:
        env = os.environ.copy()
        env['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
            cwd=DASH_DIR
        )
        success = result.returncode == 0
        message = result.stdout.strip() if result.stdout else result.stderr.strip()
        log_audit("INFO" if success else "WARNING", f"SUBPROCESS_{action.upper()}", f"client={client_name}, msg={message}")
        return success, message
    except subprocess.TimeoutExpired:
        msg = "Operation timed out after 120 seconds"
        log_audit("ERROR", f"SUBPROCESS_{action.upper()}_TIMEOUT", msg)
        return False, msg
    except Exception as e:
        msg = str(e)
        log_audit("ERROR", f"SUBPROCESS_{action.upper()}_ERROR", msg)
        return False, msg

def create_client_delegated(client_name):
    clean_name = sanitize_client_name(client_name)
    if not clean_name:
        return False, "Invalid client name. Use only letters, numbers, dots, hyphens, and underscores."

    client_file = os.path.join(OUTPUT_DIR, f"{clean_name}.ovpn")
    if os.path.exists(client_file):
        return False, f"Client {clean_name} already exists"

    success, message = call_client_action("create", clean_name)
    if success:
        log_audit("INFO", "CLIENT_CREATED", f"Client {clean_name} created successfully")
        return True, f"Client {clean_name} created successfully"
    return False, f"Failed to create client: {message}"

def revoke_client_delegated(client_name):
    clean_name = sanitize_client_name(client_name)
    if not clean_name:
        return False, "Invalid client name"
    success, message = call_client_action("revoke", clean_name)
    if success:
        with get_db() as conn:
            conn.execute("DELETE FROM disabled_clients WHERE client_name = ?", (clean_name,))
            conn.execute("DELETE FROM active_sessions WHERE client_name = ?", (clean_name,))
            conn.commit()
        log_audit("INFO", "CLIENT_REVOKED", f"Client {clean_name} revoked")
    return success, message

def disable_client(client_name, reason="Manually disabled"):
    clean_name = sanitize_client_name(client_name)
    if not clean_name:
        return False, "Invalid client name"

    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user_str = current_user.username if current_user and hasattr(current_user, 'username') else 'system'

    # Delegate to client.sh if available
    try:
        call_client_action("disable", clean_name)
    except Exception:
        pass

    # Update SQLite
    with get_db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO disabled_clients (client_name, reason, disabled_at, disabled_by) VALUES (?, ?, ?, ?)",
            (clean_name, reason, now_str, user_str)
        )
        conn.execute(
            "INSERT INTO client_activity (timestamp, action, client_name, details) VALUES (?, 'DISABLED', ?, ?)",
            (now_str, clean_name, reason)
        )
        conn.commit()

    # Sync text file
    sync_disabled_text_file()
    log_audit("INFO", "CLIENT_DISABLED", f"Client {clean_name} disabled: {reason}")
    return True, f"Client {clean_name} disabled successfully"

def enable_client(client_name):
    clean_name = sanitize_client_name(client_name)
    if not clean_name:
        return False, "Invalid client name"

    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Delegate to client.sh if available
    try:
        call_client_action("enable", clean_name)
    except Exception:
        pass

    # Update SQLite
    with get_db() as conn:
        conn.execute("DELETE FROM disabled_clients WHERE client_name = ?", (clean_name,))
        conn.execute(
            "INSERT INTO client_activity (timestamp, action, client_name, details) VALUES (?, 'ENABLED', ?, 'Client enabled')",
            (now_str, clean_name)
        )
        conn.commit()

    # Sync text file
    sync_disabled_text_file()
    log_audit("INFO", "CLIENT_ENABLED", f"Client {clean_name} enabled")
    return True, f"Client {clean_name} enabled successfully"

def kick_openvpn_mgmt(client_name):
    """Directly terminate active OpenVPN tunnel via localhost management interface (127.0.0.1:7505)"""
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.5)
        s.connect(('127.0.0.1', 7505))
        s.recv(1024)
        s.sendall(f"kill {client_name}\r\nquit\r\n".encode())
        res = s.recv(1024).decode()
        s.close()
        logging.info(f"OpenVPN management kill {client_name} response: {res.strip()}")
        return "SUCCESS" in res or "killed" in res.lower()
    except Exception as e:
        logging.warning(f"OpenVPN management socket connection failed: {e}")
        return False

def kick_client(client_name):
    clean_name = sanitize_client_name(client_name)
    if not clean_name:
        return False, "Invalid client name"

    # 1. Terminate live tunnel directly via OpenVPN management socket
    mgmt_ok = kick_openvpn_mgmt(clean_name)

    # 2. Delegate to client.sh for secondary firewall drops / CLI auditing
    try:
        call_client_action("kick", clean_name)
    except Exception as e:
        logging.warning(f"call_client_action kick warning: {e}")

    # 3. Clean up active session in SQLite
    with get_db() as conn:
        conn.execute("DELETE FROM active_sessions WHERE client_name = ?", (clean_name,))
        conn.commit()

    log_audit("INFO", "CLIENT_KICKED", f"Client {clean_name} disconnected (mgmt_socket={'success' if mgmt_ok else 'dispatched'})")
    return True, f"Client {clean_name} disconnected successfully"

def sync_disabled_text_file():
    """Ensure /etc/openvpn/disabled_clients.txt matches SQLite disabled_clients"""
    try:
        with get_db() as conn:
            rows = conn.execute("SELECT client_name FROM disabled_clients").fetchall()
            names = [r["client_name"] for r in rows]
        with open(DISABLED_LIST, "w") as f:
            for n in names:
                f.write(f"{n}\n")
    except Exception as e:
        logging.warning(f"Failed to sync disabled clients text file: {e}")

def load_disabled_clients():
    """Load dictionary of disabled clients from SQLite"""
    res = {}
    try:
        with get_db() as conn:
            rows = conn.execute("SELECT client_name, reason, disabled_at, disabled_by FROM disabled_clients ORDER BY disabled_at DESC").fetchall()
            for r in rows:
                res[r["client_name"]] = {
                    "reason": r["reason"],
                    "disabled_at": r["disabled_at"],
                    "disabled_by": r["disabled_by"],
                    "by": r["disabled_by"]
                }
    except Exception as e:
        logging.error(f"Error loading disabled clients: {e}")
    return res

def format_network_bytes(b):
    """Format byte counts into human-readable strings"""
    try:
        val = float(b)
        if val >= 1073741824:
            return f"{val / 1073741824:.2f} GB"
        if val >= 1048576:
            return f"{val / 1048576:.1f} MB"
        if val >= 1024:
            return f"{val / 1024:.0f} KB"
        return f"{int(val)} B"
    except Exception:
        return "-"

def get_openvpn_live_traffic():
    """Parse status.log for live bytes received and sent per active client"""
    traffic = {}
    if not os.path.exists(STATUS_LOG):
        return traffic
    try:
        with open(STATUS_LOG, "r") as f:
            lines = f.readlines()
        is_client_section = False
        for line in lines:
            line = line.strip()
            if "CLIENT LIST" in line or "ROUTING TABLE" in line:
                is_client_section = "CLIENT LIST" in line
                continue
            if line.startswith("CLIENT_LIST,"):
                parts = line.split(",")
                if len(parts) >= 7:
                    cname = parts[1].strip()
                    rx = parts[5].strip()
                    tx = parts[6].strip()
                    traffic[cname] = (format_network_bytes(rx), format_network_bytes(tx))
            elif is_client_section and "," in line and not line.startswith("Common Name"):
                parts = line.split(",")
                if len(parts) >= 4:
                    cname = parts[0].strip()
                    rx = parts[2].strip()
                    tx = parts[3].strip()
                    traffic[cname] = (format_network_bytes(rx), format_network_bytes(tx))
    except Exception as e:
        logging.debug(f"Error parsing status.log traffic: {e}")
    return traffic

# ==========================
# Data Queries & Helpers
# ==========================
def get_active_users():
    """Get active sessions from SQLite table, calculating live durations and bandwidth"""
    active = []
    disabled = load_disabled_clients()
    now = datetime.datetime.now()
    live_traffic = get_openvpn_live_traffic()

    try:
        with get_db() as conn:
            rows = conn.execute("SELECT client_name, public_ip, vpn_ip, location, platform, connected_at FROM active_sessions ORDER BY connected_at DESC").fetchall()
            for r in rows:
                cname = r["client_name"]
                if cname in disabled:
                    continue
                try:
                    ts = datetime.datetime.strptime(r["connected_at"], "%Y-%m-%d %H:%M:%S")
                    dur_sec = max(0, int((now - ts).total_seconds()))
                    dur_str = str(datetime.timedelta(seconds=dur_sec))
                except Exception:
                    dur_str = "-"

                rx_bytes, tx_bytes = live_traffic.get(cname, ("-", "-"))

                active.append({
                    "name": cname,
                    "client_name": cname,
                    "real_ip": r["public_ip"] or "-",
                    "public_ip": r["public_ip"] or "-",
                    "vpn_ip": r["vpn_ip"] or "-",
                    "virtual_ip": r["vpn_ip"] or "-",
                    "location": r["location"] or "-",
                    "platform": r["platform"] or "-",
                    "since": r["connected_at"],
                    "connected_since": r["connected_at"],
                    "duration": dur_str,
                    "bytes_received": rx_bytes,
                    "bytes_sent": tx_bytes
                })
    except Exception as e:
        logging.error(f"Error in get_active_users: {e}")

    return active

def check_mfa_failures():
    """Auto-disable users with 10 or more MFA failures today"""
    try:
        today = datetime.date.today().strftime("%Y-%m-%d")
        with get_db() as conn:
            rows = conn.execute(
                "SELECT username, COUNT(*) as fail_count FROM mfa_logs WHERE status = 'FAIL' AND timestamp LIKE ? GROUP BY username HAVING fail_count >= 10",
                (f"{today}%",)
            ).fetchall()
            disabled = load_disabled_clients()
            for r in rows:
                u = r["username"]
                cnt = r["fail_count"]
                if u not in disabled:
                    disable_client(u, f"Auto-disabled: {cnt} MFA failures today")
                    log_audit("WARNING", "AUTO_DISABLE_MFA", f"User {u} auto-disabled after {cnt} failures")
    except Exception as e:
        logging.error(f"check_mfa_failures error: {e}")

def get_connection_logs(from_date=None, to_date=None, search_query="", limit=200):
    """Query connection logs from SQLite with date filtering and search"""
    logs = []
    try:
        with get_db() as conn:
            query = "SELECT timestamp, action, client_name, public_ip, vpn_ip, location, platform, duration FROM connection_logs WHERE 1=1"
            params = []
            if from_date:
                query += " AND timestamp >= ?"
                params.append(f"{from_date} 00:00:00")
            if to_date:
                query += " AND timestamp <= ?"
                params.append(f"{to_date} 23:59:59")
            if search_query:
                query += " AND (client_name LIKE ? OR public_ip LIKE ? OR vpn_ip LIKE ? OR location LIKE ? OR action LIKE ?)"
                sq = f"%{search_query}%"
                params.extend([sq, sq, sq, sq, sq])
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(query, params).fetchall()
            for r in rows:
                logs.append({
                    "timestamp": r["timestamp"],
                    "action": r["action"],
                    "status": r["action"],
                    "client_name": r["client_name"],
                    "client": r["client_name"],
                    "public_ip": r["public_ip"] or "-",
                    "ip": r["public_ip"] or "-",
                    "vpn_ip": r["vpn_ip"] or "-",
                    "location": r["location"] or "-",
                    "platform": r["platform"] or "-",
                    "duration": r["duration"] or "-"
                })
    except Exception as e:
        logging.error(f"get_connection_logs error: {e}")
    return logs

def get_mfa_logs(from_date=None, to_date=None, search_query="", limit=200):
    """Query MFA logs from SQLite with actual source IP and details separated"""
    logs = []
    try:
        with get_db() as conn:
            query = "SELECT timestamp, username, status, details, COALESCE(ip, '-') as ip FROM mfa_logs WHERE 1=1"
            params = []
            if from_date:
                query += " AND timestamp >= ?"
                params.append(f"{from_date} 00:00:00")
            if to_date:
                query += " AND timestamp <= ?"
                params.append(f"{to_date} 23:59:59")
            if search_query:
                query += " AND (username LIKE ? OR status LIKE ? OR details LIKE ? OR ip LIKE ?)"
                sq = f"%{search_query}%"
                params.extend([sq, sq, sq, sq])
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(query, params).fetchall()
            for r in rows:
                ip_val = r["ip"] if ("ip" in r.keys() and r["ip"] and r["ip"] != "-") else "-"
                logs.append({
                    "timestamp": r["timestamp"],
                    "username": r["username"],
                    "user": r["username"],
                    "client": r["username"],
                    "status": r["status"],
                    "action": r["status"],
                    "details": r["details"] or "-",
                    "ip": ip_val
                })
    except Exception as e:
        # Fallback if ip column does not exist yet
        try:
            with get_db() as conn:
                query = "SELECT timestamp, username, status, details FROM mfa_logs WHERE 1=1"
                params = []
                if from_date:
                    query += " AND timestamp >= ?"
                    params.append(f"{from_date} 00:00:00")
                if to_date:
                    query += " AND timestamp <= ?"
                    params.append(f"{to_date} 23:59:59")
                if search_query:
                    query += " AND (username LIKE ? OR status LIKE ? OR details LIKE ?)"
                    sq = f"%{search_query}%"
                    params.extend([sq, sq, sq])
                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)
                rows = conn.execute(query, params).fetchall()
                for r in rows:
                    logs.append({
                        "timestamp": r["timestamp"],
                        "username": r["username"],
                        "user": r["username"],
                        "client": r["username"],
                        "status": r["status"],
                        "action": r["status"],
                        "details": r["details"] or "-",
                        "ip": "-"
                    })
        except Exception as inner_e:
            logging.error(f"get_mfa_logs error: {inner_e}")
    return logs

def generate_advanced_pdf_report(log_type, filtered_logs, headers, metadata):
    """Generate high quality PDF export report"""
    output = io.BytesIO()
    doc = SimpleDocTemplate(output, pagesize=A4, rightMargin=20, leftMargin=20, topMargin=20, bottomMargin=20)
    styles = getSampleStyleSheet()
    story = []

    title = Paragraph(f"<b>Zubby VPN - {log_type.upper()} Report</b>", styles['Title'])
    story.append(title)
    story.append(Spacer(1, 10))

    meta_info = f"""
    <b>Generated:</b> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>
    <b>Date Filter:</b> {metadata.get('from_date', 'All')} to {metadata.get('to_date', 'All')}<br/>
    <b>Total Records:</b> {len(filtered_logs)}<br/>
    <b>Generated By:</b> {getattr(current_user, 'username', 'system')}<br/>
    <b>Search Filter:</b> {metadata.get('search_query') or 'None'}
    """
    story.append(Paragraph(meta_info, styles['Normal']))
    story.append(Spacer(1, 15))

    if filtered_logs:
        table_data = [headers] + filtered_logs[:200]
        table = Table(table_data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ecf0f1')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#bdc3c7')),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(table)
    else:
        story.append(Paragraph("No records found for the specified period.", styles['Normal']))

    doc.build(story)
    output.seek(0)
    return output

# ==========================
# Routes & Controllers
# ==========================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        client_ip = request.remote_addr or "127.0.0.1"
        if is_ip_rate_limited(client_ip):
            log_audit("WARNING", "LOGIN_RATE_LIMITED", f"IP {client_ip} exceeded maximum failed login attempts")
            flash("Too many failed login attempts from your IP. Please wait 5 minutes.", "warning")
            return render_template("login.html"), 429

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        with get_db() as conn:
            row = conn.execute("SELECT username, password_hash, role, email FROM users WHERE username = ?", (username,)).fetchone()
            if row and verify_user_password(row["password_hash"], password):
                clear_login_failures(client_ip)
                # If password was stored as legacy SHA256, upgrade to strong hash
                if not (row["password_hash"].startswith("scrypt:") or row["password_hash"].startswith("pbkdf2:")):
                    new_hash = generate_password_hash(password)
                    conn.execute("UPDATE users SET password_hash = ? WHERE username = ?", (new_hash, username))
                    conn.commit()

                user = User(row["username"], row["role"], row["email"] or "")
                login_user(user)
                log_audit("INFO", "LOGIN_SUCCESS", f"User {username} logged in", username)
                flash(f"Welcome to Zubby VPN, {username}!", "success")
                return redirect(url_for("dashboard"))

        record_login_failure(client_ip)
        log_audit("WARNING", "LOGIN_FAILED", f"Invalid login attempt for {username} from {client_ip}", username)
        flash("Invalid username or password", "error")

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    log_audit("INFO", "LOGOUT", f"User {current_user.username} logged out")
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route("/", methods=["GET"])
@login_required
def dashboard():
    today = datetime.date.today().strftime("%Y-%m-%d")
    from_date = request.args.get("from_date", today)
    to_date = request.args.get("to_date", today)
    search_query = request.args.get("search", "").strip()

    active_users = get_active_users()
    disabled_clients = load_disabled_clients()
    vpn_logs = get_connection_logs(from_date, to_date, search_query, limit=100)
    mfa_logs = get_mfa_logs(from_date, to_date, search_query, limit=50)

    try:
        disk = psutil.disk_usage('/')
        disk_val = disk.percent
    except Exception:
        disk_val = 0.0

    try:
        mem_val = psutil.virtual_memory().percent
    except Exception:
        mem_val = 0.0

    try:
        cpu_val = psutil.cpu_percent()
    except Exception:
        cpu_val = 0.0

    try:
        uptime_str = str(datetime.datetime.now() - datetime.datetime.fromtimestamp(psutil.boot_time())).split('.')[0]
    except Exception:
        uptime_str = "Unknown"

    metrics = {
        "cpu": cpu_val or 0.0,
        "mem": mem_val or 0.0,
        "memory": mem_val or 0.0,
        "disk": disk_val or 0.0,
        "uptime": uptime_str
    }

    return render_template(
        "enhanced_dashboard.html",
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
        current_user=current_user
    )

@app.route("/clients")
@login_required
@require_permission('view_logs')
def clients():
    disabled_clients = load_disabled_clients()
    with get_db() as conn:
        activity = conn.execute("SELECT timestamp, action, client_name, details FROM client_activity ORDER BY timestamp DESC LIMIT 200").fetchall()

    created = [r for r in activity if r["action"] == "CREATED"]
    revoked = [r for r in activity if r["action"] == "REVOKED"]
    disabled = [r for r in activity if r["action"] == "DISABLED"]
    enabled = [r for r in activity if r["action"] == "ENABLED"]

    return render_template(
        "clients.html",
        created=created,
        revoked=revoked,
        disabled=disabled,
        enabled=enabled,
        disabled_clients=disabled_clients,
        current_user=current_user
    )

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
            success, msg = create_client_delegated(client_name)
            flash(msg, 'success' if success else 'error')
        elif action == 'revoke':
            success, msg = revoke_client_delegated(client_name)
            flash(msg, 'success' if success else 'error')
        elif action == 'disable':
            success, msg = disable_client(client_name, "Manually disabled via Dashboard")
            flash(msg, 'success' if success else 'error')
        elif action == 'enable':
            success, msg = enable_client(client_name)
            flash(msg, 'success' if success else 'error')
        elif action == 'kick':
            success, msg = kick_client(client_name)
            flash(f"Client {client_name} disconnected" if success else f"Failed to kick: {msg}", 'success' if success else 'error')

    existing_clients = []
    try:
        if os.path.exists(OUTPUT_DIR):
            for file in os.listdir(OUTPUT_DIR):
                if file.endswith('.ovpn'):
                    existing_clients.append(file[:-5])
        existing_clients.sort()
    except Exception as e:
        logging.error(f"ERROR_LISTING_CLIENTS: {e}")
        flash('Error reading client config directory', 'error')

    disabled_clients = load_disabled_clients()
    return render_template(
        "client_management.html",
        existing_clients=existing_clients,
        disabled_clients=disabled_clients,
        current_user=current_user
    )

@app.route("/download/ovpn/<client_name>")
@login_required
@require_permission('manage_clients')
def download_ovpn(client_name):
    clean_name = sanitize_client_name(client_name)
    if not clean_name:
        flash("Invalid client name", "error")
        return redirect(url_for('client_management'))

    client_file = os.path.join(OUTPUT_DIR, f"{clean_name}.ovpn")
    if os.path.exists(client_file):
        log_audit("INFO", "DOWNLOAD_OVPN", f"Downloaded config for {clean_name}")
        return send_file(client_file, as_attachment=True, download_name=f"{clean_name}.ovpn")
    flash(f"Client file {clean_name}.ovpn not found", "error")
    return redirect(url_for('client_management'))

@app.route("/download/qr/<client_name>")
@login_required
@require_permission('manage_clients')
def download_qr(client_name):
    clean_name = sanitize_client_name(client_name)
    if not clean_name:
        flash("Invalid client name", "error")
        return redirect(url_for('client_management'))

    qr_file = os.path.join(QR_DIR, f"{clean_name}_mfa.png")
    if os.path.exists(qr_file):
        log_audit("INFO", "DOWNLOAD_QR", f"Downloaded QR for {clean_name}")
        return send_file(qr_file, as_attachment=True, download_name=f"{clean_name}_mfa.png")
    flash(f"QR code for {clean_name} not found", "error")
    return redirect(url_for('client_management'))

@app.route("/user_management", methods=["GET", "POST"])
@login_required
@require_permission('manage_users')
def user_management():
    if request.method == "POST":
        action = request.form.get('action')
        if action == "create":
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            role = request.form.get('role', 'operator').strip()
            email = request.form.get('email', '').strip()

            if not username or not password:
                flash('Username and password are required', 'error')
            elif role not in ['readonly', 'operator', 'readwrite', 'admin']:
                flash('Invalid role selected', 'error')
            else:
                pwd_hash = generate_password_hash(password)
                now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                try:
                    with get_db() as conn:
                        conn.execute(
                            "INSERT INTO users (username, password_hash, role, email, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?)",
                            (username, pwd_hash, role, email, now_str, current_user.username)
                        )
                        conn.commit()
                    log_audit("INFO", "USER_CREATED", f"Created user {username} with role {role}")
                    flash(f"User {username} created successfully", "success")
                except sqlite3.IntegrityError:
                    flash(f"User {username} already exists", "error")
                except Exception as e:
                    flash(f"Error creating user: {e}", "error")

        elif action == "delete":
            username = request.form.get('username', '').strip()
            if username == current_user.username:
                flash('Cannot delete your own account', 'error')
            else:
                with get_db() as conn:
                    res = conn.execute("DELETE FROM users WHERE username = ?", (username,))
                    conn.commit()
                    if res.rowcount > 0:
                        log_audit("INFO", "USER_DELETED", f"Deleted user {username}")
                        flash(f"User {username} deleted successfully", "success")
                    else:
                        flash("User not found", "error")

        elif action == "reset_password":
            username = request.form.get('username', '').strip()
            new_password = request.form.get('new_password', '').strip()
            if not username or not new_password:
                flash('Username and new password are required', 'error')
            elif len(new_password) < 8:
                flash('Password must be at least 8 characters', 'error')
            else:
                pwd_hash = generate_password_hash(new_password)
                with get_db() as conn:
                    res = conn.execute("UPDATE users SET password_hash = ? WHERE username = ?", (pwd_hash, username))
                    conn.commit()
                    if res.rowcount > 0:
                        log_audit("INFO", "USER_PASSWORD_RESET", f"Reset password for {username}")
                        flash(f"Password for {username} reset successfully", "success")
                    else:
                        flash("User not found", "error")

        return redirect(url_for('user_management'))

    with get_db() as conn:
        users = conn.execute("SELECT username, role, email, created_at, created_by FROM users ORDER BY username ASC").fetchall()
    return render_template("user_management.html", users=users, current_user=current_user)

@app.route("/add_user", methods=["POST"])
@login_required
@require_permission('manage_users')
def add_user():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    role = request.form.get('role', 'operator').strip()
    email = request.form.get('email', '').strip()

    if not username or not password:
        flash('Username and password are required', 'error')
        return redirect(url_for('user_management'))

    if role not in ['readonly', 'operator', 'readwrite', 'admin']:
        role = 'operator'

    pwd_hash = generate_password_hash(password)
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, email, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?)",
                (username, pwd_hash, role, email, now_str, current_user.username)
            )
            conn.commit()
        log_audit("INFO", "USER_CREATED", f"Created user {username} with role {role}")
        flash(f"User {username} created successfully", "success")
    except sqlite3.IntegrityError:
        flash(f"User {username} already exists", "error")
    except Exception as e:
        flash(f"Error creating user: {e}", "error")

    return redirect(url_for('user_management'))

@app.route("/delete_user/<username>", methods=["GET", "POST"])
@login_required
@require_permission('manage_users')
def delete_user(username):
    if username == current_user.username:
        flash('Cannot delete your own account', 'error')
        return redirect(url_for('user_management'))

    with get_db() as conn:
        res = conn.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
        if res.rowcount > 0:
            log_audit("INFO", "USER_DELETED", f"Deleted user {username}")
            flash(f"User {username} deleted successfully", "success")
        else:
            flash("User not found", "error")

    return redirect(url_for('user_management'))

@app.route("/audit_logs")
@login_required
@require_permission('audit_logs')
def audit_logs():
    from_date = request.args.get("from_date", "")
    to_date = request.args.get("to_date", "")
    search_query = request.args.get("search", "").strip()

    query = "SELECT timestamp, level, level as target, action, details, user FROM audit_logs WHERE 1=1"
    params = []
    if from_date:
        query += " AND timestamp >= ?"
        params.append(f"{from_date} 00:00:00")
    if to_date:
        query += " AND timestamp <= ?"
        params.append(f"{to_date} 23:59:59")
    if search_query:
        query += " AND (action LIKE ? OR details LIKE ? OR user LIKE ? OR level LIKE ?)"
        sq = f"%{search_query}%"
        params.extend([sq, sq, sq, sq])
    query += " ORDER BY timestamp DESC LIMIT 500"

    with get_db() as conn:
        rows = conn.execute(query, params).fetchall()

    return render_template(
        "audit_logs.html",
        audit_logs=rows,
        from_date=from_date,
        to_date=to_date,
        search_query=search_query,
        current_user=current_user
    )

@app.route("/audit_logs/export")
@login_required
@require_permission('download_reports')
def audit_logs_export():
    return export_logs("audit", "pdf")

@app.route("/export/<log_type>/<format>")
@login_required
@require_permission('download_reports')
def export_logs(log_type, format):
    today = datetime.date.today().strftime("%Y-%m-%d")
    from_date = request.args.get("from_date", "")
    to_date = request.args.get("to_date", "")
    search_query = request.args.get("search", "").strip()

    if log_type == "vpn":
        raw_logs = get_connection_logs(from_date, to_date, search_query, limit=5000)
        logs = [[r["timestamp"], r["action"], r["client"], r["public_ip"], r["vpn_ip"], r["location"], r["platform"], r["duration"]] for r in raw_logs]
        headers = ["Time", "Action", "Client", "Public IP", "VPN IP", "Location", "Platform", "Duration"]
    elif log_type == "mfa":
        raw_logs = get_mfa_logs(from_date, to_date, search_query, limit=5000)
        logs = [[r["timestamp"], r["username"], r["status"], r["details"], r["ip"]] for r in raw_logs]
        headers = ["Time", "Username", "Outcome", "Details", "Source IP"]
    elif log_type == "client":
        with get_db() as conn:
            rows = conn.execute("SELECT timestamp, action, client_name, details FROM client_activity ORDER BY timestamp DESC LIMIT 5000").fetchall()
        logs = [[r[0], r[1], r[2], r[3]] for r in rows]
        headers = ["Time", "Action", "Client", "Details"]
    elif log_type == "audit":
        query = "SELECT timestamp, level, action, details, user FROM audit_logs WHERE 1=1"
        params = []
        if from_date:
            query += " AND timestamp >= ?"
            params.append(f"{from_date} 00:00:00")
        if to_date:
            query += " AND timestamp <= ?"
            params.append(f"{to_date} 23:59:59")
        if search_query:
            query += " AND (action LIKE ? OR details LIKE ? OR user LIKE ? OR level LIKE ?)"
            sq = f"%{search_query}%"
            params.extend([sq, sq, sq, sq])
        query += " ORDER BY timestamp DESC LIMIT 5000"
        with get_db() as conn:
            rows = conn.execute(query, params).fetchall()
        logs = [[r[0], r[1], r[2], r[3], r[4]] for r in rows]
        headers = ["Time", "Level", "Action", "Details", "User"]
    else:
        return "Invalid log type", 400

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(headers)
        writer.writerows(logs)
        output.seek(0)
        log_audit("INFO", "EXPORT_CSV", f"Exported {log_type} logs ({len(logs)} records)")
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8-sig')),
            mimetype="text/csv",
            download_name=f"{log_type}_logs_{datetime.date.today()}.csv",
            as_attachment=True
        )
    elif format in ["excel", "xlsx"]:
        try:
            import pandas as pd
            import openpyxl
            df = pd.DataFrame(logs, columns=headers)
            output = io.BytesIO()
            with pd.ExcelWriter(output, engine='openpyxl') as writer:
                df.to_excel(writer, index=False, sheet_name=f"{log_type.upper()} Logs")
            output.seek(0)
            log_audit("INFO", "EXPORT_EXCEL", f"Exported {log_type} Excel ({len(logs)} records)")
            return send_file(
                output,
                mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                download_name=f"{log_type}_report_{datetime.date.today()}.xlsx",
                as_attachment=True
            )
        except Exception as e:
            logging.warning(f"Excel export error: {e}, falling back to CSV")
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(headers)
            writer.writerows(logs)
            output.seek(0)
            log_audit("INFO", "EXPORT_EXCEL", f"Exported {log_type} Excel-CSV ({len(logs)} records)")
            return send_file(
                io.BytesIO(output.getvalue().encode('utf-8-sig')),
                mimetype="text/csv",
                download_name=f"{log_type}_report_{datetime.date.today()}.csv",
                as_attachment=True
            )
    elif format == "pdf":
        metadata = {'from_date': from_date or 'All', 'to_date': to_date or 'All', 'search_query': search_query or 'None'}
        pdf_out = generate_advanced_pdf_report(log_type, logs, headers, metadata)
        log_audit("INFO", "EXPORT_PDF", f"Exported {log_type} PDF ({len(logs)} records)")
        return send_file(
            pdf_out,
            mimetype="application/pdf",
            download_name=f"{log_type}_report_{datetime.date.today()}.pdf",
            as_attachment=True
        )

    return "Invalid format", 400

# ==========================
# Real-Time API Endpoints
# ==========================
@app.route("/api/stats")
@login_required
def api_dashboard_stats():
    check_mfa_failures()
    active_users = get_active_users()
    disabled_clients = load_disabled_clients()

    today = datetime.date.today().strftime("%Y-%m-%d")
    mfa_success = 0
    mfa_failures = 0
    try:
        with get_db() as conn:
            mfa_success = conn.execute("SELECT COUNT(*) FROM mfa_logs WHERE status = 'SUCCESS' AND timestamp LIKE ?", (f"{today}%",)).fetchone()[0]
            mfa_failures = conn.execute("SELECT COUNT(*) FROM mfa_logs WHERE status = 'FAIL' AND timestamp LIKE ?", (f"{today}%",)).fetchone()[0]
    except Exception:
        pass

    try:
        disk = psutil.disk_usage('/')
        disk_val = disk.percent
    except Exception:
        disk_val = 0.0

    try:
        mem_val = psutil.virtual_memory().percent
    except Exception:
        mem_val = 0.0

    try:
        cpu_val = psutil.cpu_percent()
    except Exception:
        cpu_val = 0.0

    try:
        net_io = psutil.net_io_counters()
        net_bytes_sent = net_io.bytes_sent
        net_bytes_recv = net_io.bytes_recv
    except Exception:
        net_bytes_sent = 0
        net_bytes_recv = 0

    metrics = {
        "cpu": cpu_val or 0.0,
        "mem": mem_val or 0.0,
        "memory": mem_val or 0.0,
        "disk": disk_val or 0.0,
        "network": {
            "bytes_sent": net_bytes_sent,
            "bytes_recv": net_bytes_recv
        }
    }

    return jsonify({
        "status": "ok",
        "active_connections": len(active_users),
        "disabled_clients": len(disabled_clients),
        "disabled_count": len(disabled_clients),
        "mfa_success_today": mfa_success,
        "mfa_failures_today": mfa_failures,
        "metrics": metrics,
        "system_metrics": metrics,
        "active_users": active_users,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

# ==========================
# Error Handlers
# ==========================
@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", error="Access Denied", message="You do not have permission to access this resource."), 403

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", error="Page Not Found", message="The requested page could not be found."), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template("error.html", error="Server Error", message="An unexpected server error occurred."), 500

if __name__ == "__main__":
    init_db()
    print("=== Zubby VPN Dashboard Starting ===")
    print("Database: SQLite (/etc/openvpn/zubby_vpn.db)")
    print("Default accounts: admin / operator / viewer")
    print("Web UI running at: http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
