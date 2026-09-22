# Zubby VPN - OpenVPN MFA Setup & Real-time Dashboard

Enterprise-ready OpenVPN setup that integrates TOTP-based Multi-Factor Authentication (MFA), connection auditing hooks, a high-performance **SQLite** backend, and a modern web dashboard for real-time visibility, telemetry, and access control.

---

## 🚀 Key Features

- **🛡️ Multi-Factor Authentication (MFA)**: TOTP MFA generated per client (compatible with Google Authenticator, Authy, etc.).
- **⚡ SQLite Storage Engine**: Replaced flat-file storage with a centralized, indexed SQLite database (`/etc/openvpn/zubby_vpn.db`) for fast queries, audit logging, and concurrency.
- **🔄 Live Real-Time Dashboard**: Working "Refresh All" button with asynchronous metrics and active connection tracking without full page reloads.
- **🔒 Security Hardened**:
  - Salted password hashing (Scrypt / PBKDF2 via Werkzeug)
  - Persistent 32-byte cryptographic session secret key
  - Strict input sanitization and directory traversal protection on profile downloads
  - Automatic auto-disabling on excessive MFA failures
- **👥 True Access Control**:
  - Instant client blocking and session termination (`kick`) via `client-connect` scripts and SQLite hooks.
  - Role-Based Access Control (Admin, Read/Write, Read-Only).
- **📊 Reporting & Auditing**: One-click CSV and PDF report generation for VPN connection trails and MFA logs.

---

## 🛠️ Quick Start

### 1. Server & OpenVPN Setup
Run the server installer on your Linux host as root:
```bash
sudo bash ovpn.sh
```

### 2. Install Zubby VPN Dashboard
Deploy the SQLite-powered web dashboard:
```bash
sudo bash vpn.sh
```

Access the dashboard at `http://<your-server-ip>:5000`.

### 🔑 Default Credentials
- **Admin**: `admin` / `admin123` (Full administrative privileges)
- **Operator**: `operator` / `operator123` (Client management & reporting)
- **Viewer**: `viewer` / `viewer123` (Read-only log auditing)

---

## 📁 Client Management CLI
Manage clients interactively or via CLI flags:
```bash
# Interactive menu
sudo bash client.sh

# Non-interactive CLI
sudo bash client.sh --create john.doe
sudo bash client.sh --disable john.doe
sudo bash client.sh --enable john.doe
sudo bash client.sh --kick john.doe
sudo bash client.sh --status john.doe
sudo bash client.sh --revoke john.doe
```

## 📂 Project Structure

- `vpn.sh`: Automated installer and systemd service configuration.
- `ovpn.sh`: Server installer, MFA authentication hook & alert system.
- `client.sh`: Client creation, revocation, disabling, and session kicking CLI.
- `vpn_dashboard/`: Modular Flask web dashboard application:
  - `app.py`: Application controllers, SQLite schema, REST API & routes.
  - `requirements.txt`: Python package requirements.
  - `templates/`: Modern Jinja2 templates (`enhanced_dashboard.html`, `client_management.html`, `user_management.html`, `clients.html`, `audit_logs.html`, `login.html`, `error.html`).

---

<img width="387" height="531" alt="Zubby VPN MFA" src="https://github.com/user-attachments/assets/b2049cb6-2d1c-407d-acd6-46d9b7172f39" />

