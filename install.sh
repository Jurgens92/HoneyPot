#!/usr/bin/env bash
# ============================================================================
# HoneyPot Installer for Ubuntu 24.04
#
# - Installs Python 3, pip, and dependencies
# - Stops and disables conflicting services (apache2, nginx, sshd, etc.)
# - Moves the real SSH daemon to port 2222 so port 22 is free for the honeypot
# - Installs the honeypot to /opt/honeypot
# - Creates a systemd service so it starts on boot and runs as root
# ============================================================================

set -euo pipefail

# --- Colors ----------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

# --- Root check ------------------------------------------------------------
if [ "$EUID" -ne 0 ]; then
    error "This installer must be run as root.  Use: sudo bash install.sh"
    exit 1
fi

INSTALL_DIR="/opt/honeypot"
SERVICE_NAME="honeypot"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo ""
echo "============================================"
echo "       HoneyPot Installer - Ubuntu 24       "
echo "============================================"
echo ""
info "Source directory : $SCRIPT_DIR"
info "Install directory: $INSTALL_DIR"
echo ""

# --- 1. Update packages and install dependencies --------------------------
info "Updating package lists..."
apt-get update -qq

info "Installing Python 3, pip, and build dependencies..."
apt-get install -y -qq python3 python3-pip python3-venv > /dev/null

# --- 2. Move real SSH to port 2222 ----------------------------------------
if systemctl is-active --quiet ssh || systemctl is-active --quiet sshd; then
    warn "OpenSSH is running on this machine."
    warn "Moving SSH daemon to port 2222 so port 22 is free for the honeypot."

    SSH_CONFIG="/etc/ssh/sshd_config"
    SSHD_OVERRIDE="/etc/ssh/sshd_config.d/honeypot-move-port.conf"

    # Use a drop-in override (cleaner than editing main config)
    mkdir -p /etc/ssh/sshd_config.d
    echo "Port 2222" > "$SSHD_OVERRIDE"
    info "Created $SSHD_OVERRIDE with Port 2222"

    # Restart SSH on the new port
    if systemctl is-active --quiet ssh; then
        systemctl restart ssh
        info "SSH daemon restarted on port 2222"
    elif systemctl is-active --quiet sshd; then
        systemctl restart sshd
        info "SSHD daemon restarted on port 2222"
    fi

    echo ""
    warn "=========================================================="
    warn " IMPORTANT: SSH is now on port 2222!"
    warn " Reconnect with:  ssh -p 2222 user@this-server"
    warn "=========================================================="
    echo ""
fi

# --- 3. Stop conflicting services -----------------------------------------
CONFLICTING_SERVICES="apache2 nginx postfix exim4 mysql mariadb"
for svc in $CONFLICTING_SERVICES; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        warn "Stopping and disabling $svc (conflicts with honeypot ports)..."
        systemctl stop "$svc"
        systemctl disable "$svc"
    fi
done

# --- 4. Copy application files --------------------------------------------
info "Installing honeypot to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"

# Copy all application files
cp "$SCRIPT_DIR/honeypot.py"          "$INSTALL_DIR/"
cp "$SCRIPT_DIR/honeypot_services.py" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/webapp.py"            "$INSTALL_DIR/"
cp "$SCRIPT_DIR/database.py"          "$INSTALL_DIR/"
cp "$SCRIPT_DIR/requirements.txt"     "$INSTALL_DIR/"
cp -r "$SCRIPT_DIR/templates"         "$INSTALL_DIR/"

# Copy static dir if it exists
if [ -d "$SCRIPT_DIR/static" ]; then
    cp -r "$SCRIPT_DIR/static" "$INSTALL_DIR/"
fi

# --- 5. Create Python virtual environment and install packages -------------
info "Setting up Python virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"
info "Python dependencies installed."

# --- 6. Create systemd service ---------------------------------------------
info "Creating systemd service..."
cat > /etc/systemd/system/${SERVICE_NAME}.service <<UNIT
[Unit]
Description=HoneyPot - Fake services and IP logger
After=network.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/venv/bin/python3 ${INSTALL_DIR}/honeypot.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}.service"
systemctl start "${SERVICE_NAME}.service"

# --- 7. Wait and verify ---------------------------------------------------
sleep 2
if systemctl is-active --quiet "${SERVICE_NAME}"; then
    info "HoneyPot service is running!"
else
    error "Service failed to start. Check: journalctl -u ${SERVICE_NAME} -n 50"
    exit 1
fi

# --- Done ------------------------------------------------------------------
LOCAL_IP=$(hostname -I | awk '{print $1}')

echo ""
echo "============================================"
echo "       Installation Complete!                "
echo "============================================"
echo ""
info "Backend UI:      http://${LOCAL_IP}:8080"
info "Published list:  http://${LOCAL_IP}:8080/list.txt"
info "SSH moved to:    port 2222"
echo ""
info "Honeypot services running on:"
echo "  Port 22   - Fake SSH"
echo "  Port 23   - Fake Telnet"
echo "  Port 25   - Fake SMTP"
echo "  Port 80   - Fake HTTP (credential capture)"
echo "  Port 443  - Fake HTTPS (credential capture)"
echo "  Port 1433 - Fake MSSQL"
echo "  Port 1434 - Fake MSSQL Browser"
echo "  Port 3306 - Fake MySQL"
echo "  Port 8443 - Fake RDP"
echo ""
info "Manage the service:"
echo "  sudo systemctl status  ${SERVICE_NAME}"
echo "  sudo systemctl stop    ${SERVICE_NAME}"
echo "  sudo systemctl restart ${SERVICE_NAME}"
echo "  sudo journalctl -u ${SERVICE_NAME} -f"
echo ""
