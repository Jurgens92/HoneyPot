#!/usr/bin/env bash
# ============================================================================
# HoneyPot Updater
#
# Pulls the latest changes from the Git repository and updates the
# installed application at /opt/honeypot.  Restarts the service only
# if files actually changed.
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
    error "This updater must be run as root.  Use: sudo bash update.sh"
    exit 1
fi

INSTALL_DIR="/opt/honeypot"
SERVICE_NAME="honeypot"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo ""
echo "============================================"
echo "       HoneyPot Updater                     "
echo "============================================"
echo ""

# --- 1. Pull latest changes from Git --------------------------------------
info "Checking for updates..."
cd "$SCRIPT_DIR"

# Make sure we're in a git repo
if ! git rev-parse --is-inside-work-tree &>/dev/null; then
    error "Not a Git repository. Place this script in the HoneyPot repo directory."
    exit 1
fi

# Save current commit hash
OLD_HASH=$(git rev-parse HEAD)

# Pull latest changes
git fetch origin
BRANCH=$(git rev-parse --abbrev-ref HEAD)
git pull origin "$BRANCH"

# Check if anything changed
NEW_HASH=$(git rev-parse HEAD)

if [ "$OLD_HASH" = "$NEW_HASH" ]; then
    info "Already up to date. No changes to apply."
    echo ""
    exit 0
fi

info "Update found! ($OLD_HASH -> $NEW_HASH)"
echo ""

# --- 2. Verify install directory exists ------------------------------------
if [ ! -d "$INSTALL_DIR" ]; then
    error "$INSTALL_DIR does not exist. Run install.sh first."
    exit 1
fi

# --- 3. Copy updated application files ------------------------------------
info "Updating application files in $INSTALL_DIR..."

cp "$SCRIPT_DIR/honeypot.py"          "$INSTALL_DIR/"
cp "$SCRIPT_DIR/honeypot_services.py" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/webapp.py"            "$INSTALL_DIR/"
cp "$SCRIPT_DIR/database.py"          "$INSTALL_DIR/"
cp "$SCRIPT_DIR/requirements.txt"     "$INSTALL_DIR/"
cp -r "$SCRIPT_DIR/templates"         "$INSTALL_DIR/"

if [ -d "$SCRIPT_DIR/static" ]; then
    cp -r "$SCRIPT_DIR/static" "$INSTALL_DIR/"
fi

# --- 4. Update Python dependencies ----------------------------------------
info "Updating Python dependencies..."
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"

# --- 5. Restart the service ------------------------------------------------
info "Restarting $SERVICE_NAME service..."
systemctl daemon-reload
systemctl restart "$SERVICE_NAME"

sleep 2
if systemctl is-active --quiet "$SERVICE_NAME"; then
    info "$SERVICE_NAME service restarted successfully!"
else
    error "Service failed to start after update. Check: journalctl -u $SERVICE_NAME -n 50"
    exit 1
fi

# --- Done ------------------------------------------------------------------
echo ""
echo "============================================"
echo "       Update Complete!                      "
echo "============================================"
echo ""
info "Updated from: ${OLD_HASH:0:8} -> ${NEW_HASH:0:8}"
info "Service status: $(systemctl is-active "$SERVICE_NAME")"
echo ""
