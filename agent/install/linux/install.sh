#!/usr/bin/env bash
# Discoverykastle agent — Linux installer (Ubuntu / Debian)
#
# Usage:
#   sudo bash install.sh
#   sudo bash install.sh --enroll-token <TOKEN> --server-url https://dkserver:8443
#
# What this script does:
#   1. Checks prerequisites (Python 3.10+, pip, git)
#   2. Creates a dedicated system user 'dkagent'
#   3. Installs the agent to /opt/discoverykastle/agent/
#   4. Creates a config file at /etc/discoverykastle/agent.conf
#   5. Installs and starts the systemd service
#
# Supported distributions: Ubuntu 20.04+, Debian 11+

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults (override via CLI flags)
# ---------------------------------------------------------------------------
INSTALL_DIR="/opt/discoverykastle/agent"
CONFIG_FILE="/etc/discoverykastle/agent.conf"
DATA_DIR="/var/lib/discoverykastle/agent"
LOG_DIR="/var/log/discoverykastle"
SERVICE_NAME="discoverykastle-agent"
SERVICE_USER="dkagent"
AGENT_VERSION="main"   # git branch / tag to install

SERVER_URL=""
ENROLL_TOKEN=""

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --server-url)    SERVER_URL="$2";    shift 2 ;;
        --enroll-token)  ENROLL_TOKEN="$2";  shift 2 ;;
        --version)       AGENT_VERSION="$2"; shift 2 ;;
        *)               echo "Unknown argument: $1"; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info()  { echo "  [INFO]  $*"; }
ok()    { echo "  [ OK ]  $*"; }
error() { echo "  [ERR]   $*" >&2; exit 1; }

require_root() {
    [[ $EUID -eq 0 ]] || error "This script must be run as root (use sudo)."
}

require_cmd() {
    command -v "$1" &>/dev/null || error "$1 is required but not found. Install it and retry."
}

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
require_root

info "Checking prerequisites…"
require_cmd python3
require_cmd pip3
require_cmd git
require_cmd systemctl

PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

if [[ $PYTHON_MAJOR -lt 3 || ($PYTHON_MAJOR -eq 3 && $PYTHON_MINOR -lt 10) ]]; then
    error "Python 3.10 or higher is required (found $PYTHON_VERSION)."
fi
ok "Python $PYTHON_VERSION found"

# ---------------------------------------------------------------------------
# System user
# ---------------------------------------------------------------------------
info "Creating system user '$SERVICE_USER'…"
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd \
        --system \
        --no-create-home \
        --shell /usr/sbin/nologin \
        --comment "Discoverykastle agent" \
        "$SERVICE_USER"
    ok "User '$SERVICE_USER' created"
else
    ok "User '$SERVICE_USER' already exists"
fi

# ---------------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------------
info "Creating directories…"
for dir in \
    "$INSTALL_DIR" \
    "$(dirname "$CONFIG_FILE")" \
    "$DATA_DIR" \
    "$LOG_DIR"; do
    mkdir -p "$dir"
done

chown -R "$SERVICE_USER:$SERVICE_USER" \
    "$DATA_DIR" \
    "$LOG_DIR" \
    "$(dirname "$CONFIG_FILE")"

ok "Directories ready"

# ---------------------------------------------------------------------------
# Install agent code
# ---------------------------------------------------------------------------
info "Installing agent to $INSTALL_DIR…"

# Copy repo's agent/ directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Create a virtualenv for isolation
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip

# Install requirements
if [[ -f "$REPO_ROOT/agent/requirements.txt" ]]; then
    "$INSTALL_DIR/venv/bin/pip" install --quiet -r "$REPO_ROOT/agent/requirements.txt"
fi

# Copy agent source
cp -r "$REPO_ROOT/agent" "$INSTALL_DIR/src"
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
ok "Agent installed"

# ---------------------------------------------------------------------------
# Config file
# ---------------------------------------------------------------------------
info "Creating config file at $CONFIG_FILE…"

if [[ -f "$CONFIG_FILE" ]]; then
    info "Config file already exists — skipping (delete it to regenerate)"
else
    cat > "$CONFIG_FILE" <<CONF
# Discoverykastle agent configuration
# Edit this file then restart the service: systemctl restart $SERVICE_NAME

# ---- DK server connection ----------------------------------------
DKASTLE_SERVER_URL=${SERVER_URL}
# Enrollment token (remove after first successful enrollment)
DKASTLE_ENROLL_TOKEN=${ENROLL_TOKEN}

# ---- Agent identity (filled in automatically after enrollment) ----
# DKASTLE_AGENT_ID=
# DKASTLE_AGENT_CERT=${DATA_DIR}/agent.crt
# DKASTLE_AGENT_KEY=${DATA_DIR}/agent.key
# DKASTLE_AGENT_CA=${DATA_DIR}/ca.crt
DKASTLE_AGENT_DATA_DIR=${DATA_DIR}

# ---- Logging -------------------------------------------------------
DKASTLE_LOG_LEVEL=INFO
DKASTLE_LOG_FILE=${LOG_DIR}/agent.log

# ---- Puppet collector (enable if this host IS the Puppet server) --
PUPPET_ENABLED=false
# PUPPET_FACT_CACHE_DIR=/opt/puppetlabs/puppet/cache/yaml/facts
# PUPPET_REPORT_DIR=/opt/puppetlabs/puppet/cache/reports
# PUPPET_SYNC_INTERVAL=3600
CONF
    chmod 640 "$CONFIG_FILE"
    chown "root:$SERVICE_USER" "$CONFIG_FILE"
    ok "Config file created"
fi

# ---------------------------------------------------------------------------
# systemd service
# ---------------------------------------------------------------------------
info "Installing systemd service…"

# Patch the service file with the actual install dir
sed "s|/opt/discoverykastle/agent|$INSTALL_DIR|g" \
    "$SCRIPT_DIR/discoverykastle-agent.service" \
    > "/etc/systemd/system/$SERVICE_NAME.service"

# Fix PYTHONPATH so the agent module is importable from the src copy
sed -i \
    "s|ExecStart=.*|ExecStart=$INSTALL_DIR/venv/bin/python -m agent\nEnvironment=PYTHONPATH=$INSTALL_DIR/src|" \
    "/etc/systemd/system/$SERVICE_NAME.service"

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

# ---------------------------------------------------------------------------
# Start or skip based on whether enrollment info is present
# ---------------------------------------------------------------------------
if [[ -n "$SERVER_URL" && -n "$ENROLL_TOKEN" ]]; then
    info "Starting agent (will enroll on first run)…"
    systemctl start "$SERVICE_NAME"
    sleep 3
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        ok "Service started successfully"
    else
        echo ""
        echo "  Service failed to start. Check logs with:"
        echo "    journalctl -u $SERVICE_NAME -n 50"
    fi
else
    echo ""
    echo "  ---------------------------------------------------------------"
    echo "  Service installed but NOT started."
    echo "  Edit $CONFIG_FILE and set:"
    echo "    DKASTLE_SERVER_URL=https://your-dkserver:8443"
    echo "    DKASTLE_ENROLL_TOKEN=<token from DK dashboard>"
    echo "  Then run:"
    echo "    systemctl start $SERVICE_NAME"
    echo "  ---------------------------------------------------------------"
fi

echo ""
ok "Installation complete"
echo ""
echo "  Useful commands:"
echo "    systemctl status  $SERVICE_NAME"
echo "    systemctl restart $SERVICE_NAME"
echo "    journalctl -u $SERVICE_NAME -f"
echo "    cat $LOG_DIR/agent.log"
echo ""
