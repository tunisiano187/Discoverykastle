#!/usr/bin/env bash
# Discoverykastle agent — Linux uninstaller
#
# Usage: sudo bash uninstall.sh [--purge]
#   --purge   also removes the config file and all collected data

set -euo pipefail

INSTALL_DIR="/opt/discoverykastle/agent"
CONFIG_FILE="/etc/discoverykastle/agent.conf"
DATA_DIR="/var/lib/discoverykastle/agent"
LOG_DIR="/var/log/discoverykastle"
SERVICE_NAME="discoverykastle-agent"
SERVICE_USER="dkagent"

PURGE=false
[[ "${1:-}" == "--purge" ]] && PURGE=true

info()  { echo "  [INFO]  $*"; }
ok()    { echo "  [ OK ]  $*"; }

[[ $EUID -eq 0 ]] || { echo "Run as root (sudo)."; exit 1; }

info "Stopping and disabling service…"
systemctl stop    "$SERVICE_NAME" 2>/dev/null || true
systemctl disable "$SERVICE_NAME" 2>/dev/null || true
rm -f "/etc/systemd/system/$SERVICE_NAME.service"
systemctl daemon-reload
ok "Service removed"

info "Removing agent files from $INSTALL_DIR…"
rm -rf "$INSTALL_DIR"
ok "Agent files removed"

if $PURGE; then
    info "Purging config, data and logs…"
    rm -rf "$(dirname "$CONFIG_FILE")" "$DATA_DIR" "$LOG_DIR"
    userdel "$SERVICE_USER" 2>/dev/null || true
    ok "Config, data and logs purged"
else
    echo ""
    echo "  Config and data preserved at:"
    echo "    $CONFIG_FILE"
    echo "    $DATA_DIR"
    echo "    $LOG_DIR"
    echo "  Run with --purge to remove them."
fi

ok "Uninstall complete"
