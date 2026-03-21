#!/usr/bin/env bash
# =============================================================================
# Discoverykastle — Cleanup script
#
# Resets the environment to a clean state for fresh testing.
# Does NOT uninstall Docker, Python, or system packages.
#
# What is removed:
#   ✗  systemd service (discoverykastle)
#   ✗  Docker containers: dkastle-db, dkastle-redis
#   ✗  Docker volumes: dkastle-pgdata, dkastle-redisdata
#   ✗  Docker networks created by docker compose
#   ✗  .env file
#   ✗  webpush_subscriptions.json
#   ✗  discoverykastle.log  (and rotated copies)
#   ✗  install.log
#   ✗  Python virtualenv (.venv/)
#   ✗  __pycache__ directories
#   ✗  Generated TLS certificates (*.pem, *.crt, *.key in project root)
#
# What is KEPT:
#   ✓  Docker Engine and Compose plugin
#   ✓  Python 3.12
#   ✓  All system packages
#   ✓  The project source code
#   ✓  .env.example
#   ✓  git history
#
# Usage:
#   chmod +x cleanup.sh
#   ./cleanup.sh             # interactive (asks for confirmation)
#   ./cleanup.sh --force     # non-interactive (CI / scripted use)
# =============================================================================
set -euo pipefail
IFS=$'\n\t'

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m';  GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}${BOLD}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}${BOLD}[ OK ]${RESET}  $*"; }
warn()    { echo -e "${YELLOW}${BOLD}[WARN]${RESET}  $*"; }
skip()    { echo -e "       ${RESET}skip: $*"; }
removed() { echo -e "${GREEN}       ✗  $*${RESET}"; }

# ── Privilege helper ──────────────────────────────────────────────────────────
asroot() {
    if [ "$EUID" -eq 0 ]; then "$@"; else sudo "$@"; fi
}

# Docker group helper
with_docker() {
    if id -nG "$USER" | grep -qw docker; then
        "$@"
    else
        sg docker -c "$*"
    fi
}

# ── Arguments ─────────────────────────────────────────────────────────────────
FORCE=false
for arg in "$@"; do
    case "$arg" in
        --force|-f) FORCE=true ;;
        --help|-h)
            echo "Usage: $0 [--force]"
            echo "  --force  Skip confirmation prompt (for scripted use)"
            exit 0
            ;;
        *) echo "Unknown argument: $arg"; exit 1 ;;
    esac
done

# ── Project root ──────────────────────────────────────────────────────────────
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="discoverykastle"

cd "$PROJECT_DIR"

# ── Header ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${RED}${BOLD}╔══════════════════════════════════════════════════════╗${RESET}"
echo -e "${RED}${BOLD}║        Discoverykastle — Cleanup / Reset             ║${RESET}"
echo -e "${RED}${BOLD}╚══════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  Working directory : ${CYAN}${PROJECT_DIR}${RESET}"
echo ""

# ── What will be removed ──────────────────────────────────────────────────────
echo -e "${BOLD}The following will be permanently removed:${RESET}"
echo ""

declare -A ITEMS

# systemd service
if systemctl list-unit-files 2>/dev/null | grep -q "^${SERVICE_NAME}.service"; then
    ITEMS["systemd"]="systemd service '${SERVICE_NAME}' + /etc/systemd/system/${SERVICE_NAME}.service"
fi

# Docker containers / volumes
if command -v docker &>/dev/null && (docker info &>/dev/null 2>&1 || sudo docker info &>/dev/null 2>&1); then
    ITEMS["docker_containers"]="Docker containers: dkastle-db, dkastle-redis"
    ITEMS["docker_volumes"]="Docker volumes: dkastle-pgdata, dkastle-redisdata  ← ALL DATA LOST"
    ITEMS["docker_networks"]="Docker networks created by docker compose"
fi

# Files / directories
[ -f "$PROJECT_DIR/.env" ]                           && ITEMS["env"]=".env"
[ -f "$PROJECT_DIR/webpush_subscriptions.json" ]     && ITEMS["webpush"]="webpush_subscriptions.json"
[ -n "$(ls "$PROJECT_DIR"/discoverykastle.log* 2>/dev/null)" ] \
                                                     && ITEMS["logs"]="discoverykastle.log*"
[ -f "$PROJECT_DIR/install.log" ]                    && ITEMS["ilog"]="install.log"
[ -d "$PROJECT_DIR/.venv" ]                          && ITEMS["venv"]=".venv/ (Python virtualenv)"
[ -n "$(find "$PROJECT_DIR" -maxdepth 4 -name '__pycache__' -type d 2>/dev/null | head -1)" ] \
                                                     && ITEMS["pycache"]="__pycache__/ directories"
CERT_FILES=$(find "$PROJECT_DIR" -maxdepth 1 \( -name "*.pem" -o -name "*.crt" -o -name "*.key" \) 2>/dev/null | tr '\n' ' ')
[ -n "$CERT_FILES" ]                                 && ITEMS["certs"]="TLS certs: $CERT_FILES"

if [ ${#ITEMS[@]} -eq 0 ]; then
    success "Nothing to clean — environment is already clean."
    exit 0
fi

for key in "${!ITEMS[@]}"; do
    echo -e "  ${RED}✗${RESET}  ${ITEMS[$key]}"
done
echo ""

# ── Confirmation ──────────────────────────────────────────────────────────────
if [ "$FORCE" = false ]; then
    echo -e "${YELLOW}${BOLD}WARNING: This action is irreversible. All data will be lost.${RESET}"
    echo -n "  Type 'yes' to continue: "
    read -r CONFIRM
    if [ "$CONFIRM" != "yes" ]; then
        echo "  Aborted."
        exit 0
    fi
    echo ""
else
    warn "Running in --force mode. Skipping confirmation."
fi

# =============================================================================
# 1 — Stop and remove systemd service
# =============================================================================
if [[ -v ITEMS["systemd"] ]]; then
    info "Stopping and removing systemd service..."

    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        asroot systemctl stop "$SERVICE_NAME"
        removed "service stopped"
    fi

    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        asroot systemctl disable "$SERVICE_NAME"
        removed "service disabled"
    fi

    SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
    if [ -f "$SERVICE_FILE" ]; then
        asroot rm -f "$SERVICE_FILE"
        asroot systemctl daemon-reload
        asroot systemctl reset-failed 2>/dev/null || true
        removed "$SERVICE_FILE"
    fi
else
    skip "systemd service (not installed)"
fi

# =============================================================================
# 2 — Stop and remove Docker containers + volumes + networks
# =============================================================================
if [[ -v ITEMS["docker_containers"] ]]; then
    info "Removing Docker containers, volumes and networks..."

    # docker compose down removes containers + networks
    # -v also removes named volumes (all database data)
    if with_docker docker compose down -v --remove-orphans 2>/dev/null; then
        removed "docker compose stack (containers + volumes + networks)"
    else
        # Fallback: remove individually if compose file is missing
        warn "docker compose down failed — attempting direct container/volume removal."

        for c in dkastle-db dkastle-redis; do
            if with_docker docker ps -a --format '{{.Names}}' | grep -q "^${c}$"; then
                with_docker docker rm -f "$c" && removed "container $c"
            fi
        done

        for v in dkastle-pgdata dkastle-redisdata; do
            if with_docker docker volume ls --format '{{.Name}}' | grep -q "^${v}$"; then
                with_docker docker volume rm "$v" && removed "volume $v"
            fi
        done

        # Remove dangling networks
        with_docker docker network prune -f 2>/dev/null || true
        removed "dangling networks"
    fi
else
    skip "Docker (not installed or not accessible)"
fi

# =============================================================================
# 3 — Project files
# =============================================================================
info "Removing generated files..."

if [[ -v ITEMS["env"] ]]; then
    rm -f "$PROJECT_DIR/.env"
    removed ".env"
fi

if [[ -v ITEMS["webpush"] ]]; then
    rm -f "$PROJECT_DIR/webpush_subscriptions.json"
    removed "webpush_subscriptions.json"
fi

if [[ -v ITEMS["logs"] ]]; then
    rm -f "$PROJECT_DIR"/discoverykastle.log*
    removed "discoverykastle.log*"
fi

if [[ -v ITEMS["ilog"] ]]; then
    rm -f "$PROJECT_DIR/install.log"
    removed "install.log"
fi

if [[ -v ITEMS["certs"] ]]; then
    find "$PROJECT_DIR" -maxdepth 1 \( -name "*.pem" -o -name "*.crt" -o -name "*.key" \) -delete
    removed "TLS certificate files"
fi

# =============================================================================
# 4 — Python virtualenv
# =============================================================================
if [[ -v ITEMS["venv"] ]]; then
    info "Removing Python virtualenv..."
    rm -rf "$PROJECT_DIR/.venv"
    removed ".venv/"
else
    skip ".venv (not present)"
fi

# =============================================================================
# 5 — Python bytecode caches
# =============================================================================
if [[ -v ITEMS["pycache"] ]]; then
    info "Removing Python bytecode caches..."
    find "$PROJECT_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find "$PROJECT_DIR" -name "*.pyc" -delete 2>/dev/null || true
    removed "__pycache__/ + *.pyc"
else
    skip "__pycache__ (none found)"
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║          Cleanup complete — environment is clean     ║${RESET}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${BOLD}To start fresh:${RESET}"
echo -e "  ${CYAN}./install.sh${RESET}"
echo ""
echo -e "  ${BOLD}Kept:${RESET}"
echo -e "  ✓  Docker Engine + Compose plugin"
echo -e "  ✓  Python 3.12"
echo -e "  ✓  Project source code + git history"
echo -e "  ✓  .env.example"
echo ""
