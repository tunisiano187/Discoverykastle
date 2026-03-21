#!/usr/bin/env bash
# =============================================================================
# Discoverykastle — Installation script
# Ubuntu 22.04 LTS / 24.04 LTS
#
# Run as a REGULAR USER with sudo privileges (not as root).
# Privilege escalation is used only for system-level operations.
#
# Usage:
#   chmod +x install.sh
#   ./install.sh
# =============================================================================
set -euo pipefail
IFS=$'\n\t'

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m';  GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m';  BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}${BOLD}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}${BOLD}[ OK ]${RESET}  $*"; }
warn()    { echo -e "${YELLOW}${BOLD}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}${BOLD}[ERR ]${RESET}  $*" >&2; }
step()    { echo -e "\n${BLUE}${BOLD}━━━  $*  ━━━${RESET}"; }
die()     { error "$*"; exit 1; }

# ── Constants ─────────────────────────────────────────────────────────────────
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="discoverykastle"
SERVICE_USER="$USER"
PYTHON_MIN="3.12"
SERVER_PORT="8443"
LOG_FILE="$PROJECT_DIR/install.log"

# ── Logging ───────────────────────────────────────────────────────────────────
exec > >(tee -a "$LOG_FILE") 2>&1
info "Install log: $LOG_FILE"

# ── Privilege helper ──────────────────────────────────────────────────────────
# Use sudo only when not already root.
# All privileged calls go through: asroot <command>
asroot() {
    if [ "$EUID" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

# Check sudo is available and working
check_sudo() {
    if [ "$EUID" -ne 0 ]; then
        if ! command -v sudo &>/dev/null; then
            die "sudo is not installed. Install it or run as root."
        fi
        info "Checking sudo access (you may be prompted for your password once)..."
        if ! sudo -v; then
            die "Cannot obtain sudo privileges. Add your user to the sudoers file."
        fi
        # Keep sudo alive throughout the script
        ( while true; do sudo -v; sleep 50; done ) &
        SUDO_KEEPALIVE_PID=$!
        trap 'kill $SUDO_KEEPALIVE_PID 2>/dev/null || true' EXIT
    fi
}

# ── Docker group helper ───────────────────────────────────────────────────────
# Run a command with docker group membership, even in the current session.
with_docker() {
    if id -nG "$USER" | grep -qw docker; then
        "$@"
    else
        sg docker -c "$*"
    fi
}

# ── Wait for a service to respond ────────────────────────────────────────────
wait_for() {
    local desc="$1"; local cmd="${*:2}"; local retries=30; local delay=2
    info "Waiting for $desc..."
    for i in $(seq 1 $retries); do
        if eval "$cmd" &>/dev/null; then
            success "$desc is ready."
            return 0
        fi
        printf "  attempt %d/%d — retrying in %ds...\r" "$i" "$retries" "$delay"
        sleep "$delay"
    done
    die "Timed out waiting for $desc."
}

# =============================================================================
# STEP 0 — Pre-flight checks
# =============================================================================
step "Pre-flight checks"

# Must NOT run as root (service will run as current user)
if [ "$EUID" -eq 0 ]; then
    die "Do not run this script as root. Run as a regular user with sudo privileges."
fi

# Ubuntu check
if ! grep -qi ubuntu /etc/os-release 2>/dev/null; then
    warn "This script is designed for Ubuntu. Proceeding anyway — some steps may fail."
fi

UBUNTU_VER=$(. /etc/os-release && echo "$VERSION_ID")
info "Detected OS: Ubuntu $UBUNTU_VER"
info "Install directory: $PROJECT_DIR"
info "Service user: $SERVICE_USER"
info "Server port: $SERVER_PORT"

check_sudo

# Verify project structure
[ -f "$PROJECT_DIR/pyproject.toml" ] || \
    die "pyproject.toml not found. Run this script from the Discoverykastle project root."

success "Pre-flight OK"

# =============================================================================
# STEP 1 — System packages
# =============================================================================
step "System packages"

info "Updating package lists..."
asroot apt-get update -qq

PACKAGES=(
    curl wget gnupg ca-certificates lsb-release
    git build-essential
    openssl
    python3-pip python3-venv
    # Needed by cryptography wheel builds
    libffi-dev libssl-dev
)

info "Installing base packages..."
asroot apt-get install -y -qq "${PACKAGES[@]}"
success "Base packages installed."

# =============================================================================
# STEP 2 — Python 3.12
# =============================================================================
step "Python $PYTHON_MIN"

install_python312() {
    info "Adding deadsnakes PPA for Python 3.12..."
    asroot add-apt-repository -y ppa:deadsnakes/ppa
    asroot apt-get update -qq
    asroot apt-get install -y -qq python3.12 python3.12-venv python3.12-dev
}

if python3.12 --version &>/dev/null; then
    PY_VER=$(python3.12 --version)
    success "Python already available: $PY_VER"
else
    case "$UBUNTU_VER" in
        24.*) asroot apt-get install -y -qq python3.12 python3.12-venv python3.12-dev ;;
        22.*) install_python312 ;;
        *)    install_python312 ;;
    esac
    python3.12 --version || die "Python 3.12 installation failed."
    success "Python 3.12 installed."
fi

PYTHON="python3.12"

# =============================================================================
# STEP 3 — Docker Engine + Compose plugin
# =============================================================================
step "Docker Engine"

install_docker() {
    info "Installing Docker Engine..."

    # Remove conflicting old packages silently
    for pkg in docker docker-engine docker.io containerd runc; do
        asroot apt-get remove -y -qq "$pkg" 2>/dev/null || true
    done

    # Add Docker GPG key
    asroot install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | asroot gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    asroot chmod a+r /etc/apt/keyrings/docker.gpg

    # Add Docker repository
    echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/ubuntu \
        $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
        | asroot tee /etc/apt/sources.list.d/docker.list > /dev/null

    asroot apt-get update -qq
    asroot apt-get install -y -qq \
        docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin

    asroot systemctl enable docker
    asroot systemctl start docker
    success "Docker installed."
}

if docker version &>/dev/null 2>&1 || sudo docker version &>/dev/null 2>&1; then
    DOCKER_VER=$(docker version --format '{{.Server.Version}}' 2>/dev/null \
                 || sudo docker version --format '{{.Server.Version}}')
    success "Docker already installed: v$DOCKER_VER"
else
    install_docker
fi

# Verify Compose plugin
docker compose version &>/dev/null 2>&1 \
    || sudo docker compose version &>/dev/null 2>&1 \
    || die "docker compose plugin not found after installation."

# Add user to docker group (requires re-login normally — sg handles it)
if ! id -nG "$USER" | grep -qw docker; then
    info "Adding $USER to the docker group..."
    asroot usermod -aG docker "$USER"
    success "User added to docker group."
    info "Using 'sg docker' to activate group in this session (no logout required)."
else
    success "User already in docker group."
fi

# =============================================================================
# STEP 4 — Python virtual environment
# =============================================================================
step "Python virtual environment"

VENV_DIR="$PROJECT_DIR/.venv"

if [ -d "$VENV_DIR" ] && [ -f "$VENV_DIR/bin/activate" ]; then
    success "Virtualenv already exists at $VENV_DIR"
else
    info "Creating virtualenv with Python 3.12..."
    $PYTHON -m venv "$VENV_DIR"
    success "Virtualenv created."
fi

# Activate
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

info "Upgrading pip..."
pip install --quiet --upgrade pip

info "Installing Discoverykastle and all dependencies..."
pip install --quiet -e "$PROJECT_DIR[graylog,webpush,ai]" \
    || pip install --quiet -e "$PROJECT_DIR[graylog,webpush]" \
    || pip install --quiet -e "$PROJECT_DIR"

success "Python dependencies installed."

# =============================================================================
# STEP 5 — Generate .env
# =============================================================================
step ".env configuration"

ENV_FILE="$PROJECT_DIR/.env"

if [ -f "$ENV_FILE" ]; then
    warn ".env already exists — skipping generation."
    warn "Delete $ENV_FILE and re-run to regenerate."
else
    info "Generating secure .env..."

    # Generate cryptographic values
    SECRET_KEY=$(openssl rand -hex 32)
    VAULT_KEY=$(openssl rand -base64 32 | tr -d '\n')
    PG_PASSWORD=$(openssl rand -hex 16)
    ADMIN_PASSWORD=$(openssl rand -base64 12 | tr -d '/+=' | head -c 16)

    # Detect local IP and CIDR for first scan authorisation
    LOCAL_IP=$(hostname -I | awk '{print $1}')
    LOCAL_CIDR=$(ip route | grep -E "^[0-9]" | grep "$LOCAL_IP" | awk '{print $1}' | head -1)
    LOCAL_CIDR=${LOCAL_CIDR:-"${LOCAL_IP%.*}.0/24"}

    cat > "$ENV_FILE" << EOF
# ============================================================
# Discoverykastle — Auto-generated by install.sh
# $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# NEVER commit this file to version control.
# ============================================================

# ---- Admin -------------------------------------------------
DKASTLE_ADMIN_USERNAME=admin
DKASTLE_ADMIN_PASSWORD=${ADMIN_PASSWORD}

# ---- Security ----------------------------------------------
DKASTLE_SECRET_KEY=${SECRET_KEY}
DKASTLE_VAULT_KEY=${VAULT_KEY}

# ---- Scan authorisation ------------------------------------
# Add your networks here (comma-separated CIDRs)
DKASTLE_AUTHORIZED_CIDRS=${LOCAL_CIDR}

# ---- Server ------------------------------------------------
DKASTLE_HOST=0.0.0.0
DKASTLE_PORT=${SERVER_PORT}
DKASTLE_LOG_LEVEL=INFO
DKASTLE_LOG_FILE=${PROJECT_DIR}/discoverykastle.log

# ---- Database (via Docker on localhost) --------------------
POSTGRES_DB=discoverykastle
POSTGRES_USER=dkastle
POSTGRES_PASSWORD=${PG_PASSWORD}
POSTGRES_HOST=127.0.0.1
POSTGRES_PORT=5432
DKASTLE_DATABASE_URL=postgresql+asyncpg://dkastle:${PG_PASSWORD}@127.0.0.1:5432/discoverykastle

# ---- Redis (via Docker on localhost) -----------------------
REDIS_URL=redis://127.0.0.1:6379/0
DKASTLE_REDIS_URL=redis://127.0.0.1:6379/0

# ---- TLS (leave empty to use auto-generated self-signed) ---
DKASTLE_TLS_CERT=
DKASTLE_TLS_KEY=

# ---- Notifications -----------------------------------------
DKASTLE_WEBPUSH_ENABLED=false
DKASTLE_VAPID_EMAIL=admin@example.com
DKASTLE_VAPID_PUBLIC_KEY=
DKASTLE_VAPID_PRIVATE_KEY=
DKASTLE_WEBPUSH_MIN_SEVERITY=high

# ---- AI enrichment (disabled by default) -------------------
DKASTLE_AI_ENABLED=false
DKASTLE_AI_BACKEND=auto
DKASTLE_OLLAMA_URL=http://localhost:11434
DKASTLE_OLLAMA_MODEL=llama3.2
DKASTLE_ANTHROPIC_API_KEY=
EOF

    chmod 600 "$ENV_FILE"
    success ".env generated with secure random keys."
    echo ""
    echo -e "  ${BOLD}Admin credentials:${RESET}"
    echo -e "  Username : ${GREEN}admin${RESET}"
    echo -e "  Password : ${GREEN}${ADMIN_PASSWORD}${RESET}"
    echo -e "  ${YELLOW}Save these now — they won't be shown again.${RESET}"
    echo ""
fi

# Load env for the rest of the script
set -a
# shellcheck disable=SC1091
source "$ENV_FILE"
set +a

# =============================================================================
# STEP 6 — Start Docker infrastructure (PostgreSQL + Redis)
# =============================================================================
step "Docker infrastructure (PostgreSQL + Redis)"

cd "$PROJECT_DIR"

# Use sg docker to ensure group membership is active in this session
info "Starting PostgreSQL and Redis containers..."
sg docker -c "docker compose up -d"

wait_for "PostgreSQL" \
    "sg docker -c 'docker compose exec -T db pg_isready -U ${POSTGRES_USER:-dkastle}'"

wait_for "Redis" \
    "sg docker -c 'docker compose exec -T redis redis-cli ping'"

success "Docker containers are healthy."

# =============================================================================
# STEP 7 — Initialise the database
# =============================================================================
step "Database initialisation"

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

info "Creating database tables..."
"$VENV_DIR/bin/python" - << 'PYEOF'
import asyncio, sys, os
sys.path.insert(0, os.environ.get("PROJECT_DIR", "."))
from server.database import init_db

async def main():
    await init_db()
    print("  Tables created.")

asyncio.run(main())
PYEOF

success "Database initialised."

# =============================================================================
# STEP 8 — systemd service
# =============================================================================
step "systemd service"

SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

if [ -f "$SERVICE_FILE" ]; then
    warn "Service file already exists — updating it."
fi

info "Writing systemd service as root..."
asroot tee "$SERVICE_FILE" > /dev/null << EOF
[Unit]
Description=Discoverykastle Network Discovery Server
Documentation=https://github.com/tunisiano187/Discoverykastle
After=network.target docker.service
Wants=docker.service

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${PROJECT_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${VENV_DIR}/bin/python -m uvicorn server.main:app \\
    --host 0.0.0.0 \\
    --port ${SERVER_PORT} \\
    --log-level warning
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=discoverykastle

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=${PROJECT_DIR}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

asroot systemctl daemon-reload
asroot systemctl enable "$SERVICE_NAME"
asroot systemctl restart "$SERVICE_NAME"

success "systemd service enabled and started."

# =============================================================================
# STEP 9 — Wait for server to be ready
# =============================================================================
step "Server health check"

wait_for "Discoverykastle server" \
    "curl -sk https://127.0.0.1:${SERVER_PORT}/health | grep -q ok"

success "Server is up."

# =============================================================================
# STEP 10 — First-agent registration hint
# =============================================================================
step "First agent"

LOCAL_IP=$(hostname -I | awk '{print $1}')

info "This machine is the first monitored node."
info "Network DKASTLE_AUTHORIZED_CIDRS is set to: ${DKASTLE_AUTHORIZED_CIDRS:-not set}"
info ""
info "To register this host as an agent, run the agent enrollment once agent"
info "packages are available:"
info "  curl -sk https://127.0.0.1:${SERVER_PORT}/api/v1/agents/enroll \\"
info "    -H 'Content-Type: application/json' \\"
info "    -d '{\"hostname\": \"$(hostname)\", \"ip_address\": \"${LOCAL_IP}\"}'"

# =============================================================================
# STEP 11 — Summary
# =============================================================================
step "Installation complete"

ADMIN_PASS=$(grep "DKASTLE_ADMIN_PASSWORD" "$ENV_FILE" | cut -d= -f2)

echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║       Discoverykastle installed successfully         ║${RESET}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${BOLD}Web interface${RESET}"
echo -e "  URL      : ${CYAN}https://${LOCAL_IP}:${SERVER_PORT}/setup${RESET}  (setup wizard)"
echo -e "  URL      : ${CYAN}https://${LOCAL_IP}:${SERVER_PORT}/${RESET}        (after setup)"
echo ""
echo -e "  ${BOLD}Admin credentials${RESET}"
echo -e "  Username : ${GREEN}admin${RESET}"
echo -e "  Password : ${GREEN}${ADMIN_PASS}${RESET}"
echo ""
echo -e "  ${BOLD}Service management${RESET}"
echo -e "  Status   : ${CYAN}systemctl status ${SERVICE_NAME}${RESET}"
echo -e "  Logs     : ${CYAN}journalctl -u ${SERVICE_NAME} -f${RESET}"
echo -e "  Restart  : ${CYAN}systemctl restart ${SERVICE_NAME}${RESET}"
echo ""
echo -e "  ${BOLD}Infrastructure${RESET}"
echo -e "  DB+Redis : ${CYAN}docker compose ps${RESET}  (in $PROJECT_DIR)"
echo ""
echo -e "  ${BOLD}Configuration${RESET}"
echo -e "  .env     : ${CYAN}${ENV_FILE}${RESET}"
echo -e "  Logs     : ${CYAN}${PROJECT_DIR}/discoverykastle.log${RESET}"
echo ""
echo -e "  ${YELLOW}Note: the TLS certificate is self-signed.${RESET}"
echo -e "  ${YELLOW}Your browser will warn — click 'Advanced' and proceed.${RESET}"
echo -e "  ${YELLOW}Replace with a real cert by setting DKASTLE_TLS_CERT/KEY in .env.${RESET}"
echo ""
