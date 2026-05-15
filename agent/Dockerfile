# Discoverykastle Agent — Docker image
#
# Multi-stage build: keeps the final image small by separating build-time
# tools from runtime.
#
# Build:
#   docker build -f agent/Dockerfile -t discoverykastle-agent:latest .
#
# Run:
#   docker run -d \
#     --name dkastle-agent \
#     --cap-add NET_ADMIN \
#     --cap-add NET_RAW \
#     -e DKASTLE_SERVER_URL=https://dk.example.com \
#     -e DKASTLE_ENROLL_TOKEN=<token> \
#     --restart unless-stopped \
#     discoverykastle-agent:latest

# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build tools needed for any C-extension deps (httpx → h2 → hpack, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY agent/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM python:3.12-slim

LABEL org.opencontainers.image.title="Discoverykastle Agent"
LABEL org.opencontainers.image.description="Autonomous network discovery and security assessment agent"
LABEL org.opencontainers.image.source="https://github.com/tunisiano187/Discoverykastle"
LABEL org.opencontainers.image.licenses="MIT"

# nmap is optional (only needed when NMAP_ENABLED=true)
# Install it unconditionally so the image is ready to use without a rebuild.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        ca-certificates \
        libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder stage
COPY --from=builder /install /usr/local

# Copy agent source code
WORKDIR /app
COPY agent/ ./agent/

# Non-root user for least-privilege (nmap SYN scan still needs NET_RAW cap
# which is granted at container-run time, not at image-build time).
RUN groupadd -r dkagent && useradd -r -g dkagent -d /app dkagent \
    && mkdir -p /etc/discoverykastle /var/log/discoverykastle \
    && chown dkagent:dkagent /etc/discoverykastle /var/log/discoverykastle

USER dkagent

# Config and log directories as volumes so they persist across container restarts
VOLUME ["/etc/discoverykastle", "/var/log/discoverykastle"]

# Environment defaults (all overridable at runtime)
ENV DKASTLE_SERVER_URL="" \
    DKASTLE_ENROLL_TOKEN="" \
    DKASTLE_AGENT_ID="" \
    DKASTLE_AGENT_CERT="" \
    DKASTLE_AGENT_KEY="" \
    DKASTLE_AGENT_CA="" \
    DKASTLE_LOG_LEVEL="INFO" \
    NMAP_ENABLED="false" \
    CVE_SCAN_ENABLED="false" \
    ANSIBLE_ENABLED="false" \
    NETMIKO_ENABLED="false"

ENTRYPOINT ["python", "-m", "agent"]
CMD []
