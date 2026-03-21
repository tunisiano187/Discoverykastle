# Deployment Guide

## Prerequisites

| Requirement | Minimum Version | Notes |
|-------------|----------------|-------|
| Docker | 24.x | Required on server and agent hosts |
| Docker Compose | 2.20.x | Required on server host |
| RAM (server) | 2 GB | 4 GB recommended for large networks |
| RAM (agent) | 512 MB | 1 GB recommended |
| Disk (server) | 10 GB | For database and documentation |
| OS | Linux (amd64 or arm64) | Ubuntu 22.04 LTS recommended |

Network requirements:
- Server must be reachable by agents over HTTPS (port 443, or custom port)
- Agents need network access to targets within authorized CIDRs
- Outbound internet access needed on server for CVE database updates (optional, can be airgapped)

---

## Quick Start (Development)

> **This setup is for development only. Do not expose it to the internet.**

```bash
# 1. Clone the repository
git clone https://github.com/tunisiano187/Discoverykastle.git
cd Discoverykastle

# 2. Copy the environment template
cp .env.example .env

# 3. Edit minimum required settings
nano .env
# Set at minimum:
#   DKASTLE_ADMIN_PASSWORD=<strong-password>
#   DKASTLE_VAULT_KEY=<32-char-random-key>
#   DKASTLE_AUTHORIZED_CIDRS=10.0.0.0/8,192.168.0.0/16

# 4. Start the server stack
docker compose up -d

# 5. Access the dashboard
open https://localhost:8443
# Accept the self-signed certificate warning in dev mode
```

The first startup will:
1. Initialize the PostgreSQL database
2. Generate the CA certificate
3. Create the admin user account

---

## Environment Variables

### Required

| Variable | Description | Example |
|----------|-------------|---------|
| `DKASTLE_ADMIN_USERNAME` | Initial admin username | `admin` |
| `DKASTLE_ADMIN_PASSWORD` | Initial admin password (change immediately) | `ChangeMe!2024` |
| `DKASTLE_VAULT_KEY` | 32-byte base64 key for credential vault encryption | `$(openssl rand -base64 32)` |
| `DKASTLE_AUTHORIZED_CIDRS` | Comma-separated list of authorized scan CIDRs | `192.168.1.0/24,10.0.0.0/8` |
| `DKASTLE_SECRET_KEY` | Secret key for JWT signing | `$(openssl rand -hex 32)` |

### Database

| Variable | Description | Default |
|----------|-------------|---------|
| `POSTGRES_DB` | Database name | `discoverykastle` |
| `POSTGRES_USER` | Database user | `dkastle` |
| `POSTGRES_PASSWORD` | Database password | **required** |
| `DATABASE_URL` | Override full DSN | auto-generated |

### Server

| Variable | Description | Default |
|----------|-------------|---------|
| `DKASTLE_HOST` | Server bind address | `0.0.0.0` |
| `DKASTLE_PORT` | Server port | `8443` |
| `DKASTLE_TLS_CERT` | Path to TLS certificate | (self-signed if not set) |
| `DKASTLE_TLS_KEY` | Path to TLS private key | (self-signed if not set) |
| `DKASTLE_LOG_LEVEL` | Log level | `INFO` |
| `DKASTLE_MAX_SCAN_DEPTH` | Maximum recursive scan depth | `2` |
| `DKASTLE_TASK_TIMEOUT` | Default task timeout (seconds) | `3600` |

### Agent (set on agent containers)

| Variable | Description | Required |
|----------|-------------|---------|
| `DKASTLE_SERVER_URL` | WebSocket URL of the server | Yes |
| `DKASTLE_ENROLL_TOKEN` | One-time enrollment token | Yes |
| `DKASTLE_LOG_LEVEL` | Agent log level | No |

### Notifications (optional)

| Variable | Description |
|----------|-------------|
| `DKASTLE_SMTP_HOST` | SMTP server hostname |
| `DKASTLE_SMTP_PORT` | SMTP port (default: 587) |
| `DKASTLE_SMTP_USER` | SMTP username |
| `DKASTLE_SMTP_PASSWORD` | SMTP password |
| `DKASTLE_ALERT_EMAIL` | Email address for alerts |
| `DKASTLE_SLACK_WEBHOOK` | Slack incoming webhook URL |

---

## Docker Compose Architecture

```yaml
# docker-compose.yml (reference — not yet implemented)
services:
  server:
    build: ./server
    ports:
      - "8443:8443"
    volumes:
      - db-data:/var/lib/postgresql
      - ./certs:/certs:ro          # External TLS certs (optional)
    environment:
      - POSTGRES_HOST=db
      - REDIS_URL=redis://redis:6379
    depends_on:
      - db
      - redis

  db:
    image: postgres:16-alpine
    volumes:
      - db-data:/var/lib/postgresql/data
    environment:
      - POSTGRES_DB=${POSTGRES_DB}
      - POSTGRES_USER=${POSTGRES_USER}
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}

  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis-data:/data

  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/certs:ro
    depends_on:
      - server

volumes:
  db-data:
  redis-data:
```

---

## Deploying an Agent

### Method 1: Manual Docker Run (Recommended for First Deployment)

1. Generate an enrollment token in the dashboard: **Settings → Agents → New Enrollment Token**

2. On the target host, run:

```bash
docker run -d \
  --name dkastle-agent \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --security-opt seccomp=/path/to/agent-seccomp.json \
  --read-only \
  --tmpfs /tmp:size=64m,noexec,nosuid \
  --tmpfs /var/tmp:size=32m,noexec,nosuid \
  -e DKASTLE_SERVER_URL=wss://your-server:8443 \
  -e DKASTLE_ENROLL_TOKEN=<token-from-dashboard> \
  --restart unless-stopped \
  ghcr.io/tunisiano187/discoverykastle-agent:latest
```

3. The agent will appear in the dashboard within 30 seconds.

### Method 2: Automated Deployment (via Existing Agent)

When a scan discovers a new host with SSH access:
1. An authorization request appears in the dashboard
2. Operator reviews and approves
3. The approving agent SSHes to the target, installs Docker (if needed), and starts the agent container
4. The new agent registers automatically

### Method 3: Ansible / Configuration Management

An Ansible role for agent deployment will be provided in `deploy/ansible/`. This is the recommended method for deploying agents at scale.

---

## TLS Certificate Setup

### Development (Self-Signed)

The server generates a self-signed certificate automatically on first startup if no external certificate is provided. This is fine for development but browsers will show a security warning.

### Production: Let's Encrypt (Certbot)

```bash
# On the server host
certbot certonly --standalone -d your-server.example.com

# Add to .env
DKASTLE_TLS_CERT=/etc/letsencrypt/live/your-server.example.com/fullchain.pem
DKASTLE_TLS_KEY=/etc/letsencrypt/live/your-server.example.com/privkey.pem
```

Mount the certificates into the Nginx container and configure auto-renewal.

### Production: Corporate CA

Place the signed certificate and key in `./certs/`:
```
certs/
  server.crt    # Full chain (leaf + intermediate)
  server.key    # Private key
```

Set in `.env`:
```
DKASTLE_TLS_CERT=/certs/server.crt
DKASTLE_TLS_KEY=/certs/server.key
```

---

## Upgrading

```bash
# Pull latest images
docker compose pull

# Apply database migrations
docker compose run --rm server alembic upgrade head

# Restart services
docker compose up -d
```

Agent containers on remote hosts can be updated by:
- Pulling the new image manually: `docker pull && docker restart`
- Using the automated upgrade task dispatched from the dashboard (future feature)

---

## Backup and Recovery

### Database Backup

```bash
# Create a backup
docker compose exec db pg_dump -U ${POSTGRES_USER} ${POSTGRES_DB} \
  | gzip > backup-$(date +%Y%m%d-%H%M%S).sql.gz

# Restore from backup
gunzip < backup-20240101-120000.sql.gz \
  | docker compose exec -T db psql -U ${POSTGRES_USER} ${POSTGRES_DB}
```

Automate with a cron job. Store backups off-server (S3, NFS, etc.).

### What to Back Up

| Item | Location | Frequency |
|------|----------|-----------|
| PostgreSQL data | `db-data` Docker volume | Daily |
| Redis data | `redis-data` Docker volume | Optional (task queue only) |
| `.env` file | Server host | On change |
| TLS certificates | `./certs/` | On renewal |

The CA private key and credential vault key are stored in the database encrypted, so the database backup covers them. However, the `DKASTLE_VAULT_KEY` must be stored separately (it decrypts the vault).

---

## Production Hardening Checklist

- [ ] **TLS**: Use a valid certificate (not self-signed) for the server
- [ ] **Firewall**: Expose only port 443 externally; block direct access to PostgreSQL (5432) and Redis (6379) ports
- [ ] **Secrets**: Store `DKASTLE_VAULT_KEY` and `DKASTLE_SECRET_KEY` in a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.)
- [ ] **Admin password**: Change the default admin password immediately after first login
- [ ] **Database**: Enable PostgreSQL SSL, use a strong password
- [ ] **Disk encryption**: Enable full-disk encryption on the server host
- [ ] **Logging**: Configure centralized log aggregation (ELK, Loki, etc.)
- [ ] **Monitoring**: Set up uptime monitoring for the server health endpoint (`GET /api/v1/health`)
- [ ] **Backups**: Automate daily database backups to off-site storage
- [ ] **Updates**: Subscribe to security advisories for all dependencies
- [ ] **Agent scope**: Define the smallest possible authorized CIDR list

---

## Airgapped Deployment

For networks with no internet access:

1. Pre-download the Grype CVE database and mount it into the agent container
2. Pre-pull all Docker images and push them to an internal registry
3. Configure `DKASTLE_NVD_API_ENABLED=false` to disable online CVE lookups
4. Manually update the CVE database on a regular schedule by importing the offline Grype DB

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| Agent not appearing in dashboard | Enrollment token expired or wrong server URL | Generate a new token; verify `DKASTLE_SERVER_URL` |
| Agent appears offline | Network connectivity or firewall blocking port 443 | Check agent logs: `docker logs dkastle-agent` |
| nmap tasks failing | Missing `NET_ADMIN`/`NET_RAW` capabilities | Verify agent container capabilities |
| CVE scan returning no results | Grype DB not downloaded | Check agent logs for Grype initialization |
| Dashboard not loading | Nginx or server not running | `docker compose ps` and `docker compose logs server` |
| Authentication errors (mTLS) | CA certificate mismatch | Re-enroll the agent with a new enrollment token |
