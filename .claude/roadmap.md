# Discoverykastle — Roadmap

Last updated: 2026-04-05

## Currently open PR
- None

## Recently merged
- PR #1: initial project documentation, server foundation, agent collectors, Puppet/Ansible integration,
  IP guard, DNS enrichment, WebPush notifications, AI enrichment, setup wizard, structured logging,
  Docker Compose, install scripts — merged 2026-03-21

## Currently open PR
- Branch `feat/agent-registration-ca-auth` pushed — PR to be created at:
  https://github.com/tunisiano187/Discoverykastle/pull/new/feat/agent-registration-ca-auth
  - Status: waiting for merge
  - Implements: agent registration, embedded CA, JWT operator auth, native OS agent,
    auto-update (server version endpoint + agent self-update on heartbeat)

## Todo (prioritized — pick from the top)

1. [CRITICAL] Full data ingestion API — agents push host/service/vuln/interface/scan data
   - `POST /api/v1/data/hosts`, `/services`, `/packages`, `/vulnerabilities`
   - `POST /api/v1/data/interfaces`, `/scan-results`, `/device-configs`, `/topology-edges`
   - Currently only `/api/v1/data/puppet` exists
   - Reason: agents can now enroll (PR in review) but can't submit discovery data

2. [CRITICAL] Full data ingestion API — needed for agents to push host/service/vuln/interface/scan data
   - `POST /api/v1/data/hosts`, `/services`, `/packages`, `/vulnerabilities`
   - `POST /api/v1/data/interfaces`, `/scan-results`, `/device-configs`, `/topology-edges`
   - Currently only `/api/v1/data/puppet` exists

3. [HIGH] WebSocket task dispatch — server→agent task delivery
   - `WS /api/v1/ws/agent/{id}` — persistent agent connection for task receipt
   - `WS /api/v1/ws/dashboard` — real-time dashboard updates
   - Task state machine (queued → dispatched → running → completed/failed)

4. [HIGH] Task engine — orchestrate what agents scan and when
   - Task creation, queuing, retry with backoff, timeout handling
   - Authorization enforcement before dispatching sensitive tasks
   - Redis Streams integration for task queue

5. [MEDIUM] React frontend (SPA dashboard)
   - Currently no frontend exists (only static sw.js and webpush.js)
   - Topology view (Cytoscape.js), host inventory, vuln dashboard, agent dashboard
   - Auth login page

6. [MEDIUM] Vulnerability API
   - `GET /api/v1/vulns`, `/api/v1/vulns/{cve_id}`, `/api/v1/vulns/summary`
   - Severity filtering, affected-hosts-per-CVE view

7. [MEDIUM] Documentation builder
   - Background service that generates Markdown docs from collected data
   - Network segments, individual hosts, network devices, executive summary
   - `GET /api/v1/docs/generate`, `/network/{id}`, `/device/{id}`, `/export`

8. [LOW] Credential vault API
   - Encrypted AES-256-GCM storage for device credentials
   - Ephemeral task-scoped credential delivery over WebSocket
   - `GET|POST|DELETE /api/v1/vault/credentials`

9. [LOW] Alembic migrations
   - Replace `Base.metadata.create_all` with proper Alembic migrations
   - Enables safe schema evolution in production

## Done
- Agent registration API (`POST /api/v1/agents/register`, heartbeat, list, delete, task queue) — PR in review
- Embedded CA (ECDSA P-256, 90-day agent certs, persistent root CA) — PR in review
- Operator JWT auth (`POST /api/v1/auth/login`, `/refresh`, `GET /auth/me`) — PR in review
- Auto-update: server version endpoint (`GET /api/v1/version`), agent self-update on heartbeat signal — PR in review
- Native OS agent (Ubuntu/Debian systemd + Windows Service, enrollment, heartbeat, puppet collector) — PR in review
- Server foundation (FastAPI, SQLAlchemy/asyncpg, Redis, structured logging)
- Database models: Host, Service, Package, Vulnerability, Network, NetworkInterface,
  TopologyEdge, ScanResult, NetworkDevice, Agent, AuditLog, AuthorizationRequest, Alert
- Inventory API (`/api/v1/inventory/*`) — hosts, networks, devices, auth-requests, stats
- Alerts API (`/api/v1/alerts/*`)
- Topology API (`/api/v1/topology/*`) with Cytoscape.js-format export
- Data ingestion: Puppet collector endpoint (`/api/v1/data/puppet`)
- Module system (registry, base class, loader, builtin modules: puppet, topology, ansible, dns, netbox, ai, alerts, inventory)
- First-run setup wizard (generates .env, auto-generates secret/vault keys)
- SetupGuard middleware (blocks all routes until configured)
- WebPush browser notifications (VAPID)
- AI enrichment (Ollama + Anthropic backends)
- DNS enrichment (PTR/A lookups, AD domain detection)
- IP public/private classification guard
- Docker Compose + install.sh + cleanup.sh
- Native OS agent (Ubuntu/Debian/Windows systemd/Windows Service)
  - enrollment flow, heartbeat loop, Puppet collector scheduler
  - install scripts (install.sh, uninstall.sh, install.ps1, uninstall.ps1)
