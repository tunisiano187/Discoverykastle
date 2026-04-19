# Discoverykastle — Roadmap

Last updated: 2026-04-11

## Currently open PR
- PR #6: feat(server): WebSocket task dispatch and dashboard real-time events — waiting for review
  - Implements `WS /api/v1/ws/agent/{id}` (persistent agent connection, Redis Stream consumer,
    task delivery, heartbeat/task-result handling) and `WS /api/v1/ws/dashboard` (JWT-auth,
    real-time broadcast of agent connect/disconnect, task dispatch, task update events).
  - 17 new tests, all 62 tests pass.

## Recently merged
- PR #5: feat(server): full data ingestion API — merged 2026-04-05
  - 8 POST endpoints under `/api/v1/data/` (hosts, services, packages, vulnerabilities,
    interfaces, scan-results, device-configs, topology-edges)
- PR #4: feat/agent-registration-ca-auth — merged 2026-04-05
  - Agent registration, embedded CA, JWT operator auth, native OS agent, auto-update
- PR #3: docs/initial — merged 2026-03-21
- PR #2 / #1: initial project documentation, server foundation — merged 2026-03-21

## Todo (prioritized — pick from the top)

1. [HIGH] Task engine — orchestrate what agents scan and when
   - Task creation, scheduling, retry with backoff (1 min, 5 min, 15 min), timeout handling
   - Authorization enforcement before dispatching sensitive tasks
   - Task state machine: Created → Queued → Dispatched → Running → Completed/Failed/TimedOut
   - A dedicated AgentTask DB model to persist task state across restarts
   - Background worker that reads from Redis Streams and forwards via WS

2. [HIGH] Vulnerability API
   - GET /api/v1/vulns — all vulns, filterable by severity/host
   - GET /api/v1/vulns/{cve_id} — CVE details + all affected hosts
   - GET /api/v1/vulns/summary — severity distribution, top CVEs
   - Data model and ingestion exist but no read endpoints yet

3. [MEDIUM] React frontend (SPA dashboard)
   - No frontend exists yet — only static sw.js and webpush.js
   - Topology view (Cytoscape.js), host inventory, vuln dashboard, agent dashboard
   - Auth login page, authorization queue UI
   - Connects to the new WS dashboard endpoint for real-time updates

4. [MEDIUM] Documentation builder
   - Background service generating Markdown from collected data
   - Network segments, individual hosts, network devices, executive summary
   - GET /api/v1/docs/generate, /network/{id}, /device/{id}, /export

5. [MEDIUM] Credential vault API
   - Encrypted AES-256-GCM storage for device credentials
   - Ephemeral task-scoped credential delivery over WebSocket
   - GET|POST|DELETE /api/v1/vault/credentials

6. [LOW] Alembic migrations
   - Replace Base.metadata.create_all with proper Alembic migrations
   - Enables safe schema evolution in production

7. [LOW] GitHub issue templates and triage workflow

## Done
- WebSocket task dispatch (WS /api/v1/ws/agent/{id}, WS /api/v1/ws/dashboard) — PR #6
- Full data ingestion API (hosts, services, packages, vulnerabilities, interfaces,
  scan-results, device-configs, topology-edges) — PR #5
- Agent registration API (POST /api/v1/agents/register, heartbeat, list, delete, task queue) — PR #4
- Embedded CA (ECDSA P-256, 90-day agent certs, persistent root CA) — PR #4
- Operator JWT auth (POST /api/v1/auth/login, /refresh, GET /auth/me) — PR #4
- Auto-update: server version endpoint, agent self-update on heartbeat — PR #4
- Native OS agent (Ubuntu/Debian systemd + Windows Service) — PR #4
- Server foundation (FastAPI, SQLAlchemy/asyncpg, Redis, structured logging)
- Database models: Host, Service, Package, Vulnerability, Network, NetworkInterface,
  TopologyEdge, ScanResult, NetworkDevice, Agent, AuditLog, AuthorizationRequest, Alert
- Inventory API (/api/v1/inventory/*) — hosts, networks, devices, auth-requests, stats
- Alerts API (/api/v1/alerts/*)
- Topology API (/api/v1/topology/*) with Cytoscape.js-format export
- Module system (registry, base class, loader, builtin modules)
- First-run setup wizard, SetupGuard middleware
- WebPush browser notifications (VAPID)
- AI enrichment (Ollama + Anthropic), DNS enrichment, IP guard
- Docker Compose, install.sh, cleanup.sh
