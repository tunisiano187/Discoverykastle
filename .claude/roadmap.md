# Discoverykastle — Roadmap

Last updated: 2026-04-19

## Currently open PR
- None

## Recently merged
- PR #6: feat(server): WebSocket task dispatch and dashboard real-time events — merged 2026-04-19
  - WS /api/v1/ws/agent/{id} — Redis Stream consumer, task delivery, heartbeat/task-result
  - WS /api/v1/ws/dashboard — JWT auth, real-time broadcast of all agent/task events
- PR #5: feat(server): full data ingestion API — merged 2026-04-05
- PR #4: feat/agent-registration-ca-auth — merged 2026-04-05
- PR #3: docs/initial — merged 2026-03-21

## Todo (prioritized — pick from the top)

1. [HIGH] Task engine — orchestrate what agents scan and when
   - Task creation, scheduling, retry with backoff (1 min, 5 min, 15 min), timeout handling
   - Authorization enforcement before dispatching sensitive tasks
   - Task state machine: Created → Queued → Dispatched → Running → Completed/Failed/TimedOut
   - A dedicated AgentTask DB model to persist task state across restarts
   - Background worker that monitors task timeouts and triggers retries

2. [HIGH] Vulnerability API
   - GET /api/v1/vulns — all vulns, filterable by severity/host
   - GET /api/v1/vulns/{cve_id} — CVE details + all affected hosts
   - GET /api/v1/vulns/summary — severity distribution, top CVEs
   - Data model and ingestion exist but no read endpoints yet

3. [MEDIUM] React frontend (SPA dashboard)
   - No frontend exists yet — only static sw.js and webpush.js
   - Topology view (Cytoscape.js), host inventory, vuln dashboard, agent dashboard
   - Auth login page, authorization queue UI
   - Connects to WS /api/v1/ws/dashboard for real-time updates

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

7. [LOW] GitHub issue templates and triage workflow

## Done
- WebSocket task dispatch (WS /api/v1/ws/agent/{id}, WS /api/v1/ws/dashboard) — PR #6
- Full data ingestion API (hosts, services, packages, vulnerabilities, interfaces,
  scan-results, device-configs, topology-edges) — PR #5
- Agent registration API, heartbeat, list, delete, task queue — PR #4
- Embedded CA (ECDSA P-256, 90-day agent certs) — PR #4
- Operator JWT auth (POST /api/v1/auth/login, /refresh, GET /auth/me) — PR #4
- Auto-update: server version endpoint, agent self-update on heartbeat — PR #4
- Native OS agent (Ubuntu/Debian systemd + Windows Service) — PR #4
- Server foundation (FastAPI, SQLAlchemy/asyncpg, Redis, structured logging)
- Database models: Host, Service, Package, Vulnerability, Network, NetworkInterface,
  TopologyEdge, ScanResult, NetworkDevice, Agent, AuditLog, AuthorizationRequest, Alert
- Inventory API (/api/v1/inventory/*), Alerts API, Topology API
- Module system, first-run setup wizard, SetupGuard middleware
- WebPush, AI enrichment, DNS enrichment, IP guard, Docker Compose
