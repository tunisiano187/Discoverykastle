# Discoverykastle — Roadmap

Last updated: 2026-04-21

## Currently open PR
- PR #8: feat(server): vulnerability read API — list, summary, CVE detail — in review

## Recently merged
- PR #7: feat(server): task engine — AgentTask model, state machine, retry, timeout monitor — merged 2026-04-19
- PR #6: feat(server): WebSocket task dispatch and dashboard real-time events — merged 2026-04-19
- PR #5: feat(server): full data ingestion API — merged 2026-04-05
- PR #4: feat/agent-registration-ca-auth — merged 2026-04-05

## Todo (prioritized — pick from the top)

1. [MEDIUM] React frontend (SPA dashboard)
   - No frontend exists yet — only static sw.js and webpush.js
   - Topology view (Cytoscape.js), host inventory, vuln dashboard, agent dashboard
   - Auth login page, authorization queue UI
   - Connects to WS /api/v1/ws/dashboard for real-time updates

3. [MEDIUM] Documentation builder
   - Background service generating Markdown from collected data
   - Network segments, individual hosts, network devices, executive summary
   - GET /api/v1/docs/generate, /network/{id}, /device/{id}, /export

4. [MEDIUM] Credential vault API
   - Encrypted AES-256-GCM storage for device credentials
   - Ephemeral task-scoped credential delivery over WebSocket
   - GET|POST|DELETE /api/v1/vault/credentials

5. [LOW] Alembic migrations
   - Replace Base.metadata.create_all with proper Alembic migrations

6. [LOW] GitHub issue templates and triage workflow

## Done
- Vulnerability read API (list, summary, CVE detail) — PR #8
- Task engine (AgentTask model, state machine, retry/backoff, timeout monitor) — PR #7
- WebSocket task dispatch (WS /api/v1/ws/agent/{id}, WS /api/v1/ws/dashboard) — PR #6
- Full data ingestion API — PR #5
- Agent registration, CA, JWT auth, auto-update, native OS agent — PR #4
- Server foundation, all DB models, Inventory/Alerts/Topology APIs
- Module system, setup wizard, WebPush, AI enrichment, DNS enrichment
- Docker Compose, install scripts
