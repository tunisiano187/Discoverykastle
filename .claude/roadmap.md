# Discoverykastle — Roadmap

Last updated: 2026-07-12

## Currently open PR
- PR #25 on branch `claude/gifted-babbage-et0eai` — Authorization Requests API (in review)

## Recently merged
- PR #24: feat: multitenancy foundation — teams & memberships CRUD — merged 2026-06-28
- PR #23: feat(tests): end-to-end integration test suite against live PostgreSQL — merged 2026-06-28
- PR #21: fix(vault): GitGuardian suppression + Credential model export — merged 2026-06-24
- PR #19: feat: credential vault, rate limiting, docs generator, agent auto-deploy, 346 tests — merged 2026-06-07
- PR #16: feat(auth): RBAC multi-user system + audit log API — merged
- PR #15: feat: add dkctl admin CLI and agent Docker support — merged 2026-05-15

## Todo (prioritized — pick from the top)

1. [HIGH] React SPA frontend — no UI files exist at all
   - Dashboard: host inventory, CVE feed, agent status
   - Networks/Topology page (Cytoscape.js graph)
   - Auth Requests page (approve/deny pending requests — now backed by API)
   - Requires: npm build pipeline, Vite setup

2. [HIGH] Team-scoped data isolation — multitenancy Phase 2
   - Filter hosts/networks/vulnerabilities by team membership
   - team_id FK on Host/Network (migration 0005)
   - API query params: ?team_id=...

3. [MEDIUM] Agent auto-update via WebSocket
   - When heartbeat response has agent_update_required=true, agent fetches new version
   - agent/updater.py exists but is not wired into agent/core.py main loop

4. [MEDIUM] Windows agent support (pywin32)
   - CIS hardening checks via WMI / registry
   - agent/install/windows/service.py exists; needs psutil + WMI collectors

5. [LOW] NVD API integration for CVE enrichment
   - agent/collectors/cve_scan.py exists; add NVD API fallback when Grype absent

## Done (this session / recent)
- Authorization Requests API (POST/GET/approve/deny, 22 tests) — PR #25
- Multitenancy foundation: Team + TeamMembership models, CRUD API — PR #24
- Integration test suite (auth/vault/inventory flows, live PostgreSQL, CI green) — PR #23

## Done (older)
- fix: verify_password catches UnknownHashError for plain-text admin password
- Login rate limiting (Redis sliding window, 5 failures → HTTP 429)
- Credential vault API (AES-256-GCM, POST/GET/DELETE/decrypt)
- Alembic migration 0003 for credentials table
- Documentation generator (GET /api/v1/docs/summary|network|device|export)
- Agent auto-deployment via SSH (POST /api/v1/deploy/{host_id})
- CI at 346+ tests passing
- RBAC multi-user system (viewer/analyst/operator/admin roles) — PR #16
- Audit log read API (GET /api/v1/audit-log, admin only) — PR #16
- User management CRUD API (/api/v1/users, admin only) — PR #16
- Alembic migration 0002 for users table — PR #16
- Admin CLI (dkctl) + agent Docker image — PR #15
- Test suite (151+ tests) + GitHub Actions CI — PR #14
- Ansible agent collector + Netmiko + Devices SPA — PR #13
- CVE scanner agent collector + Networks/Topology SPA — PR #12
- nmap collector + Alembic migrations + LDAP/AD module — PR #11
- Vulnerability read API — PR #8
- Task engine (AgentTask state machine, retry/timeout) — PR #7
- WebSocket task dispatch + dashboard real-time events — PR #6
- Full data ingestion API — PR #5
- Agent registration, CA, JWT auth, auto-update — PR #4
- Server foundation, all DB models, Inventory/Alerts/Topology APIs
- Module system, setup wizard, WebPush, AI enrichment, DNS enrichment
- Docker Compose, install scripts
