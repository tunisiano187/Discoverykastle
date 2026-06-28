# Discoverykastle — Roadmap

Last updated: 2026-06-28

## Currently open PR
- PR #22 on branch `claude/integration-tests-hy2ann` — end-to-end integration test suite (33 tests)
  - CI was failing with: event loop mismatch, asyncpg errors, wrong RBAC for DELETE, GitGuardian false positives
  - Fixed in cc25180: asyncio_default_fixture_loop_scope=session, admin_headers for delete tests, # gitguardian:ignore annotations
  - Waiting for CI re-run to confirm green

## Recently merged
- PR #21: fix: GitGuardian false positives + Credential model export — merged 2026-06-24
- PR #19: feat: dkctl report subcommand + 7 tests — merged 2026-06-24
- PR #16: feat(auth): RBAC multi-user system + audit log API — merged 2026-05-28
- PR #15: feat: add dkctl admin CLI and agent Docker support — merged 2026-05-15
- PR #14: feat: add comprehensive test suite + GitHub Actions CI — merged 2026-05-09
- PR #13: feat: Ansible agent collector, Netmiko device collector, Devices SPA page — merged 2026-05-09
- PR #12: feat: CVE scanner agent collector + Networks/Topology SPA pages — merged 2026-05-03
- PR #11: feat: nmap collector, Alembic migrations, LDAP/AD module — merged 2026-05-03

## Todo (prioritized — pick from the top)

1. [HIGH] React SPA — Networks, Topology, AuthRequests pages
   - `ui/src/pages/Networks.tsx`, `Topology.tsx`, `AuthRequests.tsx` are either missing or stub
   - Docs mention a full dashboard; only Hosts/Devices pages exist
   - Enables operators to visualize the discovered network without CLI

2. [HIGH] Agent nmap collector improvements
   - `agent/collectors/network_scan.py` exists but scan results need richer parsing
   - CVE correlation against discovered services is not fully wired

3. [MEDIUM] Alembic migration coverage
   - Some tables (audit_log, alerts, hosts, networks) may still use create_all()
   - Need incremental migrations so production upgrades work safely

4. [MEDIUM] LDAP/AD module
   - `server/modules/builtin/ldap/module.py` — referenced in docs and CLAUDE.md but not verified complete

5. [LOW] Multitenancy support
   - Multiple teams/projects in the same instance
   - Very high complexity — defer until core flows are stable

## Done (recent)
- Integration test suite (33 tests: auth, vault, inventory) — PR #22 in progress
- Login rate limiting (Redis sliding window, 5 failures → HTTP 429) ✅
- Credential vault API (AES-256-GCM, POST/GET/DELETE/decrypt) ✅
- Alembic migration 0003 for credentials table ✅
- Documentation generator (GET /api/v1/docs/summary|network|device|export) ✅
- Agent auto-deployment via SSH (POST /api/v1/deploy/{host_id}) ✅
- CI at 346 unit tests passing ✅

## Done (older)
- RBAC multi-user system (viewer/analyst/operator/admin roles) — PR #16
- Audit log read API (GET /api/v1/audit-log, admin only) — PR #16
- User management CRUD API (/api/v1/users, admin only) — PR #16
- Alembic migration 0002 for users table — PR #16
- Admin CLI (dkctl) + agent Docker image — PR #15
- Test suite (151+ tests) + GitHub Actions CI — PR #14
- Ansible agent collector + Netmiko + Devices SPA — PR #13
- CVE scanner agent collector + Networks/Topology SPA — PR #12
- nmap collector + Alembic migrations + LDAP/AD module — PR #11
- dkctl admin CLI + SMTP/Slack notifications — PR #15
- Vulnerability read API — PR #8
- Task engine (AgentTask state machine, retry/timeout) — PR #7
- WebSocket task dispatch + dashboard real-time events — PR #6
- Full data ingestion API — PR #5
- Agent registration, CA, JWT auth, auto-update — PR #4
- Server foundation, all DB models, Inventory/Alerts/Topology APIs
- Module system, setup wizard, WebPush, AI enrichment, DNS enrichment
- Docker Compose, install scripts
