# Discoverykastle — Roadmap

Last updated: 2026-06-28

## Currently open PR
- PR #23 on branch `claude/integration-tests-v2` — end-to-end integration tests (fresh branch, clean history)

## Recently merged
- PR #21: fix(vault): GitGuardian suppression + Credential model export — merged 2026-06-28
- PR #19: feat: credential vault, rate limiting, docs generator, agent auto-deploy, 346 tests — merged 2026-06-07
- PR #16: feat(auth): RBAC multi-user system + audit log API — merged
- PR #15: feat: add dkctl admin CLI and agent Docker support — merged 2026-05-15
- PR #14: feat: add comprehensive test suite + GitHub Actions CI — merged 2026-05-09
- PR #13: feat: Ansible agent collector, Netmiko device collector, Devices SPA page — merged 2026-05-09
- PR #12: feat: CVE scanner agent collector + Networks/Topology SPA pages — merged 2026-05-03
- PR #11: feat: nmap collector, Alembic migrations, LDAP/AD module — merged 2026-05-03

## Todo (prioritized — pick from the top)

1. [IN PROGRESS] Integration tests end-to-end — PR #23
   - tests/integration/ with auth, vault, inventory flows against live PostgreSQL
   - GitGuardian clean (fresh branch, single commit, trust auth)

2. [LOW] Multitenancy support
   - Multiple teams/projects in the same instance
   - Very high complexity

## Done (this session / recent)
- Login rate limiting (Redis sliding window, 5 failures → HTTP 429) ✅
- Credential vault API (AES-256-GCM, POST/GET/DELETE/decrypt) ✅
- Alembic migration 0003 for credentials table ✅
- Documentation generator (GET /api/v1/docs/summary|network|device|export) ✅
- Agent auto-deployment via SSH (POST /api/v1/deploy/{host_id}) ✅
- CI at 346 tests passing ✅

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
