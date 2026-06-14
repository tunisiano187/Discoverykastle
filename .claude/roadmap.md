# Discoverykastle — Roadmap

Last updated: 2026-06-14

## Currently open PR
- PR #18: feat(vault): AES-256-GCM credential vault API — in progress (this session)
  - Adds server/services/vault.py, server/models/credential.py, server/api/vault.py
  - Alembic migration 0003_credentials_table.py
  - 20 tests in tests/test_vault.py covering encryption, role enforcement, CRUD

## Recently merged
- PR #16: feat(auth): RBAC multi-user system + audit log API — merged 2026-05-28
- PR #15: feat: add dkctl admin CLI and agent Docker support — merged 2026-05-15
- PR #14: feat: add comprehensive test suite + GitHub Actions CI — merged 2026-05-09
- PR #13: feat: Ansible agent collector, Netmiko device collector, Devices SPA page — merged 2026-05-09
- PR #12: feat: CVE scanner agent collector + Networks/Topology SPA pages — merged 2026-05-03

## Todo (prioritized — pick from the top)

1. [HIGH] Rate limiting on /api/v1/auth/login
   - Prevent brute-force attacks (threshold: 5 failed attempts in 5 minutes)
   - Block IP temporarily via Redis-backed counter (slowapi or manual)
   - Described in docs/security.md hardening checklist

2. [MEDIUM] Ephemeral credential delivery over WebSocket
   - Server retrieves vault credential for a device task and generates a
     task-scoped single-use token, sent only via mTLS WebSocket to the agent
   - Needs vault PR merged first

3. [MEDIUM] Documentation generator service
   - Background service generating Markdown from collected data
   - Network segments, individual hosts, network devices, executive summary
   - GET /api/v1/docs/generate, /network/{id}, /device/{id}, /export

4. [MEDIUM] Agent auto-deployment
   - Deploy agent automatically on newly discovered hosts (with operator approval)
   - SSH-based deployment for Linux, WinRM/PSRemoting for Windows
   - Very high complexity — needs credential vault + ephemeral delivery first

5. [LOW] Integration tests end-to-end
   - Full coverage with a test PostgreSQL database
   - Test complete flows: enrollment → scan → host discovery → alert

6. [LOW] Multitenancy support
   - Multiple teams/projects in the same instance
   - Very high complexity

## Done
- Credential vault API (AES-256-GCM) — PR #18 (this session)
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
