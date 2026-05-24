# Discoverykastle — Roadmap

Last updated: 2026-05-24

## Currently open PR
- PR #16: feat(auth): RBAC multi-user system + audit log API — in progress (this session)
  - Notes: implementing viewer/analyst/operator/admin roles, user CRUD API, audit log read endpoint

## Recently merged
- PR #15: feat: add dkctl admin CLI and agent Docker support — merged 2026-05-15
- PR #14: feat: add comprehensive test suite + GitHub Actions CI — merged 2026-05-09
- PR #13: feat: Ansible agent collector, Netmiko device collector, Devices SPA page — merged 2026-05-09
- PR #12: feat: CVE scanner agent collector + Networks/Topology SPA pages — merged 2026-05-03
- PR #11: feat: nmap collector, Alembic migrations, LDAP/AD module — merged 2026-05-03

## Todo (prioritized — pick from the top)

1. [HIGH] Credential vault API
   - Described in docs/security.md: AES-256-GCM encrypted storage for device credentials
   - POST/GET/DELETE /api/v1/vault/credentials
   - Ephemeral task-scoped credential delivery over WebSocket
   - Master key sourced from DKASTLE_VAULT_KEY env var

2. [HIGH] Rate limiting on /api/v1/auth/login
   - Prevent brute-force attacks (threshold: 5 failed attempts in 5 minutes)
   - Block IP temporarily or add CAPTCHA
   - Use Redis-backed counter or slowapi

3. [MEDIUM] Documentation generator service
   - Background service generating Markdown from collected data
   - Network segments, individual hosts, network devices, executive summary
   - GET /api/v1/docs/generate, /network/{id}, /device/{id}, /export

4. [MEDIUM] Agent auto-deployment
   - Deploy agent automatically on newly discovered hosts (with operator approval)
   - SSH-based deployment for Linux, WinRM/PSRemoting for Windows
   - Very high complexity — needs credential vault first

5. [LOW] Integration tests end-to-end
   - Full coverage with a test PostgreSQL database
   - Test complete flows: enrollment → scan → host discovery → alert

6. [LOW] Multitenancy support
   - Multiple teams/projects in the same instance
   - Very high complexity

## Done
- RBAC multi-user system (viewer/analyst/operator/admin roles) — PR #16 (this session)
- Audit log read API (GET /api/v1/audit-log, admin only) — PR #16 (this session)
- User management CRUD API (/api/v1/users, admin only) — PR #16 (this session)
- Alembic migration 0002 for users table — PR #16 (this session)
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
