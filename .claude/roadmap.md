# Discoverykastle — Roadmap

Last updated: 2026-06-21

## Currently open PR
- PR #18: feat(vault): AES-256-GCM encrypted credential vault API — waiting for review/merge
  - Branch: `claude/gifted-babbage-hy2ann`
  - CI: all green (Test Suite ×2 + GitGuardian passed)
  - No review comments or requested changes
  - Implements credential vault (Todo item #1 below)

## Recently merged
- PR #16: feat(auth): RBAC multi-user system + user management API + audit log read API — merged 2026-05-28
- PR #15: feat: add dkctl admin CLI and agent Docker support — merged 2026-05-15
- PR #14: feat: add comprehensive test suite + GitHub Actions CI — merged 2026-05-09
- PR #13: feat: Ansible agent collector, Netmiko device collector, Devices SPA page — merged 2026-05-09
- PR #12: feat: CVE scanner agent collector + Networks/Topology SPA pages — merged 2026-05-03
- PR #11: feat: nmap collector, Alembic migrations, LDAP/AD module — merged 2026-05-03

## Todo (prioritized — pick from the top)

1. [IN PR #18] Credential vault API — waiting for merge
   - AES-256-GCM encrypted storage for device credentials
   - POST/GET/PATCH/DELETE /api/v1/vault/credentials
   - Master key from DKASTLE_VAULT_KEY env var

2. [HIGH] Rate limiting on /api/v1/auth/login
   - Prevent brute-force attacks (threshold: 5 failed attempts in 5 minutes)
   - Block IP temporarily using Redis-backed counter (slowapi)
   - Unblocks: secure auth for production deployments

3. [MEDIUM] Documentation generator service
   - Background service generating Markdown from collected data
   - Network segments, individual hosts, network devices, executive summary
   - GET /api/v1/docs/generate, /network/{id}, /device/{id}, /export

4. [MEDIUM] Agent auto-deployment
   - Deploy agent automatically on newly discovered hosts (with operator approval)
   - SSH-based deployment for Linux, WinRM/PSRemoting for Windows
   - Requires credential vault (#18) to be merged first

5. [LOW] Integration tests end-to-end
   - Full coverage with a test PostgreSQL database
   - Test complete flows: enrollment → scan → host discovery → alert

6. [LOW] Multitenancy support
   - Multiple teams/projects in the same instance
   - Very high complexity

## Done
- Credential vault (AES-256-GCM, operator-only API) — PR #18 (pending merge)
- RBAC multi-user system (viewer/analyst/operator/admin roles) — PR #16
- Audit log read API (GET /api/v1/audit-log, admin only) — PR #16
- User management CRUD API (/api/v1/users, admin only) — PR #16
- Alembic migration 0002 for users table — PR #16
- Admin CLI (dkctl) + agent Docker image — PR #15
- SMTP email notifications + Slack severity filtering — PR #15
- Test suite (150+ tests) + GitHub Actions CI — PR #14
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
