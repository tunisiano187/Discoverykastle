# Discoverykastle — Roadmap

Last updated: 2026-07-29

## Currently open PR
- PR feat/team-scoped-isolation — in progress (being pushed this run)
  - Adds `team_id` FK to hosts/networks (migration 0005), `?team_id=` filtering on inventory + vulns APIs, 15 unit tests

## Recently merged
- PR #28: feat(agent): wire self-update into heartbeat loop — merged 2026-07-25
- PR #25: feat(api): Authorization Requests API — merged 2026-07-12
- PR #24: feat: multitenancy foundation — teams & memberships CRUD — merged 2026-06-28
- PR #23: feat(tests): end-to-end integration test suite against live PostgreSQL — merged 2026-06-28

## Todo (prioritized — pick from the top)

1. [HIGH] Auth Requests UI page in React SPA
   - API exists (`/api/v1/auth-requests`) but there is no dedicated React page
   - Show pending/approved/denied requests, approve/deny buttons for operators
   - Networks.tsx may already have a tab — verify and add if missing

2. [HIGH] Team assignment API — allow assigning hosts/networks to teams
   - Migration 0005 adds the FK; need `PATCH /api/v1/inventory/hosts/{id}/team`
   - Also: include `team_id` in data ingestion POST body so agents can tag hosts on submission

3. [MEDIUM] Windows agent support (pywin32 WMI collectors)
   - `agent/install/windows/service.py` exists; needs psutil + WMI collectors
   - CIS hardening checks via WMI / registry

4. [LOW] Vuln summary UI: team-scoped stats panel
   - `/api/v1/vulns/summary?team_id=` now supported; wire into the frontend

## Done

- Team-scoped data isolation (migration 0005 + model FKs + API ?team_id= filtering, 15 tests) — feat/team-scoped-isolation
- Agent auto-update wired into heartbeat loop (8 tests) — PR #28
- Authorization Requests API (POST/GET/approve/deny, 22 tests) — PR #25
- Multitenancy foundation: Team + TeamMembership models, CRUD API — PR #24
- Integration test suite (auth/vault/inventory flows, live PostgreSQL, CI green) — PR #23
- fix: credential vault GitGuardian suppression — PR #21
- Credential vault API, rate limiting, docs generator, agent auto-deploy — PR #19
- RBAC multi-user system + audit log API — PR #16
- dkctl admin CLI + agent Docker support — PR #15
- Test suite (151+ tests) + GitHub Actions CI — PR #14
- Ansible agent collector + Netmiko — PR #13
- CVE scanner agent collector + Networks/Topology SPA — PR #12
- nmap collector + Alembic migrations + LDAP/AD module — PR #11
- React SPA: Login, Dashboard, Hosts, Agents, Vulns, Devices, Networks, Topology pages
