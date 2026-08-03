# Discoverykastle — Roadmap

Last updated: 2026-08-03

## Currently open PR
- PR claude/gifted-babbage-hhngmb: feat(inventory): team assignment API — PATCH hosts/{id}/team and networks/{id}/team
  - Status: waiting for review

## Recently merged
- PR #29: feat(multitenancy): team-scoped data isolation — migration 0005 + API ?team_id= filtering — merged 2026-07-29
- PR #28: feat(agent): wire self-update into heartbeat loop — merged 2026-07-25
- PR #27: chore(deps-dev): bump @babel/core — merged 2026-07-31
- PR #26: chore(deps-dev): bump vite — merged 2026-07-31
- PR #25: feat(api): Authorization Requests API — merged 2026-07-12

## Todo (prioritized — pick from the top)

1. [MEDIUM] Windows agent support (pywin32 WMI collectors)
   - `agent/install/windows/service.py` exists; needs psutil + WMI collectors
   - CIS hardening checks via WMI / registry

2. [LOW] Vuln summary UI: team-scoped stats panel
   - `/api/v1/vulns/summary?team_id=` now supported; wire into the frontend dashboard

3. [LOW] conftest.py jose stub — verify CI is not impacted
   - Added jose/passlib stubs to make tests run without native crypto in dev env
   - CI uses proper venv with working crypto — stubs are no-ops when jose is already loaded

## Done

- Team assignment API: PATCH /inventory/hosts/{id}/team + /networks/{id}/team + team_id in HostRecord (15 tests) — claude/gifted-babbage-hhngmb (open PR)
- Team-scoped data isolation (migration 0005 + model FKs + API ?team_id= filtering, 15 tests) — PR #29
- Auth Requests UI in Networks.tsx (tab with approve/deny) — already implemented
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
