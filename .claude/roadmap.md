# Discoverykastle — Roadmap

Last updated: 2026-08-13

## Currently open PR
- PR claude/gifted-babbage-hhngmb: feat(ui): CVE host-level drill-down slide-over panel

## Recently merged
- PR #33: feat(ui): team-scoped vuln stats panel on Dashboard + Vulns pages — merged 2026-08-13
- PR #31: feat(agent): Windows WMI collector with CIS Level-1 hardening checks — merged 2026-08-04
- PR #30: feat(inventory): team assignment API — PATCH hosts/{id}/team and networks/{id}/team — merged 2026-08-04
- PR #29: feat(multitenancy): team-scoped data isolation — migration 0005 + API ?team_id= filtering — merged 2026-07-29
- PR #28: feat(agent): wire self-update into heartbeat loop — merged 2026-07-25
- PR #25: feat(api): Authorization Requests API — merged 2026-07-12

## Todo (prioritized — pick from the top)

1. [MEDIUM] Windows agent — installer script
   - PowerShell install.ps1 that sets up the Windows service (pywin32), writes agent.conf,
     and starts DiscoverykastleAgent

2. [LOW] Hosts page: team assignment UI
   - PATCH /inventory/hosts/{id}/team is wired; add a team picker in the host detail view

## Done

- Vuln summary UI: CVE host-level drill-down (CveSlideOver component, click any CVE row) — claude/gifted-babbage-hhngmb (open PR)
- Vuln summary UI: team-scoped stats panel + team filter on Dashboard and Vulns pages — PR #33
- Windows WMI collector + 14 CIS Level-1 checks (32 tests) — PR #31
- Team assignment API: PATCH /inventory/hosts/{id}/team + /networks/{id}/team (15 tests) — PR #30
- conftest.py jose/passlib stubs scoped to broken-crypto envs only (fixes CI) — PR #30
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
