# Discoverykastle — Roadmap

Last updated: 2026-08-30

## Currently open PR

None.

## Dependabot status

- Unable to retrieve Dependabot alerts
- Error: 403 — "Resource not accessible by integration" (`GET /repos/tunisiano187/Discoverykastle/dependabot/alerts`)
- Cause: Insufficient permissions — the integration token does not have access to Dependabot alerts for this repository
- Security prioritization could not be completed safely
- **No feature PR has been created in this run because the security status cannot be verified**
- Recommended action: grant the integration read access to Dependabot alerts in the repository settings, or re-connect the GitHub connector under claude.ai Settings → Connectors

## Recently merged

- PR #36: docs(roadmap): sync recent merges, record Dependabot API 403 — merged 2026-08-28
- PR #35: fix(deps): replace python-jose with PyJWT, bump aiohttp/cryptography/react-router — merged 2026-08-13
- PR #34: feat(ui): CVE host-level drill-down slide-over panel — merged 2026-08-13
- PR #33: feat(ui): team-scoped vuln stats panel on Dashboard and Vulns pages — merged 2026-08-13
- PR #32: chore(deps): bump aiohttp from 3.14.1 to 3.14.3 — merged 2026-08-13
- PR #31: feat(agent): Windows WMI collector with CIS Level-1 hardening checks — merged 2026-08-04
- PR #30: feat(inventory): team assignment API — PATCH hosts/{id}/team + networks/{id}/team — merged 2026-08-04
- PR #29: feat(multitenancy): team-scoped data isolation — migration 0005 + API ?team_id= filtering — merged 2026-07-29
- PR #28: feat(agent): wire self-update into heartbeat loop — merged 2026-07-25
- PR #27: chore(deps-dev): bump @babel/core from 7.29.0 to 7.29.7 — merged 2026-07-31

## Todo — prioritized

1. [SECURITY] Verify Dependabot alert status — API returned 403; fix integration permissions first
2. [MEDIUM] Windows agent — installer script
   - PowerShell install.ps1 that sets up the Windows service (pywin32), writes agent.conf,
     and starts DiscoverykastleAgent
3. [LOW] Hosts page: team assignment UI
   - PATCH /inventory/hosts/{id}/team is wired; add a team picker in the host detail view

## Done

- docs(roadmap): sync recent merges, record Dependabot API 403 — PR #36
- fix(deps): replace python-jose with PyJWT, bump aiohttp/cryptography/react-router — PR #35
- Vuln summary UI: CVE host-level drill-down (CveSlideOver component) — PR #34
- Vuln summary UI: team-scoped stats panel + team filter on Dashboard and Vulns pages — PR #33
- chore(deps): bump aiohttp from 3.14.1 to 3.14.3 — PR #32
- Windows WMI collector + 14 CIS Level-1 checks (32 tests) — PR #31
- Team assignment API: PATCH /inventory/hosts/{id}/team + /networks/{id}/team (15 tests) — PR #30
- conftest.py jose/passlib stubs scoped to broken-crypto envs only (fixes CI) — PR #30
- Team-scoped data isolation (migration 0005 + model FKs + API ?team_id= filtering, 15 tests) — PR #29
- Auth Requests UI in Networks.tsx (tab with approve/deny) — already implemented
- Agent auto-update wired into heartbeat loop (8 tests) — PR #28
- chore(deps-dev): bump @babel/core from 7.29.0 to 7.29.7 — PR #27
- chore(deps-dev): bump vite from 6.4.2 to 8.2.0 — PR #26
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
