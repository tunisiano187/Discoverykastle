# Discoverykastle — Roadmap

Last updated: 2026-09-06

## Currently open PR

- PR #46 on branch `claude/dependabot-alert18-ogkzS` — fix(deps): nanoid 3.3.18 + feat(db): Alembic startup migrations

## Open Dependabot alerts

_(none)_

## Recently merged

- PR #45: feat(tls): mTLS cert rotation — renew endpoint + agent auto-renewal, 20 tests — merged 2026-09-06
- PR #44: feat(ui): Hosts page team assignment picker — merged 2026-09-06
- PR #43: feat(agent): SNMP collector — v1/v2c/v3, OID mappings, 30 tests — merged 2026-09-06
- PR #42: fix(data): dispatch on_vulnerability_found for new high/critical CVEs (3 new tests) — merged 2026-09-06
- PR #41: feat(ui): Teams page — list, create, delete + member management — merged 2026-09-06
- PR #40: chore: sync with main — browserslist fix merged, roadmap updated — merged 2026-09-06
- PR #39: fix(deps): update browserslist → 4.28.8 (alert #19) — merged 2026-09-04
- PR #38: docs(roadmap): sync state — merged 2026-09-04
- PR #37: chore(deps): Dependabot npm group update — merged 2026-09-04
- PR #35: fix(deps): replace python-jose with PyJWT — merged 2026-08-13
- PR #34/#33: CVE drill-down + team-scoped vuln UI — merged 2026-08-13
- PR #31: Windows WMI collector + CIS Level-1 checks — merged 2026-08-04
- PR #30: Team assignment API — merged 2026-08-04
- PR #29: Team-scoped data isolation (migration 0005) — merged 2026-07-29
- PR #24: Multitenancy foundation — Teams + memberships CRUD — merged 2026-07-01

## Todo — prioritized

1. **Scan result history UI** — per-CIDR history on Networks page + `/api/v1/data/scan-results` list endpoint
2. **Agent health dashboard** — Agents page showing CPU/memory/disk reported by agents on heartbeat
3. **Credential vault UI** — `/credentials` page for managing the encrypted vault (list, add, delete)
4. **Network device detail page** — Devices.tsx expand: vendor/model, interface table, SNMP OID tree
5. **Topology improvements** — edge labels (port/service), drag-and-drop layout persistence
6. **Alembic auto-generation** — `alembic revision --autogenerate` guidance in CONTRIBUTING.md

## Done

- feat(db): replace create_all() with alembic upgrade head at startup — PR #46
- fix(deps): nanoid 3.3.18 (Dependabot alert #18, GHSA-2v37-7h3g-55p8) — PR #46
- feat(tls): mTLS cert rotation — renew endpoint + agent auto-renewal, 20 tests — PR #45
- feat(ui): Hosts page team assignment picker — PR #44
- feat(agent): SNMP collector — v1/v2c/v3, OID mappings, vendor/model detection, 30 tests — PR #43
- fix(data): dispatch on_vulnerability_found for new high/critical CVEs (3 new tests) — PR #42
- feat(ui): Teams page — list/create/delete + member management (PR #41)
- feat(ui): Networks page — CIDR table + Auth Requests tab (approve/deny)
- feat(ui): Topology page — SVG canvas graph of host connections
- feat(agent): CVE scan — Grype + NVD API fallback, dpkg/rpm/pip/Windows packages
- feat(modules): LDAP/AD enrichment — OU path, group memberships, last logon, account status
- feat(agent): nmap network scanner — XML parsing, OS detection, service versions
- Windows WMI collector + 14 CIS Level-1 hardening checks (32 tests) — PR #31
- Windows installer: install.ps1, uninstall.ps1, service.py (pywin32)
- Team assignment API: PATCH hosts/{id}/team + networks/{id}/team — PR #30
- Team-scoped data isolation (migration 0005) — PR #29
- fix(deps): browserslist 4.28.8, python-jose → PyJWT, aiohttp 3.14.3 — PR #35, #39
- Vuln UI: CVE drill-down + team-scoped stats — PR #34, #33
- Multitenancy: Teams + memberships, CRUD API — PR #24
- Integration tests, credential vault, rate limiting, docs gen, agent auto-deploy — PR #23, #19
- RBAC, audit log, dkctl CLI, Docker agent — PR #16, #15
- Full test suite + CI — PR #14
- All server foundation, modules, agent, SPA pages
