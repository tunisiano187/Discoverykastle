# Discoverykastle — Roadmap

Last updated: 2026-09-27

## Currently open PR

_(none)_

## Dependabot status

- Unable to retrieve Dependabot alerts
- Error: HTTP 403 — "Resource not accessible by integration"
- API endpoint: `GET /repos/tunisiano187/Discoverykastle/dependabot/alerts`
- Security prioritization could not be completed safely
- The GitHub token/integration does not have permission to read Dependabot alerts
- No feature PR was created because security status cannot be verified
- Action required: Grant the GitHub App or token `security_events` read permission on the repository

## Recently merged

- PR #47: chore(deps): bump anyio from 4.14.1 to 4.14.2 — merged 2026-09-19
- PR #46: fix(deps)+feat(db+ui+agent): nanoid · Alembic startup · scan history · agent health metrics — merged 2026-09-17
- PR #45: feat(tls): mTLS cert rotation — renew endpoint + agent auto-renewal, 20 tests — merged 2026-09-06
- PR #44: feat(ui): Hosts page — team assignment picker — merged 2026-09-06
- PR #43: feat(agent): SNMP collector — v1/v2c/v3, OID mappings, 30 tests — merged 2026-09-06
- PR #42: fix(data): dispatch CVE alerts for newly discovered high/critical vulns — merged 2026-09-06
- PR #41: feat(ui): Teams page — list, create, delete + member management — merged 2026-09-06
- PR #40: chore: sync with main — all Dependabot/security fixes merged, roadmap updated — merged 2026-09-06
- PR #39: fix(deps): update browserslist to address Dependabot alert #19 — merged 2026-09-04
- PR #38: docs(roadmap): sync state — note Dependabot alert #18, record PR #36 merge — merged 2026-09-04

## Todo — prioritized

> NOTE: Security verification blocked — Dependabot alerts could not be retrieved (403). Feature work
> is on hold until Dependabot alerts can be verified as clear or addressed.

1. [BLOCKED] Verify Dependabot alert status — requires `security_events` read permission on the integration
2. [HIGH] Scan result history UI — per-CIDR history on Networks page + `/api/v1/data/scan-results` list endpoint
3. [HIGH] Agent health dashboard — Agents page showing CPU/memory/disk reported by agents on heartbeat
4. [MEDIUM] Credential vault UI — `/credentials` page for managing the encrypted vault (list, add, delete)
5. [MEDIUM] Network device detail page — Devices.tsx expand: vendor/model, interface table, SNMP OID tree
6. [MEDIUM] Topology improvements — edge labels (port/service), drag-and-drop layout persistence
7. [LOW] Alembic auto-generation — `alembic revision --autogenerate` guidance in CONTRIBUTING.md

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
