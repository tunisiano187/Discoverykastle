# Discoverykastle — Roadmap

Last updated: 2026-10-04

## Currently open PR

- PR #52: chore(deps): bump pyjwt from 2.13.0 to 2.15.0 in the uv group — waiting for merge
  - Security-related: yes (pyjwt 2.14.0 release notes reference security advisories)
  - Author: dependabot[bot]
  - Branch: dependabot/uv/uv-2118ef368f
  - CI status: all checks green (GitGuardian ✓, Test Suite ✓, Integration Tests ✓)
  - Mergeable: yes (mergeable_state: clean)
  - Notes: No reviews requested, no blocking feedback. Waiting for merge by maintainer.

## Dependabot status

- Unable to retrieve full Dependabot alert list via API
- Error: HTTP 403 — "Resource not accessible by integration"
- API endpoint: `GET /repos/tunisiano187/Discoverykastle/dependabot/alerts`
- The GitHub token/integration does not have permission to read Dependabot alerts
- Action required: Grant the GitHub App or token `security_events` read permission on the repository
- **GitHub push output confirms: 16 open vulnerabilities on the default branch**
  - 1 critical
  - 7 high
  - 8 moderate
  - Details at: https://github.com/tunisiano187/Discoverykastle/security/dependabot
- PR #52 (pyjwt 2.13.0→2.15.0) addresses at least the pyjwt advisory referenced in its changelog

## Recently merged

- PR #51: feat(tls): track cert expires_at on agent registration and renewal — merged 2026-10-01
- PR #50: feat: NVD monitor — server-side CVE poller with alert pipeline — merged 2026-09-30
- PR #49: feat: complete tenant isolation for all inventory endpoints — merged 2026-09-30
- PR #48: docs(roadmap): sync state — Dependabot API 403, feature backlog updated — merged 2026-09-27
- PR #47: chore(deps): bump anyio from 4.14.1 to 4.14.2 — merged 2026-09-19
- PR #46: fix(deps)+feat(db+ui+agent): nanoid · Alembic startup · scan history · agent health metrics — merged 2026-09-17
- PR #45: feat(tls): mTLS cert rotation — renew endpoint + agent auto-renewal, 20 tests — merged 2026-09-06
- PR #44: feat(ui): Hosts page — team assignment picker — merged 2026-09-06
- PR #43: feat(agent): SNMP collector — v1/v2c/v3, OID mappings, 30 tests — merged 2026-09-06
- PR #42: fix(data): dispatch CVE alerts for newly discovered high/critical vulns — merged 2026-09-06

## Todo — prioritized

> NOTE: Security verification blocked — Dependabot alerts could not be retrieved (403). Feature work
> is on hold until Dependabot alerts can be verified as clear or addressed.
> PR #52 (pyjwt) is open and awaiting merge.

1. [BLOCKED] Merge PR #52 — pyjwt 2.13.0 → 2.15.0 (security-related bump, CI green)
2. [BLOCKED] Verify Dependabot alert status — requires `security_events` read permission on the integration
3. [HIGH] Scan result history UI — per-CIDR history on Networks page + `/api/v1/data/scan-results` list endpoint
4. [HIGH] Agent health dashboard — Agents page showing CPU/memory/disk reported by agents on heartbeat
5. [MEDIUM] Credential vault UI — `/credentials` page for managing the encrypted vault (list, add, delete)
6. [MEDIUM] Network device detail page — Devices.tsx expand: vendor/model, interface table, SNMP OID tree
7. [MEDIUM] Topology improvements — edge labels (port/service), drag-and-drop layout persistence
8. [LOW] Alembic auto-generation — `alembic revision --autogenerate` guidance in CONTRIBUTING.md

## Done

- feat(tls): track cert expires_at on agent registration and renewal — PR #51
- feat: NVD monitor — server-side CVE poller with alert pipeline — PR #50
- feat: complete tenant isolation for all inventory endpoints — PR #49
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
