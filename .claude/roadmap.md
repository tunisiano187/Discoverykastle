# Discoverykastle — Roadmap

Last updated: 2026-10-23

## Currently open PR

- PR #60: fix(deps): update certifi to address GHSA-6q48-6c7w-9gw2 — open
  - Security-related: yes
  - Advisory: GHSA-6q48-6c7w-9gw2 (certifi bundles emSign root CAs with compromised intermediate CA keys)
  - Branch: security/dependabot-certifi-ghsa-6q48
  - Package: certifi 2026.6.17 → 2026.10.23
  - CI status: pending

## Dependabot status

- API: HTTP 403 — "Resource not accessible by integration" (permission `security_events` read not granted)
- **uv audit on security/dependabot-certifi-ghsa-6q48: 0 known vulnerabilities** (verified 2026-10-23)
- certifi 2026.6.17→2026.10.23 (GHSA-6q48-6c7w-9gw2) — fixed in this branch
- Note: Dependabot API remains the source of truth; uv audit used as supplementary check due to 403

## Recently merged

- PR #59: chore(deps-dev): bump vite from 8.2.0 to 8.3.4 — merged 2026-10-23
- PR #58: chore(deps): bump aiohttp from 3.14.3 to 3.14.4 — merged 2026-10-20
- PR #57: feat(ui)+fix(deps): device detail panel + bump mako/multidict/urllib3 — merged 2026-10-15
- PR #56: chore(deps): bump the uv group across 1 directory with 2 updates — merged 2026-10-15
- PR #55: chore(deps): bump the npm_and_yarn group across 1 directory with 2 updates — merged 2026-10-15
- PR #52: chore(deps): bump pyjwt from 2.13.0 to 2.15.0 (security fix) — merged 2026-10-12
- PR #51: feat(tls): track cert expires_at on agent registration and renewal — merged 2026-10-01
- PR #50: feat: NVD monitor — server-side CVE poller with alert pipeline — merged 2026-09-30
- PR #49: feat: complete tenant isolation for all inventory endpoints — merged 2026-09-30
- PR #47: chore(deps): bump anyio from 4.14.1 to 4.14.2 — merged 2026-09-19

## Todo — prioritized

1. [SECURITY] certifi GHSA-6q48-6c7w-9gw2 — IN PROGRESS (PR #60)
2. [MEDIUM] Topology improvements — edge labels (port/service), drag-and-drop layout persistence
3. [LOW] Alembic auto-generation — `alembic revision --autogenerate` guidance in CONTRIBUTING.md
4. [LOW] Enroll in Anthropic OSS Scanner — ajouter `projects/discoverykastle/` (project.yaml + Dockerfile autosuffisant) une fois le projet en beta et le Dockerfile de prod finalisé (https://github.com/anthropics/oss-scanner)

## Done

- feat(ui): device detail panel (interfaces/routes/VLANs/SNMP/config tabs) — PR #57
- fix(deps): mako 1.3.12→1.4.3, multidict 6.7.1→6.9.1, urllib3 2.7.0→2.8.0 (8 advisories) — PR #57
- fix(deps): pyjwt 2.13.0 → 2.15.0 (14 PYSEC advisories) — PR #52
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
