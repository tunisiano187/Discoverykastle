# Discoverykastle — Roadmap

Last updated: 2026-09-06

## Currently open PR

- PR on branch `claude/initial-project-documentation-ogkzS` — sync with main, roadmap update

## Open Dependabot alerts

- [LOW] Alert #18 — package unknown (API returns 403) — https://github.com/tunisiano187/Discoverykastle/security/dependabot/18

## Recently merged

- PR #39: fix(deps): update browserslist → 4.28.8 (alert #19) — merged 2026-09-04
- PR #38: docs(roadmap): sync state — merged 2026-09-04
- PR #37: chore(deps): Dependabot npm group update — merged 2026-09-04
- PR #36: docs(roadmap): sync recent merges — merged 2026-08-28
- PR #35: fix(deps): replace python-jose with PyJWT, bump aiohttp/cryptography — merged 2026-08-13
- PR #34: feat(ui): CVE host-level drill-down slide-over panel — merged 2026-08-13
- PR #33: feat(ui): team-scoped vuln stats panel — merged 2026-08-13
- PR #32: chore(deps): bump aiohttp 3.14.1→3.14.3 — merged 2026-08-13
- PR #31: feat(agent): Windows WMI collector + CIS Level-1 hardening checks — merged 2026-08-04
- PR #30: feat(inventory): team assignment API — PATCH hosts/{id}/team + networks/{id}/team — merged 2026-08-04
- PR #29: feat(multitenancy): team-scoped data isolation (migration 0005) — merged 2026-07-29

## Todo — prioritized

1. [SECURITY][LOW] Dependabot alert #18 — details inaccessible (403); review at https://github.com/tunisiano187/Discoverykastle/security/dependabot/18

2. [MEDIUM] Page Teams dans le SPA — React UI for team management
   - List teams, create/delete, member management, role assignment
   - Team-scoped inventory views (hosts/networks filtered by team)

3. [MEDIUM] Windows agent — PowerShell installer script
   - install.ps1: set up Windows service (pywin32), write agent.conf, start service
   - uninstall.ps1 counterpart

4. [MEDIUM] SNMP collector
   - agent/collectors/snmp_collector.py using pysnmp
   - OID mappings for Cisco/Juniper/generic

5. [MEDIUM] Alertes automatiques CVE
   - Background task comparing installed packages against new CVEs
   - Webhook/email notification

6. [LOW] Hosts page: team assignment UI
   - PATCH /inventory/hosts/{id}/team is wired; add team picker in host detail view

7. [LOW] Hardening TLS — mTLS cert rotation + enforce cert validation on agent connections

## Done

- fix(deps): browserslist 4.28.2 → 4.28.8 (alert #19, prototype pollution/DoS) — PR #39
- Windows WMI collector + 14 CIS Level-1 hardening checks (32 tests) — PR #31
- Team assignment API: PATCH hosts/{id}/team + networks/{id}/team — PR #30
- Team-scoped data isolation (migration 0005 + model FKs + ?team_id= filtering) — PR #29
- Vuln UI: CVE drill-down slide-over + team-scoped stats panel — PR #33, #34
- fix(deps): python-jose → PyJWT, aiohttp 3.14.3, cryptography, react-router — PR #35
- Dependabot auto-merge workflow + CI permissions fix (issues: write)
- Multitenancy foundation: Teams + memberships CRUD (13 tests) — PR #24
- Integration test suite (auth/vault/inventory flows, live PostgreSQL) — PR #23
- Credential vault (AES-256-GCM), rate limiting, docs generator, agent auto-deploy — PR #19
- RBAC multi-user system + audit log — PR #16
- dkctl admin CLI + agent Docker — PR #15
- Full test suite + GitHub Actions CI — PR #14
- Ansible collector + Netmiko + Devices SPA — PR #13
- CVE scanner + Networks/Topology SPA — PR #12
- nmap + Alembic migrations + LDAP/AD module — PR #11
- React SPA: all pages, server foundation, modules, agent, install scripts
