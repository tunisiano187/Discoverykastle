# Discoverykastle — Roadmap

Last updated: 2026-07-01

## Currently open PR
- PR on branch `claude/initial-project-documentation-ogkzS` — ROADMAP update, CI green at 382 tests

## Recently merged
- PR #24: feat: multitenancy foundation — teams + memberships CRUD — merged 2026-07-01
- PR #23: feat(tests): end-to-end integration test suite against live PostgreSQL — merged 2026-06-28
- PR #21: fix(vault): GitGuardian suppression + Credential model export — merged 2026-06-28
- PR #19: feat: credential vault, rate limiting, docs generator, agent auto-deploy, 346 tests — merged 2026-06-07
- PR #16: feat(auth): RBAC multi-user system + audit log API — merged
- PR #15: feat: add dkctl admin CLI and agent Docker support — merged 2026-05-15
- PR #14: feat: add comprehensive test suite + GitHub Actions CI — merged 2026-05-09
- PR #13: feat: Ansible agent collector, Netmiko device collector, Devices SPA page — merged 2026-05-09
- PR #12: feat: CVE scanner agent collector + Networks/Topology SPA pages — merged 2026-05-03
- PR #11: feat: nmap collector, Alembic migrations, LDAP/AD module — merged 2026-05-03

## Todo (prioritized — pick from the top)

1. **Isolation tenant complète** — filter hosts/networks/devices by team_id
   - Add `team_id` FK to Host, Network, NetworkDevice models
   - Alembic migration for the new FKs
   - API middleware to scope queries to the caller's team
   - Medium complexity

2. **Page Teams dans le SPA** — React UI for team management
   - List teams, create, delete
   - Member management (add/remove)
   - Team-scoped views of inventory
   - Medium complexity

3. **SNMP collector** — enrich network devices without SSH
   - `agent/collectors/snmp_collector.py` using pysnmp
   - OID mappings for Cisco/Juniper/generic
   - Submit to `POST /api/v1/data/discovery`
   - Medium complexity

4. **Alertes automatiques CVE** — auto-alert on critical CVEs
   - Background task in alerts module: compare installed packages against new CVEs
   - Webhook/email notification
   - Medium complexity

5. **Hardening TLS** — mTLS between server and agents + cert rotation
   - Auto-rotate agent certs before expiry
   - Enforce cert validation on inbound agent connections
   - High complexity

## Done (this session / recent)
- Merged main into `claude/initial-project-documentation-ogkzS` — CI at 382 tests ✅
- Dependabot auto-merge workflow (patch/minor → auto-approve+squash, major → human review) ✅
- CI permissions fix (issues: write for auto-issue creation) ✅
- Multitenancy foundation — Teams + memberships CRUD + 13 tests ✅ — PR #24
- Integration test suite (auth/vault/inventory flows, live PostgreSQL) ✅ — PR #23
- Login rate limiting (Redis sliding window) ✅
- Credential vault API (AES-256-GCM) ✅
- Documentation generator ✅
- Agent auto-deployment via SSH ✅
- RBAC multi-user system ✅
- Full nmap + Alembic + LDAP/AD + CVE scan + all SPA pages ✅

## Done (older)
- All server foundation, modules, APIs, agent, install scripts
