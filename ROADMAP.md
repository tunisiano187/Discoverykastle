# Discoverykastle — Roadmap & État du projet

> Dernière mise à jour : avril 2026

---

## Résumé de l'architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    React SPA (ui/)                              │
│   Dashboard · Agents · Hosts · Vulns · (Topology à venir)      │
└──────────────────────────┬──────────────────────────────────────┘
                           │ HTTPS / WebSocket
┌──────────────────────────▼──────────────────────────────────────┐
│                   Central Server (FastAPI)                      │
│                                                                 │
│  API v1                                                         │
│  ├── /auth         Auth JWT + bcrypt                            │
│  ├── /setup        First-run wizard                             │
│  ├── /agents       Enregistrement agents (mTLS + CA embarquée)  │
│  ├── /inventory    Hosts, Networks, Devices, AuthRequests       │
│  ├── /vulns        CVE list, summary, detail                    │
│  ├── /tasks        Task engine + dispatch WebSocket             │
│  ├── /data/puppet  Ingestion batches Puppet (DK agent push)     │
│  ├── /topology     Topologie réseau                             │
│  ├── /alerts       Alertes                                      │
│  ├── /modules      Liste modules actifs                         │
│  ├── /netbox       Sync NetBox                                  │
│  └── /ws           WebSocket temps réel                         │
│                                                                 │
│  Modules built-in                                               │
│  ├── alerts        Gestion alertes                              │
│  ├── inventory     Inventaire hosts/networks                    │
│  ├── topology      Liens topologie                              │
│  ├── netbox        Export/import NetBox                         │
│  ├── dns           Enrichissement PTR + SOA + AD detect         │
│  ├── puppet        Pull PuppetDB + réception push agent DK      │
│  ├── ansible       Pull AWX/Tower + lecture fact-cache          │
│  └── ai            Enrichissement IA (Anthropic, optionnel)     │
│                                                                 │
│  Services                                                       │
│  ├── ip_utils      Classification IP/CIDR (RFC 1918, public…)  │
│  ├── ca            CA embarquée — émet certs agents mTLS        │
│  ├── auth          JWT + bcrypt                                 │
│  ├── task          Task engine + state machine                  │
│  ├── version       Version endpoint + auto-update agents        │
│  └── webpush       Notifications push navigateur                │
│                                                                 │
│  PostgreSQL (models)                                            │
│  ├── Host          IPs, FQDN, OS, packages, services, vulns     │
│  ├── Network       CIDR, domain_name, scan_authorized           │
│  ├── NetworkDevice Équipements réseau (switch, router…)         │
│  ├── Vulnerability CVE, CVSS, severity, remédiation             │
│  ├── AgentTask     Task engine (pending→running→done/fail)      │
│  ├── AuthorizationRequest  Demandes scan IP publique            │
│  └── Agent         Enregistrement + empreinte cert mTLS         │
└──────────────────────────┬──────────────────────────────────────┘
                           │ mTLS (cert CA embarquée)
         ┌─────────────────┴──────────────────────┐
         ▼                                        ▼
┌────────────────────┐                ┌────────────────────┐
│   DK Agent Linux   │                │  DK Agent Windows  │
│   (native / venv)  │                │  (native / venv)   │
│                    │                │                    │
│ agent/core.py      │                │ agent/core.py      │
│ agent/config.py    │                │ agent/config.py    │
│ agent/updater.py   │                │ agent/updater.py   │
│                    │                │                    │
│ Collectors :       │                │ Windows Service    │
│ └ puppet.py ──────►│ lit les        │ (pywin32)          │
│     (YAML facts +  │ fichiers du    │                    │
│      reports du    │ Puppet server) │                    │
│      Puppet server)│                │                    │
│                    │                │                    │
│ Install :          │                │ Install :          │
│ systemd service    │                │ install.ps1        │
│ install.sh         │                │ service.py         │
│ uninstall.sh       │                │ uninstall.ps1      │
└────────────────────┘                └────────────────────┘
```

---

## Ce qui est fait ✅

### Serveur central (FastAPI)

| Composant | Statut | Notes |
|-----------|--------|-------|
| Bootstrap / first-run setup | ✅ Done | `POST /api/v1/setup` — crée admin + initialise DB |
| Auth JWT (login, refresh, me) | ✅ Done | `POST /api/v1/auth/token` + middleware |
| CA embarquée + enregistrement agents | ✅ Done | `server/services/ca.py` — émet certs mTLS |
| Enregistrement agents + heartbeat | ✅ Done | `POST /api/v1/agents/register` + heartbeat |
| Auto-update agents | ✅ Done | `GET /api/v1/version` — agents vérifient et se mettent à jour |
| Inventaire hosts (CRUD + détail) | ✅ Done | `GET /api/v1/inventory/hosts` |
| Inventaire networks | ✅ Done | `GET /api/v1/inventory/networks` avec `domain_name` + `ip_class` |
| Classification IP/CIDR | ✅ Done | `server/services/ip_utils.py` — RFC 1918, loopback, link-local, etc. |
| Authorization scan IP publique | ✅ Done | `AuthorizationRequest` + approve/deny |
| Inventaire devices réseau | ✅ Done | `NetworkDevice` model + API |
| Vulnérabilités (list, summary, CVE detail) | ✅ Done | `GET /api/v1/vulns/` |
| Task engine | ✅ Done | `AgentTask` state machine — pending→running→done/fail, retry, timeout |
| WebSocket temps réel | ✅ Done | `GET /ws` — dashboard live events |
| Ingestion données Puppet (push agent DK) | ✅ Done | `POST /api/v1/data/puppet` |
| Ingestion données discovery (hosts, services, vulns) | ✅ Done | `POST /api/v1/data/discovery` |
| Module DNS (PTR + SOA + AD detect) | ✅ Done | `server/modules/builtin/dns/module.py` |
| Module Puppet (PuppetDB pull + upsert) | ✅ Done | `server/modules/builtin/puppet/module.py` |
| Module Ansible (AWX + fact-cache) | ✅ Done | `server/modules/builtin/ansible/module.py` |
| Module LDAP/AD | ✅ Done | `server/modules/builtin/ldap/module.py` — enrichit OS, OU, last-logon |
| Module NetBox | ✅ Done | Sync bidirectionnelle |
| Module AI | ✅ Done | Enrichissement via Anthropic API (optionnel) |
| Topologie réseau | ✅ Done | `TopologyEdge` + `GET /api/v1/topology` |
| Alertes | ✅ Done | `GET /api/v1/alerts` |
| Config centralisée | ✅ Done | `server/config.py` — toutes les vars DKASTLE_* |

### DK Agent (natif Linux / Windows)

| Composant | Statut | Notes |
|-----------|--------|-------|
| Collecteur nmap (network_scan.py) | ✅ Done | `agent/collectors/network_scan.py` — scan SYN/TCP, XML parser, submit hosts+services |
| Config loader cross-platform | ✅ Done | `agent/config.py` — clé=valeur + env vars |
| Core : enrollment + heartbeat | ✅ Done | `agent/core.py` — mTLS, POST /register |
| Auto-update | ✅ Done | `agent/updater.py` — compare version, télécharge |
| Collecteur Puppet | ✅ Done | `agent/collectors/puppet.py` — YAML facts + reports du Puppet server |
| Entry point CLI | ✅ Done | `agent/main.py` — `python -m agent [--enroll]` |
| Service systemd (Linux) | ✅ Done | `agent/install/linux/discoverykastle-agent.service` |
| Script install Linux (Ubuntu/Debian) | ✅ Done | `agent/install/linux/install.sh` |
| Script uninstall Linux | ✅ Done | `agent/install/linux/uninstall.sh` |
| Windows Service (pywin32) | ✅ Done | `agent/install/windows/service.py` |
| Script install Windows | ✅ Done | `agent/install/windows/install.ps1` |
| Script uninstall Windows | ✅ Done | `agent/install/windows/uninstall.ps1` |

### Interface Web (React SPA)

| Composant | Statut | Notes |
|-----------|--------|-------|
| Auth / Login | ✅ Done | JWT, redirect automatique |
| Dashboard | ✅ Done | Métriques globales + events WebSocket live |
| Agents | ✅ Done | Liste agents, statut, heartbeat |
| Hosts | ✅ Done | Inventaire hosts, IPs, OS |
| Vulns | ✅ Done | Liste CVE, sévérité |

### Infrastructure / DevOps

| Composant | Statut | Notes |
|-----------|--------|-------|
| Docker Compose (serveur + PostgreSQL + Redis) | ✅ Done | `docker-compose.yml` |
| Script d'installation one-liner | ✅ Done | `install.sh` |
| Tests (auth, CA, data ingestion, tasks, vulns, WS) | ✅ Done | `tests/` — pytest |

---

## Ce qui reste à faire ❌ / En cours 🔄

### Priorité haute

| Tâche | Raison | Complexité |
|-------|--------|------------|
| **CVE scan côté agent** (Grype/Trivy/NVD) | Détection vulns packages installés | Haute |
| ~~Collecteur nmap côté DK agent~~ | ✅ `agent/collectors/network_scan.py` | |
| ~~Alembic migrations DB~~ | ✅ `alembic/` + `0001_initial_schema.py` | |
| ~~Module LDAP/AD~~ | ✅ `server/modules/builtin/ldap/module.py` | |

### Priorité moyenne

| Tâche | Raison | Complexité |
|-------|--------|------------|
| **Collecteur Ansible côté agent** | Cohérence avec Puppet : le fact-cache est sur le serveur Ansible, pas Docker | Faible |
| **Page Topology dans le SPA** | Visualisation graphique des liens réseau | Haute (D3.js) |
| **Page Networks dans le SPA** | Affichage des réseaux, ip_class, domain_name, bouton "demander scan" | Moyenne |
| **Page Authorization Requests** | Workflow approve/deny pour les scans IP publiques | Faible |
| **Page Devices dans le SPA** | Équipements réseau (switch, router) | Faible |
| **Intégration Netmiko** | Collecte infos switch/router via SSH (Cisco, Juniper, Arista, MikroTik) | Haute |
| **Notifications email/Slack** | Alertes + nouvelles vulnérabilités | Faible |
| **Documentation de déploiement** | Mise à jour docs/deployment.md avec nouveaux modules | Faible |

### Priorité basse

| Tâche | Raison | Complexité |
|-------|--------|------------|
| **Agent auto-déploiement** | Déploiement automatique sur hôtes découverts (avec autorisation) | Très haute |
| **Générateur de documentation** | Export rapport PDF/Markdown de l'infrastructure | Haute |
| **Support multitenancy** | Plusieurs équipes/projets dans la même instance | Très haute |
| **Tests d'intégration end-to-end** | Couverture complète avec DB de test | Haute |
| **Package pip + image Docker agent** | Distribution simplifiée | Faible |
| **Interface CLI admin** | Gestion sans dashboard web | Moyenne |

---

## Plan de développement mis à jour

### Sprint 1 — Fondations scan actif (2-3 semaines)

```
[x] Classification IP/CIDR (is_private / is_public)
[x] Authorization workflow (AuthorizationRequest approve/deny)
[x] Task engine (dispatch tâches aux agents)
[x] WebSocket temps réel
[ ] Collecteur nmap côté DK agent
[ ] Alembic migrations (remplace create_all())
```

### Sprint 2 — Enrichissement & Sources de données (2 semaines)

```
[x] Module DNS (PTR + SOA + AD detect)
[x] Module Puppet (PuppetDB + push agent)
[x] Module Ansible (AWX + fact-cache)
[ ] Module LDAP/AD (ldap3)
[ ] Collecteur Ansible côté agent (cohérence avec Puppet)
```

### Sprint 3 — CVE & Sécurité (2 semaines)

```
[x] Modèle Vulnerability + API read
[ ] Collecteur CVE côté agent (Grype ou NVD API)
[ ] Corrélation packages → CVE
[ ] Alertes automatiques nouvelles vulnérabilités critiques
```

### Sprint 4 — Interface complète (2 semaines)

```
[x] Dashboard (métriques + live WS)
[x] Hosts, Agents, Vulns
[ ] Networks + Authorization Requests
[ ] Topology (graphe D3.js)
[ ] Devices réseau
```

### Sprint 5 — Intégrations réseau avancées (3 semaines)

```
[ ] Netmiko (Cisco IOS, Juniper JunOS, Arista EOS, MikroTik RouterOS)
[ ] ARP/LLDP/CDP pour topologie automatique
[ ] SNMP pour équipements sans SSH
```

### Sprint 6 — Production readiness (2 semaines)

```
[ ] Tests d'intégration e2e
[ ] Packaging (pip, Docker agent)
[ ] Documentation complète
[ ] Hardening sécurité (rate limiting, audit log)
```

---

## Variables d'environnement clés

```bash
# Server
DKASTLE_DATABASE_URL=postgresql+asyncpg://dkastle:dkastle@db:5432/discoverykastle
DKASTLE_SECRET_KEY=<64-char-hex>
DKASTLE_ENROLL_TOKEN=<strong-random>
DKASTLE_REQUIRE_PUBLIC_SCAN_AUTHORIZATION=true

# DNS enrichment
DKASTLE_DNS_RESOLVE_ENABLED=true
DKASTLE_DNS_SERVER=             # vide = résolveur système
DKASTLE_DNS_TIMEOUT=3.0

# LDAP/AD (désactivé par défaut)
DKASTLE_LDAP_ENABLED=false
DKASTLE_LDAP_SERVER=ldap://dc.example.com
DKASTLE_LDAP_BIND_DN=CN=readonly,DC=example,DC=com
DKASTLE_LDAP_BIND_PASSWORD=
DKASTLE_LDAP_BASE_DN=DC=example,DC=com

# Puppet
DKASTLE_PUPPET_ENABLED=false
DKASTLE_PUPPET_PUPPETDB_URL=    # optionnel (si PuppetDB installé)
DKASTLE_PUPPET_PUPPETDB_TOKEN=

# Ansible
DKASTLE_ANSIBLE_ENABLED=false
DKASTLE_ANSIBLE_AWX_URL=https://awx.example.com
DKASTLE_ANSIBLE_AWX_TOKEN=

# AI (optionnel)
DKASTLE_AI_ENABLED=false
DKASTLE_ANTHROPIC_API_KEY=

# Agent (dans /etc/discoverykastle/agent.conf)
DKASTLE_SERVER_URL=https://dk.example.com
DKASTLE_ENROLL_TOKEN=<same-as-server>
DKASTLE_AGENT_ID=               # rempli après enrollment
DKASTLE_AGENT_CERT=             # chemin cert mTLS
DKASTLE_AGENT_KEY=              # chemin clé mTLS
```

---

## Flux de données : Puppet

```
Puppet agents  ──Puppet protocol──►  Puppet server (vardir)
                                           │
                                    DK agent (sur le Puppet server)
                                    agent/collectors/puppet.py
                                    └─ lit: yaml/facts/*.yaml
                                    └─ lit: reports/<certname>/*.yaml
                                           │
                                    POST /api/v1/data/puppet
                                           │
                                    server/modules/builtin/puppet/module.py
                                    └─ _upsert_host() → PostgreSQL
```

**Sans PuppetDB :** l'agent DK lit directement les fichiers YAML du puppet server.
**Avec PuppetDB :** le module serveur pull aussi via PuppetDB REST API (`/pdb/query/v4/`).

---

## Flux de données : Ansible

```
Ansible controller  ──facts──►  AWX/Tower API
                     ou
                     ──facts──►  fact-cache dir (json/yaml)
                                       │
                              Mode 1 : DK server pull AWX API
                              Mode 2 : DK agent lit le fact-cache
                                       │
                              server/modules/builtin/ansible/module.py
                              └─ _upsert_host() → PostgreSQL
```

> **À faire :** déplacer la lecture du fact-cache vers `agent/collectors/ansible.py`
> pour la cohérence avec Puppet (le fact-cache est sur le contrôleur Ansible, pas dans Docker).

---

## Installation rapide

### Serveur (Docker)

```bash
git clone https://github.com/tunisiano187/Discoverykastle.git
cd Discoverykastle
cp .env.example .env
# Éditer .env : SECRET_KEY, ENROLL_TOKEN
docker compose up -d
# Ouvrir http://localhost:8000 → wizard first-run
```

### Agent Linux (Ubuntu/Debian)

```bash
curl -fsSL https://dk.example.com/install-agent.sh | sudo bash \
  --server-url https://dk.example.com \
  --enroll-token <TOKEN>
```

### Agent Windows (PowerShell admin)

```powershell
.\agent\install\windows\install.ps1 `
  -ServerUrl https://dk.example.com `
  -EnrollToken "<TOKEN>"
```

---

## Tests

```bash
# Lancer les tests
pip install -e ".[test]"
pytest tests/ -v

# Tests disponibles :
# tests/test_auth.py          — auth JWT
# tests/test_ca.py            — CA embarquée + mTLS
# tests/test_data_ingestion.py — POST /api/v1/data/*
# tests/test_task_engine.py   — state machine tasks
# tests/test_vulns.py         — API vulnérabilités
# tests/test_ws.py            — WebSocket
# tests/test_version.py       — version + auto-update
```

---

*Ce document est généré et maintenu manuellement — mettre à jour à chaque sprint.*
