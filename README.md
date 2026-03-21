# Discoverykastle

> Autonomous network discovery, security assessment, and documentation platform powered by distributed agents.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-ready-blue.svg)](docs/deployment.md)
[![Status: Pre-Alpha](https://img.shields.io/badge/Status-Pre--Alpha-orange.svg)]()

---

## ⚠️ Legal Disclaimer

**Discoverykastle must only be used on networks and systems you own or have explicit written authorization to scan and assess.**

Unauthorized network scanning, device access, or vulnerability probing is illegal in most jurisdictions (CFAA in the USA, Computer Misuse Act in the UK, and equivalent laws elsewhere). The project maintainers are not responsible for any misuse of this tool.

---

## What is Discoverykastle?

Discoverykastle is an autonomous, agent-based platform for comprehensive network discovery and security assessment. Agents are deployed on target hosts and network entry points. They discover hosts, enumerate services, assess security posture (CVEs, missing patches), map network topology, and interact with network devices (switches, routers) to extract configuration and version information. All findings are reported to a central server which builds a living, auto-generated documentation of the infrastructure.

The platform is recursive by design: from each newly discovered vantage point, agents can request authorization to continue discovery further into the network.

---

## Key Features

- **Host discovery** — OS fingerprinting, installed packages, running services, listening ports
- **Security assessment** — CVE matching, missing patches, outdated software, misconfigurations
- **Network mapping** — Interface enumeration, nmap full-scan across discovered subnets
- **Network device inspection** — SSH/API access to switches and routers; extract running config, firmware version, VLAN tables, ARP tables, routing tables
- **Recursive discovery** — From each new vantage point, continue discovery with explicit user authorization
- **Agent self-deployment** — Agents can deploy themselves on newly discovered hosts after human approval
- **Auto-documentation** — Server generates comprehensive, always-up-to-date infrastructure documentation
- **Security-first design** — Agents run in sandboxed Docker containers with strict capability limits; all communication is encrypted and mutually authenticated

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                        Web Dashboard (React)                     │
└─────────────────────────────┬────────────────────────────────────┘
                              │ HTTPS / WebSocket
┌─────────────────────────────▼────────────────────────────────────┐
│                       Central Server (FastAPI)                   │
│  ┌───────────────┐  ┌───────────────┐  ┌──────────────────────┐  │
│  │  Task Engine  │  │  Doc Builder  │  │  Auth / Vault        │  │
│  └───────────────┘  └───────────────┘  └──────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │                  PostgreSQL Database                      │   │
│  └───────────────────────────────────────────────────────────┘   │
└──────────┬─────────────────────────────────────┬─────────────────┘
           │ mTLS / WebSocket                    │ mTLS / WebSocket
┌──────────▼──────────┐               ┌──────────▼──────────┐
│    Agent (Site A)   │               │    Agent (Site B)   │
│  ┌───────────────┐  │               │  ┌───────────────┐  │
│  │ Host Scanner  │  │               │  │ Host Scanner  │  │
│  │ Net Scanner   │  │               │  │ Net Scanner   │  │
│  │ Device Probe  │  │               │  │ Device Probe  │  │
│  │ CVE Analyzer  │  │               │  │ CVE Analyzer  │  │
│  └───────────────┘  │               │  └───────────────┘  │
└─────────────────────┘               └─────────────────────┘
```

See [Architecture Documentation](docs/architecture.md) for full details.

---

## Quick Start

> **Prerequisites**: Docker >= 24.x, Docker Compose >= 2.x

```bash
# Clone the repository
git clone https://github.com/tunisiano187/Discoverykastle.git
cd Discoverykastle

# Copy and configure environment
cp .env.example .env
# Edit .env: set AUTHORIZED_CIDRS, admin credentials, etc.

# Start the server
docker compose up -d server

# Deploy an agent on a target host
docker compose run --rm agent
```

Access the dashboard at `https://localhost:8443` (default).

---

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | System design, components, data flow, tech stack |
| [Agent Design](docs/agent.md) | Agent capabilities, lifecycle, security constraints |
| [Server Design](docs/server.md) | API, database schema, task orchestration, dashboard |
| [Security Model](docs/security.md) | Threat model, authentication, authorization, audit |
| [Deployment Guide](docs/deployment.md) | Docker setup, configuration, production hardening |
| [Contributing](CONTRIBUTING.md) | Development setup, code style, PR guidelines |

---

## Project Structure

```
Discoverykastle/
├── README.md
├── CONTRIBUTING.md
├── .gitignore
├── .env.example           # Environment variable template
├── docker-compose.yml     # Orchestration (server + agent)
├── docs/
│   ├── architecture.md
│   ├── agent.md
│   ├── server.md
│   ├── security.md
│   └── deployment.md
├── server/                # Central server (FastAPI)
│   ├── Dockerfile
│   ├── api/
│   ├── db/
│   ├── tasks/
│   └── frontend/          # React dashboard
└── agent/                 # Discovery agent (Python)
    ├── Dockerfile
    ├── modules/
    │   ├── host/          # Host & service discovery
    │   ├── security/      # CVE analysis, patch assessment
    │   ├── network/       # Interface enum, nmap
    │   └── devices/       # Network device probing (Netmiko)
    └── core/              # Agent core, comms, task executor
```

---

## Technology Stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Agent | Python 3.12 | Best ecosystem for security/network tooling |
| Server API | FastAPI (Python) | Async, auto OpenAPI docs, type-safe |
| Frontend | React + Cytoscape.js | Network graph visualization |
| Database | PostgreSQL | Structured inventory, relational queries |
| Message Queue | Redis Streams | Lightweight, built-in persistence |
| Auth (Agents) | mTLS (x.509) | Strong mutual authentication |
| Auth (Users) | JWT + bcrypt | Standard web auth |
| Network scan | python-nmap | nmap bindings |
| Device access | Netmiko / NAPALM | Multi-vendor: Cisco, Juniper, Arista, MikroTik |
| CVE analysis | Grype + NVD API | Offline DB + real-time CVE lookup |

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
