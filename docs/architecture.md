# Architecture

## Overview

Discoverykastle is composed of two main runtime components — a **central server** and distributed **agents** — plus a web **frontend** for human operators. Components communicate over encrypted, mutually authenticated channels.

```
                         ┌──────────────────────────┐
                         │    Operator (Browser)    │
                         └────────────┬─────────────┘
                                      │ HTTPS / WSS
                         ┌────────────▼─────────────┐
                         │     Central Server       │
                         │  ┌──────────────────────┐│
                         │  │   FastAPI (REST/WS)  ││
                         │  │   Task Engine        ││
                         │  │   Doc Builder        ││
                         │  │   Auth / CA          ││
                         │  └──────────────────────┘│
                         │  ┌──────────────────────┐│
                         │  │    PostgreSQL DB      ││
                         │  └──────────────────────┘│
                         │  ┌──────────────────────┐│
                         │  │   Redis Streams      ││
                         │  └──────────────────────┘│
                         └────────────┬─────────────┘
                      mTLS WebSocket  │  mTLS WebSocket
              ┌───────────────────────┴────────────────────────┐
              │                                                │
 ┌────────────▼──────────────┐              ┌─────────────────▼──────────────┐
 │        Agent (Host A)     │              │         Agent (Host B)          │
 │ ┌───────────────────────┐ │              │  ┌───────────────────────────┐  │
 │ │  Host Discovery       │ │              │  │  Host Discovery           │  │
 │ │  CVE / Patch Analysis │ │              │  │  CVE / Patch Analysis     │  │
 │ │  Network Enumeration  │ │              │  │  Network Enumeration      │  │
 │ │  nmap Scanner         │ │              │  │  nmap Scanner             │  │
 │ │  Device Probe (SSH)   │ │              │  │  Device Probe (SSH)       │  │
 │ │  Agent Deployer       │ │              │  │  Agent Deployer           │  │
 │ └───────────────────────┘ │              │  └───────────────────────────┘  │
 └───────────────────────────┘              └────────────────────────────────┘
```

---

## Components

### Central Server

The server is the brain of the platform. It:

- Receives, stores, and indexes all data reported by agents
- Orchestrates agent tasks (what to scan, when, from which vantage point)
- Maintains a Certificate Authority (CA) for agent authentication
- Exposes a REST + WebSocket API consumed by the frontend and agents
- Generates infrastructure documentation from collected data
- Enforces authorization for all sensitive operations (agent deployment, destructive actions)
- Holds all secrets (network device credentials) in an encrypted vault — never sent to agents in plain form

### Agent

Agents are lightweight Python processes deployed as Docker containers. Each agent:

- Registers with the server using a certificate signed by the server's CA (mTLS)
- Receives tasks from the server via a persistent WebSocket connection
- Executes tasks within defined capability limits
- Reports results back to the server
- Never initiates discovery independently — all actions are server-directed

Agents are stateless: all state is stored on the server. An agent that is killed and restarted will reconnect and resume its task queue.

### Frontend (Dashboard)

A React single-page application served by the server. It provides:

- Real-time network topology visualization (Cytoscape.js graph)
- Host inventory, services, and vulnerability dashboards
- CVE feed with severity filtering
- Agent status and task queue management
- Authorization dialogs for sensitive operations (agent deployment, deep recursive scans)
- Auto-generated infrastructure documentation viewer

---

## Data Flow

### Discovery Sequence

```
Agent                          Server                         Operator
  │                               │                               │
  │──── Register (mTLS cert) ────►│                               │
  │◄─── Scope + Task Assignment ──│                               │
  │                               │                               │
  │ 1. Enumerate host             │                               │
  │──── Report host data ────────►│──── Update DB ────────────────│
  │                               │──── Notify dashboard ─────────│
  │                               │                               │
  │ 2. CVE / patch analysis       │                               │
  │──── Report vulnerabilities ──►│──── CVE indexing ─────────────│
  │                               │                               │
  │ 3. Network interface enum     │                               │
  │──── Report interfaces ───────►│                               │
  │                               │                               │
  │ 4. nmap scan (authorized      │                               │
  │    CIDRs only)                │                               │
  │──── Report scan results ─────►│──── Build topology ───────────│
  │                               │                               │
  │ 5. Network device found       │                               │
  │    (e.g., 192.168.1.1)        │                               │
  │──── Request credentials ─────►│                               │
  │◄─── Ephemeral credentials ────│                               │
  │ 5b. SSH → extract config      │                               │
  │──── Report device config ────►│──── Document device ──────────│
  │                               │                               │
  │ 6. New subnet discovered      │                               │
  │──── Request recursion ───────►│──────────── Authorization ────►│
  │                               │◄─────────── Approve/Deny ─────│
  │◄─── Task: scan new subnet ────│ (if approved)                 │
  │                               │                               │
  │ 7. New host found with SSH    │                               │
  │──── Request agent deploy ────►│──────────── Authorization ────►│
  │                               │◄─────────── Approve/Deny ─────│
  │◄─── Deploy agent (if approved)│                               │
```

---

## Technology Stack

### Agent

| Library | Purpose |
|---------|---------|
| `python-nmap` | nmap bindings for port/service scanning |
| `netmiko` | Multi-vendor SSH to network devices (Cisco, Juniper, Arista, MikroTik, HP, etc.) |
| `napalm` | Network device abstraction (structured config extraction) |
| `psutil` | Host resource and service enumeration |
| `grype` | CVE scanning for installed packages |
| `paramiko` | Low-level SSH for custom device interactions |
| `httpx` | Async HTTP client for REST API calls |
| `websockets` | Persistent WebSocket connection to server |

### Server

| Library / Tool | Purpose |
|----------------|---------|
| `FastAPI` | REST + WebSocket API framework |
| `SQLAlchemy` | ORM for PostgreSQL |
| `Alembic` | Database migrations |
| `Redis` | Task queue (Redis Streams), caching |
| `cryptography` | CA certificate management, mTLS |
| `python-jose` | JWT tokens for user auth |
| `passlib` | Password hashing |
| `Jinja2` | Documentation template rendering |

### Frontend

| Library | Purpose |
|---------|---------|
| `React 18` | UI framework |
| `Cytoscape.js` | Network topology graph visualization |
| `React Query` | Server state management |
| `Recharts` | Vulnerability and inventory charts |
| `shadcn/ui` | Component library |

### Infrastructure

| Tool | Purpose |
|------|---------|
| `PostgreSQL 16` | Primary datastore |
| `Redis 7` | Message queue and cache |
| `Docker` | Agent and server containerization |
| `Docker Compose` | Local orchestration |
| `Nginx` | Reverse proxy, TLS termination |

---

## Key Design Decisions

### 1. Agent Is Server-Directed (Not Autonomous)

Agents are deliberately dumb executors — they do nothing without server instruction. This avoids runaway discovery and ensures every action is logged, authorized, and auditable. The server is the single source of truth for what agents can and should do.

**Trade-off**: Requires a persistent connection. An agent that loses connectivity pauses all activity. This is intentional — it prevents agents from continuing to scan when they lose oversight.

### 2. mTLS for Agent Authentication

Every agent has a unique certificate issued by the server's internal CA. This provides:
- Strong mutual authentication (server knows exactly which agent it's talking to)
- Automatic revocation via CA (revoke a certificate if an agent is compromised)
- No shared secrets between agents

**Trade-off**: Certificate management overhead. Mitigated by automated issuance at agent startup.

### 3. Authorized CIDR Scopes Are Mandatory

No scan can target an IP address outside the operator-configured authorized CIDR list. The server enforces this server-side — agents cannot override it. This is a hard safety requirement, not a configurable option.

**Trade-off**: Requires upfront configuration from the operator. This is intentional.

### 4. Recursive Discovery Requires Explicit Human Approval

When an agent discovers a new subnet or a host it could pivot through, it must request authorization from the server. The server creates an authorization request visible in the dashboard. No recursive scan proceeds until an operator explicitly approves it.

**Trade-off**: Slows down fully automated discovery. The benefit (preventing uncontrolled lateral spread) outweighs the cost.

### 5. Ephemeral Credentials for Network Devices

The server holds credentials for network devices in an encrypted vault. When an agent needs to connect to a device, the server issues a one-time-use, scoped credential that expires after the task completes. The agent never permanently holds device credentials.

**Trade-off**: Higher round-trip complexity. Dramatically reduces the impact of agent compromise.

### 6. Recursive Depth Limit

Discovery is limited to a configurable maximum hop depth (default: 2). Operators can increase this per-session with explicit confirmation. This prevents infinite recursion and keeps the blast radius bounded.

---

## Database Schema (High-Level)

```
hosts
  id, fqdn, ip_addresses[], os, os_version, first_seen, last_seen, agent_id

services
  id, host_id, port, protocol, service_name, version, banner

packages
  id, host_id, name, version, package_manager

vulnerabilities
  id, host_id, package_id, cve_id, severity, cvss_score, description, remediation, first_seen

network_interfaces
  id, host_id, name, ip_address, netmask, mac_address, type, is_up

networks
  id, cidr, description, discovered_via_host_id, scan_authorized, scan_depth

scan_results
  id, network_id, agent_id, started_at, completed_at, hosts_found[]

network_devices
  id, host_id (nullable), ip_address, device_type, vendor, model,
  firmware_version, hostname, config_snapshot, last_seen

topology_edges
  id, source_host_id, target_host_id, edge_type, interface_id

agents
  id, certificate_fingerprint, hostname, ip_address, version,
  status, last_heartbeat, authorized_cidrs[]

audit_log
  id, agent_id, user_id (nullable), action, target, params, result, timestamp

authorization_requests
  id, agent_id, request_type, details, status, requested_at,
  resolved_at, resolved_by
```

---

## Communication Protocol

### Agent → Server (REST)

Used for: registration, health checks, one-off data submissions.

- `POST /api/v1/agents/register` — initial registration, returns mTLS certificate
- `POST /api/v1/agents/{id}/heartbeat` — liveness signal (every 30s)
- `POST /api/v1/data/hosts` — submit host discovery results
- `POST /api/v1/data/vulnerabilities` — submit CVE findings
- `POST /api/v1/data/scan-results` — submit nmap results
- `POST /api/v1/data/device-configs` — submit network device configs

### Server → Agent (WebSocket)

Used for: task dispatch, real-time commands, credential delivery.

```json
{
  "type": "task",
  "task_id": "uuid",
  "action": "scan_network",
  "params": {
    "cidr": "10.0.1.0/24",
    "scan_type": "full",
    "timeout_seconds": 600
  }
}
```

Task types: `scan_host`, `scan_network`, `probe_device`, `deploy_agent`, `collect_cves`, `enumerate_interfaces`
