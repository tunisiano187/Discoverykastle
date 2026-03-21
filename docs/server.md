# Server Design

## Overview

The central server is the core of the Discoverykastle platform. It receives data from agents, orchestrates discovery tasks, stores and indexes all findings, generates infrastructure documentation, and provides the operator dashboard.

The server is a **FastAPI** application (Python 3.12) running behind an Nginx reverse proxy.

---

## Components

```
┌──────────────────────────────────────────────────────────────────────┐
│                          Central Server                              │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │                      FastAPI Application                        │ │
│  │                                                                 │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │ │
│  │  │  REST API    │  │  WS Handler  │  │  Background Workers  │  │ │
│  │  │  /api/v1/*   │  │  Agent Comms │  │  Task dispatcher     │  │ │
│  │  └──────────────┘  └──────────────┘  │  CVE sync            │  │ │
│  │                                      │  Doc builder         │  │ │
│  │  ┌──────────────────────────────┐    │  Notification engine │  │ │
│  │  │  Certificate Authority (CA)  │    └──────────────────────┘  │ │
│  │  │  Agent cert issuance/revoke  │                              │ │
│  │  └──────────────────────────────┘                              │ │
│  │                                                                 │ │
│  │  ┌──────────────────────────────────────────────────────────┐  │ │
│  │  │                  Service Layer                           │  │ │
│  │  │  HostService │ NetworkService │ DeviceService            │  │ │
│  │  │  VulnService │ AgentService   │ DocService               │  │ │
│  │  └──────────────────────────────────────────────────────────┘  │ │
│  └─────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  ┌─────────────────────────┐    ┌──────────────────────────────────┐ │
│  │     PostgreSQL DB       │    │          Redis                   │ │
│  │  (primary data store)   │    │  Task queue + Agent WS registry  │ │
│  └─────────────────────────┘    └──────────────────────────────────┘ │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │              Credential Vault (encrypted at rest)               │ │
│  │  Device credentials, API keys, sensitive config                 │ │
│  └─────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

---

## API Reference

### Authentication

| Endpoint | Auth | Description |
|----------|------|-------------|
| `POST /api/v1/auth/login` | None | Operator login, returns JWT |
| `POST /api/v1/auth/refresh` | JWT | Refresh access token |
| `POST /api/v1/auth/logout` | JWT | Invalidate token |

### Agent Management

| Endpoint | Auth | Description |
|----------|------|-------------|
| `POST /api/v1/agents/register` | Enroll token | Agent registration, returns mTLS cert |
| `GET /api/v1/agents` | JWT | List all agents |
| `GET /api/v1/agents/{id}` | JWT | Agent details and status |
| `DELETE /api/v1/agents/{id}` | JWT | Revoke agent certificate and deregister |
| `GET /api/v1/agents/{id}/tasks` | JWT | List tasks for agent |
| `POST /api/v1/agents/{id}/tasks` | JWT | Dispatch a task to an agent |
| `POST /api/v1/agents/{id}/heartbeat` | mTLS | Agent heartbeat |

### Data Ingestion (Agent → Server)

| Endpoint | Auth | Description |
|----------|------|-------------|
| `POST /api/v1/data/hosts` | mTLS | Submit host discovery results |
| `POST /api/v1/data/services` | mTLS | Submit discovered services |
| `POST /api/v1/data/packages` | mTLS | Submit installed package list |
| `POST /api/v1/data/vulnerabilities` | mTLS | Submit CVE findings |
| `POST /api/v1/data/interfaces` | mTLS | Submit network interface data |
| `POST /api/v1/data/scan-results` | mTLS | Submit nmap scan results |
| `POST /api/v1/data/device-configs` | mTLS | Submit network device configurations |
| `POST /api/v1/data/topology-edges` | mTLS | Submit discovered topology links |

### Inventory (Server → Frontend)

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /api/v1/inventory/hosts` | JWT | All discovered hosts (filterable) |
| `GET /api/v1/inventory/hosts/{id}` | JWT | Host details (services, packages, vulns) |
| `GET /api/v1/inventory/networks` | JWT | All discovered networks |
| `GET /api/v1/inventory/devices` | JWT | Network devices (switches, routers) |
| `GET /api/v1/inventory/devices/{id}` | JWT | Device details and config snapshot |
| `GET /api/v1/inventory/topology` | JWT | Network topology graph (nodes + edges) |

### Vulnerabilities

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /api/v1/vulns` | JWT | All vulnerabilities (filterable by severity, host) |
| `GET /api/v1/vulns/{cve_id}` | JWT | CVE details across all affected hosts |
| `GET /api/v1/vulns/summary` | JWT | Severity distribution, top CVEs |

### Authorization Requests

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /api/v1/auth-requests` | JWT | List pending authorization requests |
| `POST /api/v1/auth-requests/{id}/approve` | JWT | Approve an agent action request |
| `POST /api/v1/auth-requests/{id}/deny` | JWT | Deny an agent action request |

### Documentation

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /api/v1/docs/generate` | JWT | Trigger documentation rebuild |
| `GET /api/v1/docs/network/{id}` | JWT | Generated doc for a network segment |
| `GET /api/v1/docs/device/{id}` | JWT | Generated doc for a network device |
| `GET /api/v1/docs/export` | JWT | Export full infrastructure doc (Markdown/PDF) |

### WebSocket

| Endpoint | Auth | Description |
|----------|------|-------------|
| `WS /api/v1/ws/agent/{id}` | mTLS | Persistent agent connection |
| `WS /api/v1/ws/dashboard` | JWT | Real-time dashboard updates |

---

## Task Engine

The task engine is responsible for:
1. Deciding which tasks to issue to which agents
2. Tracking task status (pending, running, completed, failed, timed out)
3. Enforcing authorization requirements before dispatching sensitive tasks
4. Retrying failed tasks with backoff

### Task Types and Authorization Requirements

| Task | Auto-dispatch | Requires operator approval |
|------|--------------|---------------------------|
| `scan_host` | Yes (within scope) | No |
| `collect_cves` | Yes | No |
| `enumerate_interfaces` | Yes | No |
| `scan_network` | Yes (authorized CIDRs only) | No |
| `probe_device` | Yes (authorized CIDRs) | No |
| `scan_network` (new subnet) | No | **Yes** |
| `probe_device` (new network) | No | **Yes** |
| `deploy_agent` | No | **Yes** |

### Task State Machine

```
[Created] → [Queued] → [Dispatched] → [Running] → [Completed]
                                           │
                                           ├─► [Failed]
                                           └─► [Timed Out]
```

Tasks that fail or time out are retried up to 3 times with exponential backoff (1min, 5min, 15min). After 3 failures, the task is marked as permanently failed and the operator is notified.

---

## Certificate Authority

The server includes an embedded CA for agent certificate management.

- The CA root certificate is generated at first startup and stored in the credential vault
- Each agent receives a unique leaf certificate at registration, signed by this CA
- Certificates include the agent's unique ID in the Subject field
- Certificates expire after 90 days and are automatically renewed by the agent before expiry
- Revoked certificates are added to a CRL (Certificate Revocation List) that all server components check

The CA private key never leaves the server. If the server is compromised, all agent certificates should be revoked and new ones issued.

---

## Credential Vault

Device credentials (SSH usernames/passwords, API keys) are stored encrypted at rest using AES-256-GCM. The encryption key is derived from a master secret configured at startup (via `DKASTLE_VAULT_KEY` environment variable or a key file).

Credentials are never:
- Logged
- Sent to agents in plain form in API responses
- Stored on agent containers

When an agent needs device credentials for a task, the server creates an **ephemeral task credential** — a short-lived, single-use, task-scoped credential delivered only over the encrypted WebSocket connection.

---

## Documentation Builder

The documentation builder is a background service that runs after each significant data update. It generates Markdown documentation files for:

- **Network segments** — CIDR, discovered hosts, device topology, inter-segment links
- **Individual hosts** — OS, services, packages, open ports, vulnerabilities
- **Network devices** — vendor, model, firmware, interface table, VLAN config, routing table, neighbors
- **Overall infrastructure** — executive summary, asset count, critical vulnerabilities

Documentation is stored in the database as Markdown and exported via the API. Operators can download the full documentation as a ZIP archive or as a single Markdown file.

Documentation automatically includes a **last updated** timestamp and the agent/source that provided each piece of information.

---

## Web Dashboard

The React frontend provides:

### Topology View
- Interactive network graph (Cytoscape.js)
- Nodes: hosts (color-coded by OS family), network devices (icon by vendor), agents
- Edges: physical/logical links derived from CDP/LLDP, ARP, and routing data
- Click any node to open a detail panel

### Host Inventory
- Searchable, filterable table of all discovered hosts
- Columns: IP, hostname, OS, services count, vuln count (by severity), last seen
- Click to drill into full host detail

### Vulnerability Dashboard
- CVE list with CVSS filter, severity distribution chart
- Affected hosts per CVE
- Patch status timeline

### Agent Dashboard
- All registered agents, status, last heartbeat, current task
- Task queue management
- Agent enrollment token generator

### Authorization Queue
- Pending authorization requests from agents
- Shows: requesting agent, requested action, target, justification
- Approve / Deny buttons

### Settings
- Authorized CIDR management
- Scan profiles
- Credential vault (add/update/delete device credentials)
- Notification configuration (email, Slack webhook)

---

## Database Schema

See also: [Architecture — Database Schema](architecture.md#database-schema-high-level)

Key indexes for performance:
- `hosts.ip_addresses` — GIN index for array search
- `vulnerabilities.cve_id` — for CVE lookups
- `vulnerabilities.severity` — for severity filtering
- `audit_log.timestamp` — for time-range queries
- `network_devices.ip_address` — for device lookups

All tables include `created_at` and `updated_at` timestamps managed by the ORM.

---

## Notifications

The server can send notifications when:

- A critical CVE (CVSS ≥ 9.0) is found
- An agent goes offline unexpectedly
- An authorization request is created
- A scan completes or fails

Supported notification channels:
- Email (SMTP)
- Slack (incoming webhook)
- Webhook (generic HTTP POST with JSON payload)

Notification channels are configured in server settings and are not required for basic operation.
