# Agent Design

## Overview

An agent is a Python process running inside a Docker container deployed on a target host or network entry point. Agents are stateless, server-directed executors: they do nothing without explicit instruction from the central server and report all findings back.

Each agent is identified by a unique x.509 certificate issued by the server's Certificate Authority at registration time. All communication with the server is over mTLS (mutual TLS).

---

## Capabilities

Agents can perform the following actions, always within the scope authorized by the server:

| Capability | Description |
|-----------|-------------|
| **Host enumeration** | OS detection, installed packages, running services, listening ports, scheduled tasks, users |
| **CVE analysis** | Match installed packages against known CVE databases (Grype + NVD API) |
| **Patch assessment** | Identify missing OS patches and available updates |
| **Windows CIS hardening** | CIS Benchmark checks via Python + PowerShell (account policy, registry, firewall, audit policy, services) |
| **Wazuh integration** | Read and normalize Wazuh SCA + vulnerability results if Wazuh agent is installed |
| **Active Directory audit** | LDAP-based AD security checks: Kerberoasting, AS-REP, delegation, DCSync risk, password policy, privileged groups |
| **Linux hardening (Lynis)** | Run Lynis if installed; parse hardening index, warnings, compliance results |
| **Linux hardening (Python)** | CIS checks: SSH config, sysctl, filesystem mounts, users, sudo, AppArmor/SELinux, firewall, cron, auditd |
| **Interface enumeration** | List all network interfaces, IPs, MACs, link state, VLAN membership |
| **Network scanning** | Full nmap scan of authorized CIDRs (TCP/UDP, service/version detection, OS fingerprinting) |
| **Device probing** | SSH/API connection to network devices; extract hostname, firmware version, running config, ARP table, MAC table, routing table, VLAN config |
| **Agent deployment** | Install and start an agent on a newly discovered host (requires server + operator authorization) |

---

## Hard Limits (What Agents Cannot Do)

- **Cannot initiate any action without a server task** — agents are pure executors
- **Cannot scan outside authorized CIDR ranges** — enforced client-side and server-side
- **Cannot store device credentials** — credentials are received as ephemeral, task-scoped tokens
- **Cannot exceed configured recursive depth** — depth limit enforced by server
- **Cannot run arbitrary shell commands** — the agent exposes a fixed set of task handlers only
- **Cannot modify the host system** (except for agent self-deployment when authorized)
- **Cannot communicate with external services** other than the server endpoint

---

## Agent Lifecycle

```
  ┌─────────────────────────────────────────────────────────────────┐
  │                         AGENT LIFECYCLE                         │
  └─────────────────────────────────────────────────────────────────┘

  [Container Start]
       │
       ▼
  ┌─────────────┐
  │  Bootstrap  │  Load config (server URL, initial token)
  └──────┬──────┘
         │
         ▼
  ┌─────────────────┐
  │  Registration   │  POST /api/v1/agents/register
  │                 │  Receive mTLS certificate from server CA
  └──────┬──────────┘
         │
         ▼
  ┌─────────────────┐
  │  Connect WS     │  Open persistent WebSocket to server (mTLS)
  └──────┬──────────┘
         │
         ▼
  ┌─────────────────────────────────────────────────────────┐
  │                    MAIN LOOP                            │
  │                                                         │
  │  ┌─────────────────┐      ┌─────────────────────────┐  │
  │  │  Heartbeat      │      │  Receive Task from WS   │  │
  │  │  (every 30s)    │      │                         │  │
  │  └─────────────────┘      └────────────┬────────────┘  │
  │                                        │               │
  │                           ┌────────────▼────────────┐  │
  │                           │  Validate Task          │  │
  │                           │  - Action in allowlist? │  │
  │                           │  - Target in scope?     │  │
  │                           └────────────┬────────────┘  │
  │                                        │               │
  │                           ┌────────────▼────────────┐  │
  │                           │  Execute Task Module    │  │
  │                           └────────────┬────────────┘  │
  │                                        │               │
  │                           ┌────────────▼────────────┐  │
  │                           │  Report Results         │  │
  │                           │  POST /api/v1/data/*    │  │
  │                           └─────────────────────────┘  │
  └─────────────────────────────────────────────────────────┘
         │
  [Disconnect / Container Stop]
```

---

## Task Modules

### `host` — Host Enumeration

Collects:
- OS name, version, kernel version
- Installed packages (dpkg, rpm, apk, brew, pip, npm global)
- Running services (systemd units, init.d, Docker containers, Windows services)
- Listening ports (ss / netstat)
- Logged-in users, local user accounts
- Scheduled tasks (cron, systemd timers, Task Scheduler)
- Hardware info (CPU, RAM, disk, architecture)

Tools used: `psutil`, direct `/proc` and system file reads, `subprocess` calls to package managers.

### `security` — Security Assessment

The security module is OS-aware and automatically selects the appropriate scanner. See [Security Modules](security-modules.md) for full details.

#### OS Routing

```
Windows → Wazuh integration (if installed) + Native CIS checks (PowerShell + Python)
          + Active Directory audit (if domain-joined, via LDAP — ldap3, MIT license)

Linux   → Lynis (if installed, GPL v3 — called externally, not bundled)
          + Python CIS checks (always, fills gaps or full fallback if no Lynis)
```

#### Windows Checks

- **Wazuh integration**: if the Wazuh agent is already installed on the host, its last SCA and vulnerability scan results are read and normalized (no re-scan triggered)
- **Native CIS checks** (when Wazuh is absent or to complement it): account policies, password settings, firewall profiles, audit policies, registry security settings (WDigest, LSA protection, SMBv1, NTLMv2), service audit, shared folders, Windows Update status, Event Log analysis (failed logins, new services, log clearing)
- Tools: Python `winreg`, `pywin32` (PSF license), PowerShell subprocesses

#### Active Directory Checks (Windows, if domain-joined)

Uses `ldap3` (MIT license) — native LDAP queries, no external tools, no bundled binaries:

- Domain info, domain controllers, FSMO roles
- Password policy (default + Fine-Grained Password Policies)
- Privileged group membership (Domain Admins, Enterprise Admins, Schema Admins, etc.)
- **Kerberoastable accounts** (SPN set, RC4 encryption)
- **AS-REP roastable accounts** (pre-auth not required)
- **Delegation issues** (unconstrained, constrained with protocol transition, RBCD)
- **DCSync risk** (accounts with replication rights outside standard principals)
- AdminSDHolder anomalies
- GPO enumeration and permission review
- LAPS deployment coverage

#### Linux Checks

- **Lynis** (if present): full audit, parse hardening index, warnings, suggestions, compliance results
- **Python fallback** (always runs, full if no Lynis): filesystem mount options, sysctl network/kernel parameters, SSH config audit (20+ checks), user accounts and sudo, AppArmor/SELinux status, firewall rules, cron permissions, audit logging, kernel hardening (GRUB password, ASLR, module blacklisting)

#### CVE / Patch Analysis (all OS)

- CVE matches for all installed packages via Grype (offline DB) and NVD API for recent CVEs
- Available updates from package manager
- CVSS scores and severity classifications
- Remediation suggestions

Reports: structured finding list and vulnerability list. See [Security Modules — Output Format](security-modules.md#output-format).

### `network` — Interface Enumeration

Collects:
- All network interfaces (name, IP/mask, IPv6, MAC, state, speed, type)
- Routing table
- ARP cache
- DNS configuration
- Active connections

Uses: `psutil.net_if_addrs()`, `psutil.net_if_stats()`, `ip route`, `/etc/resolv.conf`.

After enumeration, reports interfaces and derived subnets to the server. The server decides which subnets are in scope for scanning and issues `scan_network` tasks accordingly.

### `scanner` — nmap Network Scan

Runs nmap against authorized CIDRs only. Scan profile is server-specified:

| Profile | nmap flags | Use case |
|---------|-----------|---------|
| `quick` | `-sV -T4 --top-ports 1000` | Fast initial sweep |
| `full` | `-sV -sU -p- -T3 -O --script=banner` | Comprehensive |
| `stealth` | `-sS -T2 --top-ports 100` | Low-noise |
| `service` | `-sV --version-intensity 9 -p <ports>` | Deep service detection |

Requires Docker capabilities: `NET_ADMIN`, `NET_RAW`.

Outputs: list of discovered hosts with open ports, services, versions, OS guesses.

### `devices` — Network Device Probing

Connects to discovered network devices via SSH (or HTTP API for modern devices). Uses **Netmiko** for multi-vendor SSH and **NAPALM** for structured config extraction.

**Supported vendors** (via Netmiko):
- Cisco IOS, IOS-XE, IOS-XR, NX-OS, ASA
- Juniper JunOS
- Arista EOS
- MikroTik RouterOS
- HP / HPE ProCurve, Comware
- Fortinet FortiOS
- Palo Alto PAN-OS
- Generic Linux (SSH)

**Data collected per device**:
- Hostname, vendor, model, serial number
- Firmware / software version
- Running configuration (sanitized: passwords replaced with `[REDACTED]`)
- Interface table with descriptions
- VLAN table (switches)
- ARP table / MAC address table
- Routing table (routers)
- CDP/LLDP neighbor table (for topology mapping)
- STP state (switches)

Credentials are received from the server as ephemeral task parameters and are never persisted to disk.

### `deployer` — Agent Self-Deployment

When an operator authorizes agent deployment on a new host, the agent:

1. Receives deployment task with target host IP and SSH credentials (ephemeral)
2. Connects to target via SSH
3. Verifies prerequisites (Docker available, or installs it if authorized)
4. Pulls the agent Docker image and starts the container with the correct server configuration
5. Reports deployment status to server
6. New agent registers independently with the server

The deployer module is disabled by default in the agent container configuration and must be explicitly enabled by the server.

---

## Docker Security Configuration

Agents run in Docker containers with the following security profile:

### Required Capabilities (and why)

| Capability | Required for | Mitigation |
|-----------|-------------|------------|
| `NET_ADMIN` | nmap raw socket scanning, interface enumeration | Drop after network tasks complete |
| `NET_RAW` | nmap SYN scan, ICMP | Drop after network tasks complete |

All other capabilities are dropped (`--cap-drop ALL` + explicit add).

### Additional Restrictions

```yaml
# docker-compose.yml (agent service)
security_opt:
  - no-new-privileges:true
  - seccomp:agent-seccomp.json    # custom seccomp profile
read_only: true                   # read-only root filesystem
tmpfs:
  - /tmp:size=64m,noexec          # writable tmp, no execution
  - /var/tmp:size=32m,noexec
user: "1000:1000"                 # non-root user
```

### Network Isolation

The agent container's network access is restricted to:
1. The central server endpoint (HTTPS/WSS)
2. Target networks (as needed for scanning tasks)

It has no access to the Docker socket, no access to the host's `/proc` (bind-mounted read-only where needed), and no outbound internet access except through the server.

---

## Configuration

Agents are configured entirely via environment variables passed at container startup:

| Variable | Required | Description |
|----------|----------|-------------|
| `DKASTLE_SERVER_URL` | Yes | WebSocket URL of the central server |
| `DKASTLE_ENROLL_TOKEN` | Yes | One-time enrollment token (issued by server) |
| `DKASTLE_AGENT_ID` | No | Pre-assigned agent ID (optional, set by server) |
| `DKASTLE_LOG_LEVEL` | No | Log level: `DEBUG`, `INFO`, `WARNING` (default: `INFO`) |
| `DKASTLE_HEARTBEAT_INTERVAL` | No | Heartbeat interval in seconds (default: `30`) |

After registration, the agent receives its mTLS certificate from the server and stores it in an in-memory keystore (not on disk).

---

## Multi-Vendor Device Support Matrix

| Vendor | SSH | Structured Config (NAPALM) | CLI Parsing (Netmiko) |
|--------|-----|---------------------------|----------------------|
| Cisco IOS/IOS-XE | ✅ | ✅ | ✅ |
| Cisco NX-OS | ✅ | ✅ | ✅ |
| Cisco IOS-XR | ✅ | ✅ | ✅ |
| Cisco ASA | ✅ | ❌ | ✅ |
| Juniper JunOS | ✅ | ✅ | ✅ |
| Arista EOS | ✅ | ✅ | ✅ |
| MikroTik RouterOS | ✅ | ❌ | ✅ |
| HP ProCurve | ✅ | ❌ | ✅ |
| Fortinet FortiOS | ✅ | ❌ | ✅ |
| Palo Alto PAN-OS | ✅ (API) | ❌ | ✅ |
| Generic Linux | ✅ | ❌ | ✅ |

Unsupported devices are probed generically via SSH and their raw output is stored for manual review.
