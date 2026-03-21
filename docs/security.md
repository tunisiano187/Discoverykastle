# Security Model

## ⚠️ Legal and Ethical Requirements

**Discoverykastle is a professional security assessment tool. It must only be used on:**
- Networks and systems you own
- Networks and systems for which you have explicit, written authorization to scan and assess

Network scanning, unauthorized access to computer systems, and interception of network traffic are criminal offenses in most jurisdictions, including but not limited to:
- United States: Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030
- European Union: Directive on attacks against information systems (2013/40/EU)
- United Kingdom: Computer Misuse Act 1990
- Canada: Criminal Code Section 342.1
- France: Code pénal articles 323-1 à 323-7

**The authors and contributors of this project are not responsible for any misuse.**

Before deploying Discoverykastle, obtain written authorization that specifies:
- The exact IP ranges authorized for scanning
- The types of scans permitted (passive, active, intrusive)
- The time window(s) during which scanning is permitted
- Contact information for the system owner in case of incidents

---

## Threat Model

### Assets to Protect

| Asset | Sensitivity | If compromised |
|-------|------------|----------------|
| Network device credentials | Critical | Full network access |
| Server CA private key | Critical | All agent certificates compromised |
| Collected infrastructure data | High | Detailed attack map for adversaries |
| Agent certificates | High | Impersonation of agents |
| Operator JWT tokens | Medium | Dashboard access |
| Scan results / topology | Medium | Network blueprint for attackers |

### Threat Actors

| Actor | Capabilities | Mitigation |
|-------|-------------|-----------|
| Compromised agent container | Can send false data, limited network access | mTLS identity, server-side validation, sandboxing |
| MITM on agent-server channel | Intercept commands / data | mTLS, certificate pinning |
| Unauthorized dashboard user | Access collected data, dispatch tasks | JWT auth, RBAC |
| Malicious scan target | May respond with exploits (e.g., nmap NSE exploits) | Agent sandboxing, no shell execution of scan output |
| Physical access to server host | Access to DB, vault, CA key | Encrypted vault, OS-level disk encryption |
| Insider threat (operator) | Abuse of authorization, data exfiltration | Audit log, RBAC, least-privilege roles |

---

## Authentication

### Agent Authentication: mTLS

Every agent is authenticated using a unique x.509 client certificate signed by the server's Certificate Authority (CA).

**Certificate lifecycle:**
1. Operator generates an enrollment token (one-time use, expires in 24h) in the dashboard
2. Agent starts with the enrollment token and calls `POST /api/v1/agents/register`
3. Server validates the enrollment token, generates a unique leaf certificate, signs it with the CA
4. Agent stores the certificate in memory (not on disk) and uses it for all subsequent mTLS connections
5. Certificate expires after 90 days; agent automatically requests renewal 14 days before expiry
6. Revoking an agent in the dashboard adds its certificate serial number to the CRL immediately

**Certificate fields:**
```
Subject: CN=agent-{uuid}, O=Discoverykastle
SAN: (none — agents have no DNS name by design)
KeyUsage: Digital Signature, Key Encipherment
ExtKeyUsage: Client Authentication
Validity: 90 days
```

### User Authentication: JWT + RBAC

Operators authenticate with username and bcrypt-hashed password. A successful login returns:
- `access_token` (JWT, expires 15 minutes)
- `refresh_token` (opaque, expires 7 days, stored server-side, rotated on use)

**Roles:**

| Role | Permissions |
|------|------------|
| `viewer` | Read-only: inventory, topology, vulnerabilities, docs |
| `analyst` | Viewer + manual task dispatch (non-destructive) |
| `operator` | Analyst + approve/deny authorization requests, manage credentials |
| `admin` | Full access: user management, agent revocation, server config |

---

## Authorization

### Scan Scope Enforcement

The authorized CIDR list is configured by an `admin` or `operator` user in the dashboard settings. It is enforced in two places:

1. **Server-side**: The task engine refuses to create any task targeting an IP outside authorized CIDRs
2. **Agent-side**: The agent validates every task target against the scope it received at registration and refuses tasks that violate it

This double enforcement means that even if the server is compromised and sends out-of-scope tasks, a correctly implemented agent will refuse them.

**No scan can proceed without at least one authorized CIDR being configured.**

### Human-in-the-Loop Authorization

The following actions always require explicit operator approval via the dashboard before the agent executes them:

| Action | Why |
|--------|-----|
| Scan a newly discovered subnet | Ensures operator has authorization for that subnet |
| Connect to a newly discovered network device | Credentials may need to be added first |
| Deploy an agent on a new host | Lateral movement — high impact, must be deliberate |
| Increase scan depth beyond current max | Prevents runaway recursive discovery |
| Run intrusive scan profiles | May disrupt services |

Authorization requests expire after 24 hours if not acted upon.

### Recursive Depth Control

Each authorization request to recurse into a new network segment includes the current depth level. The server enforces a global maximum depth (configurable, default: 2 hops from the initial agent). Operators must explicitly increase the limit to allow deeper discovery.

---

## Agent Container Security

### Principle of Least Privilege

Agents run as a non-root user (UID 1000) inside the container. The container is configured with:

```yaml
security_opt:
  - no-new-privileges:true       # Prevent privilege escalation
  - seccomp:agent-seccomp.json   # Restrict syscalls
cap_drop:
  - ALL                          # Drop all capabilities
cap_add:
  - NET_ADMIN                    # Required for nmap and interface enumeration
  - NET_RAW                      # Required for nmap raw sockets
read_only: true                  # Immutable root filesystem
tmpfs:
  - /tmp:size=64m,noexec,nosuid
  - /var/tmp:size=32m,noexec,nosuid
```

### Seccomp Profile

A custom seccomp profile allowlists only the syscalls the agent legitimately needs. Syscalls for:
- Loading kernel modules
- Creating namespaces (except as needed by nmap)
- `ptrace`
- `mount` / `umount`
- `mknod`
- `chroot`

...are explicitly blocked.

### No Docker Socket Access

Agents never have access to the Docker socket. The agent deployer module uses SSH to install Docker on the remote host — it does not use the local Docker daemon for lateral deployment.

### Read-Only Filesystem

The agent container's root filesystem is read-only. The only writable locations are:
- `/tmp` — temporary files (no execute, no setuid, 64MB limit)
- `/var/tmp` — same restrictions

No agent data, certificates, or configuration is written to disk. Everything is in-memory.

---

## Secrets Management

### Device Credentials

Network device credentials are stored in the server's encrypted credential vault:
- Encrypted with AES-256-GCM
- Master key sourced from environment variable `DKASTLE_VAULT_KEY` or external KMS
- Credentials are keyed by device IP / hostname and credential type (SSH, SNMP, HTTP API)

When an agent needs credentials for a device task:
1. Server retrieves credentials from vault
2. Server generates an ephemeral task credential: encrypted, task-scoped, single-use, expires when task completes or after 1 hour (whichever is sooner)
3. Ephemeral credential is sent to the agent only over the mTLS WebSocket
4. Agent uses the credential, then discards it from memory
5. The ephemeral credential is invalidated server-side after use

**Credentials are never:**
- Logged in plain form (log entries show `[REDACTED]`)
- Stored on agent containers
- Returned via the REST API to frontend clients

### Server CA Private Key

The CA private key is stored in the credential vault with the same encryption as device credentials. It is loaded into memory only when signing a new certificate and is not persistently accessible.

In production, consider using an external HSM or cloud KMS (AWS KMS, GCP Cloud KMS, HashiCorp Vault) for the CA private key.

---

## Communication Security

### TLS Configuration

All HTTP and WebSocket communication uses TLS 1.3 (minimum TLS 1.2). Cipher suites are restricted to:
- `TLS_AES_256_GCM_SHA384`
- `TLS_CHACHA20_POLY1305_SHA256`
- `TLS_AES_128_GCM_SHA256`

Weak ciphers (RC4, 3DES, MD5) are disabled.

### Certificate Pinning (Agent)

Agents pin the server's CA certificate at registration time. Subsequent connections verify not just the certificate chain, but that the certificate was signed by the exact CA that issued the agent's certificate. This prevents MITM attacks using a different trusted CA.

### Network Device Connections

When agents connect to network devices via SSH:
- Host key verification is enabled (known host keys are stored server-side and provided to the agent at task time)
- Telnet is never used (only SSH and HTTPS APIs)
- Session transcripts are sent to the server and stored in the audit log

---

## Audit Logging

Every significant action is logged to the `audit_log` table:

```json
{
  "id": "uuid",
  "timestamp": "ISO-8601",
  "actor_type": "agent | user",
  "actor_id": "agent-uuid or user-id",
  "action": "scan_network | probe_device | approve_request | ...",
  "target": "192.168.1.0/24",
  "params": { "scan_profile": "full" },
  "result": "success | failure | pending",
  "detail": "optional human-readable description"
}
```

Audit logs are:
- Append-only (no update or delete via API)
- Exportable by admins
- Retained for a configurable period (default: 1 year)

Sensitive parameters (passwords, tokens) are never written to the audit log.

---

## Data Classification

| Data type | Classification | Access |
|-----------|---------------|--------|
| Network device credentials | Secret | Vault only, no API exposure |
| CA private key | Secret | Vault only, in-memory during use |
| Device running configurations | Confidential | `analyst` role and above |
| Vulnerability / CVE data | Confidential | `viewer` role and above |
| Network topology | Confidential | `viewer` role and above |
| Audit logs | Restricted | `admin` role only |
| Agent enrollment tokens | Secret | Single use, 24h expiry |

---

## Security Hardening Checklist (Production)

- [ ] Change all default passwords before first use
- [ ] Use an external TLS certificate (Let's Encrypt or corporate CA) for the server
- [ ] Store `DKASTLE_VAULT_KEY` in a secrets manager (not in `.env` file)
- [ ] Enable disk encryption on the server host
- [ ] Restrict server port exposure: only 443 (HTTPS/WSS) should be internet-facing
- [ ] Enable database connection encryption (PostgreSQL `ssl=require`)
- [ ] Configure log rotation and centralized log shipping
- [ ] Set up alerting on failed authentication attempts (threshold: 5 in 5 minutes)
- [ ] Review and limit authorized CIDR list before first scan
- [ ] Test agent certificate revocation before production deployment
- [ ] Review the seccomp profile for your specific nmap version
- [ ] Run periodic backup of the PostgreSQL database and vault
