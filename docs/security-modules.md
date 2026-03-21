# Security Modules

This document details the OS-specific security scanning modules of the Discoverykastle agent.

---

## License Summary

All libraries used in this module are compatible with the project's MIT license and open source public distribution:

| Library | License | Usage |
|---------|---------|-------|
| `ldap3` | MIT | Active Directory LDAP queries |
| `pywin32` / `win32api` | PSF (BSD-like) | Windows registry, WMI, services |
| `psutil` | BSD-3-Clause | Cross-platform host info |
| Lynis | GPL v3 | Called as **external binary only** — not bundled, not modified |
| Wazuh Agent | GPL v2 | **Detected only** — agent queries its local data if present |
| PowerShell scripts | MIT (our code) | Called as subprocess from Python |

**Lynis and Wazuh are never bundled.** The agent detects whether they are already installed and integrates with them. If absent, the agent uses its own Python/PowerShell implementation. This means GPL v3/v2 copyleft does **not** propagate to this project.

---

## OS Detection and Module Routing

At startup, the `security` module detects the host OS and routes to the appropriate scanner:

```
detect_os()
    ├── Windows
    │   ├── check_wazuh_presence()
    │   │   ├── Wazuh found → WazuhWindowsScanner
    │   │   └── Not found   → NativeWindowsScanner
    │   └── check_domain_membership()
    │       └── In domain → ActiveDirectoryScanner (always, regardless of Wazuh)
    └── Linux / macOS
        ├── check_lynis_presence()
        │   ├── Lynis found → LynisScanner + PythonFallbackScanner (fill gaps)
        │   └── Not found   → PythonLinuxScanner (full)
        └── (domain checks not applicable on Linux by default)
```

---

## Windows: Wazuh Integration

### Detection

The agent checks for a Wazuh installation in the following locations:

```
C:\Program Files (x86)\ossec-agent\
C:\Program Files\ossec-agent\
Service: WazuhSvc
Process: wazuh-agent.exe
```

### Integration Strategy

If Wazuh agent is present, the agent:

1. **Reads the last SCA (Security Configuration Assessment) scan results** from:
   - `C:\Program Files (x86)\ossec-agent\queue\db\sca\` (SQLite DB or JSON exports)
   - Wazuh local API on `127.0.0.1:55000` (if accessible)

2. **Reads the last vulnerability scan results** from:
   - `C:\Program Files (x86)\ossec-agent\queue\vulnerabilities\`

3. **Parses and normalizes** results into the Discoverykastle vulnerability/finding format

4. **Does NOT re-run** Wazuh scans — it reads existing results only. Triggering a new Wazuh scan (if needed) is a separate task the server can dispatch.

### Data Extracted from Wazuh

| Category | Data |
|----------|------|
| SCA results | Policy name, check ID, status (pass/fail/not applicable), description, remediation |
| Vulnerabilities | CVE ID, package, version, severity |
| Agent info | Wazuh version, last scan time, OS info |
| Compliance | CIS, PCI DSS, HIPAA check results (if configured in Wazuh) |

---

## Windows: Native Security Scanner (No Wazuh)

Used when Wazuh is not present. Implements CIS Benchmark checks for Windows using Python + PowerShell.

### Architecture

Python orchestrates the scan. PowerShell scripts are used where WMI, Group Policy, or Event Log access is required. Registry reads use Python's built-in `winreg` module. Win32 API calls use `pywin32`.

### Check Categories

#### 1. Account Policies

| Check | Method | CIS Ref |
|-------|--------|---------|
| Minimum password length (≥ 14 chars) | `winreg` → `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters` | CIS 1.1.1 |
| Password complexity enabled | `secedit /export` + parse | CIS 1.1.5 |
| Maximum password age (≤ 365 days) | `secedit` | CIS 1.1.2 |
| Account lockout threshold (≤ 10 attempts) | `secedit` | CIS 1.2.1 |
| Account lockout duration (≥ 15 min) | `secedit` | CIS 1.2.2 |

#### 2. Windows Update / Patch Status

| Check | Method |
|-------|--------|
| Pending updates | PowerShell: `Get-WindowsUpdate` (WSUS API) or WMI `Win32_QuickFixEngineering` |
| Last update date | WMI |
| Automatic updates enabled | `winreg` HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update |
| Windows Defender definitions up to date | PowerShell: `Get-MpComputerStatus` |

#### 3. Windows Firewall

| Check | Method |
|-------|--------|
| Domain profile enabled | PowerShell: `Get-NetFirewallProfile -Profile Domain` |
| Private profile enabled | PowerShell |
| Public profile enabled | PowerShell |
| Default inbound action = Block | PowerShell |

#### 4. Audit Policies

| Check | Method |
|-------|--------|
| Account logon events audited | `auditpol /get /category:*` |
| Account management audited | `auditpol` |
| Logon/Logoff events audited | `auditpol` |
| Object access audited | `auditpol` |
| Policy change audited | `auditpol` |
| Privilege use audited | `auditpol` |
| System events audited | `auditpol` |

#### 5. Security Options (Registry)

| Check | Registry Path |
|-------|--------------|
| LAN Manager authentication level (NTLMv2 only) | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel` |
| SMBv1 disabled | `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1` |
| RDP encryption level | `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\MinEncryptionLevel` |
| NTP synchronization | `HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters` |
| AutoRun disabled | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun` |
| WDigest disabled (prevents cleartext creds) | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential` |
| LSA protection enabled | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` |
| Credential Guard | `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard` |

#### 6. Services Audit

| Check | Method |
|-------|--------|
| Telnet client/server disabled | PowerShell: `Get-Service` |
| SNMP v1/v2 (legacy) status | `Get-Service SNMP` |
| Remote Registry disabled | `Get-Service RemoteRegistry` |
| Print Spooler on non-print servers | `Get-Service Spooler` |
| Unnecessary scheduled tasks | PowerShell: `Get-ScheduledTask` |

#### 7. Shared Folders

| Check | Method |
|-------|--------|
| No default admin shares exposed | PowerShell: `Get-SmbShare` |
| Share permissions review | `Get-SmbShareAccess` |

#### 8. User Accounts

| Check | Method |
|-------|--------|
| Local Administrator account disabled or renamed | PowerShell: `Get-LocalUser` |
| Guest account disabled | `Get-LocalUser -Name Guest` |
| Local accounts with blank passwords | WMI `Win32_UserAccount.PasswordRequired` |
| Local admin group membership | PowerShell: `Get-LocalGroupMember -Group Administrators` |

#### 9. Event Log Analysis

The agent reads the last 24h of Windows Event Log for security-relevant events:

| Event ID | Category | Relevance |
|----------|----------|-----------|
| 4625 | Account Logon | Failed login attempts |
| 4648 | Account Logon | Explicit credential use (lateral movement indicator) |
| 4720 | Account Management | User account created |
| 4728 / 4732 | Account Management | User added to privileged group |
| 4776 | Account Logon | NTLM authentication |
| 7045 | System | New service installed |
| 4698 | Task Scheduler | Scheduled task created |
| 1102 | Security | Audit log cleared (tampering) |

Method: PowerShell `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=...}`

---

## Windows: Active Directory Scanner

Activated when the host is detected as domain-joined (check: `(Get-WmiObject Win32_ComputerSystem).PartOfDomain`).

**Library**: `ldap3` (MIT license) — native LDAP queries to Active Directory domain controllers.

### Authentication

The agent uses the **current machine account** (Kerberos / NTLM) to authenticate to LDAP. No credentials need to be provided — a domain-joined machine can query AD as itself with read-only permissions.

For elevated checks (DCSync risk, ACL analysis), the server can optionally provide domain read-only credentials via ephemeral task parameters.

### Checks Performed

#### Domain Information

| Data | LDAP Query |
|------|-----------|
| Domain name, NetBIOS name | `defaultNamingContext` |
| Forest name | `rootDSE.rootDomainNamingContext` |
| Domain functional level | `msDS-Behavior-Version` |
| Domain controllers list | `(objectCategory=nTDSDSA)` → parent objects |
| FSMO role holders | `fSMORoleOwner` on naming contexts |

#### Password Policies

| Check | Source | Risk if failing |
|-------|--------|----------------|
| Domain default password policy | `objectClass=domainDNS` attributes | Weak passwords |
| Fine-Grained Password Policies (FGPPs) | `msDS-PasswordSettings` containers | Hidden weak policies for specific accounts |
| Minimum length (recommended: ≥ 12) | `minPwdLength` | Brute force |
| Complexity required | `pwdProperties` flag | Dictionary attacks |
| Lockout threshold | `lockoutThreshold` | Password spraying possible if 0 |
| Max password age | `maxPwdAge` | Stale credentials |

#### Privileged Accounts and Groups

| Group | LDAP Filter | Risk |
|-------|------------|------|
| Domain Admins | `memberOf=CN=Domain Admins,...` | Full domain control |
| Enterprise Admins | `memberOf=CN=Enterprise Admins,...` | Full forest control |
| Schema Admins | `memberOf=CN=Schema Admins,...` | Schema modification |
| Administrators | Built-in Administrators | Local admin on DCs |
| Account Operators | `memberOf=CN=Account Operators,...` | Can modify accounts |
| Backup Operators | `memberOf=CN=Backup Operators,...` | Can bypass ACLs |

For each privileged account:
- Last logon date (`lastLogonTimestamp`)
- Password last set (`pwdLastSet`)
- Account enabled/disabled
- `adminCount=1` (protected by AdminSDHolder)

#### Kerberoastable Accounts

Accounts with a Service Principal Name (SPN) that are not computer accounts — an attacker can request a Kerberos service ticket and crack it offline.

```
LDAP filter: (&(servicePrincipalName=*)(objectClass=user)(!(objectClass=computer))(!(cn=krbtgt)))
```

For each found account: username, SPN list, password last set, encryption types supported.

**High risk**: accounts with RC4 encryption (`msDS-SupportedEncryptionTypes` not set or contains RC4).

#### AS-REP Roastable Accounts

Accounts that do not require Kerberos pre-authentication — an attacker can request an AS-REP and crack the hash offline without a valid password.

```
LDAP filter: (&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(objectClass=user))
```

#### Delegation Issues

| Type | Risk | LDAP Filter |
|------|------|------------|
| Unconstrained delegation | Any service can impersonate any user to any service — full compromise vector | `userAccountControl` flag `TRUSTED_FOR_DELEGATION` |
| Constrained delegation with protocol transition | Can impersonate any user to specific services | `msDS-AllowedToDelegateTo` + `TRUSTED_TO_AUTH_FOR_DELEGATION` |
| Resource-based constrained delegation (RBCD) | Can be abused for privilege escalation | `msDS-AllowedToActOnBehalfOfOtherIdentity` |

Unconstrained delegation on non-DC hosts is always flagged as **Critical**.

#### DCSync Risk (Replication Rights)

Users/groups with `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` rights on the domain object can perform a DCSync attack (dump all hashes without being DA).

Method: Read the `nTSecurityDescriptor` ACL on the domain root object and find ACEs granting replication rights to non-standard principals (i.e., not `SYSTEM`, `Domain Admins`, `Enterprise Admins`, `Domain Controllers`).

#### AdminSDHolder

The `adminCount=1` attribute marks accounts historically managed by AdminSDHolder. Accounts with `adminCount=1` that are no longer in privileged groups should be reviewed — they retain elevated ACLs.

```
LDAP filter: (&(adminCount=1)(objectClass=user)(!(memberOf=CN=Domain Admins,...)))
```

#### Group Policy Objects (GPOs)

| Check | Method |
|-------|--------|
| List all GPOs | `(objectClass=groupPolicyContainer)` |
| GPOs with no links (orphaned) | Check `gpLink` on OU objects |
| GPOs with edit rights for non-admins | Read `nTSecurityDescriptor` on GPO objects |

#### LAPS Deployment

Check whether Local Administrator Password Solution (LAPS) is deployed:
- Schema extension: presence of `ms-Mcs-AdmPwd` attribute in schema
- Coverage: count computer objects with `ms-Mcs-AdmPwd` populated vs. total

If LAPS is not deployed, all domain computers likely share the same local admin password — a **Critical** finding.

#### Protected Users Group

Check membership of the `Protected Users` security group (provides additional protections: no NTLM, no DES/RC4 Kerberos, no unconstrained delegation). Privileged accounts not in this group are flagged.

---

## Linux: Lynis Integration

### Detection

```python
import shutil, subprocess

LYNIS_PATHS = ["/usr/sbin/lynis", "/usr/bin/lynis", "/usr/local/sbin/lynis"]

def find_lynis():
    # Check PATH
    if shutil.which("lynis"):
        return shutil.which("lynis")
    # Check known paths
    for path in LYNIS_PATHS:
        if os.path.isfile(path):
            return path
    return None
```

### Execution

```bash
lynis audit system \
    --quiet \
    --no-colors \
    --report-file /tmp/dkastle-lynis-report.dat \
    --logfile /tmp/dkastle-lynis.log \
    --no-plugins
```

> **Note**: Running Lynis requires root or sudo. The agent requests privilege escalation via the server task parameters. If the agent container runs as root (not recommended), Lynis runs directly. If not, the agent skips Lynis and uses the Python fallback only.

### Report Parsing

Lynis writes a key-value report to the `--report-file`. Key fields extracted:

| Field | Description |
|-------|-------------|
| `hardening_index` | Overall security score (0–100) |
| `warning[]` | Array of warning items (format: `TEST_ID|description|`) |
| `suggestion[]` | Array of suggestions |
| `vulnerable_packages_list` | Packages with known CVEs |
| `os`, `os_version` | OS info |
| `kernel_version` | Running kernel |
| `installed_packages` | Package count |
| `running_services` | Service list |
| `firewall_software` | Detected firewall (iptables, ufw, firewalld, nftables) |
| `compliance[]` | Compliance test results (CIS, ISO27001 if applicable) |

The parsed output is normalized into the Discoverykastle finding format and sent to the server.

### Lynis + Python Hybrid

Even when Lynis is present, the Python fallback scanner runs a **complementary** subset of checks that are not covered by Lynis's default profile, such as:
- Docker security configuration (if Docker is installed)
- SSH key pair age and permissions
- Systemd timer review
- Additional kernel parameters

---

## Linux: Python Security Scanner (Lynis Fallback)

Full CIS Benchmark implementation in Python for when Lynis is not available.

### Check Categories

#### 1. Filesystem

| Check | Method |
|-------|--------|
| `/tmp` mounted with `noexec,nosuid,nodev` | Read `/proc/mounts` |
| `/var/tmp` separate partition | `/proc/mounts` |
| `/home` separate partition | `/proc/mounts` |
| `nodev` on all non-root filesystems | `/proc/mounts` |
| Core dumps disabled | `/proc/sys/kernel/core_pattern` + `/etc/security/limits.conf` |
| SUID root programs inventory | `find / -perm -4000 -type f 2>/dev/null` (scoped) |
| World-writable directories | `find / -perm -0002 -type d 2>/dev/null` (scoped) |

#### 2. Software Updates

| Check | Method |
|-------|--------|
| Available security updates | `apt-get -s upgrade` / `dnf check-update --security` / `zypper list-updates -t patch` |
| Last update date | `/var/log/apt/history.log` / `/var/log/dnf.log` |
| Automatic security updates enabled | `unattended-upgrades` config / `dnf-automatic` config |

#### 3. Network Parameters (sysctl)

| Parameter | Expected | Risk if wrong |
|-----------|----------|--------------|
| `net.ipv4.ip_forward` | `0` (unless router) | IP forwarding enables routing attacks |
| `net.ipv4.conf.all.send_redirects` | `0` | ICMP redirect attacks |
| `net.ipv4.conf.all.accept_redirects` | `0` | ICMP redirect spoofing |
| `net.ipv4.conf.all.log_martians` | `1` | Detect spoofed packets |
| `net.ipv4.tcp_syncookies` | `1` | SYN flood protection |
| `net.ipv6.conf.all.accept_redirects` | `0` | IPv6 redirect attacks |
| `kernel.randomize_va_space` | `2` | ASLR full randomization |
| `kernel.dmesg_restrict` | `1` | Prevent info disclosure |
| `kernel.kptr_restrict` | `2` | Prevent kernel pointer leaks |

Method: read `/proc/sys/` or call `sysctl -a`.

#### 4. SSH Configuration

File: `/etc/ssh/sshd_config` (and `/etc/ssh/sshd_config.d/*.conf`)

| Check | Expected value |
|-------|---------------|
| `PermitRootLogin` | `no` or `prohibit-password` |
| `PasswordAuthentication` | `no` (key-only) |
| `PermitEmptyPasswords` | `no` |
| `Protocol` | `2` (SSHv1 disabled) |
| `MaxAuthTries` | `≤ 4` |
| `LoginGraceTime` | `≤ 60` |
| `X11Forwarding` | `no` |
| `AllowTcpForwarding` | `no` (unless needed) |
| `ClientAliveInterval` | set (idle timeout) |
| `HostbasedAuthentication` | `no` |
| `IgnoreRhosts` | `yes` |
| Ciphers | No weak ciphers (arcfour, 3des, blowfish, cbc mode) |
| MACs | No MD5 or SHA1 MACs |
| KexAlgorithms | No diffie-hellman-group1/14 |

#### 5. User Accounts

| Check | Method |
|-------|--------|
| Accounts with UID 0 (other than root) | Parse `/etc/passwd` |
| Accounts with empty passwords | Parse `/etc/shadow` (requires root) |
| Accounts with no shell (`/sbin/nologin`) vs. active login | `/etc/passwd` |
| Password aging configured | `/etc/shadow` fields |
| `PASS_MAX_DAYS`, `PASS_MIN_DAYS`, `PASS_WARN_AGE` in `/etc/login.defs` | File read |
| Root PATH does not contain `.` | Check `$PATH` for root |
| `.rhosts`, `.netrc` files in home dirs | File scan |

#### 6. Sudo Configuration

| Check | Method |
|-------|--------|
| No NOPASSWD for sensitive commands | Parse `/etc/sudoers` + `/etc/sudoers.d/` |
| `!authenticate` not used | sudoers parse |
| sudo logs enabled | `/etc/sudoers`: `Defaults logfile=` or `Defaults log_output` |

#### 7. AppArmor / SELinux

| Check | Method |
|-------|--------|
| AppArmor enabled | `aa-status` or `/sys/kernel/security/apparmor/profiles` |
| All profiles enforced (not complain mode) | `aa-status` output |
| SELinux mode | `/sys/fs/selinux/enforce` or `getenforce` |
| No unconfined processes | `ps auxZ` for SELinux |

#### 8. Firewall

| Check | Method |
|-------|--------|
| Firewall active | Detect: `ufw status`, `firewall-cmd --state`, `iptables -L`, `nft list ruleset` |
| Default deny inbound | Parse firewall rules |
| Inbound SSH rate limiting | Check if SSH rate limit rule exists |
| Open ports match expected services | Cross-reference `ss -tlnp` vs. firewall rules |

#### 9. Cron

| Check | Method |
|-------|--------|
| `/etc/crontab` permissions | `stat /etc/crontab` — must be 600 or 644, owned by root |
| `/etc/cron.*` permissions | Directory permissions |
| `at` and `cron` access restricted | Check `/etc/cron.allow`, `/etc/cron.deny` |
| Cron jobs running unexpected scripts | Enumerate all cron jobs and flag non-standard paths |

#### 10. Logging

| Check | Method |
|-------|--------|
| syslog/rsyslog/journald running | `systemctl is-active rsyslog syslog systemd-journald` |
| Log rotation configured | `/etc/logrotate.conf` and `/etc/logrotate.d/` |
| Remote logging configured | Check syslog config for remote targets |
| `auditd` running | `systemctl is-active auditd` |
| Audit rules for sensitive files | `auditctl -l` (check rules for `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`) |

#### 11. Kernel and Boot

| Check | Method |
|-------|--------|
| GRUB password set | `/etc/grub.d/` or `/boot/grub/grub.cfg` for `password_pbkdf2` |
| Single user mode requires authentication | `/etc/sysconfig/init` or `sulogin` in systemd |
| Unused kernel modules disabled | `/etc/modprobe.d/` — check dccp, sctp, rds, tipc disabled |
| Secure Boot enabled | `mokutil --sb-state` (if available) |

---

## Output Format

All findings from all scanners are normalized into this structure before being sent to the server:

```json
{
  "scanner": "lynis | wazuh | native_windows | native_linux | active_directory",
  "scan_time": "ISO-8601",
  "host_id": "uuid",
  "os": "windows | linux",
  "hardening_score": 72,
  "findings": [
    {
      "id": "SSH-001",
      "title": "SSH root login permitted",
      "description": "PermitRootLogin is set to 'yes' in /etc/ssh/sshd_config",
      "severity": "high",
      "cvss_score": null,
      "category": "ssh_hardening",
      "status": "fail",
      "evidence": "PermitRootLogin yes",
      "remediation": "Set PermitRootLogin to 'no' or 'prohibit-password' in /etc/ssh/sshd_config",
      "reference": "CIS Benchmark 5.2.10",
      "source": "native_linux"
    }
  ],
  "ad_findings": [
    {
      "id": "AD-KERB-001",
      "title": "Kerberoastable account: svc_backup",
      "description": "Account svc_backup has SPN set and uses RC4 encryption — vulnerable to offline cracking",
      "severity": "critical",
      "category": "active_directory",
      "affected_object": "CN=svc_backup,OU=ServiceAccounts,DC=corp,DC=example,DC=com",
      "details": {
        "spn": "MSSQLSvc/dbserver.corp.example.com:1433",
        "encryption_types": ["RC4"],
        "password_last_set": "2021-03-15T00:00:00Z"
      },
      "remediation": "Set msDS-SupportedEncryptionTypes to AES only; rotate the service account password"
    }
  ]
}
```

Severity levels: `critical`, `high`, `medium`, `low`, `info`

---

## Roadmap (Future Modules)

| Module | Platform | Status |
|--------|---------|--------|
| macOS CIS Benchmark | macOS | Planned |
| Docker security check | Linux | Planned |
| Kubernetes node hardening | Linux | Planned |
| Azure AD (Entra ID) integration | Windows | Planned |
| SCAP/OVAL compliance scan | Linux | Planned |
