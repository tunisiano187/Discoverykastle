# Discoverykastle Agent

Lightweight network-discovery and security-assessment agent for the
[Discoverykastle](https://github.com/tunisiano187/Discoverykastle) platform.

## Quick start — Docker (recommended)

```bash
docker run -d \
  --name dkastle-agent \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  -e DKASTLE_SERVER_URL=https://dk.example.com \
  -e DKASTLE_ENROLL_TOKEN=<token-from-dashboard> \
  --restart unless-stopped \
  ghcr.io/tunisiano187/discoverykastle-agent:latest
```

## Quick start — pip

```bash
pip install discoverykastle-agent
dkagent --config /etc/discoverykastle/agent.conf
```

With optional Netmiko support (network device collection):

```bash
pip install 'discoverykastle-agent[netmiko]'
```

## Configuration

Set variables in `/etc/discoverykastle/agent.conf` (key=value) or as environment variables:

| Variable | Description | Required |
|----------|-------------|---------|
| `DKASTLE_SERVER_URL` | HTTPS URL of the DK server | Yes |
| `DKASTLE_ENROLL_TOKEN` | One-time enrollment token | Yes (first run) |
| `NMAP_ENABLED` | Enable nmap network scan | No |
| `CVE_SCAN_ENABLED` | Enable CVE scanning (Grype/NVD) | No |
| `ANSIBLE_ENABLED` | Enable Ansible fact-cache collection | No |
| `NETMIKO_ENABLED` | Enable Netmiko device collection | No |

See [docs/deployment.md](../docs/deployment.md) for the full variable reference.

## Collectors

| Collector | env var | Requires |
|-----------|---------|---------|
| nmap network scan | `NMAP_ENABLED=true` | `nmap` binary |
| CVE scan | `CVE_SCAN_ENABLED=true` | `grype` binary or NVD API key |
| Ansible fact-cache | `ANSIBLE_ENABLED=true` | Read access to fact-cache dir |
| Netmiko devices | `NETMIKO_ENABLED=true` | `pip install discoverykastle-agent[netmiko]` |
| Puppet fact-cache | Always active when fact-cache dir exists | Read access to Puppet vardir |
