from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # Database
    database_url: str = "postgresql+asyncpg://dkastle:dkastle@localhost:5432/discoverykastle"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Security
    secret_key: str = "changeme-64-char-hex"
    vault_key: str = "changeme-base64-32-bytes"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60

    # Scan authorization
    authorized_cidrs: list[str] = []
    max_recursion_depth: int = 2
    # When True (default), scanning a public IP/CIDR requires an explicit
    # AuthorizationRequest approved by a human before proceeding.
    # Private RFC-1918 ranges are always allowed without extra approval.
    require_public_scan_authorization: bool = True

    # ------------------------------------------------------------------ #
    # DNS resolution (enabled by default)
    #
    # Performs reverse PTR lookups for discovered hosts and forward A/AAAA
    # lookups for hostnames.  Also queries SOA/NS records to identify the
    # Active Directory / DNS domain owning each subnet.
    # Set dns_resolve_enabled=false to skip all DNS enrichment.
    # ------------------------------------------------------------------ #
    dns_resolve_enabled: bool = True
    # Optional: IP or hostname of a specific DNS server to query.
    # Leave empty to use the system resolver (recommended).
    dns_server: Optional[str] = None
    # Timeout in seconds for each DNS query
    dns_timeout: float = 3.0

    # ------------------------------------------------------------------ #
    # Active Directory / LDAP domain info
    #
    # When hosts are detected inside a Windows domain, Discoverykastle can
    # query the domain controller for computer account details (OS version,
    # OU membership, groups).  Requires read-only LDAP credentials.
    # ------------------------------------------------------------------ #
    ldap_enabled: bool = False
    ldap_server: Optional[str] = None          # e.g. "ldap://dc.example.com"
    ldap_bind_dn: Optional[str] = None         # e.g. "CN=readonly,DC=example,DC=com"
    ldap_bind_password: Optional[str] = None
    ldap_base_dn: Optional[str] = None         # e.g. "DC=example,DC=com"

    # ------------------------------------------------------------------ #
    # Puppet integration (disabled by default)
    #
    # Two data flows:
    #
    #   1. PuppetDB REST API  (server-side pull, optional)
    #      The server contacts PuppetDB over HTTP.
    #      Only available when PuppetDB is installed (Puppet Enterprise or
    #      open-source with PuppetDB bolt-on).
    #      Set puppet_puppetdb_url to enable.
    #
    #   2. Agent push  (agent/collectors/puppet.py)
    #      The Discoverykastle agent running on (or near) the Puppet master
    #      reads the YAML fact cache and report files locally, then submits
    #      the data to POST /api/v1/data/puppet.
    #      No filesystem access is required from the Docker server container.
    #      Configure PUPPET_FACT_CACHE_DIR / PUPPET_REPORT_DIR on the agent.
    #
    # ------------------------------------------------------------------ #
    puppet_enabled: bool = False
    # PuppetDB API — optional, only if PuppetDB is installed
    puppet_puppetdb_url: Optional[str] = None      # e.g. "https://puppet.example.com:8081"
    puppet_puppetdb_token: Optional[str] = None    # PE RBAC token or bearer token
    # Interval in seconds between PuppetDB pull syncs (default: 3600 = 1 hour)
    puppet_sync_interval: int = 3600

    # ------------------------------------------------------------------ #
    # Ansible integration (disabled by default)
    #
    # Two collection modes:
    #   1. AWX / Ansible Tower REST API (set ansible_awx_url + token)
    #   2. Local fact cache directory   (set ansible_fact_cache_dir)
    # Both modes import host facts into the inventory.
    # ------------------------------------------------------------------ #
    ansible_enabled: bool = False
    ansible_awx_url: Optional[str] = None      # e.g. "https://awx.example.com"
    ansible_awx_token: Optional[str] = None    # AWX OAuth2 token
    # Path to Ansible fact cache directory (jsonfile or yaml cache plugin)
    ansible_fact_cache_dir: Optional[str] = None
    # Interval in seconds between Ansible syncs (default: 3600 = 1 hour)
    ansible_sync_interval: int = 3600

    # Notifications
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from: Optional[str] = None
    slack_webhook_url: Optional[str] = None
    generic_webhook_url: Optional[str] = None

    # NetBox integration (optional)
    netbox_url: Optional[str] = None
    netbox_token: Optional[str] = None
    netbox_sync_enabled: bool = False

    # ------------------------------------------------------------------ #
    # Logging
    # ------------------------------------------------------------------ #

    # Minimum log level: DEBUG, INFO, WARNING, ERROR, CRITICAL
    log_level: str = "INFO"

    # JSON rotating log file. Set to empty string "" to disable file logging.
    log_file: str = "discoverykastle.log"

    # Graylog GELF/UDP — leave graylog_host empty to disable.
    # Install extra dep first: pip install 'discoverykastle-server[graylog]'
    graylog_host: Optional[str] = None
    graylog_port: int = 12201
    graylog_facility: str = "discoverykastle"

    # ------------------------------------------------------------------ #
    # AI enrichment (disabled by default)
    #
    # Enable ONLY for tasks that cannot be solved deterministically.
    # Current use: contextual CVE exploitability triage — assessing whether
    # a vulnerability's prerequisites are actually met on a specific host,
    # which requires reading and understanding the CVE description.
    # ------------------------------------------------------------------ #
    # ------------------------------------------------------------------ #
    # Web Push notifications (disabled by default)
    #
    # Sends browser push notifications when alerts are created.
    # Requires: pip install 'discoverykastle-server[webpush]'
    # Generate VAPID keys via the setup wizard or:
    #   GET /setup/generate-vapid
    # ------------------------------------------------------------------ #
    webpush_enabled: bool = False

    # VAPID contact email (included in push requests — required by browsers)
    vapid_email: str = "admin@example.com"

    # VAPID key pair — generate once via the setup wizard
    vapid_private_key: str = ""
    vapid_public_key: str = ""

    # File where push subscriptions are stored (JSON, relative to working dir)
    webpush_sub_file: str = "webpush_subscriptions.json"

    # Which severity levels trigger a browser push notification
    # Comma-separated: critical,high,medium,low,info
    webpush_min_severity: str = "high"

    ai_enabled: bool = False

    # Backend selection: "auto" | "ollama" | "anthropic"
    #   auto      → prefer Ollama if ollama_url is set, otherwise Anthropic
    #   ollama    → force local Ollama (no API key needed)
    #   anthropic → force Anthropic cloud (requires anthropic_api_key +
    #               pip install 'discoverykastle-server[ai]')
    ai_backend: str = "auto"

    # Ollama — local inference, no API key, no extra pip dependency.
    # Install Ollama: https://ollama.com/download
    # Then pull a model: ollama pull llama3.2
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2"

    # Anthropic cloud — requires SDK:
    # pip install 'discoverykastle-server[ai]'
    anthropic_api_key: Optional[str] = None
    anthropic_model: str = "claude-haiku-4-5-20251001"

    class Config:
        env_prefix = "DKASTLE_"
        env_file = ".env"


settings = Settings()
