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
