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
    #
    # Install extra dep first: pip install 'discoverykastle-server[ai]'
    # ------------------------------------------------------------------ #
    ai_enabled: bool = False
    anthropic_api_key: Optional[str] = None

    class Config:
        env_prefix = "DKASTLE_"
        env_file = ".env"


settings = Settings()
