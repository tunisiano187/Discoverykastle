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

    class Config:
        env_prefix = "DKASTLE_"
        env_file = ".env"


settings = Settings()
