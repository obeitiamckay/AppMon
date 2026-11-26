"""Application configuration loaded from environment variables and .env file."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration for soc-monitor."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "soc-monitor"
    app_env: str = "production"
    debug: bool = False

    # Web server
    host: str = "0.0.0.0"
    port: int = 8443
    ssl_certfile: Optional[str] = None
    ssl_keyfile: Optional[str] = None

    # Database
    database_url: str = "sqlite:///./soc_monitor.db"

    # Security
    fernet_key: str = Field(
        default="",
        description="Base64-encoded 32-byte Fernet key for encrypting stored credentials.",
    )
    jwt_secret: str = Field(
        default="dev-insecure-jwt-secret-change-in-production-32chars",
        description="Secret key for signing JWT session tokens.",
    )
    session_expire_minutes: int = 480
    cookie_secure: bool = True

    # HashiCorp Vault (optional)
    vault_enabled: bool = False
    vault_addr: str = "https://127.0.0.1:8200"
    vault_token: str = ""
    vault_mount_point: str = "secret"

    # Scan & Concurrency
    scan_cron_hour: int = 2
    scan_cron_minute: int = 0
    scan_max_workers: int = 25
    host_timeout_seconds: int = 45
    host_max_retries: int = 2
    winrm_verify_ssl: bool = True

    # Directories & Logging
    reports_dir: Path = Path("/var/lib/soc-monitor/reports")
    logs_dir: Path = Path("/var/log/soc-monitor")
    log_level: str = "INFO"

    # Notificaciones Email / Gmail SMTP (v2.0)
    smtp_enabled: bool = False
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_use_tls: bool = True
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_to: str = ""

    # Bootstrap initial admin user
    initial_admin_user: str = "socadmin"
    initial_admin_password: str = "ChangeMe!SocAdmin2026"


@lru_cache
def get_settings() -> Settings:
    """Return cached Settings instance."""
    return Settings()
