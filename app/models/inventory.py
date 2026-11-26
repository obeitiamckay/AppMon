"""Inventory, grouping, credentials, and threshold ORM models."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class HostGroup(Base):
    """Logical group of servers (e.g., Web, DB, App) with shared policies."""

    __tablename__ = "host_groups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    scan_schedule: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, default="02:00")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    hosts: Mapped[list[Host]] = relationship("Host", back_populates="group")
    thresholds: Mapped[list[Threshold]] = relationship("Threshold", back_populates="group", cascade="all, delete-orphan")
    firewall_rules: Mapped[list["FirewallAllowedRule"]] = relationship(
        "FirewallAllowedRule", back_populates="group", cascade="all, delete-orphan"
    )
    allowed_admins: Mapped[list["AdminUserAllowed"]] = relationship(
        "AdminUserAllowed", back_populates="group", cascade="all, delete-orphan"
    )


class CredentialRef(Base):
    """Reference to encrypted credentials or HashiCorp Vault path."""

    __tablename__ = "credentials_ref"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False, index=True)
    auth_type: Mapped[str] = mapped_column(String(32), nullable=False)  # ssh_key, winrm_ntlm, winrm_kerberos, winrm_basic, vault
    username: Mapped[str] = mapped_column(String(128), nullable=False)
    encrypted_secret: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Fernet-encrypted SSH private key or password
    encrypted_passphrase: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    vault_path: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    hosts: Mapped[list[Host]] = relationship("Host", back_populates="credential")


class Host(Base):
    """Monitored server inventory entry."""

    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    hostname: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    ip_address: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    os_type: Mapped[str] = mapped_column(String(16), nullable=False)  # linux | windows
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=22)
    group_id: Mapped[Optional[int]] = mapped_column(ForeignKey("host_groups.id", ondelete="SET NULL"), nullable=True)
    credential_id: Mapped[Optional[int]] = mapped_column(ForeignKey("credentials_ref.id", ondelete="SET NULL"), nullable=True)
    scan_interval_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=1440)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")  # ok, warning, critical, unreachable, pending
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    os_version: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    group: Mapped[Optional[HostGroup]] = relationship("HostGroup", back_populates="hosts")
    credential: Mapped[Optional[CredentialRef]] = relationship("CredentialRef", back_populates="hosts")
    thresholds: Mapped[list[Threshold]] = relationship("Threshold", back_populates="host", cascade="all, delete-orphan")


class Threshold(Base):
    """Configurable metric thresholds per group or per host."""

    __tablename__ = "thresholds"
    __table_args__ = (
        UniqueConstraint("group_id", "host_id", "metric_name", name="uq_threshold_scope_metric"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    group_id: Mapped[Optional[int]] = mapped_column(ForeignKey("host_groups.id", ondelete="CASCADE"), nullable=True)
    host_id: Mapped[Optional[int]] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), nullable=True)
    metric_name: Mapped[str] = mapped_column(String(64), nullable=False)  # disk_pct, cpu_pct, memory_pct, swap_pct, disk_inode_pct
    warning_value: Mapped[float] = mapped_column(Float, nullable=False)
    critical_value: Mapped[float] = mapped_column(Float, nullable=False)
    sustained_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    group: Mapped[Optional[HostGroup]] = relationship("HostGroup", back_populates="thresholds")
    host: Mapped[Optional[Host]] = relationship("Host", back_populates="thresholds")
