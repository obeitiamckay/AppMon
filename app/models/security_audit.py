"""Firewall and privileged admin user audit ORM models."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class FirewallBaseline(Base):
    """Approved firewall & listening ports baseline per host."""

    __tablename__ = "firewall_baseline"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    firewall_backend: Mapped[str] = mapped_column(String(32), nullable=False)  # firewalld, nftables, iptables, windows_defender
    rules_snapshot: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    ports_snapshot: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class FirewallAllowedRule(Base):
    """Configured allowed ports and source CIDRs per host group."""

    __tablename__ = "firewall_allowed_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("host_groups.id", ondelete="CASCADE"), nullable=False, index=True)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False, default="tcp")  # tcp | udp
    allowed_sources: Mapped[str] = mapped_column(String(255), nullable=False, default="10.0.0.0/8")  # comma-separated CIDRs
    description: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    group: Mapped["HostGroup"] = relationship("HostGroup", back_populates="firewall_rules")


class AdminUserAllowed(Base):
    """Authorized administrative accounts per group or specific host."""

    __tablename__ = "admin_users_allowed"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    group_id: Mapped[Optional[int]] = mapped_column(ForeignKey("host_groups.id", ondelete="CASCADE"), nullable=True, index=True)
    host_id: Mapped[Optional[int]] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), nullable=True, index=True)
    username: Mapped[str] = mapped_column(String(128), nullable=False)
    account_type: Mapped[str] = mapped_column(String(32), nullable=False, default="human")  # human | service
    notes: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    group: Mapped[Optional["HostGroup"]] = relationship("HostGroup", back_populates="allowed_admins")


class AdminUserCurrent(Base):
    """Latest observed privileged/admin accounts on each host."""

    __tablename__ = "admin_users_current"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False, index=True)
    username: Mapped[str] = mapped_column(String(128), nullable=False)
    privilege_source: Mapped[str] = mapped_column(String(128), nullable=False)  # uid_0, wheel, sudoers, Administrators
    is_service_account: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_login_days: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    password_never_expires: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_authorized: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class AdminUserHistory(Base):
    """Historical audit trail of admin account additions, removals, and status changes."""

    __tablename__ = "admin_users_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False, index=True)
    username: Mapped[str] = mapped_column(String(128), nullable=False)
    change_type: Mapped[str] = mapped_column(String(32), nullable=False)  # added | removed | privilege_changed
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
