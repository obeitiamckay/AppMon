"""Monitoring execution, baselines, check results, findings, and reports ORM models."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScanRun(Base):
    """Represents a single daily or manual scan execution across all active hosts."""

    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    trigger_type: Mapped[str] = mapped_column(String(32), nullable=False, default="scheduled")  # scheduled | manual
    triggered_by: Mapped[str] = mapped_column(String(64), nullable=False, default="scheduler")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="running")  # running | completed | failed
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    total_hosts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    ok_hosts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    warning_hosts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    critical_hosts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    unreachable_hosts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class Baseline(Base):
    """Versioned host baseline captured during discovery or approved after legitimate changes."""

    __tablename__ = "baselines"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    approved_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    os_info: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    services_snapshot: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    ports_snapshot: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    filesystems_snapshot: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    logs_inventory: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    firewall_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    admins_snapshot: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class CheckResult(Base):
    """Normalized check metric result for a host during a scan run."""

    __tablename__ = "check_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False, index=True)
    check_name: Mapped[str] = mapped_column(String(64), nullable=False)  # filesystem, cpu, memory, services, logs, availability, updates
    status: Mapped[str] = mapped_column(String(16), nullable=False)  # ok, warning, critical, error
    metric_value: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class Finding(Base):
    """Actionable operational or security finding with SOC metadata and MITRE ATT&CK mapping."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False, index=True)
    check_name: Mapped[str] = mapped_column(String(64), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)  # availability, capacity, service, security, firewall, privilege, logs, patching, drift
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)  # critical, high, medium, low
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[str] = mapped_column(Text, nullable=False)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    suggested_command: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    mitre_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")  # open | acknowledged | resolved
    fingerprint: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    occurrences: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class Report(Base):
    """Generated report artifacts (HTML, PDF, JSON) per scan run."""

    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False, unique=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    html_path: Mapped[str] = mapped_column(String(512), nullable=False)
    pdf_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    json_path: Mapped[str] = mapped_column(String(512), nullable=False)
    summary_stats: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
