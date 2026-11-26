"""Threshold resolution per host, group, and system defaults."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.inventory import Host, Threshold


@dataclass
class EffectiveThreshold:
    """Resolved warning/critical threshold for a metric."""

    warning: float
    critical: float
    sustained_minutes: int = 0


DEFAULT_THRESHOLDS: dict[str, EffectiveThreshold] = {
    "disk_pct": EffectiveThreshold(warning=80.0, critical=90.0),
    "disk_inode_pct": EffectiveThreshold(warning=80.0, critical=90.0),
    "cpu_pct": EffectiveThreshold(warning=80.0, critical=95.0, sustained_minutes=15),
    "memory_pct": EffectiveThreshold(warning=85.0, critical=95.0),
    "swap_pct": EffectiveThreshold(warning=20.0, critical=50.0),
    "latency_ms": EffectiveThreshold(warning=500.0, critical=1500.0),
}


def resolve_host_thresholds(db: Session, host: Host) -> dict[str, EffectiveThreshold]:
    """Resolve effective thresholds: host override > group override > system default."""
    resolved = {k: EffectiveThreshold(v.warning, v.critical, v.sustained_minutes) for k, v in DEFAULT_THRESHOLDS.items()}

    if host.group_id is not None:
        group_rows = db.execute(
            select(Threshold).where(Threshold.group_id == host.group_id, Threshold.host_id.is_(None))
        ).scalars().all()
        for row in group_rows:
            resolved[row.metric_name] = EffectiveThreshold(
                warning=row.warning_value,
                critical=row.critical_value,
                sustained_minutes=row.sustained_minutes,
            )

    host_rows = db.execute(
        select(Threshold).where(Threshold.host_id == host.id)
    ).scalars().all()
    for row in host_rows:
        resolved[row.metric_name] = EffectiveThreshold(
            warning=row.warning_value,
            critical=row.critical_value,
            sustained_minutes=row.sustained_minutes,
        )

    return resolved
