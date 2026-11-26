"""Baseline creation, drift comparison, and approval workflow."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.collectors.base import HostTelemetry
from app.models.inventory import Host
from app.models.monitoring import Baseline
from app.models.security_audit import FirewallBaseline


def get_active_baseline(db: Session, host_id: int) -> Optional[Baseline]:
    """Return the currently active baseline for a host, if any."""
    stmt = (
        select(Baseline)
        .where(Baseline.host_id == host_id, Baseline.is_active.is_(True))
        .order_by(Baseline.version.desc())
        .limit(1)
    )
    return db.execute(stmt).scalar_one_or_none()


def create_initial_baseline(
    db: Session,
    host: Host,
    telemetry: HostTelemetry,
    approved_by: str = "auto-discovery",
) -> Baseline:
    """Persist version 1 baseline and firewall baseline on first discovery."""
    now = datetime.now(timezone.utc)
    baseline = Baseline(
        host_id=host.id,
        version=1,
        is_active=True,
        approved_by=approved_by,
        approved_at=now,
        os_info=telemetry.os_info,
        services_snapshot=telemetry.services,
        ports_snapshot=telemetry.ports,
        filesystems_snapshot=telemetry.filesystems,
        logs_inventory=telemetry.logs_inventory,
        firewall_snapshot=telemetry.firewall,
        admins_snapshot=telemetry.admins,
    )
    db.add(baseline)

    fw_baseline = FirewallBaseline(
        host_id=host.id,
        version=1,
        is_active=True,
        firewall_backend=telemetry.firewall.get("backend", "unknown"),
        rules_snapshot=telemetry.firewall.get("rules", []),
        ports_snapshot=telemetry.ports,
    )
    db.add(fw_baseline)
    db.flush()
    return baseline


def approve_new_baseline(
    db: Session,
    host_id: int,
    telemetry_dict: dict[str, Any],
    approved_by: str,
) -> Baseline:
    """Deactivate current baseline and create a new approved version."""
    current = get_active_baseline(db, host_id)
    next_version = (current.version + 1) if current else 1

    db.execute(
        update(Baseline)
        .where(Baseline.host_id == host_id, Baseline.is_active.is_(True))
        .values(is_active=False)
    )
    db.execute(
        update(FirewallBaseline)
        .where(FirewallBaseline.host_id == host_id, FirewallBaseline.is_active.is_(True))
        .values(is_active=False)
    )

    now = datetime.now(timezone.utc)
    new_baseline = Baseline(
        host_id=host_id,
        version=next_version,
        is_active=True,
        approved_by=approved_by,
        approved_at=now,
        os_info=telemetry_dict.get("os_info", {}),
        services_snapshot=telemetry_dict.get("services", []),
        ports_snapshot=telemetry_dict.get("ports", []),
        filesystems_snapshot=telemetry_dict.get("filesystems", []),
        logs_inventory=telemetry_dict.get("logs_inventory", []),
        firewall_snapshot=telemetry_dict.get("firewall", {}),
        admins_snapshot=telemetry_dict.get("admins", []),
    )
    db.add(new_baseline)

    fw = telemetry_dict.get("firewall", {})
    new_fw = FirewallBaseline(
        host_id=host_id,
        version=next_version,
        is_active=True,
        firewall_backend=fw.get("backend", "unknown"),
        rules_snapshot=fw.get("rules", []),
        ports_snapshot=telemetry_dict.get("ports", []),
    )
    db.add(new_fw)
    db.flush()
    return new_baseline


def compute_baseline_diff(baseline: Baseline, telemetry: HostTelemetry) -> dict[str, Any]:
    """Compare current host telemetry against the active baseline and return drift details."""
    base_svcs = {s.get("name"): s for s in (baseline.services_snapshot or []) if s.get("name")}
    curr_svcs = {s.get("name"): s for s in (telemetry.services or []) if s.get("name")}

    added_services = sorted(set(curr_svcs.keys()) - set(base_svcs.keys()))
    removed_services = sorted(set(base_svcs.keys()) - set(curr_svcs.keys()))

    def _port_key(p: dict[str, Any]) -> tuple[str, int]:
        return (str(p.get("protocol", "tcp")).lower(), int(p.get("port", 0)))

    base_ports = {_port_key(p) for p in (baseline.ports_snapshot or []) if p.get("port")}
    curr_ports = {_port_key(p) for p in (telemetry.ports or []) if p.get("port")}

    added_ports = sorted([f"{proto}/{port}" for proto, port in (curr_ports - base_ports)])
    removed_ports = sorted([f"{proto}/{port}" for proto, port in (base_ports - curr_ports)])

    base_admins = {a.get("username") for a in (baseline.admins_snapshot or []) if a.get("username")}
    curr_admins = {a.get("username") for a in (telemetry.admins or []) if a.get("username")}

    added_admins = sorted(curr_admins - base_admins)
    removed_admins = sorted(base_admins - curr_admins)

    base_os = (baseline.os_info or {}).get("os_name", "")
    curr_os = (telemetry.os_info or {}).get("os_name", "")
    os_changed = bool(base_os and curr_os and base_os != curr_os)

    has_drift = any([
        added_services,
        removed_services,
        added_ports,
        removed_ports,
        added_admins,
        removed_admins,
        os_changed,
    ])

    return {
        "has_drift": has_drift,
        "added_services": added_services,
        "removed_services": removed_services,
        "added_ports": added_ports,
        "removed_ports": removed_ports,
        "added_admins": added_admins,
        "removed_admins": removed_admins,
        "os_changed": os_changed,
        "baseline_version": baseline.version,
    }
