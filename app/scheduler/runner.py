"""Concurrent scan runner with ThreadPoolExecutor, retries, timeouts, and APScheduler."""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks.engine import evaluate_host_checks
from app.collectors.base import BaseCollector, HostTelemetry
from app.collectors.linux_collector import LinuxCollector
from app.collectors.windows_collector import WindowsCollector
from app.config import get_settings
from app.database import SessionLocal
from app.discovery.baseline_service import compute_baseline_diff, create_initial_baseline, get_active_baseline
from app.firewall.analyzer import analyze_firewall_and_ports
from app.models.inventory import CredentialRef, Host
from app.models.monitoring import ScanRun
from app.notifications.email_sender import send_report_email
from app.reporting.generator import generate_scan_report
from app.security import SecretCipher, get_vault_secret
from app.users.admin_audit import audit_admin_users

logger = logging.getLogger(__name__)

_scheduler: Optional[BackgroundScheduler] = None


def build_collector(host: Host, cred: Optional[CredentialRef], timeout_seconds: int) -> BaseCollector:
    """Instantiate LinuxCollector or WindowsCollector with decrypted credentials."""
    if cred is None:
        raise ValueError(f"Host {host.hostname} has no credential configured")

    cipher = SecretCipher()
    secret = ""
    passphrase = None

    if cred.auth_type == "vault" and cred.vault_path:
        secret = get_vault_secret(cred.vault_path, "secret") or ""
        passphrase = get_vault_secret(cred.vault_path, "passphrase")
    else:
        secret = cipher.decrypt(cred.encrypted_secret) if cred.encrypted_secret else ""
        passphrase = cipher.decrypt(cred.encrypted_passphrase) if cred.encrypted_passphrase else None

    if host.os_type.lower() == "linux":
        return LinuxCollector(
            hostname=host.hostname,
            ip_address=host.ip_address,
            port=host.port or 22,
            username=cred.username,
            secret=secret,
            passphrase=passphrase,
            timeout_seconds=timeout_seconds,
        )
    if host.os_type.lower() == "windows":
        transport = "kerberos" if cred.auth_type == "winrm_kerberos" else ("basic" if cred.auth_type == "winrm_basic" else "ntlm")
        return WindowsCollector(
            hostname=host.hostname,
            ip_address=host.ip_address,
            port=host.port or 5986,
            username=cred.username,
            secret=secret,
            auth_transport=transport,
            timeout_seconds=timeout_seconds,
        )
    raise ValueError(f"Unsupported OS type: {host.os_type}")


def _collect_with_retries(
    collector: BaseCollector,
    max_retries: int,
) -> HostTelemetry:
    last_exc: Optional[Exception] = None
    for attempt in range(max_retries + 1):
        try:
            return collector.collect_all()
        except Exception as exc:
            last_exc = exc
            logger.warning(
                "Collection attempt %d/%d failed for %s: %s",
                attempt + 1,
                max_retries + 1,
                collector.hostname,
                exc,
                extra={"host": collector.hostname},
            )
            if attempt < max_retries:
                time.sleep(min(2 ** attempt, 5))
    return HostTelemetry(
        hostname=collector.hostname,
        os_type="unknown",
        reachable=False,
        error_message=str(last_exc) if last_exc else "Unknown connection error",
    )


def _scan_single_host(
    host_id: int,
    scan_run_id: int,
    timeout_seconds: int,
    max_retries: int,
    session_factory: Callable[[], Session],
    collector_factory: Optional[Callable[[Host, Optional[CredentialRef], int], BaseCollector]] = None,
) -> tuple[int, str, dict[str, Any]]:
    """Scan a single host in an isolated DB session and return (host_id, status, runtime_data)."""
    db = session_factory()
    try:
        host = db.get(Host, host_id)
        if not host:
            return host_id, "unreachable", {}

        factory = collector_factory or build_collector
        try:
            collector = factory(host, host.credential, timeout_seconds)
            telemetry = _collect_with_retries(collector, max_retries=max_retries)
        except Exception as exc:
            telemetry = HostTelemetry(
                hostname=host.hostname,
                os_type=host.os_type,
                reachable=False,
                error_message=str(exc),
            )

        baseline = get_active_baseline(db, host.id)
        drift: Optional[dict[str, Any]] = None
        if telemetry.reachable:
            if baseline is None:
                baseline = create_initial_baseline(db, host, telemetry)
                logger.info("Created initial baseline v1 for %s", host.hostname, extra={"host": host.hostname})
            else:
                drift = compute_baseline_diff(baseline, telemetry)

            host.os_version = telemetry.os_info.get("os_name", host.os_version)
            host.last_seen_at = datetime.now(timezone.utc)

        check_results, findings = evaluate_host_checks(db, scan_run_id, host, telemetry, baseline, drift)
        ports_table: list[dict[str, Any]] = []
        if telemetry.reachable:
            ports_table, fw_findings = analyze_firewall_and_ports(db, scan_run_id, host, telemetry)
            admin_findings = audit_admin_users(db, scan_run_id, host, telemetry)
            findings.extend(fw_findings)
            findings.extend(admin_findings)

        for cr in check_results:
            db.add(cr)
        for f in findings:
            db.add(f)

        if not telemetry.reachable:
            status = "unreachable"
        elif any(f.severity == "critical" for f in findings):
            status = "critical"
        elif any(f.severity in ("high", "medium") for f in findings):
            status = "warning"
        else:
            status = "ok"

        host.last_status = status
        db.commit()

        runtime_data = {
            "ports_table": ports_table,
            "admins_count": len(telemetry.admins),
            "drift": drift,
        }
        return host_id, status, runtime_data
    except Exception as exc:
        db.rollback()
        logger.exception("Unhandled error scanning host_id=%s: %s", host_id, exc)
        return host_id, "unreachable", {}
    finally:
        db.close()


def run_full_scan(
    trigger_type: str = "scheduled",
    triggered_by: str = "scheduler",
    session_factory: Callable[[], Session] = SessionLocal,
    collector_factory: Optional[Callable[[Host, Optional[CredentialRef], int], BaseCollector]] = None,
) -> ScanRun:
    """Execute a full concurrent scan across all active hosts and generate reports."""
    settings = get_settings()
    db = session_factory()
    try:
        active_hosts = list(db.execute(select(Host).where(Host.is_active.is_(True))).scalars().all())
        scan_run = ScanRun(
            trigger_type=trigger_type,
            triggered_by=triggered_by,
            status="running",
            total_hosts=len(active_hosts),
        )
        db.add(scan_run)
        db.commit()
        db.refresh(scan_run)
        scan_run_id = scan_run.id
        host_ids = [h.id for h in active_hosts]
    finally:
        db.close()

    counts = {"ok": 0, "warning": 0, "critical": 0, "unreachable": 0}
    host_runtime_data: dict[int, dict[str, Any]] = {}

    if host_ids:
        workers = min(settings.scan_max_workers, max(1, len(host_ids)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [
                pool.submit(
                    _scan_single_host,
                    hid,
                    scan_run_id,
                    settings.host_timeout_seconds,
                    settings.host_max_retries,
                    session_factory,
                    collector_factory,
                )
                for hid in host_ids
            ]
            for fut in as_completed(futures):
                hid, status, rt = fut.result()
                counts[status] = counts.get(status, 0) + 1
                host_runtime_data[hid] = rt

    db = session_factory()
    try:
        scan_run = db.get(ScanRun, scan_run_id)
        assert scan_run is not None
        scan_run.ok_hosts = counts["ok"]
        scan_run.warning_hosts = counts["warning"]
        scan_run.critical_hosts = counts["critical"]
        scan_run.unreachable_hosts = counts["unreachable"]
        scan_run.status = "completed"
        scan_run.finished_at = datetime.now(timezone.utc)
        db.flush()

        report_rec = generate_scan_report(db, scan_run, host_runtime_data)
        db.commit()
        db.refresh(scan_run)
        send_report_email(db, scan_run, report_rec)
        logger.info(
            "Scan #%d completed: total=%d ok=%d warn=%d crit=%d unreach=%d",
            scan_run.id,
            scan_run.total_hosts,
            scan_run.ok_hosts,
            scan_run.warning_hosts,
            scan_run.critical_hosts,
            scan_run.unreachable_hosts,
            extra={"scan_id": scan_run.id},
        )
        return scan_run
    finally:
        db.close()


def init_scheduler() -> None:
    """Start APScheduler for daily automated scans at configured hour/minute."""
    global _scheduler
    if _scheduler is not None:
        return
    settings = get_settings()
    _scheduler = BackgroundScheduler(timezone="UTC")
    _scheduler.add_job(
        run_full_scan,
        trigger=CronTrigger(hour=settings.scan_cron_hour, minute=settings.scan_cron_minute),
        kwargs={"trigger_type": "scheduled", "triggered_by": "apscheduler"},
        id="daily_soc_scan",
        replace_existing=True,
    )
    _scheduler.start()
    logger.info(
        "APScheduler started: daily scan at %02d:%02d UTC",
        settings.scan_cron_hour,
        settings.scan_cron_minute,
    )


def shutdown_scheduler() -> None:
    """Stop APScheduler cleanly on app shutdown."""
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
