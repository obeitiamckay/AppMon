"""Main operational web console routes."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.discovery.baseline_service import approve_new_baseline, get_active_baseline
from app.models.inventory import CredentialRef, Host, HostGroup, Threshold
from app.models.monitoring import Baseline, Finding, Report, ScanRun
from app.models.security_audit import (
    AdminUserAllowed,
    AdminUserCurrent,
    AdminUserHistory,
    FirewallAllowedRule,
)
from app.models.system import SystemUser
from app.scheduler.runner import build_collector, run_full_scan
from app.security import SecretCipher
from app.web.deps import get_current_user, record_audit, require_role, templates

router = APIRouter(tags=["console"])


@router.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    user: SystemUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    hosts = list(db.execute(select(Host)).scalars().all())
    last_scan = db.execute(select(ScanRun).order_by(ScanRun.id.desc()).limit(1)).scalar_one_or_none()
    recent_findings = list(
        db.execute(select(Finding).order_by(Finding.id.desc()).limit(15)).scalars().all()
    )
    status_counts = {
        "total": len(hosts),
        "ok": sum(1 for h in hosts if h.last_status == "ok"),
        "warning": sum(1 for h in hosts if h.last_status == "warning"),
        "critical": sum(1 for h in hosts if h.last_status == "critical"),
        "unreachable": sum(1 for h in hosts if h.last_status == "unreachable"),
    }
    problem_hosts = [h for h in hosts if h.last_status in ("critical", "warning", "unreachable")]
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "user": user,
            "stats": status_counts,
            "last_scan": last_scan,
            "problem_hosts": problem_hosts,
            "recent_findings": recent_findings,
        },
    )


@router.post("/scans/run")
def trigger_manual_scan(
    request: Request,
    user: SystemUser = Depends(require_role("admin", "operador")),
    db: Session = Depends(get_db),
):
    record_audit(db, user.username, "trigger_manual_scan", "scan_run", None, "Manual scan started", request)
    db.commit()
    threading.Thread(
        target=run_full_scan,
        kwargs={"trigger_type": "manual", "triggered_by": user.username},
        daemon=True,
    ).start()
    return RedirectResponse(url="/reports", status_code=status.HTTP_303_SEE_OTHER)


# --- INVENTORY & CREDENTIALS ---

@router.get("/inventory", response_class=HTMLResponse)
def inventory_page(
    request: Request,
    msg: Optional[str] = None,
    user: SystemUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    hosts = list(db.execute(select(Host).order_by(Host.hostname)).scalars().all())
    groups = list(db.execute(select(HostGroup).order_by(HostGroup.name)).scalars().all())
    creds = list(db.execute(select(CredentialRef).order_by(CredentialRef.name)).scalars().all())
    return templates.TemplateResponse(
        request,
        "inventory.html",
        {"user": user, "hosts": hosts, "groups": groups, "creds": creds, "msg": msg},
    )


@router.post("/inventory/hosts")
def create_host(
    request: Request,
    hostname: str = Form(...),
    ip_address: str = Form(...),
    os_type: str = Form(...),
    port: int = Form(22),
    group_id: Optional[int] = Form(None),
    credential_id: Optional[int] = Form(None),
    scan_interval_minutes: int = Form(1440),
    user: SystemUser = Depends(require_role("admin", "operador")),
    db: Session = Depends(get_db),
):
    host = Host(
        hostname=hostname.strip(),
        ip_address=ip_address.strip(),
        os_type=os_type.strip().lower(),
        port=port,
        group_id=group_id or None,
        credential_id=credential_id or None,
        scan_interval_minutes=scan_interval_minutes,
        is_active=True,
    )
    db.add(host)
    db.flush()
    record_audit(db, user.username, "create_host", "host", str(host.id), f"hostname={host.hostname}", request)
    db.commit()
    return RedirectResponse(url="/inventory?msg=Host+creado", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/inventory/hosts/{host_id}/toggle")
def toggle_host(
    request: Request,
    host_id: int,
    user: SystemUser = Depends(require_role("admin", "operador")),
    db: Session = Depends(get_db),
):
    host = db.get(Host, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host no encontrado")
    host.is_active = not host.is_active
    record_audit(db, user.username, "toggle_host", "host", str(host.id), f"is_active={host.is_active}", request)
    db.commit()
    return RedirectResponse(url="/inventory", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/inventory/hosts/{host_id}/delete")
def delete_host(
    request: Request,
    host_id: int,
    user: SystemUser = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    host = db.get(Host, host_id)
    if host:
        record_audit(db, user.username, "delete_host", "host", str(host.id), f"hostname={host.hostname}", request)
        db.delete(host)
        db.commit()
    return RedirectResponse(url="/inventory", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/inventory/hosts/{host_id}/test")
def test_host_connection(
    request: Request,
    host_id: int,
    user: SystemUser = Depends(require_role("admin", "operador")),
    db: Session = Depends(get_db),
):
    host = db.get(Host, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host no encontrado")
    try:
        collector = build_collector(host, host.credential, timeout_seconds=15)
        ok, message = collector.test_connection()
        status_txt = "OK" if ok else "ERROR"
    except Exception as exc:
        status_txt = "ERROR"
        message = str(exc)
    record_audit(db, user.username, "test_connection", "host", str(host.id), f"{status_txt}: {message[:120]}", request)
    db.commit()
    return RedirectResponse(url=f"/inventory?msg={status_txt}:+{message[:80]}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/inventory/credentials")
def create_credential(
    request: Request,
    name: str = Form(...),
    auth_type: str = Form(...),
    username: str = Form(...),
    secret: str = Form(""),
    passphrase: str = Form(""),
    vault_path: str = Form(""),
    user: SystemUser = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    cipher = SecretCipher()
    cred = CredentialRef(
        name=name.strip(),
        auth_type=auth_type.strip(),
        username=username.strip(),
        encrypted_secret=cipher.encrypt(secret) if secret else None,
        encrypted_passphrase=cipher.encrypt(passphrase) if passphrase else None,
        vault_path=vault_path.strip() or None,
    )
    db.add(cred)
    db.flush()
    record_audit(db, user.username, "create_credential", "credential", str(cred.id), f"name={cred.name}", request)
    db.commit()
    return RedirectResponse(url="/inventory?msg=Credencial+guardada", status_code=status.HTTP_303_SEE_OTHER)


# --- GROUPS & THRESHOLDS ---

@router.get("/groups", response_class=HTMLResponse)
def groups_page(
    request: Request,
    user: SystemUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    groups = list(db.execute(select(HostGroup).order_by(HostGroup.name)).scalars().all())
    thresholds = list(db.execute(select(Threshold)).scalars().all())
    hosts = list(db.execute(select(Host).order_by(Host.hostname)).scalars().all())
    return templates.TemplateResponse(
        request,
        "groups.html",
        {"user": user, "groups": groups, "thresholds": thresholds, "hosts": hosts},
    )


@router.post("/groups")
def create_group(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    scan_schedule: str = Form("02:00"),
    user: SystemUser = Depends(require_role("admin", "operador")),
    db: Session = Depends(get_db),
):
    grp = HostGroup(name=name.strip(), description=description.strip(), scan_schedule=scan_schedule.strip())
    db.add(grp)
    db.flush()
    record_audit(db, user.username, "create_group", "host_group", str(grp.id), f"name={grp.name}", request)
    db.commit()
    return RedirectResponse(url="/groups", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/groups/thresholds")
def upsert_threshold(
    request: Request,
    group_id: Optional[int] = Form(None),
    host_id: Optional[int] = Form(None),
    metric_name: str = Form(...),
    warning_value: float = Form(...),
    critical_value: float = Form(...),
    sustained_minutes: int = Form(0),
    user: SystemUser = Depends(require_role("admin", "operador")),
    db: Session = Depends(get_db),
):
    gid = group_id if group_id else None
    hid = host_id if host_id else None
    existing = db.execute(
        select(Threshold).where(
            Threshold.group_id == gid,
            Threshold.host_id == hid,
            Threshold.metric_name == metric_name,
        )
    ).scalar_one_or_none()
    if existing:
        existing.warning_value = warning_value
        existing.critical_value = critical_value
        existing.sustained_minutes = sustained_minutes
    else:
        db.add(Threshold(
            group_id=gid,
            host_id=hid,
            metric_name=metric_name,
            warning_value=warning_value,
            critical_value=critical_value,
            sustained_minutes=sustained_minutes,
        ))
    record_audit(
        db,
        user.username,
        "upsert_threshold",
        "threshold",
        metric_name,
        f"group={gid}, host={hid}, warn={warning_value}, crit={critical_value}",
        request,
    )
    db.commit()
    return RedirectResponse(url="/groups", status_code=status.HTTP_303_SEE_OTHER)


# --- FIREWALL RULES ---

@router.get("/firewall", response_class=HTMLResponse)
def firewall_page(
    request: Request,
    user: SystemUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rules = list(db.execute(select(FirewallAllowedRule)).scalars().all())
    groups = list(db.execute(select(HostGroup).order_by(HostGroup.name)).scalars().all())
    return templates.TemplateResponse(
        request,
        "firewall.html",
        {"user": user, "rules": rules, "groups": groups},
    )


@router.post("/firewall/rules")
def create_firewall_rule(
    request: Request,
    group_id: int = Form(...),
    port: int = Form(...),
    protocol: str = Form("tcp"),
    allowed_sources: str = Form("10.0.0.0/8"),
    description: str = Form(""),
    user: SystemUser = Depends(require_role("admin", "operador")),
    db: Session = Depends(get_db),
):
    rule = FirewallAllowedRule(
        group_id=group_id,
        port=port,
        protocol=protocol.lower(),
        allowed_sources=allowed_sources.strip(),
        description=description.strip(),
        is_enabled=True,
    )
    db.add(rule)
    db.flush()
    record_audit(db, user.username, "create_fw_rule", "firewall_rule", str(rule.id), f"port={port}/{protocol}", request)
    db.commit()
    return RedirectResponse(url="/firewall", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/firewall/rules/{rule_id}/delete")
def delete_firewall_rule(
    request: Request,
    rule_id: int,
    user: SystemUser = Depends(require_role("admin", "operador")),
    db: Session = Depends(get_db),
):
    rule = db.get(FirewallAllowedRule, rule_id)
    if rule:
        record_audit(db, user.username, "delete_fw_rule", "firewall_rule", str(rule.id), f"port={rule.port}", request)
        db.delete(rule)
        db.commit()
    return RedirectResponse(url="/firewall", status_code=status.HTTP_303_SEE_OTHER)


# --- ADMIN USERS AUDIT ---

@router.get("/admins", response_class=HTMLResponse)
def admins_page(
    request: Request,
    user: SystemUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    allowed = list(db.execute(select(AdminUserAllowed)).scalars().all())
    current = list(db.execute(select(AdminUserCurrent)).scalars().all())
    history = list(db.execute(select(AdminUserHistory).order_by(AdminUserHistory.id.desc()).limit(50)).scalars().all())
    groups = list(db.execute(select(HostGroup).order_by(HostGroup.name)).scalars().all())
    hosts = list(db.execute(select(Host).order_by(Host.hostname)).scalars().all())
    return templates.TemplateResponse(
        request,
        "admins.html",
        {
            "user": user,
            "allowed": allowed,
            "current": current,
            "history": history,
            "groups": groups,
            "hosts": hosts,
        },
    )


@router.post("/admins/allowed")
def create_allowed_admin(
    request: Request,
    username: str = Form(...),
    account_type: str = Form("human"),
    group_id: Optional[int] = Form(None),
    host_id: Optional[int] = Form(None),
    notes: str = Form(""),
    user: SystemUser = Depends(require_role("admin", "operador")),
    db: Session = Depends(get_db),
):
    entry = AdminUserAllowed(
        username=username.strip(),
        account_type=account_type,
        group_id=group_id or None,
        host_id=host_id or None,
        notes=notes.strip() or None,
    )
    db.add(entry)
    db.flush()
    record_audit(db, user.username, "add_allowed_admin", "admin_allowed", str(entry.id), f"username={username}", request)
    db.commit()
    return RedirectResponse(url="/admins", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/admins/allowed/{entry_id}/delete")
def delete_allowed_admin(
    request: Request,
    entry_id: int,
    user: SystemUser = Depends(require_role("admin", "operador")),
    db: Session = Depends(get_db),
):
    entry = db.get(AdminUserAllowed, entry_id)
    if entry:
        record_audit(db, user.username, "delete_allowed_admin", "admin_allowed", str(entry.id), f"username={entry.username}", request)
        db.delete(entry)
        db.commit()
    return RedirectResponse(url="/admins", status_code=status.HTTP_303_SEE_OTHER)


# --- BASELINES ---

@router.get("/baselines", response_class=HTMLResponse)
def baselines_page(
    request: Request,
    user: SystemUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    hosts = list(db.execute(select(Host).order_by(Host.hostname)).scalars().all())
    baselines = list(db.execute(select(Baseline).where(Baseline.is_active.is_(True))).scalars().all())
    baseline_map = {b.host_id: b for b in baselines}
    return templates.TemplateResponse(
        request,
        "baselines.html",
        {"user": user, "hosts": hosts, "baseline_map": baseline_map},
    )


@router.post("/baselines/{host_id}/approve")
def approve_baseline_route(
    request: Request,
    host_id: int,
    user: SystemUser = Depends(require_role("admin", "operador")),
    db: Session = Depends(get_db),
):
    host = db.get(Host, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host no encontrado")
    collector = build_collector(host, host.credential, timeout_seconds=30)
    telemetry = collector.collect_all()
    new_base = approve_new_baseline(
        db,
        host_id=host.id,
        telemetry_dict={
            "os_info": telemetry.os_info,
            "services": telemetry.services,
            "ports": telemetry.ports,
            "filesystems": telemetry.filesystems,
            "logs_inventory": telemetry.logs_inventory,
            "firewall": telemetry.firewall,
            "admins": telemetry.admins,
        },
        approved_by=user.username,
    )
    record_audit(db, user.username, "approve_baseline", "baseline", str(new_base.id), f"host={host.hostname}, v={new_base.version}", request)
    db.commit()
    return RedirectResponse(url="/baselines", status_code=status.HTTP_303_SEE_OTHER)


# --- REPORTS ---

@router.get("/reports", response_class=HTMLResponse)
def reports_page(
    request: Request,
    user: SystemUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    reports = list(db.execute(select(Report).order_by(Report.id.desc()).limit(50)).scalars().all())
    scans = list(db.execute(select(ScanRun).order_by(ScanRun.id.desc()).limit(20)).scalars().all())
    return templates.TemplateResponse(
        request,
        "reports.html",
        {"user": user, "reports": reports, "scans": scans},
    )


@router.get("/reports/{report_id}/download/{fmt}")
def download_report(
    report_id: int,
    fmt: str,
    user: SystemUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")
    path_map = {
        "html": (report.html_path, "text/html"),
        "pdf": (report.pdf_path, "application/pdf"),
        "json": (report.json_path, "application/json"),
    }
    if fmt not in path_map:
        raise HTTPException(status_code=400, detail="Formato inválido")
    file_path_str, media_type = path_map[fmt]
    if not file_path_str or not Path(file_path_str).exists():
        raise HTTPException(status_code=404, detail=f"Archivo {fmt.upper()} no disponible")
    if fmt == "html":
        return HTMLResponse(content=Path(file_path_str).read_text(encoding="utf-8"))
    return FileResponse(path=file_path_str, media_type=media_type, filename=Path(file_path_str).name)
