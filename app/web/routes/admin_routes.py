"""Settings, JSON/YAML config export/import, system users CRUD, and audit log routes."""

from __future__ import annotations

import json
from typing import Any

import yaml
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import HTMLResponse, Response, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.inventory import HostGroup, Threshold
from app.models.security_audit import AdminUserAllowed, FirewallAllowedRule
from app.models.system import AppSetting, AuditLog, SystemUser
from app.security import hash_password
from app.web.deps import get_current_user, record_audit, require_role, templates

router = APIRouter(tags=["admin"])


@router.get("/settings", response_class=HTMLResponse)
def settings_page(
    request: Request,
    user: SystemUser = Depends(require_role("admin", "operador")),
    db: Session = Depends(get_db),
):
    rows = {s.key: s.value for s in db.execute(select(AppSetting)).scalars().all()}
    return templates.TemplateResponse(request, "settings.html", {"user": user, "settings": rows})


@router.post("/settings")
def update_settings(
    request: Request,
    retention_days: str = Form("90"),
    smtp_host: str = Form(""),
    smtp_to: str = Form(""),
    scan_hour: str = Form("2"),
    user: SystemUser = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    updates = {
        "retention_days": retention_days.strip(),
        "smtp_host": smtp_host.strip(),
        "smtp_to": smtp_to.strip(),
        "scan_hour": scan_hour.strip(),
    }
    for k, v in updates.items():
        row = db.get(AppSetting, k)
        if row:
            row.value = v
        else:
            db.add(AppSetting(key=k, value=v))
    record_audit(db, user.username, "update_settings", "app_settings", None, str(updates), request)
    db.commit()
    return RedirectResponse(url="/settings", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/settings/export/{fmt}")
def export_configuration(
    fmt: str,
    user: SystemUser = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    groups = list(db.execute(select(HostGroup)).scalars().all())
    thresholds = list(db.execute(select(Threshold)).scalars().all())
    fw_rules = list(db.execute(select(FirewallAllowedRule)).scalars().all())
    admins = list(db.execute(select(AdminUserAllowed)).scalars().all())
    settings_rows = list(db.execute(select(AppSetting)).scalars().all())

    payload: dict[str, Any] = {
        "groups": [{"name": g.name, "description": g.description, "scan_schedule": g.scan_schedule} for g in groups],
        "thresholds": [
            {
                "group": g_name(db, t.group_id),
                "metric_name": t.metric_name,
                "warning_value": t.warning_value,
                "critical_value": t.critical_value,
                "sustained_minutes": t.sustained_minutes,
            }
            for t in thresholds
        ],
        "firewall_allowed_rules": [
            {
                "group": g_name(db, r.group_id),
                "port": r.port,
                "protocol": r.protocol,
                "allowed_sources": r.allowed_sources,
                "description": r.description,
                "is_enabled": r.is_enabled,
            }
            for r in fw_rules
        ],
        "admin_users_allowed": [
            {
                "group": g_name(db, a.group_id),
                "username": a.username,
                "account_type": a.account_type,
                "notes": a.notes,
            }
            for a in admins
        ],
        "app_settings": {s.key: s.value for s in settings_rows},
    }

    if fmt == "yaml":
        content = yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)
        return Response(content=content, media_type="application/x-yaml", headers={"Content-Disposition": "attachment; filename=soc-monitor-config.yaml"})
    content = json.dumps(payload, indent=2, ensure_ascii=False)
    return Response(content=content, media_type="application/json", headers={"Content-Disposition": "attachment; filename=soc-monitor-config.json"})


def g_name(db: Session, group_id: int | None) -> str | None:
    if not group_id:
        return None
    g = db.get(HostGroup, group_id)
    return g.name if g else None


@router.post("/settings/import")
async def import_configuration(
    request: Request,
    file: UploadFile = File(...),
    user: SystemUser = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    raw = (await file.read()).decode("utf-8")
    data = yaml.safe_load(raw) if file.filename and file.filename.endswith((".yml", ".yaml")) else json.loads(raw)

    group_cache: dict[str, HostGroup] = {
        g.name: g for g in db.execute(select(HostGroup)).scalars().all()
    }
    for g in data.get("groups", []):
        if g["name"] not in group_cache:
            obj = HostGroup(name=g["name"], description=g.get("description"), scan_schedule=g.get("scan_schedule", "02:00"))
            db.add(obj)
            db.flush()
            group_cache[obj.name] = obj

    for k, v in data.get("app_settings", {}).items():
        row = db.get(AppSetting, k)
        if row:
            row.value = str(v)
        else:
            db.add(AppSetting(key=k, value=str(v)))

    record_audit(db, user.username, "import_config", "app_settings", None, f"file={file.filename}", request)
    db.commit()
    return RedirectResponse(url="/settings", status_code=status.HTTP_303_SEE_OTHER)


# --- SYSTEM USERS & AUDIT LOG ---

@router.get("/users", response_class=HTMLResponse)
def users_page(
    request: Request,
    user: SystemUser = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    users = list(db.execute(select(SystemUser).order_by(SystemUser.username)).scalars().all())
    return templates.TemplateResponse(request, "users.html", {"user": user, "users": users})


@router.post("/users")
def create_system_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form("lector"),
    user: SystemUser = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    if role not in ("admin", "operador", "lector"):
        raise HTTPException(status_code=400, detail="Rol inválido")
    new_u = SystemUser(
        username=username.strip(),
        password_hash=hash_password(password),
        role=role,
        is_active=True,
    )
    db.add(new_u)
    db.flush()
    record_audit(db, user.username, "create_system_user", "system_user", str(new_u.id), f"username={username}, role={role}", request)
    db.commit()
    return RedirectResponse(url="/users", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/users/{uid}/toggle")
def toggle_system_user(
    request: Request,
    uid: int,
    user: SystemUser = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    target = db.get(SystemUser, uid)
    if target and target.id != user.id:
        target.is_active = not target.is_active
        record_audit(db, user.username, "toggle_system_user", "system_user", str(uid), f"is_active={target.is_active}", request)
        db.commit()
    return RedirectResponse(url="/users", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/audit", response_class=HTMLResponse)
def audit_page(
    request: Request,
    user: SystemUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    logs = list(db.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(100)).scalars().all())
    return templates.TemplateResponse(request, "audit.html", {"user": user, "logs": logs})
