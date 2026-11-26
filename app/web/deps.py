"""Web dependencies: authentication, RBAC, audit logging, and Jinja2 templates."""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.system import AuditLog, SystemUser
from app.security import decode_access_token

TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

SESSION_COOKIE_NAME = "soc_monitor_session"


def get_current_user_optional(request: Request, db: Session = Depends(get_db)) -> Optional[SystemUser]:
    """Return authenticated SystemUser from session cookie, or None."""
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None
    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        return None
    user = db.execute(
        select(SystemUser).where(SystemUser.username == payload["sub"], SystemUser.is_active.is_(True))
    ).scalar_one_or_none()
    return user


def get_current_user(
    request: Request,
    user: Optional[SystemUser] = Depends(get_current_user_optional),
) -> SystemUser:
    """Require an authenticated user; redirect browsers to /login or return 401."""
    if user is None:
        accept = request.headers.get("accept", "")
        if "text/html" in accept:
            raise HTTPException(
                status_code=status.HTTP_303_SEE_OTHER,
                headers={"Location": "/login"},
            )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return user


def require_role(*allowed_roles: str) -> Callable[[SystemUser], SystemUser]:
    """Dependency enforcing RBAC roles (admin, operador, lector)."""

    def _checker(user: SystemUser = Depends(get_current_user)) -> SystemUser:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Rol '{user.role}' no autorizado para esta operación",
            )
        return user

    return _checker


def record_audit(
    db: Session,
    actor: str,
    action: str,
    target_type: str,
    target_id: Optional[str] = None,
    details: Optional[str] = None,
    request: Optional[Request] = None,
) -> None:
    """Persist an entry in audit_log."""
    ip_addr = request.client.host if (request and request.client) else None
    db.add(AuditLog(
        actor=actor,
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        details=details,
        ip_address=ip_addr,
    ))
