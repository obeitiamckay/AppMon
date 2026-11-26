"""Authentication routes with rate limiting, lockout, and secure JWT cookies."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.models.system import SystemUser
from app.security import create_access_token, login_rate_limiter, verify_password
from app.web.deps import SESSION_COOKIE_NAME, record_audit, templates

router = APIRouter(tags=["auth"])

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"error": None})


@router.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    client_ip = request.client.host if request.client else "unknown"
    if not login_rate_limiter.is_allowed(client_ip):
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Demasiados intentos desde esta IP. Intente nuevamente en unos minutos."},
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        )

    login_rate_limiter.record_attempt(client_ip)
    user = db.execute(select(SystemUser).where(SystemUser.username == username.strip())).scalar_one_or_none()
    now = datetime.now(timezone.utc)

    if user and user.locked_until and user.locked_until > now:
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Cuenta bloqueada temporalmente por intentos fallidos."},
            status_code=status.HTTP_403_FORBIDDEN,
        )

    if not user or not user.is_active or not verify_password(password, user.password_hash):
        if user:
            user.failed_attempts += 1
            if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
                user.locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)
                record_audit(db, user.username, "account_locked", "system_user", str(user.id), "Max failed logins", request)
            db.commit()
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Usuario o contraseña inválidos."},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    user.failed_attempts = 0
    user.locked_until = None
    user.last_login_at = now
    record_audit(db, user.username, "login_success", "system_user", str(user.id), None, request)
    db.commit()
    login_rate_limiter.reset(client_ip)

    token = create_access_token(subject=user.username, role=user.role)
    settings = get_settings()
    resp = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    resp.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=settings.cookie_secure and settings.app_env == "production",
        samesite="lax",
        max_age=settings.session_expire_minutes * 60,
    )
    return resp


@router.post("/logout")
def logout():
    resp = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    resp.delete_cookie(SESSION_COOKIE_NAME)
    return resp
