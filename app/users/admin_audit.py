"""Admin users audit: unauthorized admins, >90d inactive, password expiration, and change history."""

from __future__ import annotations

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.collectors.base import HostTelemetry
from app.models.inventory import Host
from app.models.monitoring import Finding
from app.models.security_audit import AdminUserAllowed, AdminUserCurrent, AdminUserHistory


def audit_admin_users(
    db: Session,
    scan_run_id: int,
    host: Host,
    telemetry: HostTelemetry,
) -> list[Finding]:
    """Audit privileged users on a host against authorized list and track history."""
    findings: list[Finding] = []

    # Load allowed admins for host and its group
    allowed_rows = list(
        db.execute(
            select(AdminUserAllowed).where(
                (AdminUserAllowed.host_id == host.id)
                | ((AdminUserAllowed.group_id == host.group_id) & (AdminUserAllowed.host_id.is_(None)))
            )
        ).scalars().all()
    )
    allowed_map = {row.username.lower(): row for row in allowed_rows}

    # Previous observed admins for change history
    prev_rows = list(
        db.execute(select(AdminUserCurrent).where(AdminUserCurrent.host_id == host.id)).scalars().all()
    )
    prev_names = {r.username for r in prev_rows}

    curr_admins = telemetry.admins or []
    curr_names = {str(a.get("username", "")) for a in curr_admins if a.get("username")}

    added = sorted(curr_names - prev_names) if prev_names else []
    removed = sorted(prev_names - curr_names) if prev_names else []

    for uname in added:
        db.add(AdminUserHistory(
            host_id=host.id,
            username=uname,
            change_type="added",
            details=f"Nuevo administrador detectado en {host.hostname}",
        ))
        findings.append(Finding(
            scan_run_id=scan_run_id,
            host_id=host.id,
            check_name="admin_users",
            category="privilege",
            severity="high",
            title=f"Nuevo usuario administrador detectado: {uname}",
            description=f"La cuenta '{uname}' obtuvo privilegios administrativos en {host.hostname}.",
            evidence=f"username={uname}, host={host.hostname}",
            recommendation="Confirmar si el alta fue aprobada mediante ticket de cambio.",
            mitre_id="T1098",
        ))

    for uname in removed:
        db.add(AdminUserHistory(
            host_id=host.id,
            username=uname,
            change_type="removed",
            details=f"Administrador eliminado en {host.hostname}",
        ))
        findings.append(Finding(
            scan_run_id=scan_run_id,
            host_id=host.id,
            check_name="admin_users",
            category="privilege",
            severity="low",
            title=f"Usuario administrador eliminado: {uname}",
            description=f"La cuenta '{uname}' ya no tiene privilegios administrativos en {host.hostname}.",
            evidence=f"username={uname}",
            recommendation="Verificar que la revocación corresponda a baja o cambio autorizado.",
        ))

    # Replace AdminUserCurrent snapshot
    db.execute(delete(AdminUserCurrent).where(AdminUserCurrent.host_id == host.id))

    for adm in curr_admins:
        uname = str(adm.get("username", "")).strip()
        if not uname:
            continue
        priv_src = str(adm.get("privilege_source", "unknown"))
        is_svc = bool(adm.get("is_service_account", False))
        last_days = adm.get("last_login_days")
        pwd_never_exp = bool(adm.get("password_never_expires", False))

        allowed_entry = allowed_map.get(uname.lower())
        is_authorized = allowed_entry is not None

        db.add(AdminUserCurrent(
            host_id=host.id,
            username=uname,
            privilege_source=priv_src,
            is_service_account=is_svc,
            last_login_days=last_days,
            password_never_expires=pwd_never_exp,
            is_authorized=is_authorized,
        ))

        if allowed_rows and not is_authorized:
            findings.append(Finding(
                scan_run_id=scan_run_id,
                host_id=host.id,
                check_name="admin_users",
                category="privilege",
                severity="critical",
                title=f"Administrador NO autorizado: {uname}",
                description=f"La cuenta '{uname}' ({priv_src}) tiene privilegios de admin pero no está en la lista autorizada.",
                evidence=f"username={uname}, source={priv_src}",
                recommendation="Revocar privilegios administrativos de inmediato o agregar a la lista autorizada si es legítima.",
                suggested_command=f"sudo gpasswd -d {uname} wheel" if host.os_type == "linux" else f"Remove-LocalGroupMember -Group 'Administrators' -Member '{uname}'",
                mitre_id="T1136",
            ))

        if is_svc and (not allowed_entry or allowed_entry.account_type != "service"):
            findings.append(Finding(
                scan_run_id=scan_run_id,
                host_id=host.id,
                check_name="admin_users",
                category="privilege",
                severity="high",
                title=f"Cuenta de servicio con privilegios admin: {uname}",
                description=f"La cuenta de servicio '{uname}' posee privilegios administrativos.",
                evidence=f"username={uname}, source={priv_src}",
                recommendation="Aplicar principio de mínimo privilegio y remover permisos de administrador.",
                mitre_id="T1078",
            ))

        if last_days is not None and int(last_days) > 90:
            findings.append(Finding(
                scan_run_id=scan_run_id,
                host_id=host.id,
                check_name="admin_users",
                category="privilege",
                severity="medium",
                title=f"Cuenta admin inactiva >90 días: {uname} ({last_days}d)",
                description=f"La cuenta administrativa '{uname}' no registra inicio de sesión hace {last_days} días.",
                evidence=f"username={uname}, last_login_days={last_days}",
                recommendation="Deshabilitar o eliminar cuentas administrativas inactivas.",
                mitre_id="T1078",
            ))

        if pwd_never_exp:
            findings.append(Finding(
                scan_run_id=scan_run_id,
                host_id=host.id,
                check_name="admin_users",
                category="privilege",
                severity="medium",
                title=f"Cuenta admin sin expiración de contraseña: {uname}",
                description=f"La cuenta '{uname}' tiene configurada contraseña que nunca expira.",
                evidence=f"username={uname}, password_never_expires=True",
                recommendation="Habilitar política de rotación/expiración de contraseñas.",
            ))

    db.flush()
    return findings
