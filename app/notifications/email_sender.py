"""Gmail SMTP email sender for daily SOC reports and structured logs."""

from __future__ import annotations

import logging
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path
from typing import Optional

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.monitoring import Report, ScanRun
from app.models.system import AppSetting
from app.security import SecretCipher

logger = logging.getLogger(__name__)


@dataclass
class EmailConfig:
    """Resolved SMTP configuration (DB AppSetting overrides .env)."""

    enabled: bool
    smtp_host: str
    smtp_port: int
    use_tls: bool
    username: str
    password: str
    recipients: list[str]


def load_email_config(db: Session) -> EmailConfig:
    """Load SMTP settings from AppSetting table, falling back to .env Settings."""
    settings = get_settings()
    rows = {s.key: s.value for s in db.query(AppSetting).all()}

    enabled_raw = rows.get("smtp_enabled", str(settings.smtp_enabled)).lower()
    enabled = enabled_raw in ("true", "1", "yes", "on")

    smtp_host = rows.get("smtp_host") or settings.smtp_host or "smtp.gmail.com"
    try:
        smtp_port = int(rows.get("smtp_port") or settings.smtp_port or 587)
    except ValueError:
        smtp_port = 587

    use_tls_raw = rows.get("smtp_use_tls", str(settings.smtp_use_tls)).lower()
    use_tls = use_tls_raw in ("true", "1", "yes", "on")

    username = rows.get("smtp_user") or settings.smtp_user or ""
    password = settings.smtp_password or ""
    if rows.get("smtp_password_enc"):
        try:
            password = SecretCipher().decrypt(rows["smtp_password_enc"])
        except Exception as exc:
            logger.error("Failed to decrypt stored SMTP password: %s", exc)
            password = ""

    to_raw = rows.get("smtp_to") or settings.smtp_to or ""
    recipients = [addr.strip() for addr in to_raw.split(",") if addr.strip()]

    return EmailConfig(
        enabled=enabled,
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        use_tls=use_tls,
        username=username,
        password=password,
        recipients=recipients,
    )


def _send_mime_message(cfg: EmailConfig, msg: EmailMessage) -> None:
    """Send an EmailMessage using Gmail SMTP (STARTTLS on 587 or SSL on 465)."""
    if not cfg.username or not cfg.password:
        raise ValueError("Gmail SMTP username and App Password are required")
    if not cfg.recipients:
        raise ValueError("At least one recipient email address is required")

    if cfg.smtp_port == 465 and not cfg.use_tls:
        with smtplib.SMTP_SSL(cfg.smtp_host, cfg.smtp_port, timeout=30) as server:
            server.login(cfg.username, cfg.password)
            server.send_message(msg)
    else:
        with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=30) as server:
            server.ehlo()
            if cfg.use_tls:
                server.starttls()
                server.ehlo()
            server.login(cfg.username, cfg.password)
            server.send_message(msg)


def _attach_file(msg: EmailMessage, file_path: Optional[str], maintype: str, subtype: str) -> None:
    if not file_path:
        return
    p = Path(file_path)
    if not p.exists():
        return
    msg.add_attachment(
        p.read_bytes(),
        maintype=maintype,
        subtype=subtype,
        filename=p.name,
    )


def send_report_email(db: Session, scan_run: ScanRun, report: Report) -> bool:
    """Send the generated report (HTML, PDF, JSON) and recent logs via Gmail SMTP."""
    cfg = load_email_config(db)
    if not cfg.enabled:
        return False

    stats = report.summary_stats or {}
    subject = (
        f"[soc-monitor] {report.title} | "
        f"Crit: {stats.get('critical_hosts', 0)} Warn: {stats.get('warning_hosts', 0)} "
        f"Unreach: {stats.get('unreachable_hosts', 0)}"
    )

    msg = EmailMessage()
    msg["From"] = cfg.username
    msg["To"] = ", ".join(cfg.recipients)
    msg["Subject"] = subject

    body_text = (
        f"Reporte diario de monitoreo SOC-Monitor (Scan #{scan_run.id})\n"
        f"Trigger: {scan_run.trigger_type} ({scan_run.triggered_by})\n"
        f"Total Hosts: {stats.get('total_hosts', 0)}\n"
        f"OK: {stats.get('ok_hosts', 0)} | Warning: {stats.get('warning_hosts', 0)} | "
        f"Críticos: {stats.get('critical_hosts', 0)} | Inalcanzables: {stats.get('unreachable_hosts', 0)}\n\n"
        "Se adjuntan:\n"
        "- Reporte estructurado JSON (para análisis automático por IA)\n"
        "- Reporte interactivo HTML\n"
        "- Reporte imprimible PDF (si está disponible)\n"
        "- Extracto reciente de logs de ejecución (soc-monitor.log)\n"
    )
    msg.set_content(body_text)

    _attach_file(msg, report.json_path, "application", "json")
    _attach_file(msg, report.html_path, "text", "html")
    _attach_file(msg, report.pdf_path, "application", "pdf")

    # Attach tail of structured JSON log so AI can correlate scan execution logs
    settings = get_settings()
    log_file = settings.logs_dir / "soc-monitor.log"
    if log_file.exists():
        try:
            lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()[-200:]
            msg.add_attachment(
                "\n".join(lines).encode("utf-8"),
                maintype="text",
                subtype="plain",
                filename=f"soc-monitor-scan-{scan_run.id}.log",
            )
        except OSError:
            pass

    try:
        _send_mime_message(cfg, msg)
        logger.info("Report email sent via %s to %s", cfg.smtp_host, cfg.recipients)
        return True
    except Exception as exc:
        logger.error("Failed to send report email: %s", exc)
        return False


def send_test_email(db: Session) -> tuple[bool, str]:
    """Send a test email using current Gmail SMTP configuration."""
    cfg = load_email_config(db)
    msg = EmailMessage()
    msg["From"] = cfg.username or "soc-monitor@localhost"
    msg["To"] = ", ".join(cfg.recipients)
    msg["Subject"] = "[soc-monitor v2.0] Prueba de conexión Gmail SMTP"
    msg.set_content(
        "Esta es una prueba de notificación desde soc-monitor v2.0.\n"
        "Si recibiste este mensaje, la autenticación SMTP con Gmail funciona correctamente."
    )
    try:
        _send_mime_message(cfg, msg)
        return True, f"Correo de prueba enviado a {', '.join(cfg.recipients)}"
    except Exception as exc:
        return False, f"Error SMTP: {exc}"
