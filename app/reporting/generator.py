"""Report generator producing interactive HTML, PDF (WeasyPrint), and LLM-ready JSON."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.inventory import Host
from app.models.monitoring import CheckResult, Finding, Report, ScanRun

logger = logging.getLogger(__name__)

_SEVERITY_ES = {
    "critical": "crítica",
    "high": "alta",
    "medium": "media",
    "low": "baja",
}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_jinja_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=select_autoescape(["html", "xml"]),
)


def generate_scan_report(
    db: Session,
    scan_run: ScanRun,
    host_runtime_data: dict[int, dict[str, Any]],
    output_dir: Optional[Path] = None,
) -> Report:
    """Generate HTML, PDF, and structured JSON reports for a completed ScanRun."""
    settings = get_settings()
    reports_dir = output_dir or settings.reports_dir
    reports_dir.mkdir(parents=True, exist_ok=True)

    ts_label = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base_name = f"soc_report_{scan_run.id}_{ts_label}"

    hosts = {h.id: h for h in db.execute(select(Host)).scalars().all()}
    findings_rows = list(
        db.execute(select(Finding).where(Finding.scan_run_id == scan_run.id)).scalars().all()
    )
    findings_rows.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))

    check_rows = list(
        db.execute(select(CheckResult).where(CheckResult.scan_run_id == scan_run.id)).scalars().all()
    )
    checks_by_host: dict[int, dict[str, CheckResult]] = {}
    for cr in check_rows:
        checks_by_host.setdefault(cr.host_id, {})[cr.check_name] = cr

    json_findings: list[dict[str, Any]] = []
    for f in findings_rows:
        host_obj = hosts.get(f.host_id)
        group_name = host_obj.group.name if (host_obj and host_obj.group) else "default"
        json_findings.append({
            "id": f.id,
            "timestamp": f.created_at.isoformat() if f.created_at else datetime.now(timezone.utc).isoformat(),
            "host": host_obj.hostname if host_obj else f"host-{f.host_id}",
            "grupo": group_name,
            "check": f.check_name,
            "categoria": f.category,
            "severidad": _SEVERITY_ES.get(f.severity, f.severity),
            "severidad_raw": f.severity,
            "titulo": f.title,
            "descripcion": f.description,
            "evidencia": f.evidence,
            "recomendacion": f.recommendation,
            "comando_sugerido": f.suggested_command,
            "mitre_id": f.mitre_id,
            "estado": f.status,
        })

    host_sections: list[dict[str, Any]] = []
    drifts: list[dict[str, Any]] = []
    for host_id, rt in host_runtime_data.items():
        h = hosts.get(host_id)
        if not h:
            continue
        h_checks = checks_by_host.get(host_id, {})
        cpu_m = h_checks.get("cpu").metric_value if "cpu" in h_checks else 0.0
        mem_c = h_checks.get("memory")
        mem_m = mem_c.metric_value if mem_c else 0.0
        swap_m = (mem_c.details or {}).get("swap_pct", 0.0) if mem_c else 0.0
        disk_m = h_checks.get("filesystem").metric_value if "filesystem" in h_checks else 0.0
        log_err = int(h_checks.get("logs").metric_value or 0) if "logs" in h_checks else 0

        host_sections.append({
            "hostname": h.hostname,
            "ip_address": h.ip_address,
            "os_type": h.os_type,
            "status": h.last_status,
            "cpu_pct": round(cpu_m or 0.0, 1),
            "mem_pct": round(mem_m or 0.0, 1),
            "swap_pct": round(float(swap_m or 0.0), 1),
            "disk_pct": round(disk_m or 0.0, 1),
            "admins_count": rt.get("admins_count", 0),
            "log_errors": log_err,
            "ports_table": rt.get("ports_table", []),
        })
        drift = rt.get("drift")
        if drift and drift.get("has_drift"):
            drifts.append({"hostname": h.hostname, **drift})

    duration_sec = 0.0
    if scan_run.finished_at and scan_run.started_at:
        fin = scan_run.finished_at if scan_run.finished_at.tzinfo else scan_run.finished_at.replace(tzinfo=timezone.utc)
        sta = scan_run.started_at if scan_run.started_at.tzinfo else scan_run.started_at.replace(tzinfo=timezone.utc)
        duration_sec = round((fin - sta).total_seconds(), 2)

    exec_summary = (
        f"Se escanearon {scan_run.total_hosts} servidores: {scan_run.ok_hosts} en estado OK, "
        f"{scan_run.warning_hosts} con advertencias, {scan_run.critical_hosts} en estado crítico y "
        f"{scan_run.unreachable_hosts} inalcanzables. Se registraron {len(json_findings)} hallazgos totales."
    )

    report_payload = {
        "title": f"Reporte Diario SOC-Monitor ({ts_label})",
        "scan_run_id": scan_run.id,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "duration_seconds": duration_sec,
        "summary": {
            "total_hosts": scan_run.total_hosts,
            "ok_hosts": scan_run.ok_hosts,
            "warning_hosts": scan_run.warning_hosts,
            "critical_hosts": scan_run.critical_hosts,
            "unreachable_hosts": scan_run.unreachable_hosts,
        },
        "executive_summary": exec_summary,
        "top_findings": json_findings[:10],
        "findings": json_findings,
        "categories": sorted({f["categoria"] for f in json_findings}),
        "hosts": host_sections,
        "drifts": drifts,
        "soc_recommendations": [f for f in json_findings if f["severidad_raw"] in ("critical", "high")][:25],
    }

    # 1. Write structured JSON for LLM (Gemini / Meta AI)
    json_path = reports_dir / f"{base_name}.json"
    json_path.write_text(json.dumps(report_payload, indent=2, ensure_ascii=False), encoding="utf-8")

    # 2. Write interactive HTML
    template = _jinja_env.get_template("report_template.html")
    html_content = template.render(report=report_payload)
    html_path = reports_dir / f"{base_name}.html"
    html_path.write_text(html_content, encoding="utf-8")

    # 3. Write PDF via WeasyPrint
    pdf_path = reports_dir / f"{base_name}.pdf"
    pdf_path_str: Optional[str] = None
    try:
        from weasyprint import HTML

        HTML(string=html_content).write_pdf(str(pdf_path))
        pdf_path_str = str(pdf_path)
    except Exception as exc:
        logger.warning("WeasyPrint PDF generation failed (check system Pango/Cairo libs): %s", exc)

    report_rec = Report(
        scan_run_id=scan_run.id,
        title=report_payload["title"],
        html_path=str(html_path),
        pdf_path=pdf_path_str,
        json_path=str(json_path),
        summary_stats=report_payload["summary"],
    )
    db.add(report_rec)
    db.flush()
    return report_rec
