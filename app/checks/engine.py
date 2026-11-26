"""Check evaluation engine producing CheckResult and deduplicated Finding records."""

from __future__ import annotations

import hashlib
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks.thresholds import EffectiveThreshold, resolve_host_thresholds
from app.collectors.base import HostTelemetry
from app.models.inventory import Host
from app.models.monitoring import Baseline, CheckResult, Finding


def _make_fingerprint(host_id: int, check_name: str, key: str) -> str:
    raw = f"{host_id}:{check_name}:{key}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _get_previous_filesystem_map(db: Session, host_id: int, current_scan_id: int) -> dict[str, float]:
    stmt = (
        select(CheckResult)
        .where(
            CheckResult.host_id == host_id,
            CheckResult.check_name == "filesystem",
            CheckResult.scan_run_id != current_scan_id,
        )
        .order_by(CheckResult.checked_at.desc())
        .limit(1)
    )
    prev = db.execute(stmt).scalar_one_or_none()
    if not prev or not prev.details:
        return {}
    return {
        fs.get("mount", ""): float(fs.get("usage_pct", 0.0))
        for fs in prev.details.get("filesystems", [])
        if fs.get("mount")
    }


def evaluate_host_checks(
    db: Session,
    scan_run_id: int,
    host: Host,
    telemetry: HostTelemetry,
    baseline: Optional[Baseline],
    drift: Optional[dict[str, Any]] = None,
) -> tuple[list[CheckResult], list[Finding]]:
    """Run all daily checks on telemetry and return CheckResults and Findings."""
    thresholds = resolve_host_thresholds(db, host)
    results: list[CheckResult] = []
    findings: list[Finding] = []
    seen_fingerprints: dict[str, Finding] = {}

    def add_finding(
        check_name: str,
        category: str,
        severity: str,
        title: str,
        description: str,
        evidence: str,
        recommendation: str,
        suggested_command: Optional[str] = None,
        mitre_id: Optional[str] = None,
        dedup_key: str = "",
    ) -> None:
        fp = _make_fingerprint(host.id, check_name, dedup_key or title)
        if fp in seen_fingerprints:
            seen_fingerprints[fp].occurrences += 1
            return
        f = Finding(
            scan_run_id=scan_run_id,
            host_id=host.id,
            check_name=check_name,
            category=category,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            recommendation=recommendation,
            suggested_command=suggested_command,
            mitre_id=mitre_id,
            fingerprint=fp,
            occurrences=1,
        )
        seen_fingerprints[fp] = f
        findings.append(f)

    # 1. Availability & Latency
    lat_th = thresholds["latency_ms"]
    lat_status = "ok"
    if not telemetry.reachable:
        lat_status = "critical"
        add_finding(
            check_name="availability",
            category="availability",
            severity="critical",
            title=f"Host unreachable: {host.hostname}",
            description=f"No se pudo conectar con {host.hostname} ({host.ip_address}:{host.port}).",
            evidence=telemetry.error_message or "Connection timeout / error",
            recommendation="Verificar estado del servidor, conectividad de red, firewall y servicio SSH/WinRM.",
            suggested_command=f"nc -zv {host.ip_address} {host.port}",
            dedup_key="unreachable",
        )
        results.append(CheckResult(
            scan_run_id=scan_run_id,
            host_id=host.id,
            check_name="availability",
            status=lat_status,
            metric_value=None,
            details={"reachable": False, "error": telemetry.error_message},
        ))
        return results, findings

    if telemetry.latency_ms >= lat_th.critical:
        lat_status = "critical"
        add_finding(
            check_name="availability",
            category="availability",
            severity="high",
            title=f"Latencia crítica en {host.hostname} ({telemetry.latency_ms} ms)",
            description="La latencia de conexión supera el umbral crítico configurado.",
            evidence=f"latency_ms={telemetry.latency_ms} (umbral={lat_th.critical} ms)",
            recommendation="Revisar saturación de red o carga extrema en el host destino.",
            suggested_command=f"mtr -r -c 5 {host.ip_address}",
            dedup_key="high_latency",
        )
    elif telemetry.latency_ms >= lat_th.warning:
        lat_status = "warning"
    results.append(CheckResult(
        scan_run_id=scan_run_id,
        host_id=host.id,
        check_name="availability",
        status=lat_status,
        metric_value=telemetry.latency_ms,
        details={"reachable": True, "latency_ms": telemetry.latency_ms},
    ))

    # 2. Filesystem
    disk_th = thresholds["disk_pct"]
    inode_th = thresholds["disk_inode_pct"]
    prev_fs = _get_previous_filesystem_map(db, host.id, scan_run_id)
    max_disk_pct = 0.0
    fs_status = "ok"
    enriched_fs: list[dict[str, Any]] = []
    for fs in telemetry.filesystems:
        mount = fs.get("mount", "/")
        pct = float(fs.get("usage_pct", 0.0))
        inode_pct = float(fs.get("inode_pct", 0.0))
        growth = round(pct - prev_fs[mount], 2) if mount in prev_fs else 0.0
        enriched_fs.append({**fs, "growth_pct": growth})
        max_disk_pct = max(max_disk_pct, pct)

        if pct >= disk_th.critical:
            fs_status = "critical"
            add_finding(
                check_name="filesystem",
                category="capacity",
                severity="critical",
                title=f"Filesystem crítico {mount} al {pct}%",
                description=f"El punto de montaje {mount} en {host.hostname} superó el umbral crítico ({disk_th.critical}%).",
                evidence=f"mount={mount}, usage={pct}%, growth_24h={growth:+.1f}%",
                recommendation="Liberar espacio en disco, rotar logs o ampliar el volumen.",
                suggested_command=f"du -xh --max-depth=2 {mount} | sort -rh | head -n 15" if host.os_type == "linux" else f"Get-ChildItem {mount} | Sort-Object Length -Descending | Select-Object -First 15",
                dedup_key=f"disk_crit:{mount}",
            )
        elif pct >= disk_th.warning:
            if fs_status != "critical":
                fs_status = "warning"
            add_finding(
                check_name="filesystem",
                category="capacity",
                severity="medium",
                title=f"Filesystem en advertencia {mount} al {pct}%",
                description=f"El punto de montaje {mount} superó el umbral de advertencia ({disk_th.warning}%).",
                evidence=f"mount={mount}, usage={pct}%, growth_24h={growth:+.1f}%",
                recommendation="Monitorear crecimiento y planificar limpieza o expansión.",
                suggested_command=f"df -h {mount}" if host.os_type == "linux" else "Get-Volume",
                dedup_key=f"disk_warn:{mount}",
            )

        if inode_pct >= inode_th.critical:
            fs_status = "critical"
            add_finding(
                check_name="filesystem",
                category="capacity",
                severity="high",
                title=f"Inodos críticos en {mount} ({inode_pct}%)",
                description=f"El uso de inodos en {mount} alcanzó {inode_pct}%.",
                evidence=f"mount={mount}, inode_pct={inode_pct}%",
                recommendation="Identificar directorios con millones de archivos pequeños (ej. colas de correo o sesiones).",
                suggested_command=f"find {mount} -xdev -printf '%h\\n' | sort | uniq -c | sort -rn | head -n 10",
                dedup_key=f"inode_crit:{mount}",
            )

    results.append(CheckResult(
        scan_run_id=scan_run_id,
        host_id=host.id,
        check_name="filesystem",
        status=fs_status,
        metric_value=max_disk_pct,
        details={"filesystems": enriched_fs},
    ))

    # 3. CPU
    cpu_th = thresholds["cpu_pct"]
    cpu_pct = float(telemetry.cpu.get("usage_pct", 0.0))
    cores = max(1, int(telemetry.cpu.get("cores", 1)))
    load_15m = float(telemetry.cpu.get("load_15m", 0.0))
    sustained_pct = round((load_15m / cores) * 100.0, 2) if host.os_type == "linux" and load_15m > 0 else cpu_pct
    cpu_status = "ok"
    if cpu_pct >= cpu_th.critical:
        cpu_status = "critical"
        add_finding(
            check_name="cpu",
            category="capacity",
            severity="critical",
            title=f"CPU crítica en {host.hostname} ({cpu_pct}%)",
            description=f"El uso de CPU alcanzó {cpu_pct}% (umbral crítico {cpu_th.critical}%).",
            evidence=f"cpu_pct={cpu_pct}%, load_15m={load_15m}, top={telemetry.cpu.get('top_processes', [])[:3]}",
            recommendation="Inspeccionar procesos con mayor consumo y validar si corresponde a carga legítima o posible abuso/cryptominer.",
            suggested_command="ps -eo pid,ppid,cmd,%cpu,%mem --sort=-%cpu | head -n 15" if host.os_type == "linux" else "Get-Process | Sort-Object CPU -Descending | Select-Object -First 10",
            mitre_id="T1496",
            dedup_key="cpu_crit",
        )
    elif sustained_pct >= cpu_th.warning or cpu_pct >= cpu_th.warning:
        cpu_status = "warning"
        add_finding(
            check_name="cpu",
            category="capacity",
            severity="medium",
            title=f"CPU elevada sostenida en {host.hostname} ({max(cpu_pct, sustained_pct):.1f}%)",
            description=f"Uso de CPU/load promedio elevado respecto al umbral ({cpu_th.warning}%).",
            evidence=f"cpu_pct={cpu_pct}%, load_15m={load_15m}, cores={cores}",
            recommendation="Revisar procesos activos y tendencias de carga.",
            dedup_key="cpu_warn",
        )
    results.append(CheckResult(
        scan_run_id=scan_run_id,
        host_id=host.id,
        check_name="cpu",
        status=cpu_status,
        metric_value=cpu_pct,
        details=telemetry.cpu,
    ))

    # 4. Memory & Swap
    mem_th = thresholds["memory_pct"]
    swap_th = thresholds["swap_pct"]
    mem_pct = float(telemetry.memory.get("usage_pct", 0.0))
    swap_pct = float(telemetry.memory.get("swap_pct", 0.0))
    mem_status = "ok"
    if mem_pct >= mem_th.critical:
        mem_status = "critical"
        add_finding(
            check_name="memory",
            category="capacity",
            severity="critical",
            title=f"Memoria RAM crítica en {host.hostname} ({mem_pct}%)",
            description=f"Uso de RAM al {mem_pct}% (umbral crítico {mem_th.critical}%).",
            evidence=f"ram_pct={mem_pct}%, swap_pct={swap_pct}%, top={telemetry.memory.get('top_processes', [])[:3]}",
            recommendation="Identificar posibles memory leaks o procesos sobredimensionados.",
            suggested_command="ps -eo pid,comm,%mem,rss --sort=-%mem | head -n 15" if host.os_type == "linux" else "Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 10",
            dedup_key="mem_crit",
        )
    elif mem_pct >= mem_th.warning:
        mem_status = "warning"
        add_finding(
            check_name="memory",
            category="capacity",
            severity="medium",
            title=f"Memoria RAM en advertencia ({mem_pct}%)",
            description=f"Uso de RAM superó el umbral de advertencia ({mem_th.warning}%).",
            evidence=f"ram_pct={mem_pct}%, swap_pct={swap_pct}%",
            recommendation="Monitorear consumo de memoria.",
            dedup_key="mem_warn",
        )
    if swap_pct > swap_th.warning:
        if mem_status == "ok":
            mem_status = "warning"
        add_finding(
            check_name="memory",
            category="capacity",
            severity="medium",
            title=f"Uso elevado de Swap ({swap_pct}%)",
            description=f"El uso de swap ({swap_pct}%) supera el umbral ({swap_th.warning}%).",
            evidence=f"swap_pct={swap_pct}%, ram_pct={mem_pct}%",
            recommendation="Evaluar ampliación de RAM o ajuste de swappiness/procesos.",
            dedup_key="swap_warn",
        )
    results.append(CheckResult(
        scan_run_id=scan_run_id,
        host_id=host.id,
        check_name="memory",
        status=mem_status,
        metric_value=mem_pct,
        details=telemetry.memory,
    ))

    # 5. Services
    svc_status = "ok"
    failed_svcs = [s["name"] for s in telemetry.services if s.get("active_state") == "failed"]
    if failed_svcs:
        svc_status = "critical"
        add_finding(
            check_name="services",
            category="service",
            severity="high",
            title=f"Servicios en estado failed ({len(failed_svcs)})",
            description="Se detectaron servicios del sistema en estado failed.",
            evidence=", ".join(failed_svcs[:15]),
            recommendation="Revisar logs del servicio fallido y reiniciar si corresponde.",
            suggested_command=f"systemctl status {failed_svcs[0]} --no-pager" if host.os_type == "linux" else f"Get-Service -Name '{failed_svcs[0]}'",
            dedup_key="failed_services",
        )

    if baseline and baseline.services_snapshot:
        base_active = {
            s["name"]
            for s in baseline.services_snapshot
            if s.get("active_state") == "active" and s.get("name")
        }
        curr_map = {s["name"]: s for s in telemetry.services if s.get("name")}
        down_from_baseline = sorted(
            name for name in base_active if name in curr_map and curr_map[name].get("active_state") != "active"
        )
        if down_from_baseline:
            svc_status = "critical"
            add_finding(
                check_name="services",
                category="service",
                severity="high",
                title=f"Servicios de baseline caídos ({len(down_from_baseline)})",
                description="Servicios que estaban activos en la línea base ahora están detenidos.",
                evidence=", ".join(down_from_baseline[:15]),
                recommendation="Verificar si la detención fue planificada o si hubo un fallo.",
                suggested_command=f"systemctl restart {down_from_baseline[0]}" if host.os_type == "linux" else f"Start-Service -Name '{down_from_baseline[0]}'",
                mitre_id="T1489",
                dedup_key="baseline_services_down",
            )

    results.append(CheckResult(
        scan_run_id=scan_run_id,
        host_id=host.id,
        check_name="services",
        status=svc_status,
        metric_value=float(len(failed_svcs)),
        details={"total": len(telemetry.services), "failed": failed_svcs},
    ))

    # 6. Logs & Security Events (deduplicated)
    log_status = "ok"
    for ev in telemetry.log_events:
        source = ev.get("source", "system")
        msg = ev.get("message", "")[:300]
        ctx = ev.get("context", "")[:1000]
        count = int(ev.get("count", 1))
        is_auth = source in ("auth_log", "Security") or "authentication" in msg.lower() or "failed logon" in msg.lower()
        sev = "high" if (is_auth and count >= 5) or "panic" in msg.lower() or "i/o error" in msg.lower() else "medium"
        if sev == "high":
            log_status = "warning"
        add_finding(
            check_name="logs",
            category="logs",
            severity=sev,
            title=f"Evento crítico en {source}: {msg[:90]}",
            description=f"Hallazgo detectado en logs ({source}) del host {host.hostname}.",
            evidence=f"Message: {msg}\nContext:\n{ctx}",
            recommendation="Investigar el origen del evento en los registros del servidor y validar actividad anómala.",
            mitre_id="T1110" if is_auth else None,
            dedup_key=f"log:{source}:{msg[:80]}",
        )
    results.append(CheckResult(
        scan_run_id=scan_run_id,
        host_id=host.id,
        check_name="logs",
        status=log_status,
        metric_value=float(len(telemetry.log_events)),
        details={"events_count": len(telemetry.log_events)},
    ))

    # 7. Updates
    pending_updates = int(telemetry.updates.get("pending_count", 0))
    upd_status = "warning" if pending_updates > 0 else "ok"
    if pending_updates > 0:
        add_finding(
            check_name="updates",
            category="patching",
            severity="medium" if pending_updates < 20 else "high",
            title=f"{pending_updates} actualizaciones pendientes en {host.hostname}",
            description="Existen paquetes o parches pendientes de instalación.",
            evidence=f"pending_count={pending_updates}",
            recommendation="Planificar ventana de mantenimiento para aplicar parches de seguridad.",
            suggested_command="dnf update --security" if host.os_type == "linux" else "Install-WindowsUpdate -AcceptAll",
            dedup_key="pending_updates",
        )
    results.append(CheckResult(
        scan_run_id=scan_run_id,
        host_id=host.id,
        check_name="updates",
        status=upd_status,
        metric_value=float(pending_updates),
        details=telemetry.updates,
    ))

    # 8. Drift vs Baseline
    if drift and drift.get("has_drift"):
        if drift.get("added_services"):
            add_finding(
                check_name="drift",
                category="drift",
                severity="medium",
                title=f"Nuevos servicios detectados respecto a baseline ({len(drift['added_services'])})",
                description="Se detectaron servicios no presentes en la línea base aprobada.",
                evidence=", ".join(drift["added_services"][:15]),
                recommendation="Validar si los nuevos servicios son legítimos y aprobar nueva baseline si corresponde.",
                mitre_id="T1543",
                dedup_key="drift_added_services",
            )
        if drift.get("added_ports"):
            add_finding(
                check_name="drift",
                category="drift",
                severity="high",
                title=f"Nuevos puertos en escucha respecto a baseline ({len(drift['added_ports'])})",
                description="Se abrieron nuevos puertos TCP/UDP no registrados en la línea base.",
                evidence=", ".join(drift["added_ports"][:15]),
                recommendation="Verificar el proceso asociado y las reglas de firewall.",
                mitre_id="T1049",
                dedup_key="drift_added_ports",
            )

    return results, findings
