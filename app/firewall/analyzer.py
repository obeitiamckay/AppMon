"""Firewall and open ports analyzer."""

from __future__ import annotations

from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.collectors.base import HostTelemetry
from app.models.inventory import Host
from app.models.monitoring import Finding
from app.models.security_audit import FirewallAllowedRule, FirewallBaseline

SENSITIVE_PORTS = {22, 23, 3389, 5432, 1433, 3306, 6379, 27017, 5985, 5986, 445}
LOOPBACK_ADDRS = {"127.0.0.1", "::1", "localhost"}


def analyze_firewall_and_ports(
    db: Session,
    scan_run_id: int,
    host: Host,
    telemetry: HostTelemetry,
) -> tuple[list[dict[str, Any]], list[Finding]]:
    """Compare listening ports and firewall rules against allowed rules and baseline."""
    findings: list[Finding] = []
    port_table: list[dict[str, Any]] = []

    allowed_rules: list[FirewallAllowedRule] = []
    if host.group_id is not None:
        allowed_rules = list(
            db.execute(
                select(FirewallAllowedRule).where(FirewallAllowedRule.group_id == host.group_id)
            ).scalars().all()
        )

    allowed_map: dict[tuple[int, str], FirewallAllowedRule] = {
        (r.port, r.protocol.lower()): r for r in allowed_rules if r.is_enabled
    }

    fw_rules = telemetry.firewall.get("rules", []) or []
    fw_backend = telemetry.firewall.get("backend", "none")

    # Check if firewall is completely disabled
    if fw_backend == "none":
        findings.append(Finding(
            scan_run_id=scan_run_id,
            host_id=host.id,
            check_name="firewall",
            category="firewall",
            severity="critical",
            title=f"Firewall del host deshabilitado o no detectado en {host.hostname}",
            description="No se detectó un firewall activo (firewalld/nftables/iptables/Windows Defender).",
            evidence=f"backend={fw_backend}",
            recommendation="Habilitar firewalld o Windows Defender Firewall inmediatamente.",
            suggested_command="systemctl enable --now firewalld" if host.os_type == "linux" else "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
            mitre_id="T1562.004",
        ))

    # Inspect firewall rules for Any-to-Any or 0.0.0.0/0 on sensitive ports
    for rule in fw_rules:
        if not rule.get("enabled", True):
            continue
        r_port = int(rule.get("port", 0) or 0)
        r_proto = str(rule.get("protocol", "any")).lower()
        r_src = str(rule.get("source", "")).strip()
        is_any_src = r_src in ("0.0.0.0/0", "::/0", "*", "any", "")

        if r_port == 0 and r_proto == "any" and is_any_src:
            findings.append(Finding(
                scan_run_id=scan_run_id,
                host_id=host.id,
                check_name="firewall",
                category="firewall",
                severity="critical",
                title="Regla de firewall Any-to-Any detectada",
                description=f"Regla permisiva Any-to-Any activa en {host.hostname}.",
                evidence=f"rule={rule}",
                recommendation="Restringir la regla a puertos y redes de origen específicos.",
                mitre_id="T1562.004",
            ))
        elif r_port in SENSITIVE_PORTS and is_any_src:
            findings.append(Finding(
                scan_run_id=scan_run_id,
                host_id=host.id,
                check_name="firewall",
                category="firewall",
                severity="high",
                title=f"Puerto sensible {r_port}/{r_proto} expuesto a 0.0.0.0/0",
                description=f"El firewall permite tráfico desde cualquier origen hacia el puerto sensible {r_port}.",
                evidence=f"port={r_port}, source={r_src}, backend={fw_backend}",
                recommendation="Limitar el acceso a la subred de administración o red interna autorizada.",
                suggested_command=f"firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=10.0.0.0/8 port port={r_port} protocol={r_proto} accept'" if host.os_type == "linux" else f"Set-NetFirewallRule -DisplayName '{rule.get('name','')}' -RemoteAddress 10.0.0.0/8",
                mitre_id="T1021",
            ))

    # Check disabled rules that should be active per group policy
    for rule in allowed_rules:
        if rule.is_enabled:
            matching = [r for r in fw_rules if int(r.get("port", 0) or 0) == rule.port]
            if matching and all(not r.get("enabled", True) for r in matching):
                findings.append(Finding(
                    scan_run_id=scan_run_id,
                    host_id=host.id,
                    check_name="firewall",
                    category="firewall",
                    severity="medium",
                    title=f"Regla de firewall deshabilitada para puerto permitido {rule.port}/{rule.protocol}",
                    description="Una regla requerida por la política del grupo se encuentra deshabilitada en el host.",
                    evidence=f"expected_port={rule.port}/{rule.protocol}, host_rules={matching}",
                    recommendation="Habilitar la regla en el firewall local.",
                    mitre_id="T1562.004",
                ))

    # Evaluate listening ports against allowed_map
    for p in telemetry.ports:
        port_num = int(p.get("port", 0))
        proto = str(p.get("protocol", "tcp")).lower()
        addr = str(p.get("address", ""))
        proc = str(p.get("process", "unknown"))

        if addr in LOOPBACK_ADDRS:
            port_table.append({
                "port": port_num,
                "protocol": proto,
                "address": addr,
                "process": proc,
                "allowing_rule": "loopback-only",
                "status": "permitido",
            })
            continue

        matched_rule: Optional[FirewallAllowedRule] = allowed_map.get((port_num, proto))
        if matched_rule:
            # Check if host firewall exposes it to 0.0.0.0/0 while policy restricts sources
            exposed_any = any(
                int(r.get("port", 0) or 0) == port_num
                and str(r.get("source", "")) in ("0.0.0.0/0", "::/0", "*")
                and r.get("enabled", True)
                for r in fw_rules
            )
            if exposed_any and matched_rule.allowed_sources not in ("0.0.0.0/0", "*"):
                status = "revisar"
                allowing = f"Grupo ({matched_rule.allowed_sources}) vs Host (0.0.0.0/0)"
                findings.append(Finding(
                    scan_run_id=scan_run_id,
                    host_id=host.id,
                    check_name="firewall",
                    category="firewall",
                    severity="high",
                    title=f"Puerto {port_num}/{proto} más abierto que la política del grupo",
                    description=f"La política permite solo {matched_rule.allowed_sources}, pero el host expone 0.0.0.0/0.",
                    evidence=f"port={port_num}, process={proc}, policy_sources={matched_rule.allowed_sources}",
                    recommendation="Restringir el origen en el firewall del host.",
                    mitre_id="T1021",
                ))
            else:
                status = "permitido"
                allowing = f"Regla grupo ({matched_rule.allowed_sources})"
        elif allowed_rules:
            status = "no autorizado"
            allowing = "Ninguna"
            findings.append(Finding(
                scan_run_id=scan_run_id,
                host_id=host.id,
                check_name="firewall",
                category="firewall",
                severity="high",
                title=f"Puerto abierto no autorizado: {port_num}/{proto} ({proc})",
                description=f"El puerto {port_num}/{proto} escuchando en {addr} no está en la lista permitida del grupo.",
                evidence=f"port={port_num}, protocol={proto}, address={addr}, process={proc}",
                recommendation="Cerrar el servicio/puerto o agregar una regla justificada en la consola.",
                suggested_command=f"ss -tulnp | grep :{port_num}" if host.os_type == "linux" else f"Get-NetTCPConnection -LocalPort {port_num}",
                mitre_id="T1049",
            ))
        else:
            status = "revisar"
            allowing = "Sin política de grupo"

        port_table.append({
            "port": port_num,
            "protocol": proto,
            "address": addr,
            "process": proc,
            "allowing_rule": allowing,
            "status": status,
        })

    # Compare against FirewallBaseline
    fw_base = db.execute(
        select(FirewallBaseline)
        .where(FirewallBaseline.host_id == host.id, FirewallBaseline.is_active.is_(True))
        .order_by(FirewallBaseline.version.desc())
        .limit(1)
    ).scalar_one_or_none()
    if fw_base and fw_base.firewall_backend != fw_backend:
        findings.append(Finding(
            scan_run_id=scan_run_id,
            host_id=host.id,
            check_name="firewall",
            category="drift",
            severity="high",
            title=f"Cambio de backend de firewall ({fw_base.firewall_backend} -> {fw_backend})",
            description="El motor de firewall activo cambió respecto a la línea base.",
            evidence=f"baseline={fw_base.firewall_backend}, current={fw_backend}",
            recommendation="Verificar el cambio y restaurar la configuración aprobada.",
            mitre_id="T1562.004",
        ))

    return port_table, findings
