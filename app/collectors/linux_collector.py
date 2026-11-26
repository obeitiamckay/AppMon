"""Agentless Linux collector using Paramiko with SSH key authentication."""

from __future__ import annotations

import io
import logging
import re
import time
from typing import Any, Optional

import paramiko

from app.collectors.base import BaseCollector, CommandResult, HostTelemetry

logger = logging.getLogger(__name__)


def _load_private_key(key_text: str, passphrase: Optional[str] = None) -> paramiko.PKey:
    """Load an SSH private key (Ed25519, RSA, ECDSA) from PEM/OpenSSH string."""
    key_stream = io.StringIO(key_text.strip())
    for key_cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            key_stream.seek(0)
            return key_cls.from_private_key(key_stream, password=passphrase or None)
        except paramiko.SSHException:
            continue
    raise ValueError("Unsupported or invalid SSH private key format")


class LinuxCollector(BaseCollector):
    """Collects telemetry from Linux servers over SSH using Paramiko."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._client: Optional[paramiko.SSHClient] = None

    def connect(self) -> None:
        client = paramiko.SSHClient()
        # In production environments with known_hosts, WarningPolicy/RejectPolicy can be configured;
        # AutoAddPolicy allows initial onboarding without manual SSH prompt.
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        pkey = _load_private_key(self.secret, self.passphrase)
        client.connect(
            hostname=self.ip_address,
            port=self.port or 22,
            username=self.username,
            pkey=pkey,
            timeout=self.timeout_seconds,
            banner_timeout=self.timeout_seconds,
            auth_timeout=self.timeout_seconds,
            look_for_keys=False,
            allow_agent=False,
        )
        self._client = client

    def run_command(self, command: str) -> CommandResult:
        if self._client is None:
            raise RuntimeError("SSH client not connected")
        start = time.monotonic()
        _, stdout, stderr = self._client.exec_command(command, timeout=self.timeout_seconds)
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        duration_ms = (time.monotonic() - start) * 1000.0
        return CommandResult(exit_code=exit_code, stdout=out, stderr=err, duration_ms=duration_ms)

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            finally:
                self._client = None

    def collect_all(self) -> HostTelemetry:
        telemetry = HostTelemetry(hostname=self.hostname, os_type="linux")
        t0 = time.monotonic()
        self.connect()
        try:
            telemetry.latency_ms = round((time.monotonic() - t0) * 1000.0, 2)
            telemetry.os_info = self._collect_os_info()
            telemetry.cpu = self._collect_cpu()
            telemetry.memory = self._collect_memory()
            telemetry.filesystems = self._collect_filesystems()
            telemetry.services = self._collect_services()
            telemetry.ports = self._collect_ports()
            telemetry.firewall = self._collect_firewall()
            telemetry.admins = self._collect_admins()
            telemetry.logs_inventory, telemetry.log_events = self._collect_logs()
            telemetry.updates = self._collect_updates()
            return telemetry
        finally:
            self.close()

    def _collect_os_info(self) -> dict[str, Any]:
        res = self.run_command(
            "cat /etc/os-release 2>/dev/null | grep -E '^(PRETTY_NAME|NAME|VERSION_ID)='; "
            "echo '---KERNEL---'; uname -r; "
            "echo '---UPTIME---'; cat /proc/uptime; "
            "echo '---HOSTNAME---'; hostname -f 2>/dev/null || hostname"
        )
        sections = res.stdout.split("---KERNEL---")
        os_release = sections[0] if sections else ""
        pretty_name = "Linux"
        for line in os_release.splitlines():
            if line.startswith("PRETTY_NAME="):
                pretty_name = line.split("=", 1)[1].strip().strip('"')
                break
        kernel = ""
        uptime_seconds = 0.0
        fqdn = self.hostname
        if len(sections) > 1:
            rest = sections[1].split("---UPTIME---")
            kernel = rest[0].strip()
            if len(rest) > 1:
                up_rest = rest[1].split("---HOSTNAME---")
                try:
                    uptime_seconds = float(up_rest[0].strip().split()[0])
                except (ValueError, IndexError):
                    uptime_seconds = 0.0
                if len(up_rest) > 1 and up_rest[1].strip():
                    fqdn = up_rest[1].strip()
        return {
            "os_name": pretty_name,
            "kernel": kernel,
            "uptime_seconds": int(uptime_seconds),
            "fqdn": fqdn,
        }

    def _collect_cpu(self) -> dict[str, Any]:
        res = self.run_command(
            "cat /proc/loadavg; "
            "echo '---NPROC---'; nproc 2>/dev/null || echo 1; "
            "echo '---STAT---'; grep '^cpu ' /proc/stat; sleep 1; grep '^cpu ' /proc/stat; "
            "echo '---TOP---'; ps -eo pid,comm,%cpu,%mem --sort=-%cpu | head -n 6"
        )
        lines = res.stdout.splitlines()
        load_1, load_5, load_15 = 0.0, 0.0, 0.0
        if lines:
            parts = lines[0].split()
            if len(parts) >= 3:
                load_1, load_5, load_15 = float(parts[0]), float(parts[1]), float(parts[2])

        cpu_pct = 0.0
        cores = 1
        top_procs: list[dict[str, Any]] = []

        if "---NPROC---" in res.stdout and "---STAT---" in res.stdout:
            nproc_part = res.stdout.split("---NPROC---")[1].split("---STAT---")[0].strip()
            try:
                cores = max(1, int(nproc_part))
            except ValueError:
                cores = 1

        if "---STAT---" in res.stdout:
            stat_part = res.stdout.split("---STAT---")[1].split("---TOP---")[0].strip().splitlines()
            if len(stat_part) >= 2:
                v1 = [int(x) for x in stat_part[0].split()[1:8]]
                v2 = [int(x) for x in stat_part[1].split()[1:8]]
                total_diff = sum(v2) - sum(v1)
                idle_diff = (v2[3] - v1[3]) + (v2[4] - v1[4] if len(v2) > 4 else 0)
                if total_diff > 0:
                    cpu_pct = round((1.0 - (idle_diff / total_diff)) * 100.0, 2)

        if "---TOP---" in res.stdout:
            top_lines = res.stdout.split("---TOP---")[1].strip().splitlines()[1:]
            for line in top_lines:
                cols = line.split(None, 3)
                if len(cols) == 4:
                    top_procs.append({
                        "pid": cols[0],
                        "name": cols[1],
                        "cpu_pct": float(cols[2]),
                        "mem_pct": float(cols[3]),
                    })

        return {
            "usage_pct": cpu_pct,
            "load_1m": load_1,
            "load_5m": load_5,
            "load_15m": load_15,
            "cores": cores,
            "top_processes": top_procs,
        }

    def _collect_memory(self) -> dict[str, Any]:
        res = self.run_command(
            "free -b; echo '---TOP---'; ps -eo pid,comm,%cpu,%mem --sort=-%mem | head -n 6"
        )
        ram_total = ram_used = swap_total = swap_used = 0
        for line in res.stdout.splitlines():
            if line.startswith("Mem:"):
                cols = line.split()
                if len(cols) >= 3:
                    ram_total = int(cols[1])
                    ram_used = int(cols[2])
            elif line.startswith("Swap:"):
                cols = line.split()
                if len(cols) >= 3:
                    swap_total = int(cols[1])
                    swap_used = int(cols[2])

        ram_pct = round((ram_used / ram_total) * 100.0, 2) if ram_total > 0 else 0.0
        swap_pct = round((swap_used / swap_total) * 100.0, 2) if swap_total > 0 else 0.0

        top_procs: list[dict[str, Any]] = []
        if "---TOP---" in res.stdout:
            for line in res.stdout.split("---TOP---")[1].strip().splitlines()[1:]:
                cols = line.split(None, 3)
                if len(cols) == 4:
                    top_procs.append({
                        "pid": cols[0],
                        "name": cols[1],
                        "cpu_pct": float(cols[2]),
                        "mem_pct": float(cols[3]),
                    })

        return {
            "total_bytes": ram_total,
            "used_bytes": ram_used,
            "usage_pct": ram_pct,
            "swap_total_bytes": swap_total,
            "swap_used_bytes": swap_used,
            "swap_pct": swap_pct,
            "top_processes": top_procs,
        }

    def _collect_filesystems(self) -> list[dict[str, Any]]:
        res = self.run_command("df -P -k; echo '---INODES---'; df -P -i")
        blocks_part, _, inodes_part = res.stdout.partition("---INODES---")
        inode_map: dict[str, float] = {}
        for line in inodes_part.strip().splitlines()[1:]:
            cols = line.split()
            if len(cols) >= 6:
                mount = cols[5]
                pct_str = cols[4].rstrip("%")
                if pct_str.isdigit():
                    inode_map[mount] = float(pct_str)

        filesystems: list[dict[str, Any]] = []
        for line in blocks_part.strip().splitlines()[1:]:
            cols = line.split()
            if len(cols) >= 6:
                fs_name = cols[0]
                if fs_name.startswith(("tmpfs", "devtmpfs", "udev", "overlay")):
                    continue
                total_kb = int(cols[1]) if cols[1].isdigit() else 0
                used_kb = int(cols[2]) if cols[2].isdigit() else 0
                pct_str = cols[4].rstrip("%")
                usage_pct = float(pct_str) if pct_str.isdigit() else 0.0
                mount = cols[5]
                filesystems.append({
                    "filesystem": fs_name,
                    "mount": mount,
                    "total_kb": total_kb,
                    "used_kb": used_kb,
                    "usage_pct": usage_pct,
                    "inode_pct": inode_map.get(mount, 0.0),
                })
        return filesystems

    def _collect_services(self) -> list[dict[str, Any]]:
        res = self.run_command(
            "systemctl list-units --type=service --all --no-pager --no-legend 2>/dev/null; "
            "echo '---ENABLED---'; "
            "systemctl list-unit-files --type=service --no-pager --no-legend 2>/dev/null"
        )
        units_part, _, enabled_part = res.stdout.partition("---ENABLED---")
        enabled_map: dict[str, str] = {}
        for line in enabled_part.strip().splitlines():
            cols = line.split()
            if len(cols) >= 2:
                enabled_map[cols[0]] = cols[1]

        services: list[dict[str, Any]] = []
        for line in units_part.strip().splitlines():
            cols = line.split(None, 4)
            if len(cols) >= 4:
                unit = cols[0].lstrip("●").strip()
                if not unit.endswith(".service"):
                    continue
                active = cols[2]
                sub = cols[3]
                services.append({
                    "name": unit,
                    "active_state": active,
                    "sub_state": sub,
                    "enabled_state": enabled_map.get(unit, "unknown"),
                })
        return services

    def _collect_ports(self) -> list[dict[str, Any]]:
        res = self.run_command("sudo -n ss -tulnpH 2>/dev/null || ss -tulnH 2>/dev/null")
        ports: list[dict[str, Any]] = []
        for line in res.stdout.splitlines():
            cols = line.split()
            if len(cols) < 5:
                continue
            proto = cols[0].lower()
            local_addr = cols[4]
            if ":" not in local_addr:
                continue
            addr_part, port_str = local_addr.rsplit(":", 1)
            if not port_str.isdigit():
                continue
            proc_match = re.search(r'users:\(\("([^"]+)"', line)
            process_name = proc_match.group(1) if proc_match else "unknown"
            ports.append({
                "protocol": "udp" if proto.startswith("udp") else "tcp",
                "address": addr_part.strip("[]"),
                "port": int(port_str),
                "process": process_name,
            })
        return ports

    def _collect_firewall(self) -> dict[str, Any]:
        res = self.run_command(
            "if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then "
            "  echo 'BACKEND=firewalld'; sudo -n firewall-cmd --list-all-zones 2>/dev/null || firewall-cmd --list-all 2>/dev/null; "
            "elif command -v nft >/dev/null 2>&1; then "
            "  echo 'BACKEND=nftables'; sudo -n nft list ruleset 2>/dev/null; "
            "elif command -v iptables >/dev/null 2>&1; then "
            "  echo 'BACKEND=iptables'; sudo -n iptables -S 2>/dev/null; "
            "else echo 'BACKEND=none'; fi"
        )
        lines = res.stdout.splitlines()
        backend = "none"
        raw_lines = lines
        if lines and lines[0].startswith("BACKEND="):
            backend = lines[0].split("=", 1)[1].strip()
            raw_lines = lines[1:]
        return {
            "backend": backend,
            "raw_output": "\n".join(raw_lines),
            "rules": parse_linux_firewall_rules(backend, "\n".join(raw_lines)),
        }

    def _collect_admins(self) -> list[dict[str, Any]]:
        res = self.run_command(
            "awk -F: '$3 == 0 {print $1}' /etc/passwd; "
            "echo '---GROUPS---'; "
            "grep -E '^(wheel|sudo):' /etc/group 2>/dev/null; "
            "echo '---SUDOERS---'; "
            "sudo -n grep -hvE '^(#|$|Defaults)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null || true; "
            "echo '---LASTLOG---'; "
            "lastlog 2>/dev/null | head -n 50 || true"
        )
        uid0_part, _, rest = res.stdout.partition("---GROUPS---")
        groups_part, _, rest2 = rest.partition("---SUDOERS---")
        sudoers_part, _, _lastlog_part = rest2.partition("---LASTLOG---")

        admins: dict[str, dict[str, Any]] = {}
        for user in uid0_part.strip().splitlines():
            u = user.strip()
            if u:
                admins[u] = {
                    "username": u,
                    "privilege_source": "uid_0",
                    "is_service_account": u != "root",
                    "last_login_days": None,
                    "password_never_expires": False,
                }

        for line in groups_part.strip().splitlines():
            if ":" in line:
                gname, _, members = line.rpartition(":")
                group_label = gname.split(":")[0]
                for m in members.split(","):
                    u = m.strip()
                    if u and u not in admins:
                        admins[u] = {
                            "username": u,
                            "privilege_source": group_label,
                            "is_service_account": False,
                            "last_login_days": None,
                            "password_never_expires": False,
                        }

        for line in sudoers_part.strip().splitlines():
            tok = line.split()[0] if line.split() else ""
            if tok and not tok.startswith("%") and tok != "root" and tok not in admins:
                admins[tok] = {
                    "username": tok,
                    "privilege_source": "sudoers",
                    "is_service_account": False,
                    "last_login_days": None,
                    "password_never_expires": False,
                }

        return list(admins.values())

    def _collect_logs(self) -> tuple[list[str], list[dict[str, Any]]]:
        res = self.run_command(
            "ls -1 /var/log 2>/dev/null | head -n 50; "
            "echo '---EVENTS---'; "
            "sudo -n journalctl -p err..emerg --since '24 hours ago' -n 60 --no-pager 2>/dev/null || true; "
            "echo '---AUTH---'; "
            "sudo -n grep -iE 'failed password|authentication failure|invalid user' /var/log/secure /var/log/auth.log 2>/dev/null | tail -n 40 || true"
        )
        inv_part, _, rest = res.stdout.partition("---EVENTS---")
        events_part, _, auth_part = rest.partition("---AUTH---")
        inventory = [line.strip() for line in inv_part.splitlines() if line.strip()]

        events: list[dict[str, Any]] = []
        event_lines = [l for l in events_part.splitlines() if l.strip()]
        for idx, line in enumerate(event_lines):
            if any(k in line.lower() for k in ("error", "fail", "panic", "oom", "critical", "i/o error")):
                ctx_start = max(0, idx - 2)
                ctx_end = min(len(event_lines), idx + 3)
                events.append({
                    "source": "journald",
                    "message": line[:300],
                    "context": "\n".join(event_lines[ctx_start:ctx_end])[:1000],
                })

        auth_lines = [l for l in auth_part.splitlines() if l.strip()]
        if auth_lines:
            events.append({
                "source": "auth_log",
                "message": f"{len(auth_lines)} authentication failures detected in last 24h",
                "context": "\n".join(auth_lines[-5:])[:1000],
                "count": len(auth_lines),
            })

        return inventory, events

    def _collect_updates(self) -> dict[str, Any]:
        res = self.run_command(
            "if command -v dnf >/dev/null 2>&1; then "
            "  dnf check-update -q 2>/dev/null | grep -E '^[a-zA-Z0-9]' | wc -l; "
            "elif command -v apt-get >/dev/null 2>&1; then "
            "  apt-get -s upgrade 2>/dev/null | grep -c '^Inst ' || echo 0; "
            "else echo 0; fi"
        )
        try:
            pending = int(res.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            pending = 0
        return {"pending_count": pending}


def parse_linux_firewall_rules(backend: str, raw_output: str) -> list[dict[str, Any]]:
    """Parse Linux firewall output into normalized rule dictionaries."""
    rules: list[dict[str, Any]] = []
    if backend == "firewalld":
        active_zone = "public"
        for line in raw_output.splitlines():
            s = line.strip()
            if s and not s.startswith(("target:", "icmp-", "interfaces:", "sources:", "services:", "ports:", "protocols:", "masquerade:", "forward-ports:", "source-ports:", "icmp-blocks:", "rich rules:")):
                active_zone = s.split()[0]
            elif s.startswith("ports:"):
                for item in s.split(":", 1)[1].split():
                    if "/" in item:
                        p_str, proto = item.split("/", 1)
                        if p_str.isdigit():
                            rules.append({
                                "zone": active_zone,
                                "port": int(p_str),
                                "protocol": proto.lower(),
                                "source": "0.0.0.0/0",
                                "action": "allow",
                                "enabled": True,
                            })
            elif s.startswith("services:"):
                svc_port_map = {"ssh": 22, "http": 80, "https": 443, "postgresql": 5432, "mysql": 3306}
                for svc in s.split(":", 1)[1].split():
                    if svc in svc_port_map:
                        rules.append({
                            "zone": active_zone,
                            "port": svc_port_map[svc],
                            "protocol": "tcp",
                            "source": "0.0.0.0/0",
                            "action": "allow",
                            "enabled": True,
                            "service": svc,
                        })
    elif backend == "iptables":
        for line in raw_output.splitlines():
            if line.startswith("-A INPUT") and "-j ACCEPT" in line:
                port_m = re.search(r"--dport\s+(\d+)", line)
                proto_m = re.search(r"-p\s+(tcp|udp)", line)
                src_m = re.search(r"-s\s+([0-9./]+)", line)
                rules.append({
                    "zone": "INPUT",
                    "port": int(port_m.group(1)) if port_m else 0,
                    "protocol": proto_m.group(1) if proto_m else "any",
                    "source": src_m.group(1) if src_m else "0.0.0.0/0",
                    "action": "allow",
                    "enabled": True,
                })
    return rules
