"""Mock collectors for 2 Linux hosts and 2 Windows hosts."""

from __future__ import annotations

from app.collectors.base import BaseCollector, CommandResult, HostTelemetry


class MockCollector(BaseCollector):
    """In-memory mock collector returning deterministic telemetry."""

    def __init__(self, telemetry: HostTelemetry, *args, **kwargs) -> None:
        super().__init__(
            hostname=telemetry.hostname,
            ip_address="10.0.0.10",
            port=22 if telemetry.os_type == "linux" else 5986,
            username="socmon_ro",
            secret="mock-secret",
        )
        self._telemetry = telemetry

    def connect(self) -> None:
        if not self._telemetry.reachable:
            raise ConnectionError(self._telemetry.error_message or "Host unreachable")

    def run_command(self, command: str) -> CommandResult:
        return CommandResult(exit_code=0, stdout="soc-monitor-ok", stderr="", duration_ms=5.0)

    def collect_all(self) -> HostTelemetry:
        if not self._telemetry.reachable:
            raise ConnectionError(self._telemetry.error_message or "Host unreachable")
        return self._telemetry

    def close(self) -> None:
        pass


def make_linux_mock_1(hostname: str = "linux-web-01") -> HostTelemetry:
    """Healthy Linux web server."""
    return HostTelemetry(
        hostname=hostname,
        os_type="linux",
        reachable=True,
        latency_ms=12.5,
        os_info={"os_name": "Rocky Linux 9.4", "kernel": "5.14.0", "uptime_seconds": 86400},
        cpu={"usage_pct": 24.0, "load_1m": 0.4, "load_5m": 0.35, "load_15m": 0.3, "cores": 4, "top_processes": []},
        memory={"usage_pct": 48.0, "swap_pct": 2.0, "top_processes": []},
        filesystems=[{"filesystem": "/dev/sda1", "mount": "/", "usage_pct": 42.0, "inode_pct": 10.0}],
        services=[
            {"name": "nginx.service", "active_state": "active", "sub_state": "running", "enabled_state": "enabled"},
            {"name": "sshd.service", "active_state": "active", "sub_state": "running", "enabled_state": "enabled"},
        ],
        ports=[
            {"protocol": "tcp", "address": "0.0.0.0", "port": 80, "process": "nginx"},
            {"protocol": "tcp", "address": "0.0.0.0", "port": 443, "process": "nginx"},
        ],
        firewall={
            "backend": "firewalld",
            "rules": [
                {"port": 80, "protocol": "tcp", "source": "10.0.0.0/8", "enabled": True},
                {"port": 443, "protocol": "tcp", "source": "10.0.0.0/8", "enabled": True},
            ],
        },
        admins=[{"username": "root", "privilege_source": "uid_0", "is_service_account": False}],
        logs_inventory=["messages", "secure"],
        log_events=[],
        updates={"pending_count": 0},
    )


def make_linux_mock_2(hostname: str = "linux-db-01") -> HostTelemetry:
    """Linux DB server with disk critical, unauthorized port, and unauthorized admin."""
    return HostTelemetry(
        hostname=hostname,
        os_type="linux",
        reachable=True,
        latency_ms=25.0,
        os_info={"os_name": "Rocky Linux 9.4", "kernel": "5.14.0", "uptime_seconds": 120000},
        cpu={"usage_pct": 88.0, "load_1m": 3.5, "load_5m": 3.2, "load_15m": 3.4, "cores": 4, "top_processes": []},
        memory={"usage_pct": 91.0, "swap_pct": 28.0, "top_processes": []},
        filesystems=[{"filesystem": "/dev/sdb1", "mount": "/var/lib/pgsql", "usage_pct": 93.0, "inode_pct": 40.0}],
        services=[
            {"name": "postgresql-16.service", "active_state": "failed", "sub_state": "failed", "enabled_state": "enabled"},
        ],
        ports=[
            {"protocol": "tcp", "address": "0.0.0.0", "port": 5432, "process": "postgres"},
            {"protocol": "tcp", "address": "0.0.0.0", "port": 4444, "process": "nc"},
        ],
        firewall={
            "backend": "iptables",
            "rules": [
                {"port": 22, "protocol": "tcp", "source": "0.0.0.0/0", "enabled": True},
                {"port": 5432, "protocol": "tcp", "source": "0.0.0.0/0", "enabled": True},
            ],
        },
        admins=[
            {"username": "root", "privilege_source": "uid_0", "is_service_account": False},
            {"username": "rogue_admin", "privilege_source": "wheel", "is_service_account": False, "last_login_days": 120, "password_never_expires": True},
        ],
        logs_inventory=["messages", "secure"],
        log_events=[
            {"source": "auth_log", "message": "12 authentication failures detected", "context": "Failed password for root", "count": 12},
            {"source": "auth_log", "message": "12 authentication failures detected", "context": "Failed password for root", "count": 12},
        ],
        updates={"pending_count": 25},
    )


def make_windows_mock_1(hostname: str = "win-app-01") -> HostTelemetry:
    """Healthy Windows Server."""
    return HostTelemetry(
        hostname=hostname,
        os_type="windows",
        reachable=True,
        latency_ms=18.0,
        os_info={"os_name": "Microsoft Windows Server 2022", "kernel": "20348", "uptime_seconds": 50000},
        cpu={"usage_pct": 30.0, "cores": 4, "top_processes": []},
        memory={"usage_pct": 55.0, "swap_pct": 5.0, "top_processes": []},
        filesystems=[{"filesystem": "C:", "mount": "C:\\", "usage_pct": 50.0, "inode_pct": 0}],
        services=[{"name": "W3SVC", "active_state": "active", "sub_state": "running", "enabled_state": "automatic"}],
        ports=[{"protocol": "tcp", "address": "0.0.0.0", "port": 443, "process": "System"}],
        firewall={"backend": "windows_defender", "rules": [{"port": 443, "protocol": "tcp", "source": "10.0.0.0/8", "enabled": True}]},
        admins=[{"username": "WIN-APP-01\\Administrator", "privilege_source": "Administrators", "is_service_account": False}],
        logs_inventory=["System", "Application", "Security"],
        log_events=[],
        updates={"pending_count": 0},
    )


def make_windows_mock_2(hostname: str = "win-dc-01") -> HostTelemetry:
    """Windows Server with Any-to-Any firewall rule and service account admin."""
    return HostTelemetry(
        hostname=hostname,
        os_type="windows",
        reachable=True,
        latency_ms=32.0,
        os_info={"os_name": "Microsoft Windows Server 2022", "kernel": "20348", "uptime_seconds": 90000},
        cpu={"usage_pct": 40.0, "cores": 8, "top_processes": []},
        memory={"usage_pct": 62.0, "swap_pct": 10.0, "top_processes": []},
        filesystems=[{"filesystem": "C:", "mount": "C:\\", "usage_pct": 82.0, "inode_pct": 0}],
        services=[{"name": "NTDS", "active_state": "active", "sub_state": "running", "enabled_state": "automatic"}],
        ports=[{"protocol": "tcp", "address": "0.0.0.0", "port": 3389, "process": "TermService"}],
        firewall={
            "backend": "windows_defender",
            "rules": [{"port": 0, "protocol": "any", "source": "0.0.0.0/0", "enabled": True}],
        },
        admins=[
            {"username": "Administrator", "privilege_source": "Administrators", "is_service_account": False},
            {"username": "svc_backup", "privilege_source": "Administrators", "is_service_account": True},
        ],
        logs_inventory=["System", "Application", "Security"],
        log_events=[{"source": "Security", "message": "8 failed logon attempts (Event ID 4625)", "context": "Event ID 4625", "count": 8}],
        updates={"pending_count": 5},
    )
