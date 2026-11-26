"""Base collector interface and normalized telemetry data structures."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class CommandResult:
    """Result of executing a single remote command."""

    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float = 0.0


@dataclass
class HostTelemetry:
    """Normalized telemetry collected from a Linux or Windows host."""

    hostname: str
    os_type: str
    reachable: bool = True
    error_message: Optional[str] = None
    latency_ms: float = 0.0
    os_info: dict[str, Any] = field(default_factory=dict)
    cpu: dict[str, Any] = field(default_factory=dict)
    memory: dict[str, Any] = field(default_factory=dict)
    filesystems: list[dict[str, Any]] = field(default_factory=list)
    services: list[dict[str, Any]] = field(default_factory=list)
    ports: list[dict[str, Any]] = field(default_factory=list)
    firewall: dict[str, Any] = field(default_factory=dict)
    admins: list[dict[str, Any]] = field(default_factory=list)
    logs_inventory: list[str] = field(default_factory=list)
    log_events: list[dict[str, Any]] = field(default_factory=list)
    updates: dict[str, Any] = field(default_factory=dict)


class BaseCollector(ABC):
    """Abstract base class for agentless host collectors."""

    def __init__(
        self,
        hostname: str,
        ip_address: str,
        port: int,
        username: str,
        secret: str,
        passphrase: Optional[str] = None,
        timeout_seconds: int = 45,
    ) -> None:
        self.hostname = hostname
        self.ip_address = ip_address
        self.port = port
        self.username = username
        self.secret = secret
        self.passphrase = passphrase
        self.timeout_seconds = timeout_seconds

    @abstractmethod
    def connect(self) -> None:
        """Establish remote connection."""

    @abstractmethod
    def run_command(self, command: str) -> CommandResult:
        """Execute a read-only command on the target host."""

    @abstractmethod
    def collect_all(self) -> HostTelemetry:
        """Collect all required operational and security telemetry."""

    def test_connection(self) -> tuple[bool, str]:
        """Verify connectivity and basic read-only execution."""
        try:
            self.connect()
            res = self.run_command("echo soc-monitor-ok")
            if res.exit_code == 0 and "soc-monitor-ok" in res.stdout:
                return True, f"Connection successful ({res.duration_ms:.1f} ms)"
            return False, f"Command failed (exit={res.exit_code}): {res.stderr.strip()}"
        except Exception as exc:
            return False, str(exc)
        finally:
            self.close()

    @abstractmethod
    def close(self) -> None:
        """Close remote connection cleanly."""
