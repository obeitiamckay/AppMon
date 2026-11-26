"""Agentless remote collectors for Linux (SSH/Paramiko) and Windows (WinRM/HTTPS)."""

from app.collectors.base import BaseCollector, CommandResult, HostTelemetry
from app.collectors.linux_collector import LinuxCollector
from app.collectors.windows_collector import WindowsCollector

__all__ = [
    "BaseCollector",
    "CommandResult",
    "HostTelemetry",
    "LinuxCollector",
    "WindowsCollector",
]
