"""Agentless Windows collector using pywinrm over HTTPS (port 5986)."""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Optional

import winrm

from app.collectors.base import BaseCollector, CommandResult, HostTelemetry
from app.config import get_settings

logger = logging.getLogger(__name__)

_WINDOWS_TELEMETRY_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$os = Get-CimInstance Win32_OperatingSystem
$uptimeSec = [int]((Get-Date) - $os.LastBootUpTime).TotalSeconds
$cpuPct = [math]::Round((Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average, 2)
$topCpu = Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 | ForEach-Object {
    @{ pid = $_.Id; name = $_.ProcessName; cpu_sec = [math]::Round($_.CPU, 2); mem_mb = [math]::Round($_.WorkingSet64 / 1MB, 1) }
}
$totalMem = [int64]$os.TotalVisibleMemorySize * 1024
$freeMem = [int64]$os.FreePhysicalMemory * 1024
$usedMem = $totalMem - $freeMem
$memPct = if ($totalMem -gt 0) { [math]::Round(($usedMem / $totalMem) * 100, 2) } else { 0 }
$pf = Get-CimInstance Win32_PageFileUsage
$swapTotal = ($pf | Measure-Object -Property AllocatedBaseSize -Sum).Sum * 1MB
$swapUsed = ($pf | Measure-Object -Property CurrentUsage -Sum).Sum * 1MB
$swapPct = if ($swapTotal -gt 0) { [math]::Round(($swapUsed / $swapTotal) * 100, 2) } else { 0 }

$disks = Get-Volume | Where-Object { $_.DriveLetter -and $_.Size -gt 0 } | ForEach-Object {
    $used = $_.Size - $_.SizeRemaining
    @{
        filesystem = $_.DriveLetter + ":"
        mount = $_.DriveLetter + ":\"
        total_kb = [int64]($_.Size / 1024)
        used_kb = [int64]($used / 1024)
        usage_pct = [math]::Round(($used / $_.Size) * 100, 2)
        inode_pct = 0
    }
}

$services = Get-Service | Select-Object -First 300 | ForEach-Object {
    @{
        name = $_.Name
        active_state = if ($_.Status -eq 'Running') { 'active' } else { 'inactive' }
        sub_state = $_.Status.ToString().ToLower()
        enabled_state = $_.StartType.ToString().ToLower()
    }
}

$procMap = @{}
Get-Process | ForEach-Object { $procMap[$_.Id] = $_.ProcessName }
$tcpPorts = Get-NetTCPConnection -State Listen | ForEach-Object {
    @{
        protocol = 'tcp'
        address = $_.LocalAddress
        port = [int]$_.LocalPort
        process = if ($procMap.ContainsKey($_.OwningProcess)) { $procMap[$_.OwningProcess] } else { "pid:$($_.OwningProcess)" }
    }
}
$udpPorts = Get-NetUDPEndpoint | ForEach-Object {
    @{
        protocol = 'udp'
        address = $_.LocalAddress
        port = [int]$_.LocalPort
        process = if ($procMap.ContainsKey($_.OwningProcess)) { $procMap[$_.OwningProcess] } else { "pid:$($_.OwningProcess)" }
    }
}

$fwRules = Get-NetFirewallRule -Direction Inbound -Action Allow | Select-Object -First 150 | ForEach-Object {
    $pfObj = $_ | Get-NetFirewallPortFilter
    $afObj = $_ | Get-NetFirewallAddressFilter
    @{
        name = $_.DisplayName
        enabled = ($_.Enabled -eq 'True')
        protocol = ($pfObj.Protocol | Out-String).Trim().ToLower()
        port = if ($pfObj.LocalPort -match '^\d+$') { [int]$pfObj.LocalPort } else { 0 }
        source = (($afObj.RemoteAddress -join ',') -replace 'Any','0.0.0.0/0')
        action = 'allow'
    }
}

$adminGroup = Get-LocalGroup -SID 'S-1-5-32-544'
$admins = Get-LocalGroupMember -Group $adminGroup.Name | ForEach-Object {
    $lu = Get-LocalUser -Name ($_.Name -replace '^.*\\','') -ErrorAction SilentlyContinue
    $daysInactive = $null
    if ($lu -and $lu.LastLogon) {
        $daysInactive = [int]((Get-Date) - $lu.LastLogon).TotalDays
    }
    @{
        username = $_.Name
        privilege_source = 'Administrators'
        is_service_account = ($_.Name -match 'svc|service')
        last_login_days = $daysInactive
        password_never_expires = if ($lu) { [bool]$lu.PasswordNeverExpires } else { $false }
    }
}

$since = (Get-Date).AddHours(-24)
$events = @()
foreach ($logName in @('System','Application')) {
    Get-WinEvent -FilterHashtable @{ LogName=$logName; Level=1,2; StartTime=$since } -MaxEvents 20 | ForEach-Object {
        $events += @{
            source = $logName
            message = ($_.Message -split "`n")[0].Substring(0, [Math]::Min(280, ($_.Message -split "`n")[0].Length))
            context = $_.Message.Substring(0, [Math]::Min(800, $_.Message.Length))
        }
    }
}
$failedLogons = (Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4625; StartTime=$since } -MaxEvents 50).Count
if ($failedLogons -gt 0) {
    $events += @{
        source = 'Security'
        message = "$failedLogons failed logon attempts (Event ID 4625) in last 24h"
        context = "Event ID 4625 count=$failedLogons"
        count = $failedLogons
    }
}

$hotfixes = (Get-HotFix | Measure-Object).Count

@{
    os_info = @{ os_name = $os.Caption; kernel = $os.BuildNumber; uptime_seconds = $uptimeSec; fqdn = $env:COMPUTERNAME }
    cpu = @{ usage_pct = $cpuPct; load_1m = 0; load_5m = 0; load_15m = 0; cores = [int]$env:NUMBER_OF_PROCESSORS; top_processes = @($topCpu) }
    memory = @{ total_bytes = $totalMem; used_bytes = $usedMem; usage_pct = $memPct; swap_total_bytes = $swapTotal; swap_used_bytes = $swapUsed; swap_pct = $swapPct; top_processes = @() }
    filesystems = @($disks)
    services = @($services)
    ports = @($tcpPorts) + @($udpPorts)
    firewall = @{ backend = 'windows_defender'; rules = @($fwRules) }
    admins = @($admins)
    logs_inventory = @('System','Application','Security')
    log_events = @($events)
    updates = @{ pending_count = 0; installed_hotfixes = $hotfixes }
} | ConvertTo-Json -Depth 6 -Compress
"""


class WindowsCollector(BaseCollector):
    """Collects telemetry from Windows servers over WinRM HTTPS (port 5986)."""

    def __init__(self, *args: Any, auth_transport: str = "ntlm", **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.auth_transport = auth_transport
        self._session: Optional[winrm.Session] = None

    def connect(self) -> None:
        settings = get_settings()
        port = self.port or 5986
        endpoint = f"https://{self.ip_address}:{port}/wsman"
        cert_val = "validate" if settings.winrm_verify_ssl else "ignore"
        self._session = winrm.Session(
            endpoint,
            auth=(self.username, self.secret),
            transport=self.auth_transport,
            server_cert_validation=cert_val,
            read_timeout_sec=self.timeout_seconds,
            operation_timeout_sec=max(10, self.timeout_seconds - 5),
        )

    def run_command(self, command: str) -> CommandResult:
        if self._session is None:
            raise RuntimeError("WinRM session not initialized")
        start = time.monotonic()
        resp = self._session.run_ps(command)
        duration_ms = (time.monotonic() - start) * 1000.0
        return CommandResult(
            exit_code=resp.status_code,
            stdout=resp.std_out.decode("utf-8", errors="replace"),
            stderr=resp.std_err.decode("utf-8", errors="replace"),
            duration_ms=duration_ms,
        )

    def close(self) -> None:
        self._session = None

    def collect_all(self) -> HostTelemetry:
        telemetry = HostTelemetry(hostname=self.hostname, os_type="windows")
        t0 = time.monotonic()
        self.connect()
        try:
            res = self.run_command(_WINDOWS_TELEMETRY_PS)
            telemetry.latency_ms = round((time.monotonic() - t0) * 1000.0, 2)
            if res.exit_code != 0 and not res.stdout.strip():
                raise RuntimeError(f"WinRM PowerShell failed: {res.stderr.strip()}")
            data = json.loads(res.stdout)
            telemetry.os_info = data.get("os_info", {})
            telemetry.cpu = data.get("cpu", {})
            telemetry.memory = data.get("memory", {})
            telemetry.filesystems = data.get("filesystems", [])
            telemetry.services = data.get("services", [])
            telemetry.ports = data.get("ports", [])
            telemetry.firewall = data.get("firewall", {})
            telemetry.admins = data.get("admins", [])
            telemetry.logs_inventory = data.get("logs_inventory", [])
            telemetry.log_events = data.get("log_events", [])
            telemetry.updates = data.get("updates", {})
            return telemetry
        finally:
            self.close()
