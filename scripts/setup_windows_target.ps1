# Run on target Windows servers as Administrator to configure read-only WinRM HTTPS monitoring.
param(
    [string]$MonitorUser = "socmon_ro",
    [Parameter(Mandatory=$true)][string]$Password
)

$secPass = ConvertTo-SecureString $Password -AsPlainText -Force
if (-not (Get-LocalUser -Name $MonitorUser -ErrorAction SilentlyContinue)) {
    New-LocalUser -Name $MonitorUser -Password $secPass -Description "SOC-Monitor Read-Only Account" -PasswordNeverExpires:$false
}

# Add to read-only built-in groups (no Domain Admin, no local Administrators)
foreach ($grp in @("Event Log Readers", "Performance Monitor Users", "Distributed COM Users")) {
    if (Get-LocalGroup -Name $grp -ErrorAction SilentlyContinue) {
        Add-LocalGroupMember -Group $grp -Member $MonitorUser -ErrorAction SilentlyContinue
    }
}

# Enable WinRM HTTPS (port 5986) with self-signed cert if no HTTPS listener exists
$httpsListener = Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys -match "Transport=HTTPS" }
if (-not $httpsListener) {
    $cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My
    New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -Force
}

New-NetFirewallRule -DisplayName "SOC-Monitor WinRM HTTPS" -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow -ErrorAction SilentlyContinue
Write-Host "Windows target $MonitorUser and WinRM HTTPS (5986) configured."
