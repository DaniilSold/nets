param(
    [string]$ProcessName = "python",
    [int]$Port = 8080
)
$ErrorActionPreference = "Stop"
New-NetFirewallRule -DisplayName "NETS Temp Quarantine" -Direction Inbound -Action Block -Protocol TCP -LocalPort $Port | Out-Null
Start-Sleep -Seconds 2
Remove-NetFirewallRule -DisplayName "NETS Temp Quarantine"
