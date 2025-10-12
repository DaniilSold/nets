param(
    [string]$Prefix = "C:\\Program Files\\NETS"
)
$ErrorActionPreference = "Stop"
$version = $env:VERSION
if (-not $version) { $version = "0.1.0" }
$dist = "dist\\msi"
New-Item -ItemType Directory -Force -Path $dist | Out-Null
Copy-Item -Path "target\\x86_64-pc-windows-msvc\\release\\nets.exe" -Destination "$dist\\nets-cli.exe"
Copy-Item -Path "target\\x86_64-pc-windows-msvc\\release\\ui.exe" -Destination "$dist\\nets-ui.exe" -ErrorAction SilentlyContinue
Copy-Item -Path "target\\x86_64-pc-windows-msvc\\release\\analyzer.exe" -Destination "$dist\\nets-analyzer.exe" -ErrorAction SilentlyContinue
Write-Host "Generate WiX toolset command manually: candle + light"
