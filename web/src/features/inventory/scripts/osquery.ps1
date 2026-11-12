# Vedette osquery installer for Windows Server. Served by your Vedette box: @@BOX@@
# Run in PowerShell as Administrator (Windows PowerShell 5.1 or later). Safe to run again. Remove everything with: -Uninstall
# What it does, in order:
#   1. writes the Vedette box CA certificate (embedded below) to C:\Program Files\osquery\vedette-ca.pem
#   2. downloads osquery @@VERSION@@ (MSI) and SHA256SUMS from the box (the box mirrors the official osquery release),
#      checks the SHA-256 of the MSI, installs it silently with msiexec /qn
#   3. writes the enroll secret and osquery.flags, sets the osqueryd service to Automatic and starts it
#   4. waits for the first check-in and prints the result
param([string]$Token = '', [switch]$Uninstall)
$ErrorActionPreference = 'Stop'
$Box = '@@BOX@@'
$Version = '@@VERSION@@'
$Dir = 'C:\Program Files\osquery'
$Ca = Join-Path $Dir 'vedette-ca.pem'
$Curl = Join-Path $env:SystemRoot 'System32\curl.exe'   # ships with Windows Server 2019 and later; it can use our CA file with --cacert

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run PowerShell as Administrator.' }

if ($Uninstall) {
  if (Get-Service osqueryd -ErrorAction SilentlyContinue) { Stop-Service osqueryd -Force -ErrorAction SilentlyContinue; sc.exe delete osqueryd | Out-Null }
  $p = Get-CimInstance Win32_Product -Filter "Name='osquery'" -ErrorAction SilentlyContinue
  if ($p) { Start-Process msiexec -ArgumentList '/x', $p.IdentifyingNumber, '/qn', '/norestart' -Wait }
  Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $Dir 'osquery.flags'), (Join-Path $Dir 'enroll.secret'), $Ca
  Write-Host 'osquery and the Vedette settings were removed from this machine.'
  return
}

if (-not $Token) { throw 'Missing -Token. Copy the install command from Vedette, Devices, Scope and sensors.' }
if (-not (Test-Path $Curl)) { throw 'curl.exe was not found. Use Windows Server 2019 or later, or follow Advanced: manual setup in Vedette.' }

$Tmp = Join-Path $env:TEMP ('vedette-osquery-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $Tmp | Out-Null
try {
  New-Item -ItemType Directory -Force -Path $Dir | Out-Null
  @'
@@CA@@
'@ | Set-Content -Path $Ca -Encoding ascii

  $File = "osquery-$Version.msi"
  & $Curl -fsS --cacert $Ca "$Box/api/v1/install/osquery/SHA256SUMS" -o (Join-Path $Tmp 'SHA256SUMS')
  & $Curl -fsS --cacert $Ca "$Box/api/v1/install/osquery/$File" -o (Join-Path $Tmp $File)
  $want = ((Get-Content (Join-Path $Tmp 'SHA256SUMS')) | Where-Object { $_ -match [regex]::Escape($File) + '$' } | Select-Object -First 1) -split '\s+' | Select-Object -First 1
  $got = (Get-FileHash (Join-Path $Tmp $File) -Algorithm SHA256).Hash
  if (-not $want -or $got -ne $want.ToUpper()) { throw "Checksum of $File does not match. Nothing was installed." }
  Start-Process msiexec -ArgumentList '/i', (Join-Path $Tmp $File), '/qn', '/norestart' -Wait

  Set-Content -Path (Join-Path $Dir 'enroll.secret') -Value $Token -NoNewline -Encoding ascii
  $hostPort = $Box -replace '^https://', ''
  @(
    '--config_plugin=tls', '--logger_plugin=tls', '--host_identifier=hostname',
    "--enroll_secret_path=$Dir\enroll.secret", "--tls_server_certs=$Ca", "--tls_hostname=$hostPort",
    '--enroll_tls_endpoint=/api/v1/intake/osquery/enroll', '--config_tls_endpoint=/api/v1/intake/osquery/config', '--logger_tls_endpoint=/api/v1/intake/osquery/log'
  ) | Set-Content -Path (Join-Path $Dir 'osquery.flags') -Encoding ascii
  if (-not (Test-Path (Join-Path $Dir 'osquery.conf'))) { '{}' | Set-Content -Path (Join-Path $Dir 'osquery.conf') -Encoding ascii }

  if (-not (Get-Service osqueryd -ErrorAction SilentlyContinue)) {
    Push-Location $Dir
    .\manage-osqueryd.ps1 -install -startupArgs ('--flagfile="' + $Dir + '\osquery.flags"')
    Pop-Location
  }
  Set-Service osqueryd -StartupType Automatic
  Restart-Service osqueryd

  Write-Host 'Waiting for the first check-in (up to 2 minutes)...'
  for ($i = 0; $i -lt 24; $i++) {
    $r = & $Curl -fsS --cacert $Ca -X POST -H "Authorization: Bearer $Token" "$Box/api/v1/intake/osquery/status"
    if ($r -match '"enrolled":true') { Write-Host 'Done: this machine checked in with Vedette.'; return }
    Start-Sleep -Seconds 5
  }
  Write-Warning 'osquery is installed and running, but Vedette has not received its first report yet. This is normal: osquery sends its first report within about an hour. If it is still missing after two hours, check: Get-Service osqueryd'
} finally { Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue }
