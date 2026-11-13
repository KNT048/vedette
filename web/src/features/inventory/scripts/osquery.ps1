# Vedette osquery installer for Windows Server. Served by your Vedette box: @@BOX@@
# Run in PowerShell as Administrator (Windows PowerShell 5.1 or later). Safe to run again. Remove everything with: -Uninstall
# What it does, in order:
#   1. writes the Vedette box CA certificate (embedded below) to C:\Program Files\osquery\vedette-ca.pem
#   2. downloads osquery @@VERSION@@ (MSI) and SHA256SUMS from the box (the box mirrors the official osquery release),
#      checks the SHA-256 of the MSI, installs it silently with msiexec /qn
#   3. writes the enroll secret and osquery.flags, sets the osqueryd service to Automatic and starts it; with a token this machine does
#      not hold yet, it first removes osquery's database (osquery.db: the old node key and unsent results) so that it enrols under the new token
#   4. waits until this machine has enrolled (not for its first report, due within a few minutes) and exits 0
param([string]$Token = '', [switch]$Uninstall)
$ErrorActionPreference = 'Stop'
$Box = '@@BOX@@'
$Version = '@@VERSION@@'
$Dir = 'C:\Program Files\osquery'
$Ca = Join-Path $Dir 'vedette-ca.pem'
$Db = Join-Path $Dir 'osquery.db'   # osqueryd's default --database_path: its node key and its unsent results
$Secret = Join-Path $Dir 'enroll.secret'
$Curl = Join-Path $env:SystemRoot 'System32\curl.exe'   # ships with Windows Server 2019 and later; it can use our CA file with --cacert

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run PowerShell as Administrator.' }

if ($Uninstall) {
  if (Get-Service osqueryd -ErrorAction SilentlyContinue) { Stop-Service osqueryd -Force -ErrorAction SilentlyContinue; sc.exe delete osqueryd | Out-Null }
  $p = Get-CimInstance Win32_Product -Filter "Name='osquery'" -ErrorAction SilentlyContinue
  if ($p) { Start-Process msiexec -ArgumentList '/x', $p.IdentifyingNumber, '/qn', '/norestart' -Wait }
  Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $Dir 'osquery.flags'), $Secret, $Ca
  Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $Db
  Write-Host 'osquery and the Vedette settings were removed from this machine.'
  return
}

if (-not $Token) { throw 'Missing -Token. Copy the install command from Vedette, Devices, Scope and sensors.' }
if (-not (Test-Path $Curl)) { throw 'curl.exe was not found. Use Windows Server 2019 or later, or follow Advanced: manual setup in Vedette.' }

# The name this machine enrols under is chosen here (--host_identifier=specified), so the status check below asks for exactly that name.
$hostId = [regex]::Replace([System.Net.Dns]::GetHostName(), '[^A-Za-z0-9._-]', '')
if (-not $hostId) { throw "Cannot read this machine's host name." }
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

  # osqueryd keeps the node key of its enrolment in its database and does not enrol again while the box accepts that key. Unless this
  # machine already holds this very token (a repair keeps its key), its database is removed so that it enrols under this token (D-411).
  $held = if (Test-Path $Secret) { Get-Content -Raw -Path $Secret } else { '' }
  if ($held -cne $Token) {
    if ($held) { Write-Host 'This machine was enrolled with another token; it enrols again under this one. The old token lists it until it has been silent for 90 days or you revoke that token in Vedette.' }
    if (Get-Service osqueryd -ErrorAction SilentlyContinue) { Stop-Service osqueryd -Force }
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $Db
    if (Test-Path $Db) { throw "Could not remove $Db (a file is still open). Stop the osqueryd service and run this command again." }
  }
  Set-Content -Path $Secret -Value $Token -NoNewline -Encoding ascii
  $hostPort = $Box -replace '^https://', ''
  @(
    '--config_plugin=tls', '--logger_plugin=tls', '--host_identifier=specified', "--specified_identifier=$hostId",
    "--enroll_secret_path=$Secret", "--tls_server_certs=$Ca", "--tls_hostname=$hostPort",
    '--enroll_tls_endpoint=/api/v1/intake/osquery/enroll', '--config_tls_endpoint=/api/v1/intake/osquery/config', '--config_refresh=300', '--logger_tls_endpoint=/api/v1/intake/osquery/log'
  ) | Set-Content -Path (Join-Path $Dir 'osquery.flags') -Encoding ascii
  if (-not (Test-Path (Join-Path $Dir 'osquery.conf'))) { '{}' | Set-Content -Path (Join-Path $Dir 'osquery.conf') -Encoding ascii }

  if (-not (Get-Service osqueryd -ErrorAction SilentlyContinue)) {
    Push-Location $Dir
    .\manage-osqueryd.ps1 -install -startupArgs ('--flagfile="' + $Dir + '\osquery.flags"')
    Pop-Location
  }
  Set-Service osqueryd -StartupType Automatic
  # status for THIS machine: sent its name (the host_identifier set above), it returns host_last_seen, when the box last heard from a machine of
  # this token with that name (null = none yet). Success = osqueryd runs and that value appeared or moved since before the restart.
  $statusBody = Join-Path $Tmp 'status.json'
  Set-Content -Path $statusBody -Value ('{"host_identifier":"' + $hostId + '"}') -Encoding ascii -NoNewline
  function Get-Seen {
    $r = $null
    try { $r = & $Curl -fsS --cacert $Ca -X POST -H "Authorization: Bearer $Token" -H 'Content-Type: application/json' --data-binary "@$statusBody" "$Box/api/v1/intake/osquery/status" } catch { $r = $null }
    if ("$r" -match '"host_last_seen":"([^"]*)"') { return $Matches[1] }
    return ''
  }
  $base = Get-Seen
  Restart-Service osqueryd

  Write-Host 'Waiting for this machine to enrol with Vedette (up to 2 minutes)...'
  for ($i = 0; $i -lt 24; $i++) {
    $now = Get-Seen
    if ($hostId -and $now -and $now -ne $base -and (Get-Service osqueryd).Status -eq 'Running') { Write-Host "Installed and enrolled; this machine's operating system and packages appear in Vedette within a few minutes."; return }
    Start-Sleep -Seconds 5
  }
  Write-Warning 'osquery is installed, but this machine did not enrol with Vedette within 2 minutes. Check that the box address is reachable from here and the token is still valid, then: Get-Service osqueryd'
  exit 3
} finally { Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue }
