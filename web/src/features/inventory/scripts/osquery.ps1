# Vedette osquery installer for Windows Server. Served by your Vedette box: @@BOX@@
# Run in PowerShell as Administrator (Windows PowerShell 5.1 or later). Safe to run again. Remove everything with: -Uninstall
# What it does, in order:
#   1. downloads osquery @@VERSION@@ (MSI) and SHA256SUMS from the box (the box mirrors the official osquery release),
#      checks the SHA-256 of the MSI, installs it silently with msiexec /qn
#   2. writes the Vedette box CA certificate (embedded below) to C:\Program Files\osquery\vedette-ca.pem, the enroll secret and osquery.flags, sets the osqueryd service to start automatically (delayed) and to restart itself after a failure, checks those settings, and starts it; with a token this machine does
#      not hold yet, it first removes osquery's database (osquery.db: the old node key and unsent results) so that it enrols under the new token
#   3. waits until this machine has enrolled (not for its first report, due within a few minutes) and exits 0
# Every request to the box checks that its certificate chains to the CA embedded below. Nothing is added to the Windows certificate
# store, and no other server is trusted.
param([string]$Token = '', [switch]$Uninstall)
$ErrorActionPreference = 'Stop'
$Box = '@@BOX@@'
$Version = '@@VERSION@@'
$Dir = 'C:\Program Files\osquery'
$Ca = Join-Path $Dir 'vedette-ca.pem'
$Db = Join-Path $Dir 'osquery.db'   # osqueryd's default --database_path: its node key and its unsent results
$Secret = Join-Path $Dir 'enroll.secret'
$CaPem = @'
@@CA@@
'@

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

if (-not $Token) { throw 'Missing -Token. Copy the install command from Vedette, Devices › Setup › Agents.' }
# The certificate check below is C# code (Add-Type). A WDAC or AppLocker policy that puts PowerShell in Constrained Language Mode blocks it;
# say so plainly instead of PowerShell's language-mode error (#798 review minor 3).
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
  throw "PowerShell runs in $($ExecutionContext.SessionState.LanguageMode) mode on this machine (a WDAC or AppLocker policy), which blocks the check of the box's certificate this script needs. Nothing was installed. Use 'Advanced: manual setup' in Vedette (Settings › Scanning › Safety, Agents) instead."
}

# HTTPS to the box with .NET, not curl.exe: curl.exe's Schannel asks for the revocation status of the box CA, which has none, and
# with a CA file it does not match an IP address in the certificate, so it cannot reach a box at its default (IPv4) address. The check
# below accepts the box only when its certificate chain contains a certificate embedded in this script, every signature and date in the
# chain is valid, the certificate is for server use, and it names the box address (Windows' own name check, or the IP address entry
# when Windows does not match one). It is set on each request of this script, never for the whole machine; TLS 1.2.
if (-not ('VedetteBox' -as [type])) {
  Add-Type -Language CSharp -IgnoreWarnings -TypeDefinition @'
using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

public static class VedetteBox {
  static X509Certificate2Collection pins = new X509Certificate2Collection();
  static string host = "";
  // Why the last check refused the box's certificate ("" = it did not), for the error message: Windows' own message is the same for every
  // reason (#798 review minor 4).
  public static string Refusal = "";

  static bool Refuse(string why) { Refusal = why; return false; }

  public static void Pin(string pem, string boxHost) {
    pins.Clear();
    foreach (Match m in Regex.Matches(pem, "-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\\s]+)-----END CERTIFICATE-----")) {
      pins.Add(new X509Certificate2(Convert.FromBase64String(Regex.Replace(m.Groups[1].Value, "\\s", ""))));
    }
    if (pins.Count == 0) { throw new InvalidOperationException("This script holds no box certificate. Copy the command again from Vedette."); }
    host = boxHost.Trim('[', ']');
    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
  }

  static bool Check(object sender, X509Certificate cert, X509Chain sent, SslPolicyErrors errors) {
    if (cert == null || pins.Count == 0 || (errors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0) { return Refuse("the server sent no certificate"); }
    X509Certificate2 leaf = new X509Certificate2(cert);
    if ((errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0 && !IpInSan(leaf, host)) { return Refuse("its certificate is not for the address " + host); }
    X509Chain chain = new X509Chain(false);
    try {
      chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // the box CA has no CRL or OCSP; the pin below replaces the store
      chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
      chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1")); // serverAuth
      chain.ChainPolicy.ExtraStore.AddRange(pins);
      if (sent != null) { foreach (X509ChainElement e in sent.ChainElements) { chain.ChainPolicy.ExtraStore.Add(e.Certificate); } }
      if (!chain.Build(leaf)) { return Refuse("its certificate chain is not valid (" + Flags(chain) + ")"); }
      // AllowUnknownCertificateAuthority only waives "not in the Windows store"; anything else (a bad signature, an expired certificate,
      // usage) refuses. NotTimeNested is ignored as Windows itself does: each certificate's own dates are still checked (NotTimeValid).
      X509ChainStatusFlags waived = X509ChainStatusFlags.UntrustedRoot | X509ChainStatusFlags.PartialChain | X509ChainStatusFlags.NotTimeNested;
      foreach (X509ChainStatus s in chain.ChainStatus) {
        if ((s.Status & ~waived) != 0) { return Refuse("its certificate chain is not valid (" + Flags(chain) + ")"); }
      }
      foreach (X509ChainElement e in chain.ChainElements) {
        foreach (X509Certificate2 p in pins) {
          if (Same(e.Certificate.RawData, p.RawData)) { return true; }
        }
      }
      return Refuse("its certificate is not signed by the box CA embedded in this script");
    } finally { chain.Reset(); }
  }

  static string Flags(X509Chain chain) {
    StringBuilder b = new StringBuilder();
    foreach (X509ChainStatus s in chain.ChainStatus) { if (b.Length > 0) { b.Append(", "); } b.Append(s.Status.ToString()); }
    return b.Length > 0 ? b.ToString() : "no status";
  }

  static bool Same(byte[] a, byte[] b) {
    if (a.Length != b.Length) { return false; }
    for (int i = 0; i < a.Length; i++) { if (a[i] != b[i]) { return false; } }
    return true;
  }

  // The DER header at d[i]: tag, where the content starts and its length; false when it does not fit in d.
  static bool Header(byte[] d, int i, out int tag, out int start, out int len) {
    tag = 0; start = 0; len = 0;
    if (i < 0 || i + 2 > d.Length) { return false; }
    tag = d[i];
    int l = d[i + 1];
    start = i + 2;
    if (l >= 0x80) {
      int n = l & 0x7f;
      if (n < 1 || n > 2 || start + n > d.Length) { return false; }
      l = 0;
      for (int k = 0; k < n; k++) { l = (l << 8) | d[start + k]; }
      start += n;
    }
    len = l;
    return start + len <= d.Length;
  }

  // True when the box address is an IP address and the certificate's subjectAltName has that iPAddress entry ([7], RFC 5280 4.2.1.6).
  static bool IpInSan(X509Certificate2 leaf, string h) {
    IPAddress want;
    if (!IPAddress.TryParse(h, out want)) { return false; }
    byte[] w = want.GetAddressBytes();
    foreach (X509Extension x in leaf.Extensions) {
      if (x.Oid == null || x.Oid.Value != "2.5.29.17") { continue; }
      byte[] d = x.RawData;
      int tag, s, n;
      if (!Header(d, 0, out tag, out s, out n) || tag != 0x30) { return false; }
      int end = s + n;
      for (int i = s; i < end; i = s + n) {
        if (!Header(d, i, out tag, out s, out n) || s + n > end) { return false; }
        if (tag == 0x87 && n == w.Length) {
          byte[] got = new byte[n];
          Array.Copy(d, s, got, 0, n);
          if (Same(got, w)) { return true; }
        }
      }
    }
    return false;
  }

  static HttpWebRequest Open(string url, string method) {
    HttpWebRequest r = (HttpWebRequest)WebRequest.Create(url);
    if (r.RequestUri.Scheme != Uri.UriSchemeHttps) { throw new InvalidOperationException("Not an https address: " + url); }
    r.Method = method;
    r.ServerCertificateValidationCallback = Check;
    r.Proxy = null;              // straight to the box on the LAN, like osqueryd
    r.AllowAutoRedirect = false; // the box never redirects
    r.Timeout = 30000;
    r.ReadWriteTimeout = 300000;
    return r;
  }

  public static void Download(string url, string path) {
    Refusal = "";
    using (HttpWebResponse res = (HttpWebResponse)Open(url, "GET").GetResponse()) {
      if (res.StatusCode != HttpStatusCode.OK) { throw new WebException("The box answered " + (int)res.StatusCode + " for " + url); }
      using (Stream body = res.GetResponseStream()) {
        using (FileStream f = File.Create(path)) { body.CopyTo(f); }
      }
    }
  }

  public static string PostJson(string url, string bearer, string json) {
    HttpWebRequest r = Open(url, "POST");
    r.ContentType = "application/json";
    r.Headers[HttpRequestHeader.Authorization] = "Bearer " + bearer;
    byte[] b = Encoding.UTF8.GetBytes(json);
    r.ContentLength = b.Length;
    using (Stream o = r.GetRequestStream()) { o.Write(b, 0, b.Length); }
    using (HttpWebResponse res = (HttpWebResponse)r.GetResponse()) {
      using (StreamReader rd = new StreamReader(res.GetResponseStream(), Encoding.UTF8)) { return rd.ReadToEnd(); }
    }
  }
}
'@
}
[VedetteBox]::Pin($CaPem, ([Uri]$Box).Host)
function Get-FromBox([string]$Name, [string]$To) {
  try { [VedetteBox]::Download("$Box/api/v1/install/osquery/$Name", $To) }
  catch {
    # The pinned check's own reason comes first: Windows says only that the certificate is invalid, whatever the reason.
    $why = if ([VedetteBox]::Refusal) { "the box's certificate was refused: $([VedetteBox]::Refusal)" } else { $_.Exception.GetBaseException().Message }
    throw "Could not download $Name from $Box ($why). Nothing was installed."
  }
}

# The name this machine enrols under is chosen here (--host_identifier=specified), so the status check below asks for exactly that name.
$hostId = [regex]::Replace([System.Net.Dns]::GetHostName(), '[^A-Za-z0-9._-]', '')
if (-not $hostId) { throw "Cannot read this machine's host name." }
$Tmp = Join-Path $env:TEMP ('vedette-osquery-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $Tmp | Out-Null
try {
  $File = "osquery-$Version.msi"
  Get-FromBox 'SHA256SUMS' (Join-Path $Tmp 'SHA256SUMS')
  Get-FromBox $File (Join-Path $Tmp $File)
  $want = ((Get-Content (Join-Path $Tmp 'SHA256SUMS')) | Where-Object { $_ -match [regex]::Escape($File) + '$' } | Select-Object -First 1) -split '\s+' | Select-Object -First 1
  $got = (Get-FileHash (Join-Path $Tmp $File) -Algorithm SHA256).Hash
  if (-not $want -or $got -ne $want.ToUpper()) { throw "Checksum of $File does not match. Nothing was installed." }
  $msi = Start-Process msiexec -ArgumentList '/i', (Join-Path $Tmp $File), '/qn', '/norestart' -Wait -PassThru
  # 0 = installed, 3010 = installed, a restart finishes it. Anything else (1603 failed, 1618 another installation is running) stops here,
  # before the CA file, the flags or the service are touched (#801 review r1 #5).
  if ($msi.ExitCode -ne 0 -and $msi.ExitCode -ne 3010) { throw "The osquery installer (msiexec) failed with exit code $($msi.ExitCode). Nothing was changed; run this command again (1618: wait for the other installation to finish)." }
  # Only now, with the package verified and installed: a failed run (another box unreachable, a refused certificate) leaves the CA file of a
  # working enrolment alone, which the running osqueryd pins (#798 review minor 2).
  New-Item -ItemType Directory -Force -Path $Dir | Out-Null
  $CaPem | Set-Content -Path $Ca -Encoding ascii

  # osqueryd keeps the node key of its enrolment in its database and does not enrol again while the box accepts that key. Unless this
  # machine already holds this very token (a repair keeps its key), its database is removed so that it enrols under this token.
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
  # The agent keeps itself running: osqueryd restarts after a failure (1 minute, 1 minute, then 5 minutes every time; the failure count
  # resets after a day without one), also when it exits with an error code instead of crashing (failureflag), and starts automatically,
  # delayed until the boot is done. The settings are read back from the service's registry key (not from sc.exe's text, which is
  # translated). A setting that did not apply does not stop this run (the service may already be stopped and its database removed above,
  # and the agent must come back and enrol): the problem is kept, the agent is started, and the run ends with a warning and exit code 4.
  $recoveryProblem = ''
  $scOut = @()
  $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue' # a native command's stderr must not end the run before the read-back
  $scOut += (sc.exe config osqueryd start= delayed-auto 2>&1)
  $scOut += (sc.exe failure osqueryd reset= 86400 actions= restart/60000/restart/60000/restart/300000 2>&1)
  $scOut += (sc.exe failureflag osqueryd 1 2>&1)
  $ErrorActionPreference = $eap
  $svc = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\osqueryd'
  $fa = $svc.FailureActions
  $restarts = 0
  if ($fa -and $fa.Length -ge 28) {
    $n = [BitConverter]::ToUInt32($fa, 12)
    for ($k = 0; $k -lt $n -and (20 + 8 * $k + 8) -le $fa.Length; $k++) { if ([BitConverter]::ToUInt32($fa, 20 + 8 * $k) -eq 1) { $restarts++ } }
  }
  if ($svc.Start -ne 2 -or $svc.DelayedAutostart -ne 1 -or -not $fa -or $fa.Length -lt 28 -or [BitConverter]::ToUInt32($fa, 0) -ne 86400 -or $restarts -ne 3 -or $svc.FailureActionsOnNonCrashFailures -ne 1) {
    $recoveryProblem = "The osqueryd service did not take its recovery settings (restart on failure, delayed automatic start), so nothing restarts the agent if it stops. sc.exe said: $(($scOut | Where-Object { $_ }) -join ' ')  Check them with: sc.exe qfailure osqueryd ; sc.exe qc osqueryd"
  }
  function Show-RecoveryProblem {
    if ($recoveryProblem) { Write-Warning "The agent is running and enrolled, but it will NOT restart itself. $recoveryProblem" }
  }
  # status for THIS machine: sent its name (the host_identifier set above), it returns host_last_seen, when the box last heard from a machine of
  # this token with that name (null = none yet). Success = osqueryd runs and that value appeared or moved since before the restart.
  function Get-Seen {
    $r = ''
    try { $r = [VedetteBox]::PostJson("$Box/api/v1/intake/osquery/status", $Token, '{"host_identifier":"' + $hostId + '"}') } catch { $r = '' }
    if ("$r" -match '"host_last_seen":"([^"]*)"') { return $Matches[1] }
    return ''
  }
  $base = Get-Seen
  Restart-Service osqueryd

  Write-Host 'Waiting for this machine to enrol with Vedette (up to 2 minutes)...'
  for ($i = 0; $i -lt 24; $i++) {
    $now = Get-Seen
    if ($hostId -and $now -and $now -ne $base -and (Get-Service osqueryd).Status -eq 'Running') {
      if ($recoveryProblem) { Show-RecoveryProblem; exit 4 }
      Write-Host "Installed and enrolled; this machine's operating system and packages appear in Vedette within a few minutes."; return
    }
    Start-Sleep -Seconds 5
  }
  Write-Warning 'osquery is installed, but this machine did not enrol with Vedette within 2 minutes. Check that the box address is reachable from here and the token is still valid, then: Get-Service osqueryd'
  Show-RecoveryProblem
  exit 3
} finally { Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue }
