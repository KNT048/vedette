// Two one-line osquery install scripts served by THE BOX ITSELF (S-INV-4): /api/v1/install/osquery.sh and /osquery.ps1.
// The box uses a self-signed CA so the CA is embedded straight into the script; the user compares the SHA-256 of the script (shown in the UI, a signed-in channel) before running it,
// every later download pins this CA (no more -k): Linux with curl --cacert, Windows with .NET using a verification function of its own for each request (curl.exe/Schannel cannot check the box's CA). The osquery package is mirrored by the box from the official release and checksum-checked, so the server needs no Internet.
// Checked against documentation (2026-11-06):
// - Linux: .deb/.rpm packages, the systemd service "osqueryd" (/usr/lib/systemd/system/osqueryd.service), configuration in /etc/osquery/, `systemctl enable --now osqueryd`.
//   https://osquery.readthedocs.io/en/stable/installation/install-linux/ ; the manual install in agentConfig.ts also downloads the package from the box, no external repository.
// - Windows: the MSI installs into C:\Program Files\osquery, daemon osqueryd\osqueryd.exe, the service "osqueryd" created with manage-osqueryd.ps1 -install -startupArgs "--flagfile=…", Start-Service osqueryd.
//   https://osquery.readthedocs.io/en/stable/installation/install-windows/
// - TLS flags: config_plugin, logger_plugin, enroll_secret_path, tls_server_certs, tls_hostname (with the port, without https://), *_tls_endpoint, host_identifier.
//   https://osquery.readthedocs.io/en/stable/deployment/remote/
// PACKAGE NAMES mirrored by the box (following the osquery release file names on GitHub; a real backend must match): osquery_<ver>-1.linux_amd64.deb, osquery-<ver>-1.linux.x86_64.rpm,
// osquery_<ver>-1.linux_arm64.deb, osquery-<ver>-1.linux.aarch64.rpm, osquery-<ver>.msi, with SHA256SUMS, all under /api/v1/install/osquery/. The paths /api/v1/install/*, /api/v1/intake/* are Vedette's own (mock names).

export const OSQUERY_VERSION = '5.12.1'
/** The host part of server_url while the box knows no address other machines can reach (agent-intake PRE-3): the box serves no script
 *  then (404 no_box_address) and the GUI shows how to give it one instead of a command that cannot work. */
export const NO_BOX_ADDRESS = '<VEDETTE_BOX_IP>'

import BASH from './scripts/osquery.sh?raw'
import PWSH from './scripts/osquery.ps1?raw'

const fill = (t: string, box: string, ca: string) => t.replaceAll('@@BOX@@', box).replaceAll('@@VERSION@@', OSQUERY_VERSION).replaceAll('@@CA@@', ca.trim())
export const linuxInstallScript = (box: string, ca: string) => fill(BASH, box, ca)
export const windowsInstallScript = (box: string, ca: string) => fill(PWSH, box, ca)

/** A one-line install command: download from the box, compare the SHA-256 shown in the UI, then run with the token. The token goes through a parameter, never in the URL.
 *  The script downloads into a fresh mktemp file every time and then deletes it: a fixed path in /tmp left by another user cannot overwrite it
 *  (Ubuntu's fs.protected_regular=2; the real run 2). */
export function linuxOneLiner(box: string, sha256: string, token: string, action: 'install' | 'uninstall' = 'install') {
  const arg = action === 'install' ? `--token ${token}` : '--uninstall'
  // In a subshell, so the exit status of the download, the check or the install survives the cleanup and `exit` never closes the admin's terminal.
  // One command for every common Linux. A system without sudo (Alpine as root) runs the script itself; one without curl (Alpine) downloads with
  // busybox wget. The script's checksum is checked either way, and it then decides by itself between osquery and the package reporter.
  const url = `${box}/api/v1/install/osquery.sh`
  return `(command -v sudo >/dev/null 2>&1 || sudo() { "$@"; }; f=$(mktemp) && { curl -fsSLk ${url} -o "$f" || wget -qO "$f" --no-check-certificate ${url}; } && echo "${sha256}  $f" | sha256sum -c - && sudo sh "$f" ${arg}; r=$?; rm -f "$f"; exit $r)`
}
/** Windows PowerShell 5.1: there is no -SkipCertificateCheck, so only the first script download uses curl.exe -k (there is no CA yet); the script embeds the CA and pins it for every later download (.NET).
 *  A new file name each time (a GUID, the .ps1 extension because -File needs it) and deleted after running, like the Linux version. */
export function windowsOneLiner(box: string, sha256: string, token: string, action: 'install' | 'uninstall' = 'install') {
  const arg = action === 'install' ? `-Token '${token}'` : '-Uninstall'
  return `$f=Join-Path $env:TEMP ('vedette-osquery-'+[guid]::NewGuid()+'.ps1'); curl.exe -fsSLk ${box}/api/v1/install/osquery.ps1 -o $f; if ((Get-FileHash $f -Algorithm SHA256).Hash -ieq '${sha256}') { powershell -NoProfile -ExecutionPolicy Bypass -File $f ${arg}; Remove-Item -Force $f } else { Remove-Item -Force $f; throw 'Checksum mismatch: do not run this file' }`
}
