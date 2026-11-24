// Agent configuration (S-INV-4). Only two ways: osquery (Linux and Windows Server; Vedette is the TLS server of osquery) and Wazuh (Vedette pulls over the API, nothing is installed on the agent machine).
// NO Trivy, NO macOS: Vedette supports server operating systems only (a product decision).
// Checked against vendor documentation (2026-11-06):
// - osquery TLS: flags config_plugin/logger_plugin=tls, enroll_secret_path, tls_server_certs, tls_hostname (with the port, without https://), enroll/config/logger_tls_endpoint, host_identifier.
//   https://osquery.readthedocs.io/en/stable/deployment/remote/
// - osquery query schedule: the JSON "schedule" (query, interval in seconds, snapshot, platform). https://osquery.readthedocs.io/en/stable/deployment/configuration/
// - osquery tables: os_version, deb_packages, rpm_packages, programs, system_info, interface_details, interface_addresses, kernel_info (the column
//   `version` is the running kernel, "7.0.0-43-generic", a one-line query of its own; the box attaches it to the package list so the Kernel row gets the exact running kernel image). https://osquery.io/schema/
//   (`os_revision` reads the `revision` column of os_version, available on Windows only since osquery 5.12: the UBR, the monthly patch, "22631.4460"; osquery reads
//   HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UBR. https://github.com/osquery/osquery/blob/5.12.1/specs/os_version.table)
//   (the `programs` query also reads exactly one registry value, PatchLevel of the Setup key of each SQL Server version
//   HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL<n>.<instance>\Setup: the installed build including the CU; the shared Uninstall entry
//   "Microsoft SQL Server 2022 (64-bit)" has no DisplayVersion. https://learn.microsoft.com/en-us/troubleshoot/sql/releases/components-client-tools-versions ,
//   https://github.com/osquery/osquery/blob/5.12.1/specs/windows/registry.table)
//   (INV-22: `listening_ports` JOIN `processes` for Open services of a machine that has only an agent; on Linux only the network namespace of
//   pid 1 (process_namespaces), Windows has no net_namespace column so it has its own query. https://osquery.io/schema/ listening_ports, process_namespaces)
//   (`interfaces` lets the box know the machine's MAC/IP to match the device; cpu_brand, physical_memory and patches are left out because the store has no field for them.)
// - osquery install: the official package is served by THE BOX ITSELF (the box is the only source, no pkg.osquery.io, no Chocolatey), the SHA-256 is checked against the value on
//   the signed-in page before installing: `dpkg -i` / `rpm -Uvh` (https://osquery.readthedocs.io/en/stable/installation/install-linux/); the MSI installs into
//   C:\Program Files\osquery, manage-osqueryd.ps1 -install -startupArgs, Start-Service osqueryd (https://osquery.readthedocs.io/en/stable/installation/install-windows/).
// - Wazuh API: port 55000, POST /security/user/authenticate (-u user:pass, ?raw=true), policy/role/user through POST /security/policies|roles|users, linked with
//   POST /security/roles/{id}/policies?policy_ids= and POST /security/users/{id}/roles?role_ids=; the actions agent:read and syscollector:read on agent:id:*;
//   syscollector: GET /syscollector/{agent_id}/os|packages|hotfixes|ports, GET /agents.
//   https://documentation.wazuh.com/current/user-manual/api/getting-started.html , .../api/rbac/configuration.html , .../api/rbac/reference.html
// VEDETTE'S OWN PATHS: /api/v1/install/*, /api/v1/intake/osquery/{enroll,config,log,status}, /api/v1/intake/ca.pem.
import { linuxOneLiner, OSQUERY_VERSION, windowsOneLiner } from './installScripts'
import type { OsqueryPackage } from './types'

export type Platform = 'linux' | 'windows'
export interface ConfigStep { key: string; file: string; code: string }

const hostOf = (serverUrl: string) => serverUrl.replace(/^https:\/\//, '')

/** The query schedule Vedette needs (sent through the config endpoint; shown here so the user knows what is collected). Read only, no write query or command execution.
 *  In the first hour after enrolment, any query the store has not received is asked again every minute (`queriesBody`); `--config_refresh=300` brings a machine back to this schedule. */
export const OSQUERY_SCHEDULE = JSON.stringify({
  schedule: {
    os_version: { query: 'SELECT name, version, major, minor, patch, build, platform, arch FROM os_version;', interval: 3600, snapshot: true },
    system_info: { query: 'SELECT hostname, hardware_vendor, hardware_model FROM system_info;', interval: 3600, snapshot: true },
    interfaces: { query: "SELECT d.mac, a.address FROM interface_details d JOIN interface_addresses a USING (interface) WHERE a.address NOT LIKE '%:%' AND a.address NOT LIKE '127.%' AND a.address NOT LIKE '169.254.%' AND d.mac != '00:00:00:00:00:00';", interval: 3600, snapshot: true },
    deb_packages: { query: 'SELECT name, version, arch, source FROM deb_packages;', interval: 3600, snapshot: true, platform: 'linux' },
    rpm_packages: { query: 'SELECT name, version, release, arch, epoch FROM rpm_packages;', interval: 3600, snapshot: true, platform: 'linux' },
    programs: { query: "SELECT '' AS name, r.data AS version, '' AS publisher, '' AS install_date, r.key AS sql_setup FROM registry r WHERE r.key LIKE 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\MSSQL%\\Setup' AND r.name = 'PatchLevel' UNION ALL SELECT name, version, publisher, install_date, '' FROM programs;", interval: 3600, snapshot: true, platform: 'windows' },
    kernel_info: { query: 'SELECT version FROM kernel_info;', interval: 3600, snapshot: true, platform: 'linux' },
    os_revision: { query: 'SELECT name, version, revision, arch FROM os_version;', interval: 3600, snapshot: true, platform: 'windows' },
    listening_ports: { query: "SELECT DISTINCT l.port, l.protocol, l.address, p.name FROM listening_ports l LEFT JOIN processes p USING (pid) WHERE l.port > 0 AND l.protocol IN (6, 17) AND l.address NOT LIKE '127.%' AND l.address != '::1' AND l.net_namespace = (SELECT net_namespace FROM process_namespaces WHERE pid = 1);", interval: 3600, snapshot: true, platform: 'linux' },
    listening_ports_windows: { query: "SELECT DISTINCT l.port, l.protocol, l.address, p.name FROM listening_ports l LEFT JOIN processes p USING (pid) WHERE l.port > 0 AND l.protocol IN (6, 17) AND l.address NOT LIKE '127.%' AND l.address != '::1';", interval: 3600, snapshot: true, platform: 'windows' },
  },
}, null, 2)

/** The manual install steps ("Advanced: manual setup"). `token` is the real secret (only right when it is created) or "<TOKEN>". The package is downloaded from the box itself and checked
 *  against the SHA-256 of `packages` (the signed-in page) before installing, and a mismatch is not installed; a box with no package → no install step (the UI says why).
 *  One command for both x86_64 and arm64: the package name follows `dpkg --print-architecture` (amd64, arm64) or `uname -m` (x86_64, aarch64), exactly the box's file name. */
export function osquerySteps(platform: Platform, serverUrl: string, token: string, packages: OsqueryPackage[]): ConfigStep[] {
  const host = hostOf(serverUrl)
  const mirror = `${serverUrl}/api/v1/install/osquery`
  const linuxGet = (format: 'deb' | 'rpm', file: string, install: string): ConfigStep[] => {
    const sums = packages.filter((p) => p.format === format).map((p) => `'${p.sha256}  ${p.file}'`)
    if (!sums.length) return []
    return [{
      key: format === 'deb' ? 'installDeb' : 'installRpm', file: format === 'deb' ? 'Debian, Ubuntu (shell)' : 'RHEL, Rocky, AlmaLinux (shell)',
      // Three lines that each stand alone: a copied file (USB) skips the second, the third checks and installs in one command.
      code: `f=${file}\ncd "$(mktemp -d)" && curl -fSLk ${mirror}/$f -o $f\ns=$(printf '%s\\n' ${sums.join(' ')} | grep " $f\\$") && printf '%s\\n' "$s" | sha256sum -c - && ${install} $f`,
    }]
  }
  if (platform === 'linux') {
    const ca = '/etc/osquery/vedette-ca.pem'
    return [
      ...linuxGet('deb', `osquery_${OSQUERY_VERSION}-1.linux_$(dpkg --print-architecture).deb`, 'sudo dpkg -i'),
      ...linuxGet('rpm', `osquery-${OSQUERY_VERSION}-1.linux.$(uname -m).rpm`, 'sudo rpm -Uvh'),
      { key: 'secret', file: 'Shell', code: `sudo mkdir -p /etc/osquery\n(umask 077; echo '${token}' | sudo tee /etc/osquery/enroll.secret >/dev/null)\nsudo curl -fsSk ${serverUrl}/api/v1/intake/ca.pem -o ${ca}\nopenssl x509 -in ${ca} -noout -fingerprint -sha256` },
      { key: 'flags', file: '/etc/osquery/osquery.flags', code: `--config_plugin=tls\n--logger_plugin=tls\n--host_identifier=hostname\n--enroll_secret_path=/etc/osquery/enroll.secret\n--tls_server_certs=${ca}\n--tls_hostname=${host}\n--enroll_tls_endpoint=/api/v1/intake/osquery/enroll\n--config_tls_endpoint=/api/v1/intake/osquery/config\n--config_refresh=300\n--logger_tls_endpoint=/api/v1/intake/osquery/log` },
      { key: 'start', file: 'Shell', code: 'sudo systemctl enable --now osqueryd' },
    ]
  }
  const dir = 'C:\\Program Files\\osquery'
  return [
    ...packages.filter((p) => p.format === 'msi').slice(0, 1).map((p) => ({
      key: 'install', file: 'PowerShell (Administrator)',
      code: `$f = "$env:TEMP\\${p.file}"\ncurl.exe -fSLk ${mirror}/${p.file} -o $f\nif ((Get-FileHash $f -Algorithm SHA256).Hash -ieq '${p.sha256}') { $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/i \`"$f\`" /qn /norestart"; if ($p.ExitCode -notin 0, 3010) { throw "msiexec failed with exit code $($p.ExitCode)" } } else { throw 'Checksum mismatch: do not install this file' }`,
    })),
    { key: 'secret', file: 'PowerShell (Administrator)', code: `Set-Content -Path "${dir}\\enroll.secret" -Value '${token}' -NoNewline -Encoding ascii\ncurl.exe -fsSk ${serverUrl}/api/v1/intake/ca.pem -o "${dir}\\vedette-ca.pem"\ncertutil -dump "${dir}\\vedette-ca.pem"` },
    { key: 'flags', file: `${dir}\\osquery.flags`, code: `--config_plugin=tls\n--logger_plugin=tls\n--host_identifier=hostname\n--enroll_secret_path=${dir}\\enroll.secret\n--tls_server_certs=${dir}\\vedette-ca.pem\n--tls_hostname=${host}\n--enroll_tls_endpoint=/api/v1/intake/osquery/enroll\n--config_tls_endpoint=/api/v1/intake/osquery/config\n--config_refresh=300\n--logger_tls_endpoint=/api/v1/intake/osquery/log` },
    { key: 'service', file: 'PowerShell (Administrator)', code: `cd "${dir}"\n.\\manage-osqueryd.ps1 -install -startupArgs "--flagfile=\`"${dir}\\osquery.flags\`""\nSet-Service osqueryd -StartupType Automatic\nStart-Service osqueryd` },
  ]
}

export { linuxOneLiner, windowsOneLiner }

/** The steps to create a READ-ONLY Wazuh API user: one policy (agent:read + syscollector:read on every agent), one role, one user. Run on a machine that can reach the Wazuh API. */
export function wazuhReaderSteps(): ConfigStep[] {
  const api = 'https://<WAZUH_MANAGER>:55000'
  const auth = '-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json"'
  return [
    { key: 'login', file: 'Shell', code: `# Log in with an existing Wazuh API administrator (-k only because the default Wazuh certificate is self-signed)\nTOKEN=$(curl -u <WAZUH_ADMIN_USER>:<WAZUH_ADMIN_PASSWORD> -k -X POST "${api}/security/user/authenticate?raw=true")` },
    { key: 'policy', file: 'Shell', code: `curl -k -X POST "${api}/security/policies" ${auth} \\\n  -d '{"name":"vedette_read","policy":{"actions":["agent:read","syscollector:read"],"resources":["agent:id:*"],"effect":"allow"}}'\n# note the "id" in the answer: <POLICY_ID>` },
    { key: 'role', file: 'Shell', code: `curl -k -X POST "${api}/security/roles" ${auth} -d '{"name":"vedette_reader"}'\n# note the "id": <ROLE_ID>` },
    { key: 'user', file: 'Shell', code: `curl -k -X POST "${api}/security/users" ${auth} -d '{"username":"vedette","password":"<CHOOSE_A_STRONG_PASSWORD>"}'\n# note the "id": <USER_ID>` },
    { key: 'link', file: 'Shell', code: `curl -k -X POST "${api}/security/roles/<ROLE_ID>/policies?policy_ids=<POLICY_ID>" -H "Authorization: Bearer $TOKEN"\ncurl -k -X POST "${api}/security/users/<USER_ID>/roles?role_ids=<ROLE_ID>" -H "Authorization: Bearer $TOKEN"` },
  ]
}
