// Cấu hình agent (S-INV-4). Chỉ hai đường: osquery (Linux và Windows Server; Vedette là máy chủ TLS của osquery) và Wazuh (Vedette kéo qua API, không cài gì lên máy agent).
// KHÔNG hỗ trợ Trivy, KHÔNG macOS: Vedette chỉ hỗ trợ hệ điều hành máy chủ (chủ dự án, D-33).
// Đối chiếu tài liệu hãng (2026-11-06):
// - osquery TLS: cờ config_plugin/logger_plugin=tls, enroll_secret_path, tls_server_certs, tls_hostname (kèm cổng, không https://), enroll/config/logger_tls_endpoint, host_identifier.
//   https://osquery.readthedocs.io/en/stable/deployment/remote/
// - osquery lịch truy vấn: JSON "schedule" (query, interval giây, snapshot, platform). https://osquery.readthedocs.io/en/stable/deployment/configuration/
// - osquery bảng: os_version, deb_packages, rpm_packages, programs, system_info, interface_details, interface_addresses. https://osquery.io/schema/
//   (D-169 (7): `interfaces` cho hộp biết MAC/IP của máy để khớp thiết bị; bỏ cpu_brand, physical_memory, patches vì kho không có trường nào cho chúng.)
// - osquery cài: gói chính thức do CHÍNH HỘP phục vụ (D-404: hộp là nguồn duy nhất, không pkg.osquery.io, không Chocolatey), kiểm SHA-256 bằng giá trị trên
//   trang đã đăng nhập rồi mới cài: `dpkg -i` / `rpm -Uvh` (https://osquery.readthedocs.io/en/stable/installation/install-linux/); MSI cài vào
//   C:\Program Files\osquery, manage-osqueryd.ps1 -install -startupArgs, Start-Service osqueryd (https://osquery.readthedocs.io/en/stable/installation/install-windows/).
// - Wazuh API: cổng 55000, POST /security/user/authenticate (-u user:pass, ?raw=true), policy/role/user qua POST /security/policies|roles|users, nối bằng
//   POST /security/roles/{id}/policies?policy_ids= và POST /security/users/{id}/roles?role_ids=; hành động agent:read và syscollector:read trên agent:id:*;
//   syscollector: GET /syscollector/{agent_id}/os|packages|hotfixes, GET /agents.
//   https://documentation.wazuh.com/current/user-manual/api/getting-started.html , .../api/rbac/configuration.html , .../api/rbac/reference.html
// ĐƯỜNG DẪN CỦA RIÊNG VEDETTE: /api/v1/install/*, /api/v1/intake/osquery/{enroll,config,log,status}, /api/v1/intake/ca.pem.
import { linuxOneLiner, OSQUERY_VERSION, windowsOneLiner } from './installScripts'
import type { OsqueryPackage } from './types'

export type Platform = 'linux' | 'windows'
export interface ConfigStep { key: string; file: string; code: string }

const hostOf = (serverUrl: string) => serverUrl.replace(/^https:\/\//, '')

/** Lịch truy vấn Vedette cần (gửi qua config endpoint; hiện ở đây để người dùng biết thu thập gì). Chỉ đọc, không có truy vấn ghi hay chạy lệnh. */
export const OSQUERY_SCHEDULE = JSON.stringify({
  schedule: {
    os_version: { query: 'SELECT name, version, major, minor, patch, build, platform, arch FROM os_version;', interval: 3600, snapshot: true },
    system_info: { query: 'SELECT hostname, hardware_vendor, hardware_model FROM system_info;', interval: 86400, snapshot: true },
    interfaces: { query: "SELECT d.mac, a.address FROM interface_details d JOIN interface_addresses a USING (interface) WHERE a.address NOT LIKE '%:%' AND a.address NOT LIKE '127.%' AND a.address NOT LIKE '169.254.%' AND d.mac != '00:00:00:00:00:00';", interval: 3600, snapshot: true },
    deb_packages: { query: 'SELECT name, version, arch, source FROM deb_packages;', interval: 3600, snapshot: true, platform: 'linux' },
    rpm_packages: { query: 'SELECT name, version, release, arch, epoch FROM rpm_packages;', interval: 3600, snapshot: true, platform: 'linux' },
    programs: { query: 'SELECT name, version, publisher, install_date FROM programs;', interval: 3600, snapshot: true, platform: 'windows' },
  },
}, null, 2)

/** Các bước cài thủ công ("Advanced: manual setup"). `token` là secret thật (chỉ lúc vừa tạo) hoặc "<TOKEN>". Gói tải từ chính hộp (D-404) và kiểm
 *  bằng SHA-256 của `packages` (trang đã đăng nhập) trước khi cài, sai thì không cài; hộp không có gói nào → không có bước cài (giao diện nói lý do).
 *  Một lệnh cho cả x86_64 và arm64: tên gói theo `dpkg --print-architecture` (amd64, arm64) hay `uname -m` (x86_64, aarch64), đúng tên tệp của hộp. */
export function osquerySteps(platform: Platform, serverUrl: string, token: string, packages: OsqueryPackage[]): ConfigStep[] {
  const host = hostOf(serverUrl)
  const mirror = `${serverUrl}/api/v1/install/osquery`
  const linuxGet = (format: 'deb' | 'rpm', file: string, install: string): ConfigStep[] => {
    const sums = packages.filter((p) => p.format === format).map((p) => `'${p.sha256}  ${p.file}'`)
    if (!sums.length) return []
    return [{
      key: format === 'deb' ? 'installDeb' : 'installRpm', file: format === 'deb' ? 'Debian, Ubuntu (shell)' : 'RHEL, Rocky, AlmaLinux (shell)',
      code: `cd "$(mktemp -d)" && f=${file} && \\\ncurl -fSLk ${mirror}/$f -o $f && \\\nprintf '%s\\n' ${sums.join(' ')} | grep " $f\\$" | sha256sum -c - && \\\n${install} $f`,
    }]
  }
  if (platform === 'linux') {
    const ca = '/etc/osquery/vedette-ca.pem'
    return [
      ...linuxGet('deb', `osquery_${OSQUERY_VERSION}-1.linux_$(dpkg --print-architecture).deb`, 'sudo dpkg -i'),
      ...linuxGet('rpm', `osquery-${OSQUERY_VERSION}-1.linux.$(uname -m).rpm`, 'sudo rpm -Uvh'),
      { key: 'secret', file: 'Shell', code: `sudo mkdir -p /etc/osquery\n(umask 077; echo '${token}' | sudo tee /etc/osquery/enroll.secret >/dev/null)\nsudo curl -fsSk ${serverUrl}/api/v1/intake/ca.pem -o ${ca}\nopenssl x509 -in ${ca} -noout -fingerprint -sha256` },
      { key: 'flags', file: '/etc/osquery/osquery.flags', code: `--config_plugin=tls\n--logger_plugin=tls\n--host_identifier=hostname\n--enroll_secret_path=/etc/osquery/enroll.secret\n--tls_server_certs=${ca}\n--tls_hostname=${host}\n--enroll_tls_endpoint=/api/v1/intake/osquery/enroll\n--config_tls_endpoint=/api/v1/intake/osquery/config\n--logger_tls_endpoint=/api/v1/intake/osquery/log` },
      { key: 'start', file: 'Shell', code: 'sudo systemctl enable --now osqueryd' },
    ]
  }
  const dir = 'C:\\Program Files\\osquery'
  return [
    ...packages.filter((p) => p.format === 'msi').slice(0, 1).map((p) => ({
      key: 'install', file: 'PowerShell (Administrator)',
      code: `$f = "$env:TEMP\\${p.file}"\ncurl.exe -fSLk ${mirror}/${p.file} -o $f\nif ((Get-FileHash $f -Algorithm SHA256).Hash -ieq '${p.sha256}') { Start-Process msiexec.exe -Wait -ArgumentList "/i \`"$f\`" /qn /norestart" } else { throw 'Checksum mismatch: do not install this file' }`,
    })),
    { key: 'secret', file: 'PowerShell (Administrator)', code: `Set-Content -Path "${dir}\\enroll.secret" -Value '${token}' -NoNewline -Encoding ascii\ncurl.exe -fsSk ${serverUrl}/api/v1/intake/ca.pem -o "${dir}\\vedette-ca.pem"\ncertutil -dump "${dir}\\vedette-ca.pem"` },
    { key: 'flags', file: `${dir}\\osquery.flags`, code: `--config_plugin=tls\n--logger_plugin=tls\n--host_identifier=hostname\n--enroll_secret_path=${dir}\\enroll.secret\n--tls_server_certs=${dir}\\vedette-ca.pem\n--tls_hostname=${host}\n--enroll_tls_endpoint=/api/v1/intake/osquery/enroll\n--config_tls_endpoint=/api/v1/intake/osquery/config\n--logger_tls_endpoint=/api/v1/intake/osquery/log` },
    { key: 'service', file: 'PowerShell (Administrator)', code: `cd "${dir}"\n.\\manage-osqueryd.ps1 -install -startupArgs "--flagfile=\`"${dir}\\osquery.flags\`""\nSet-Service osqueryd -StartupType Automatic\nStart-Service osqueryd` },
  ]
}

export { linuxOneLiner, windowsOneLiner }

/** Các bước tạo người dùng API Wazuh CHỈ ĐỌC: một policy (agent:read + syscollector:read trên mọi agent), một role, một user. Chạy trên máy có tới được API Wazuh. */
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
