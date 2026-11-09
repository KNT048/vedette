// Hai script cài osquery một dòng lệnh do CHÍNH HỘP phục vụ (S-INV-4): /api/v1/install/osquery.sh và /osquery.ps1.
// Hộp dùng CA tự ký nên CA được nhúng thẳng trong script; người dùng đối chiếu SHA-256 của script (hiện trong giao diện, kênh đã đăng nhập) trước khi chạy,
// mọi lần tải sau đó dùng --cacert/CA này (không còn -k). Gói osquery do hộp phản chiếu từ bản phát hành chính thức và kiểm checksum nên máy chủ không cần Internet.
// Đối chiếu tài liệu (2026-11-06):
// - Linux: gói .deb/.rpm, dịch vụ systemd "osqueryd" (/usr/lib/systemd/system/osqueryd.service), cấu hình /etc/osquery/, `systemctl enable --now osqueryd`.
//   https://osquery.readthedocs.io/en/stable/installation/install-linux/ ; kho chính thức pkg.osquery.io (deb/pubkey.gpg, rpm/GPG) dùng cho cách cài thủ công trong agentConfig.ts
// - Windows: MSI cài vào C:\Program Files\osquery, daemon osqueryd\osqueryd.exe, dịch vụ "osqueryd" tạo bằng manage-osqueryd.ps1 -install -startupArgs "--flagfile=…", Start-Service osqueryd.
//   https://osquery.readthedocs.io/en/stable/installation/install-windows/
// - Cờ TLS: config_plugin, logger_plugin, enroll_secret_path, tls_server_certs, tls_hostname (kèm cổng, không https://), *_tls_endpoint, host_identifier.
//   https://osquery.readthedocs.io/en/stable/deployment/remote/
// TÊN GÓI do hộp phản chiếu (theo tên tệp phát hành osquery trên GitHub; backend làm thật phải khớp): osquery_<ver>-1.linux_amd64.deb, osquery-<ver>-1.linux.x86_64.rpm,
// osquery-<ver>.msi, kèm SHA256SUMS, tất cả dưới /api/v1/install/osquery/. Đường dẫn /api/v1/install/*, /api/v1/intake/* là của riêng Vedette (tên mock).

export const OSQUERY_VERSION = '5.12.1'

import BASH from './scripts/osquery.sh?raw'
import PWSH from './scripts/osquery.ps1?raw'

const fill = (t: string, box: string, ca: string) => t.replaceAll('@@BOX@@', box).replaceAll('@@VERSION@@', OSQUERY_VERSION).replaceAll('@@CA@@', ca.trim())
export const linuxInstallScript = (box: string, ca: string) => fill(BASH, box, ca)
export const windowsInstallScript = (box: string, ca: string) => fill(PWSH, box, ca)

/** Một dòng lệnh cài: tải từ hộp, đối chiếu SHA-256 đã hiện trong giao diện, rồi chạy với token. Token đi qua tham số, không nằm trong URL. */
export function linuxOneLiner(box: string, sha256: string, token: string, action: 'install' | 'uninstall' = 'install') {
  const arg = action === 'install' ? `--token ${token}` : '--uninstall'
  return `curl -fsSLk ${box}/api/v1/install/osquery.sh -o /tmp/vedette-osquery.sh && echo "${sha256}  /tmp/vedette-osquery.sh" | sha256sum -c - && sudo sh /tmp/vedette-osquery.sh ${arg}`
}
/** Windows PowerShell 5.1: không có -SkipCertificateCheck, nên chỉ lần tải script đầu tiên dùng curl.exe -k (chưa có CA); script đã nhúng CA và dùng --cacert cho mọi lần tải sau. */
export function windowsOneLiner(box: string, sha256: string, token: string, action: 'install' | 'uninstall' = 'install') {
  const arg = action === 'install' ? `-Token '${token}'` : '-Uninstall'
  return `$f="$env:TEMP\\vedette-osquery.ps1"; curl.exe -fsSLk ${box}/api/v1/install/osquery.ps1 -o $f; if ((Get-FileHash $f -Algorithm SHA256).Hash -ieq '${sha256}') { powershell -NoProfile -ExecutionPolicy Bypass -File $f ${arg} } else { throw 'Checksum mismatch: do not run this file' }`
}
