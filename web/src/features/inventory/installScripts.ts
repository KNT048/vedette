// Hai script cài osquery một dòng lệnh do CHÍNH HỘP phục vụ (S-INV-4): /api/v1/install/osquery.sh và /osquery.ps1.
// Hộp dùng CA tự ký nên CA được nhúng thẳng trong script; người dùng đối chiếu SHA-256 của script (hiện trong giao diện, kênh đã đăng nhập) trước khi chạy,
// mọi lần tải sau đó dùng --cacert/CA này (không còn -k). Gói osquery do hộp phản chiếu từ bản phát hành chính thức và kiểm checksum nên máy chủ không cần Internet.
// Đối chiếu tài liệu (2026-11-06):
// - Linux: gói .deb/.rpm, dịch vụ systemd "osqueryd" (/usr/lib/systemd/system/osqueryd.service), cấu hình /etc/osquery/, `systemctl enable --now osqueryd`.
//   https://osquery.readthedocs.io/en/stable/installation/install-linux/ ; cài tay trong agentConfig.ts cũng tải gói từ hộp (D-404), không dùng kho ngoài.
// - Windows: MSI cài vào C:\Program Files\osquery, daemon osqueryd\osqueryd.exe, dịch vụ "osqueryd" tạo bằng manage-osqueryd.ps1 -install -startupArgs "--flagfile=…", Start-Service osqueryd.
//   https://osquery.readthedocs.io/en/stable/installation/install-windows/
// - Cờ TLS: config_plugin, logger_plugin, enroll_secret_path, tls_server_certs, tls_hostname (kèm cổng, không https://), *_tls_endpoint, host_identifier.
//   https://osquery.readthedocs.io/en/stable/deployment/remote/
// TÊN GÓI do hộp phản chiếu (theo tên tệp phát hành osquery trên GitHub; backend làm thật phải khớp): osquery_<ver>-1.linux_amd64.deb, osquery-<ver>-1.linux.x86_64.rpm,
// osquery_<ver>-1.linux_arm64.deb, osquery-<ver>-1.linux.aarch64.rpm (D-399), osquery-<ver>.msi, kèm SHA256SUMS, tất cả dưới /api/v1/install/osquery/. Đường dẫn /api/v1/install/*, /api/v1/intake/* là của riêng Vedette (tên mock).

export const OSQUERY_VERSION = '5.12.1'
/** The host part of server_url while the box knows no address other machines can reach (agent-intake PRE-3): the box serves no script
 *  then (404 no_box_address) and the GUI shows how to give it one instead of a command that cannot work (D-399 (2)). */
export const NO_BOX_ADDRESS = '<VEDETTE_BOX_IP>'

import BASH from './scripts/osquery.sh?raw'
import PWSH from './scripts/osquery.ps1?raw'

const fill = (t: string, box: string, ca: string) => t.replaceAll('@@BOX@@', box).replaceAll('@@VERSION@@', OSQUERY_VERSION).replaceAll('@@CA@@', ca.trim())
export const linuxInstallScript = (box: string, ca: string) => fill(BASH, box, ca)
export const windowsInstallScript = (box: string, ca: string) => fill(PWSH, box, ca)

/** Một dòng lệnh cài: tải từ hộp, đối chiếu SHA-256 đã hiện trong giao diện, rồi chạy với token. Token đi qua tham số, không nằm trong URL.
 *  Script tải vào một tệp mktemp mới mỗi lần rồi xoá: một đường cố định trong /tmp do người dùng khác để lại không ghi đè được
 *  (fs.protected_regular=2 của Ubuntu; lượt đi thật 2, W2-3). */
export function linuxOneLiner(box: string, sha256: string, token: string, action: 'install' | 'uninstall' = 'install') {
  const arg = action === 'install' ? `--token ${token}` : '--uninstall'
  return `f=$(mktemp) && curl -fsSLk ${box}/api/v1/install/osquery.sh -o "$f" && echo "${sha256}  $f" | sha256sum -c - && sudo sh "$f" ${arg}; rm -f "$f"`
}
/** Windows PowerShell 5.1: không có -SkipCertificateCheck, nên chỉ lần tải script đầu tiên dùng curl.exe -k (chưa có CA); script đã nhúng CA và dùng --cacert cho mọi lần tải sau.
 *  Tên tệp mới mỗi lần (GUID, đuôi .ps1 vì -File cần nó) và xoá sau khi chạy, như bản Linux. */
export function windowsOneLiner(box: string, sha256: string, token: string, action: 'install' | 'uninstall' = 'install') {
  const arg = action === 'install' ? `-Token '${token}'` : '-Uninstall'
  return `$f=Join-Path $env:TEMP ('vedette-osquery-'+[guid]::NewGuid()+'.ps1'); curl.exe -fsSLk ${box}/api/v1/install/osquery.ps1 -o $f; if ((Get-FileHash $f -Algorithm SHA256).Hash -ieq '${sha256}') { powershell -NoProfile -ExecutionPolicy Bypass -File $f ${arg}; Remove-Item -Force $f } else { Remove-Item -Force $f; throw 'Checksum mismatch: do not run this file' }`
}
