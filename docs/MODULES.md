# Module — bật/tắt riêng biệt

Nguyên tắc (kien, 2026-11-06): người dùng bật đúng cái họ cần. Mỗi module là một gói Go trong `modules/<tên>/` với:

```
modules/<tên>/
  MANIFEST.yaml   # id, tên hiển thị (vi/en), mô tả 1 câu, phụ thuộc, quyền cần, cổng mở, dữ liệu ghi, story phục vụ
  CONTRACT.md     # INV/PRE/POST/FORBID — docs/MODULE_CONTRACTS.md
  IMPACT.md       # ai gọi gì, tắt module này ảnh hưởng ai
  module.go       # implements core.Module: Init, Routes, Jobs, Migrations, Enable, Disable, Health
  migrations/     # bảng có tiền tố <tên>_ ; tắt không xoá
  ...
```

Quy tắc chung:
- **Tắt** = không đăng ký route, không chạy job, không mở cổng; dữ liệu giữ nguyên; UI hiển thị "đang tắt" ở chỗ dữ liệu thiếu (S-CORE-1).
- **Phụ thuộc** khai báo trong MANIFEST; bật module thiếu phụ thuộc → UI hỏi bật kèm, không tự bật ngầm.
- **Quyền** (raw socket, cổng <1024, đọc file) khai báo; core cấp đúng quyền đó (capabilities / systemd socket), không chạy root toàn bộ.
- **Story**: MANIFEST liệt kê story ID module phục vụ; không có story → không có module.
- Tiers: *lõi* luôn bật; *chuẩn* bật mặc định ở SMB; *tuỳ chọn* tắt mặc định.

| ID | Tên | Tier | Phụ thuộc | Quyền/cổng | Ghi dữ liệu | Story | Mốc |
|---|---|---|---|---|---|---|---|
| `core` | Lõi: UI, auth, cấu hình, module registry, job scheduler, audit, update client | lõi | — | HTTP 8443 | `core_*` | S-CORE-1..3 | M2 |
| `feeds` | Kho feed cục bộ: kéo `index.json` đã ký, bảng nóng, tra cứu CVE/IOC | chuẩn | core | ra Internet (HTTPS) | `feeds_*` | S-FEED-1..3 | M2 |
| `inventory` | Tồn kho tài sản: khai tay + nhập từ sensor; khớp với feeds | chuẩn | core, feeds | — | `inv_*` | S-INV-2, S-FEED-1 cột "Anh có?" | M2 (khai tay), M3 (tự động) |
| `notify` | Kênh Zalo OA/Telegram/email/webhook, gộp, lịch im lặng | chuẩn | core | ra Internet | `notify_*` | S-NOT-1, S-ALERT-1..2 | M2 |
| `sensor-passive` | Thụ động: DHCP/mDNS/SSDP/ARP/LLDP listener, Zeek/Suricata EVE reader (SPAN tuỳ chọn), OUI, Fingerbank API tuỳ chọn | chuẩn | inventory | raw socket, pcap | `inv_*` (nguồn=passive) | S-INV-1, S-INV-3 | M3 |
| `sensor-active` | Chủ động: nmap (`-sV -O`, cửa sổ giờ, throttle), SNMP sysDescr, Recog trên banner | chuẩn | inventory | raw socket; nmap từ repo OS | `inv_*` (nguồn=active) | S-INV-1, S-SCAN-4 | M3 |
| `mitigation` | Gói giảm thiểu: hướng dẫn vá, vá tạm, sinh cấu hình theo vendor, rule pack, dấu hiệu khai thác | chuẩn | feeds, inventory | — | `mit_*` | S-MIT-1..3 | M3 |
| `exposure` | Bề mặt ngoài: xác thực sở hữu, subfinder/CT → dnsx → httpx, ảnh chụp theo ngày | tuỳ chọn | inventory | ra Internet | `exp_*` | S-EXP-1 | M4 |
| `scan` | Quét xác nhận Nuclei (kev/vkev safe set), quét lại theo sự kiện KEV, bằng chứng | tuỳ chọn | inventory, feeds | ra LAN/Internet | `scan_*` | S-SCAN-1..4 | M4 |
| `scan-credentialed` | Greenbone CE trong container riêng, SSH key | tuỳ chọn | scan | docker/podman | `scan_*` | S-SCAN-5 | M7 |
| `honeypot` | OpenCanary (tiến trình riêng, BSD-3): SMB/RDP/SSH/MSSQL/HTTP giả | tuỳ chọn | inventory | cổng 445/3389/22/1433/80 trên IP phụ | `hp_*` | S-HP-1 | M5 |
| `logs` | Thu syslog (UDP/TCP/TLS 514), parser FortiGate/MikroTik/pfSense/Windows/Suricata, gộp + baseline 7 ngày, đối chiếu IOC, forward SIEM | tuỳ chọn | feeds, inventory | cổng 514 | `logs_*` | S-LOG-1..3 | M5 |
| `response` | AI đề xuất phản ứng cho phát hiện Critical (D-40); **thực thi hành động đã duyệt** qua kết nối ghi (D-41, rủi ro cao, công tắc riêng TẮT mặc định) | tuỳ chọn | ai, notify, inventory | — | `resp_*` | S-RESP-1, S-RESP-2 | M1 (GUI) |
| `agent-intake` | Nhận danh sách gói từ osquery (Vedette làm máy chủ TLS) hoặc kéo từ Wazuh API (không ship agent, D-33) | tuỳ chọn | inventory | HTTPS | `inv_*` (nguồn=agent) | S-INV-4 | M7 |
| `ai` | Trợ lý BYOK: provider, skill runner, RAG, 3 mức, tool chỉ-đọc, đồng hồ token | tuỳ chọn | core (+ module nào có dữ liệu) | ra Internet tới provider | `ai_*` | S-AI-1..6 | M6 |
| `reports` | Báo cáo tuần, báo cáo PDPL/cấp độ, PDF | tuỳ chọn | inventory, feeds (+scan, logs nếu có) | — | `rep_*` | S-REP-1..2 | M7 |
| `fleet` | Server trung tâm nhiều site/khách: sensor đăng ký, bảng tổng MSP, multi-tenant | tuỳ chọn | core | HTTPS mTLS | `fleet_*` | S-FLEET-1 | hoãn (D-24) |
| `mcp-server` | MCP chỉ-đọc cho agent/SIEM ngoài | tuỳ chọn | core | HTTP local | — | S-MCP-1 | M6 |
| `auth-oidc` | OIDC/SSO + RBAC 3 vai | tuỳ chọn | core | ra IdP | `core_*` | S-CORE-3 | M7 |

Ghi chú:
- `feeds` kéo thêm **feed cần key của khách** (VulnCheck, AbuseIPDB, VirusTotal, GreyNoise, Shodan, OTX, urlscan, OpenPhish, Censys) trực tiếp từ nguồn; mỗi nguồn một ô key, tắt mặc định (`DATA_PIPELINE.md` §Feed BYOK).
- `sensor-*` và `honeypot`, `logs` chạy được ở chế độ **sensor** tách khỏi server (`ARCHITECTURE.md` §Sensor/Server).
- Thứ tự mốc theo `ROADMAP.md`; **mọi module đều có màn hình GUI trước khi có backend**.
