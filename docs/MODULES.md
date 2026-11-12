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
- **Cần `vedette-host`** (D-381): `needs_host: true` trong MANIFEST (honeypot, scan-credentialed). Bản chỉ container (D-168) không bật được module đó: `GET /modules` báo `available: false`, bật → 409 `not_appliance`, gói của setup bỏ nó.
- **Quyền** (raw socket, cổng <1024, đọc file) khai báo; core cấp đúng quyền đó (capabilities / systemd socket), không chạy root toàn bộ.
- **Story**: MANIFEST liệt kê story ID module phục vụ; không có story → không có module.
- Tiers: *lõi* luôn bật; *chuẩn* bật mặc định ở SMB; *tuỳ chọn* tắt mặc định.

| ID (hợp đồng) | Tên | Tier | Phụ thuộc | Container (D-55) | Quyền/cổng | Bảng sở hữu | Story | Mốc |
|---|---|---|---|---|---|---|---|---|
| [`core`](../modules/core/CONTRACT.md) | Lõi: UI, auth, cấu hình, module registry, job scheduler, audit, update client | lõi | host (kiểu Appliance) | `core` | HTTPS 8443 | `core_*` | S-CORE-1..7 | M2 |
| [`feeds`](../modules/feeds/CONTRACT.md) | Kho feed cục bộ: hộp tự kéo và phân tích feed trực tiếp từ nguồn (D-36, D-37), bảng nóng, tra cứu CVE/IOC | chuẩn | core | `core` | ra Internet (HTTPS) | `feeds_*` | S-FEED-1..5 | M2 |
| [`inventory`](../modules/inventory/CONTRACT.md) | Tồn kho tài sản: khai tay + nhập từ sensor/agent; khớp với feeds; "This box" là thiết bị đầu tiên (D-53) | chuẩn | core, feeds | `core` | — | `inv_*` | S-INV-1..3, 5; S-FEED-1 cột "Anh có?" | M2 (khai tay), M3 (tự động) |
| [`notify`](../modules/notify/CONTRACT.md) | Kênh Zalo OA/Zalo cá nhân/Telegram/Slack/email/webhook, gộp, lịch im lặng, người duyệt trong từng kênh (D-46) | chuẩn | core | `core` | ra Internet | `notify_*` | S-NOT-1, 2; S-ALERT-1, 3 | M2 |
| [`sensor-passive`](../modules/sensor-passive/CONTRACT.md) | Thụ động: DHCP/mDNS/SSDP/ARP/LLDP listener, bộ phân tích SPAN metadata viết bằng Go (D-43, không Zeek/Suricata), OUI, Fingerbank API tuỳ chọn | chuẩn | inventory | `sensor` | raw socket, pcap | `inv_*` (nguồn=passive, qua interface) | S-INV-1, 3; S-LOG-4 | M3 |
| [`sensor-active`](../modules/sensor-active/CONTRACT.md) | Chủ động: nmap (`-sV -O`, cửa sổ giờ theo múi giờ tổ chức, throttle), thiết bị mong manh hoặc chưa phân loại quét nhẹ một lần (không `-sV`) trong cửa sổ (D-45, D-84); SNMP sysDescr chưa xây (D-84) | chuẩn | inventory | `scan` (nmap; WP-12 chạy từ core) | raw socket | `sa_*` (D-84; ghi quan sát vào inventory qua `core/observe`) | S-INV-1, S-SCAN-4 | M3 |
| [`findings`](../modules/findings/CONTRACT.md) | Khớp lỗ hổng × thiết bị → phát hiện nghi ngờ/xác nhận, vòng đời xử lý (D-57) | chuẩn | inventory, feeds | `core` | — | `fnd_*` | S-MIT-1 (danh sách, trạng thái), S-INV-2, S-SCAN-3, S-ALERT-1 | M2 |
| [`mitigation`](../modules/mitigation/CONTRACT.md) | Gói giảm thiểu: hướng dẫn vá, vá tạm, cấu hình theo vendor, dấu hiệu khai thác; khuyến nghị đã xác nhận đi kèm bản cập nhật ký (D-21, D-31) | chuẩn | findings, inventory | `core` | — | `mit_*` | S-MIT-1 ("What to do"), 3, 4; S-AI-2 | M3 |
| [`exposure`](../modules/exposure/CONTRACT.md) | Bề mặt ngoài: xác thực sở hữu, subfinder/CT → dnsx → httpx, ảnh chụp theo ngày | tuỳ chọn | inventory | `scan` | ra Internet | `exp_*` | S-EXP-1 | M4 |
| [`scan`](../modules/scan/CONTRACT.md) | Quét xác nhận Nuclei (kev/vkev safe set), quét lại theo sự kiện KEV, bằng chứng | tuỳ chọn | inventory, feeds | `scan` | ra LAN/Internet | `scan_*` | S-SCAN-1..4 | M4 |
| [`scan-credentialed`](../modules/scan-credentialed/CONTRACT.md) | Greenbone CE trong container riêng, SSH key | tuỳ chọn | scan | `greenbone` | OCI | `scan_*` | S-SCAN-5 | M7 |
| [`honeypot`](../modules/honeypot/CONTRACT.md) | Bẫy (OpenCanary, BSD-3): SMB/RDP/SSH/MSSQL/HTTP giả, vai thiết bị theo kho, honey token, phát hiện quét IP bẫy (D-50) | tuỳ chọn | inventory | `honeypot` (+ API ở `core`) | cổng 445/3389/22/1433/80 trên IP phụ (macvlan) | `hp_*` | S-HP-1, 2 | M5 |
| [`logs`](../modules/logs/CONTRACT.md) | Thu syslog (UDP/TCP/TLS 514/6514), parser theo danh mục 48 nguồn (D-30), gộp + baseline 7 ngày, đối chiếu IOC, SPAN metadata (D-43), forward SIEM | tuỳ chọn | feeds, inventory | `sensor` (nghe) + `core` (lưu, API) | cổng 514/6514 | `logs_*` | S-LOG-1..4 | M5 |
| [`response`](../modules/response/CONTRACT.md) | Phản ứng: quy tắc KHI-NẾU-THÌ và đề xuất AI → hành động lên firewall/switch/DNS, **mặc định cần duyệt**, 2 người cho rủi ro cao, danh sách chặn cho firewall kéo; công tắc thực thi riêng TẮT mặc định (D-41, D-44, D-46, D-47, D-51). Ngoại lệ duy nhất của SYS-8 | tuỳ chọn (rủi ro cao) | notify, inventory (mềm: ai; kết nối thiết bị thuộc `core`, D-93) | `core` | — (route công khai trên 8443) | `resp_*` | S-RESP-1..4, S-AI-8 | M1 (GUI) |
| [`agent-intake`](../modules/agent-intake/CONTRACT.md) | Nhận gói từ osquery (Vedette là máy chủ TLS, script cài một dòng cho Linux/Windows Server) hoặc kéo Wazuh API chỉ đọc; không ship agent, chỉ máy chủ (D-33, D-34) | tuỳ chọn | inventory | `core` | HTTPS 8443 | `intake_*` (ghi quan sát nguồn=agent vào `inv_*` qua interface) | S-INV-4 | M7 |
| [`ai`](../modules/ai/CONTRACT.md) | Trợ lý BYOK: nhiều hồ sơ + phân việc có dự phòng (D-29), harness (rule, memory, skill, RAG, kết nối ngoài, hook, D-39), nhật ký AI chống sửa (D-48), 3 mức token, **không có công cụ ghi** | tuỳ chọn | core (+ module nào có dữ liệu) | `core` | ra Internet tới provider | `ai_*` | S-AI-1..8 | M6 |
| [`reports`](../modules/reports/CONTRACT.md) | Báo cáo tuần, báo cáo PDPL (Luật 91/2025/QH15, NĐ 356/2025/NĐ-CP), in/lưu PDF | tuỳ chọn | inventory, feeds (+notify để gửi; scan, logs nếu có) | `core` | — | `rep_*` | S-REP-1, 2 | M7 |
| `fleet` | ~~Server trung tâm nhiều site/khách~~ **hoãn, không có trong GUI (D-24)** | — | — | — | — | — | S-FLEET-1 `[rớt]` | hoãn |
| [`mcp-server`](../modules/mcp-server/CONTRACT.md) | MCP chỉ-đọc cho agent/SIEM ngoài (7 công cụ, token theo phạm vi assets/findings/feeds) | tuỳ chọn | core | `core` | HTTP 127.0.0.1:8765 | `mcp_*` | S-MCP-1 | M6 |
| [`auth-oidc`](../modules/auth-oidc/CONTRACT.md) | OIDC/SSO (code + PKCE), ánh xạ nhóm → 3 vai | tuỳ chọn | core | `core` | ra IdP | `oidc_*` | S-CORE-3 | M7 |

Cột "Container" theo D-55; module nhóm A ghi theo D-55 và có thể chỉnh trong `MANIFEST.yaml` riêng của chúng, `MANIFEST.yaml` thắng khi lệch.

**`host` — thành phần, không phải module.** [`vedette-host`](../modules/host/CONTRACT.md) (D-53, D-55, D-56) là tiến trình systemd chạy root, rất nhỏ, chỉ chạy một **danh sách lệnh cố định** (cập nhật OS, mạng/SPAN/IP phụ, kéo và hoàn tác image ký cosign, sao lưu); chỉ `core` gọi được qua socket nội bộ. Không bật/tắt trong Cài đặt, có ở kiểu cài **Appliance**, **vắng ở kiểu "Chỉ container"** (tính năng cần nó báo "không hỗ trợ"). Có `modules/host/{MANIFEST.yaml,CONTRACT.md,IMPACT.md}` như module để người khác làm song song.

Ghi chú:
- `feeds` kéo thêm **feed cần key của khách** (VulnCheck, AbuseIPDB, VirusTotal, GreyNoise, Shodan, OTX, urlscan, OpenPhish, Censys) trực tiếp từ nguồn; mỗi nguồn một ô key, tắt mặc định (`DATA_PIPELINE.md` §Feed BYOK).
- `sensor-*` và `honeypot`, `logs` chạy được ở chế độ **sensor** tách khỏi server (`ARCHITECTURE.md` §Sensor/Server).
- Thứ tự mốc theo `ROADMAP.md`; **mọi module đều có màn hình GUI trước khi có backend**.
