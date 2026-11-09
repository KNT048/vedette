# Kiến trúc kỹ thuật

Trạng thái: **viết lại 2026-11-09** theo D-1…D-56 (giai đoạn M2-0, docs-first). Chưa có mã backend; GUI chạy trên mock (D-22). Khi mâu thuẫn, quyết định sau thắng quyết định trước. Mọi lựa chọn có lý do trong `DECISIONS.md`.

Bản cũ (2026-11-06) mô tả builder trung tâm, module fleet, giao diện vi/en, Zeek/Suricata, A/B slot cho binary: tất cả đã bị thay (D-36, D-24, D-28, D-43, D-55).

Tài liệu liên quan: [`DEPLOYMENT.md`](DEPLOYMENT.md) (container, cài đặt, nâng cấp) · [`DATA_MODEL.md`](DATA_MODEL.md) (bảng, quan hệ) · [`API_CONVENTIONS.md`](API_CONVENTIONS.md) (REST, lỗi, phân trang, SSE) · [`specs/`](specs/) (`specs/*.md`, gồm [`specs/host-api.md`](specs/host-api.md)) · `modules/<id>/CONTRACT.md` (hợp đồng từng module, `MODULE_CONTRACTS.md`) · `UPDATES.md` · `DATA_PIPELINE.md` · `AI_ASSISTANT.md` · `../PRIVACY.md` · `../SECURITY.md`.

## 1. Tổng quan

Vedette là một **appliance** đặt trong LAN của doanh nghiệp (một site, D-24): kéo feed lỗ hổng đang bị khai thác, khớp với kho thiết bị, quét xác nhận, bẫy, log, phản ứng có duyệt, trợ lý AI BYOK. **Không inline, không chặn traffic** (D-3). Mọi kết nối ra Internet do hộp chủ động mở; không cần cổng vào từ Internet.

```
                         Internet (chỉ kết nối RA, HTTPS 443)
   ┌─────────────────────────────────────────────────────────────────────────────┐
   │ nguồn feed (CISA, FIRST, NVD, abuse.ch…)  D-36    GitHub Releases + registry │
   │ provider AI của khách (BYOK)                      (chỉ bản phần mềm ký, D-36)│
   │ kênh: Slack/Telegram/Zalo/SMTP của khách          tín hiệu ẩn danh (D-16)    │
   └──────────────────────────────▲──────────────────────────────────────────────┘
                                  │ chỉ hộp chủ động mở kết nối
┌─────────────────────────────────┴────────────────── LAN khách ──────────────────┐
│  HỘP VEDETTE (Debian/Ubuntu + vedette-host + Podman)                             │
│                                                                                  │
│   vedette-host (systemd, root, rất nhỏ)   ◄── socket nội bộ, lệnh cố định        │
│     OS update · netplan · kéo image + cosign · start/rollback container · backup │
│        │ quản lý                                                                 │
│   ┌────▼─────────────────────────────────────────────────────────────────────┐  │
│   │ core   (Go + SPA nhúng + SQLite)   ◄── mTLS poll ── sensor  (host net)   │  │
│   │  module registry, feeds, inventory,           ◄───── honeypot (macvlan)  │  │
│   │  mitigation, notify, ai, response,            ◄───── scan     (host net) │  │
│   │  reports, logs-analysis, mcp-server           ◄───── greenbone (tuỳ chọn)│  │
│   └──────────────────────────────────────────────────────────────────────────┘  │
│        ▲ HTTPS 8443        ▲ syslog 514      ▲ SPAN/TAP        ▲ bẫy (IP phụ)    │
└────────┼───────────────────┼─────────────────┼─────────────────┼─────────────────┘
   trình duyệt (3 vai)   firewall/switch/server  cổng mirror      máy trong LAN chạm bẫy
                         (nguồn syslog, osquery, Wazuh API, API thiết bị)
```

Hộp **không** nằm trên đường mạng: nó là một host trong LAN, tuỳ chọn nhận SPAN/TAP (chỉ đọc metadata, D-43) và syslog. Kết nối ghi duy nhất tới thiết bị khách là module `response`, tắt mặc định, từng hành động có người duyệt (D-41, D-51).

**Hai kiểu cài** (D-55): *Appliance* (đủ tính năng, `vedette-host` quản lý OS) và *Chỉ container* (Docker/Podman sẵn có của khách, không quản lý OS). Khác biệt: `DEPLOYMENT.md` §5.

## 2. Thành phần

| Thành phần | Vai trò | Chạy ở đâu | Đặc quyền | Căn cứ |
|---|---|---|---|---|
| `vedette-host` | OS update, cấu hình mạng (card quản trị, SPAN, IP phụ), kéo + xác minh image, start/stop/rollback container, sao lưu, đọc dpkg cho "This box" | Tiến trình systemd trên host | root, bề mặt rất nhỏ (lệnh cố định, SYS-1) | D-53, D-55, D-56 |
| `core` | Go + SPA nhúng + SQLite: auth, module registry, job, audit, secrets, feeds, inventory, matching, mitigation, notify, ai, response, reports, mcp-server | Container, mạng bridge nội bộ, publish 8443 | không root, cap_drop ALL, rootfs chỉ đọc | D-8, D-55 |
| `sensor` | `sensor-passive` (DHCP/ARP/mDNS/SSDP/LLDP, bộ phân tích SPAN metadata viết bằng Go), `sensor-active` (nmap qua `core/exec`), nhận syslog (`logs`) | Container, **mạng host** | `CAP_NET_RAW`, `CAP_NET_BIND_SERVICE` | D-43, D-55 |
| `honeypot` | OpenCanary + tác tử Go (lấy cấu hình sinh từ DB, gửi `honeypot.hit`), honey token | Container, **macvlan** (IP phụ) | `CAP_NET_BIND_SERVICE` (cổng thấp trên IP riêng) | D-50, D-55 |
| `scan` | nmap + nuclei, nhận việc từ hàng đợi của `core`, trả bằng chứng | Container, mạng host | `CAP_NET_RAW` | D-4, D-55 |
| `greenbone` | Greenbone CE, quét có đăng nhập (S-SCAN-5) | Nhóm container upstream, tuỳ chọn, mạng nội bộ | GPL/AGPL, không sửa | D-55, S-SCAN-5 |
| SPA (`web/`) | React, một locale `en` qua i18next | Nhúng trong `core` | — | D-22, D-28 |

Một codebase Go, đóng gói thành nhiều image (D-8, D-55): `core`, `sensor` và phần tác tử của `honeypot`/`scan` là cùng module Go với entrypoint khác nhau.

## 3. Stack và lý do

| Lớp | Chọn | Lý do |
|---|---|---|
| Backend | Go (ghim trong `go.mod`), `net/http` + router nhẹ, `embed` SPA, cross-compile amd64/arm64 | D-8: nuclei/httpx/naabu/subfinder là thư viện Go; sensor I/O nhẹ; một codebase |
| DB | SQLite (`modernc.org/sqlite`, không cgo, WAL) mặc định; PostgreSQL tuỳ chọn qua cùng lớp `store` (sqlc); FTS5 cho RAG | Backup = chép file; Postgres để sau (M7, ngoài danh sách container D-55) |
| Frontend | React + TypeScript + Vite + Tailwind + Radix + TanStack Query/Table + React Router; chỉ tiếng Anh | D-28; chi tiết `FRONTEND.md` |
| Job | Trong process (`core/jobs`), có khoá + lịch sử, không message queue. `ponytail: 1 process; nâng cấp: queue trên Postgres nếu cần` | Đủ cho ≤1.000 thiết bị một site |
| Giao tiếp sensor ↔ core | HTTPS JSON, mTLS, **sensor poll core** (core không gọi vào sensor) | Không mở cổng vào trên sensor; §6 |
| Runtime container | **Podman + systemd Quadlet** trên appliance; Docker Compose cho dev/CI; cùng image OCI | D-55: không daemon root; không tự mở cổng vượt tường lửa như Docker |
| Chuỗi cung ứng | Image ký **cosign**, SBOM CycloneDX, phát hành theo lô, rollback bằng tag cũ | D-12 cập nhật bởi D-55; `UPDATES.md` |
| Discovery/Scan | nmap (tiến trình riêng, NPSL), Recog, gosnmp, Nuclei lib (tag an toàn `kev,vkev`) | D-4 |
| Honeypot | OpenCanary (BSD-3) tiến trình riêng, cấu hình sinh từ DB | Không viết lại honeypot |
| AI | Adapter Anthropic / OpenAI-compatible / Gemini / tuỳ chỉnh; harness | D-29, D-39 |

Không dùng: Zeek, Suricata (D-43), builder trung tâm/Cloudflare/CDN (D-36), A/B slot cho binary (D-55), cơ chế fleet/tenant (D-24).

## 4. Bản đồ module

Module bật/tắt riêng (D-10; `MODULES.md`, `rules/modules.md`): tắt = không route, không job, không cổng, dữ liệu giữ (SYS-5). Cột "Container" cho biết tiến trình thực chạy.

| Module | Tier | Container | Phụ thuộc | Cổng/quyền | Story |
|---|---|---|---|---|---|
| `core` | lõi | core | — | 8443 | S-CORE-1…7 |
| `feeds` | chuẩn | core | core | ra HTTPS | S-FEED-1…5 |
| `inventory` | chuẩn | core | core, feeds | — | S-INV-1…5 |
| `notify` | chuẩn | core | core | ra HTTPS/SMTP | S-NOT-1, S-NOT-2, S-ALERT-1, S-ALERT-3 |
| `sensor-passive` | chuẩn | sensor | inventory | raw socket; SPAN (D-43, D-56) | S-INV-1, S-INV-3, S-LOG-4 |
| `sensor-active` | chuẩn | sensor / scan | inventory | raw socket; nmap | S-INV-1, S-SCAN-4 |
| `mitigation` | chuẩn | core | feeds, inventory | — | S-MIT-1, S-MIT-3, S-MIT-4 (S-MIT-2 rớt, D-31) |
| `exposure` | tuỳ chọn | scan | inventory | ra Internet | S-EXP-1 |
| `scan` | tuỳ chọn | scan | inventory, feeds | LAN/Internet trong phạm vi | S-SCAN-1…4 |
| `scan-credentialed` | tuỳ chọn | greenbone | scan | container riêng | S-SCAN-5 |
| `honeypot` | tuỳ chọn | honeypot | inventory | 22/80/445/1433/3389 trên IP phụ | S-HP-1, S-HP-2 |
| `logs` | tuỳ chọn | sensor (nhận) + core (gộp, baseline, IOC) | feeds, inventory | UDP/TCP/TLS 514 | S-LOG-1…4 |
| `response` | tuỳ chọn | core | ai, notify, inventory | ghi qua kết nối đã duyệt | S-RESP-1…4 |
| `agent-intake` | tuỳ chọn | core | inventory | HTTPS (osquery TLS) | S-INV-4 |
| `ai` | tuỳ chọn | core | core | ra provider | S-AI-1…8 |
| `reports` | tuỳ chọn | core | inventory, feeds | — | S-REP-1, S-REP-2 |
| `mcp-server` | tuỳ chọn | core | core | localhost | S-MCP-1 |
| `auth-oidc` | tuỳ chọn | core | core | ra IdP | S-CORE-3 |
| `fleet` | — | — | — | — | S-FLEET-1 rớt (D-24) |

Quy ước còn hiệu lực: bảng DB có tiền tố module, không module nào đọc bảng module khác trực tiếp mà qua interface trong `core/` (`rules/modules.md`). Chi tiết bảng: `DATA_MODEL.md`.

## 5. Luồng dữ liệu chính

**5.1 Feed → phát hiện → incident (S-FEED-1, S-ALERT-1)**

```
nguồn feed ─HTTPS(ETag, giới hạn size/time)─► feeds (parser fail-closed, D-37)
   ─► chuẩn hoá ─► lọc trùng ─► chấm điểm ─► feeds_* ─► matching ─► inv_finding
   ─► notify (lịch im lặng, gộp theo sản phẩm; Critical gửi ngay)
```
Thiết bị mới (khai tay, CSV, osquery, quét) được đối chiếu ngay với toàn bộ feed đang có. "Đã xác nhận" chỉ khi có bằng chứng quét an toàn (S-SCAN-3); còn lại là "nghi" (theo phiên bản) hoặc "chỉ khớp sản phẩm". Feed độc hại (IOC "chặn Google") bị bài kiểm tra an toàn trên hộp chặn trước khi dùng (`UPDATES.md` §5).

**5.2 Kho thiết bị (S-INV-1…5)**: nguồn quan sát (manual > agent > snmp > nmap > passive) ghi vào `inv_observation` (chỉ thêm), thiết bị là view hợp nhất. Thụ động: DHCP/ARP/mDNS/SSDP/LLDP + SPAN metadata (DNS query, TLS SNI, HTTP Host, luồng IP; **không lưu payload**, D-43). Chủ động: nmap chỉ trong `inv_scope` đã xác nhận (CIDR bắt buộc có tiền tố, D-32), thiết bị mong manh quét nhẹ một lần rồi chỉ nghe (D-45). Agent: osquery (hộp là máy chủ TLS, D-33/D-34) hoặc Wazuh API chỉ đọc. **"This box"** là thiết bị đầu tiên, danh sách gói từ dpkg qua `vedette-host` (D-53, S-INV-5).

**5.3 Quét xác nhận (S-SCAN-1…4)**: `core` đặt việc → `scan` poll nhận → nuclei (tag an toàn) / nmap → bằng chứng rút gọn → `core`. Mục tiêu ngoài chỉ khi đã xác thực: domain bằng DNS TXT kiểm lại ngay trước mỗi lần quét; IP chỉ là IP mà chính hộp dùng ra Internet, hiệu lực 90 ngày (D-25). Mỗi probe ghi log (SYS-7).

**5.4 Log / SPAN → IOC → incident (S-LOG-1…4)**: `sensor` nhận syslog (hoặc đọc SPAN) → gửi lô `logs.batch` / quan sát → `core` gộp theo cửa sổ, baseline 7 ngày, khớp IOC → incident (D-52). Không lưu log thô dài hạn.

**5.5 Bẫy (S-HP-1, S-HP-2)**: `honeypot` ghi JSON hit → `honeypot.hit` → incident + (nếu có) quy tắc phản ứng (D-50, D-44).

**5.6 Một lần gọi AI** (D-39): việc → hook trước (chặn dữ liệu cá nhân, ngoài phạm vi bảo mật) → chọn hồ sơ (chính → dự phòng, log/thiết bị chỉ tới hồ sơ nội bộ nếu bật, D-29) → RAG (BM25) + memory + rules → provider → công cụ **chỉ đọc** → hook sau + kiểm schema + nhãn "AI-generated" → `ai_run` hash-chain (D-48).

**5.7 Cập nhật** (D-53, D-55): `core` hỏi `vedette-host` qua socket → host kéo manifest ký → xác minh cosign → backup DB → thay image theo digest → health check → lỗi thì quay về tag cũ. Chi tiết `DEPLOYMENT.md` §9 và `UPDATES.md`.

## 6. Sensor / server tách được

- Cùng codebase Go; hai vai chạy ở hai container trên appliance (`core`, `sensor`), cùng nói một giao thức. Tách sensor ra máy khác trong LAN được hỗ trợ ở tầng kiến trúc nhưng **không lộ ra GUI** (D-24).
- Sensor/honeypot/scan **chỉ gọi ra** `core` bằng mTLS; cert cấp khi enroll bằng token một lần; không có cổng vào trên sensor trừ syslog 514 và bẫy. `core` không bao giờ gọi vào sensor; lệnh (quét ngay, đổi cửa sổ, đổi cấu hình bẫy) là hàng đợi sensor poll.
- Giao thức HTTPS JSON, lô sự kiện (`inventory.observation`, `honeypot.hit`, `logs.batch`, và lô metadata SPAN), idempotent theo `seq`; sensor có hàng đợi đĩa chịu được `core` khởi động lại. Định nghĩa hợp đồng: `modules/core/CONTRACT.md`, `docs/specs/`.
- Trên appliance cổng sensor-intake mTLS (đề xuất 8444) chỉ bind `127.0.0.1`/mạng nội bộ container, không mở ra LAN (`DEPLOYMENT.md` §7).

## 7. Kiến trúc bảo mật

### 7.1 Bất biến hệ thống (`MODULE_CONTRACTS.md`)

| ID | Bất biến | Thực thi trong kiến trúc container |
|---|---|---|
| SYS-1 | Tiến trình ngoài chỉ qua `core/exec`, allowlist binary + argv, không shell | Cũng áp cho `vedette-host`: danh sách lệnh cố định, tham số kiểm kiểu (D-53, D-55); lint cấm `os/exec` ngoài `core/exec` |
| SYS-2 | Input ở biên validate theo schema | Handler sinh từ OpenAPI; `vedette-host` validate lại tham số từ socket |
| SYS-3 | Mọi mutation ghi `core_audit` | Gồm lệnh `core` gửi `vedette-host` (ai, lệnh, tham số, kết quả) |
| SYS-4 | Secret chỉ qua `core/secrets` (AES-256-GCM), không log/xuất | Khoá file 0600 ngoài DB, mount chỉ đọc vào `core`; không vào sao lưu mặc định |
| SYS-5 | Module tắt: không route/job/cổng, dữ liệu giữ | Module tắt hết dùng container thì container không khởi động (honeypot, scan, greenbone) |
| SYS-6 | Feed/log/web/agent không tin cậy | Parser fail-closed, giới hạn size/time, fuzz |
| SYS-7 | Hành động mạng ngoài LAN chỉ trong scope xác thực hoặc nguồn feed khai báo | Egress của `scan` kiểm theo bảng phạm vi; test egress |
| SYS-8 | AI không có công cụ ghi | Ngoại lệ duy nhất: `response` (§7.2) |

### 7.2 Ngoại lệ D-41: thực thi hành động đã duyệt

`response` tắt mặc định; bật cần quản trị viên + 2FA + gõ câu chấp nhận rủi ro (ghi kiểm toán). Mỗi hành động qua các cổng, kiểm **ở máy chủ**:

| Cổng | Quy tắc |
|---|---|
| G-1 | Thực thi đang bật, dừng khẩn cấp chưa kích hoạt |
| G-2 | Loại hành động nằm trong danh sách cho phép (D-47), công cụ ghi bật trên kết nối bật |
| G-3 | Yêu cầu hiện chính xác thay đổi trước/sau + bước hoàn tác |
| G-4 | Người duyệt là người dùng Vedette vai ≥ vận hành, danh tính kênh đã liên kết; rủi ro cao cần 2 người (D-51) |
| G-5 | Chưa hết hạn (15–30 phút), một lần duyệt cho đúng một hành động |
| G-6 | Chưa vượt hạn mức theo giờ/quy tắc; cầu dao chung |
| G-7 | Mọi bước ghi kiểm toán hash-chain |
| G-8 | Dừng khẩn cấp tắt thực thi và huỷ yêu cầu đang chờ |

Ngoại lệ không mở rộng sang `vedette-host`: AI không bao giờ gọi `vedette-host`; chỉ mã của `core` (đường cập nhật, mạng, sao lưu do admin bấm) gọi, qua danh sách lệnh cố định.

### 7.3 Ranh giới tin cậy

| Ranh giới | Bên kia | Kiểm soát chính |
|---|---|---|
| TB-1 trình duyệt ↔ core | người dùng trong LAN | TLS, cookie `vedette_session` (Secure/HttpOnly/SameSite=Strict) + CSRF, 2FA (D-35), RBAC, CSP không inline, rate limit |
| TB-2 core ↔ nguồn feed | dữ liệu Internet | HTTPS, giới hạn size/time, parser fail-closed, kiểm tra an toàn |
| TB-3 hộp ↔ thiết bị LAN | thiết bị có thể bị chiếm | banner/syslog/agent không tin cậy; quét chỉ đọc trong phạm vi |
| TB-4 harness ↔ provider AI | dịch vụ ngoài | chỉ khi cấu hình; che PII; hồ sơ nội bộ; output theo schema |
| TB-5 AI ↔ công cụ | mô hình có thể bị prompt injection | khối dữ liệu có nhãn; công cụ đọc theo allowlist; ghi chỉ qua §7.2 |
| TB-6 kênh chat/email ↔ core | lời duyệt từ ngoài | danh tính đã liên kết, token ký dùng một lần, POST xác nhận (D-46) |
| TB-7 hộp ↔ registry/GitHub | chuỗi cung ứng | chữ ký cosign **bắt buộc** khi kéo (policy trên host), digest ghim, thu hồi, theo lô |
| TB-8 core ↔ `vedette-host` | tiến trình root | socket nội bộ quyền chặt, lệnh cố định, tham số kiểm kiểu, một việc tại một thời điểm, audit; xem `specs/host-api.md` |
| TB-9 sensor/honeypot/scan ↔ core | container có bề mặt tấn công từ LAN (bẫy, syslog) | mTLS cert riêng từng container, không tin dữ liệu từ container; honeypot bị chiếm không có đường tới DB |

### 7.4 Lớp cô lập container

| Lớp | Áp dụng |
|---|---|
| Quyền | Không `--privileged`; `cap_drop ALL` + đúng capability cần (bảng `DEPLOYMENT.md` §2); `no-new-privileges`; rootfs chỉ đọc + tmpfs |
| Người dùng | Không root trong container trừ chỗ capability bắt buộc (xem câu hỏi mở); `UserNS=auto` khi tương thích |
| Mạng | Mặc định bridge nội bộ; host/macvlan chỉ `sensor`, `scan`, `honeypot` vì cần (D-55) |
| Image | Ghim digest; cosign bắt buộc; chỉ chứa runtime tối thiểu; SBOM mỗi bản phát hành; `govulncheck`, `trivy` trong CI |
| Host | `vedette-host` hardening systemd; không SSH vào container (`agent-safety.md`) |

### 7.5 Xác thực, phân quyền, API

- REST JSON `/api/v1`, OpenAPI 3.1 **spec-first** (D-18): hợp đồng sinh từ schema Zod của mock, hiện là `api/openapi.json` (D-18 ghi `.yaml`; tên file chốt trong `API_CONVENTIONS.md`). Go sinh type/handler; CI so khớp. SSE `/api/v1/events`. Lỗi chuẩn `{"error": {"code","message"}}`.
- 3 vai: viewer / operator / admin; quyền thật luôn kiểm ở máy chủ (GUI chỉ ẩn nút). Bật thực thi phản ứng: chỉ admin + 2FA.
- Mật khẩu argon2id (tối thiểu 12 ký tự); 2FA TOTP hoặc mã email (D-35); OIDC tuỳ chọn (`auth-oidc`); token API chỉ đọc, scoped; MCP chỉ đọc, mặc định localhost.
- Secret: `core/secrets` AES-256-GCM, UI chỉ hiện 4 ký tự cuối. Header: CSP nghiêm, không tài nguyên CDN ngoài, một cookie phiên, không analytics (`rules/legal.md`).

## 8. Harness AI (D-39, D-29, D-48)

Hộp **không** nhúng agent ngoài; harness của Vedette bọc mọi lần gọi (`AI_ASSISTANT.md`):

| Thành phần | Vai trò |
|---|---|
| Hồ sơ + phân việc | Nhiều nhà cung cấp, mỗi việc một hồ sơ chính + dự phòng, quy tắc "log/thiết bị chỉ tới hồ sơ nội bộ" |
| Rules / Memory / Skills / RAG | Quy tắc đưa vào mọi lần gọi; memory xem/sửa/xoá/tắt; skill sản phẩm (`skills/`, ship cùng bản phát hành ký, D-36); kho tri thức FTS5 (+ vector tuỳ chọn) |
| Kết nối (MCP/SSH/HTTP) | Allowlist host/lệnh theo kết nối; mỗi công cụ đọc hoặc ghi; ghi chỉ qua §7.2 |
| Hook | Chặn PII, chặn việc ngoài bảo mật, công cụ ghi phải duyệt (khoá luôn bật); hook khách tự thêm |
| Nhật ký | `ai_run` + hành động, hash-chain, giữ 1 năm (chỉnh được), tải về được (S-AI-8, S-CORE-6) |
| Nhãn | Mọi output "AI-generated, needs human review", không gỡ được |

Khuyến nghị giảm thiểu có hai nguồn không trộn: gói người duy trì xác nhận (D-21, ship cùng bản phát hành) và trả lời AI của khách khi chưa có gói.

## 9. Phản ứng (D-40, D-44, D-47, D-51)

```
tác nhân (chạm bẫy, kết nối độc hại, phát hiện mới, thiết bị lạ, log vượt ngưỡng,
          cổng mới trên IP public, lịch, chạy tay)
   ─► KHI/NẾU/THÌ (quy tắc người dùng) hoặc đề xuất AI (có chốt chặn D-51)
   ─► vỏ an toàn: danh sách không bao giờ đụng, gộp trùng, giới hạn, cầu dao, cửa sổ bảo trì
   ─► yêu cầu duyệt gộp (kênh: Slack, Telegram, email/Zalo qua liên kết, trong app)
   ─► thực thi qua kết nối (pull ưu tiên: danh sách chặn URL nội bộ có token; push: API/SSH theo mẫu)
   ─► kiểm lại sau chạy · hoàn tác + TTL · audit hash-chain
```

Tham số do kẻ tấn công kiểm soát (IP, domain trong log) được kiểm kiểu và escape theo đường truyền (SYS-1). Mọi hành động cần duyệt; "duyệt sẵn" theo quy tắc là tuỳ chọn TẮT mặc định (D-51). Quy tắc mới chạy khô trước. Thiết bị không có API/SSH: chỉ cảnh báo (D-44).

## 10. Giấy phép thành phần

| Thành phần | Giấy phép | Cách dùng trong kiến trúc container |
|---|---|---|
| Mã Vedette | Apache-2.0 | |
| nuclei, httpx, naabu, subfinder, dnsx, nuclei-templates | MIT | thư viện Go nhúng (`core`, `scan`) |
| recog / recog-go | BSD-2 | nhúng |
| nmap | NPSL 0.95 | **tiến trình riêng** trong `scan`/`sensor`; xem câu hỏi mở về việc đóng gói trong image (D-4) |
| OpenCanary | BSD-3 | tiến trình riêng trong image `honeypot` |
| Greenbone CE | GPL-2/AGPL-3 | nhóm container upstream riêng, không sửa, không nhúng |
| Podman, Quadlet, cosign, netavark | Apache-2.0 | công cụ của host, không phân phối lại trong image |
| Zeek, Suricata | — | **không cài** (D-43); log Suricata của khách vẫn vào qua syslog như mọi nguồn |
| Wazuh, osquery | GPL-2 / Apache-2.0+GPL-2 | không ship; osquery gửi về hộp, Wazuh đọc qua API (D-33) |
| Dữ liệu feed | theo nguồn | hộp tự kéo trực tiếp (D-36); IOC giấy phép hạn chế vẫn do hộp kéo |
| OpenCVE | BSL 1.1 | không dùng trong lõi |

Dependency/feed mới → cập nhật `../THIRD_PARTY_NOTICES.md` cùng commit (`rules/legal.md`).

## 11. Hiệu năng mục tiêu (đo lại khi có mã)

- Hộp 4 nhân/8 GB: 1.000 thiết bị, 50k IOC, 7 ngày log gộp ≤ 2 GB SQLite; UI < 300 ms p95 cho trang chính.
- Sensor thụ động ≤ 5% một nhân ở 100 Mbps SPAN.
- Kéo feed ≤ 5 MB/giờ nhờ ETag/If-Modified-Since.
- Hạn mức tài nguyên từng container và phương pháp đo: `DEPLOYMENT.md` §2.5 (đề xuất, chốt sau khi đo ở M2).
- Nâng cấp: quay về bản trước ≤ 5 phút (đề xuất đo bằng test hiệu ứng).

## 12. Câu hỏi mở

| # | Câu hỏi | Ảnh hưởng |
|---|---|---|
| A1 | Debian 12 đi kèm Podman 4.3 (không có Quadlet, từ 4.4). D-55 ghi Debian 12 / Ubuntu 24.04. Chọn: Debian 13, backports, hay chỉ Ubuntu 24.04 ở M2? Cần kiểm lại phiên bản gói | `DEPLOYMENT.md` §4 |
| A2 | Image `scan` chứa nmap là phân phối lại nmap (NPSL 0.95), khác D-4 ("cài từ repo OS, không ship"). Giữ D-55 hay build image tại máy khách? | Giấy phép, `THIRD_PARTY_NOTICES.md` |
| A3 | Registry chứa image (đề xuất GHCR cùng repo) và cosign key-based hay keyless: là luồng dữ liệu ra mới → cập nhật `PRIVACY.md` luồng 6 + UI cùng commit | `rules/legal.md` |
| A4 | Capability cho non-root trong container (sensor/scan): xác minh bằng test hiệu ứng, nếu không được thì chạy UID 0 + cap hạn chế | §7.4 |
| A5 | Một container honeypot cho mỗi IP/vai giả (D-50) hay nhiều IP trong một container? | `DEPLOYMENT.md` §2.3 |
| A6 | Sao lưu có kèm khoá bí mật không (mã hoá bằng passphrase?) | `DEPLOYMENT.md` §10 |
| A7 | Chế độ Chỉ container: "This box" (S-INV-5) lấy gói từ đâu khi không có dpkg của host? Cập nhật image do ai bấm? | `DEPLOYMENT.md` §5 |
| A8 | `docs/MODULES.md`, `docs/DATA_PIPELINE.md` (mục cũ) vẫn nhắc fleet, vi/en, Zeek/Suricata, builder; cần dọn để khỏi mâu thuẫn tài liệu này | nhất quán tài liệu |
