# Agent-intake Contract

> Tier: tuỳ chọn (tắt mặc định) · Story: S-INV-4 · Quyết định: D-33, D-34, D-55, D-169 · Last verified: 2026-11-11 (WP-26 lát 0: hợp đồng, chưa có mã Go)
> GUI nằm dưới `inventory` (`web/src/features/inventory/{contract,AgentsSection,installScripts,agentConfig}.ts*`). Backend là module riêng.

## Invariants (luôn đúng)
- **INV-1** Chỉ hai nguồn: osquery (Vedette là máy chủ TLS cho osquery) và Wazuh (hộp kéo qua Wazuh server API). Không Trivy, không macOS, không ship agent (D-33). `AgentKind = ['osquery']`; Wazuh không có token.
- **INV-2** Hệ điều hành hỗ trợ chỉ là máy chủ: Linux (Debian, Ubuntu, RHEL, Rocky, AlmaLinux) và Windows Server. Script cài khác theo OS: Linux dùng curl + kiểm SHA-256 + bash; Windows dùng PowerShell 5.1 + `Get-FileHash` (D-34).
- **INV-3** Token osquery: chỉ dùng để đăng ký osquery và hỏi trạng thái; **không đọc được gì khác**. Hiện đầy đủ đúng một lần lúc tạo (`CreateTokenResult.secret`); sau đó chỉ `last4`; lưu dạng băm. Hết hạn mặc định 7 ngày (`expires_in_days` 0..365, 0 = không hết hạn); thu hồi được và có hiệu lực ngay. Token 160 bit, lưu SHA-256; sau `enroll` mỗi máy có `node_key` riêng 256 bit (lưu SHA-256, bảng `intake_osquery_nodes`, D-169 (2)): hết hạn chỉ chặn đăng ký mới, thu hồi xoá luôn các máy của token đó.
- **INV-4** Token không bao giờ nằm trong URL: chỉ header `Authorization: Bearer` (`POST /intake/osquery/status`). Token không vào log, audit, export (SYS-4).
- **INV-5** Script cài (`/install/osquery.sh`, `/install/osquery.ps1`) phục vụ công khai, **không chứa bí mật**; token truyền bằng tham số. Mỗi script có SHA-256 hiển thị trong GUI để người dùng so trước khi chạy. Gói osquery chính thức do hộp phục vụ nên máy chủ không cần Internet (D-34): ba tệp (`.deb`, `.rpm`, `.msi`) + `SHA256SUMS` **đóng sẵn trong image**, phiên bản và hash ghim trong repo, kiểm lúc dựng; không tải lúc chạy, không luồng ra mới (D-169 (10)). Có lệnh gỡ một dòng. Script và `ca.pem` nhúng/trả cùng một chứng chỉ ghim (INV-11).
- **INV-6** Wazuh: tài khoản chỉ đọc (`agent:read`, `syscollector:read`); `url` phải là https; mật khẩu lưu mã hoá qua `core/secrets`, API chỉ trả `password_last4`; `interval_minutes` ∈ {5, 15, 60, 360, 1440}; `status` ∈ {never, connected, error}. Xoá kết nối xoá luôn mật khẩu.
- **INV-7** Dữ liệu từ agent/Wazuh là không tin cậy (SYS-6): parser fail-closed, giới hạn kích thước (đăng ký 64 KiB, config 4 KiB, log 4 MiB, status 1 KiB), chỉ đọc cột trong danh sách cho phép của truy vấn đã biết; khoá thừa ở lớp ngoài của osquery (`decorations`, `epoch`, …) được **bỏ qua và không lưu** (từ chối chúng sẽ hỏng mỗi lần nâng osquery, D-169 (8)); dòng sai kiểu hoặc sai chữ bị bỏ riêng, phần còn lại giữ; gói/phiên bản chỉ vào kho qua `inventory` với `source = agent`, `confidence` cố định (mock dùng 0.95; hộp tự khai gói dpkg của chính nó là 1.0, D-53).
- **INV-8** Phần mềm nguồn `agent` được thay ở lần báo kế tiếp; phần mềm khai tay (`source=manual`) không bị đụng.
- **INV-9** Mọi mutation (tạo/thu hồi token, lưu/xoá Wazuh) ghi `core_audit` (SYS-3).
- **INV-10** Điểm cuối `.../sample-data` là **chỉ bản xem trước (mock)**; trong bản dựng thật chúng vẫn nằm trong hợp đồng và bảng route (sinh từ OpenAPI) nhưng handler trả 404 `not_found` như đường không tồn tại, và nút trong GUI không hiện (`MOCK_BUILD`).
- **INV-11** (D-169 (9)) Chứng chỉ osquery ghim là một **CA riêng của hộp** (khoá riêng, `CA:TRUE`, `pathlen 0`, sống lâu) ký chứng chỉ lá 8443 tự tạo; D-139 chỉ cấp lại lá bằng cùng CA nên gia hạn hay đổi địa chỉ không làm máy đã đăng ký mất kết nối. Lá **không** được là CA (trình duyệt từ chối). `GET /intake/ca.pem` và script nhúng đúng chứng chỉ CA đó. Chứng chỉ chủ hộp đưa vào (`-tls-cert`) không bị đụng: `ca.pem` là chuỗi chủ hộp đưa vào (lá nếu tệp chỉ có lá; chủ hộp tự chạy lại lệnh cài khi đổi chứng chỉ của mình); từng kiểu (lá tự ký, CA riêng, CA công cộng) có test `openssl verify` ở lát 1.
- **INV-12** (D-169 (5)) Hộp chỉ ghi gói của một máy khi địa chỉ TCP của kết nối nằm trong các IPv4 máy khai ở truy vấn `interfaces`; MAC dùng là của đúng card đó. Không khớp = không ghi, máy ghi nhận `unmatched` (đóng kín). Chỉ IPv4 (kho chỉ có IPv4).
- **INV-13** (D-169 (8)) Giao thức osquery: mọi lỗi thông tin xác thực (token lạ/thu hồi/hết hạn, `node_key` sai) = HTTP 200 + `{"node_invalid": true}`, không phân biệt lý do; thân quá lớn, không phải JSON, quá tần suất = 413/400/429 với envelope chuẩn. Không có `distributed` (không chạy truy vấn từ xa): đường đó không tồn tại.

## Preconditions (trước khi gọi)
- **PRE-1** Tạo token / cấu hình Wazuh: vai admin (`/inventory/agents*`).
- **PRE-2** `PUT /inventory/agents/wazuh`: đăng nhập API thử thành công **trước** khi lưu (`/test` kiểm mà không lưu).
- **PRE-3** `server_url` = `https://<IP hộp>:8443`; chưa biết IP → `https://<VEDETTE_BOX_IP>:8443` (placeholder hiện rõ, không đoán).

## Postconditions (sau khi xong)
- **POST-1** Máy chủ chạy một dòng cài + token hợp lệ → `POST /intake/osquery/status` trả `{enrolled: true, hosts ≥ 1}` và thiết bị xuất hiện trong kho với danh sách gói, nguồn `agent`.
- **POST-2** Wazuh kết nối → mỗi chu kỳ `interval_minutes` cập nhật `last_sync`, `agents`, `packages`; lỗi → `status=error` và `error` có nội dung; không xoá dữ liệu cũ.
- **POST-3** Thu hồi token → máy dùng token đó bị từ chối ở lần báo kế tiếp; dữ liệu đã nhận giữ nguyên.
- **POST-4** Hết hạn token không làm máy đã đăng ký ngừng báo (token chỉ để đăng ký; quyết ở D-169 (3), câu hỏi mở 3 đã đóng). Token hết hạn chỉ bị xoá khi không còn máy nào dùng nó; máy im quá 90 ngày bị dọn (job `Housekeeping`, D-160).

## Forbidden (không bao giờ)
- **FORBID-1** Cài/chạy bất cứ thứ gì lên máy agent từ hộp (chỉ phục vụ script để người dùng tự chạy; D-33).
- **FORBID-2** Token hoặc mật khẩu Wazuh trong URL, log, export, sao lưu.
- **FORBID-3** Ghi trực tiếp bảng `inv_*`: chỉ qua interface của `inventory` (modules.md).
- **FORBID-4** Gọi Wazuh API bằng phương thức ghi (chỉ đọc: `agent:read`, `syscollector:read`, D-33).

## Endpoints owned
| Method | Path | Vai tối thiểu | Ghi chú |
|---|---|---|---|
| GET | `/inventory/agents` | admin | token, Wazuh, script cài, `server_url` |
| POST | `/inventory/agents/tokens` | admin | trả token đầy đủ một lần |
| DELETE | `/inventory/agents/tokens/{id}` | admin | thu hồi |
| POST | `/inventory/agents/tokens/{id}/sample-data` | admin | chỉ xem trước (INV-10) |
| PUT | `/inventory/agents/wazuh` | admin | xác minh rồi lưu |
| POST | `/inventory/agents/wazuh/test` | admin | không lưu |
| DELETE | `/inventory/agents/wazuh` | admin | xoá luôn mật khẩu |
| POST | `/inventory/agents/wazuh/sample-data` | admin | chỉ xem trước |
| GET | `/install/osquery.sh` | public | không bí mật |
| GET | `/install/osquery.ps1` | public | không bí mật |
| POST | `/intake/osquery/status` | public (Bearer token) | token trong header |
| POST | `/intake/osquery/enroll` | public (token trong thân, `enroll_secret`) | máy-với-máy; trả `node_key` một lần; INV-13 |
| POST | `/intake/osquery/config` | public (`node_key`) | lịch truy vấn chỉ đọc, snapshot |
| POST | `/intake/osquery/log` | public (`node_key`) | kết quả truy vấn → `inventory` (INV-7, INV-12) |
| GET | `/intake/ca.pem` | public | chứng chỉ ghim, không bí mật (INV-11) |
| GET | `/install/osquery/{file}` | public | `SHA256SUMS` + 3 tệp gói (danh sách cố định, tra bảng, không ghép đường dẫn từ input); tên khác 404 |

Giao thức osquery TLS: `enroll`, `config`, `log` có trong `contract.ts` từ WP-26 lát 0 (câu hỏi mở 2 đã đóng); `distributed` không có (INV-13). Đường dẫn osquery nằm trong cờ `*_tls_endpoint` của script (`/api/v1/intake/osquery/{enroll,config,log}`).

## Tables owned
`intake_agent_tokens` (băm token, tên, hết hạn, `last_received`, số host), `intake_osquery_nodes` (băm `node_key`, token, `host_identifier`, hostname, hệ điều hành, `last_seen`, IP/MAC đã gắn; D-169 (2), thêm ở lát 2), `intake_wazuh` (url, user, mật khẩu mã hoá, chu kỳ, trạng thái, dấu vân tay ghim `tls_pin`). Thiết bị/gói/quan sát thuộc `inventory` (`inv_*`).

## Events
- **Phát**: `inventory.observation` (tên có trong ARCHITECTURE) với `source=agent`.
- **Nhận**: không.

## Khi tắt module (SYS-5)
Không route `/install/*`, `/intake/*`, `/inventory/agents*`; không kéo Wazuh; osquery không đăng ký/báo được (mất kết nối). Token, cấu hình Wazuh và dữ liệu đã nhận giữ nguyên. Thiết bị nguồn `agent` ngừng cập nhật và hiển thị tuổi dữ liệu thật, không giả vờ mới.

## Dependencies
- **DEPENDS ON**: `core` (auth, `core/secrets`, TLS 8443), `inventory` (nhận quan sát), `core/updates` (gói osquery chính thức nằm trong `managed` của Cập nhật).
- **DEPENDED ON BY**: `inventory` (cột nguồn `agent`, độ tin cậy cao), `exposure/scan` (không bắt buộc), `reports` (nguồn kiểm kê trong PDPL `inventory.sources`).

## Câu hỏi mở
1. ~~Tên bảng `inv_*` vs `intake_*`~~ Mock đã đổi sang `intake_agent_tokens`/`intake_wazuh` (WP-06).
2. ~~Đường dẫn osquery TLS API và `node_key`~~ Đóng (D-169 (1), (2), (8)): `contract.ts` có `enroll`/`config`/`log`.
3. ~~Token hết hạn có làm máy đã đăng ký ngừng báo không?~~ Đóng: không (D-169 (3)).
4. ~~Gói osquery lấy từ đâu~~ Đóng: đóng sẵn trong image, hash ghim, không luồng ra mới (D-169 (10)); dòng `THIRD_PARTY_NOTICES.md` cùng commit với bước dựng (lát 3).
5. ~~Chứng chỉ nhúng trong script~~ Đóng: là chứng chỉ CA công khai của hộp (không phải khoá); `MOCK_CA` chỉ là mẫu (D-169 (9), INV-11). Việc đổi hộp sang CA riêng làm ở lát 1 (core TLS).
6. [verify] Truy vấn `interfaces` (JOIN `interface_details` với `interface_addresses`) trên Windows Server thật và cầu nối Linux; script PowerShell dùng `curl.exe --cacert` (Windows Server 2019 có thể ship curl 7.55, chưa hỗ trợ `--cacert` với Schannel). Chờ máy Windows Server (D-169 (16)); trước đó chỉ test tĩnh, dòng `.ai/deferred` có ngày.
