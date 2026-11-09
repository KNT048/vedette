# Agent-intake Contract

> Tier: tuỳ chọn (tắt mặc định) · Story: S-INV-4 · Quyết định: D-33, D-34, D-55 · Last verified: 2026-11-09
> GUI nằm dưới `inventory` (`web/src/features/inventory/{contract,AgentsSection,installScripts,agentConfig}.ts*`). Backend là module riêng.

## Invariants (luôn đúng)
- **INV-1** Chỉ hai nguồn: osquery (Vedette là máy chủ TLS cho osquery) và Wazuh (hộp kéo qua Wazuh server API). Không Trivy, không macOS, không ship agent (D-33). `AgentKind = ['osquery']`; Wazuh không có token.
- **INV-2** Hệ điều hành hỗ trợ chỉ là máy chủ: Linux (Debian, Ubuntu, RHEL, Rocky, AlmaLinux) và Windows Server. Script cài khác theo OS: Linux dùng curl + kiểm SHA-256 + bash; Windows dùng PowerShell 5.1 + `Get-FileHash` (D-34).
- **INV-3** Token osquery: chỉ dùng để đăng ký osquery và hỏi trạng thái; **không đọc được gì khác**. Hiện đầy đủ đúng một lần lúc tạo (`CreateTokenResult.secret`); sau đó chỉ `last4`; lưu dạng băm. Hết hạn mặc định 7 ngày (`expires_in_days` 0..365, 0 = không hết hạn); thu hồi được và có hiệu lực ngay.
- **INV-4** Token không bao giờ nằm trong URL: chỉ header `Authorization: Bearer` (`POST /intake/osquery/status`). Token không vào log, audit, export (SYS-4).
- **INV-5** Script cài (`/install/osquery.sh`, `/install/osquery.ps1`) phục vụ công khai, **không chứa bí mật**; token truyền bằng tham số. Mỗi script có SHA-256 hiển thị trong GUI để người dùng so trước khi chạy. Gói osquery chính thức do hộp phục vụ nên máy chủ không cần Internet (D-34). Có lệnh gỡ một dòng.
- **INV-6** Wazuh: tài khoản chỉ đọc (`agent:read`, `syscollector:read`); `url` phải là https; mật khẩu lưu mã hoá qua `core/secrets`, API chỉ trả `password_last4`; `interval_minutes` ∈ {5, 15, 60, 360, 1440}; `status` ∈ {never, connected, error}. Xoá kết nối xoá luôn mật khẩu.
- **INV-7** Dữ liệu từ agent/Wazuh là không tin cậy (SYS-6): parser fail-closed, giới hạn kích thước, từ chối trường lạ; gói/phiên bản chỉ vào kho qua `inventory` với `source = agent`, `confidence` cố định (mock dùng 0.95; hộp tự khai gói dpkg của chính nó là 1.0, D-53).
- **INV-8** Phần mềm nguồn `agent` được thay ở lần báo kế tiếp; phần mềm khai tay (`source=manual`) không bị đụng.
- **INV-9** Mọi mutation (tạo/thu hồi token, lưu/xoá Wazuh) ghi `core_audit` (SYS-3).
- **INV-10** Điểm cuối `.../sample-data` là **chỉ bản xem trước (mock)**; không tồn tại trong bản dựng thật.

## Preconditions (trước khi gọi)
- **PRE-1** Tạo token / cấu hình Wazuh: vai admin (`/inventory/agents*`).
- **PRE-2** `PUT /inventory/agents/wazuh`: đăng nhập API thử thành công **trước** khi lưu (`/test` kiểm mà không lưu).
- **PRE-3** `server_url` = `https://<IP hộp>:8443`; chưa biết IP → `https://<VEDETTE_BOX_IP>:8443` (placeholder hiện rõ, không đoán).

## Postconditions (sau khi xong)
- **POST-1** Máy chủ chạy một dòng cài + token hợp lệ → `POST /intake/osquery/status` trả `{enrolled: true, hosts ≥ 1}` và thiết bị xuất hiện trong kho với danh sách gói, nguồn `agent`.
- **POST-2** Wazuh kết nối → mỗi chu kỳ `interval_minutes` cập nhật `last_sync`, `agents`, `packages`; lỗi → `status=error` và `error` có nội dung; không xoá dữ liệu cũ.
- **POST-3** Thu hồi token → máy dùng token đó bị từ chối ở lần báo kế tiếp; dữ liệu đã nhận giữ nguyên.
- **POST-4** Hết hạn token không làm máy đã đăng ký ngừng báo (token chỉ để đăng ký). Nếu thiết kế thật khác, ghi vào đây (câu hỏi mở 3).

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

Giao thức osquery TLS (enroll, config, logger, distributed) không có trong `contract.ts`; xem câu hỏi mở 2.

## Tables owned
`intake_agent_tokens` (băm token, tên, hết hạn, `last_received`, số host), `intake_wazuh` (url, user, mật khẩu mã hoá, chu kỳ, trạng thái). Thiết bị/gói/quan sát thuộc `inventory` (`inv_*`).

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
2. Đường dẫn osquery TLS API và cách xác thực sau đăng ký (node_key) chưa ghi ở đâu; không nằm trong `contract.ts` nên OpenAPI sẽ không phủ.
3. Token hết hạn có làm máy đã đăng ký ngừng báo không? Thiết kế (D-34) nói token "chỉ dùng để đăng ký" nên đề xuất: không.
4. Gói osquery chính thức hộp phục vụ lấy từ đâu (đóng sẵn trong image hay kéo)? Nếu kéo = luồng ra mới → `PRIVACY.md` (legal.md) và `THIRD_PARTY_NOTICES.md`.
5. Chứng chỉ CA của hộp nhúng trong script (mock có `MOCK_CA`): xác nhận là CA công khai, không phải khoá.
