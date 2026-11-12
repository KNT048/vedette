# Agent-intake — Change Impact Map

> Mã Go có từ WP-26 lát 2 (package `modules/agent-intake`, tên Go `agentintake`): osquery `enroll`/`config`/`log`/`status`, token ở mức dịch vụ, ánh xạ gói. Đường admin, script cài và Wazuh là lát 3 và 4. Kế hoạch: `docs/plans/2026-11-11-wp26-agent-intake.md`.

## Modifying: `IssueToken(ctx, actor, name, ttlDays) (Token, secret string, error)` — 0 người gọi trong Go cho tới lát 3 (đường admin)
- **web/features/inventory/AgentsSection**: `CreateTokenResult` hiện secret một lần; đổi định dạng token (`vdt_osquery_` + 32 ký tự) → regex trong `parse.go`, script cài và `/intake/osquery/status` vỡ.
- Mã lỗi `bad_name`, `bad_expiry`, `too_many_tokens` (409) là của GUI tạo token.

## Modifying: `RevokeToken` — thu hồi xoá hàng token và (khoá ngoại) các máy của nó
- Máy đã đăng ký nhận `node_invalid` ở lần gọi kế (POST-3); dữ liệu đã nhận ở `inv_*` giữ nguyên. Đổi sang "đánh dấu thu hồi" thì phải đổi tra cứu ở `service.go` và job `node-prune`.

## Modifying: giao thức osquery (`/intake/osquery/{enroll,config,log}`, D-169) — 1 người gọi: `osqueryd` trên máy chủ khách
- **Script cài và cài tay** (`web/src/features/inventory/{scripts/*,agentConfig.ts}`): cờ `*_tls_endpoint` trỏ vào đúng ba đường này; đổi đường dẫn = SHA-256 script đổi và mọi máy đã cài phải cài lại.
- **Lịch truy vấn** (`schedule.go` = `OSQUERY_SCHEDULE` trong `agentConfig.ts`; `schedule_test.go` so khớp từng truy vấn, khoảng, nền tảng): thêm/bớt truy vấn phải đổi `schedule.go`, bảng `columns` trong `parse.go`, GUI và mapper; `interfaces` là truy vấn định danh máy (INV-12), bỏ nó = không máy nào ghi được gì.
- **core/server**: bốn thao tác là `public`; cổng module (SYS-5) và `BodyLimits` áp theo `operationId` (`inventory_post_intake_osquery_*`); đổi `operationId` (đổi đường dẫn trong `contract.ts`) làm đổi khoá giới hạn thân (`cmd/vedette/modules.go` nhận `agentintake.BodyLimits`; `server.New` từ chối khoá không tồn tại).
- **Đọc địa chỉ nguồn**: `Exchange.ClientAddr()` (`r.RemoteAddr`). Đặt hộp sau proxy/NAT ngược làm mọi máy "chưa khớp" (INV-12) và chung một hạn mức nguồn (INV-14).

## Modifying: ghi vào `inventory` (`observe.Sink.Record`, `observe.SoftwareSink.ReplaceSoftware`, nguồn `agent`) — 1 đích
- **inventory**: nhận quan sát `os`/`hostname`/`vendor`/`model`/`mac` và danh sách gói (≤ 5.000, khoá `vendor|product` ≤ 400 byte, phiên bản ≤ 100 ký tự). Đổi giới hạn của `inventory.checkItems`/`cleanText` → `mapper.go` (`maxName`, `maxVersion`, `maxKeyBytes`) phải đổi theo, nếu không kho từ chối cả danh sách. Đổi độ tin cậy → cách kho gộp nhiều nguồn và cột "nghi"/"chắc" đổi theo. Đổi khoá định danh host (MAC rồi IP) → trùng thiết bị.
- **pkgmap.json**: mỗi cặp phải có trong `content/catalog` (test); đổi `kev-products.json`/`curated.json` có thể làm một cặp chết → test đỏ.

## Modifying: chứng chỉ ghim (`GET /intake/ca.pem`, INV-11, D-169 (9), D-351) — `handlers.go`, `Config.TrustAnchor`; cmd/vedette/boxca.go, tls.go
- **Mọi máy đã đăng ký**: tin cậy nằm ở CA riêng của hộp; đổi khoá CA = mọi máy phải cài lại. Gia hạn/đổi địa chỉ chỉ cấp lại lá (không ảnh hưởng máy). CA nằm trong `core_secret` (core INV-33): khôi phục `vedette.db` + `vedette.key` giữ nó; mất khoá chủ thì không.
- **`Config.TrustAnchor`** (cmd/vedette `deps.TrustAnchor`): nil = 404. Bộ lọc khối `CERTIFICATE` ở handler là chốt duy nhất giữ khoá của tệp chủ hộp không ra ngoài: bỏ nó = lộ khoá TLS của chủ hộp trên một route công khai.
- **core (D-139)**: logic cấp lại lá phải ký bằng CA này; chứng chỉ chủ hộp đưa vào không bị đụng.
- **GUI**: SHA-256 của script thay đổi khi chứng chỉ ghim đổi (script nhúng nó).

## Modifying: kéo Wazuh (`wazuh.go`, `wazuh_client.go`, `wazuh_handlers.go`, job `wazuh-pull`, lát 4, D-305..D-309)
- **core/jobs**: nhịp 1 phút; chu kỳ thật là `interval_minutes` ∈ {5, 15, 60, 360, 1440} (`WazuhIntervals` = GUI `WazuhInput.interval_minutes`; đổi một bên làm bên kia vỡ).
- **core/conn** (facade `Service.NewHTTPS`, `HTTPSTargetProblem`, D-305): đổi chính sách địa chỉ hay TLS của `core/conn` là đổi luôn của Wazuh; `TestWazuh_FormChecks` (loopback, metadata, hộp) và `TestWazuh_PinMismatchStopsThePull` phải chạy lại. Mật khẩu Wazuh nằm trong `core_secret` purpose `intake_wazuh.password`, mở bằng `Secrets.Open` như các module khác (không `Reserve`/`Restrict`, hai test quét mã không đổi).
- **Settings → Privacy** (`modules/core/handlers_privacy.go` luồng 14, `PrivacyFacts.WazuhConnected`, `cmd/vedette` `privacyFacts`, mock `web/src/features/core/mocks.ts`, `PRIVACY.md` hàng 14): đổi cái được gửi (đường dẫn, trường, nhịp) phải sửa cả bốn cùng commit (rules/legal.md).
- **inventory**: số `agents`/`packages` hiện trong thẻ Wazuh; gói vào kho qua `ReplaceSoftware` với gợi ý chỉ IP (D-307); đổi cách kho tìm thiết bị (MAC trước) → xem lại `agentIP`.
- **Wazuh server API** (bên ngoài, v4.9.x theo `api/api/spec/spec.yaml`): đổi tên trường `affected_items`/`total_affected_items`, `lastKeepAlive`, cột syscollector → `wazuh_bad_reply` hoặc agent bị bỏ; phiên bản Wazuh mới cần một lần chạy thật (dòng deferred).
- **Lát 3** (`GET /inventory/agents`): đọc thẻ qua `Service.Wazuh(ctx)`; không đọc bảng trực tiếp ngoài module.

## Modifying: script cài (`/install/osquery.sh|ps1`, lát 3)
- Máy chủ khách đã cài: script chỉ chạy một lần; đổi **nội dung** thì SHA-256 trên GUI đổi (người dùng so lại), đổi **tham số** thì lệnh một dòng trong GUI + hướng dẫn gỡ phải sửa cùng lúc.
- **core/updates**: gói osquery nằm trong `managed`; đổi phiên bản = đổi `osquery_version` trong `AgentsResponse.install`.

## Modifying: job `node-prune` (`Prune`, job thường, D-265 (8))
- Không chạy khi module tắt: khi tắt mọi máy đều "im" nên im lặng không được tính; chuỗi 90 ngày chỉ tính khi job chạy liền (bắt đầu lại sau khoảng tắt hoặc khởi động lại, trong bộ nhớ). Đổi sang Housekeeping = hộp tắt 90 ngày cắt mọi máy vĩnh viễn. Đổi 90 ngày (`NodeSilentDays`) hay 30 ngày = đổi lời hứa trong CONTRACT POST-4 và DATA_MODEL.

## Disabling this module
- Mục Agents trong Inventory hiện "module đang tắt"; script cài và `/intake/*` trả 404 (cổng SYS-5, test `TestContract_SYS5_ModuleOffIs404`); osquery trên máy chủ khách nhận 404 ở config/log (osquery tự thử lại; rẻ, qua cổng); không đăng ký/báo được.
- `inventory`: thiết bị nguồn `agent` không cập nhật nữa; phát hiện (findings) dựa trên gói cũ có thể lỗi thời, UI hiện tuổi dữ liệu. Token, máy, dữ liệu giữ nguyên (`node-prune` cũng dừng; thời gian tắt không tính vào 90 ngày im lặng).
- `reports` (PDPL): mục nguồn kiểm kê không còn `agent` mới.
