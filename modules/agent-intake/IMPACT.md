# Agent-intake — Change Impact Map

> Mã Go có từ WP-26 lát 2 (package `modules/agent-intake`, tên Go `agentintake`): osquery `enroll`/`config`/`log`/`status`, token ở mức dịch vụ, ánh xạ gói. Lát 4: Wazuh. Lát 3: đường admin, script cài, `ca.pem`, kho gói. Kế hoạch: `docs/plans/2026-11-11-wp26-agent-intake.md`.

## Modifying: `IssueToken(ctx, actor, name, ttlDays) (Token, secret string, error)` — 1 người gọi: `AdminHandlers.InventoryPostInventoryAgentsTokens` (lát 3)
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

## Modifying: chứng chỉ ghim (`GET /intake/ca.pem`, INV-11, D-169 (9)) — cmd/vedette/tls.go (lát 1)
- **Mọi máy đã đăng ký**: tin cậy nằm ở CA riêng của hộp; đổi khoá CA = mọi máy phải cài lại. Gia hạn/đổi địa chỉ chỉ cấp lại lá (không ảnh hưởng máy).
- **core (D-139)**: logic cấp lại lá phải ký bằng CA này; chứng chỉ chủ hộp đưa vào không bị đụng.
- **GUI**: SHA-256 của script thay đổi khi chứng chỉ ghim đổi (script nhúng nó).

## Modifying: kéo Wazuh (`wazuh.go`, `wazuh_client.go`, `wazuh_handlers.go`, job `wazuh-pull`, lát 4, D-305..D-309)
- **core/jobs**: nhịp 1 phút; chu kỳ thật là `interval_minutes` ∈ {5, 15, 60, 360, 1440} (`WazuhIntervals` = GUI `WazuhInput.interval_minutes`; đổi một bên làm bên kia vỡ).
- **core/conn** (facade `Service.NewHTTPS`, `HTTPSTargetProblem`, D-305): đổi chính sách địa chỉ hay TLS của `core/conn` là đổi luôn của Wazuh; `TestWazuh_FormChecks` (loopback, metadata, hộp) và `TestWazuh_PinMismatchStopsThePull` phải chạy lại. Mật khẩu Wazuh nằm trong `core_secret` purpose `intake_wazuh.password`, mở bằng `Secrets.Open` như các module khác (không `Reserve`/`Restrict`, hai test quét mã không đổi).
- **Settings → Privacy** (`modules/core/handlers_privacy.go` luồng 14, `PrivacyFacts.WazuhConnected`, `cmd/vedette` `privacyFacts`, mock `web/src/features/core/mocks.ts`, `PRIVACY.md` hàng 14): đổi cái được gửi (đường dẫn, trường, nhịp) phải sửa cả bốn cùng commit (rules/legal.md).
- **inventory**: số `agents`/`packages` hiện trong thẻ Wazuh; gói vào kho qua `ReplaceSoftware` với gợi ý chỉ IP (D-307); đổi cách kho tìm thiết bị (MAC trước) → xem lại `agentIP`.
- **Wazuh server API** (bên ngoài, v4.9.x theo `api/api/spec/spec.yaml`): đổi tên trường `affected_items`/`total_affected_items`, `lastKeepAlive`, cột syscollector → `wazuh_bad_reply` hoặc agent bị bỏ; phiên bản Wazuh mới cần một lần chạy thật (dòng deferred).
- **Lát 3** (`GET /inventory/agents`): đọc thẻ qua `Service.Wazuh(ctx)`; không đọc bảng trực tiếp ngoài module.

## Modifying: script cài (`/install/osquery.sh|ps1`, `GET /inventory/agents` khối `install`, lát 3)
- Máy chủ khách đã cài: script chỉ chạy một lần; đổi **nội dung** thì SHA-256 trên GUI đổi (người dùng so lại), đổi **tham số** thì lệnh một dòng trong GUI + hướng dẫn gỡ phải sửa cùng lúc.
- **web/features/inventory** (`scripts/osquery.sh`, `scripts/osquery.ps1`, `installScripts.ts`): `modules/agent-intake/scripts/` là bản chép; sửa một bên mà không sửa bên kia làm `TestInstall_ScriptsEqualTheGUI` đỏ (chép lại bằng `cp`). Đổi cách GUI điền `@@BOX@@/@@VERSION@@/@@CA@@` (dòng `const fill`) cũng làm test đỏ: sửa `fill` ở `install.go` cùng lúc.
- **Địa chỉ trong script** (`boxURL`): Host của yêu cầu chỉ được dùng khi `Config.HostAllowed` (danh sách Host của server) chấp nhận; đổi cách `core/server` so Host (`HostMatcher`) đổi luôn cái script được phép mang. Hộp sau proxy/NAT ngược: Host là tên proxy, phải nằm trong `-hosts`, nếu không script mang địa chỉ cấu hình hoặc `<VEDETTE_BOX_IP>`.
- **cmd/vedette** (`trustAnchor`): chứng chỉ ghim đọc một lần lúc khởi động; đổi tệp chứng chỉ của chủ hộp thì phải khởi động lại để `ca.pem` và script theo kịp (cùng lúc listener mới phục vụ chứng chỉ mới). Hộp HTTP trên loopback: 404 `no_certificate`.
- **core/updates**: gói osquery nằm trong `managed`; đổi phiên bản = đổi `osquery_version` trong `AgentsResponse.install`.

## Modifying: kho gói osquery (`GET /install/osquery/{file}`, `deploy/osquery/PINS`, `deploy/containers/core/Containerfile`, lát 3)
- Đổi phiên bản osquery = một commit đổi **bốn chỗ**: `deploy/osquery/PINS` (phiên bản + 3 SHA-256), `OSQUERY_VERSION` ở `web/src/features/inventory/installScripts.ts`, `OsqueryVersion` ở `install.go`, dòng osquery ở `THIRD_PARTY_NOTICES.md`; `TestInstall_VersionsAgree` bắt ba số đầu lệch nhau, bước dựng image bắt hash sai. Tên tệp trong script, trong `mirrorFiles` và trong Containerfile phải khớp (test đọc cả ba).
- **image `core`**: +~76 MiB (3 tệp, 79.872.941 byte; đã nén sẵn nên lớp image cũng cỡ đó). Thư mục `/usr/share/vedette/osquery/` là mặc định của cờ `-osquery-dir`; đổi một bên làm kho trả 404 `mirror_missing`. Bản dựng không qua image (`make dev`) không có thư mục đó: kho 404 `mirror_missing`, script cài trên máy chủ khách sẽ lỗi khi tải gói.
- **Tải**: tối đa 4 lượt cùng lúc (429 `rate_limited`, `Retry-After: 5`); một máy chủ khách tải thất bại thì script dừng, chạy lại sau. Nhiều máy cùng cài một lúc (> 4) phải thử lại.
- Không có luồng dữ liệu ra mới (không tải lúc chạy), nên `PRIVACY.md` không đổi.

## Modifying: job `node-prune` (`Prune`, job thường, D-265 (8)) và bảng `intake_prune_clock` (lát 3)
- Không chạy khi module tắt: khi tắt mọi máy đều "im" nên im lặng không được tính. Lần chạy cuối nằm trong DB (`intake_prune_clock`): lần chạy đầu sau khoảng trống > 3 giờ (tắt module, tắt hộp, khởi động lại, nâng cấp) cộng khoảng trống vào `last_seen` của mọi máy (không quá lúc đó). `last_seen` chỉ dùng để dọn, nên dời nó không đổi gì khác. Đổi sang Housekeeping = hộp tắt 90 ngày cắt mọi máy vĩnh viễn. Đổi 90 ngày (`NodeSilentDays`), 30 ngày hay ngưỡng 3 giờ (`pruneGap`, phải lớn hơn nhịp `pruneEvery` 1 giờ) = đổi lời hứa trong CONTRACT POST-4 và DATA_MODEL. Xoá hàng đồng hồ (hoặc khôi phục DB cũ) = mọi máy được thêm 90 ngày từ lần chạy kế.
- **core/export** (`modules/core/export_policy.go`): `intake_prune_clock` là bảng xuất; thêm cột phải phân loại ở đó (`TestExport_PolicyClassifiesEveryColumn`).

## Disabling this module
- Mục Agents trong Inventory hiện "module đang tắt"; script cài và `/intake/*` trả 404 (cổng SYS-5, test `TestContract_SYS5_ModuleOffIs404`); osquery trên máy chủ khách nhận 404 ở config/log (osquery tự thử lại; rẻ, qua cổng); không đăng ký/báo được.
- `inventory`: thiết bị nguồn `agent` không cập nhật nữa; phát hiện (findings) dựa trên gói cũ có thể lỗi thời, UI hiện tuổi dữ liệu. Token, máy, dữ liệu giữ nguyên (`node-prune` cũng dừng; thời gian tắt không tính vào 90 ngày im lặng).
- `reports` (PDPL): mục nguồn kiểm kê không còn `agent` mới.
