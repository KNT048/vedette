# Agent-intake — Change Impact Map

> Chưa có mã Go; chữ ký là kế hoạch (package `modules/agentintake`), chốt ở M7. Kế hoạch lát: `docs/plans/2026-11-11-wp26-agent-intake.md`.

## Modifying: `IssueToken(ctx, name, ttlDays) (Token, secret string, error)` — 1 người gọi
- **web/features/inventory/AgentsSection**: `CreateTokenResult` hiện secret một lần; đổi định dạng token → script cài và `/intake/osquery/status` vỡ.

## Modifying: giao thức osquery (`/intake/osquery/{enroll,config,log}`, D-169) — 1 người gọi: `osqueryd` trên máy chủ khách
- **Script cài và cài tay** (`web/src/features/inventory/{scripts/*,agentConfig.ts}`): cờ `*_tls_endpoint` trỏ vào đúng ba đường này; đổi đường dẫn = SHA-256 script đổi và mọi máy đã cài phải cài lại.
- **Lịch truy vấn** (`OSQUERY_SCHEDULE` trong `agentConfig.ts` = nội dung `config` của Go, hiện cho người dùng ở "What Vedette asks osquery for"): thêm/bớt truy vấn phải đổi cả hai nơi và test so khớp; `interfaces` là truy vấn định danh máy (INV-12), bỏ nó = không máy nào ghi được gói.
- **inventory**: nhận quan sát/gói `source=agent` qua `core/observe`; đổi cột đọc từ truy vấn → đổi `confidence` và khớp KEV theo gói (`pkgmap`).
- **core/server**: ba đường là thao tác `public`, cổng module và giới hạn thân (`BodyLimits`) áp theo `operationId`; đổi `operationId` (đổi đường dẫn trong `contract.ts`) làm đổi khoá giới hạn.

## Modifying: chứng chỉ ghim (`GET /intake/ca.pem`, INV-11, D-169 (9)) — cmd/vedette/tls.go (lát 1)
- **Mọi máy đã đăng ký**: tin cậy nằm ở CA riêng của hộp; đổi khoá CA = mọi máy phải cài lại. Gia hạn/đổi địa chỉ chỉ cấp lại lá (không ảnh hưởng máy).
- **core (D-139)**: logic cấp lại lá phải ký bằng CA này; chứng chỉ chủ hộp đưa vào không bị đụng.
- **GUI**: SHA-256 của script thay đổi khi chứng chỉ ghim đổi (script nhúng nó).

## Modifying: `ReportPackages(ctx, host, []Package) error` → `inventory.SubmitObservations` — 1 đích
- **inventory**: nhận `source=agent`, `confidence`. Đổi độ tin cậy → cách `inventory` gộp quan sát nhiều nguồn và cột "nghi"/"chắc" trong kho đổi theo. Đổi khoá định danh host → trùng thiết bị.

## Modifying: `WazuhSync(ctx) (SyncResult, error)` (job theo `interval_minutes`)
- **core/jobs**: đổi chu kỳ/giá trị hợp lệ → `WazuhInput.interval_minutes` trong GUI vỡ.
- **inventory**: số `agents`/`packages` hiển thị trong Agents.

## Modifying: script cài (`/install/osquery.sh|ps1`)
- Máy chủ khách đã cài: script chỉ chạy một lần; đổi **nội dung** thì SHA-256 trên GUI đổi (người dùng so lại), đổi **tham số** thì lệnh một dòng trong GUI + hướng dẫn gỡ phải sửa cùng lúc.
- **core/updates**: gói osquery nằm trong `managed`; đổi phiên bản = đổi `osquery_version` trong `AgentsResponse.install`.

## Disabling this module
- Mục Agents trong Inventory hiện "module đang tắt"; script cài và `/intake/*` trả 404; osquery trên máy chủ khách mất kết nối (không lỗi phía khách ngoài log osquery).
- `inventory`: thiết bị nguồn `agent` không cập nhật nữa; phát hiện (findings) dựa trên gói cũ có thể lỗi thời, UI hiện tuổi dữ liệu.
- `reports` (PDPL): mục nguồn kiểm kê không còn `agent` mới. Token, Wazuh, dữ liệu giữ nguyên.
