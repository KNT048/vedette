# Agent-intake — Change Impact Map

> Chưa có mã Go; chữ ký là kế hoạch (package `modules/agentintake`), chốt ở M7.

## Modifying: `IssueToken(ctx, name, ttlDays) (Token, secret string, error)` — 1 người gọi
- **web/features/inventory/AgentsSection**: `CreateTokenResult` hiện secret một lần; đổi định dạng token → script cài và `/intake/osquery/status` vỡ.

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
