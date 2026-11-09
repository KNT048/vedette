# Reports — Change Impact Map

> Chưa có mã Go; chữ ký là kế hoạch (package `modules/reports`), chốt ở M7.

## Modifying: `Weekly.Build(ctx, period) (WeeklyReport, error)` — 3 người gọi
- **HTTP** `/reports/weekly/preview`, **job gửi theo lịch**, **`/reports/weekly/send`**: đổi cấu trúc `counts`/`actions` → GUI `WeeklyDocument` + trang in + email đều đổi; lịch sử cũ (`HistoryEntry.report`) phải đọc được (số liệu lưu theo phiên bản schema).

## Modifying: `Pdpl.Generate(ctx, org) (PdplReport, error)` — 1 người gọi
- **HTTP** `/reports/pdpl/generate`. Đổi luật/quy tắc tính `regime`, `measures` → nội dung pháp lý thay đổi: phải kiểm lại với nguồn chính thức (D-23) và ghi ngày vào CONTRACT.

## Modifying: interface đọc dữ liệu (`inventory.List`, `findings.List`, `feeds.KEVStats`)
- Reports là **người tiêu thụ** của `inventory`, findings (core), `feeds`; đổi ngữ nghĩa trạng thái finding (`confirmed/suspected/mitigated/patched/false_positive/not_relevant`) hoặc loại thiết bị → báo cáo đếm sai nhưng không báo lỗi. Cần test hợp đồng ở `inventory`.

## Modifying: `Mail.Send(ctx, recipients, report) error` (qua `notify`)
- **notify**: đổi chữ ký/lỗi → `status`/`error` trong lịch sử sai.

## Modifying: `ai.RunJob(weekly-report | pdpl-assessment)`
- **ai**: đổi `JobResult` → khối nhận xét AI vỡ; đổi `data: internal` của hai việc này → có thể gửi dữ liệu tổ chức tới cloud.

## Disabling this module
- Trang Reports và lịch gửi biến mất; người nhận không còn nhận báo cáo tuần (không báo lỗi phía họ).
- Không module nào phụ thuộc vào `reports`. `rep_*` giữ nguyên.
