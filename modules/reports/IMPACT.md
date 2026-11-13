# Reports — Change Impact Map

> Mã Go ở `modules/reports` (service.go, weekly.go, pdpl.go); chữ ký dưới đây là chữ ký thật. Cổng sang module khác nằm ở `ports.go`, bộ chuyển ở `cmd/vedette/reports.go`.

## Modifying: `Service.Weekly(ctx) (WeeklyReport, error)` (`buildWeekly`) — 3 người gọi
- **HTTP** `/reports/weekly/preview`, **job gửi theo lịch**, **`/reports/weekly/send`**: đổi cấu trúc `counts`/`actions` → GUI `WeeklyDocument` + trang in + email đều đổi; lịch sử cũ (`HistoryEntry.report`) phải đọc được (số liệu lưu theo phiên bản schema).

## Modifying: `Service.GeneratePdpl(ctx, actor) (PdplReport, error)` (`buildPdpl`, `Regime`) — 1 người gọi
- **HTTP** `/reports/pdpl/generate`. Đổi luật/quy tắc tính `regime`, `measures` → nội dung pháp lý thay đổi: phải kiểm lại với nguồn chính thức (D-23) và ghi ngày vào CONTRACT.

## Modifying: interface đọc dữ liệu (`inventory.AllDevices`, `findings.List`, `feeds.Store.KevVulns` / `KevPulledAt`, `feeds.Service.NewlyExploited`, `feeds.DisplayOf`)
- D-485: `kev_new`/`kev_matched` là `feeds.Service.NewlyExploited` (cùng số với trang chủ), tên sản phẩm là `feeds.DisplayOf` (cùng tên với Findings), `devices` đếm cả hộp như trang Devices. Đổi một trong ba ở module kia là đổi báo cáo theo, đúng ý.
- Reports là **người tiêu thụ** của `inventory`, findings (core), `feeds`; đổi ngữ nghĩa trạng thái finding (`confirmed/suspected/mitigated/patched/false_positive/not_relevant`) hoặc loại thiết bị → báo cáo đếm sai nhưng không báo lỗi. Cần test hợp đồng ở `inventory`.

## Modifying: `notify.Service.IncidentsSince` (class of an incident) / `findings.FixedInForAll` (via `reportsRemedies`, `reportsIncidents`) — D-490
- **reports**: `modules/logs/authfail.go` titles ("N failed logins from …", "A login from … was ACCEPTED after …") are how notify's `incidentClass` tells failed-login from accepted-login incidents (`TestIncidentsSinceCountsEveryClassBeyondTheListCap`); `findings.GroupFix` kinds `fixed|none|up_to|distro` feed the action sentence (`todo.go`).

## Modifying: `notify.Service.SendReport(ctx, to, ReportMail) error` / `EmailReady`
- **notify**: đổi chữ ký/lỗi → `status`/`error` trong lịch sử sai.

## Modifying: `ai.Service.RunJob(weekly-report | pdpl-assessment)` (qua `reportsAI`)
- **ai**: đổi `JobResult` → khối nhận xét AI vỡ; đổi `data: internal` của hai việc này → có thể gửi dữ liệu tổ chức tới cloud.

## Disabling this module
- Trang Reports và lịch gửi biến mất; người nhận không còn nhận báo cáo tuần (không báo lỗi phía họ).
- Không module nào phụ thuộc vào `reports`. `rep_*` giữ nguyên.
