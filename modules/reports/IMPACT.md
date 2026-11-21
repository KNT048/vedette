# Reports — Change Impact Map

> Mã Go ở `modules/reports` (service.go, weekly.go, pdpl.go); chữ ký dưới đây là chữ ký thật. Cổng sang module khác nằm ở `ports.go`, bộ chuyển ở `cmd/vedette/reports.go`.

## Modifying: `Service.Weekly(ctx) (WeeklyReport, error)` (`buildWeekly`) — 3 người gọi
- **HTTP** `/reports/weekly/preview`, **job gửi theo lịch**, **`/reports/weekly/send`**: đổi cấu trúc `counts`/`actions` → GUI `WeeklyDocument` + trang in + email đều đổi; lịch sử cũ (`HistoryEntry.report`) phải đọc được (số liệu lưu theo phiên bản schema).

## Modifying: `buildWeekly` / `buildPdpl` → `computeWeekly` / `computePdpl` + `approvedOnly(weeklyInput)` (INV-16)
- `buildWeekly`/`buildPdpl` tính hai lần khi có thiết bị chưa duyệt: bản đầy đủ và `approved_only` (không thiết bị chưa duyệt, không finding của chúng). Lần hai đọc lại bản sửa (`fixesFor`) cho top risks của nó; không có thiết bị chưa duyệt thì không tính lại. `buildPdpl` gọi `computeWeekly` (không cần khung nhìn tuần).
- **web** `features/reports/filters.tsx` (`weeklyView`, `pdplView`) đọc `approved_only`, `device_approved`, `not_relevant*`: đổi tên/nghĩa các trường này → công tắc trên trang, trang in và lịch sử lọc sai mà không báo lỗi.
- Đổi nghĩa `Device.Approved` ở adapter `cmd/vedette/reports.go` (từ `inventory` `Approved`) → "devices not in the Devices list" đổi theo.

## Modifying: `Service.GeneratePdpl(ctx, actor) (PdplReport, error)` (`buildPdpl`, `Regime`) — 1 người gọi
- **HTTP** `/reports/pdpl/generate`. Đổi luật/quy tắc tính `regime`, `measures` → nội dung pháp lý thay đổi: phải kiểm lại với nguồn chính thức và ghi ngày vào CONTRACT.

## Modifying: interface đọc dữ liệu (`inventory.AllDevices`, `findings.List`, `feeds.Store.KevVulns` / `KevPulledAt`, `feeds.Service.NewlyExploited`, `feeds.DisplayOf`)
- `kev_new`/`kev_matched` là `feeds.Service.NewlyExploited` (cùng số với trang chủ), tên sản phẩm là `feeds.DisplayOf` (cùng tên với Findings), `devices` đếm cả hộp như trang Devices. Đổi một trong ba ở module kia là đổi báo cáo theo, đúng ý.
- Finding `patched` do Vedette đóng vì thiết bị được cập nhật (`fixed_by_update`, `resolved_by=system`) được tính là đã xử lý và dòng ghi `by` = "Vedette" (INV-13); đổi `resolved_by` của đóng tự động ⇒ sửa `weekly.go`.
- Reports là **người tiêu thụ** của `inventory`, findings (core), `feeds`; đổi ngữ nghĩa trạng thái finding (`confirmed/suspected/mitigated/patched/false_positive/not_relevant/risk_accepted`; `risk_accepted` là đã đóng nhưng **không** tính vào "đã xử lý" của tuần: `Counts.Accepted`/`AcceptedUntil` và dòng "Risk accepted: N (until …)"; cần `Finding.AcceptedUntil` do adapter `cmd/vedette/reports.go` điền từ findings) hoặc loại thiết bị → báo cáo đếm sai nhưng không báo lỗi. Cần test hợp đồng ở `inventory`.

- `Finding.Agent` do `cmd/vedette/reports.go` điền từ `findings.Record.Evidence.Agent`; mất ⇒ dòng báo cáo lại nói "Suspected" cho phát hiện của agent.

## Modifying: `notify.Service.IncidentsSince` (class of an incident) / `findings.FixedInForAll` (via `reportsRemedies`, `reportsIncidents`)
- **reports**: `modules/logs/authfail.go` titles ("N failed logins from …", "A login from … was ACCEPTED after …") are how notify's `incidentClass` tells failed-login from accepted-login incidents (`TestIncidentsSinceCountsEveryClassBeyondTheListCap`); `findings.GroupFix` kinds `fixed|none|up_to|distro|feature_update|esu` feed the action sentence (`todo.go`; the last two from a Windows release row: "Move … to a Windows release Microsoft still services", "Install the Extended Security Update …"; each its own `class()` and counted as a "fix" step).

## Modifying: `notify.Service.SendReport(ctx, to, ReportMail) error` / `EmailReady`
- **notify**: đổi chữ ký/lỗi → `status`/`error` trong lịch sử sai.

## Modifying: `ai.Service.RunJob(weekly-report | pdpl-assessment)` (qua `reportsAI`)
- **ai**: đổi `JobResult` → khối nhận xét AI vỡ; đổi `data: internal` của hai việc này → có thể gửi dữ liệu tổ chức tới cloud.

## Disabling this module
- Trang Reports và lịch gửi biến mất; người nhận không còn nhận báo cáo tuần (không báo lỗi phía họ).
- Không module nào phụ thuộc vào `reports`. `rep_*` giữ nguyên.
- **Loại thiết bị**: đọc `content/devicetypes` (gói lá, chỉ thư viện chuẩn). PDPL so loại hành xử như (`ActsAs`): VPN gateway là firewall, máy ảo là hệ thống chính (server); đếm theo loại giữ id loại.

- `Finding.Urgency` (findings' layer, 0 = not stated, reads as exploited): an action sentence says "exploited vulnerabilit(y/ies)" only while every finding of its line is layer 1 or 2, else "vulnerabilit(y/ies)"; the PDPL facts say "Open vulnerability findings". Adapter: `cmd/vedette/reports.go`.
