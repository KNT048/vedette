# Scan — Change Impact Map

## Modifying: `scan.Service.StartRun(ctx, targets, trigger)` và bộ chọn `Targets()`
- **SPA** (`/scans`, `RunsTab`, Devices → "Scan"), **core/jobs** (lịch), `OnNewKEV`. Đổi điều kiện chọn mục tiêu đổi số gói/request rời hộp: sửa CONTRACT + test INV-1…3.

## Modifying: gọi `inventory.InScope/ScanPolicy` và `exposure.CheckScannable`
- **inventory**, **exposure**: đây là hai rào SYS-7. Nới ở một phía mà không sửa phía kia ⇒ lỗ hổng phạm vi.

## Modifying: `findings.ConfirmFromScan(…)` và sự kiện `scan.finding.confirmed`
- **findings** (tạo/xác nhận finding), **notify** (qua finding). Đổi `Evidence` làm hỏng bằng chứng hiển thị (S-SCAN-3).

## Modifying: `feeds.vuln.new_kev` (trường `has_template`)
- Nguồn kích hoạt quét lại. Đổi tên/trường ⇒ mất S-SCAN-2 mà không có lỗi.

## Modifying: nhật ký `scan_probe` / danh mục `scan_probes`
- **core** (`/core/logs/export`), **SPA** Probes. Giảm thời gian giữ dưới 90 ngày phá S-SCAN-4.

## Disabling this module
- Mất trang Scans và nút quét; không xác nhận mới; không tự quét lại sau KEV mới.
- `scan-credentialed` không chạy được (phụ thuộc); `findings` chỉ còn `suspected`; `reports` bỏ mục quét.
- Cấu hình, lịch sử, probe log, sự kiện quét lại giữ.

## Modifying: `scan.Engine` (S1, D-125)
- Seam of the scanner: the worker of the `scan` container over the sensor protocol (S5), a fake in tests. `Ready` decides `can_scan` and the 503 `scanner_unavailable` (INV-2). No Engine wired = scanner not available: `cmd/vedette` wires none until S5, so a real box never sends a request before then.

## Modifying: `scan_setting` / `Service.SaveConfig` (S1)
- **SPA** Schedule and safety tab, **jobs** of S4 (window, schedule, auto rescan, rate, exclusions). INV-5 is checked twice: in `Settings.validate` (with the mock's words) and by the CHECKs of `0001_scan_setting.sql`.
