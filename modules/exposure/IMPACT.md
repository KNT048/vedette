# Exposure — Change Impact Map

## Modifying: `exposure.Service.CheckScannable(ctx, actor, targetID) (bool, BlockedReason, error)`
- **scan** (gọi ngay trước mỗi lần quét mục tiêu ngoài, truyền người hoặc module gọi làm `actor`). Đây là rào chắn SYS-7 phía Internet: nới điều kiện phải sửa CONTRACT + test INV-1 và INV-13 của cả `exposure` và `scan`. Với IP, lời gọi có thể chạy một lượt dò đầy đủ ra Internet (5 vòng, tối đa một lần mỗi 5 phút, PRIVACY luồng 9): `scan` phải chịu được độ trễ vài giây và `BlockedNotCurrent` (`ip_not_current`, quét tạm dừng, IP vẫn trong danh sách).

## Modifying: `exposure.Service.Targets(ctx)` (the scan module keeps the `scannable` ones; ids `ext:<id>` are accepted by `CheckScannable`; `verified_at`, `expires_at`)
- **scan** (`GET /scans/targets` `reason ∈ {unverified, expired}`), **reports**. Đổi định dạng id `ext:<id>` làm hỏng lịch quét đã lưu. `scannable` trên `Target` là phán đoán theo trạng thái đã lưu; việc "hộp còn dùng IP này" chỉ biết lúc quét (INV-13), nên một IP `scannable` vẫn có thể bị `CheckScannable` từ chối.

## Modifying: kiểm xác thực (`Verify`, `Detect`), chu kỳ tự phát hiện (`exp_setting.interval_min`, job `auto-detect`), danh sách ba dịch vụ "IP của tôi" (D-81) và danh sách bỏ qua (`exp_ignored`, D-79)
- **PRIVACY.md luồng 9** và SPA Settings → Privacy (`web/src/locales/en/core.json`): đổi dịch vụ hoặc tần suất (nay: lần đầu khi cài là lần dò đầy đủ 15 yêu cầu, rồi 1 phút đến 24 giờ một lần, mặc định 60 phút, mỗi lần 3 yêu cầu; lần dò đầy đủ còn chạy tối đa mỗi giờ, khi bấm Detect now, khi bật tự phát hiện, khi `Verify` một IP và ngay trước khi quét một IP) là đổi luồng dữ liệu ra, phải sửa PRIVACY + UI cùng commit (legal.md).
- **`scan`**: đọc `validity` của IP từ `Targets()`; IP hết hạn tự lành khi hộp dò lại (INV-4), không cần người bấm. IP trong danh sách bỏ qua không phải mục tiêu nên không có trong `Targets()` (INV-14).
- **SPA** `ExposurePage` (công tắc tự phát hiện, chu kỳ, "Detect now", danh sách IP, hộp thoại gỡ IP với ô "Don't add it again if detected", mục Ignored với Restore), `VerifyPanel`; `contract.ts` là nguồn OpenAPI cho `PUT /exposure/box-ip/settings`, `box_ip` và `ignored` trong `GET /exposure/targets`, `?ignore` của `DELETE /exposure/targets/{id}` và `DELETE /exposure/box-ip/ignored/{ip}`.
- **`core/server`**: `ModuleOf` đưa mọi `/exposure/*` về module `exposure` theo tag; route mới cần một dòng trong `contractRoutes` của `core/server/modules_test.go` và `api/route-modules.json`.

## Modifying: `ScannableIP(ctx, actor, ip)` (D-57 (7), LEGAL §3)
- **scan** (runner) hỏi nó trước khi quét cổng một địa chỉ mà tên của domain trỏ tới. Nới nó (ví dụ trả `true` cho IP chưa cam kết hay không phải mục tiêu) là quét ngoài phạm vi: sửa CONTRACT INV-12 + `TestContract_INV12_ScannableIP` + `cmd/vedette` `TestExposureRunnerResult`.

## Modifying: `Runner` (`Config.Runner`, `SetRunner`, `ScanTarget.User`), `ScanEvery`, khoá một lượt mỗi lúc, và `ErrScanOff`, `ErrScanBusy`, `ErrCTDown`, `ErrScanTooLong`, `TooManyNames`
- **scan** sở hữu runner (`cmd/vedette` `scanRunner`, `modules/scan/surface`, D-229): đổi `ScanTarget`/`Content` phải sửa adapter `contentOf` và `TestExposureRunnerResult`. Ba lỗi là câu người dùng đọc (toast của Scan now); mock `exposure` trả đúng `module_off` khi module `scan` tắt.
- **response** (`new_port`) và **reports** đọc ảnh chụp do runner tạo; runner không lưu gì khi lỗi.

## Modifying: `TargetView.open_ports`, `MaxOpenPorts`, `latestResults` (D-485)
- **web/features/exposure**: câu đầu và mục "N ports open to the Internet" của `ExposurePage.tsx` đọc `open_ports`; nhãn "Commonly attacked" theo `PortRow.service` (`services.ts`), nên đổi tên dịch vụ trong `modules/scan/surface/ports.go` là đổi nhãn đó. Mock `mocks.ts` cắt 20 như hộp.

## Modifying: trường `Snapshot`/`Diff`
- **SPA** `ResultsPanel`, `TargetPage`; **reports**. `contract.ts` là nguồn OpenAPI.

## Modifying: `Snapshots`, `SnapshotOf`, `Diff` (`Diff.Added`, nhãn mục), `upsertSnapshot`, sự kiện `exposure.snapshot.created` (`SnapshotCreatedEvent`)
- **response** (trigger `new_port`, D-384) qua cầu `cmd/vedette/exposureports.go`: mỗi `exposure.snapshot.created` nó đọc `Snapshots` (mới nhất trước) lấy ngày quét trước của cùng mục tiêu, rồi `Diff` và `SnapshotOf` hai ngày đó, và phát một `exposure.port.opened` cho mỗi cổng mở bây giờ mà ngày trước không có. Nó dựa vào: nhãn của mục `port` trong `Diff.Added` đúng dạng `"<ip>:<port>"`; **một ảnh chụp mỗi mục tiêu mỗi ngày** (`upsertSnapshot` ghi đè trong ngày); `SnapshotCreatedEvent` mang `TargetID` + `Date` của ảnh vừa ghi; ngày quét đầu tiên của mục tiêu là mốc, không phát gì. Đổi bất kỳ điều nào → sửa cầu và `cmd/vedette` `TestExposureSnapshotOpensNewPorts`. Nếu sau này `exposure` tự phát `exposure.port.opened` thì cầu bỏ đi.

## Disabling this module
- Trang External exposure mất; `scan` chỉ quét mục tiêu nội bộ; luồng PRIVACY 9 dừng (job không chạy, kể cả lượt dò đầy đủ trước khi quét).
- Mục tiêu, cam kết, ảnh chụp, cài đặt và danh sách bỏ qua giữ; `reports` bỏ mục bề mặt ngoài.
