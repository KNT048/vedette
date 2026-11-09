# Exposure — Change Impact Map

## Modifying: `exposure.Service.CheckScannable(ctx, targetID) (bool, BlockedReason)`
- **scan** (gọi ngay trước mỗi lần quét mục tiêu ngoài). Đây là rào chắn SYS-7 phía Internet: nới điều kiện phải sửa CONTRACT + test INV-1 của cả `exposure` và `scan`.

## Modifying: `exposure.Service.Targets()` / `ScannableTargets()` (`ext:<id>`, `verified_at`, `expires_at`)
- **scan** (`GET /scans/targets` `reason ∈ {unverified, expired}`), **reports**. Đổi định dạng id `ext:<id>` làm hỏng lịch quét đã lưu.

## Modifying: kiểm xác thực (`Verify`, `Detect`), chu kỳ tự phát hiện (`exp_setting.interval_min`, job `auto-detect`) và endpoint cố định của dự án
- **PRIVACY.md luồng 9** và SPA Settings → Privacy: đổi đích hoặc tần suất (nay: lần đầu khi cài rồi 15 phút đến 24 giờ một lần, mặc định 60 phút, mỗi lần 3 yêu cầu) là đổi luồng dữ liệu ra, phải sửa PRIVACY + UI cùng commit (legal.md).
- **`scan`**: `Targets()`/`ScannableTargets()` đọc `validity` của IP; IP hết hạn tự lành khi hộp dò lại (INV-4), không cần người bấm.
- **SPA** `ExposurePage` (công tắc tự phát hiện, chu kỳ, "Detect now", danh sách IP), `VerifyPanel`; `contract.ts` là nguồn OpenAPI cho `PUT /exposure/box-ip/settings` và `box_ip` trong `GET /exposure/targets`.

## Modifying: trường `Snapshot`/`Diff`
- **SPA** `ResultsPanel`, `TargetPage`; **reports**. `contract.ts` là nguồn OpenAPI.

## Disabling this module
- Trang External exposure mất; `scan` chỉ quét mục tiêu nội bộ; luồng PRIVACY 9 dừng.
- Mục tiêu, cam kết, ảnh chụp giữ; `reports` bỏ mục bề mặt ngoài.
