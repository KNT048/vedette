# Exposure — Change Impact Map

## Modifying: `exposure.Service.CheckScannable(ctx, targetID) (bool, BlockedReason)`
- **scan** (gọi ngay trước mỗi lần quét mục tiêu ngoài). Đây là rào chắn SYS-7 phía Internet: nới điều kiện phải sửa CONTRACT + test INV-1 của cả `exposure` và `scan`.

## Modifying: `exposure.Service.Targets()` / `ScannableTargets()` (`ext:<id>`, `verified_at`, `expires_at`)
- **scan** (`GET /scans/targets` `reason ∈ {unverified, expired}`), **reports**. Đổi định dạng id `ext:<id>` làm hỏng lịch quét đã lưu.

## Modifying: kiểm xác thực (`verify`, `boxip.Detect`) và danh sách dịch vụ "IP của tôi" (D-81)
- **PRIVACY.md luồng 9** và SPA Settings → Privacy: đổi đích là đổi luồng dữ liệu ra, phải sửa PRIVACY + UI cùng commit (legal.md).

## Modifying: trường `Snapshot`/`Diff`
- **SPA** `ResultsPanel`, `TargetPage`; **reports**. `contract.ts` là nguồn OpenAPI.

## Disabling this module
- Trang External exposure mất; `scan` chỉ quét mục tiêu nội bộ; luồng PRIVACY 9 dừng.
- Mục tiêu, cam kết, ảnh chụp giữ; `reports` bỏ mục bề mặt ngoài.
