# features/scan

Modules `scan` và `scan-credentialed`. Story: S-SCAN-1 (quét xác nhận, chọn mục tiêu trong phạm vi), S-SCAN-2 (tự quét lại khi có KEV mới có mẫu, bật/tắt + nhật ký sự kiện), S-SCAN-3 (kết quả và bằng chứng từng lần quét, nối về phát hiện), S-SCAN-4 (cửa sổ giờ, tốc độ, loại trừ, tự dừng, "Dừng ngay", lịch, nhật ký probe giữ ≥90 ngày), S-SCAN-5 (quét có tài khoản SSH).

- Bảng riêng: `scan_config`, phạm vi và ô cam kết đọc từ inventory (`scope_confirmed_at`), mục tiêu ngoài đọc từ exposure (IP của hộp, hộp thấy trong 30 ngày qua; tên miền DNS TXT), `scan_runs`, `scan_probes`, `scan_events`, `scc_target`.
- Mock tính tiến độ theo đồng hồ (`timing.stepMs` mỗi thiết bị, `timing.stopMs` cho "Dừng ngay"); UI poll 1 giây khi có lần quét đang chạy. `a-cam03` là thiết bị mẫu không phản hồi để minh hoạ tự dừng.
- Khoá SSH không được lưu hay trả lại; chỉ giữ 4 ký tự cuối.
- Slot cung cấp/tiêu thụ: không. Đường dẫn: `/scans?tab=runs|safety|auto|probes|credentialed&target=<assetId>`.
- Mục tiêu ngoài (exposure) được liệt kê nhưng bản này chưa quét (`reason: not_supported`, 400 `out_of_scope`); khi xây, `POST /scans/runs` hỏi `CheckScannable` của exposure (INV-13, 409 `ip_not_current`) ngay trước khi quét. Thiết bị khai tay không bao giờ bị quét (`declared_by_hand`, INV-5 của inventory); chọn tay một thiết bị là đồng ý cho thiết bị đó (mong manh: một phần tư tốc độ).
- Máy quét của container `scan` không sẵn sàng: `can_scan=false` kèm `block_reason`, `POST /scans/runs` trả 503 `scanner_unavailable` (`scannerStore` để test). Probe đang bay khi bấm "Dừng ngay" ghi `stopped`. CSV chặn công thức bảng tính (tên thiết bị đến từ mạng).
- Thiết bị mong manh, chưa phân loại, khai tay mang `pick_only`: trang không bao giờ tick sẵn (mặc định, "Select all", "Only devices with findings", `?target=`), người dùng tự tick mới là chọn (D-126 (2)); dòng ghi "Fragile: pick it to scan at a quarter of the speed".
- D-261: `zoneStore` (múi giờ tổ chức đọc được không) cho `schedule_blocked_reason` và `next_run: null`; `engineStore.busyUntil` (máy quét còn bận sau "Dừng ngay", `timing.engineMs`) cho `engine_busy` của `GET /scans/runs` và 409 `already_running`; sự kiện quét lại bị bỏ sau 7 ngày là `expired_no_template|expired_scanner|expired_zone`.
