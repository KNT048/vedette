# features/scan

Modules `scan` và `scan-credentialed`. Story: S-SCAN-1 (quét xác nhận, chọn mục tiêu trong phạm vi), S-SCAN-2 (tự quét lại khi có KEV mới có mẫu, bật/tắt + nhật ký sự kiện), S-SCAN-3 (kết quả và bằng chứng từng lần quét, nối về phát hiện), S-SCAN-4 (cửa sổ giờ, tốc độ, loại trừ, tự dừng, "Dừng ngay", lịch, nhật ký probe giữ ≥90 ngày), S-SCAN-5 (quét có tài khoản SSH).

- Bảng riêng: `scan_config`, phạm vi và ô cam kết đọc từ inventory (`scope_confirmed_at`), mục tiêu ngoài đọc từ exposure (IP của hộp, xác nhận ≤ 90 ngày; tên miền DNS TXT), `scan_runs`, `scan_probes`, `scan_events`, `scan_cred`.
- Mock tính tiến độ theo đồng hồ (`timing.stepMs` mỗi thiết bị, `timing.stopMs` cho "Dừng ngay"); UI poll 1 giây khi có lần quét đang chạy. `a-cam03` là thiết bị mẫu không phản hồi để minh hoạ tự dừng.
- Khoá SSH không được lưu hay trả lại; chỉ giữ 4 ký tự cuối.
- Slot cung cấp/tiêu thụ: không. Đường dẫn: `/scans?tab=runs|safety|auto|probes|credentialed&target=<assetId>`.
