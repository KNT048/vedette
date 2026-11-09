# features/logs

Story: S-LOG-1 (nguồn log: danh mục 48 loại thiết bị/phần mềm có ô tìm, nhóm, giao thức gửi được, mức Vedette đọc được hay chỉ lưu; đoạn cấu hình copy-dán hoặc các bước giao diện cho từng loại; digest "mới / tăng đột biến"; tìm sự kiện; lưu giữ), S-LOG-2 + S-LOG-4 (kết nối tới IP/domain xấu: thời điểm, thiết bị trong kiểm kê, đích, cách thấy = SPAN DNS/SNI/HTTP host/luồng hoặc syslog, feed khớp, độ tin cậy; D-43: không IDS trên hộp), S-LOG-3 (Cài đặt, mục `siem`: syslog/CEF/JSON webhook, gửi thử).
Slot tiêu thụ: `logs.panels` (props `{}`), nơi module ai gắn digest AI. Không cung cấp slot.
Bảng mock: `logs_sources`, `logs_events`, `logs_retention`, `logs_siem`, `logs_ioc_hits` (`{ id, ts, asset_id, src_ip, dest, dest_kind, seen_via, feeds, confidence }`, module response đọc bằng `peek`). Cài sạch: nguồn, sự kiện, digest rỗng.
`kinds.ts` = mã loại (enum của hợp đồng); `catalog.ts` = nội dung từng loại (nhóm, giao thức, `reads: parsed|stored`, các bước, đoạn dán, ghi chú; nguồn tài liệu hãng trong comment). Thêm một loại: thêm mã vào `kinds.ts`, một mục vào `catalog.ts`, chạy `logs.test.tsx`.
