# features/honeypot

Stories: S-HP-1, S-HP-2 (D-50: vai giả/personality theo thiết bị thật trong kiểm kê, honey token file/credential/URL/DNS, phát hiện quét IP bẫy, bảng "Is this enough?"). S-HP-1 (bẫy SMB/RDP/SSH/MSSQL/HTTP trên IP phụ, lần chạm kèm IP nguồn, thiết bị nguồn từ kiểm kê, 1 giờ sự kiện quanh đó).
Máy quét của chính Vedette (hộp 192.168.10.250) luôn bị loại trừ và hiện rõ ở trang; "Thử chạm bẫy" tạo lần chạm có nhãn "thử", không tính vào số liệu, không gửi cảnh báo.
Bảng mock: `hp_config`, `hp_hits` (thêm `kind` service|token|scan, `source_ip`, `token_id`; module response đọc bằng `peek`), `hp_decoys`, `hp_tokens`. Mỗi lần chạm có liên kết Respond tới `/response`. Đọc `assetsStore` (kiểm tra IP/tên trùng, tra thiết bị nguồn).
Slot cung cấp: `device.panels` (props `{ assetId }`). Không tiêu thụ slot nào.
Quyền: bật/tắt bẫy, IP phụ, tên máy giả = admin; Thử chạm bẫy = operator; xem = viewer.
