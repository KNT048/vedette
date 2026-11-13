# features/honeypot

Stories: S-HP-1, S-HP-2 (D-50, D-466). Trang theo khung D-464: KPI (Trap IP đang nghe, hit hôm nay, hit 7 ngày), tab Overview, Trap IPs, Services, Tokens, Hits (`?tab=`).
**Trap IP** (D-466) là một hồ sơ: tên (host name NetBIOS), địa chỉ, preset (`presets.ts` = `modules/honeypot/presets.go`), vendor cho tiền tố MAC, dịch vụ riêng; mỗi Trap IP chỉ trả lời dịch vụ của nó (host đóng cổng khác). Danh sách cho thấy nó nằm ở đâu (B2): MAC và hãng mà máy quét đọc từ MAC, dịch vụ đang mở, link macvlan `vdh…` trên card nào, lần chạm cuối, thiết bị kho đang chiếm địa chỉ (link). Lỗi form nằm dưới đúng ô.
Phát hiện quét (W1-13): một nguồn chạm ≥ 2 Trap IP trong 1 phút = một hit `scan` (thẻ "Scan detection" nêu các Trap IP lần quét chạm); bảng hit có cột Trap IP.
Máy quét của chính Vedette (hộp 192.168.10.250) luôn bị loại trừ và hiện rõ ở trang; "Test trap" tạo lần chạm có nhãn "thử" trên Trap IP đầu tiên có dịch vụ đó, không tính vào số liệu, không gửi cảnh báo.
Bảng mock: `hp_config`, `hp_trap_ips` (core network mock đọc bằng `peek`), `hp_hits` (`kind` service|token|scan, `source_ip`, `token_id`, `trap_ip`, `trap_hostname`; module response đọc bằng `peek`), `hp_tokens`. Mỗi lần chạm có liên kết Respond tới `/response`. Đọc `assetsStore` (kiểm tra IP/tên trùng, tra thiết bị nguồn).
Slot cung cấp: `device.panels` (props `{ assetId }`). Không tiêu thụ slot nào.
Quyền: thêm/sửa/bật/tắt/xoá Trap IP = admin; Test trap, Test scan, Test token = operator; xem = viewer.
