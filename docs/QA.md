# Cách kiểm giao diện (bắt buộc cho mọi màn hình mới hoặc sửa)

Lập 2026-11-09 sau lỗi kien bắt được: form "Add a custom action" vẫn hiện ô API khi chọn kết nối SSH và cho chọn kết nối chỉ đọc cho hành động ghi. Lỗi lọt vì người làm tự kiểm, test chỉ kiểm logic máy chủ, đợt rà giao diện chỉ dò tự động và bỏ qua module đang làm lại.

## 1. Người làm ≠ người kiểm
Agent viết màn hình không tự nghiệm thu. Một agent kiểm độc lập (không xem lời giải thích của người làm, chỉ xem màn hình và story) đi hết các bước như người dùng thật.

## 2. Ma trận form (test tự động, mỗi form có bộ chọn đổi nghĩa)
Form có bộ chọn làm thay đổi ý nghĩa các ô khác (loại kết nối, loại kênh, loại nhà cung cấp AI, định dạng feed, kiểu xác thực, loại tác nhân, domain hay IP…) phải có test lặp qua **từng lựa chọn**:
- chỉ các ô thuộc lựa chọn đó hiện ra; ô của lựa chọn khác ẩn;
- không có giá trị mặc định rò từ lựa chọn khác (ví dụ đường dẫn FortiGate khi chọn SSH);
- đổi lựa chọn thì xoá ô không còn áp dụng;
- lựa chọn không dùng được trong ngữ cảnh này (kết nối chỉ đọc cho hành động ghi, kênh chưa cấu hình…) bị khoá kèm lý do, và máy chủ cũng từ chối.
Helper dùng chung: `web/src/test/formMatrix.ts` (thêm khi viết test đầu tiên).

## 3. Đi kịch bản bằng tay ảo (Playwright, trên server dev)
Mỗi story có ít nhất một kịch bản viết theo việc người dùng muốn làm, ví dụ "tạo hành động SSH thêm ACL chặn IP trên switch Cisco". Agent kiểm đi từng bước, chụp ảnh từng bước, và trả lời ở mỗi bước: ô nào thừa, ô nào thiếu, chữ nào khó hiểu, bước nào cụt (dead end), có đường quay lại không. Desktop + điện thoại, sáng + tối.

## 4. Danh mục form phải đi qua
Danh sách mọi hộp thoại và form có bộ chọn, ghi kết quả lần kiểm gần nhất (ngày, người kiểm, kết quả). Form mới thêm vào danh sách trong cùng commit.

| Form | Bộ chọn | Lần kiểm gần nhất |
|---|---|---|
| Response → Add a custom action | loại kết nối (API thiết bị, HTTP, SSH, MCP, danh sách chặn, tin nhắn, webhook) | lỗi 2026-11-09 (kien) |
| Response → quy tắc (KHI/NẾU/THÌ) | loại tác nhân, loại hành động | chưa |
| Settings → Alert channels → kênh | loại kênh (Slack, Telegram, email, Zalo OA, Zalo cá nhân, webhook) | chưa |
| Settings → AI assistant → Add AI profile | loại nhà cung cấp, nơi chạy | chưa |
| Settings → AI assistant → Connections | loại kết nối, kiểu xác thực | chưa |
| Settings → AI assistant → Hooks | thời điểm, kiểu khớp, hành động | chưa |
| Settings → Feeds → feed tuỳ chỉnh | loại feed, định dạng, xác thực | chưa |
| Devices → Add a device | danh mục / nhập tay | chưa |
| Devices → Scope and sensors | quét chủ động bật/tắt, loại thiết bị | chưa |
| External exposure → thêm mục tiêu | domain / IP | chưa |
| Logs → thêm nguồn log | loại nguồn (48 loại) | chưa |
| Internal traps → vai giả, honey token | loại vai, loại token | chưa |
| My account → hai bước | ứng dụng / email | chưa |
| Settings → Updates → cửa sổ bảo trì | chế độ (mọi lúc / chỉ trong cửa sổ) | 2026-11-09, agent làm + ma trận tự động + Playwright 4 biến thể (kien chưa xem) |
| Settings → Updates → Schedule reboot | lịch (đầu cửa sổ tiếp / giờ tự chọn), khoá khi không có cửa sổ | 2026-11-09, như trên |
| Devices → hộp (This box) → xoá | nút bị khoá, máy chủ từ chối 409 | 2026-11-09, như trên |

## 5. Tốc độ không bỏ được bước 2–3
Khi kien muốn ship nhanh: được bỏ chạy lại toàn bộ E2E, được bỏ test hồi quy rộng; **không** được bỏ ma trận form và kịch bản cho màn hình vừa làm.
