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

Lần kiểm độc lập 2026-11-09 còn thêm ba lỗi chung: hộp thoại đóng (X) chỉ cao 24 px trên điện thoại (nay 40 px); `Field` kéo giãn hàng lưới làm ô chọn lệch so với ô bên cạnh (nay `content-start`); trang Response và Settings → AI response tràn ngang trên điện thoại do lưới `grid` một cột không có `minmax(0,1fr)`.

| Form | Bộ chọn | Lần kiểm gần nhất |
|---|---|---|
| Response → Add a custom action | loại kết nối (API thiết bị, HTTP, SSH, MCP, danh sách chặn, tin nhắn, webhook) | 2026-11-09, người kiểm độc lập: ma trận 7 loại kết nối + khoá chỉ đọc đã có; thêm đường dẫn "Open Settings, AI assistant, Connections" khi chưa có kết nối cần dùng (trước đó là ngõ cụt); Playwright 4 biến thể |
| Response → quy tắc (KHI/NẾU/THÌ) | loại tác nhân, loại hành động | 2026-11-09, người kiểm độc lập: ma trận loại kích hoạt (chỉ "On a schedule" có chu kỳ) và kiểu điều kiện; lỗi: đổi kiểu điều kiện giữ nguyên giá trị cũ (CIDR còn lại trong ô); đã sửa; trên điện thoại cả trang Response tràn ngang (474 > 412 px) làm hộp thoại lệch, đã sửa |
| Settings → Alert channels → kênh | loại kênh (Slack, Telegram, email, Zalo OA, Zalo cá nhân, webhook) | 2026-11-09, người kiểm độc lập: ma trận 6 loại kênh (ô, người duyệt, kênh chỉ-liên-kết), Slack tắt duyệt thì không gửi channel_id, Zalo cá nhân hai người duyệt; ô "Add approver" trống khi hết người nay có chữ; Playwright 4 biến thể |
| Settings → AI assistant → Add AI profile | loại nhà cung cấp, nơi chạy | 2026-11-09, người kiểm độc lập: ma trận 5 loại nhà cung cấp (mặc định, khoá "Inside your network" cho nhà cung cấp cloud); lỗi: khoá API gõ cho nhà cung cấp này vẫn đi theo sang nhà cung cấp khác, tick "I understand" cũng giữ; đã sửa |
| Settings → AI assistant → Connections | loại kết nối, kiểu xác thực | 2026-11-09, người kiểm độc lập: ma trận 5 loại kết nối; lỗi: kiểu xác thực không hợp loại (SSH với API token, Device API với SSH key…) vẫn chọn được và máy chủ nhận; đổi loại giữ nguyên địa chỉ, danh sách cho phép, khoá; đã sửa (khoá lựa chọn + lý do, máy chủ từ chối 400, đổi loại thì xoá) |
| Settings → AI assistant → Hooks | thời điểm, kiểu khớp, hành động | 2026-11-09, người kiểm độc lập: ma trận keywords/regex; lỗi: mẫu từ khoá còn lại khi đổi sang regex; đã sửa. Còn lại: "Require approval" cho hook trước/sau AI chưa bị khoá (động cơ hook chạy được cả hai) |
| Settings → Feeds → feed tuỳ chỉnh | loại feed, định dạng, xác thực | 2026-11-09, người kiểm độc lập: ma trận kiểu xác thực và định dạng; lỗi: gợi ý regex "CVE-…" hiện trong feed IOC, lỗi tên header/tên người dùng hiện dưới ô khoá bí mật; đã sửa |
| Devices → Add a device | danh mục / nhập tay | 2026-11-09, người kiểm độc lập: ma trận danh mục / nhập tay; lỗi: bấm "Back to the list" rồi vào lại "nhập tay" thì ô Maker/Product trông còn chữ cũ nhưng Add bị khoá; đã sửa |
| Devices → Scope and sensors | quét chủ động bật/tắt, loại thiết bị | 2026-11-09, người kiểm độc lập: ma trận quét chủ động tắt/bật (khoá cửa sổ quét), loại mỏng manh, máy chủ từ chối quét khi chưa xác nhận phạm vi; không lỗi mới |
| External exposure → thêm mục tiêu | domain / IP | 2026-11-09, người kiểm độc lập: hộp thoại chỉ có ô Domain, IP đi qua nút riêng không có ô nhập; thêm nút Cancel (trước đó chỉ có Add) |
| Logs → thêm nguồn log | loại nguồn (48 loại) | 2026-11-09, người kiểm độc lập: ma trận cả 48 loại thiết bị: giao thức đúng của loại đó, cổng theo giao thức, máy chủ từ chối giao thức sai; không lỗi mới |
| Internal traps → vai giả, honey token | loại vai, loại token | 2026-11-09, người kiểm độc lập: ma trận 5 vai giả và 4 loại token; lỗi: tên và nơi đặt gõ cho loại này vẫn còn khi đổi loại, lỗi cũ còn hiện sau khi đổi; đã sửa |
| My account → hai bước | ứng dụng / email | 2026-11-09, người kiểm độc lập: ma trận ứng dụng / email (QR, gửi lại mã, Cancel quay về lựa chọn); không lỗi mới |
| Settings → Updates → cửa sổ bảo trì | chế độ (mọi lúc / chỉ trong cửa sổ) | 2026-11-09, agent làm + ma trận tự động + Playwright 4 biến thể (kien chưa xem) |
| Settings → Updates → Schedule reboot | lịch (đầu cửa sổ tiếp / giờ tự chọn), khoá khi không có cửa sổ | 2026-11-09, như trên |
| Devices → hộp (This box) → xoá | nút bị khoá, máy chủ từ chối 409 | 2026-11-09, như trên |
| Settings → Box network → Interfaces | vai giao diện (management / SPAN capture / unused), máy chủ từ chối hai management, đổi management, hai SPAN | 2026-11-09, agent làm + ma trận tự động + Playwright 4 biến thể (kien chưa xem) |
| Settings → Box network → Management interface | DHCP / static (DHCP ẩn IP, prefix, gateway, DNS; không rò giá trị cũ), bước xác nhận 2 phút và hoàn tác | 2026-11-09, như trên |
| Settings → Box network → SPAN capture | công tắc đọc gì (DNS, TLS SNI, HTTP host, kết nối), loại bộ lọc loại trừ (CIDR / host / port), cổng SPAN không được là cổng quản lý | 2026-11-09, như trên |
| Settings → Box network → NTP | pool mặc định / máy chủ riêng | 2026-11-09, như trên |
| Settings → Box network → Hướng dẫn mirror | hãng switch (8 mục) | 2026-11-09, như trên |
| Devices → Scope and sensors → Sensor on this box | hộp thoại chỉ đọc: trạng thái SPAN + liên kết sang Box network | 2026-11-09, như trên |

## 5. Tốc độ không bỏ được bước 2–3
Khi kien muốn ship nhanh: được bỏ chạy lại toàn bộ E2E, được bỏ test hồi quy rộng; **không** được bỏ ma trận form và kịch bản cho màn hình vừa làm.
