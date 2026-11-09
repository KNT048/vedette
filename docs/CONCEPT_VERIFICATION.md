# Xác minh concept (M0)

> **Không áp dụng từ 2026-11-06 (D-23):** kien quyết không phỏng vấn; mọi story `[đạt]` theo quyết định. Tài liệu giữ lại để tham khảo nếu sau này cần xác minh với khách.

Mục tiêu: trước khi viết GUI thật, chứng minh bằng người thật rằng (a) họ hiểu, (b) họ tin, (c) họ sẽ hành động theo cảnh báo, (d) họ sẽ cài/giữ. Không xác minh = không xây.

## 1. Giả thuyết (mỗi cái gắn story)

| # | Giả thuyết | Story | Đo bằng | Ngưỡng đạt |
|---|---|---|---|---|
| H1 | P2 hiểu bảng nóng trong 2 phút và nêu đúng "hôm nay có gì mới" | S-FEED-1 | task trên prototype, hỏi lại | ≥7/10 |
| H2 | P1 đọc 5 câu tiếng Việt (S-FEED-2) và nói đúng "có liên quan tới tôi không" | S-FEED-2 | task | ≥6/8 |
| H3 | P1/P2 muốn nhận alert "chỉ cái tôi có" qua Zalo/Telegram và sẵn sàng khai tay ≤5 sản phẩm để được thế | S-ALERT-1, S-INV-2 | hỏi + làm thử khai tay | ≥7/10 khai xong ≤3 phút |
| H4 | P2 tin cột "Anh có?" khi thấy nguồn/độ tin cậy; biết phân biệt "xác nhận" vs "nghi" | S-INV-1, S-SCAN-3 | hỏi diễn giải | ≥7/10 |
| H5 | P2 sẽ dùng đoạn cấu hình copy-dán cho vendor của họ, sau khi đọc cảnh báo tác dụng phụ | S-MIT-1 | hỏi + quan sát | ≥6/10 nói "sẽ dán vào thiết bị test trước" |
| H6 | P2 chấp nhận cắm hộp vào LAN với điều kiện "không inline, tháo được" | S-INV-1 | hỏi | ≥7/10 |
| H7 | P2 có key AI hoặc sẵn sàng tạo; hiểu 3 mức token | S-AI-1, S-AI-4 | hỏi | ≥5/10 có hoặc sẵn sàng |
| H8 | P3 (MSP) cần bảng tổng nhiều khách trước cả honeypot/log | S-FLEET-1 | xếp hạng | top-3 |
| H9 | Honeypot nội bộ được hiểu là "bẫy", không bị coi là nguy hiểm | S-HP-1 | hỏi | ≥6/10 |
| H10 | Báo cáo PDPL/cấp độ là lý do mua triển khai với P1 | S-REP-2 | hỏi xếp hạng | top-3 với P1 |
| H11 | Giao diện "dễ hiểu, không rối" | (FRONTEND) | hỏi sau các task | ≥7/10 |
| H12 | P2/P3 coi "tự quét lại khi có KEV mới" và "xác nhận ≠ nghi" là lý do để giữ hộp | S-SCAN-1, S-SCAN-2 | xếp thẻ + giải thích lại một phát hiện | top-3 với ≥4/6 người P2+P3 |
| H13 | P2 có firewall gửi được syslog, sẵn sàng trỏ về hộp, thấy digest "cái mới" dùng được hơn log thô | S-LOG-1, S-LOG-2 | hỏi + đọc digest mẫu | ≥3/4 P2 |
| H14 | P2/P3 chấp nhận xác thực sở hữu domain (DNS TXT) và ký văn bản đồng ý để được quét bề mặt ngoài | S-EXP-1 | hỏi | ≥4/6 người P2+P3 |
| H15 | Giải thích AI (có nhãn, có nguồn) hữu ích hơn advisory gốc; người đọc vẫn muốn tự xác nhận trước khi làm; khi chưa có khuyến nghị đã xác nhận (D-21) sẵn sàng hỏi AI của mình | S-AI-2, S-AI-3, S-AI-6 | đọc mẫu, hỏi | ≥6/10 |
| H16 | P2 dùng "Tôi đã bị chưa?"; một phần P2 có IPS/WAF sẵn để nạp rule pack | S-MIT-3, S-MIT-2 | task + hỏi | MIT-3 ≥3/4 P2 · MIT-2 ≥2/4 P2 có IPS/WAF |

H11–H16 thêm theo D-20. Story chưa gắn giả thuyết được phân loại ở §5.

## 2. Người phỏng vấn

8–10 người: 3 P1 (chủ/quản lý SMB không IT), 4 P2 (IT một người), 2 P3 (đội triển khai/MSP), 1 P4 nếu có. 45 phút/người, ghi âm chỉ khi đã ký `docs/templates/consent-interview.md` (Luật 91/2025), ghi chép ẩn danh theo mẫu trong `docs/research/m0-interviews.md`; không tên công ty, không nội dung hợp đồng; xoá ghi âm sau khi tổng hợp.

## 3. Prototype

- **Bấm được, không backend**: SPA tĩnh (Vite) với fixture: bảng nóng từ KEV thật tuần phỏng vấn; tồn kho giả 30 thiết bị giống SMB VN (FortiGate 60F, MikroTik, Synology DS920+, Windows Server 2016, WordPress, máy in, camera Hikvision); 3 phát hiện mẫu (1 xác nhận, 2 nghi); 1 gói giảm thiểu FortiGate; 1 alert Telegram mẫu; 1 digest log; 1 câu AI giải thích (soạn tay, gắn nhãn AI).
- Màn hình: Trang chủ (bảng nóng + "Anh có?"), Thiết bị, Phát hiện → Làm gì, Cảnh báo, Cài đặt (bật/tắt module, kênh, AI). Mỗi màn hình ghi story ID ở góc (ẩn với người test).
- Làm bằng stack thật của M1 (React + shadcn) để tái dụng, nhưng **không** đầu tư kiến trúc. Thời gian: ≤5 ngày.
- Thiết kế theo `FRONTEND.md` để phản hồi về "mùi AI"/thân thiện cũng được đo ở M0 (H11: ≥7/10 nói "dễ hiểu, không rối").

## 4. Kịch bản phỏng vấn (rút gọn)

1. Hoàn cảnh: ai lo bảo mật, dùng thiết bị gì, lần cuối cập nhật firmware, đã từng bị gì.
2. Task A (H1/H2): "Mở trang chủ, nói cho tôi hôm nay có gì cần lo."
3. Task B (H3): "Khai 3 thứ công ty anh đang dùng."
4. Task C (H4/H5): "Có một phát hiện trên NAS. Anh làm gì?" → quan sát họ mở "Làm gì", đọc cấu hình.
5. Hỏi H6–H16; xếp 10 thẻ theo "tôi muốn có trước": bảng nóng, cảnh báo cái tôi có, kiểm kê tự động, thiết bị lạ, gói giảm thiểu, quét lại tự động, bề mặt ngoài, bẫy nội bộ, đọc log, báo cáo tuần/PDPL.
6. Giá trị: "Nếu miễn phí, anh tự cài hay thuê? Thuê thì mong đợi gì?"

## 5. Quyết định sau M0

- Story đạt ngưỡng → `[đạt]`, vào M1. Rớt → `[rớt]`, không xây; ghi lý do trong `DECISIONS.md`.
- Story không có giả thuyết riêng (D-20): **A** nền theo quyết định (S-CORE-1 D-10, S-CORE-2 D-12, S-CORE-4 D-16/D-17, S-AI-6 D-11) → `[đạt]`; **B** đi theo story cha (S-NOT-1 ← S-ALERT-1, S-SCAN-4 ← S-SCAN-1, S-FEED-3 ← S-FEED-1, S-ALERT-2 ← S-FLEET-1); **C** S-INV-3, S-REP-1, S-AI-5 chấm theo bài xếp thẻ (cuối bảng và không giả thuyết nào đạt → `[rớt]`); **D** story P4 (S-INV-4, S-SCAN-5, S-LOG-3, S-CORE-3, S-MCP-1) giữ `[chưa]`, xác minh với 3–5 người P4 trước M7, M7 có pha GUI riêng.
- **Điều kiện dừng** (D-20): H1 **và** H3 cùng rớt → không vào M1, quay lại `PRODUCT.md`.
- Module không có story đạt nào → không vào M1.
- Kết quả ghi `docs/research/m0-interviews.md` (ẩn danh), bảng tổng ở `USER_STORIES.md` §Nhật ký xác minh.
