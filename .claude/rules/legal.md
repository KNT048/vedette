# Pháp lý minh bạch (kien, 2026-11-06, D-17)

- Thêm dependency, công cụ ngoài, nguồn dữ liệu → cập nhật `THIRD_PARTY_NOTICES.md` cùng commit, ghi giấy phép và cách dùng (nhúng / tiến trình riêng / dữ liệu). GPL/AGPL không nhúng.
- Thêm bất kỳ luồng dữ liệu rời hộp → cập nhật `PRIVACY.md` bảng luồng + UI Cài đặt → Quyền riêng tư cùng commit. Tín hiệu ẩn danh: payload cố định, không thêm trường nào mà không ghi vào PRIVACY.md.
- Chỉ cookie cần cho đăng nhập: phiên, CSRF, thiết bị tin cậy (D-77); không thêm cookie nào khác; không analytics; không tài nguyên từ CDN ngoài trong SPA.
- Quét chủ động chỉ trong scope đã xác nhận sở hữu + có đồng ý; probe ghi log.
- Nhãn "AI tạo" trên mọi output AI; không gỡ.
- Không dùng tên/logo hãng khác, nmap, Spamhaus trong marketing.
