# Bảo mật của chính sản phẩm

- Tiến trình ngoài: chỉ `core/exec` với allowlist binary + argv; không gọi shell bằng chuỗi lệnh, không eval.
- Validate ở biên: IP qua `netip`, tên qua regex `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`, JSON theo schema; từ chối ký tự nguy hiểm trước khi vào file cấu hình/sinh lệnh.
- Secret: `core/secrets` AES-256-GCM, khoá file 0600; không log, không export, UI chỉ 4 ký tự cuối.
- Feed/log/web/agent = dữ liệu không tin cậy: parser fail-closed, giới hạn kích thước, fuzz parser.
- Cập nhật và content pack phải ký; không ký → từ chối.
- AI: không tool ghi — ngoại lệ duy nhất là module `response` (D-41): tắt mặc định, từng hành động phải được người có quyền duyệt, hết hạn, có hoàn tác, ghi kiểm toán; output theo schema; nhãn "AI tạo".
- Dữ liệu rời hộp chỉ gồm: kéo feed, gọi provider AI/feed BYOK khách cấu hình, và tín hiệu ẩn danh theo `PRIVACY.md` (tắt được). Thêm luồng ra khác = cập nhật PRIVACY.md + UI trước.
- Dependency: ghim phiên bản; không GPL/AGPL vào lõi; `govulncheck`/`trivy` chạy trên máy (`make verify`, `make audit`, phát hành), không GitHub Actions (D-61).
