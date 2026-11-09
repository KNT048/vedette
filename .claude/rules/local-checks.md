# Kiểm tra chạy trên máy, không dùng GitHub Actions (kien, 2026-11-09, D-61)

GitHub Actions tốn tiền ngoài dự kiến. Mọi việc làm được trên máy thì làm trên máy, cho cả Kiên lẫn Emily.

- **Không** thêm, khôi phục hay kích hoạt workflow trong `.github/workflows/`; không bật GitHub Actions, không dùng runner GitHub cho bất kỳ việc gì (test, build image, phát hành, quét lịch).
- Cổng trước khi mở PR **và** trước khi merge: rebase lên `origin/main` mới nhất rồi chạy `make verify` trên máy; PR chạm `web/` (giao diện, mock, e2e) chạy thêm `make e2e` (hoặc các spec bị ảnh hưởng khi bộ e2e gốc còn đỏ, ghi rõ trong PR). Dán phần cuối kết quả vào mục **Local checks** của PR, kèm SHA commit đã kiểm.
- Đẩy commit mới sau khi kiểm = kiểm lại. Người duyệt tin kết quả dán, được quyền tự chạy lại; kết quả không khớp → không merge.
- Quét định kỳ thay cho lịch CI: `make audit` (govulncheck + `pnpm audit`) đầu mỗi phiên làm việc và trước mỗi bản phát hành. Phát hiện có đường gọi tới → sửa trước khi merge tiếp.
- Phát hành (image, SBOM, ký cosign) chạy trên máy người duy trì bằng `make` (WP-08); không có bước nào trên runner GitHub.
- Không có CI làm lưới an toàn: chạy kiểm tra mất thời gian vẫn phải chạy; không bỏ bước vì "CI sẽ bắt".
