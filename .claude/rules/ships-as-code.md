# Mọi thứ ship như code (2026-08-18)

Thay đổi xong khi máy MỚI dựng từ repo này đạt cùng trạng thái. Phụ thuộc (nmap, opencanary, zeek…) cài bởi `install.sh`/package, ghim phiên bản, idempotent, xác minh bằng hiệu ứng (dịch vụ chạy, cổng mở, cấu hình đúng), không bằng exit code. Cấu hình sinh từ DB/repo, không sửa tay trên máy. Nêu rõ giả định OS trong code; OS không hỗ trợ → báo rõ.
