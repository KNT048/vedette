# Module bật/tắt riêng biệt

- `modules/<tên>/MANIFEST.yaml` bắt buộc: id, tier, depends, permissions, ports, tables_prefix, stories[].
- Tắt = không route, không job, không cổng; dữ liệu giữ nguyên; UI nói rõ chỗ thiếu dữ liệu vì module tắt.
- Ngoại lệ (D-141): `core` sở hữu cổng liên kết sensor 8444, dùng chung cho hai module; khi cả hai tắt cổng vẫn mở và trả 409 `module_off`; dữ liệu giữ nguyên.
- Ngoại lệ (D-189): một module tắt có thể chạy vòng thử lại của `OffGuard` (chỉ để dừng thứ còn sống ngoài tiến trình, như container và IP bẫy của honeypot) cho tới khi host xác nhận; đó không phải job và không mở route hay cổng (SYS-5).
- Ngoại lệ (D-160): job `Housekeeping: true` của `core/jobs` chạy cả khi module tắt, chỉ để xoá dữ liệu quá thời hạn lưu khách đã đặt hoặc sản phẩm đã công bố (CONTRACT và GUI), hoặc vượt trần lưu trữ đã ghi trong tài liệu (D-201, D-202), và ghi dòng audit của việc xoá đó; không mở route, cổng hay kết nối ra ngoài.
- Bật module thiếu phụ thuộc → hỏi, không tự bật ngầm.
- Bảng DB có tiền tố module; không module nào đọc bảng module khác trực tiếp — qua interface trong `core/`.
- FE: `web/src/features/<module>` mount theo trạng thái module từ API.
