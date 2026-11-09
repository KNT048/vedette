# Module bật/tắt riêng biệt

- `modules/<tên>/MANIFEST.yaml` bắt buộc: id, tier, depends, permissions, ports, tables_prefix, stories[].
- Tắt = không route, không job, không cổng; dữ liệu giữ nguyên; UI nói rõ chỗ thiếu dữ liệu vì module tắt.
- Bật module thiếu phụ thuộc → hỏi, không tự bật ngầm.
- Bảng DB có tiền tố module; không module nào đọc bảng module khác trực tiếp — qua interface trong `core/`.
- FE: `web/src/features/<module>` mount theo trạng thái module từ API.
