# GUI trước, backend sau (kien, 2026-11-06)

Thứ tự bắt buộc: xác minh concept (M0) → GUI hoàn chỉnh trên mock API (M1) → backend từng module.
- Không viết backend cho màn hình chưa tồn tại và chưa được duyệt.
- Mock API (MSW) là hợp đồng: OpenAPI sinh từ mock trước, backend phải khớp.
- Mỗi màn hình đi qua plan → build → critique (`docs/FRONTEND.md` §5) trước khi coi là xong.
- Khi làm backend, không "tiện tay" đổi GUI đã duyệt; đổi GUI là story mới.
