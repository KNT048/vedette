# Trạng thái hiện tại — đọc file này trước

Cập nhật: 2026-11-09. Repo: `KNT048/vedette` (public từ 2026-11-09, D-63; CI GitHub Actions miễn phí). Nhóm: Kiên (`@kiennt048`) và Emily / Mlee (`@kiennt049`).

## Đọc theo thứ tự
1. `CLAUDE.md` — luật làm việc.
2. `docs/TEAM_PLAN.md` — ai làm gì, gói việc (WP), thứ tự, cách chạy nhiều phiên AI.
3. File nhiệm vụ của người bạn làm cho: `.ai/tasks/kien.md` hoặc `.ai/tasks/emily.md`.
4. Hợp đồng module của WP: `modules/<id>/CONTRACT.md`, cùng `docs/ARCHITECTURE.md`, `docs/DATA_MODEL.md`, `docs/API_CONVENTIONS.md`, `docs/specs/`.
5. `docs/QA.md` — bắt buộc cho mọi màn hình (ma trận form + kịch bản, người làm ≠ người kiểm).

## Hiện trạng (đo 2026-11-09)
- **M1 xong**: giao diện đầy đủ trên mock API (`web/`), chỉ tiếng Anh. `tsc` sạch, lint 0 lỗi, vitest 624/624, `api/openapi.json` 222 đường dẫn / 274 thao tác. E2E toàn bộ chưa chạy lại sau đợt cuối.
- **M2-0 xong**: tài liệu kiến trúc, triển khai (appliance chạy container, D-55), dữ liệu, quy ước API, hợp đồng 18 module + `host`, 7 đặc tả, sổ tay kỹ thuật, runbook khung, kế hoạch nhóm.
- **M2 (backend) bắt đầu**: theo `docs/TEAM_PLAN.md` §3. Đường găng: WP-01 → WP-03 → WP-04.
- Quyết định mới nhất: D-58 (lõi không gắn hãng thiết bị). Toàn bộ ở `docs/DECISIONS.md`.

## Việc mở đã biết
- WP-06 (Kiên): chỉnh giao diện khớp hợp đồng và D-57/D-58 — danh sách ở `docs/TEAM_PLAN.md` §6.
- Câu hỏi mở cuối mỗi tài liệu ("Câu hỏi mở"); hồ sơ kiến trúc để audit: `docs/review/2026-11-09-architecture.html` (phát hiện F-01…F-15).
- `.ai/deferred/` — việc để sau theo từng nhánh.

## Lưu ý máy Kiên
Nhánh local `archive/pre-squash` và `docs/m0-plan` chứa lịch sử cũ (có tên tổ chức cũ): **không push**.
