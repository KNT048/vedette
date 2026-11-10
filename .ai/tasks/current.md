# Trạng thái hiện tại — đọc file này trước

Cập nhật: 2026-11-10. Repo: `KNT048/vedette` (public từ 2026-11-09, D-63; CI GitHub Actions miễn phí). Nhóm: Kiên (`@kiennt048`) và Emily / Mlee (`@kiennt049`).

## Đọc theo thứ tự
1. `CLAUDE.md` — luật làm việc.
2. `docs/TEAM_PLAN.md` — ai làm gì, gói việc (WP), thứ tự, cách chạy nhiều phiên AI.
3. File nhiệm vụ của người bạn làm cho: `.ai/tasks/kien.md` hoặc `.ai/tasks/emily.md`.
4. Hợp đồng module của WP: `modules/<id>/CONTRACT.md`, cùng `docs/ARCHITECTURE.md`, `docs/DATA_MODEL.md`, `docs/API_CONVENTIONS.md`, `docs/specs/`.
5. `docs/QA.md` — bắt buộc cho mọi màn hình (ma trận form + kịch bản, người làm ≠ người kiểm).

## Hiện trạng (2026-11-10, `origin/main` 6389e36)
- **M1 xong** (2026-11-09): giao diện đầy đủ trên mock API (`web/`), chỉ tiếng Anh. Bản build không còn mang mock (#86).
- **M2 (backend) đang chạy** theo `docs/TEAM_PLAN.md` §3. **Đường găng WP-04 xong** (#58) và **đường găng WP-13b xong** (#105). Phía Kiên đã merge: core, inventory, sensor-passive/active (kể cả nmap/capture từ xa qua mTLS), honeypot, response 13a + 13b lát 0–7, 9, 10, host 07a/07b tới `container.start/stop` + Quadlet. Phía Emily đã merge: feeds, findings, mitigation, notify, exposure/tự dò IP, scan S0/S1, ai thư viện. Trạng thái từng WP: `docs/ROADMAP.md` mục "Trạng thái 2026-11-10".
- **Đang mở**: #137 (xuất log core), #139 (docs D-136), #140 (host `container.pull`), 13b-8 duyệt qua chat (chưa PR); của Emily #123 (ai lát 1), #138 (scan S2), #141 (docs).
- **Kế tiếp (phía Kiên)**: merge #137 → #139 → #140; healthcheck subcommands (D-137); host 3-8; SP-3b; SP-5; SP-6; WP-08; WP-30; WP-31; WP-32; 13b-11 sau WP-25. Chi tiết và thứ tự: `.ai/tasks/kien.md`.
- Quyết định: trên `main` tới D-129, D-131, D-134; D-130/D-132/D-136 trong PR mở; D-133/D-135/D-137 đặt chỗ; **số trống kế tiếp D-138**. Toàn bộ ở `docs/DECISIONS.md`.

## Việc mở đã biết
- Chờ kien: khoá ký phát hành offline (minisign chính + dự phòng, cosign), máy ảo lab Ubuntu 24.04/26.04 + Debian 13, quyết định chứng chỉ TLS khi địa chỉ quản trị đổi (`.ai/tasks/kien.md` mục "Cần kien").
- Chờ Emily: #123, #138, đăng ký xuất log `ai_activity`, nối `ai` với `core/conn/read` (PRIVACY luồng 3, hook `block-pii`), `Tokens`/`BoxAddrs` còn lại trong dây nối.
- Câu hỏi mở cuối mỗi tài liệu; hồ sơ kiến trúc để audit: `docs/review/2026-11-09-architecture.html` (phát hiện F-01…F-15).
- `.ai/deferred/` — việc để sau theo từng nhánh.

## Lưu ý máy Kiên
Nhánh local `archive/pre-squash` và `docs/m0-plan` chứa lịch sử cũ (có tên tổ chức cũ): **không push**.
