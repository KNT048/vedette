# Trạng thái hiện tại — đọc file này trước

Cập nhật: 2026-11-10. Repo: `KNT048/vedette` (public từ 2026-11-09, D-63; CI GitHub Actions miễn phí). Nhóm: Kiên (`@kiennt048`) và Emily / Mlee (`@kiennt049`).

> **Bàn giao 2026-11-10:** phần của Kiên chuyển cho anh Trưởng — `.ai/handoff/README.md`.

## Đọc theo thứ tự
1. `CLAUDE.md` — luật làm việc.
2. `docs/TEAM_PLAN.md` — ai làm gì, gói việc (WP), thứ tự, cách chạy nhiều phiên AI.
3. File nhiệm vụ của người bạn làm cho: `.ai/tasks/kien.md` hoặc `.ai/tasks/emily.md`.
4. Hợp đồng module của WP: `modules/<id>/CONTRACT.md`, cùng `docs/ARCHITECTURE.md`, `docs/DATA_MODEL.md`, `docs/API_CONVENTIONS.md`, `docs/specs/`.
5. `docs/QA.md` — bắt buộc cho mọi màn hình (ma trận form + kịch bản, người làm ≠ người kiểm).

## Hiện trạng (2026-11-10 tối, `origin/main` 557a84e)
- **M1 xong** (2026-11-09): giao diện đầy đủ trên mock API (`web/`), chỉ tiếng Anh. Bản build không còn mang mock (#86).
- **M2 (backend) đang chạy** theo `docs/TEAM_PLAN.md` §3. **Đường găng WP-04 xong** (#58) và **đường găng WP-13b xong** (#105). Phía Kiên đã merge: core, inventory, sensor-passive/active (kể cả nmap/capture/nuclei từ xa qua mTLS, SP-3b, SP-5a), honeypot, response 13a + 13b lát 0–10 trừ 13b-11, host 07a/07b **hoàn tất** (phần 3 lát 3-0…3-8b), healthcheck, TLS tự cấp lại, CI nhanh. Phía Emily đã merge: feeds, findings, mitigation, notify, exposure/tự dò IP, scan S0–S3 (S4 là #164), ai lát 1. Trạng thái từng WP: `docs/ROADMAP.md` mục "Trạng thái 2026-11-10".
- **Đang mở**: #168 (flake ARP + `host_unreachable`), SP-5b (nhánh `feat/sensor-images`, chưa PR); của Emily #164 (scan S4).
- **Kế tiếp (phía Kiên)**: SP-5b; SP-6; WP-08; WP-30; WP-31; WP-32; 13b-11 sau WP-25. Chi tiết và thứ tự: `.ai/tasks/kien.md`, `.ai/handoff/README.md`.
- Quyết định: **D-137…D-145 đã dùng**, D-146 đặt chỗ cho SP-5b; **số trống kế tiếp D-147**. Toàn bộ ở `docs/DECISIONS.md`.

## Việc mở đã biết
- Chờ kien: khoá ký phát hành offline (minisign chính + dự phòng, cosign), máy ảo lab Ubuntu 24.04/26.04 + Debian 13 (`.ai/tasks/kien.md` mục "Cần kien"). Quyết định TLS đã xong (D-139).
- Chờ Emily: #157 (`BoxAddrs` thêm tín hiệu "chưa biết"), phương thức đọc lô của scan, WP-25 cho 13b-11, đăng ký xuất log `ai_activity`, nối `ai` với `core/conn/read` (PRIVACY luồng 3, hook `block-pii`), `Tokens` còn lại trong dây nối.
- Câu hỏi mở cuối mỗi tài liệu; hồ sơ kiến trúc để audit: `docs/review/2026-11-09-architecture.html` (phát hiện F-01…F-15).
- `.ai/deferred/` — việc để sau theo từng nhánh.

## Lưu ý máy Kiên
Nhánh local `archive/pre-squash` và `docs/m0-plan` chứa lịch sử cũ (có tên tổ chức cũ): **không push**.
