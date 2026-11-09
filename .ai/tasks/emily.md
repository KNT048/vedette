# Việc của Emily (Mlee) — đọc cùng docs/TEAM_PLAN.md

Cập nhật: 2026-11-09. Sở hữu: feeds, mitigation + phát hiện, notify, exposure, scan, scan-credentialed, logs, agent-intake, ai, reports, mcp-server, auth-oidc.

## Bắt đầu
1. Clone `kiennt048/vedette`, đọc `CLAUDE.md`, `CONTRIBUTING.md`, `docs/TEAM_PLAN.md`, `docs/ENGINEERING.md`, `docs/QA.md`.
2. Chạy giao diện: `make dev` → http://localhost:5173 ("Use sample data").
3. Đọc `docs/ARCHITECTURE.md`, `docs/DATA_MODEL.md`, `docs/API_CONVENTIONS.md`, `modules/{feeds,mitigation,notify,ai}/CONTRACT.md`.

## Giai đoạn 0 (không phụ thuộc core — làm ngay, song song)
- [ ] WP-20a thư viện feed (`feat/feeds-lib`)
- [ ] WP-21a thư viện khớp lỗ hổng (`feat/matching-lib`)
- [ ] WP-22a thư viện adapter kênh (`feat/notify-adapters`)
- [ ] WP-25a thư viện AI (`feat/ai-lib`)

## Ghi chú cho phiên AI
- Mỗi phiên một worktree + một nhánh + một WP; không sửa module của Kiên.
- Đổi hợp đồng → PR nhãn `contract`, gán @kiennt048 duyệt.
