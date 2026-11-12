# Việc để sau — phía `core` của `host.self_update` (lát 5, D-316, nhánh feat/core-updates-host)

- [ ] 2026-11-12 — S-CORE-2 D-316 (e), phần mock: sau `rollback_failed`/`self_update_interrupted` các mock OS install, Box network và backups của bản xem thử chưa trả 409 (hộp thật trả `transition_pending`, core đã ánh xạ ở lát 5) — vì sao để sau: đổi GUI/mock đã duyệt là việc của một lát GUI (rules/gui-first.md), không thuộc backend — ở đâu: web/src/features/core/mocks.ts `settleHost`, osMock.ts, networkMock.ts (chuyển từ feat-core-updates-host-gui.md dòng 1)
