# Deferred — feat/reports (WP-27 reports)
- [ ] Báo cáo tuần chưa có số chạm bẫy và bất thường log (CONTRACT INV-9, câu hỏi mở 2): cần interface thống kê từ `honeypot`/`logs`; thêm nguồn vào `sources` khi có.
- [ ] `notify` đăng ký `reports.report.ready` (feat-notify-module.md:6): chưa cần, vì reports gửi qua `notify.SendReport`; mở lại nếu muốn báo "báo cáo mới" qua Slack/Telegram.
- [ ] Trang in `/reports/print/*` vẫn do GUI (đã đạt); chưa kiểm bản in với số liệu thật từ backend (cần `make e2e-real`, ngoài phạm vi lát này).
- [ ] e2e: spec Playwright cho luồng gửi tay với SMTP giả (WP-30), chưa viết.
