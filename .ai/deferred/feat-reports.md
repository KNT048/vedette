# Deferred — feat/reports (WP-27 reports)
- [ ] `notify` đăng ký `reports.report.ready` (feat-notify-module.md:6): chưa cần, vì reports gửi qua `notify.SendReport`; mở lại nếu muốn báo "báo cáo mới" qua Slack/Telegram.
- [ ] Trang in `/reports/print/*` vẫn do GUI (đã đạt); chưa kiểm bản in với số liệu thật từ backend (cần `make e2e-real`, ngoài phạm vi lát này).
- [ ] e2e: spec Playwright cho luồng gửi tay với SMTP giả (WP-30), chưa viết.
