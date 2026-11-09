# Việc để sau — nhánh feat/fast-checks (D-62, D-63)

- [ ] Đổi đường dẫn module Go `github.com/kiennt048/vedette` → `github.com/knt048/vedette` (`go.mod`, `tools/go.mod`, mọi import, `.golangci.yml`, `sqlc.yaml`): đụng mọi gói của cả hai người, làm lúc không có nhánh Go nào đang mở dài; GitHub chuyển hướng nên chưa gấp.
- [ ] Bật branch protection cho `main` (repo public → miễn phí): PR bắt buộc, check `go` + `web` bắt buộc, cấm force-push. kien 2026-11-09: "chưa cần" — để sau, hỏi lại khi có người ngoài đóng góp.
- [ ] Bỏ `continue-on-error` của job `e2e` khi `fix/e2e-baseline` vào main.
