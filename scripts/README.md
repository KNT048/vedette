install.sh (idempotent, cài nmap/opencanary từ repo OS, systemd/OpenRC). Chưa có.

`release/`: công cụ dựng bản phát hành (Go; WP-08f, D-164): `go run ./scripts/release cosign-plan|manifest|index|sign|verify`, qua `make release-*`; `release/minisign.sh` in đường dẫn minisign đã ghim (tải nếu chưa có).

`dev/orphan-reaper.sh`: dừng tiến trình test/dev mồ côi (Playwright, Chromium headless, vitest, binary `go test`, golangci-lint ngay; vite mồ côi quá 2 giờ) làm quá tải máy; `make reaper-install` cài chạy 10 phút một lần (macOS launchd, Linux systemd user), log `~/Library/Logs/vedette-orphan-reaper.log`.
