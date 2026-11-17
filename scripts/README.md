install.sh (idempotent, cài nmap/opencanary từ repo OS, systemd/OpenRC). Chưa có.

`release/`: công cụ dựng bản phát hành (Go; WP-08f): `go run ./scripts/release cosign-plan|manifest|index|sign|verify`, qua `make release-*`; `release/minisign.sh` in đường dẫn minisign đã ghim (tải nếu chưa có).

`dev/orphan-reaper.sh`: dừng tiến trình test/dev mồ côi (Playwright, Chromium headless, vitest, binary `go test`, golangci-lint ngay; vite mồ côi quá 2 giờ) làm quá tải máy; xét **gốc cây**: leo từ tiến trình khớp qua launcher (pnpm/npm/npx/yarn/tsx/vite…) tới gốc, cả cây bị dừng khi cha của gốc là init/launchd hoặc `systemd --user` (shell/node chung chung không bao giờ bị leo qua); test `dev/orphan-reaper-test.sh` (chạy trong `make verify-go-static`); `make reaper-install` cài chạy 10 phút một lần (macOS launchd, Linux systemd user), log `~/Library/Logs/vedette-orphan-reaper.log`.

`dev/home-summary-measure.sh` (#825): đo Home trên hộp thật: `GET /findings/summary` và ba danh sách Home cũ đọc (p50/p95/max ms, byte, N lần; `COLD=k` thêm k lần tính sau TTL 60 s), RSS của core trước/sau khi chạy trên chính hộp; `BASE=https://127.0.0.1:8443 EMAIL=… N=50 scripts/dev/home-summary-measure.sh` (mật khẩu hỏi hoặc `PASSWORD`, tài khoản viewer đủ). Tải trang: `web/e2e/qa/home-load.mjs`. RSS chỉ so được khi hộp đã yên (không lượt kéo feed đang chạy).
