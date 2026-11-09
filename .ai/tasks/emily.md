# Việc của Emily (Mlee) — đọc cùng docs/TEAM_PLAN.md

Cập nhật: 2026-11-09 (phiên AI lead của Emily). Repo: **`KNT048/vedette`** (public, D-63). Module Go: `github.com/knt048/vedette`.
Sở hữu (TEAM_PLAN §2): feeds, findings (D-57 (6)), mitigation, notify, exposure, scan, scan-credentialed, logs, agent-intake, ai, reports, mcp-server, auth-oidc.
File này là **file handoff duy nhất** của các phiên AI làm cho Emily: sau compact/restart đọc lại trước khi làm tiếp.

## Quy trình (D-61 → D-65)
- **Kiểm trên máy trong WSL2 Ubuntu**, mã ở hệ file WSL (`~/src/vedette`, worktree `~/src/vedette-wt/<nhánh>`), không `/mnt/c`; Makefile từ chối Windows gốc.
  - Trước khi push/mở PR: rebase lên `origin/main`, `make check`, dán phần cuối + SHA vào mục "Local checks".
  - Merge khi CI (GitHub Actions: `go`, `web`) xanh; CI đỏ thì sửa, không merge.
  - `make audit` đầu mỗi phiên.
- **E2E**: chỉ spec của module vừa chạm + kịch bản kiểm độc lập theo QA.md (D-64); không sửa bộ e2e cũ đang đỏ.
- **Tải máy**: tối đa 2 việc nặng cùng lúc. Trước Playwright, `pgrep -f playwright/test/cli.js` phải rỗng; dùng `--workers=2`. Bộ dọn mồ côi đã cài (`make reaper-install`).
- **Chồng lấn → Kiên làm (D-65).** Việc đụng module của Kiên hoặc phần dùng chung thì dừng phần đó và mở issue `owner:kien` (nhánh, đã làm, còn gì, cần gì), rồi làm việc khác.
  - Phần dùng chung: `core/`, `cmd/`, `Makefile`, `go.mod`, `tools/`, `scripts/`, `.github/`, `web/src/lib`, `web/src/mocks`, `docs/DECISIONS.md`, `DATA_MODEL`, `API_CONVENTIONS`, `MODULE_CONTRACTS`.
  - Thêm dependency Go = sửa `go.mod`, nên cũng mở issue.
- **PR không chờ duyệt**, kể cả nhãn `contract`; PR chạm module của Kiên thì @kiennt048 để thông báo.
- **Không tự đánh số D-xx**: ghi mục "Quyết định cần ghi" trong mô tả PR; phiên của Kiên chép vào DECISIONS.
- **Cổng kiểm của PR thư viện** = người làm (Sonnet) → người kiểm độc lập (không đọc lời giải thích của người làm; Opus cho phần nhận dữ liệu không tin cậy) → sửa → `make check`.

## Đã merge
- Giai đoạn 0 (thư viện): #8, #10 findings · #15 notify · #16 ai · #28 feeds. Quyết định D-67 (notify), D-68 (feeds), D-69 (findings), D-70 (ai).
- #42 Zalo cá nhân: gửi tin (D-46, giao thức zca-js, stdlib); rà bảo mật Opus đã sửa hết.
- #44 WP-21 findings + mitigation backend — **chưa gắn vào binary**, chờ #38.
- #46 WP-20 feeds backend, đã gắn (`feeds.FeedHandlers` cạnh `inventory.Handlers`).

## Đang làm
- **WP-22 notify** (`feat/notify-module`): 12 endpoint, hàng đợi gửi + job, đăng ký sự kiện qua `deps.Bus`, `CodeMailer`, link duyệt email. Đang sửa kết quả rà bảo mật Opus (link duyệt khi chưa có BaseURL, người nhận yêu cầu duyệt rủi ro cao, mở lại incident trùng khoá, gửi tin khi job bị ngắt, SSRF webhook, giờ im lặng theo múi giờ của hộp). Mã hoá URL webhook (SYS-4) để sang PR giao diện notify.
- **WP-23 exposure** (`feat/exposure-module`): yêu cầu mới của Kiên — tự dò IP public (bật mặc định, lần đầu khi cài, dò lại 60 phút, chỉnh 15 phút–24 giờ), nhiều IP (cân bằng tải), hiệu lực 30 ngày tự gia hạn, khách gỡ được IP, vẫn không cho gõ IP tay (D-25). Dò qua 3 dịch vụ công khai, nhận IP khi ≥ 2 dịch vụ trùng (**D-81**). Phần giao diện trước (story, hợp đồng, contract.ts, mock, ma trận form, Playwright) xong; backend đang làm.

## Chờ từ Kiên
- #38: inventory cài `findings.Inventory`, `mitigation.Vendors`; FK `fnd_finding.asset_id`; nối sự kiện; bộ kiểm chữ ký gói khuyến nghị.
- #39: inventory cài `feeds.Inventory`; `Events: d.Bus` trong `cmd/vedette/feeds.go`.

## Kế tiếp
1. Issue #50: test `TestContract_INV12_RegexTimeBound` (ai) đỏ khi máy bận — sửa cho ổn định.
2. WP-23 `scan` (nuclei, nhật ký probe; `CanScan` của exposure).
3. notify: listener duyệt bằng trả lời mã cho Zalo cá nhân + Slack Socket Mode (thư viện websocket đã có, #45).
4. PR giao diện notify: mã hoá URL webhook; người duyệt Zalo OA qua liên kết (D-46); chuyển sang API thật.
5. Chuyển giao diện feeds, findings, mitigation, exposure sang API thật (`make dev-api REAL=<module>`), mỗi màn có ma trận form + Playwright spec của module (D-64) + kiểm độc lập.
6. Giai đoạn 2: WP-24 logs, WP-25 ai module, WP-26 agent-intake, WP-27 reports/mcp-server/auth-oidc.

Mỗi module:
1. Migration có tiền tố bảng theo MANIFEST (`storetest.AssertMigrationsUsePrefix`).
2. Handler cho operation trong `core/api/oas`.
3. `audit.(*Log).Append` trong cùng giao dịch, `apierr` cho lỗi, `server.PrincipalFrom(ctx)`.
4. Test hợp đồng `go test ./modules/<id>/... -run Contract`.
5. Giao diện chuyển từ mock sang API thật (cơ chế WP-05 của Kiên).

Chữ ký thật của core: `modules/core/IMPACT.md`. Thứ core chưa có (events, auth): interface nhỏ phía module + đồ giả trong test, không viết trong `core/`.

## Bẫy kỹ thuật
- **Việc nặng trong WSL đi qua `heavy`** (`~/bin/heavy`: khoá toàn máy, mỗi lúc một việc, `GOMEMLIMIT=2GiB`, `-p=2`). WSL chỉ có 5 GB / 3 CPU; một lượt golangci-lint toàn repo ~4 GB; ba lượt song song từng làm WSL treo (2026-11-09).
- Máy Emily có script kiểm tra 10 phút (`C:/Users/BYN/.vedette-tools/health.sh`): tiến trình treo/mồ côi/trùng, WSL treo, đồng hồ (so giờ chuẩn lấy từ GitHub), thay đổi trên GitHub. Trạng thái phiên chi tiết: `C:/Users/BYN/.vedette-tools/SESSION-STATE.md`.
- `wsl.exe` tự thay `$VAR` và `$?` trước khi bash chạy: viết `\$`, hoặc đặt lệnh trong file script.
- Không viết giá trị test có hình dạng giống secret thật (URL webhook Slack, token Telegram…): GitHub push protection chặn. Ghép lúc chạy hoặc dùng giá trị rõ là giả.
- Hai struct handler nhúng cùng tên kiểu (`Handlers`) trong `cmd/vedette/handler.go` không biên dịch: đặt tên riêng (`FeedHandlers`, `NotifyHandlers`, `ExposureHandlers`…).
- Windows gốc: `core/store` (URI SQLite) và `web/scripts/openapi.mjs` hỏng; chỉ dùng WSL.
- pnpm bản độc lập bỏ qua bản native oxlint/rolldown nếu thiếu `node-version` (đã sửa ở `web/.npmrc`, #23).
- Git trong WSL dùng `gh` bên Windows làm credential helper (không chép token).
- vitest toàn bộ có thể timeout giả khi máy đang fuzz/test song song: chạy lại riêng file đỏ lúc máy rảnh.
- Fuzz chạy từng target một; số exec đứng yên khi fuzzer đang thu gọn input là bình thường.
