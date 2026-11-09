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
- #8 tách hợp đồng `findings` khỏi `mitigation` (D-57 (6)) · #10 thư viện findings (CPE 2.3, khoảng phiên bản, bộ khớp, vòng đời).
- #15 thư viện notify (adapter Slack/Telegram/SMTP/Zalo OA/webhook, quy tắc gửi, token duyệt email).
- #16 thư viện ai (nhà cung cấp, định tuyến nội bộ kiểm lúc quay số, đồng hồ token, hook PII tiếng Việt, chuỗi hash qua `core/chain`).
- Quyết định của các thư viện: D-67 (notify), D-68 (feeds), D-69 (findings), D-70 (ai).

## Đang làm
- **WP-20a thư viện feeds**: PR #28 (sửa 15 phát hiện rà bảo mật), merge khi CI xanh. Issue #29 (Public Suffix List cần `go.mod`).
- **Zalo cá nhân (notify, D-46)**: `feat/notify-zalo-personal`. Gửi tin bằng stdlib; listener duyệt bằng trả lời mã cần thư viện websocket trong `go.mod` (cùng nhu cầu với Slack Socket Mode, D-38) → issue owner:kien.

## Chờ từ Kiên
- #17: head record cho chuỗi hash, `secrets.Value.Last4/IsSet`.
- #29: `x/net/publicsuffix`.
- WP-04a (server, registry, scheduler) để bắt đầu giai đoạn 1.

## Kế tiếp — giai đoạn 1 (khi WP-04a vào main)
- WP-20 feeds: endpoint, feed tuỳ chỉnh, trạng thái.
- WP-21 findings + mitigation: endpoint, gói "What to do". Kiểm `modules/mitigation/MANIFEST.yaml` depends có `findings` (D-57 (6)).
- WP-22 notify: kênh, giờ im lặng, gộp, Incidents, lịch sử gửi, token duyệt email; Zalo OA refresh token; Slack Socket Mode.
- WP-23 exposure + scan.

Mỗi module:
1. Migration có tiền tố bảng theo MANIFEST (`storetest.AssertMigrationsUsePrefix`).
2. Handler cho operation trong `core/api/oas`.
3. `audit.(*Log).Append` trong cùng giao dịch, `apierr` cho lỗi, `server.PrincipalFrom(ctx)`.
4. Test hợp đồng `go test ./modules/<id>/... -run Contract`.
5. Giao diện chuyển từ mock sang API thật (cơ chế WP-05 của Kiên).

Chữ ký thật của core: `modules/core/IMPACT.md`. Thứ core chưa có (events, auth): interface nhỏ phía module + đồ giả trong test, không viết trong `core/`.

## Bẫy kỹ thuật
- Windows gốc: `core/store` (URI SQLite) và `web/scripts/openapi.mjs` hỏng; chỉ dùng WSL.
- pnpm bản độc lập bỏ qua bản native oxlint/rolldown nếu thiếu `node-version` (đã sửa ở `web/.npmrc`, #23).
- Git trong WSL dùng `gh` bên Windows làm credential helper (không chép token).
- vitest toàn bộ có thể timeout giả khi máy đang fuzz/test song song: chạy lại riêng file đỏ lúc máy rảnh.
- Fuzz chạy từng target một; số exec đứng yên khi fuzzer đang thu gọn input là bình thường.
