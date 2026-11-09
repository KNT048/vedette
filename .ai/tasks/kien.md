# Việc của Kiên — đọc cùng docs/TEAM_PLAN.md

Cập nhật: 2026-11-09 (phiên AI lead). Sở hữu: core, host, đóng gói/phát hành, inventory, sensor-passive, sensor-active, response, honeypot, rà bảo mật; **cộng mọi việc chồng lấn/dùng chung (D-65)**.
File này là **file handoff duy nhất** của phiên AI làm việc cho Kiên: sau compact/restart đọc lại trước khi làm tiếp.

## Repo và quy trình (đọc trước)
- Repo `KNT048/vedette` (public, D-63), remote `https://github.com/KNT048/vedette.git`, module Go `github.com/knt048/vedette`.
- Cổng: `make check` trên máy trước khi push (D-62); CI GitHub (go, web) miễn phí, **merge khi CI xanh**; không chờ ai duyệt, PR chạm phần người kia chỉ @ để báo (D-65). E2E chỉ cho tính năng mới, bộ đầy đủ khi gần production (D-64).
- Máy: tối đa 2 việc nặng song song; bộ dọn tiến trình mồ côi chạy 10 phút/lần (`make reaper-install`, log `~/Library/Logs/vedette-orphan-reaper.log`).
- Emily (Mlee) nhường mọi chỗ chồng lấn cho phía Kiên, mở issue `owner:kien` (D-65). Quyết định của Emily: phía Kiên chép vào DECISIONS.

## Đã merge
WP-01 (#7), WP-02 ogen (#11), WP-03 store/secrets/audit/exec (#12), #14 (đổi tham chiếu findings), #18 (hợp đồng core), #19 (make check, CI public, D-62..D-65), #20 (module path), #22 (orphan reaper), #23 (pnpm node-version, issue #21), #24 (findings trong enum module), WP-04a server/registry/jobs (#25), WP-06 giao diện khớp hợp đồng (#26), D-67..D-70 (#27), issue #29 (#31), WP-05 giao diện gọi API thật theo module (#32), issue #33 nối module trong `cmd/vedette` (PR này).

## Nối một module vào binary (issue #33)
`cmd/vedette/modules.go`: thêm một dòng vào `wiredModules()` (id, `Migrations`, `Jobs func(deps) []jobs.Job`), theo thứ tự phụ thuộc (test `TestWiredModulesFollowDependencies`); handler của module nhúng vào struct `handler` trong `handler.go`, dựng từ `deps` (Log, DB, Reg, Secrets, Audit, Clock). Không sửa `main.go` khi thêm module.

## Đang làm
| Việc | Nhánh / worktree | Trạng thái |
|---|---|---|
| WP-04b phần 1: core/auth (argon2id, phiên, CSRF, TOTP chống dùng lại, mã email, giới hạn đăng nhập), core/events, issue #17 (head chuỗi hash, secrets.Value.Last4/IsSet) | `feat/core-auth` (`../vedette-wt/core-auth`) | rà bảo mật (Opus) tìm 12 lỗi (H1 argon2 DoS đồng thời, M1–M5, L1–L6, mã email HMAC); agent đang sửa → `make check`, PR đóng #17, merge khi CI xanh |
| WP-10 inventory (+ `core/observe` Sink cho sensor) | `feat/inventory` (`../vedette-wt/inventory`) | đang làm (Sonnet); sau #33 dùng `wiredModules()` + `deps` |
| Reaper báo issue mới `owner:kien` | `feat/reaper-issues` (`../vedette-wt/reaper-issues`) | xong, chờ PR; sau merge chạy lại `scripts/dev/reaper-install.sh` |

## Kế tiếp (thứ tự TEAM_PLAN §3)
1. WP-04b phần 2: HTTP handler cho /auth/*, /me, /setup, /core/setup, account, users, audit (list/export), general; TLS tự ký trên 8443 + allowlist Host (DNS rebinding); rà bảo mật mô hình mạnh.
2. WP-11 sensor-passive (cần `core/observe`) → giao thức sensor mTLS (WP core riêng, `docs/specs/sensor-protocol.md`) → WP-12 sensor-active → WP-07 host (rà Opus) → WP-13 response (rà Opus), WP-14 honeypot → WP-08 đóng gói → WP-30 E2E backend thật module của Kiên → WP-31 rà bảo mật SYS-1..8 + D-41 → WP-32 RUNBOOK.

## Số quyết định
D-59 khung Go · D-60 ogen · D-61 không Actions (đã thay) · D-62 make check · D-63 repo public + CI · D-64 e2e chỉ tính năng mới · D-65 chồng lấn → Kiên · D-66 tín hiệu ẩn danh ≥ 2 thiết bị · D-67..D-70 quyết định của Emily (notify, feeds, findings, ai) · D-71 thời hạn phiên idle 4 h / tuyệt đối 7 ngày + giới hạn đăng nhập (nhánh core-auth). D-72, D-73 (nhánh inventory: xuất dữ liệu ghi audit; lỗi schema trả `invalid` kèm đường dẫn trường) · D-74 phân vân → top-tier · D-75 mã cài đặt một lần · D-76 bật 2FA nhập lại mật khẩu. Tiếp theo: **D-77**.

## Câu hỏi đang chờ Kiên
- Không có. Từ D-74: phân vân → tham khảo top-tier rồi tự quyết, chỉ hỏi khi rất đặc biệt. B2 đã quyết: có mã cài đặt một lần (D-75); bật 2FA đòi nhập lại mật khẩu (D-76); cả hai làm trong WP-04b phần 2.
- Branch protection `main`: kien "chưa cần".

## Bẫy kỹ thuật đã gặp
- Agent để lại Playwright/Chromium mồ côi khi lệnh hết giờ → máy tải 150–200, test timeout giả. Reaper xử lý; vẫn giới hạn 2 việc nặng.
- vitest dưới tải nặng: `findBy…` timeout hàng loạt; CI là thẩm quyền.
- Bộ kiểm an toàn của Claude Code chặn lệnh Bash gộp có heredoc phức tạp/`$$(…)`: tách lệnh, sửa file bằng công cụ Edit/Write.
- `TestCodesAreCatalogued` (core/apierr) đọc API_CONVENTIONS §3.3: mã mới phải vào bảng, danh sách "proposed" trong test phải rỗng khi đã vào.
- ogen: thao tác tạo trả 201 → tên kiểu Go đổi khi hợp đồng đổi `status`; sinh lại (`make generate-api`) sau mỗi rebase có đổi `api/openapi.json`.
- Chuỗi hash: một công thức D-57 (14), khoá sắp theo code point, NULL giữ `null`; vector `modules/core/testdata/chain_vectors.json`.
- golangci-lint chỉ báo một lỗi mỗi dòng; `bodyclose` không thấy body đóng trong hàm phụ → trả status/header thay vì `*http.Response`.
- Go cục bộ cũ → `go.mod` ghim 1.26.10, go tự tải toolchain. Công cụ dev ở `tools/go.mod`; ogen là `tool` trong `go.mod` chính.
