# Việc của Kiên — đọc cùng docs/TEAM_PLAN.md

Cập nhật: 2026-11-09 tối (phiên AI lead). Sở hữu: core, host, đóng gói/phát hành, inventory, sensor-passive, sensor-active, response, honeypot, rà bảo mật; **cộng mọi việc chồng lấn/dùng chung (D-65)**.
File này là **file handoff duy nhất** của phiên AI làm việc cho Kiên: sau compact/restart đọc lại trước khi làm tiếp.

## Repo và quy trình (đọc trước)
- Repo `KNT048/vedette` (public, D-63), remote `https://github.com/KNT048/vedette.git`, module Go `github.com/knt048/vedette`.
- Cổng: `make check` trên máy trước khi push (D-62); CI GitHub (go, web) miễn phí, **merge khi CI xanh**; không chờ ai duyệt, PR chạm phần người kia chỉ @ để báo (D-65). E2E chỉ cho tính năng mới, bộ đầy đủ khi gần production (D-64).
- Máy: tối đa 2 việc nặng song song; bộ dọn tiến trình mồ côi chạy 10 phút/lần (`make reaper-install`, log `~/Library/Logs/vedette-orphan-reaper.log`).
- Emily (Mlee) nhường mọi chỗ chồng lấn cho phía Kiên, mở issue `owner:kien` (D-65). Quyết định của Emily: phía Kiên chép vào DECISIONS.

## Đã merge
WP-01 (#7), WP-02 ogen (#11), WP-03 store/secrets/audit/exec (#12), #14, #18 (hợp đồng core), #19 (make check, CI, D-62..D-65), #20, #22 (orphan reaper), #23, #24, WP-04a server/registry/jobs (#25), WP-06 (#26), D-67..D-70 (#27), #31, WP-05 (#32), #34 (nối module, issue #33), #35 (reaper báo issue), WP-04b phần 1 core/auth + events (#36, đóng #17), D-74..D-76 (#37), WP-10 inventory (#40), giới hạn thân theo thao tác (#41), #45 (đóng #43), `deps.Bus` + inventory dùng chung (#47), #48, giám sát WP-23 (#49), D-81/D-82 (#51, #53), WP-07a khung vedette-host (#52), #54 (gỡ binary lỡ commit), nối inventory/feeds/findings/mitigation qua cổng và bus + D-78 (#56, issue #38, #39), WP-11 sensor-passive + D-80/D-83 (#57), WP-04b phần 2 = **xong đường găng** (#58), D-86 + bảng notify (#63), D-79/D-81 (#65), WP-12 sensor-active + D-84 (#66), WP-07b phần 1 lệnh OS/sao lưu/xuất log của vedette-host + D-85/D-87 (#67), auth + handler core dựng trong `buildServices` (#68), nối notify/sensor-active lần 2 (#69), #71 (đóng #70), WP-14 honeypot + D-89/D-90 (#72), WP-13a response phần 1 + D-88 (#74), D-91 KEV dự phòng (#75), `exectest.WriteScript` (#76), WP-07b phần 2 cập nhật OS + tải bản sao lưu (#77). Của Emily: #42, #44, #46, #55, #59, notify WP-22 (#60).

## Nối một module vào binary (issue #33)
`cmd/vedette/modules.go`: một dòng trong `wiredModules()` (id, `Migrations`, `Jobs func(deps) []jobs.Job`, `BodyLimits`), theo thứ tự phụ thuộc (`TestWiredModulesFollowDependencies`); handler nhúng vào struct `handler` trong `handler.go`; dịch vụ module dựng **một lần** trong `buildServices` (`cmd/vedette/wiring.go`) và đặt vào `deps`; adapter giữa module nằm trong `cmd/vedette` (module không import nhau); sự kiện qua `deps.Bus`, handler chỉ chạy khi module bật. `TestNewHandlerSetsEveryModule` bắt handler nhúng bị nil.

## Đang làm (2026-11-09 khuya)
| Việc | PR / worktree | Trạng thái |
|---|---|---|
| Sửa CI đỏ trên main: honeypot dừng êm khi core tắt lúc khởi động; test FIFO không còn ghi đầy đĩa (issue #79) | PR #81, `../vedette-wt/fix-hp` | chờ CI rồi merge |
| D-92 bỏ feed SSLBL, tiêu chí S-FEED-1 "chưa tải được KEV", DATA_MODEL `feeds_source.answered_by` (issue #79) | `docs/feeds-79` | PR tài liệu; Emily làm phần mã |

## Kế tiếp (thứ tự TEAM_PLAN §3)
1. Issue #78 (QA của Emily trên core): `GET/PATCH /core/privacy` dùng chung khoá `core_privacy.update_check` với #77; GUI 501 không gợi ý "Restore sample data" trên hộp thật; `/setup` đăng nhập luôn admin; mật khẩu tạm từ `POST /core/users` bị từ chối lúc đăng nhập đầu (tái hiện bằng test trước); `dev-api` giữ mock cho module không có trong `REAL`.
2. WP-13b (response phần 2), 12 lát, tài liệu trước (13b-0, D-93..D-98): kết nối thiết bị chuyển về core (`core/conn`, Cài đặt → Kết nối, chạy được khi `ai` tắt), HTTPS/SSH/MCP không mã riêng hãng, kiểm trước + đọc lại là dữ liệu, kênh duyệt (link, chat, mã trả lời), AI là định danh dịch vụ trong tiến trình, `VerifyTwoStep`. Đích công cộng được phép khi admin tự khai + PRIVACY luồng 12 "Connections you add" (tham khảo Tines, n8n, Cortex XSOAR, Home Assistant). Thứ tự: 13b-0 → 13b-1 → 13b-4 → 13b-5 → 13b-6; song song 13b-2, 13b-3 → 13b-9 → 13b-10, 13b-7, 13b-8; 13b-11 sau WP-25 của Emily.
3. WP-07b phần 3: `net.*` + `decoy_ip.*` (D-56), `container.*` (manifest ký).
4. Giao thức sensor mTLS (đưa capture/nmap ra khỏi tiến trình core) → WP-08 đóng gói (Quadlet `Restart=always`, `KillMode=control-group`, `core_cgroup`, `core_data`, TZ + `time/tzdata`, GOMEMLIMIT) → WP-30 E2E backend thật → WP-31 rà SYS-1..8 + D-41 → WP-32 RUNBOOK.

## Số quyết định
… D-74 phân vân → top-tier · D-75 mã cài đặt một lần (sửa 2026-11-09: đếm theo địa chỉ client) · D-76 bật 2FA nhập lại mật khẩu · D-77 cookie thiết bị · D-78 đường cơ sở KEV · D-79 exposure: tự dò IP, kiểm lúc quét, danh sách bỏ qua · D-80 sensor-passive · D-81 không máy chủ dự án ngoài GitHub · D-82 không gửi tín hiệu ẩn danh · D-83 bảng OUI · D-84 sensor-active · D-85 lệnh OS của host · D-86 notify (Emily) · D-87 host chỉ chép byte, không đọc dữ liệu core · D-88 response phần 1 · D-89 hit honeypot qua tệp JSON-lines · D-90 honeypot · D-91 KEV dự phòng từ GitHub của CISA · D-92 bỏ feed SSLBL. Tiếp theo: **D-93** (WP-13b dùng D-93..D-98).

## Giám sát WP-23: tự phát hiện IP công cộng (việc của Emily, phía Kiên chỉ giám sát)
kien 2026-11-09 (đã chuyển cho Emily): "tôi muốn box có thêm chế độ tự detect ip public để bỏ vào kho. ví dụ KH có nhiều ip public và load balance, chỉ cần bật chế độ tự detect là được, trong 1 số trường hợp, khách hàng muốn chủ động detect thì manual cũng ok. tự detect lần đầu lúc mới cài, 60p 1 lần recheck, cho KH sửa nếu muốn. kho ip public cho phép sử dụng cũng expire time 30 ngày thay cho 90 ngày hiện tại. nhưng chỉ trong trường hợp không renew được mới phải chạy". Phía Kiên **không chủ động làm**; khi PR của Emily tới, kiểm:
- [ ] Hai chế độ: tự động (chạy ngay khi cài/bật module, rồi 60 phút một lần) và thủ công (chỉ khi bấm); đổi chế độ chỉ admin, có audit.
- [ ] Nhiều IP sau load balancer/nhiều WAN được phát hiện (một lần dò mở nhiều kết nối mới, ghi mọi IP thấy được).
- [ ] Vẫn không cho gõ IP tay (D-25, FORBID-2); vẫn từ chối IP riêng/dành riêng/CGNAT (INV-3).
- [ ] Hiệu lực 30 ngày tính từ lần thấy cuối; mỗi lần thấy lại tự gia hạn; chỉ hết hạn khi 30 ngày không gia hạn được; IP hết hạn không quét được (INV-1).
- [ ] Khách sửa được danh sách, có audit, và lần dò sau không phá lựa chọn đó một cách bất ngờ. kien bổ sung 2026-11-09: "khách sửa được thời gian check, ví dụ 1p, 5p, 10p tối đa 24h 1 lần. khách xoá được public ip đã lấy":
  - [ ] Chu kỳ kiểm lại do khách chọn, từ 1 phút tới tối đa 24 giờ (ví dụ 1, 5, 10, 15, 30 phút, 1, 6, 12, 24 giờ; mặc định 60 phút), chỉ admin, có audit; ngoài khoảng → 400.
  - [ ] Xoá được từng IP đã lấy (admin, có audit).
  - [ ] Giới hạn 10 lần/giờ của INV-5 không chặn lịch tự động ngắn (tách lần chạy theo lịch khỏi lần bấm tay).
  - [ ] Dò IP theo **D-81**: không endpoint của dự án; HTTPS tới `checkip.amazonaws.com`, `icanhazip.com`, `api.ipify.org`, nhận IP khi ≥ 2 dịch vụ trùng; tìm IP sau load balancer bằng nhiều kết nối mới mỗi lần dò. Lịch ngắn (1 phút) vẫn nên nhẹ: ở chu kỳ ngắn mỗi dịch vụ một kết nối, lượt dò nhiều kết nối tối đa mỗi giờ một lần (lịch sự với dịch vụ miễn phí của người khác, tránh bị chặn).
- [ ] Đi đúng thứ tự GUI trước: story S-EXP-1 cập nhật, `contract.ts` + mock + màn hình trước backend; CONTRACT/IMPACT/DATA_MODEL cập nhật; e2e cho tính năng mới (D-64).
- [ ] Pháp lý: PRIVACY luồng 9 + chữ ở Settings → Privacy ghi tần suất mới (60 phút, nhiều kết nối mỗi lần) cùng commit (rules/legal.md).
- [ ] Quyết định ghi vào DECISIONS (số **D-79** để dành cho việc này).

## Trước khi phát hành (đợt rà WP-31/WP-32)
- [ ] D-82: tín hiệu ẩn danh không được gửi (không có bộ gửi, không có nơi nhận). PRIVACY luồng 2 và mục "Anonymous signal" ở Cài đặt → Quyền riêng tư phải khớp thực tế lúc phát hành (dùng lại theo story mới, hoặc ẩn/ghi "không gửi").

- [ ] D-81: ba dịch vụ dò IP công cộng (`checkip.amazonaws.com`, `icanhazip.com`, `ifconfig.me/ip`) vẫn thuộc ba nhà vận hành khác nhau: tra DNS/AS mỗi lần phát hành.

## Câu hỏi đang chờ Kiên
- Không có. Từ D-74: phân vân → tham khảo top-tier rồi tự quyết, chỉ hỏi khi rất đặc biệt. B2 đã quyết: có mã cài đặt một lần (D-75); bật 2FA đòi nhập lại mật khẩu (D-76); cả hai làm trong WP-04b phần 2.
- Branch protection `main`: kien "chưa cần".

## Bẫy kỹ thuật đã gặp
- Agent để lại Playwright/Chromium mồ côi khi lệnh hết giờ → máy tải 150–200, test timeout giả. Reaper xử lý; vẫn giới hạn 2 việc nặng.
- vitest dưới tải nặng: `findBy…` timeout hàng loạt; CI là thẩm quyền.
- Đừng `go build ./cmd/vedette` ở gốc repo (sinh `./vedette`, từng lỡ commit ở #47); dùng `go vet`/`go build -o /dev/null`, xem `git status` trước `git add -A`.
- Nhánh đã push: merge `origin/main` vào, không rebase (force-push bị chặn).
- `gh pr checks --watch` trả về ngay khi check chưa đăng ký: lặp tới khi có check rồi mới watch.
- Tệp `*_linux.go` không được lint trên macOS: `GOOS=linux $(go tool -n -modfile=tools/go.mod golangci-lint) run ./pkg/...` (CI lint trên Linux).
- Test đo thời gian thực hỏng khi máy tải cao: chặn dưới theo thời gian (tải chỉ làm chậm hơn), không chặn trên.
- Bộ kiểm an toàn của Claude Code chặn lệnh Bash gộp có heredoc phức tạp/`$$(…)`: tách lệnh, sửa file bằng công cụ Edit/Write.
- `TestCodesAreCatalogued` (core/apierr) đọc API_CONVENTIONS §3.3: mã mới phải vào bảng, danh sách "proposed" trong test phải rỗng khi đã vào.
- ogen: thao tác tạo trả 201 → tên kiểu Go đổi khi hợp đồng đổi `status`; sinh lại (`make generate-api`) sau mỗi rebase có đổi `api/openapi.json`.
- Chuỗi hash: một công thức D-57 (14), khoá sắp theo code point, NULL giữ `null`; vector `modules/core/testdata/chain_vectors.json`.
- golangci-lint chỉ báo một lỗi mỗi dòng; `bodyclose` không thấy body đóng trong hàm phụ → trả status/header thay vì `*http.Response`.
- Go cục bộ cũ → `go.mod` ghim 1.26.10, go tự tải toolchain. Công cụ dev ở `tools/go.mod`; ogen là `tool` trong `go.mod` chính.
