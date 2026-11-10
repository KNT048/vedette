# Việc của Kiên — đọc cùng docs/TEAM_PLAN.md

Cập nhật: 2026-11-10 chiều (phiên AI lead; `origin/main` = 6389e36). Sở hữu: core, host, đóng gói/phát hành, inventory, sensor-passive, sensor-active, response, honeypot, rà bảo mật; **cộng mọi việc chồng lấn/dùng chung (D-65)**.
File này là **file handoff duy nhất** của phiên AI làm việc cho Kiên: sau compact/restart đọc lại trước khi làm tiếp. Bản sao trạng thái sống của lead (brief, worktree, job chờ merge) ở `../vedette-wt/LEAD-STATE.md` trên máy Kiên; file này là bản trong repo.

## Repo và quy trình (đọc trước)
- Repo `KNT048/vedette` (public, D-63), remote `https://github.com/KNT048/vedette.git`, module Go `github.com/knt048/vedette`.
- Cổng: `make check` trên máy trước khi push (D-62); CI GitHub (go, web) miễn phí, **merge khi CI xanh**; không chờ ai duyệt, PR chạm phần người kia chỉ @ để báo (D-65). E2E chỉ cho tính năng mới, bộ đầy đủ khi gần production (D-64).
- Máy: tối đa 2 việc nặng song song (agent chờ khi `load5` > 12); bộ dọn tiến trình mồ côi chạy 10 phút/lần (`make reaper-install`, log `~/Library/Logs/vedette-orphan-reaper.log`).
- Emily (Mlee) nhường mọi chỗ chồng lấn cho phía Kiên, mở issue `owner:kien` (D-65). Quyết định của Emily: phía Kiên chép vào DECISIONS (ví dụ D-86, D-92, D-128, D-129, D-131, D-134).
- **Cách làm mỗi lát việc:** Sonnet làm (brief riêng) → Opus rà độc lập (bắt buộc cho core/auth, host, response, sensor) → sửa theo review → PR → merge-step. Merge-step (`../vedette-wt/merge-step.sh <pr> <worktree>…`) gộp `origin/main` vào nhánh, tự giải xung đột chỉ ở DECISIONS, chờ CI, đòi `go:pass` + `web:pass`, thử lại tối đa 3 lần nếu `main` đổi trong lúc chờ, rồi kiểm trạng thái `MERGED`. Sau merge: `git worktree remove` thư mục worktree.
- Quyết định mới: D-74 (phân vân → top-tier, ghi D-xx kèm nguồn, chỉ hỏi kien khi rất đặc biệt).

## Trạng thái từng WP của Kiên (TEAM_PLAN §2/§3)
| WP | Trạng thái | PR / ghi chú |
|---|---|---|
| WP-01 khung Go, WP-02 ogen, WP-03 store/secrets/audit/exec | **xong** | #7, #11, #12 |
| WP-04 core/auth + registry + jobs (**đường găng**) | **xong** | #25 (04a), #36 (04b phần 1), #58 (04b phần 2) |
| WP-05 dev env, WP-06 giao diện khớp hợp đồng | **xong** | #32, #26 |
| WP-10 inventory | **xong** | #40; `VulnScanPolicy` #119 (D-126) |
| WP-11 sensor-passive | **xong** | #57 (D-80, D-83); tách capture sang `vedette-sensor passive` qua mTLS #130 (SP-4, D-122) |
| WP-12 sensor-active | **xong** | #66 (D-84); nmap từ xa qua mTLS #117 (SP-3, D-113) |
| WP-14 honeypot | **xong** | #72 (D-89, D-90) |
| WP-13 response | 13a **xong** (#74, D-88); 13b lát 0–7, 9, 10 **xong**; 13b-8 (duyệt qua chat) đang sửa theo review; 13b-11 chờ WP-25 của Emily | **đường găng 13b xong** (#105: đẩy cấu hình lên thiết bị chạy được khi AI tắt); #84, #88, #92, #96, #97, #101, #105, #109, #110, #113, #128 |
| WP-07 host (`vedette-host`) | 07a khung #52; 07b phần 1 #67; phần 2 #77; phần 3 lát 0–6 **xong**; lát 7 `container.pull` = PR #140 chờ merge; lát 8 chưa làm | #95, #99, #102, #104, #107, #112, #125; D-85, D-87, D-99..D-107, D-120, D-121, D-123 |
| Giao thức sensor mTLS (SP-0…SP-4) | **xong**; SP-3b, SP-5, SP-6 chưa làm | #103, #106, #108, #117, #130; D-109..D-116, D-122 |
| Core: Box network (S-CORE-8), conn read, logs export, OS updates | network #111 (D-118), conn read #126 (D-127), OS updates #77 xong; **logs export = PR #137 chờ merge** (D-132) | |
| WP-08 đóng gói/phát hành | chưa làm | cần khoá phát hành và VM lab (xem "Cần kien"); chặn bởi healthcheck + host 3-8 |
| WP-30 E2E backend thật | chưa làm | nhánh `fix/e2e-baseline` (a07a3c2) còn trên origin; dựng lại worktree lúc bắt đầu; cần đo 6 spec lỗi của `inventory.spec` (chọn card mạng, cài sạch, dải) trên main |
| WP-31 rà SYS-1…8 + D-41, WP-32 RUNBOOK | chưa làm | |

## PR đang mở (2026-11-10)
| PR | Của ai | Nội dung | Trạng thái |
|---|---|---|---|
| #137 | Kiên | `GET /core/logs/export`, registry nguồn, chuỗi kiểm được ngoại tuyến, spool có giới hạn (S-CORE-6, #114, D-132) | job merge đang chờ; thứ tự: #137 → #139 → #140 |
| #139 | Kiên | docs D-136 gói lá nuclei của scan (cho #138 của Emily) | chờ sau #137 |
| #140 | Kiên | host `container.pull`: kiểm index, manifest và cosign rồi mới kéo digest ghim (lát 3-7, D-130) | chờ sau #139 |
| #138 | Emily | scan S2: nuclei argv, JSONL, gói template (WP-23 phần 2) | Emily giữ để sửa theo review của chính cô; SP-3b chờ PR này |
| #123 | Emily | `ai` lát 1: profile, khoá, gán, token (WP-25, S-AI-1; D-129 đã vào main) | Emily giữ để sửa; yêu cầu của Kiên: lỗi `newAI` khi dựng không được làm hộp dừng |
| #141 | Emily | docs: handoff của Emily sau đợt merge giai đoạn 1 | không có gì cho phía Kiên |

Worktree còn mở (trên máy Kiên): `resp-chat` (13b-8, nhánh `feat/response-chat`, 8c781b2; agent đang sửa review: bảng giới hạn tốc độ riêng cho chat, ghi từ chối một lần mỗi cửa sổ, tách Decide khỏi vòng chạy, các mục L1-L7, test còn thiếu), `logexport`, `docs-d136`, `host-pull`. Khi 13b-8 xong: đẩy, mở PR, báo Emily (listener, nonce Telegram, `notify_approver` UNIQUE, địa chỉ Zalo = user ID), merge-step.

## Việc chờ Emily (đã báo trên issue/PR; không chặn phía Kiên)
- **#123** (ai) và **#138** (scan S2) như trên; sau khi #138 vào main thì phía Kiên mới làm SP-3b.
- Đăng ký danh mục xuất log: `d.Logs.Register("ai_activity", ai.ExportActivity)` trong `cmd/vedette/logexport.go` (sau #137; Emily, issue #114).
- `ai` nối với `core/conn/read` (D-127): luồng PRIVACY 3 (dữ liệu thiết bị chỉ tới profile AI nội bộ, `ai_activity` ghi `connection_id`) và hook `block-pii` phủ thêm mật khẩu type-7, hash, community SNMP, khoá chia sẻ trước (`feat-conn-read.md`).
- Chưa nối trong `cmd/vedette`: `Findings` của notify đã nối (#120); còn `Tokens` (record token của response, WP-13), `honeypot.hit.created` (honeypot đã phát; notify đăng ký đúng tên), `Config.BoxAddrs` (WP-08). Issue #62 đã trả lời, phần còn mở là các mục này.
- Phát hành sự kiện `logs.anomaly.detected`, `logs.bad_address.detected` (module `logs` của Emily), thấm khoá URL webhook (SYS-4), làm mới token Zalo OA, nhịp xoá `notify_send/incident/notice`, GUI notify chuyển mock → API thật: các dòng còn lại trong `.ai/deferred/feat-notify-module.md`.
- Mục tiêu ngoài (`exposure.Runner`) của scan: gói nhỏ riêng về sau (D-131).
- Xem thêm các dòng `.ai/deferred/*.md` của nhánh phía Kiên (feat-core-network, feat-core-os-updates, feat-sensor-active, feat-sensor-protocol, feat-host-net-containers, feat-response-13b, feat-conn-read).

## Cần kien (chưa chặn; chặn WP-08 và phần thật của host lát 3-8)
- **Khoá ký phát hành offline:** minisign chính, minisign dự phòng, cosign. Phần riêng không vào repo hay hộp (D-103, D-108).
- **Máy ảo lab:** Ubuntu 24.04, Ubuntu 26.04, Debian 13: để kiểm hộp thật (Box network qua reboot trong cửa sổ xác nhận, Quadlet, nmap, SPAN, các việc `*_linux.go` chưa chạy trên máy thật).
- Quyết định **chứng chỉ TLS**: chứng chỉ tự ký không có IP quản trị mới trong SAN sau khi đổi địa chỉ (ghi trong `feat-core-network.md`); cần chọn làm mới chứng chỉ tự ký khi địa chỉ đổi hay chỉ hỗ trợ chứng chỉ riêng của chủ hộp.
- AI thật khi thử: chỉ chạy trên máy kien với `VEDETTE_LIVE_AI=1`, khoá do kien cấp cho đúng một tiến trình test; không bao giờ trên CI, không ghi khoá vào repo hay log.

## Kế tiếp (theo thứ tự)
1. Merge #137 → #139 → #140; gỡ worktree tương ứng.
2. Xong 13b-8 (`resp-chat`): PR + merge.
3. **Healthcheck subcommands** cho `core`, `sensor`, `honeypot` (D-137, brief `../vedette-wt/healthcmd-brief.md`, worktree `healthcmd`, nhánh `feat/healthcmd`). Là cổng trước host 3-8 và WP-08: hiện `cmd/` chưa có lệnh này nên mọi `container.start` sẽ tự rollback.
4. **Host 3-8:** `container.start(version)`/rollback/giữ bản cũ (retention)/CLI bootstrap (kế hoạch `../vedette-wt/wp07b3-plan.md`; viết brief sau khi #140 merge). `container.start` 5 phút, `TimeoutStartSec` 16 phút.
5. **SP-3b:** kiểu job `nuclei` trên giao thức sensor (D-133 để dành, issue #115; brief `../vedette-wt/sp3b-brief.md`, worktree `sp-nuclei`, nhánh `feat/sensor-nuclei`) sau khi #138 merge.
6. **SP-5** đóng gói sensor (image scan-base ghim nuclei, gói template qua make, `manifest bundled[]`), **SP-6** unit host cho sensor (sau 3-7/3-8).
7. **WP-08** đóng gói/phát hành (Quadlet: `Restart=always`, `KillMode=control-group`, `core_cgroup` trong `host.conf`, `GOMEMLIMIT` cho core; bản build phát hành không mang mock, xem mục "Trước khi phát hành").
8. **WP-30** E2E backend thật cho module phía Kiên → **WP-31** rà SYS-1…8 + D-41 → **WP-32** RUNBOOK.
9. **13b-11** sau WP-25 của Emily. Core còn: `/core/updates*` phần phần mềm (`container.*`, manifest ký) vẫn 501, `/core/data/export` và `/purge`, nút Khôi phục.
10. Việc sau khi PR Emily về: DATA_MODEL `exp_*` đã vào (#94); kiểm danh mục WP-23 ở dưới khi có PR mới.

## Nối một module vào binary (issue #33)
`cmd/vedette/modules.go`: một dòng trong `wiredModules()` (id, `Migrations`, `Jobs func(deps) []jobs.Job`, `BodyLimits`), theo thứ tự phụ thuộc (`TestWiredModulesFollowDependencies`); handler nhúng vào struct `handler` trong `handler.go`; dịch vụ module dựng **một lần** trong `buildServices` (`cmd/vedette/wiring.go`) và đặt vào `deps`; adapter giữa module nằm trong `cmd/vedette` (module không import nhau); sự kiện qua `deps.Bus`, handler chỉ chạy khi module bật. `TestNewHandlerSetsEveryModule` bắt handler nhúng bị nil.

## Số quyết định
Đã dùng tới **D-137** (đặt chỗ). **Số trống kế tiếp: D-138.** Trên `main` có D-1…D-129, D-131, D-134. Chưa lên main: D-130 (host pull, #140), D-132 (logs export, #137), D-136 (scan S2, #139) nằm trong PR đang mở; D-133 (SP-3b), D-135 (13b-8 chat), D-137 (healthcheck) đặt chỗ cho nhánh chưa mở PR. Đo số cao nhất trên `main` và trong PR mở trước khi thêm.
Nhóm gần đây: D-71 thời hạn phiên · D-74 phân vân → top-tier · D-75 mã cài đặt · D-76 2FA nhập lại mật khẩu · D-77 cookie thiết bị · D-78 đường cơ sở KEV · D-79 exposure tự dò IP · D-80 sensor-passive · D-81 không máy chủ dự án ngoài GitHub · D-82 không gửi tín hiệu ẩn danh · D-83 bảng OUI · D-84 sensor-active · D-85 lệnh OS của host · D-86 notify · D-87 host chỉ chép byte · D-88 response phần 1 · D-89/D-90 honeypot · D-91 KEV dự phòng GitHub · D-92 bỏ SSLBL · D-93..D-98 kết nối thuộc core, transport chung, kiểm trước/đọc lại là dữ liệu, kênh duyệt, AI là định danh dịch vụ, `VerifyTwoStep` · D-99..D-107 host mạng/mồi/container/ký/pull/Quadlet/chrony/test không root · D-108 giữ index schema cũ 12 tháng · D-109..D-116 giao thức sensor · D-117 bộ ghi thiết bị (13b lát 6) · D-118 Box network (cửa sổ xác nhận 300 s) · D-119 AI đề xuất qua `Propose` · D-120/D-121 mồi IP · D-122 sensor-passive tách capture · D-123 Quadlet host · D-124 link duyệt qua email · D-125 nuclei là binary ghim, D-126 chính sách quét lỗ hổng · D-127 reader chỉ đọc cho AI · D-128 notify thông báo lỗ hổng · D-129 ai lát 1 · D-130 host pull · D-131 scan S0 · D-132 xuất log · D-134 feeds · D-136 scan S2.

## Giám sát WP-23: tự phát hiện IP công cộng (việc của Emily, phía Kiên chỉ giám sát)
**Đã merge (#91, D-79, D-81).** Danh mục dưới giữ để đối chiếu khi Emily sửa tiếp.
kien 2026-11-09 (đã chuyển cho Emily): "tôi muốn box có thêm chế độ tự detect ip public để bỏ vào kho. ví dụ KH có nhiều ip public và load balance, chỉ cần bật chế độ tự detect là được, trong 1 số trường hợp, khách hàng muốn chủ động detect thì manual cũng ok. tự detect lần đầu lúc mới cài, 60p 1 lần recheck, cho KH sửa nếu muốn. kho ip public cho phép sử dụng cũng expire time 30 ngày thay cho 90 ngày hiện tại. nhưng chỉ trong trường hợp không renew được mới phải chạy". Phía Kiên **không chủ động làm**; khi PR của Emily tới, kiểm:
- [ ] Hai chế độ: tự động (chạy ngay khi cài/bật module, rồi 60 phút một lần) và thủ công (chỉ khi bấm); đổi chế độ chỉ admin, có audit.
- [ ] Nhiều IP sau load balancer/nhiều WAN được phát hiện (một lần dò mở nhiều kết nối mới, ghi mọi IP thấy được).
- [ ] Vẫn không cho gõ IP tay (D-25, FORBID-2); vẫn từ chối IP riêng/dành riêng/CGNAT (INV-3).
- [ ] Hiệu lực 30 ngày tính từ lần thấy cuối; mỗi lần thấy lại tự gia hạn; chỉ hết hạn khi 30 ngày không gia hạn được; IP hết hạn không quét được (INV-1).
- [ ] Khách sửa được danh sách, có audit, và lần dò sau không phá lựa chọn đó một cách bất ngờ. kien bổ sung 2026-11-09: "khách sửa được thời gian check, ví dụ 1p, 5p, 10p tối đa 24h 1 lần. khách xoá được public ip đã lấy":
  - [ ] Chu kỳ kiểm lại do khách chọn, từ 1 phút tới tối đa 24 giờ (ví dụ 1, 5, 10, 15, 30 phút, 1, 6, 12, 24 giờ; mặc định 60 phút), chỉ admin, có audit; ngoài khoảng → 400.
  - [ ] Xoá được từng IP đã lấy (admin, có audit).
  - [ ] Giới hạn 10 lần/giờ của INV-5 không chặn lịch tự động ngắn (tách lần chạy theo lịch khỏi lần bấm tay).
  - [ ] Dò IP theo **D-81**: không endpoint của dự án; HTTPS tới `checkip.amazonaws.com`, `icanhazip.com`, `ifconfig.me/ip`, nhận IP khi ≥ 2 dịch vụ trùng; tìm IP sau load balancer bằng nhiều kết nối mới mỗi lần dò. Lịch ngắn (1 phút) vẫn nên nhẹ: ở chu kỳ ngắn mỗi dịch vụ một kết nối, lượt dò nhiều kết nối tối đa mỗi giờ một lần (lịch sự với dịch vụ miễn phí của người khác, tránh bị chặn).
- [ ] Đi đúng thứ tự GUI trước: story S-EXP-1 cập nhật, `contract.ts` + mock + màn hình trước backend; CONTRACT/IMPACT/DATA_MODEL cập nhật; e2e cho tính năng mới (D-64).
- [ ] Pháp lý: PRIVACY luồng 9 + chữ ở Settings → Privacy ghi tần suất mới (60 phút, nhiều kết nối mỗi lần) cùng commit (rules/legal.md).
- [ ] Quyết định ghi vào DECISIONS (D-79).

## Trước khi phát hành (đợt rà WP-31/WP-32)
- [ ] D-108: mỗi lần tăng `schema` của `index.json`/manifest, job phát hành **vẫn đăng index của schema trước** cạnh bản mới (ví dụ `index.v1.json`) ít nhất 12 tháng, để hộp cũ nhận được thu hồi (update-manifest §14); và ký image bằng `cosign sign --key … <kho>@<digest>` đúng như update-manifest §4.2 (docker-reference = kho). Payload cosign thật dùng khoá chữ thường `docker-manifest-digest` (D-103).

- [ ] D-82: tín hiệu ẩn danh không được gửi (không có bộ gửi, không có nơi nhận). PRIVACY luồng 2 và mục "Anonymous signal" ở Cài đặt → Quyền riêng tư phải khớp thực tế lúc phát hành (dùng lại theo story mới, hoặc ẩn/ghi "không gửi").

- [ ] D-81: ba dịch vụ dò IP công cộng (`checkip.amazonaws.com`, `icanhazip.com`, `ifconfig.me/ip`) vẫn thuộc ba nhà vận hành khác nhau: tra DNS/AS mỗi lần phát hành.

- [ ] WP-08: bản build phát hành (`VITE_API_MOCK=off`) không mang lớp mock: bước build fail nếu chunk JS nào chứa `[MSW]` hoặc `mswjs`, và không ship `web/public/mockServiceWorker.js` (vite chép nguyên `public/`). #86 đã tách mock khỏi bản build; cần bước kiểm tự động ở WP-08.

- [ ] PRIVACY luồng 6 (`ghcr.io`, host kéo image) đã thêm cùng #140; luồng 12 (kết nối thiết bị) từ #92.

## Câu hỏi đang chờ Kiên
- Không có ngoài mục "Cần kien" ở trên. Từ D-74: phân vân → tham khảo top-tier rồi tự quyết, chỉ hỏi khi rất đặc biệt. Branch protection `main`: kien "chưa cần".

## Bẫy kỹ thuật đã gặp
- Agent để lại Playwright/Chromium mồ côi khi lệnh hết giờ → máy tải 150–200, test timeout giả. Reaper xử lý; vẫn giới hạn 2 việc nặng.
- vitest dưới tải nặng: `findBy…` timeout hàng loạt; CI là thẩm quyền.
- Đừng `go build ./cmd/vedette` ở gốc repo (sinh `./vedette`, từng lỡ commit ở #47, gỡ ở #54); dùng `go vet`/`go build -o /dev/null`, xem `git status` trước `git add -A`.
- Nhánh đã push: merge `origin/main` vào, không rebase (force-push bị chặn).
- `gh pr checks --watch` trả về ngay khi check chưa đăng ký: lặp tới khi có check rồi mới watch; kiểm `headRefOid` sau merge.
- Người chờ không được `pgrep -f "merge-step.sh N"` (khớp chính dòng lệnh của mình, không bao giờ thoát): chờ bằng `gh pr view N --json state`.
- Tệp `*_linux.go` không được lint trên macOS: `GOOS=linux $(go tool -n -modfile=tools/go.mod golangci-lint) run ./pkg/...` (CI lint trên Linux; #57 từng đỏ vì gosec G103/G115).
- Runner CI là UTC: test cửa sổ giờ dùng múi giờ tường minh, không `time.Local`; chạy `TZ=UTC go test …` trước khi push thay đổi liên quan giờ.
- Thư mục tạm của CI nằm dưới `/tmp` sticky ghi được toàn cục: code từ chối cha như vậy cần điểm cắm cho test (host: `Deps.ChainTop`); tái hiện cục bộ bằng `TMPDIR=/private/tmp`.
- Test ghi script rồi exec ngay gây ETXTBSY trên Linux: ghi chương trình giả bằng `core/exec/exectest.WriteScript` (giữ `syscall.ForkLock`).
- Hai PR đụng chung dây nối, mỗi cái xanh riêng, có thể làm `main` đỏ (#57 + #58): trước merge kiểm `git merge-base --is-ancestor origin/main <head>`; không thì gộp `main` và chờ CI lại.
- Test đo thời gian thực hỏng khi máy tải cao: chặn dưới theo thời gian, không chặn trên; sự kiện phải lưu trước khi phát (host `enterAwaiting`, #122).
- Alias `ls` của kien là `eza` và làm treo shell của agent (zsh + eza mồ côi 14–48 phút): brief ghi dùng `/bin/ls`; giết các tiến trình treo.
- Bộ kiểm an toàn của Claude Code chặn lệnh Bash gộp có heredoc phức tạp/`$$(…)`: tách lệnh, sửa file bằng công cụ Edit/Write.
- `TestCodesAreCatalogued` (core/apierr) đọc API_CONVENTIONS §3.3: mã mới phải vào bảng, danh sách "proposed" trong test phải rỗng khi đã vào.
- ogen: thao tác tạo trả 201 → tên kiểu Go đổi khi hợp đồng đổi `status`; sinh lại (`make generate-api`) sau mỗi rebase có đổi `api/openapi.json`.
- Chuỗi hash: một công thức D-57 (14), khoá sắp theo code point, NULL giữ `null`; vector `modules/core/testdata/chain_vectors.json`.
- golangci-lint chỉ báo một lỗi mỗi dòng; `bodyclose` không thấy body đóng trong hàm phụ → trả status/header thay vì `*http.Response`.
- Go cục bộ cũ → `go.mod` ghim 1.26.10, go tự tải toolchain. Công cụ dev ở `tools/go.mod`; ogen là `tool` trong `go.mod` chính.
- Merge đua với PR của người kia: bị lệch `DECISIONS.md` (hai bên cùng thêm D-xx) thì merge-step tự giải; xung đột `openapi`/`oas` của hai PR hợp đồng thì PR sau chạy `make generate`.
