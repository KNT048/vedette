# Bàn giao phần việc của Kiên — 2026-11-10

Người nhận: anh Trưởng, làm tiếp phần của Kiên bằng Claude Code. Kien (`@kiennt048`) vẫn là chủ dự án. Emily / Mlee (`@kiennt049`) vẫn làm phần của Emily.

**Đích:** mọi WP của Kiên đã merge, và E2E chạy xanh trên backend thật cho các module của Kiên (TEAM_PLAN §2/§3).

## 1. Đọc theo thứ tự
1. `CLAUDE.md` và `.claude/rules/*`. Đây là luật cứng; đặc biệt `agent-safety`, `security`, `local-checks` và `decide-like-top-tier` (D-74).
2. `.ai/tasks/kien.md`:
   - trạng thái từng WP;
   - các PR đang mở;
   - việc chờ Emily, việc chờ kien;
   - số D-xx đã dùng;
   - các bẫy đã gặp.
3. `.ai/tasks/current.md`, `docs/TEAM_PLAN.md` §2/§3, và `docs/project-map/lessons.md` (các dòng 2026-11-10).
4. File này: điểm bắt đầu, danh sách việc theo thứ tự, công cụ.

## 2. Đã xong tới đâu (đo trên `origin/main` lúc bàn giao; mục đã gạch ở §3 là xong sau đó)
Phần Kiên ước khoảng **75%**. Danh sách PR chi tiết nằm trong `docs/project-map/completion-log.md`.

**Đã xong:**
- WP-01…06, WP-10, WP-11, WP-12, WP-14;
- WP-04: đường găng;
- WP-13: 13a, cùng 13b lát 0–7, 9, 10. Đường găng 13b đã xong: đẩy cấu hình lên thiết bị chạy được khi AI tắt;
- WP-07: host 07a, 07b phần 1–2, phần 3 lát 0–6;
- giao thức sensor mTLS SP-0…SP-4;
- core: network (S-CORE-8), bộ đọc `core/conn/read` cho AI, xuất log (#137), OS updates.

**Đang bay lúc bàn giao (nay đã merge hết: #139, #140, #142, #143, healthcheck = #144).** Kiểm trạng thái bằng `gh pr view N -R KNT048/vedette --json state`.

| Việc | Ở đâu | Làm gì nếu chưa xong |
|---|---|---|
| #139 docs D-136 (4)–(7) | nhánh `docs/d136-scan-s2` | merge-step |
| #140 host 3-7 `container.pull` (D-130) | nhánh `feat/host-pull` | merge-step, sau #139 |
| #142 làm mới docs tình trạng + thư mục bàn giao này | nhánh `docs/status-refresh` | merge-step, sau #140 |
| #143 13b-8 duyệt qua chat (D-135) | nhánh `feat/response-chat` | merge-step, sau #142 |
| `healthcheck` (D-137), cổng trước 3-8/WP-08 | nhánh `feat/healthcmd`; trên máy kien là worktree `/Users/kien/Desktop/vedette-wt/healthcmd` | xem việc 1 bên dưới |

Merge lần lượt từng PR (xem §4). Mỗi PR merge xong thì xoá worktree và nhánh local của nó.

**Cập nhật 2026-11-10 (tối, phiên Ubuntu):** #139, #140, #142, #143 đã merge; việc 1, 2, 3 và 7 dưới đây **xong** (xem từng mục). WP-07b phần 3 **hoàn tất**. Số D trống kế tiếp là **D-147** (D-146 đặt chỗ cho SP-5b).

## 3. Việc còn lại, theo thứ tự, tới khi hoàn thành
Mỗi lát việc đi một vòng giống nhau:
1. Mở worktree và nhánh riêng, cắt từ `origin/main`.
2. Agent Sonnet làm theo brief.
3. Một agent Opus rà độc lập. Bắt buộc với core/auth, host, response và sensor; nên làm với mọi lát.
4. Sửa theo kết quả rà.
5. Mở PR, chạy merge-step.

Không cho hai agent làm cùng một module. Quyết định mới ghi thành D-xx, số trống tiếp theo là **D-147**.

1. ~~**`healthcheck`**~~ **XONG** (#144, D-137): subcommand `healthcheck` cho core, sensor, honeypot; HealthCmd dạng JSON exec, không qua `/bin/sh -c`. Còn để sau: adapter honeypot phải khởi động lại khi cấu hình đổi.
2. ~~**Host 3-8**~~ **XONG, tách làm hai:** 3-8a `container.start(version)`, `container.rollback`, giữ bản cũ (#148, D-138); 3-8b `vedette-host -bootstrap`, khoá trong `core_data`, lối thoát khỏi `core_data_unrecoverable` (#163, D-142). **WP-07b phần 3 hoàn tất.** Còn để sau: `backup.restore` ngoài `core_data_unrecoverable` đã xử ở 3-8b; WP-32 ghi runbook.
3. ~~**SP-3b**~~ **XONG** (#151, D-133): nuclei là job kind, giao thức v2, hai slot, gói ký đã kiểm, môi trường sạch. Nợ cho Emily: `nucleiout` từ chối dạng host trần; dòng lab thật chặn S5; kết quả rỗng không có nghĩa là không dính lỗi (D-133 (5)).
4. **SP-5:** đóng gói và địa chỉ hộp (`sensor-plan.md`, lát SP-5). **Tách đôi:** 5a nối core cho production (PKI, listener 8444, một Backend, không còn capture/nmap trong core, một nguồn địa chỉ hộp) **XONG** (#158, D-141); **5b** (image scan-base, pack qua make, `bundled[]`, D-146) **đang làm** (nhánh `feat/sensor-images`, worktree `sp-pack`). `BoxAddrs`: chờ Emily thêm tín hiệu "chưa biết" (#157), rồi chỉnh `cmd/vedette/notify.go`.
   - Ghim nuclei theo version và sha256 trong scan-base.
   - Dựng pack bằng `make`; manifest có `bundled[]`.
   - Có `BoxAddrs` cho notify (issue #62, mục cuối còn mở).
5. **SP-6:** unit trên host và build `scan` tại chỗ (`sensor-plan.md`, lát SP-6; cần host 3-6/3-7).
6. **13b-11:** chỉ làm sau WP-25 của Emily (PR #123 và các lát sau; tài liệu `wp13b-plan.md`).
7. ~~**Quyết định TLS**~~ **XONG** (#150, D-139): hộp tự cấp lại chứng chỉ tự ký của chính nó theo địa chỉ quản trị do host báo (tham khảo OPNsense, Proxmox).
8. **WP-08 đóng gói/phát hành:** image, SBOM, ký cosign, Quadlet và cài đặt.
   - Cần kien chuẩn bị: khoá phát hành offline (minisign chính + dự phòng, cosign) và VM lab (Ubuntu 24.04/26.04, Debian 13).
   - Phần không cần khoá thì làm trước; phần cần khoá thì hỏi kien.
9. **WP-30 E2E trên backend thật** cho các module của Kiên.
   - Nhánh `fix/e2e-baseline` (a07a3c2) còn trên origin: dựng lại worktree từ nhánh này.
   - Trước tiên đo 6 spec `inventory.spec` lỗi trên main.
10. **WP-31 rà bảo mật tổng:** SYS-1…8 (`docs/MODULE_CONTRACTS.md`) và D-41, bằng một agent Opus độc lập.
11. **WP-32 RUNBOOK.**

Khi việc 1–11 merge xong và E2E xanh: báo kien, cập nhật `kien.md`, `completion-log.md`, `ROADMAP.md` và `current.md`.

## 4. Công cụ (trong thư mục này)
- **`merge-step.sh <pr> <worktree> [<pr> <worktree>…]`** merge lần lượt từng cặp PR/worktree. Với mỗi PR, nó:
  1. gộp `origin/main` vào nhánh. Nếu chỉ `docs/DECISIONS.md` bị xung đột, nó tự giải bằng `resolve_decisions.py`;
  2. push;
  3. chờ CI tới khi không còn check pending;
  4. yêu cầu cả `go:pass` và `web:pass`;
  5. nếu main đổi trong lúc chờ thì làm lại (tối đa 3 lần);
  6. squash-merge với `--match-head-commit`, rồi kiểm lại trạng thái `MERGED`.

  Chạy nền, mỗi lần một chuỗi.
- **Chờ một PR merge:** poll `gh pr view N --json state`. Không dùng `pgrep -f "merge-step.sh N"`, vì nó khớp với chính dòng lệnh của nó.
- **Lint Linux:** `GOOS=linux $(go tool -n -modfile=tools/go.mod golangci-lint) run ./...`. Lint trên macOS bỏ qua các file `*_linux.go`.
- **Test có thời gian:** chạy với `TZ=UTC`. Nếu code từ chối thư mục tạm dùng chung, thêm `TMPDIR=/private/tmp`.

## 5. Luật làm việc của phiên lead
- **Không bao giờ được:**
  - push thẳng `main`;
  - tạo git tag (kien tag tay);
  - force-push: nhánh đã push thì merge `origin/main` vào, không rebase;
  - SSH;
  - quét mạng thật;
  - chạy Bash không có timeout;
  - nhúng GPL/AGPL vào lõi;
  - gắn lõi với một hãng thiết bị (D-58);
  - chạy `go build ./cmd/vedette` ở gốc repo.
- **Máy:** tối đa 2 việc nặng cùng lúc. Agent chờ trong vòng lặp có giới hạn khi `load5` > 12–15. Trước khi chạy `make check`, chờ tới khi `pgrep -f scripts/check.sh` không còn gì.
- **Dependency mới:** ghim phiên bản và ghi vào `THIRD_PARTY_NOTICES.md`.
- **Emily (D-65):**
  - Mọi chỗ chồng lấn hoặc dùng chung là việc của phía Kiên: DECISIONS, API_CONVENTIONS, DATA_MODEL, `cmd/vedette`, Makefile, `scripts/`.
  - Cứ 10 phút xem issue `owner:kien`, issue do `kiennt049` mở, comment mới trên PR đang mở, và PR của Emily chạm file dùng chung.
  - Việc nhỏ thì làm ngay trên nhánh riêng và comment link PR. Việc lớn thì đưa vào kế hoạch và comment khi nào làm.
  - Quyết định của Emily được chép vào DECISIONS bằng một docs PR.
- **Hỏi kien chỉ khi rất đặc biệt (D-74):** tiền, pháp lý hoặc luồng dữ liệu mới rời hộp, đổi hướng sản phẩm, việc không hoàn tác được.
- **Test AI thật:** chỉ chạy trên máy kien, với `VEDETTE_LIVE_AI=1`, model Haiku và effort thấp. Không bao giờ chạy trên CI, không ghi khoá vào repo, chat hay log.
- **Báo kien mỗi mốc:** khi một PR lớn merge, khi xong một WP, hoặc khi bị chặn.

## 6. Các file trong thư mục này
- `wp07b3-plan.md`: kế hoạch host phần 3 (lát 3-0…3-8, D-99…D-107). Lát 3-8 là việc còn lại.
- `sensor-plan.md`: kế hoạch giao thức sensor (SP-0…SP-6, D-109…D-116). Còn SP-3b, SP-5 và SP-6.
- `wp13b-plan.md`: kế hoạch WP-13b. Còn 13b-11.
- `healthcmd-brief.md`, `sp3b-brief.md`: hai brief sẵn sàng, đưa thẳng cho agent Sonnet.
- `merge-step.sh`, `resolve_decisions.py`: công cụ merge.

Khi mọi việc ở §3 xong, xoá thư mục này cùng PR cuối.
