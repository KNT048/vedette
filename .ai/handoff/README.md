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

## 2. Đã xong tới đâu (đo trên `origin/main` lúc bàn giao)
Phần Kiên ước khoảng **75%**. Danh sách PR chi tiết nằm trong `docs/project-map/completion-log.md`.

**Đã xong:**
- WP-01…06, WP-10, WP-11, WP-12, WP-14;
- WP-04: đường găng;
- WP-13: 13a, cùng 13b lát 0–7, 9, 10. Đường găng 13b đã xong: đẩy cấu hình lên thiết bị chạy được khi AI tắt;
- WP-07: host 07a, 07b phần 1–2, phần 3 lát 0–6;
- giao thức sensor mTLS SP-0…SP-4;
- core: network (S-CORE-8), bộ đọc `core/conn/read` cho AI, xuất log (#137), OS updates.

**Đang bay lúc bàn giao.** Kiểm trạng thái bằng `gh pr view N -R KNT048/vedette --json state`.

| Việc | Ở đâu | Làm gì nếu chưa xong |
|---|---|---|
| #139 docs D-136 (4)–(7) | nhánh `docs/d136-scan-s2` | merge-step |
| #140 host 3-7 `container.pull` (D-130) | nhánh `feat/host-pull` | merge-step, sau #139 |
| #142 làm mới docs tình trạng + thư mục bàn giao này | nhánh `docs/status-refresh` | merge-step, sau #140 |
| #143 13b-8 duyệt qua chat (D-135) | nhánh `feat/response-chat` | merge-step, sau #142 |
| `healthcheck` (D-137), cổng trước 3-8/WP-08 | nhánh `feat/healthcmd`; trên máy kien là worktree `/Users/kien/Desktop/vedette-wt/healthcmd` | xem việc 1 bên dưới |

Merge lần lượt từng PR (xem §4). Mỗi PR merge xong thì xoá worktree và nhánh local của nó.

## 3. Việc còn lại, theo thứ tự, tới khi hoàn thành
Mỗi lát việc đi một vòng giống nhau:
1. Mở worktree và nhánh riêng, cắt từ `origin/main`.
2. Agent Sonnet làm theo brief.
3. Một agent Opus rà độc lập. Bắt buộc với core/auth, host, response và sensor; nên làm với mọi lát.
4. Sửa theo kết quả rà.
5. Mở PR, chạy merge-step.

Không cho hai agent làm cùng một module. Quyết định mới ghi thành D-xx, số trống tiếp theo là **D-138**.

1. **`healthcheck`** (D-137, brief `healthcmd-brief.md`). Cần các subcommand mà dòng `HealthCmd=` trong Quadlet gọi; thiếu chúng thì mọi `container.start` đều bị hoàn tác.
   - Nếu nhánh `feat/healthcmd` đã có commit của agent: rà Opus → sửa → PR.
   - Nếu chưa có: chạy brief từ đầu.
2. **Host 3-8:** `container.start(version)`, `container.rollback`, retention, bootstrap CLI.
   - Tài liệu: `wp07b3-plan.md` §2 lát 3-8, cùng các quyết định D-99…D-107 và D-130.
   - Viết brief theo mẫu `healthcmd-brief.md` và `sp3b-brief.md`.
   - Phải qua vòng rà Opus.
3. **SP-3b:** nuclei là một job kind (D-133, brief `sp3b-brief.md`, đã cập nhật theo D-136 (4)–(7)).
   - Chỉ bắt đầu khi PR #138 của Emily đã merge. #138 chứa các gói `modules/scan/nucleiargv`, `nucleiout` và `pack`.
4. **SP-5:** đóng gói và địa chỉ hộp (`sensor-plan.md`, lát SP-5).
   - Ghim nuclei theo version và sha256 trong scan-base.
   - Dựng pack bằng `make`; manifest có `bundled[]`.
   - Có `BoxAddrs` cho notify (issue #62, mục cuối còn mở).
5. **SP-6:** unit trên host và build `scan` tại chỗ (`sensor-plan.md`, lát SP-6; cần host 3-6/3-7).
6. **13b-11:** chỉ làm sau WP-25 của Emily (PR #123 và các lát sau; tài liệu `wp13b-plan.md`).
7. **Quyết định TLS:** chứng chỉ tự ký thiếu địa chỉ IP quản trị mới (`.ai/deferred/feat-core-network.md`).
   - Tự quyết theo D-74: xem cách top-tier làm, ghi D-xx kèm nguồn.
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
