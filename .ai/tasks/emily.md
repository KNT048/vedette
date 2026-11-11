# Việc của Emily (Mlee) — đọc cùng docs/TEAM_PLAN.md

Cập nhật: 2026-11-11, handoff cuối của phiên AI lead của Emily. Repo: **`KNT048/vedette`** (public, D-63). Module Go: `github.com/knt048/vedette`.
Emily sở hữu (TEAM_PLAN §2) các module: feeds, findings (D-57 (6)), mitigation, notify, exposure, scan, scan-credentialed, logs, agent-intake, ai, reports, mcp-server, auth-oidc.

**Từ 2026-11-11 (quyết định của Emily):**
- Emily cài lại Ubuntu cho giống máy của trưởng nhóm. Phiên AI của Kiên điều phối các phiên làm cho Emily, như với trưởng nhóm.
- Không dùng Discussion #145 nữa.
- Phiên lead cũ đã dừng sau khi merge xong mọi việc đang dở.
- Mọi thứ người điều phối mới cần đều có trong repo: file này, các file `.ai/deferred/*` và nội dung các PR. Những gì nằm dưới `~/agents`, `~/scanwp`, `~/fgr` và các worktree trên máy cũ đều không còn.

## Quy trình đã dùng (D-61 → D-65)
- **Kiểm trên máy, trong WSL2 Ubuntu.** Mã nằm ở hệ file của WSL, không đặt ở `/mnt/c`.
  - Trước khi push: chạy `heavy make check`, ghi mã thoát, dán phần cuối log kèm SHA vào mục "Local checks".
  - Chỉ merge khi CI xanh.
  - CI đỏ vì test chập chờn ở module của Kiên: chạy lại job hỏng, rồi báo.
- **Cổng kiểm mỗi lát:**
  1. Test đỏ trước, hoặc bằng chứng mutation khi test viết sau.
  2. Rà độc lập (Opus) cho dữ liệu không tin cậy, quyền đồng ý quét, secret, xoá dữ liệu.
  3. Sửa theo kết quả rà.
  4. Chạy gate.
  5. Merge khi CI xanh.

  Ý không chặn merge ghi một dòng vào `.ai/deferred/<nhánh>.md`.
- **Chồng lấn → Kiên làm (D-65).** Việc đụng module của Kiên hoặc phần dùng chung: mở issue `owner:kien`. Phần dùng chung gồm `core/`, `cmd/` (trừ dòng nối dây chỉ thêm vào), `Makefile`, `go.mod`, `tools/`, `scripts/`, `.github/`, `web/src/lib`, `web/src/mocks`, `docs/DECISIONS.md`, `DATA_MODEL`, `API_CONVENTIONS`, `MODULE_CONTRACTS`. Dòng Makefile chỉ thêm vào thì để commit riêng và báo @sysjrvn.
- **Không tự đánh số D-xx.** Ghi vào mục "Quyết định cần ghi" của PR; phiên của Kiên chép vào DECISIONS.

## Đã merge
- **Giai đoạn 0 (thư viện):** #8, #10 findings · #15 notify · #16 ai · #28 feeds.
- **feeds (WP-20):**
  - #46 backend · #80 giao diện chạy trên backend thật;
  - #93 KEV dự phòng qua kho GitHub của CISA (D-91);
  - #135 bỏ SSLBL (D-92) · #152 bảng nóng nói rõ lý do khi chưa nạp được danh sách CISA (D-134 (4)).
- **findings + mitigation (WP-21):**
  - #44 backend · #159 giao diện trên backend thật;
  - #170 đối chiếu định kỳ chữa sự kiện bị mất (D-144). Finding tạo ra khi đối chiếu là baseline, trừ khi KEV `dateAdded` mới trong 7 ngày.
- **notify (WP-22, WP-13b lát 8):**
  - #42 Zalo cá nhân · #60 module;
  - #120 gửi tin lỗ hổng thật · #171 fail-closed khi chưa biết địa chỉ hộp (#157);
  - Telegram: #172 nút duyệt và listener long-polling, #178 sửa theo rà, #198 gỡ nút khi yêu cầu đã chốt hoặc hết hạn (lát 2) · #197 test channel không thể treo CI.
- **exposure (WP-23):** #91.
- **scan (WP-23 phần 2):**
  - #127 S0 giao diện · #131 S1 cấu hình;
  - #138 S2 argv, JSONL, gói template · #154 S3 Scan now/Stop, nhật ký probe, kết quả thành finding;
  - #164 S4 quét lại theo KEV, lịch, lưu giữ · #189 S4b bù sự kiện `new_kev` bị lỡ;
  - #193 sửa test race · #208 S5 nối scanner (Dispatcher của sensor-active) và gói chỉ mục nuclei nhúng (988 template, khớp `pins.env`).
- **ai (WP-25):**
  - #123 lát 1 hồ sơ, khoá, phân việc;
  - #179 lát 2 giải thích CVE, mỗi lần gọi AI một dòng activity, usage và runs;
  - #205 lát 3 nhật ký activity, cắt bớt theo thời hạn lưu qua `chainhead.Prune` (#195), nguồn export.
- **logs (WP-24):**
  - #186 L1: nguồn, sự kiện, lưu giữ, nhận và purge, trên `logs.db` riêng (D-151: không nằm trong bản sao lưu; migration chỉ thêm, có test chặn);
  - #182 sửa test toast chập chờn.
- **Handoff:** #30, #55, #141.

## Việc còn mở theo module (kế hoạch chi tiết nằm trong file deferred)
| Module | Việc tiếp | File |
|---|---|---|
| ai | Lát 4a (rules, hooks) → 4b (memory, skills) → 4c (knowledge, kiểm FTS5 trước) → 6 → 5 (`core/conn/read`) → 7 (`Propose`, D-97/D-119). Route, bảng, quyết định cho từng lát đã ghi sẵn. | `.ai/deferred/feat-ai-activity.md` (cùng `feat-ai-module.md`, `feat-ai-explain.md`) |
| scan | Kiểm trong lab với nuclei v3.11.1 (cờ, một dòng `-jsonl` thật) · tự dừng khi thiết bị không phản hồi · #189 L3 · lý do hiện trên GUI khi không đọc được múi giờ tổ chức · sự kiện KEV bị bỏ không để lại dòng · ghi chú 2, 3 của #154 · việc worker cho Kiên · các ý từ rà #208. | `.ai/deferred/feat-scan-module.md` |
| notify | Lát 3 Slack Socket Mode · 3b gỡ nút Slack · lát 4 mã trả lời Zalo cá nhân (phần gửi trước; người duyệt là Zalo user ID; UNIQUE (channel, address)) · Telegram L1/L3/L4 từ rà #198 · giao diện chuyển sang API thật · mã hoá URL webhook (SYS-4). | `.ai/deferred/feat-notify-listeners.md`, `feat-notify-module.md`, `feat-notify-zalo-personal.md` |
| logs | L2–L7 chưa làm · M2 giới hạn byte/đĩa · L1 trần export · L2 kẹp timestamp · L4 ghi nguồn · L5 purge khi module tắt · các ý rà lần 2 của #186. | `.ai/deferred/feat-logs-module.md` |
| findings / mitigation | Các dòng còn mở, gồm việc giữ hay bỏ `findings.RescanClear`. | `.ai/deferred/feat-findings-*.md` |
| feeds | Các dòng còn mở. | `.ai/deferred/feat-feeds-*.md` |
| exposure | Mục tiêu quét ngoài. | `.ai/deferred/feat-exposure-module.md` |
| Giai đoạn 2 | WP-26 agent-intake, WP-27 reports / mcp-server / auth-oidc: chưa bắt đầu. | `docs/TEAM_PLAN.md` |

## Chờ từ Kiên (`owner:kien`)
- **#115 scan:** các dòng lab và `bundled[]`; S5 đã nối scanner ở #208.
- **Quyết định cần ghi: đã ghi** trong `docs/DECISIONS.md`: #205 → D-184 (giữ và dọn nhật ký, khoá `activity`, audit) và D-185 (giới hạn 1000 dòng, dòng huỷ); #208 → D-186 (chỉ mục gói nuclei) và D-187 (`ErrEngineDown`, seam `Engine`); #198 → D-188 (gỡ nút Telegram). Thêm D-183: `store.Migrate` từ chối DB mới hơn binary (kiểm goose, INV-26).
- **`API_CONVENTIONS` §3.3: đã ghi** `server_busy` cho `GET /logs/events` (503, không `Retry-After`).
- Gần đây Kiên đã sửa vào module notify ở #203 (D-174/D-175: thông tin xác thực không nằm trong mẫu; người duyệt đọc được toàn bộ nội dung). Đọc trước khi làm notify lát 3/4.

## Bài học (giữ cho người điều phối sau)
- **Khoá `heavy`:** mọi lệnh nặng (`go build/vet/test`, `make check/generate`, `pnpm tsc/build/vitest/playwright`) chạy qua một khoá duy nhất. Khoá chờ tối đa 180 phút; mã thoát 75 = hết thời gian chờ, chạy lại một lần.
  - Script giám sát chỉ được tính `make` cấp ngoài cùng là gate. `make verify` do `make check` gọi ra không phải gate trùng (ngày 2026-11-11 tính nhầm nên đã giết gate S5).
  - Gate chạy dưới systemd unit làm hỏng test `host/ops` và honeypot decoy vì môi trường khác; chạy gate bằng shell thường.
- **Không rebase PR đang mở.** Merge main vào nhánh, hoặc dùng nhánh `sync/<nhánh>` của trưởng nhóm rồi fast-forward. Rebase chỉ trước khi mở PR.
- **Bản release không chứa mock (#184):** code feature hay lib không import tĩnh `msw`, `web/src/mocks/*` hoặc `features/*/mocks*`. Kiểu dữ liệu đặt ở `contract.ts`/`types.ts`. `make verify-web` chạy `make web-release`.
- **Cổng 5173 dùng chung:** Playwright kiểm bất cứ server nào đang nghe ở cổng đó. Kiểm chủ trước bằng `ss -ltnp` và `/proc/<pid>/cwd`.
- **Bus sự kiện chỉ cố gắng giao (D-144).** Bên nhận phải tự đối chiếu lại; đừng dựa vào việc sự kiện luôn tới.
- **`logs.db` (D-151):** migration chỉ được thêm. Test `TestVolumeMigrationsAreAddOnly` còn kẽ hở, xem file deferred của logs.
- **Kết quả rỗng của nuclei = "không báo khớp"**, không bao giờ là "không có lỗ hổng" (D-133).
- **Test listener:** chạy nhiều lần cả khi không có `-race` (#183). Server giả phải đọc body trước khi chờ `r.Context()` (#197).
- **Test có giới hạn thời gian thật dễ chập chờn khi máy hoặc CI bận.** Kiểm tính đúng bằng điều kiện tất định.
- **Giá trị test giống secret thật** bị GitHub push protection chặn: ghép lúc chạy, hoặc dùng giá trị rõ là giả.
- **`wsl.exe` tự thay `$VAR`:** đặt lệnh trong file script. Script để dưới `~/`, không để ở `/tmp`.
- **Playwright trong WSL:** `pnpm --dir web e2e:install` và các gói apt `libnss3 libnspr4 libasound2t64 fonts-liberation fonts-noto-color-emoji`.
