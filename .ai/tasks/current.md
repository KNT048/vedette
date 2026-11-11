# Trạng thái hiện tại — đọc file này trước

Cập nhật: 2026-11-12. Repo: `KNT048/vedette` (public, D-63; CI GitHub Actions miễn phí). Nhóm: Kiên (`@kiennt048`) và Emily / Mlee (`@kiennt049`).

**Mục tiêu cuối:** app chạy đủ chức năng trên backend thật. Mọi WP đã merge, E2E xanh, bản phát hành ký được và cài được (định nghĩa "xong" ở cuối file).

## Đọc theo thứ tự
1. `CLAUDE.md` — luật làm việc.
2. File này — ai đang làm gì, còn lại gì.
3. `docs/TEAM_PLAN.md` — ai sở hữu gì, gói việc (WP), cách các phiên AI chạy (§4, cập nhật D-190).
4. File nhiệm vụ của phía bạn: `.ai/tasks/kien.md` (phía Kiên: phiên Mac và AI-Trưởng) hoặc `.ai/tasks/emily.md` (AI-Mlee).
5. Hợp đồng module của WP: `modules/<id>/CONTRACT.md` và `IMPACT.md`, cùng `docs/ARCHITECTURE.md`, `docs/DATA_MODEL.md`, `docs/API_CONVENTIONS.md`.
6. `docs/QA.md` — bắt buộc cho mọi màn hình.
7. `.ai/deferred/` — việc để sau theo từng nhánh.

## Ai đang làm gì (D-190, chia lại theo D-198)
| Phiên | Ở đâu | Phạm vi |
|---|---|---|
| **AI-Supervisor** | Máy Mac của Kiên | Điều phối cả ba phía, kiểm mỗi 30 phút. Mỗi lát việc phía Mac chạy thành một session phụ của Claude Desktop |
| **Session phụ (Mac)** | Worktree riêng trên máy Mac | WP-30 các lát 3, 5, 6, 7, 9a, 9b, 10 và spec WP-30 cho scan, ai, logs; WP-31 R3 (định danh kênh người duyệt); WP-27 `auth-oidc`, `reports`, `mcp-server`; phần còn lại của `notify`; lỗi GUI Settings của core |
| **AI-Trưởng** | Box Ubuntu của Kiên (`byn`, tmux `claude`) | WP-08 phần còn lại; `honeypot` (gồm WP-30 lát 8a/8b); WP-30 lát 4 (qua `vedette-host`); phần còn lại của `scan`; WP-32 (cả hai phần); WP-26 `agent-intake`; WP-08h (`install.sh`) |
| **AI-Mlee** | Box Ubuntu của Emily (`byn2`, tmux `claude`) | `ai` (WP-25), `logs` (WP-24), việc đang dở (feeds chia nhỏ IOC apply, spec e2e exposure) |

Dải số quyết định: Trưởng D-157…D-169 · Mac D-170…D-199 (đã hết) rồi D-230…D-259 · Mlee D-200…D-229. Số đã ghi nằm trong `docs/DECISIONS.md`.

## Hiện trạng (2026-11-12)
- **M1 xong:** giao diện đầy đủ trên mock API; bản build release không mang mock (#184).
- **M2 (backend) — mọi module đã có backend và đã merge:** core, auth, host, inventory, sensor-passive và sensor-active, giao thức sensor, response, honeypot, feeds, findings/mitigation, exposure, scan, notify, WP-27 `auth-oidc` / `reports` / `mcp-server`; `ai` và `logs` còn các lát cuối (bên dưới).
- **WP-30 xong** (lát 1–10, #335: `make e2e-real` xanh, trừ các bug đã biết #302, #304, #305, #308 đánh dấu `test.fail`; project `@mobile` là `web/e2e-real/mobile.spec.ts`). Lát 1–9b: #204, #210, #222, #228, #235, #253, #257, #262, #284, #287, #291, #293, #295, #307, #311.
- **WP-31:** R1, R2, S, I, H, M3, M4/L10 đã merge; R3 (định danh kênh người duyệt, L7) đã merge (#234, #259); lỗi e2e-real #302 #304 #305 #306 #308 đã sửa (#333).
- **Đang mở (PR):** #336 (gộp D-xx vào `DECISIONS.md`, supervisor) · #331 (logs L3: chữ ký, baseline 7 ngày, bất thường; Mlee) · #326 (ai: tin CVE; Mlee) · #297 (logs: core mở syslog 514, Mlee/Trưởng).
- **Issue mở:** #332 (response `log_threshold` nối `logs.Service.Counts`) · #324 (core/exec: tiến trình con giới hạn tài nguyên để đọc PDF cho kho tri thức AI) · #298 (install test không dựng được artifact trên Mac) · #266 (logs L2: cổng syslog của container; PR #297). #115 đã đóng 2026-11-12 (đã xong qua #116, #119, #138, #151, #176, #208…).

## Đã xong (đến 2026-11-12)
**Phía Kiên — AI-Trưởng**
- [x] #218 core purge (#329 FTS5 nguyên vẹn khi xoá hết) · #225 job dọn dẹp chạy khi module tắt (D-160) · #236 `Scheduler.Wake`.
- [x] WP-08: a, b, c, d, g, j; 08i SBOM + trivy (#229); 08e image honeypot (#288); 08f bản build release (#269) + khoá ký thật nhúng, nghi thức khoá thành code (#313, D-256..D-258); 08m compose container-only (#315, #334); 08h `install.sh` (#296; sửa 26.04: #321); nâng cấp khởi động lại `vedette-host` (#318, D-260).
- [x] WP-30 lát 4 (#257) · 8a (#250) · 8b (#287) · scan: tự dừng khi thiết bị im (#299, D-165), 4 trạng thái im lặng (#317, D-261).
- [x] WP-32 RUNBOOK cả hai phần (#303, cập nhật #322) · WP-26 `agent-intake`: lát 0 (#314), lát 1 CA riêng của box cho 8443 (#328, D-262).

**Phía Kiên — session phụ trên Mac**
- [x] #221 13b-11 (và #289) · WP-30 lát 3, 5, 6, 7, 9a, 9b, 10 (#253, #284, #293, #291, #311, #307, #335).
- [x] WP-31 R3 (#234, #259) · WP-27 `auth-oidc` (#248, #261), `reports` (#279), `mcp-server` (#280).
- [x] `notify`: Slack lát 3 (#265), 3b (#282); Zalo lát 4 gửi (#292), 4b listener mã trả lời (#316, D-243, thử nghiệm); Telegram L1 (#198, #319), L3 (#325), L4 (#327).
- [x] Lỗi GUI Settings của core: #247, #256, #215; #251 giới hạn chờ writer (#283, D-246); orphan-reaper (#252); feeds không tự kết nối box (#309, D-208).

**Phía Emily — AI-Mlee**
- [x] feeds (#222, #260), findings + mitigation (#228), notify (#235), exposure (#262), scan S0–S5 (#208, #189/#190), `ai` lát 1–4c: 1 (#123), 2 (#179), 3 (#205), 4a (#273), 4a-2 (#289), 4b (#310), 4c kho tri thức FTS5 (#323); logs L1 (#186), an toàn production (#226), N1/N2 (#233), purge (#249), L2 syslog UDP/TCP (#267).

## Còn lại tới "app chạy đủ chức năng"
**AI-Trưởng (Ubuntu `byn`)**
- [ ] WP-08 phần còn lại: kiểm `install.sh` trên box Mlee (Ubuntu 26.04, LAN) và Mac độc lập qua SSH (#298 chặn bước dựng artifact trên Mac; xem `docs/INSTALL-TEST`); scan-base còn 28 ngoại lệ trivy hết hạn 2026-12-11 (ghim lại Debian, nâng nuclei).
- [ ] #297 (logs: core mở syslog 514, kèm #266) — cùng Mlee (logs L3–L7).
- [ ] #324 (core/exec: đọc PDF trong tiến trình con giới hạn tài nguyên, cho `ai`) · scan: kiểm trong LAB với nuclei v3.11.1 (`.ai/deferred/feat-scan-autostop.md`).
- [ ] WP-26 `agent-intake`: các lát sau lát 1.

**Session phụ trên Mac**
- [ ] #332 nối `logs.Service.Counts` vào `response log_threshold` (sau logs L3).
- [ ] #336 gộp các D-xx (supervisor).
- [ ] WP-27 `auth-oidc`: IdP sau CA riêng (cần story) và spec e2e-real SSO (WP-30) — xem `.ai/deferred/feat-auth-oidc.md`.

**AI-Mlee (Ubuntu `byn2`)**
- [ ] WP-24 logs: L3 (#331, đang mở) → L4–L7.
- [ ] WP-25 ai: tin CVE (#326, đang mở) → lát 5 → lát 7. (Các lát 4b, 4c đã merge.)

**Chờ kien (người)**
- [ ] VM lab: Ubuntu 24.04 và Debian 13 (Ubuntu 26.04 thử trên box Mlee, D-198) cho `install.sh` (WP-08h), danh sách LAB của WP-31, kiểm scan trong lab.
- [ ] Thử listener Zalo cá nhân trong lab (#316, thử nghiệm).
- [ ] Ghi chú phát hành (release note) cho migration `notify` 0006.
- [x] Khoá ký phát hành: đã nhúng khoá thật (#313; nghi thức khoá đã thành code).

## Định nghĩa "xong" (M2 → bản phát hành đầu tiên)
1. Mọi WP trong `docs/TEAM_PLAN.md` §3 đã merge, CI xanh trên `main`.
2. WP-30: `make e2e-real` xanh cho **mọi module**. Không còn `test.fixme` cho phần đã xây; `KNOWN_501` và `KNOWN_404` chỉ còn những endpoint ngoài phạm vi, có ghi lý do.
3. WP-31: mọi phát hiện High/Medium đã đóng; danh sách LAB đã chạy trên VM.
4. WP-08: bản phát hành ký được (cosign, minisign); `install.sh` cài sạch trên VM lab; nâng cấp và quay lui đã thử.
5. WP-32: RUNBOOK đủ cho cài đặt, quản trị, sao lưu, khôi phục.
6. `docs/QA.md`: các dòng đã kiểm; `docs/project-map/completion-log.md` đã ghi; `.ai/deferred/*` đã đóng hoặc chuyển có lý do.

## Lưu ý máy Kiên
Nhánh local `archive/pre-squash` và `docs/m0-plan` chứa lịch sử cũ (có tên tổ chức cũ): **không push**. Kiến thức về máy và box (cài box mới, mạng, mirror, RAM/swap) nằm ở máy Mac của kien, ngoài git: `vedette-wt/box-setup/BOX-SETUP.md`.
