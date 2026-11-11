# Trạng thái hiện tại — đọc file này trước

Cập nhật: 2026-11-11 (trưa, giờ VN). Repo: `KNT048/vedette` (public, D-63; CI GitHub Actions miễn phí). Nhóm: Kiên (`@kiennt048`) và Emily / Mlee (`@kiennt049`).

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

## Hiện trạng (2026-11-11)
- **M1 xong:** giao diện đầy đủ trên mock API; bản build release không mang mock (#184).
- **M2 (backend):**
  - Phía Kiên đã merge: core, auth, host, inventory, sensor-passive và sensor-active, giao thức sensor, response (13a, 13b lát 1–10), honeypot.
  - WP-08 đã merge các phần a, b, c, d, g, j.
  - WP-31 đã rà xong; các lát sửa R1, R2, S, I, H và M4/L10 đã merge.
  - WP-30 lát 1–2 đã merge (#204, #210); feeds của Emily đã merge (#222).
  - Phía Emily đã merge: feeds, findings/mitigation, notify (phần lớn), exposure, scan S0–S5, ai lát 1–3, logs L1 và an toàn production (#226: giới hạn theo byte, trần export, kẹp thời điểm; D-200).
- **Hôm nay đã merge:** #203–#217, #219, #220 (Go 1.26.11 vá GO-2026-6859), #222, #226, #228, #233, #234, #235, #249, #254 (Mlee).
- **Đang mở:** #218 (core purge, Trưởng); #221 (13b-11 AI viết kế hoạch xử lý, Mac); WP-30 lát 3 (session phụ `wp30-s3`); Mlee: logs L2 syslog (`feat/logs-l2-syslog`), feeds chunked IOC apply (`fix/feeds-chunked-ioc-apply`: hagezi giữ writer ~15 s, chặn đăng nhập lúc khởi động và mỗi 6 giờ), e2e-real exposure (`feat/e2e-real-exposure`, chờ bản sửa feeds).

## Còn lại tới "app chạy đủ chức năng"
**Phía Kiên — AI-Trưởng**
- [x] #218 core purge (đóng #187) đã merge. - [ ] #225 job dọn dẹp chạy cả khi module tắt (D-160, đóng #223), rồi `Scheduler.Wake` cho logs (nhánh `feat/jobs-wake`).
- [ ] WP-08i SBOM và quét lỗ hổng (D-159, PR này; scan-base còn 28 ngoại lệ hết hạn 2026-12-11: ghim lại Debian, nâng nuclei) · 08e image honeypot (đang làm, D-162) · 08f bộ build release (cần khoá của kien) · 08m compose · 08h `install.sh` (cần VM lab của kien).
- [ ] WP-30 lát 4 (os-updates và network qua host giả; đang làm) · lát 8a (adapter host thật cho honeypot, D-161; đang sửa theo rà Opus) · lát 8b (honeypot.spec).
- [ ] WP-32 RUNBOOK (cả hai phần, D-198) · WP-26 `agent-intake`.
- [ ] scan (từ Mlee, D-198): tự dừng khi thiết bị không phản hồi; #189 L3; lý do trên GUI; kiểm trong LAB với nuclei v3.11.1.
- [ ] WP-08h: thử cài trên box Mlee (Ubuntu 26.04, có LAN; kien 2026-11-11); Mac cài độc lập qua SSH theo README rồi kiểm.

**Phía Kiên — session phụ trên Mac**
- [ ] #221 13b-11.
- [ ] WP-30 lát 3 (đăng nhập hai bước), 5 (connections), 6 (inventory), 7 (sensors), 9a/9b (response), 10 (chạy toàn bộ, có `@mobile`).
- [ ] WP-31 R3 (L7); WP-31 danh sách kiểm trong LAB (cần VM).
- [ ] WP-27 `auth-oidc` (story trước).
- [ ] Sửa `scripts/dev/orphan-reaper.sh`: nó bỏ sót `pnpm dev` mồ côi.
- [ ] Lỗi GUI Settings của core: #237–#244 (PR 2 của `fix/core-settings-gui`); #251 giới hạn chờ writer của `core/store`.
- [ ] Từ Mlee (D-198): `notify` lát 3 (Slack Socket Mode), 3b, 4 (mã trả lời Zalo cá nhân), Telegram L1/L3/L4 · WP-27 `reports`, `mcp-server` · spec WP-30 cho scan, ai, logs.

**Phía Emily — AI-Mlee**
- [ ] WP-24 logs: L2 listener (đang làm) → L3–L7. Đã xong: an toàn production (#226, D-200), N1/N2 (#233), vòng purge + housekeeping (#249, D-201).
- [x] notify: cổng `Config.ApproverLinks` (#234). Phía Kiên (WP-31 R3, #259) nối `Linked` vào `response`.
- [x] Job dọn của ai và scan là housekeeping (#254, D-202).
- [ ] WP-25 ai: lát 4a (rules và hook; kèm bí danh khôi phục được để kế hoạch xử lý đề xuất được hành động khi đang che dữ liệu cá nhân) → 4b → 4c → 6 → 5 → 7.
- [ ] Việc đang dở: feeds chia nhỏ IOC apply (#260); spec e2e exposure. WP-30 của Emily đã xong: feeds (#222), findings + mitigation (#228), notify (#235). (notify, scan, reports, mcp-server, spec WP-30 scan/ai/logs và WP-32 phần Emily đã chuyển đi theo D-198.)

**Chờ kien (người)**
- [ ] Khoá ký phát hành offline: minisign chính và dự phòng, cosign.
- [ ] VM lab: Ubuntu 24.04 và Debian 13 (Ubuntu 26.04 thử trên box Mlee, D-198). Cần trước khi phát hành cho WP-08h, LAB của WP-31 và kiểm scan trong lab.

## Định nghĩa "xong" (M2 → bản phát hành đầu tiên)
1. Mọi WP trong `docs/TEAM_PLAN.md` §3 đã merge, CI xanh trên `main`.
2. WP-30: `make e2e-real` xanh cho **mọi module**. Không còn `test.fixme` cho phần đã xây; `KNOWN_501` và `KNOWN_404` chỉ còn những endpoint ngoài phạm vi, có ghi lý do.
3. WP-31: mọi phát hiện High/Medium đã đóng; danh sách LAB đã chạy trên VM.
4. WP-08: bản phát hành ký được (cosign, minisign); `install.sh` cài sạch trên VM lab; nâng cấp và quay lui đã thử.
5. WP-32: RUNBOOK đủ cho cài đặt, quản trị, sao lưu, khôi phục.
6. `docs/QA.md`: các dòng đã kiểm; `docs/project-map/completion-log.md` đã ghi; `.ai/deferred/*` đã đóng hoặc chuyển có lý do.

## Lưu ý máy Kiên
Nhánh local `archive/pre-squash` và `docs/m0-plan` chứa lịch sử cũ (có tên tổ chức cũ): **không push**. Kiến thức về máy và box (cài box mới, mạng, mirror, RAM/swap) nằm ở máy Mac của kien, ngoài git: `vedette-wt/box-setup/BOX-SETUP.md`.
