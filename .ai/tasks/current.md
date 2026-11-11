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

## Ai đang làm gì (D-190)
| Phiên | Ở đâu | Phạm vi |
|---|---|---|
| **AI-Supervisor** | Máy Mac của Kiên | Điều phối cả ba phía, kiểm mỗi 30 phút. Mỗi lát việc phía Mac chạy thành một session phụ của Claude Desktop |
| **Session phụ (Mac)** | Worktree riêng trên máy Mac | WP-30 các lát 3, 5, 6, 7, 9a, 9b, 10; WP-31 R3 (định danh kênh người duyệt); WP-27 `auth-oidc` |
| **AI-Trưởng** | Box Ubuntu của Kiên (`byn`, tmux `claude`) | WP-08 phần còn lại; `honeypot` (gồm WP-30 lát 8a/8b); WP-30 lát 4 (qua `vedette-host`); WP-32 phần Kiên; WP-26 `agent-intake` |
| **AI-Mlee** | Box Ubuntu của Emily (`byn2`, tmux `claude`) | Các module của Emily: logs → ai → notify → scan; WP-30 và WP-32 phần Emily; WP-27 `reports` và `mcp-server` |

Dải số quyết định: Trưởng D-157…D-169 · Mac D-170…D-199 (đã dùng tới D-190) · Mlee D-200…D-229. Số đã ghi nằm trong `docs/DECISIONS.md`.

## Hiện trạng (2026-11-11)
- **M1 xong:** giao diện đầy đủ trên mock API; bản build release không mang mock (#184).
- **M2 (backend):**
  - Phía Kiên đã merge: core, auth, host, inventory, sensor-passive và sensor-active, giao thức sensor, response (13a, 13b lát 1–10), honeypot.
  - WP-08 đã merge các phần a, b, c, d, g, j.
  - WP-31 đã rà xong; các lát sửa R1, R2, S, I, H và M4/L10 đã merge.
  - WP-30 lát 1–2 đã merge (#204, #210); feeds của Emily đã merge (#222).
  - Phía Emily đã merge: feeds, findings/mitigation, notify (phần lớn), exposure, scan S0–S5, ai lát 1–3, logs L1.
- **Hôm nay đã merge:** #203–#217, #219, #220 (Go 1.26.11 vá GO-2026-6859), #222.
- **Đang mở:** #218 (core purge, Trưởng); #221 (13b-11 AI viết kế hoạch xử lý, Mac); WP-30 lát 3 (session phụ `wp30-s3`); logs production-safety (Mlee).

## Còn lại tới "app chạy đủ chức năng"
**Phía Kiên — AI-Trưởng**
- [ ] #218 core purge (đóng #187), #223 job dọn dẹp chạy cả khi module tắt (D-160).
- [ ] WP-08i SBOM và quét lỗ hổng (D-159) · 08e image honeypot · 08f bộ build release (cần khoá của kien) · 08m compose · 08h `install.sh` (cần VM lab của kien).
- [ ] WP-30 lát 4 (os-updates và network qua host giả) · lát 8a (adapter host thật cho honeypot) · lát 8b (honeypot.spec).
- [ ] WP-32 RUNBOOK phần Kiên · WP-26 `agent-intake`.

**Phía Kiên — session phụ trên Mac**
- [ ] #221 13b-11.
- [ ] WP-30 lát 3 (đăng nhập hai bước), 5 (connections), 6 (inventory), 7 (sensors), 9a/9b (response), 10 (chạy toàn bộ, có `@mobile`).
- [ ] WP-31 R3 (L7); WP-31 danh sách kiểm trong LAB (cần VM).
- [ ] WP-27 `auth-oidc` (story trước).
- [ ] Sửa `scripts/dev/orphan-reaper.sh`: nó bỏ sót `pnpm dev` mồ côi.

**Phía Emily — AI-Mlee**
- [ ] WP-24 logs: các dòng deferred, gồm M2, L1–L7 và các ý rà của #186.
- [ ] WP-25 ai: lát 4a (rules và hook; kèm bí danh khôi phục được để kế hoạch xử lý đề xuất được hành động khi đang che dữ liệu cá nhân) → 4b → 4c → 6 → 5 → 7.
- [ ] notify: lát 3 (Slack), 3b, 4 (mã trả lời Zalo cá nhân), Telegram L1/L3/L4.
- [ ] scan: tự dừng khi thiết bị không phản hồi; #189 L3; kiểm trong LAB với nuclei v3.11.1.
- [ ] WP-30 cho findings, notify, exposure, scan, ai, logs · WP-32 phần Emily · WP-27 `reports`, `mcp-server`.

**Chờ kien (người)**
- [ ] Khoá ký phát hành offline: minisign chính và dự phòng, cosign.
- [ ] VM lab: Ubuntu 24.04/26.04 và Debian 13. Cần cho WP-08h, LAB của WP-31 và kiểm scan trong lab.

## Định nghĩa "xong" (M2 → bản phát hành đầu tiên)
1. Mọi WP trong `docs/TEAM_PLAN.md` §3 đã merge, CI xanh trên `main`.
2. WP-30: `make e2e-real` xanh cho **mọi module**. Không còn `test.fixme` cho phần đã xây; `KNOWN_501` và `KNOWN_404` chỉ còn những endpoint ngoài phạm vi, có ghi lý do.
3. WP-31: mọi phát hiện High/Medium đã đóng; danh sách LAB đã chạy trên VM.
4. WP-08: bản phát hành ký được (cosign, minisign); `install.sh` cài sạch trên VM lab; nâng cấp và quay lui đã thử.
5. WP-32: RUNBOOK đủ cho cài đặt, quản trị, sao lưu, khôi phục.
6. `docs/QA.md`: các dòng đã kiểm; `docs/project-map/completion-log.md` đã ghi; `.ai/deferred/*` đã đóng hoặc chuyển có lý do.

## Lưu ý máy Kiên
Nhánh local `archive/pre-squash` và `docs/m0-plan` chứa lịch sử cũ (có tên tổ chức cũ): **không push**. Kiến thức về máy và box (cài box mới, mạng, mirror, RAM/swap) nằm ở máy Mac của kien, ngoài git: `vedette-wt/box-setup/BOX-SETUP.md`.
