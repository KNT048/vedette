# Trạng thái hiện tại — đọc file này trước

Cập nhật: 2026-11-13 (đối chiếu `origin/main` 1c804d50 và bản rà v1 2026-11-12 của supervisor). Repo: `KNT048/vedette` (public, D-63; CI GitHub Actions miễn phí). Nhóm: Kiên (`@kiennt048`) và Emily / Mlee (`@kiennt049`).

**Mục tiêu cuối:** app chạy đủ chức năng trên backend thật. Mọi WP đã merge, E2E xanh, bản phát hành ký được và cài được (định nghĩa "xong" ở cuối file).

## Đọc theo thứ tự
1. `CLAUDE.md` — luật làm việc.
2. File này — ai đang làm gì, còn lại gì.
3. `docs/TEAM_PLAN.md` — ai sở hữu gì, gói việc (WP), cách các phiên AI chạy (§4, cập nhật D-190).
4. File nhiệm vụ của phía bạn: `.ai/tasks/kien.md` (phía Kiên: phiên Mac và AI-Trưởng) hoặc `.ai/tasks/emily.md` (AI-Mlee).
5. Hợp đồng module của WP: `modules/<id>/CONTRACT.md` và `IMPACT.md`, cùng `docs/ARCHITECTURE.md`, `docs/DATA_MODEL.md`, `docs/API_CONVENTIONS.md`.
6. `docs/QA.md` — bắt buộc cho mọi màn hình.
7. `.ai/deferred/` — việc để sau theo từng nhánh.

**Luật test (D-376):** agent không ngồi chờ test: chạy `make check-fast` một lần, push, CI là cổng. Test chậm vào danh sách `slow`, test chập chờn vào cách ly 7 ngày; cả hai ở `scripts/ci/skip-tests.txt`. `-race` chỉ chạy ở lượt hằng ngày. Test mới tối giản, kiểm chức năng.

## Ai đang làm gì (D-190, chia lại theo D-198; Mac theo kien 2026-11-12)
| Phiên | Ở đâu | Phạm vi |
|---|---|---|
| **AI-Supervisor** | Máy Mac của Kiên | Điều phối cả ba phía, kiểm mỗi 30 phút, gộp PR (merge captain). Phía Mac chạy bằng **subagent** của Supervisor, mỗi subagent một PR, push sớm; không còn session phụ của Claude Desktop |
| **Subagent (Mac)** | Worktree riêng trên máy Mac | Việc nhỏ của phía Mac: BEFORE-V1, sửa lỗi QA, e2e-real, docs; WP-27 `auth-oidc` phần IdP sau CA riêng khi có story |
| **AI-Trưởng** | Box Ubuntu của Kiên (`byn`, tmux `claude`) | `vedette-host` (`host.self_update`, D-316), WP-08 phần còn lại, lab, `agent-intake`, `scan`, `honeypot` |
| **AI-Mlee** | Box Ubuntu của Emily (`byn2`, tmux `claude`) | `notify`, `ai`, `logs`, QA walk theo form (docs/QA.md §4) |

Dải số quyết định: Trưởng D-157…D-169 · Mac D-170…D-199 (đã hết) rồi D-230…D-259 · Mlee D-200…D-229. Số đã ghi nằm trong `docs/DECISIONS.md`.

## Hiện trạng (2026-11-12)
- **M1 xong:** giao diện đầy đủ trên mock API; bản build release không mang mock (#184).
- **M2 (backend) — mọi module đã có backend và đã merge:** core, auth, host, inventory, sensor-passive và sensor-active, giao thức sensor, response, honeypot, feeds, findings/mitigation, exposure, scan, notify, WP-27 `auth-oidc` / `reports` / `mcp-server`; `ai` còn lát 7 (#365) và `logs` còn L4 (nhánh `feat/logs-l4-ioc`); L6 để sau v1 (D-297).
- **WP-30 xong** (lát 1–10, #335: `make e2e-real` xanh, trừ các bug đã biết #302, #304, #305, #308 đánh dấu `test.fail`; project `@mobile` là `web/e2e-real/mobile.spec.ts`). Lát 1–9b: #204, #210, #222, #228, #235, #253, #257, #262, #284, #287, #291, #293, #295, #307, #311.
- **WP-31 xong, trừ danh sách LAB** (đóng 2026-11-12, bảng trạng thái ở `wp31-findings.md` của supervisor): R1, R2, S, I, H, M3, M4/L10, R3 (L7: #234, #259) đã merge; phần đóng: M7 (MAC lạ ở IP decoy là thiết bị) và L12 (D-296), L14 sửa chữ D-189 (D-295); M1 còn một LOW chấp nhận (`.ai/deferred/fix-wp31-closeout-inventory.md`); lỗi e2e-real #302 #304 #305 #306 #308 đã sửa (#333).
- **Đã xong, từng ghi là đang mở:** #464 (logs: giới hạn listener syslog đo trên box lab, D-222) · #463 (notify: cổng email rời 465 khi Encryption không còn SSL/TLS) · #298 (đóng sau lần chạy 3c trên .141) · ghi chú phát hành cho migration `notify` 0006 (#505).
- **Đang mở (PR):** #564 (tên hộp do host báo) · #565 (TLD IDN cho `lookup_ioc`, dòng thử gần nhất của hồ sơ AI) · #566 (hagezi subdomain), cùng ba PR sửa QA walk 3.
- **Đã merge gần đây (2026-11-12, mới nhất trước):** #462 (host: `host.self_update` áp dụng, chờ ổn định, quay lui; D-316 lát 2b; Trưởng) · #461, #455 (QA walk của Mlee: `docs/QA.md` §4; lỗi form nhóm a) · #460 (e2e-real: trang in `/reports/print/*`; Mac) · #458, #456, #450, #446 (host: pre_restore có nhóm lưu giữ riêng, self_update lát 2a và 1, lab Podman; Trưởng) · #454 (core: khôi phục sao lưu, luôn giữ bản dữ liệu hiện tại trước, D-377) · #448, #449 (cổng merge nhanh D-376; test cmd/vedette nhanh hơn) · #451, #452, #453, #457 (BEFORE-V1 Mac: build release ẩn dữ liệu mẫu D-369, dòng deferred đã xong, ghim lỗ hổng cũ) · #444 (notify: Zalo OA; Mlee).
- **Issue mở:** #363 (L6 post-v1: syslog và metadata SPAN qua sensor; Kiên) · #377…#395 (danh sách deferred post-v1 theo module; các dòng chuyển thêm ở lượt dọn 2026-11-13 ghi trong comment của từng issue). Đã đóng: #298, #350, #338, #324, #266.

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
- [x] feeds (#222, #260), findings + mitigation (#228), notify (#235), exposure (#262), scan S0–S5 (#208, #189/#190), `ai` lát 1–4c và 6: 1 (#123), 2 (#179), 3 (#205), 4a (#273), 4a-2 (#289), 4b (#310), 4c kho tri thức FTS5 (#323), 6 tin CVE (#326, bản Mac); feeds SSRF cổng riêng (#309, D-208); logs L1 (#186), an toàn production (#226), N1/N2 (#233), purge (#249), L2 syslog UDP/TCP (#267), L3 chữ ký (#331), TopAddresses (#347, #338, D-210), L4 IOC + kết nối xấu (PR này, D-213), L5 SIEM (#344, bản Mac), L7 GUI thật (#351, #355, bản Mac); `ai` 5a hỏi dữ liệu + công cụ đọc (#346, D-211, D-212), 4c PDF qua tiến trình con (#357); core purge FTS (#329).

## Còn lại tới "app chạy đủ chức năng"
**AI-Trưởng (Ubuntu `byn`)**
- [ ] `host.self_update` các lát còn lại (D-316, lát 5 và phần lab của lát 6; #562) · [x] chạy lần 3 kiểm `install.sh` trên .141 (3c, đạt; #298 đóng; xem `docs/INSTALL-TEST.md`).
- [ ] Hết hạn 2026-12-11: ghim lại `DEBIAN_IMAGE` và nâng nuclei lên 3.11.1 (28 ngoại lệ trivy của scan-base) · các mục lab (`.ai/deferred/`).

**Mac (subagent của Supervisor)**
- [ ] BEFORE-V1: danh sách đã xong, chỉ còn các lỗi QA đang được sửa.
- [ ] WP-27 `auth-oidc`: IdP sau CA riêng (cần story) — xem `.ai/deferred/feat-auth-oidc.md`.

**AI-Mlee (Ubuntu `byn2`)**
- [x] QA nhóm b: sửa notify (#463, đã merge) · còn hai mục lab.

**Chờ kien (người)**
- [ ] VM lab: Ubuntu 24.04 và Debian 13 (Ubuntu 26.04 thử trên box Mlee, D-198) cho `install.sh` (WP-08h), danh sách LAB của WP-31, kiểm scan trong lab.
  - Danh sách LAB của WP-31 (không sửa được bằng code; chạy trên VM/box thật):
    - [ ] M7: MAC macvlan của decoy mà vedette-host báo (`state/net`) trùng MAC sensor thụ động thấy trên dây; một máy thật nhận IP decoy (DHCP hay IP tĩnh) thành thiết bị, có cảnh báo, decoy bị gỡ.
    - [ ] L10: systemd thật: host tự tạo `/run/vedette` 0750 root:`socket_gid`, không vòng crash khi khởi động lại.
    - [ ] L5: dừng khẩn cấp cắt một lượt SSH đang chạy trên thiết bị thật.
    - [ ] L7: người duyệt tự liên kết danh tính bằng mã trên Telegram, Zalo, email thật.
    - [ ] L9: IP decoy đã áp trên box Ubuntu bị `never_touch` từ chối khi một hành động nhắm vào.
    - [ ] M5: nmap không đè loại do sensor thụ động gán cho máy chặn probe (ít quan trọng: thiết bị chưa duyệt không được tin).
    - [ ] Root boundary: `SO_PEERPIDFD` và cgroup của core dưới Quadlet; NET_RAW ambient cho container sensor/scan không root; kill cả process group và `Pdeathsig` trên kernel thật.
    - [ ] SYS-7: egress của nuclei (`-duc -ni`) với tcpdump, vì `scan`/`sensor` dùng `Network=host` không có hàng rào egress.
- [ ] Thử listener Zalo cá nhân trong lab (#316, thử nghiệm).
- [x] Ghi chú phát hành (release note) cho migration `notify` 0006 (#505).
- [x] Khoá ký phát hành: đã nhúng khoá thật (#313; nghi thức khoá đã thành code).

## Định nghĩa "xong" (M2 → bản phát hành đầu tiên)
Trạng thái theo bản rà v1 2026-11-12 (`origin/main` 4ec006d6; chứng cứ là số PR):
1. Mọi WP trong `docs/TEAM_PLAN.md` §3 đã merge, CI xanh trên `main`. **Xong phần mã** (ai 7 #365, ai 5b #488, logs L4 #375, exposure Runner #553, scan S5 #208; L6 sau v1, D-297). Còn hở: WP-08k, job phát hành chưa dựng.
2. WP-30: `make e2e-real` xanh cho **mọi module**. Không còn `test.fixme` cho phần đã xây; `KNOWN_501` và `KNOWN_404` chỉ còn những endpoint ngoài phạm vi, có ghi lý do. **Một phần:** `KNOWN_*` đã rỗng (#335); còn 11 `test.fixme` (ai ×4, scan ×4, logs ×2, notify ×1) và chưa có lượt chạy đầy đủ sau các PR 11-12.
3. WP-31: mọi phát hiện High/Medium đã đóng; danh sách LAB đã chạy trên VM. **Một phần:** phát hiện không cần lab đã đóng; danh sách LAB chưa chạy (decoy và nc hit đạt trên .141, lần 3c).
4. WP-08: bản phát hành ký được (cosign, minisign); `install.sh` cài sạch trên VM lab; nâng cấp và quay lui đã thử. **Một phần:** khoá nhúng (#313), `.deb` và tự cập nhật thử trên ubuntu2404/debian13 (#518, #562), cài sạch Ubuntu 26.04 đạt; chưa có job phát hành (bake `install.sh`, đẩy ghcr, ký image), `make vuln-scan` còn đỏ.
5. WP-32: RUNBOOK đủ cho cài đặt, quản trị, sao lưu, khôi phục. **Một phần:** viết xong (#303, #322); thiếu danh sách gói của `--uninstall`, cách xử lý `quick_check` hỏng, kiểm cổng, sao lưu volume khoá container-only.
6. `docs/QA.md`: các dòng đã kiểm; `docs/project-map/completion-log.md` đã ghi; `.ai/deferred/*` đã đóng hoặc chuyển có lý do. **Mở:** QA walk 1 đến 3 xong (#455, #461, #558-#560); lượt dọn 2026-11-13 đã đóng 11 dòng đã xong và chuyển 174 dòng sang #377…#395, còn 79 file có dòng mở; completion-log chưa cập nhật cho 11-12.

## Lưu ý máy Kiên
Nhánh local `archive/pre-squash` và `docs/m0-plan` chứa lịch sử cũ (có tên tổ chức cũ): **không push**. Kiến thức về máy và box (cài box mới, mạng, mirror, RAM/swap) nằm ở máy Mac của kien, ngoài git: `vedette-wt/box-setup/BOX-SETUP.md`.
