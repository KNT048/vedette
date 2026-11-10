# Completion log — Vedette (mới nhất trước)

## 2026-11-10 — M2 giai đoạn 1 và 2 của phía Kiên: đường găng 13b xong, host/sensor/response nối vào binary

Giờ địa phương (UTC+7); mọi PR dưới đây đã merge vào `main` (CI go + web xanh), tới `6389e36`. Mỗi lát: Sonnet làm → Opus rà → sửa → PR → merge-step.

- **Response (WP-13b, D-93..D-98, D-117, D-119, D-124)**: lát 0 tài liệu/hợp đồng (#84), Cài đặt → Kết nối + luồng PRIVACY 12 (#92), kiểm trước/đọc lại là dữ liệu (#97), `core/conn` kho + endpoint (#96), transport HTTPS/SSH/MCP + Test với ghim TOFU (#101), bộ ghi chạy trên thiết bị: kiểm trước → chạy → đọc lại → hoàn tác (#105, **đường găng 13b xong: đẩy cấu hình khi AI tắt**), duyệt yêu cầu AI bằng mã hai bước (#109), đề xuất AI qua cổng Go `Propose` (#113), yêu cầu duyệt gửi sau commit + link email dùng một lần với luật hai người (#128). Core: `VerifyTwoStep` (#88), reader chỉ đọc cho AI (#126, D-127).
- **Host (WP-07b, D-85, D-87, D-99..D-107, D-120, D-121, D-123)**: lệnh OS/sao lưu/xuất log (#67), cập nhật OS + tải bản sao lưu phía core (#77), khung chạy chờ xác nhận (#102), `internal/release` kiểm minisign + cosign trong cây (#99), đọc mạng + netplan + ARP (#104), `net.apply/confirm/revert` + NTP (#107), IP mồi: namespace `vedette-hp`, macvlan theo IP (#112), Quadlet + start/stop với journal từng dịch vụ và phục hồi sau READY (#125). Core: màn Box network trên host thật, cửa sổ xác nhận 5 phút (#111, S-CORE-8, D-118).
- **Giao thức sensor mTLS (D-109..D-116, D-122)**: tài liệu SP-0 (#103), CA nội bộ + `sensorlink` (#106), tách `nmapargv` (#108), nmap từ xa (#117), sensor-passive tách capture sang `vedette-sensor` (#130).
- **Inventory/sensor/honeypot**: sensor-passive (#57, D-80, D-83), sensor-active (#66, D-84), honeypot (#72, D-89, D-90), `VulnScanPolicy` (#119, D-126).
- **Core**: auth API + mã cài đặt + 2FA nhập lại mật khẩu + cookie thiết bị (#58, **đường găng WP-04 xong**), handler dựng trong `buildServices` (#68), nối notify/sensor-active lần 2 (#69), Privacy thật + setup + dev-api theo phiên thật (#85, đóng #78), bản build không còn mock (#86), lỗi giải mã body nêu `field` (#87).
- **Phía Emily vào main trong ngày**: feeds GUI thật (#80), exposure/tự dò IP (#91, D-79, D-81), KEV dự phòng GitHub (#93, D-91), notify thông báo lỗ hổng (#120), scan S0/S1 (#127, #131), bỏ SSLBL (#135, D-92). Phía Kiên ghi quyết định thay cô theo D-65: D-79/D-81 (#65), D-86 (#63), D-92 (#82), D-128 (#121), D-129 (#124), D-131 (#129), D-134 (#136), D-125/D-126 (#116, issue #115).
- **Sửa flake và CI**: ETXTBSY của nmap giả (#76), honeypot dừng khi đang khởi động (#81), test chờ `run` dừng (#83), giới hạn test feeds 60 s (#90, #89), `authtest` ghim MaxHashing (#71, đóng #70), hai flake CI exposure/host `enterAwaiting` (#122), sweep của sensor-active (#133), ba flake core `waitRun`/reader/writer (#134, đóng #132), e2e `core.spec.ts` (#100), gỡ binary lỡ commit (#54).
- **Đang mở lúc ghi (chưa tính là xong)**: #137 xuất log core (D-132), #139 docs D-136, #140 host `container.pull` (D-130), 13b-8 duyệt qua chat (nhánh `feat/response-chat`, chưa PR); của Emily #123 (ai lát 1), #138 (scan S2), #141 (docs).
- **Đo**: CI go + web xanh trước mỗi merge (merge-step đòi cả hai). Không có số đo toàn bộ tại thời điểm này: `make verify` đầy đủ và bộ e2e toàn bộ chưa chạy lại cho cả đợt (D-64: bộ đầy đủ chỉ khi gần production).
- **Chưa làm / chưa xác minh**: mọi đường `*_linux.go` của host (Quadlet, netplan, macvlan, `SO_PEERPIDFD`, reboot trong cửa sổ xác nhận) chưa chạy trên hộp thật vì thiếu VM lab của kien; khoá phát hành offline (minisign chính + dự phòng, cosign) chưa tạo; healthcheck subcommands, host 3-8, SP-3b, SP-5, SP-6, WP-08, WP-30, WP-31, WP-32, 13b-11 chưa làm. Chi tiết: `.ai/tasks/kien.md`.

## 2026-11-09 — M2 bắt đầu: nền tảng core (phía Kiên)

- WP-01 khung Go (#7), WP-02 ogen từ `api/openapi.json` (#11), WP-03 `core/store`, `core/secrets`, `core/audit`, `core/exec` (#12), hợp đồng core (#18), `make check` + CI + D-62..D-65 (#19), orphan reaper (#22, #35), WP-04a server/registry/jobs (#25), WP-06 giao diện khớp hợp đồng (#26), WP-05 dev env + giao diện bật API thật theo module (#31, #32), nối module vào binary (#34, issue #33), WP-04b phần 1 `core/auth` + events (#36, đóng #17, hai vòng rà bảo mật), D-74..D-76 (#37), WP-10 inventory (#40), giới hạn thân theo thao tác (#41), `deps.Bus` + inventory dùng chung (#47), giám sát WP-23 (#49), D-81/D-82 (#51, #53), WP-07a khung `vedette-host` (#52, hai vòng rà Opus), nối inventory/feeds/findings/mitigation + D-78 (#56).
- Của Emily: feeds backend (#46), findings + mitigation (#44), notify Zalo cá nhân (#42), notify WP-22 (#60).

## 2026-11-06 → 2026-11-09 — M1 hoàn tất, M2-0 tài liệu, repo GitHub cho 2 người

- **Giao diện (M1)**: đủ mọi story trên mock API, chỉ tiếng Anh (D-28). Thêm trong đợt: feed tuỳ chỉnh + parser (D-36/37), Slack + duyệt trong chat (D-38/46), harness AI (D-39), phản ứng KHI/NẾU/THÌ có duyệt + chốt chặn AI (D-40/41/44/51), Incidents (D-52), hộp tự cập nhật OS và là thiết bị đầu tiên (D-53), Box network + SPAN (D-56), honey token (D-50), nhật ký AI chống sửa + tải toàn bộ log (D-48), đăng nhập hai bước app/email (D-35).
- **Chất lượng**: quy trình kiểm mới `docs/QA.md` (người làm ≠ người kiểm, ma trận form, kịch bản) sau lỗi kien bắt được; đợt kiểm độc lập 13 form sửa 14 lỗi.
- **Tài liệu M2-0**: ARCHITECTURE (viết lại), DEPLOYMENT (appliance chạy container, D-55), DATA_MODEL, API_CONVENTIONS, hợp đồng 18 module + `host`, 7 đặc tả (`docs/specs/`), ENGINEERING, RUNBOOK khung, CHANGELOG, TEAM_PLAN; quyết định D-43…D-58 (lõi không gắn hãng thiết bị, D-58).
- **Repo**: `kiennt048/vedette` riêng tư, lịch sử gộp thành 1 commit sạch (D-54); Emily (`@kiennt049`) có quyền ghi; PR #1–#4 đã merge.
- **Đo** (2026-11-09, trên `main`): `tsc -b` sạch; lint 0 lỗi; vitest 624/624 (21 file); `api/openapi.json` 222 đường dẫn / 274 thao tác, không lệch. E2E toàn bộ chưa chạy lại sau đợt cuối.
- **Chưa làm**: backend (M2) — bắt đầu theo `docs/TEAM_PLAN.md`; WP-06 chỉnh giao diện khớp hợp đồng; câu hỏi mở cuối mỗi tài liệu; phát hiện F-01…F-15 trong `docs/review/2026-11-09-architecture.html`.

## 2026-11-06 — GUI FE hoàn chỉnh trên mock API (D-18…D-22)

- kien duyệt kế hoạch M0 (`docs/plans/2026-11-06-m0-m1.md`) và quyết D-18 (OpenAPI spec-first), D-19 (không pilot concierge; Telegram dùng bình thường), D-20 (phân loại story, H11–H16, điều kiện dừng), D-21 (khuyến nghị dự án soạn bằng AI + người duy trì xác nhận qua PR; hộp hiện "chưa có" + AI của khách; story S-MIT-4), D-22 (/goal: GUI hoàn chỉnh trên mock cho mọi story, AI làm supervisor).
- `web/`: React 19, TS 7 strict, Vite 8, Tailwind v4, Radix, TanStack Query/Table, i18next vi/en, MSW 3 (mock lưu localStorage), Node ghim 26.13.0 bằng `devEngines.runtime`. Nền + module mẫu `feeds` do supervisor viết; 6 agent Sonnet làm inventory, findings+scan, exposure+honeypot, logs+notify, ai+reports, core+fleet theo `docs/plans/2026-11-06-fe-spec.md`; supervisor nối dữ liệu giữa module và sửa lỗi a11y E2E bắt được.
- Bảng nóng dùng dữ liệu thật: CISA KEV 2026.11.04 + EPSS + danh sách CVE nuclei-templates (`make fixtures`, 35 CVE).
- **Đo** (2026-11-06): `tsc -b` sạch; `pnpm lint` 0 lỗi, 19 cảnh báo (fast-refresh, setState trong effect); `pnpm test` 346/346 xanh (13 file, có axe từng trang); `pnpm e2e` 7 qua, 3 bỏ qua có chủ đích (Playwright Chromium trên bản build, desktop 1366 + Pixel 7: cài đặt lần đầu, 28 đường dẫn không lỗi console + axe gồm tương phản, luồng khai thiết bị → phát hiện → đăng xuất → đăng nhập vai chỉ xem, tiếng Anh + giao diện tối, điện thoại không cuộn ngang). Mã: ~14,8k dòng TS/TSX + ~4k dòng test. Build xong đã dọn (`make clean`).
- Sửa phát hiện qua review: `web/.gitignore` của Vite có mẫu `logs` làm git bỏ qua `src/features/logs/` → đổi thành `/logs`.
- **Chưa làm / chưa xác minh**: OpenAPI sinh từ schema (D-18) chưa có — mock chưa có Zod schema; chưa phỏng vấn M0 (K2); gói giảm thiểu NAS và số phiên bản vá QNAP chưa được người rà (K4); nội dung báo cáo BVDLCN chưa qua người rà pháp lý; chưa commit. Chi tiết: `.ai/deferred/docs-m0-plan.md`.

## 2026-11-06 — Khởi tạo dự án

- Tên Vedette; cấu trúc thư mục; LICENSE Apache-2.0; bộ docs: PRODUCT, USER_STORIES (37 story, tất cả `[chưa]`), MODULES (18 module), ARCHITECTURE, DATA_PIPELINE, AI_ASSISTANT (10 skill), UPDATES (4 kênh), ROADMAP (M0–M7), CONCEPT_VERIFICATION (10 giả thuyết), FRONTEND, DECISIONS (D-1…D-14), MODULE_CONTRACTS, END_OF_SESSION; rules; harness (.claude, .mcp.json.example, .ai).
- Nguồn: khảo sát 2026-11-06 (`docs/research/2026-11-06-proposal.md`): 6 agent khảo sát web (feed, discovery, vá ảo, thị trường/VN, IOC, đối thủ).
- kien quyết (D-15…D-17): không instance chung; tín hiệu fleet ẩn danh bật mặc định, minh bạch, tắt được; Go + TypeScript xác nhận; pháp lý minh bạch → thêm `docs/LEGAL.md`, `PRIVACY.md`, `THIRD_PARTY_NOTICES.md`, `NOTICE`, `docs/templates/consent-scan.md`, rule `legal.md`, story S-CORE-4.
- **Chưa có code.** Commit khởi tạo trên `main`. Việc kế tiếp: `.ai/tasks/current.md`.
