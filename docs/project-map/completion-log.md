# Completion log — Vedette (mới nhất trước)

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
