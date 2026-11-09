# Completion log — Vedette (mới nhất trước)

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
