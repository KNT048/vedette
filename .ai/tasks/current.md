# Trạng thái hiện tại — ĐỌC FILE NÀY TRƯỚC (handoff khi kien tắt máy)

Cập nhật: 2026-11-09. kien: "cắt bớt test/check để ship nhanh, mới chỉ FE, muốn thấy sản phẩm" → ưu tiên cho xem sản phẩm; các bước 3–5 dưới đây làm khi kien yêu cầu. Nhánh `docs/m0-plan`, **đã commit WIP** (xem `git log -1`). Git user cá nhân `kiennt048@gmail.com`.
Không có agent nào đang chạy. Server dev đã tắt cùng máy: bật lại `pnpm --dir web dev --port 5173 --strictPort` (chạy nền).
Thư mục tạm `/private/tmp/...scratchpad` mất khi khởi động lại — mọi thông tin cần thiết đã chép vào file này.

## Mục tiêu (kien /goal + D-23)
GUI FE hoàn chỉnh, production-ready cho FE, trên mock API (MSW), **chỉ tiếng Anh** (D-28), dùng được như người dùng thật. AI tự QA, tự sửa; **chỉ báo kien khi thật hoàn hảo**. Không hỏi lại chủ đề đã chốt.

## Quyết định (chi tiết `docs/DECISIONS.md`)
D-18…D-34 như trước (OpenAPI từ Zod; không pilot; không multi-site; domain TXT / IP egress 90 ngày; 1 ô cam kết; dự án cá nhân không BYN; chỉ tiếng Anh; nhiều hồ sơ AI; danh mục đầy đủ; bỏ rule vá ảo; CIDR bắt buộc tiền tố; osquery mặc định + Wazuh API, bỏ Trivy/macOS; cài osquery một dòng).
**D-35 (mới)**: đăng nhập hai bước 2 kiểu — ứng dụng xác thực (QR `uqr@0.1.3` hoặc khoá tay) hoặc mã email (cần kênh email bật; gửi tới email đăng nhập; 6 số, 10 phút, 1 lần, 5 lần sai, gửi lại sau 60 s, 5 lần/giờ); admin đặt lại; cảnh báo khi tắt/xoá kênh email còn người dùng mã email; không bao giờ lùi về chỉ mật khẩu.

## Đã xong trong phiên này (sau compact)
- Agent inventory + ai/reports xong (chi tiết ở completion-log khi viết). Agent dịch toàn bộ summary/describe trong `features/*/contract.ts` sang tiếng Anh; `api/openapi.json` sinh lại (135 path; chữ có dấu duy nhất là tên "Nghị định 356/2025/NĐ-CP").
- Agent 2FA (D-35) xong: `features/core/{emailCode.ts,QrCode.tsx,useCountdown.ts}`, AccountPage, UsersSection, LoginPage, notify ChannelsSettings guard, `e2e/qa/twofa.spec.ts` (8/8), vitest core+notify+contract 137 qua. Chưa quét QR bằng điện thoại thật; chưa xem ảnh desktop của 2FA.
- Supervisor: gỡ alias `byn`, NavGroup `multi`; tên tác giả "Kien Nguyen"; đổi dữ liệu mẫu sang tiếng Anh toàn cục (`@acme.example`, NAS-PHOTOS, PC-ACCOUNTS, CAM-LOBBY, AP-FLOOR…); findings dùng hồ sơ AI theo việc (`ai_available: {explain, config}`, `profile` trên AiResult); `vite.config.ts` bỏ theo dõi qa-shots/test-results (trước đó gây tải lại CSS liên tục); `main.tsx`: tải lại khi chunk cũ mất (`vite:preloadError`) + thông báo rõ khi service worker bị chặn (không còn trang trắng); `router.tsx`: `hydrateFallbackElement` (PageLoading có lề); **matcher mock mới `src/mocks/match.ts`**: thiết bị khai tay/agent khớp ngay KEV fixture → phát hiện "suspected, product only" (trước đó cài sạch thêm thiết bị không bao giờ có phát hiện); cảm biến cài sạch dùng tên hộp; câu trạng thái phạm vi rõ hơn; DataTable wrapper `relative` (span sr-only tràn làm trang cuộn ngang 14px); menu "Notification channels" → "Alert channels"; AI "Apply suggestion" nói rõ khi không có gì để lưu; AiBlock key trích dẫn trùng (cisa.gov) đã sửa; deferred file cập nhật; D-35 + S-CORE-3 + S-REP-2 cập nhật.
- Kiểm: tsc sạch; lint 0 lỗi / 28 cảnh báo (đã rà: 14 fast-refresh, còn lại là mẫu có chủ đích — không lỗi thật); vitest toàn bộ **443/443** (trước 2FA). E2E toàn bộ trên bản build: 216 qua, ~30 rớt → đã chẩn đoán và sửa hết nguyên nhân (key localStorage cũ `v1` trong findings/scan spec; 2 kỳ vọng Sonnet bị em revert nhầm; core.spec /24→/25; app.spec điện thoại là list; tràn ngang; còn lại là chập chờn do 4 worker) — **chưa chạy lại toàn bộ**.

## Đợt 2026-11-09 (8 yêu cầu mới của kien)
- D-36…D-42 + story S-FEED-4/5, S-AI-7, S-RESP-1/2, S-NOT-2, S-CORE-5. Đã xây trên GUI mock: Settings → Feeds (feed có sẵn + feed tuỳ chỉnh + parser 5 định dạng, nút Thử), kênh Slack + duyệt trong chat + người duyệt, Report a problem, harness AI (tab Rules/Memory/Skills/Knowledge/Connections/Hooks; hook chặn PII, phạm vi bảo mật, công cụ ghi phải duyệt khoá bật), module `response` (đề xuất cho Critical bật; thực thi đã duyệt TẮT mặc định, cổng G-1…G-8 có test).
- "hermess" = harness (kien xác nhận), không dùng Hermes Agent.
- Đo 09/11: tsc sạch; vitest 504/504; `api/openapi.json` 175 path / 217 thao tác. E2E toàn bộ chưa chạy lại (kien: ưu tiên tốc độ).
- Bản thiết kế kiến trúc để audit: artifact https://claude.ai/artifact/7Xjw5sDq1uKBSQSid327EM, bản lưu `docs/review/2026-11-09-architecture.html`. Phát hiện mở F-01…F-12 (trừ F-04 đã sửa) nằm trong đó — F-03: cập nhật `docs/ARCHITECTURE.md` theo D-24/28/36/39/41.
- Việc nhỏ còn lại: thêm dòng `finding.panels` vào bảng slot trong `docs/plans/2026-11-06-fe-spec.md`; response chỉ có builder cho `disable_virtual_ip`.

## 2026-11-09 tối: GitHub
- Repo riêng tư `kiennt048/vedette` (D-54), lịch sử gộp thành 1 commit; `main` = code tại thời điểm tạo. Làm tiếp: tạo nhánh từ `main` mới, mở PR. Lịch sử cũ: nhánh local `archive/pre-squash` (KHÔNG push).
- Đã xong trước khi đưa lên: D-43…D-53 (phản ứng D-51, Incidents D-52, hộp tự cập nhật + là thiết bị đầu tiên D-53). Đo: tsc sạch, lint 0 lỗi, vitest 577/577, OpenAPI 215 path / 267 thao tác.
- Việc tiếp: PR đầu tiên = agent kiểm độc lập theo `docs/QA.md` (13 form) + viết lại `e2e/qa/notify.spec.ts`.

## VIỆC TIẾP THEO (theo thứ tự)
1. ~~Hồi quy dải mạng sau wizard~~ — 2026-11-09: không phải lỗi app; test journey rời trang /setup trước khi lưu xong (tiêu đề h1 của trang setup làm điều kiện chờ sai). Đã sửa test, journey 2/2 qua.
2. Chạy lại journey (`pnpm exec playwright test -c playwright.qa.config.ts e2e/journey.spec.ts --project=desktop --workers=1`), sửa cho xanh; journey đang có 1 `console.log` thừa → bỏ. Mở rộng journey: Exposure (domain TXT, IP hộp), osquery token (bật module agent intake → lệnh Linux/Windows), 2FA (đã có spec riêng), đổi vai viewer.
3. `pnpm --dir web test` toàn bộ, `pnpm --dir web exec tsc -b`, `pnpm --dir web lint`, `pnpm --dir web openapi` (kiểm không lệch).
4. E2E toàn bộ trên bản build: `cd web && pnpm exec playwright test --workers=2 --output=<tmp>` (4 worker gây chập chờn). Mục tiêu 0 rớt.
5. Xem ảnh 2FA desktop + sáng/tối (`web/qa-shots/twofa/`), ảnh journey.
6. Docs: entry completion-log (số đo), cập nhật file này, `.ai/deferred/docs-m0-plan.md`, `make clean`.
7. Báo kien khi xanh hết + hỏi: viết lại lịch sử git để xoá chữ BYN ở commit đầu 35a1697 trước khi public?

## Câu hỏi đã trả lời (không hỏi lại)
Rule vá ảo → bỏ (D-31). Agents on servers → osquery mặc định, cài một dòng (D-33/34). Thêm subnet sau wizard → Devices → Scope and sensors → Add a network range (có tiền tố, Enter để thêm) → tick xác nhận cạnh Save → Save changes. 2FA → D-35.

## Môi trường / bẫy
- Node 26.13.0 ghim `devEngines.runtime`; TS 7, Vite 8, React Router 8, MSW 3 (`onUnhandledFrame`), TanStack Table v8, Zod 4, oxlint.
- Khung trình duyệt tích hợp của app Claude **không đăng ký được service worker** → không dùng để xem mock; dùng Playwright hoặc Chrome thật.
- Mock DB key `vedette-mock-db-v2`; spec nào ghi localStorage phải dùng v2.
- Playwright: `playwright.config.ts` = bản build cổng 4173 (testDir e2e gồm cả qa/ và journey); `playwright.qa.config.ts` = server dev 5173. Kiểm cổng 4173 không có preview cũ trước khi chạy (reuseExistingServer).
- `make clean` xoá dist/test-results; `web/qa-shots/` bị gitignore.
