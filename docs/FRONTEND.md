# Frontend — thân thiện, không "mùi AI"

kien, 2026-11-06: GUI tốt trước; nghiên cứu skill/plugin FE để tránh bị gán mác AI quá đà; thân thiện người dùng.

## 1. Stack

React 19 + TypeScript (strict) + Vite + Tailwind v4 + shadcn/ui (Radix) + TanStack Query v5/Table v8 + React Router + react-i18next (chỉ tiếng Anh, D-28) + Zod (schema API) + MSW (mock API cho M0/M1) + vitest + Testing Library + Playwright (E2E) + axe-core (a11y trong test). pnpm. Không Next.js, không SSR: SPA nhúng vào binary Go.

## 2. Ai dùng, dùng khi nào

P2 mở mỗi sáng 2 phút và khi có alert; P1 chỉ đọc Zalo và thỉnh thoảng mở báo cáo; P3 nhìn bảng tổng. Vậy: **thông tin đặc, bình tĩnh, tiếng Việt thường**, không "wow", không chat là trung tâm. AI xuất hiện **trong ngữ cảnh** (nút "Giải thích" trên một phát hiện), có nhãn nguồn và token, không có chatbox nổi.

## 3. Hướng thiết kế (quyết định, không phải gợi ý)

- **Chữ**: một họ sans hỗ trợ dấu tiếng Việt tốt, có tabular figures: **Be Vietnam Pro** (thiết kế bởi người Việt, Google Fonts) cho toàn bộ UI; mono (JetBrains Mono) **chỉ** cho đoạn cấu hình/log/CVE id trong code block, không cho nhãn nhỏ. Cỡ 14/16, line-height 1.5, ≤80 ký tự/dòng cho văn bản.
- **Màu**: nền trung tính (sáng: trắng ngà rất nhẹ; tối: xám xanh đậm), **một** màu nhấn (xanh lục đậm — "gác, an toàn"), bốn màu trạng thái có nghĩa cố định: đỏ = xác nhận/khẩn, cam = nghi/cần xem, xanh lục = ổn/đã xử lý, xám = tắt/không biết. Trạng thái luôn kèm **chữ**, không chỉ màu. Không gradient, không glass, không tím, không "sparkle".
- **Bố cục**: thanh bên trái cố định (Trang chủ, Thiết bị, Phát hiện, Bề mặt ngoài, Cảnh báo, Log, Báo cáo, Cài đặt), nội dung căn trái, bảng là thành phần chính, bo góc 6px thống nhất, bóng gần như không. Mật độ: 8px grid, bảng 40px/dòng.
- **Khung trang (D-464, S-UI-1)**: mọi trang trong menu chính theo một thứ tự: `PageHeader` (tiêu đề ~20 px và mô tả ngắn cùng một dòng) → `KpiStrip` tuỳ chọn (tối đa 4 ô: số, nhãn, liên kết; chỉ khi con số là câu trả lời) → `PageTabs` khi trang có hơn một phần (hàng tab ngang, tab đang mở ở `?tab=<id>`, đổi tab thay mục lịch sử, tab có việc chờ người dùng mang số đỏ kèm câu đọc cho trình đọc màn hình; điện thoại: hàng tab cuộn trong chính nó). Cả ba ở `web/src/components/common/{PageHeader,PageFrame}.tsx`; không tự dựng tab hay thẻ số riêng trong module, không lưu tab ở `#hash`. Trang dài nhiều mục độc lập (≥ 4) tách thành tab. Khi dùng `PageTabs`: tab mà vai trò không được xem thì **không đưa vào** `tabs` (không vẽ rồi ẩn); panel tải lười (`lazy`) thì mỗi panel một `Suspense` riêng; số đỏ chỉ cho việc cần người dùng ngay; tham số riêng của một tab (ví dụ `?run=` của Scans) **được giữ** khi đổi tab (`PageTabs` chỉ đặt `tab`), nên tab khác phải bỏ qua tham số không thuộc nó. Khi chuyển một trang cũ sang khung: liên kết cũ (`#hash`, đường dẫn cũ) phải chuyển hướng tới đúng `?tab=`, giữ tham số khác, và chỉ bắt đúng các tên cũ (hash khác như `#main` của liên kết "Skip to content" để nguyên). Cài đặt giữ menu dọc (nhiều form ngắn; như Grafana, GitLab admin).
- **Chuyển động**: chỉ khi trả lời hành động (mở, xác nhận); không fade-in từng card, không hover transform. Tôn trọng `prefers-reduced-motion`.
- **Ngôn ngữ**: động từ rõ ("Gửi thử", "Áp dụng", "Đánh dấu đã xử lý"); lỗi nói cái gì sai và sửa thế nào; màn trống là hướng dẫn hành động ("Chưa có thiết bị. Bật kiểm kê thụ động hoặc khai tay."); không "Oops", không emoji trong UI, không chữ hoa toàn bộ cho nhãn, không eyebrow label, không "→" cuối nút.
- **Thứ bậc thông tin**: mỗi trang trả lời một câu hỏi của persona ở dòng đầu ("Hôm nay: 2 phát hiện mới, 1 xác nhận"). Số to chỉ khi là câu trả lời, không phải trang trí.
- **Độ tin cậy nhìn thấy**: mọi dữ liệu có "nguồn" và "cập nhật lúc"; "xác nhận" / "nghi" là hai chip khác hình (không chỉ khác màu); dữ liệu AI có viền chấm + nhãn "AI tạo".

## 4. Tránh "mùi AI" — checklist review (từ skill frontend-design + kinh nghiệm thực tế)

Rớt nếu có: nền kem + serif + cam đất; đen + một màu neon; card giống hệt nhau xếp lưới với bóng xám; eyebrow ALL-CAPS trên mỗi tiêu đề; "A · B · C"; "WORD — fragment"; mono cho nhãn; "→" cuối link; hero với số to + gradient; fade-slide-up mọi section; emoji làm icon; chatbox AI nổi; từ "AI-powered"/"thông minh" trong copy. Mỗi PR FE có mục "Checklist mùi AI" trong mô tả.

## 5. Skill / plugin FE (bật theo giai đoạn, tắt khi xong)

| Dùng | Việc | Khi |
|---|---|---|
| `frontend-design` (Anthropic, claude-plugins-official) | hướng thiết kế, hai pass (plan → review → build), checklist mùi AI | M0 prototype, M1 |
| `typesafe` (typesafe-ai) | TS strict, Zod schema API | M1+ |
| Design (Anthropic knowledge-work): `design-critique`, `accessibility-review`, `ux-copy`, `user-research`, `research-synthesis` | critique mỗi màn hình; tổng hợp phỏng vấn M0; viết copy tiếng Việt | M0, M1 |
| VectorLab UI/UX Skills: `anti-slop`, `empty-states`, `errors`, `forms`, `labels`, `loaders`, `reduced-motion`, `ux-audit` | review từng loại thành phần | M1 |
| Axe Accessibility (Deque, MCP) hoặc A11y Enforcer | quét a11y trong vòng lặp | M1 |
| Playwright MCP | E2E và chụp màn hình để tự critique | M1+ |
| `dataviz` (built-in) | biểu đồ (ít; chỉ xu hướng 7 ngày) | M1 |
| Pencil MCP (.pen) | mockup trước khi code | M0 nếu cần |
| `context7` | API shadcn/TanStack/React 19 — không đoán | luôn |

Cách dùng: mỗi màn hình đi qua **plan (frontend-design) → build → critique (design-critique + anti-slop + accessibility-review, kèm screenshot) → sửa**. Ghi lại cái đã thử trong `docs/project-map/lessons.md` để pass sau không lặp.

## 6. a11y, i18n, responsive

- WCAG 2.2 AA: contrast ≥4.5:1, focus thấy được, điều hướng bàn phím toàn bộ, bảng có header, trạng thái có chữ. axe chạy trong vitest cho mọi page.
- i18n: mọi chuỗi qua `t()`; chỉ tiếng Anh (D-28), giọng văn đơn giản, cụ thể, sentence case; số/ngày theo en-GB; không nối chuỗi.
- Responsive: desktop là chính; tablet đọc được; mobile: trang chủ + phát hiện + cảnh báo đọc được, không bắt buộc thao tác.

## 7. Cấu trúc `web/`

```
web/src/
  app/            router, layout, providers
  features/<module>/   pages, components, hooks, api (1 thư mục mỗi module; tắt module = không mount route)
  components/ui/  shadcn
  components/common/  StatusChip, SourceBadge, AiBadge, EmptyState, ErrorState, DataTable
  lib/            api client (OpenAPI → types), i18n, format
  mocks/          MSW handlers + fixtures (M0/M1)
  test/
```

Mỗi `features/<module>` có `README.md` nêu story ID nó phục vụ.
