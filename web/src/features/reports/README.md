# features/reports

Story: S-REP-1 (báo cáo tuần 1 trang: xem trước, lịch gửi, người nhận, gửi ngay, lịch sử, in/lưu PDF), S-REP-2 (đánh giá an toàn theo Luật BVDLCN: form tổ chức, sinh mục từ kiểm kê và phát hiện, câu miễn trừ "hỗ trợ đánh giá, không phải tư vấn pháp lý", in/lưu PDF).
Không cung cấp và không tiêu thụ slot. Trang in: `/reports/print/weekly[/:id]`, `/reports/print/pdpl` (CSS `@media print` + `window.print()`, không thư viện PDF).
Bảng riêng: `rep_schedule`, `rep_history`, `rep_weekly_ai`, `rep_pdpl`. Đọc `assetsStore`, `findingsStore`, KEV thật. KHÔNG có số lần chạm bẫy / bất thường log: dữ liệu đó thuộc module honeypot/logs và chưa có store dùng chung (cần nếu muốn đưa vào báo cáo tuần). Hợp đồng API: `contract.ts` → `types.ts`.
Nhận xét AI chỉ hiện trong `AiBlock`, ghi `recordAiRun` (không đi qua trần token của module ai, vì trần nằm trong mock của module đó).
Nội dung pháp lý (D-23) đã đối chiếu 2026-11-06 với Luật 91/2025/QH15 và Nghị định 356/2025/NĐ-CP (Công báo số 18, 18/01/2026): số Điều của Nghị định đọc thẳng từ Công báo; số Điều của Luật qua toàn văn trên cơ sở dữ liệu pháp luật. Quy mô tổ chức quyết định Điều 21, 22, khoản 2 Điều 33 theo Điều 41 NĐ 356 (`regimeOf` trong `pdpl.ts`). Cấp độ an toàn hệ thống thông tin (1-5) là quy định riêng, không thuộc Luật BVDLCN.
