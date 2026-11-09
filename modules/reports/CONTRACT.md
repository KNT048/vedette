# Reports Contract

> Tier: tuỳ chọn (tắt mặc định) · Story: S-REP-1, S-REP-2 · Quyết định: D-18, D-23, D-29 · Last verified: 2026-11-09
> Nguồn hành vi thực tế: `web/src/features/reports/{contract,types,mocks,weekly,pdpl}.ts`. Nội dung pháp lý đã đối chiếu 2026-11-06 (D-23): Luật 91/2025/QH15, NĐ 356/2025/NĐ-CP.

## Invariants (luôn đúng)
- **INV-1** Số liệu báo cáo tuần **tính khi mở** từ `inventory`, findings và KEV; `sources[]` nêu nguồn và thời điểm của từng nhóm số. Số liệu không do AI sinh.
- **INV-2** Mục lịch sử gửi (`rep_history`) giữ **nguyên số liệu của tuần đó** (`HistoryEntry.report`); mở lại/in lại không tính lại.
- **INV-3** Lịch: `day` ∈ {mon..sun}, `hour` 0..23, `recipients` ≤ 20 email, mỗi địa chỉ ≤ 120 ký tự và hợp lệ (kiểm ở biên, SYS-2); `next_run` tính từ lịch, `null` khi tắt. Trạng thái gửi ∈ {sent, failed}, `trigger` ∈ {manual, scheduled}, lỗi ghi rõ (`error`).
- **INV-4** Gửi email chỉ qua kênh email của `notify` (SMTP của khách, PRIVACY luồng 5); không SMTP riêng của module.
- **INV-5** Nhận xét AI (`AiSummary`) chỉ do module `ai` sinh (`weekly-report`, `pdpl-assessment`), luôn hiển thị trong khối "AI tạo" và **không thay đổi số liệu**; tuân luật dữ liệu nội bộ (D-29) vì báo cáo chứa dữ liệu thiết bị. Không có AI → báo cáo vẫn đầy đủ, `ai_available=false`.
- **INV-6** Báo cáo PDPL: chế độ nghĩa vụ (`Obligation.regime`: required/optional/exempt) cho `dpia`, `dpo` được **tính tất định** từ quy mô tổ chức (`size`, theo Điều 38 Luật 91/2025/QH15 và Điều 41 NĐ 356/2025/NĐ-CP), không do AI quyết; các nghĩa vụ còn lại luôn bắt buộc. Cấp độ hệ thống thông tin (`level` 1..5 hoặc rỗng) là chế độ riêng, không thuộc Luật BVDLCN.
- **INV-7** Mọi báo cáo PDPL mang câu miễn trừ "hỗ trợ đánh giá, không phải tư vấn pháp lý" và nêu nguồn pháp lý; câu này không gỡ được (D-26, `LEGAL.md`).
- **INV-8** `PdplOrg` kiểm từng trường khi lưu (`PUT /reports/pdpl/org`); `measures` (firewall, patching, eol, unapproved, remote, logging, honeypot, scan, backup) mang `status ∈ {ok, attention, unknown}` — thiếu dữ liệu vì module tắt là `unknown`, **không bao giờ `ok`**; `coverage[]` nêu module nào đang bật.
- **INV-9** Báo cáo tuần chưa gồm số lần chạm bẫy và bất thường log (`sources` chỉ `inventory`, `findings`, `kev`) tới khi có interface dữ liệu từ `honeypot`/`logs` (câu hỏi mở 2).
- **INV-10** Mọi mutation (lịch, thông tin tổ chức, gửi) ghi `core_audit` (SYS-3). PDF không sinh ở máy chủ: trang in `/reports/print/weekly[/:id]`, `/reports/print/pdpl` là route SPA.

## Preconditions (trước khi gọi)
- **PRE-1** `PUT /reports/schedule`: vai admin. `POST /reports/weekly/send`: vai operator, có ≥ 1 người nhận và kênh email của `notify` bật; thiếu → lỗi nêu rõ, không gửi.
- **PRE-2** `POST /reports/*/ai-summary`: module `ai` bật và việc tương ứng có hồ sơ được phép (409 `ai_unavailable`).
- **PRE-3** `POST /reports/pdpl/generate`: đã lưu thông tin tổ chức hợp lệ.

## Postconditions (sau khi xong)
- **POST-1** Gửi xong: một mục `rep_history` (`sent`/`failed`), email tới đúng danh sách người nhận lúc gửi.
- **POST-2** Lịch bật: đến `next_run` tự sinh và gửi, ghi `trigger=scheduled`; bỏ lỡ do hộp tắt → gửi bù tối đa một lần ở lần chạy kế (S-REP-1 "gửi tự động"). *(đề xuất, câu hỏi mở 3)*
- **POST-3** `generate` PDPL: sinh `PdplReport` từ kho thiết bị, findings, trạng thái module; có `generated_at`; mục "key_systems", "by_kind", "sources" khớp kho tại lúc sinh.
- **POST-4** Nhận xét AI lưu tại `rep_weekly_ai`/`rep_pdpl`, ghi một mục `ai_activity` (D-48) qua module `ai`.

## Forbidden (không bao giờ)
- **FORBID-1** AI sửa số liệu hoặc kết luận pháp lý; nhận xét AI không có nhãn "AI tạo".
- **FORBID-2** Gửi báo cáo tới địa chỉ không nằm trong `recipients` đã lưu.
- **FORBID-3** Phát biểu "đạt chuẩn/tuân thủ" khi `measures` còn `unknown` hoặc `attention`.
- **FORBID-4** Đọc bảng của module khác trực tiếp (dùng interface, IMPACT).
- **FORBID-5** Thư viện/dịch vụ PDF ngoài hoặc tài nguyên từ CDN trong trang in (legal.md).

## Endpoints owned (từ `contract.ts`)
| Method | Path | Vai tối thiểu | Story |
|---|---|---|---|
| GET | `/reports/weekly/preview` | viewer | S-REP-1 |
| POST | `/reports/weekly/ai-summary` | operator | S-REP-1 |
| GET | `/reports/schedule` | viewer | S-REP-1 |
| PUT | `/reports/schedule` | admin | S-REP-1 |
| GET | `/reports/weekly/history` | viewer | S-REP-1 |
| GET | `/reports/weekly/history/{id}` | viewer | S-REP-1 |
| POST | `/reports/weekly/send` | operator | S-REP-1 |
| GET | `/reports/pdpl` | viewer | S-REP-2 |
| PUT | `/reports/pdpl/org` | operator | S-REP-2 |
| POST | `/reports/pdpl/generate` | operator | S-REP-2 |
| POST | `/reports/pdpl/ai-summary` | operator | S-REP-2 |

## Tables owned
`rep_schedule`, `rep_history`, `rep_weekly_ai`, `rep_pdpl`.

## Events
- **Phát**: `report.sent` (tên đề xuất) cho nhật ký.
- **Nhận**: tick lịch từ `core/jobs`. Không nhận sự kiện của module khác.

## Khi tắt module (SYS-5)
Không route `/reports/*`, không job gửi theo lịch. Trang Reports "module đang tắt". `rep_*` (lịch, lịch sử, thông tin tổ chức, báo cáo đã sinh) giữ nguyên; bật lại thì lịch tiếp tục, không gửi bù hàng loạt.

## Dependencies
- **DEPENDS ON**: `core` (jobs, audit), `inventory` (thiết bị, nguồn kiểm kê), `feeds` (KEV), `notify` (gửi, mềm nhưng cần để gửi), `ai` (nhận xét, mềm), `scan`/`logs`/`honeypot` (mềm, mở rộng số liệu).
- **DEPENDED ON BY**: không module nào. `core/logs export` không dùng.

## Câu hỏi mở
1. `docs/MODULES.md` liệt `reports` phụ thuộc `inventory, feeds (+scan, logs)` mà không có `notify`, trong khi gửi theo lịch cần kênh email. Đề xuất: thêm `notify` vào `depends` hoặc ghi rõ "không gửi được khi `notify` tắt" (đã làm ở `soft_depends`).
2. `honeypot`/`logs` cần phơi dữ liệu thống kê qua interface (số chạm bẫy, bất thường/tuần) nếu muốn đưa vào báo cáo tuần.
3. Gửi bù khi hộp tắt đúng giờ lịch: có hay không?
4. S-REP-2 nói "xuất PDF"; mock chỉ in qua trình duyệt (không có tệp PDF từ máy chủ). Chấp nhận in-to-PDF hay cần PDF phía máy chủ (khi đó thêm dependency → `THIRD_PARTY_NOTICES.md`)?
5. `PdplOrg` có tên, email, điện thoại người liên hệ: có được đưa vào prompt của AI không? Hook `block-pii` sẽ che; cần quyết định có gửi trường này hay không.
