# Reports Contract

> Tier: tuỳ chọn (tắt mặc định) · Story: S-REP-1, S-REP-2 · Last verified: 2026-11-21 (mọi câu đã đối chiếu với mã)
> Nguồn hành vi thực tế: `web/src/features/reports/{contract,types,mocks,weekly,pdpl}.ts`. Nội dung pháp lý đã đối chiếu 2026-11-06: Luật 91/2025/QH15, NĐ 356/2025/NĐ-CP.

## Invariants (luôn đúng)
- **INV-1** Số liệu báo cáo tuần **tính khi mở** từ `inventory`, findings và KEV; `sources[]` nêu nguồn và thời điểm của từng nhóm số. Số liệu không do AI sinh. Thiết bị người đã bỏ qua (ignored) và finding đóng vì thiết bị bị bỏ qua không vào báo cáo nào; số KEV chỉ lấy danh sách CISA (VulnCheck KEV ở lại trên hộp, chỉ được nêu trong `sources` khi một finding của báo cáo đến từ đó).
- **INV-13** Mỗi số của báo cáo tuần có cùng nguồn và định nghĩa với trang khác: `kev_new`/`kev_matched` = `KEV.NewlyExploited` (câu đầu trang chủ: CVE mới bị khai thác 7 ngày và số sản phẩm đang dùng trong đó, cùng bảng `GET /feeds/hot?window=7d`); `devices` = số của trang Devices (kể cả hộp Vedette: `Device.Box`; báo cáo PDPL bỏ hộp như trước); tên sản phẩm = `feeds.DisplayOf` như trang Findings (`KEVEntry.Display`). `resolved` là finding do người đóng trong 7 ngày, mỗi dòng có `by` (người đóng); finding chấp nhận rủi ro trong 7 ngày không nằm trong `resolved` mà đếm riêng `accepted` + `accepted_until` (ngày hết sớm nhất), trên **cùng tập finding** các dòng khác dùng (sản phẩm thêm tay không thiết bị cũng tính, cờ `noDevice` chỉ đổi cách viết; finding có `first_seen` sau lúc lập thì không dòng nào tính; `TestWeeklyAcceptedRiskIsNotResolved`, `TestWeeklyAcceptedCountsWhatTheRowsShow`). `top_risks` (≤ `TopRiskCount` = 3) gom finding mở theo sản phẩm (`severity` là mức nặng nhất của nhóm, `cve`/`finding_id` là finding đã quét xác nhận nếu có): có xác nhận trước, rồi mức nặng nhất, rồi nhiều finding, rồi tên; `actions` fix/verify là một việc cho mỗi rủi ro đó (`product`, `count`), rồi `review_devices`, `plan_os`. Trang đầu là số liệu, Top 3 risks, Done this week (≤ 5 dòng), To do next week; danh sách đầy đủ là phụ lục. Báo cáo lưu ở bản cũ (không `top_risks`) vẫn đọc được (INV-2). Lời nhắc AI có Top risks theo số thiết bị, không tên thiết bị. Finding `patched` do Vedette đóng vì thiết bị được cập nhật (`resolution_reason = fixed_by_update`, `resolved_by = system`; findings INV-2) là `resolved` trong tuần như mọi `patched` (chỉ `not_relevant` bị trừ khi công tắc "Include not relevant" tắt) và dòng của nó ghi `by` = "Vedette" thay vì tài khoản `system` (`weekly.go`: `ResolvedBy == "system"`). `TestWeeklyPatchedByAnUpdateIsResolvedByVedette`.
- **INV-14** `top_risks` gom theo thiết bị + sản phẩm rồi gộp các nhóm cần cùng hành động (cùng sản phẩm, cùng bản sửa); `top_risks[].action` và `actions[].text` (fix/verify) là cùng một câu, nêu thiết bị và, chỉ khi NVD nói (`findings.FixedInForAll` qua port `Remedies`): bản gần nhất, lấy từ mọi mốc kết thúc cao hơn phiên bản của thiết bị, nằm ngoài khoảng bị ảnh hưởng của MỌI finding của cùng phần mềm đã cài trên thiết bị (một nhóm = một dòng phần mềm, không theo tên sản phẩm của CISA) (không phải bản cao nhất của từng finding), "fixes N of M" chỉ đếm finding bản đó thật sự đóng, không có bản nào thì "NVD names no single release that fixes all N: check the vendor advisory" (N = 1: "NVD names no release that fixes the exploited vulnerability of …"); bản phát hành Windows Microsoft không còn cập nhật (`feature_update`) thì "Move … to a Windows release Microsoft still services (a feature update) …", bản vá chỉ có qua Extended Security Updates (`esu`) thì "Install the Extended Security Update … or move it to a Windows release Microsoft still services"; hai loại này là lớp riêng (`class()`: loại + bản), tính là việc "fix", không bao giờ gộp với thiết bị cần bản khác hay không có dữ liệu bản vá (`TestTopRisksWindowsStepsAreNotMerged`); lời nhắc của bản phân phối đi kèm; xếp hạng theo sản phẩm như `top_risks` (một sản phẩm một chỗ, các thiết bị cần bước khác nói "N more devices need another step"), bản sửa chỉ đọc cho các sản phẩm trang nêu; không có thì lời dự phòng thật (khuyến cáo nhà cung cấp / kiểm tra phiên bản). Thư: tiêu đề "N things to do this week", `What` mở bằng câu sự cố, `Action` là việc đầu, `Items` là các việc còn lại (INV-12). Báo cáo lưu ở bản cũ (không `action`/`text`/`happened`) vẫn đọc được.
- **INV-15** Dòng finding của báo cáo tuần và PDPL (`FindingRow`) có `agent` (true khi phiên bản so là phiên bản agent của chính thiết bị báo, `findings` `evidence.agent`, qua `Finding.Agent` của port `Findings`): trạng thái hiện "Detected by the agent" thay cho "Suspected", như trang Findings. Báo cáo lưu trước không có trường này vẫn đọc được (INV-2). `TestWeeklyOpenRowSaysTheAgentDetectedIt`.
- **INV-16** Hai công tắc trên trang Reports, chung cho báo cáo tuần và PDPL, nhớ theo trình duyệt (`localStorage` `vedette.reports.include`, bọc try/catch): "Include devices not in the Devices list" (mặc định bật) và "Include not relevant" (mặc định tắt; chỉ ở báo cáo tuần, vì `risks` PDPL chỉ là finding mở). Áp vào cả số tổng lẫn danh sách, trên trang, trang in (`/reports/print/*`, có cùng công tắc) và báo cáo đã gửi mở lại; mỗi tài liệu in một dòng nói đã dùng lựa chọn nào (`FiltersUsed`). Máy chủ cấp dữ liệu, trình duyệt lọc: `FindingRow.device_approved` (false = thiết bị chưa duyệt, "To review"; thiết bị inventory không biết tính là đã duyệt); `Counts.not_relevant` / `not_relevant_new` / `not_relevant_resolved` (finding "not relevant" trong số liệu, để trừ); các số `not_relevant*` bỏ đi khi bằng 0 (`omitempty`) để báo cáo cũ đọc lại từ lịch sử vẫn không có chúng (`TestHistoryEntryKeepsTheNotRelevantCountsAsSent`); `WeeklyReport.approved_only` = `counts`, `top_risks`, `actions` tính lại chỉ trên thiết bị đã duyệt và finding của chúng (không có `review_devices`; `kev_matched` bỏ các sản phẩm KEV mới chỉ có trên thiết bị chưa duyệt, `kev_new` giữ nguyên); `PdplReport.approved_only` = `inventory`, `measures`, `risks` như vậy, nhưng biện pháp `unapproved` giữ của bản đầy đủ (bỏ thiết bị khỏi khung nhìn không có nghĩa là đã duyệt chúng). Báo cáo lưu trước không có các trường này: thiết bị luôn được tính, "not relevant" trừ theo dòng như trước. Email và nhận xét AI dùng số liệu đầy đủ. `TestWeeklyApprovedOnlyView`, `TestWeeklyCountsNotRelevant`, `TestPdplApprovedOnlyView`, `web/src/features/reports/includeToggles.test.tsx`.
- **INV-17** Báo cáo định kỳ (hợp đồng `contract.ts`: `ReportDefinition`, `ReportDocument`, `SentReport`; máy chủ chưa có, các endpoint dưới đây trả 501 `not_implemented` qua `server.Fallback` cho tới khi có): **một** định nghĩa (một mẫu, công tắc từng mục `options.sections`, kỳ `last_7_days | last_30_days | calendar_month` = tháng trọn gần nhất, nhóm `device | cve`, `include_not_added` mặc định bật, `include_not_relevant` mặc định tắt, `charts`, ≤ 20 người nhận). Lịch gửi **không** nằm trong định nghĩa: là một lịch chung, khoá chủ `schedule_key = reports.def:<id>` (`GET/PUT /schedules/{owner_key}`). Tài liệu có các mục Summary, Handled (ai và cách nào từ trường lưu: `status`, `via`, `by`, `from_version → to_version`), Still open, New, External exposure, Detections, Coverage; mục tắt thì vắng; trạng thái dùng đúng bộ mã chung của findings (`under_attack`, `exploited`, `public_exploit`, `critical_edge`, `update_recommended`, `patched`, `mitigated`, `accepted`, `not_relevant`, `false_positive`). Báo cáo đã gửi lưu cả tài liệu (`SentReport.document`), mở lại đúng như đã gửi. Kiểm: `web/src/features/reports/conformance.test.ts`.
- **INV-2** Mục lịch sử gửi (`rep_history`) giữ **nguyên số liệu của tuần đó** (`HistoryEntry.report`); mở lại/in lại không tính lại.
- **INV-3** Lịch: `day` ∈ 1..7 (1=Thứ Hai), `hour` 0..23, `recipients` ≤ 20 email, mỗi địa chỉ ≤ 120 ký tự và hợp lệ (kiểm ở biên, SYS-2); `next_run` tính từ lịch, `null` khi tắt. `day`/`hour` đọc theo múi giờ của tổ chức (`Config.Zone`, cmd/vedette `orgZone`; cột `zone` của `rep_schedule` ghi múi giờ đã dùng): khi múi giờ đổi, job đặt lại mốc từ lúc đó thay vì gửi lần hai trong tuần. Lịch tuần này là lịch riêng của module (bảng `rep_schedule`, job `weekly-send`), không đi qua `core/schedule`. Trạng thái gửi ∈ {sent, failed}, `trigger` ∈ {manual, scheduled}, lỗi ghi rõ (`error`).
- **INV-4** Gửi email chỉ qua kênh email của `notify` (SMTP của khách, PRIVACY luồng 5); không SMTP riêng của module.
- **INV-5** Nhận xét AI (`AiSummary`) chỉ do module `ai` sinh (`weekly-report`, `pdpl-assessment`), luôn hiển thị trong khối "AI tạo" và **không thay đổi số liệu**; tuân luật dữ liệu nội bộ vì báo cáo chứa dữ liệu thiết bị. Không có AI → báo cáo vẫn đầy đủ, `ai_available=false`.
- **INV-6** Báo cáo PDPL: chế độ nghĩa vụ (`Obligation.regime`: required/optional/exempt) cho `dpia`, `dpo` được **tính tất định** từ quy mô tổ chức (`size`, theo Điều 38 Luật 91/2025/QH15 và Điều 41 NĐ 356/2025/NĐ-CP), không do AI quyết; các nghĩa vụ còn lại luôn bắt buộc. Cấp độ hệ thống thông tin (`level` 1..5 hoặc rỗng) là chế độ riêng, không thuộc Luật BVDLCN.
- **INV-7** Mọi báo cáo PDPL mang câu miễn trừ "hỗ trợ đánh giá, không phải tư vấn pháp lý" và nêu nguồn pháp lý; câu này không gỡ được (`LEGAL.md`).
- **INV-8** `PdplOrg` kiểm từng trường khi lưu (`PUT /reports/pdpl/org`); `measures` (firewall, patching, eol, unapproved, remote, logging, honeypot, scan, backup) mang `status ∈ {ok, attention, unknown}` — thiếu dữ liệu vì module tắt là `unknown`, **không bao giờ `ok`**; `coverage[]` nêu module nào đang bật.
- **INV-9** Báo cáo tuần có `happened` (sự cố 7 ngày: chạm bẫy, đăng nhập sai, đăng nhập được chấp nhận sau khi sai, kết nối xấu, bất thường khác; `summary` + tối đa 3 dòng) đọc qua port `Incidents` từ `notify` (đăng nhập được chấp nhận trước ngưỡng cũng mang tiêu đề "was ACCEPTED", `modules/logs/authfail.go`) (không đọc bảng `notify_*`); `notify` tắt → `happened` null và `sources` không có `incidents`. Sự cố thiết bị mới không tính (trang Devices đã nói). `sources[].at` của `kev` là lần kéo CISA KEV thành công gần nhất (feeds tắt: giờ dựng báo cáo, không có số KEV).
- **INV-11** Kích thước có trần: mỗi danh sách của báo cáo tuần ≤ 100 dòng cho mỗi khung nhìn (INV-16; danh sách gửi đi giữ 100 dòng đầu của từng khung nhìn — tất cả, chỉ thiết bị đã duyệt, bỏ "not relevant", cả hai — nên ≤ 400 dòng, `capViews`; trình duyệt cắt lại 100 sau khi lọc; rủi ro PDPL ≤ 100), hệ thống trọng yếu PDPL ≤ 50, lịch sử gửi 52 mục; số đếm luôn của toàn bộ. Chuỗi từ mạng (tên thiết bị, sản phẩm) được làm sạch (ký tự điều khiển/bidi, một dòng, giới hạn độ dài) trước khi vào báo cáo.
- **INV-12** Máy chủ không dựng HTML/PDF: thư gửi là bản tóm tắt chữ thường qua `notify.SendReport` kèm liên kết `/reports`. Lời nhắc AI của PDPL không chứa tên, mã số thuế, địa chỉ, người liên hệ.
- **INV-10** Mọi mutation (lịch, thông tin tổ chức, gửi) ghi `core_audit` (SYS-3). PDF không sinh ở máy chủ: trang in `/reports/print/weekly[/:id]`, `/reports/print/pdpl` là route SPA.

## Preconditions (trước khi gọi)
- **PRE-1** `PUT /reports/schedule`: vai admin. `POST /reports/weekly/send`: vai operator, có ≥ 1 người nhận (400 `no_recipients`) và kênh email của `notify` bật (409 `email_not_ready`); thiếu → lỗi nêu rõ, không gửi, không ghi lịch sử.
- **PRE-2** `POST /reports/*/ai-summary`: module `ai` bật và việc tương ứng có hồ sơ được phép (409 `ai_unavailable`).
- **PRE-3** `POST /reports/pdpl/generate`: đã lưu thông tin tổ chức hợp lệ (409 `org_required`). `POST /reports/pdpl/ai-summary` cần báo cáo đã sinh (409 `report_required`); nếu báo cáo được sinh lại trong lúc AI đang viết thì 409 `report_changed` và không lưu nhận xét.

## Postconditions (sau khi xong)
- **POST-1** Gửi xong: một mục `rep_history` (`sent`/`failed`), email tới đúng danh sách người nhận lúc gửi.
- **POST-2** Lịch bật: đến `next_run` tự sinh và gửi, ghi `trigger=scheduled`; mỗi ô giờ xử lý tối đa một lần (đánh dấu trước khi gửi); bỏ lỡ do hộp/module tắt → gửi bù đúng một lần nếu trễ ≤ 24 giờ, quá thì bỏ ô; lưu lịch đặt lại mốc, không gửi bù ô đã qua.
- **POST-3** `generate` PDPL: sinh `PdplReport` từ kho thiết bị, findings, trạng thái module; có `generated_at`; mục "key_systems", "by_kind", "sources" khớp kho tại lúc sinh.
- **POST-4** Nhận xét AI lưu tại `rep_weekly_ai`/`rep_pdpl`, ghi một mục `ai_activity` qua module `ai`.

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
| GET | `/reports/definition` | viewer | S-REP-1 |
| PUT | `/reports/definition` | admin | S-REP-1 |
| GET | `/reports/document` | viewer | S-REP-1 |
| POST | `/reports/send` | operator | S-REP-1 |
| GET | `/reports/history` | viewer | S-REP-1 |
| GET | `/reports/history/{id}` | viewer | S-REP-1 |

## Tables owned
`rep_schedule`, `rep_history`, `rep_weekly_ai`, `rep_pdpl`.

## Events
- **Phát**: không phát sự kiện bus; mọi thay đổi và mỗi lần gửi ghi `core_audit` (`report.schedule`, `report.send`, `report.pdpl_org`, `report.pdpl_generate`, `report.ai_summary`). `notify` chưa đăng ký `reports.report.ready` (chưa có người cần).
- **Nhận**: job `weekly-send` (1 phút một lần) từ `core/jobs`. Không nhận sự kiện của module khác.

## Khi tắt module (SYS-5)
Không route `/reports/*`, không job gửi theo lịch. Trang Reports "module đang tắt". `rep_*` (lịch, lịch sử, thông tin tổ chức, báo cáo đã sinh) giữ nguyên; bật lại thì lịch tiếp tục, không gửi bù hàng loạt.

## Ports (cmd/vedette/reports.go)
`Inventory.Devices` (kể cả hộp, `Device.Box`; `Device.NoDevice` = sản phẩm thêm tay không thiết bị, câu việc cần làm không nhắc tên nó hai lần), `Findings.All` (+ `ResolvedBy`), `KEV.Entries` (+ giờ kéo, `Display`), `KEV.NewlyExploited` (feeds), `Remedies.Fixes` (findings.FixedInForAll + inventory.MatchInput), `Incidents.Week` (notify.IncidentsSince: đếm cả tuần bằng SQL), `Mailer.Ready/Send` (notify), `AI.Available/Summarize` (ai: `ai.Service.RunJob`, việc `weekly-report`, `pdpl-assessment`), `Modules.Enabled`. Reports không đọc bảng của module khác.

## Dependencies
- **DEPENDS ON**: `core` (jobs, audit, múi giờ tổ chức qua `Config.Zone`), `inventory` (thiết bị, nguồn kiểm kê), `feeds` (KEV), `notify` (gửi, mềm nhưng cần để gửi), `ai` (nhận xét, mềm), `scan`/`logs`/`honeypot` (mềm, mở rộng số liệu).
- **DEPENDED ON BY**: không module nào đọc dữ liệu của `reports`; `ai` khai báo hai việc `weekly-report`, `pdpl-assessment` (`modules/ai/jobs.go`, `skills.go`), `core/server/modules.go` định tuyến `/reports/*` theo module này. `core/logs export` không dùng.

## Câu hỏi mở
1. *(đã chốt: `notify` là phụ thuộc mềm, không gửi được khi `notify` tắt)* `docs/MODULES.md` liệt `reports` phụ thuộc `inventory, feeds (+scan, logs)` mà không có `notify`, trong khi gửi theo lịch cần kênh email. Đề xuất: thêm `notify` vào `depends` hoặc ghi rõ "không gửi được khi `notify` tắt" (đã làm ở `soft_depends`).
2. *(đã chốt: qua sự cố của `notify`)* `honeypot`/`logs` cần phơi dữ liệu thống kê qua interface (số chạm bẫy, bất thường/tuần) nếu muốn đưa vào báo cáo tuần.
3. *(đã chốt: một lần trong 24 giờ)* Gửi bù khi hộp tắt đúng giờ lịch: có hay không?
4. *(đã chốt: in-ra-PDF của trình duyệt)* S-REP-2 nói "xuất PDF"; mock chỉ in qua trình duyệt (không có tệp PDF từ máy chủ). Chấp nhận in-to-PDF hay cần PDF phía máy chủ (khi đó thêm dependency → `THIRD_PARTY_NOTICES.md`)?
5. *(đã chốt: không đưa vào lời nhắc AI)* `PdplOrg` có tên, email, điện thoại người liên hệ: có được đưa vào prompt của AI không? Hook `block-pii` sẽ che; cần quyết định có gửi trường này hay không.
