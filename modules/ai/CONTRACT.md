# AI Contract

> Tier: tuỳ chọn (tắt mặc định) · Story: S-AI-1..8 (+ S-RESP-1 qua việc `response-plan`) · Quyết định: D-11, D-29, D-39, D-41, D-48, D-51 · Last verified: 2026-11-09
> Nguồn hành vi thực tế: `web/src/features/ai/{contract,types,mocks,harness,harness-mocks,activity}.ts`, `web/src/mocks/stores.ts` (`AI_JOBS`).

## Invariants (luôn đúng)

### Hồ sơ, phân việc, dữ liệu nội bộ (D-29)
- **INV-1** Khoá API lưu qua `core/secrets` (AES-GCM); API chỉ trả `key_last4`; không log, không export (SYS-4). `key_last4 = null` hợp lệ chỉ với `location=internal` (`usable = key ≠ null ∨ location = internal`).
- **INV-2** Mười việc AI (`AiJob`): explain-finding, mitigation-config, cve-news, log-digest, log-investigate, ask-my-data, weekly-report, pdpl-assessment, translate-advisory, response-plan. Mỗi việc có một hồ sơ chính và một dự phòng. Chuyển sang dự phòng khi hồ sơ chính lỗi, quá thời gian, hết trần riêng hoặc bị luật riêng tư loại; tên hồ sơ và `fallback=true` ghi vào kết quả và `ai_runs`.
- **INV-3** **Quy tắc dữ liệu nội bộ**: các việc gửi log/dữ liệu thiết bị (mọi việc trừ `cve-news`, `translate-advisory`) khi `assignments.internal_only = true` chỉ được gán và chỉ được gọi tới hồ sơ `location=internal`. Chặn ở **hai nơi**: `PUT /ai/assignments` từ chối gán sai; lúc chạy, hồ sơ cloud không bao giờ nhận dữ liệu loại này, kể cả khi failover. Không còn hồ sơ hợp lệ → 409 `ai_unavailable` với lý do rõ, không im lặng chuyển sang cloud. Test: `TestContract_INV3_InternalOnlyNeverReachesCloud`.
- **INV-4** Mức token ∈ {min, med, max}; trần chung `daily_cap` 1.000..5.000.000; trần riêng từng hồ sơ cùng khoảng. Vượt trần chung → tự hạ mức và ghi `ai_downgrades` + `core_audit`. Không hiện tiền (D-6). Ước lượng/ngày: min ≈ 10.000, med ≈ 60.000, max = `null` (phụ thuộc số cảnh báo). Hạ mức không bao giờ tăng quyền (max → med → min).
- **INV-5** Mọi output AI mang `model`, `profile`, `tokens` và hiển thị nhãn "AI tạo, cần người xác nhận" (S-AI-6); không có nút hành động trực tiếp trên output AI. Output AI không bao giờ hiển thị như khuyến nghị đã xác nhận (S-MIT-1, D-21).
- **INV-6** Cache: `GET /ai/cve/{id}/cached` không gọi AI; `explain`/`news` mới tốn token. `news`: **hộp** fetch advisory/GitHub PoC/RSS, AI chỉ tóm tắt (S-AI-3); AI không tự duyệt web.

### Harness (D-39)
- **INV-7** Luật dựng sẵn (`br-scope`, `br-evidence`, `br-readonly`, `br-untrusted`) luôn đưa vào mọi lần gọi, không sửa/xoá/tắt được. Luật tuỳ chỉnh: 3..300 ký tự, `jobs=[]` nghĩa là mọi việc.
- **INV-8** Memory: AI chỉ **đề xuất** (`MemorySuggestion`); một đề xuất chưa được admin chấp nhận (`accept`) thì không vào ngữ cảnh. Mục memory 3..300 ký tự, xem/sửa/xoá/tắt được; `suggest_enabled=false` → AI không đề xuất.
- **INV-9** Skill là skill **của sản phẩm** (`skills/`, ký trong content pack); bật/tắt được; không phải skill Claude Code (D-13).
- **INV-10** Kho tri thức: PDF/MD/TXT/DOCX ≤ 10 MB; trạng thái `uploading → indexing → ready`; chỉ mục nằm trên hộp; mỗi tài liệu chọn việc nào được dùng (`jobs`); xoá tài liệu xoá cả chỉ mục. Tài liệu của khách là dữ liệu nội bộ: áp dụng INV-3 cho hồ sơ dựng chỉ mục (`index_profile`).
- **INV-11** Kết nối ngoài (`Connector`: device-api, ssh, http, mcp-http, mcp-stdio): có `allow` (host/URL prefix/lệnh được dùng); bí mật mã hoá, chỉ `last4`; mỗi công cụ là `read` hoặc `write` và bật/tắt riêng. Chỉ đi tới đích nằm trong `allow` (SYS-7). Lệnh SSH/process chỉ qua `core/exec` với allowlist (SYS-1). `mcp-stdio` chạy tiến trình theo allowlist argv, không shell.
- **INV-12** Hook chặn có ba thời điểm (`before_ai`, `after_ai`, `before_tool`) và ba hành động (`block`, `mask`, `approve`). Hook dựng sẵn: `block-pii` (che email/số điện thoại/tên cạnh tài khoản; chặn số định danh 9 hoặc 12 chữ số), `security-only`, và **`write-approval` khoá luôn bật** (`locked=true`, tắt → 400 `locked`). Hook tuỳ chỉnh theo từ khoá (phân tách bằng dấu phẩy) hoặc regex, mẫu 1..200 ký tự, tên 1..40, thông báo 3..200 ký tự; thực thi hook có giới hạn thời gian (SYS-6, mẫu do khách nhập).
- **INV-13** Một câu hỏi bị chặn không được lưu nguyên văn (`[question hidden: contains personal data]`) và không tốn token.

### SYS-8: AI không có công cụ ghi
- **INV-14** Bộ công cụ mà mô hình **nhìn thấy** chỉ gồm công cụ `access=read` (tra tài sản, phát hiện, feed, log, kết nối chỉ-đọc). Công cụ `write` của kết nối **không bao giờ** được đưa vào danh sách công cụ gửi cho mô hình, không phụ thuộc cấu hình hay hook tuỳ chỉnh. Test: `TestContract_INV14_NoWriteToolInModelToolList`.
- **INV-15** Hook `write-approval` khoá: bất kỳ lời gọi công cụ ghi nào (kể cả nếu lọt tới `before_tool`) chỉ đi tiếp qua một hành động đã được người duyệt trong module `response`. Đây là **ngoại lệ duy nhất** của SYS-8 (D-41), thực thi và ràng buộc hoàn toàn trong `response` (xem `modules/response/CONTRACT.md`); module `ai` không tự thực thi ghi.
- **INV-16** AI gửi yêu cầu phản ứng chỉ bằng `POST /response/ai/proposals` (tên hành động + tham số có kiểu + bằng chứng); không gửi lệnh. Mọi chốt chặn nằm ở `response`, không ở prompt.

### Nhật ký AI, chống sửa (D-48)
- **INV-17** Mọi lần gọi AI (kể cả bị hook chặn, dùng dự phòng, lỗi) tạo đúng một `ActivityEntry`: `job, profile, model, trigger, hooks[], tools[] (read|write, tham số đã tóm tắt, không bí mật), input_hash, output_hash, summary, tokens, result, links[]`. Nội dung gửi/nhận **không lưu**, chỉ hash.
- **INV-18** Chuỗi hash: `hash = SHA-256(prev_hash + JSON chuẩn hoá khoá-sắp-xếp của entry không có hash)`. Không có endpoint sửa/xoá entry. `GET /ai/activity/verify` trả `ok` hoặc `broken_at` (vị trí 1-based) và `entry_id`.
- **INV-19** Giữ mặc định 365 ngày, tối thiểu 90 (`retention_days ≥ 90`); entry chỉ biến mất theo hết hạn lưu giữ, không theo yêu cầu sửa/xoá.
- **INV-20** Mọi mutation cấu hình (hồ sơ, phân việc, rule, memory, skill, tri thức, kết nối, hook) ghi `core_audit` (SYS-3).
- **INV-21** Dữ liệu từ log/feed/web/tài liệu đưa vào prompt là không tin cậy (SYS-6): được bọc rõ là dữ liệu, kèm luật `br-untrusted`; AI trả theo schema.

## Preconditions (trước khi gọi)
- **PRE-1** Chạy một việc AI cần: module `ai` bật, ≥ 1 hồ sơ usable, việc đó có hồ sơ được phép (INV-3). Thiếu → 409 `ai_unavailable` kèm lý do.
- **PRE-2** `POST /ai/ask` câu hỏi 3..500 ký tự, vai operator; qua hook `before_ai` rồi mới tới AI.
- **PRE-3** `POST /ai/profiles` `daily_cap` 1.000..5.000.000, `name` 1..40 ký tự, vai admin. Thử (`/ai/profiles/test`) gửi một lệnh nhỏ và trả `latency_ms`, token, khả năng (`tools`, `structured`).

## Postconditions (sau khi xong)
- **POST-1** `ask`: `AskResult` có `answer`, bảng kết quả (nếu có) tính từ công cụ chỉ-đọc, `tool_calls` đầy đủ, `hooks` liệt kê hook đã tác động (rỗng nếu không), `downgraded` nếu có (S-AI-5).
- **POST-2** `explain` (S-AI-2): `affected ∈ {yes,no,unknown}`, bước vá đúng phiên bản, vá tạm, dấu hiệu, có nguồn (`citations`) và token đã dùng.
- **POST-3** Log digest (S-AI-4): không có sự kiện log → `empty=true`, **không gọi AI, không tốn token**.
- **POST-4** Xoá hồ sơ đang được gán → các việc đó bị bỏ gán rõ ràng và UI nêu việc nào mất hồ sơ; không im lặng chuyển hồ sơ khác.
- **POST-5** Mỗi lần chạy ghi `ai_runs` (`skill, model, tokens, status ∈ {ok, schema_error, capped}`) và một `ActivityEntry` (INV-17).

## Forbidden (không bao giờ)
- **FORBID-1** Công cụ ghi trong danh sách công cụ của mô hình (INV-14).
- **FORBID-2** Gửi dữ liệu nội bộ tới hồ sơ cloud khi `internal_only` bật (INV-3).
- **FORBID-3** Gỡ hook `write-approval`, tắt luật dựng sẵn, hoặc sửa/xoá entry nhật ký (INV-7, INV-12, INV-18).
- **FORBID-4** Trả khoá API/bí mật kết nối qua API, log, export, nhật ký AI (SYS-4).
- **FORBID-5** AI tự duyệt, tự thực thi, hoặc tạo yêu cầu không qua `response` (INV-16).
- **FORBID-6** AI tự duyệt web; việc lấy tin do hộp thực hiện (INV-6).
- **FORBID-7** Hiển thị output AI mà không có nhãn "AI tạo" (INV-5).

## Endpoints owned (từ `contract.ts`)
| Method | Path | Vai tối thiểu |
|---|---|---|
| GET | `/ai/config`, `/ai/profiles`, `/ai/assignments`, `/ai/assignments/suggestion`, `/ai/usage`, `/ai/runs`, `/ai/asks`, `/ai/cve/{id}/cached`, `/ai/logs/digest` | viewer |
| POST | `/ai/ask`, `/ai/cve/{id}/explain`, `/ai/cve/{id}/news`, `/ai/logs/digest` | operator |
| GET | `/ai/activity`, `/ai/activity/verify` | operator |
| PUT | `/ai/config` | admin |
| POST/PUT/DELETE | `/ai/profiles`, `/ai/profiles/{id}` ; POST `/ai/profiles/test` | admin |
| PUT | `/ai/assignments` | admin |
| GET/PUT | `/ai/activity/settings` | admin |
| GET/POST, PUT/DELETE | `/ai/rules`, `/ai/rules/{id}` | admin |
| GET/POST, PUT/DELETE | `/ai/memory`, `/ai/memory/{id}`; PUT `/ai/memory/settings`; POST `/ai/memory/suggestions/{id}/accept\|reject` | admin |
| GET, PUT | `/ai/skills`, `/ai/skills/{id}` | admin |
| GET/POST, PUT/DELETE | `/ai/knowledge`, `/ai/knowledge/{id}`; PUT `/ai/knowledge/settings` | admin |
| GET/POST, PUT/DELETE | `/ai/connections`, `/ai/connections/{id}`; POST `/ai/connections/{id}/test` | admin |
| GET, POST, PUT/DELETE | `/ai/hooks`, `/ai/hooks/{id}`; PUT `/ai/hooks/builtin/{id}`; POST `/ai/hooks/test` | admin |

Việc `response-plan` (kế hoạch phản ứng) do `ai` chạy; endpoint `/response/plans` thuộc `response`.

## Tables owned
`ai_config, ai_profiles, ai_assign, ai_runs, ai_sample_runs, ai_downgrades, ai_explains, ai_news, ai_asks, ai_log_digests` (S-AI-1..6); `ai_rules, ai_memory, ai_memory_suggestions, ai_memory_settings, ai_skills, ai_knowledge, ai_knowledge_settings, ai_hooks, ai_hooks_builtin, ai_connectors` (harness); `ai_activity, ai_activity_settings` (D-48). `ai_sample_runs` chỉ có trong bản xem trước.

## Events
- **Phát**: `ai.activity` (mỗi entry; tên đề xuất) cho export log; `ai.downgrade` (cũng đi vào `core_audit`).
- **Nhận**: yêu cầu việc từ `core` (UI), `reports` (`weekly-report`, `pdpl-assessment`), `response` (`response-plan`), `mitigation` (`mitigation-config`).

## Khi tắt module (SYS-5)
Không route `/ai/*`, không gọi provider, không job. Nút "Giải thích", "Hỏi AI của tôi", digest AI, nhận xét AI trong báo cáo, kế hoạch AI của `response` biến mất hoặc báo "module `ai` đang tắt". Hồ sơ, rule, memory, tri thức, nhật ký giữ nguyên (chuỗi hash vẫn kiểm được). **Kết nối ngoài (`ai_connectors`) vẫn là dữ liệu mà `response` cần**: tắt `ai` thì `response` không thể chạy hành động lên thiết bị (xem `response/CONTRACT.md`).

## Dependencies
- **DEPENDS ON**: `core` (`core/secrets`, `core/exec`, audit, scheduler), `feeds`/`inventory`/`logs`/`scan`/`notify` (dữ liệu, mềm).
- **DEPENDED ON BY**: `response` (kết nối, `response-plan`), `reports` (nhận xét AI), `mitigation` (hỏi AI khi chưa có khuyến nghị đã xác nhận), `logs` (digest AI), GUI `findings`/`cve` (panel `cve.panels`), `mcp-server` (không), `core/logs export` (`ai_activity`).

## Câu hỏi mở
1. README của GUI nói "9 việc" còn `contract.ts` có 10 (`response-plan`): sửa README.
2. Hai chuỗi hash khác công thức: `ai_activity` (JSON khoá-sắp-xếp, không có `\n`) và `resp_log` (`prev_hash\nJSON([id,ts,kind,actor,detail])`). Giữ khác hay thống nhất (một helper trong `core`)? Trình xác minh offline (S-CORE-6) phải biết cả hai.
3. Danh tính của "AI agent" gọi `POST /response/ai/proposals` (vai `operator` trong contract): dùng chung tài khoản người dùng, hay principal dịch vụ riêng? Ảnh hưởng audit và hook.
4. `index_profile` dựng chỉ mục RAG: BM25 (D-11) không cần AI, vậy hồ sơ này gửi nội dung tài liệu đi đâu? Nếu gửi thì rơi vào INV-3.
5. Hook tuỳ chỉnh: `contract.ts` ghi "JavaScript regular expression" còn backend Go dùng RE2 (không lookahead/backreference): chốt cú pháp và báo người dùng khi mẫu không hợp lệ.
6. Kết nối ngoài (`ai_connectors`) là hạ tầng dùng chung với `response`: giữ trong `ai` hay chuyển lên `core`?
