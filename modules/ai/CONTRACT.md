# AI Contract

> Tier: tuỳ chọn (tắt mặc định) · Story: S-AI-1..8 (+ S-RESP-1 qua việc `response-plan`) · Quyết định: D-11, D-29, D-39, D-41, D-48, D-51, D-93, D-97 · Last verified: 2026-11-10
> Nguồn hành vi thực tế: `web/src/features/ai/{contract,types,mocks,harness,harness-mocks,activity}.ts`, `web/src/mocks/stores.ts` (`AI_JOBS`).

## Invariants (luôn đúng)

### Hồ sơ, phân việc, dữ liệu nội bộ (D-29)
- **INV-1** Khoá API lưu qua `core/secrets` (AES-GCM); API chỉ trả `key_last4`; không log, không export (SYS-4). `key_last4 = null` hợp lệ chỉ với `location=internal` (`usable = key ≠ null ∨ location = internal`).
- **INV-2** Mười việc AI (`AiJob`): explain-finding, mitigation-config, cve-news, log-digest, log-investigate, ask-my-data, weekly-report, pdpl-assessment, translate-advisory, response-plan. Mỗi việc có một hồ sơ chính và một dự phòng. Chuyển sang dự phòng khi hồ sơ chính lỗi, quá thời gian, hết trần riêng hoặc bị luật riêng tư loại; tên hồ sơ và `fallback=true` ghi vào kết quả và `ai_runs`.
- **INV-3** **Quy tắc dữ liệu nội bộ**: các việc gửi log/dữ liệu thiết bị (mọi việc trừ `cve-news`, `translate-advisory`) khi `assignments.internal_only = true` chỉ được gán và chỉ được gọi tới hồ sơ `location=internal`. Chặn ở **hai nơi**: `PUT /ai/assignments` từ chối gán sai; lúc chạy, hồ sơ cloud không bao giờ nhận dữ liệu loại này, kể cả khi failover và kể cả khi cài đặt đổi giữa chừng (mỗi lần thử đọc lại cài đặt hiện hành). Mọi yêu cầu có công cụ hoặc kết quả công cụ được coi là dữ liệu nội bộ; công cụ cho `cve-news`/`translate-advisory` phải đánh dấu `public` và nêu rõ việc. **`location=internal` được cưỡng chế bằng địa chỉ, không chỉ là nhãn**: IP trong base URL phải là loopback, RFC 1918, link-local, ULA hoặc CGNAT; tên máy được chấp nhận nhưng lúc nối (dial) từ chối mọi địa chỉ đã phân giải mà là địa chỉ công cộng (chống DNS rebinding) và không dùng proxy môi trường; `http` chỉ cho hồ sơ nội bộ; loại gốc anthropic/openai/gemini không bao giờ là `internal`. Không còn hồ sơ hợp lệ → 409 `ai_unavailable` với lý do rõ, không im lặng chuyển sang cloud. Test: `TestContract_INV3_InternalOnlyNeverReachesCloud`, `TestContract_INV3_InternalLabelIsEnforced`, `TestContract_INV3_ToolsMeanInternalData`, `TestContract_INV3_SettingsChangeReachesRunningCalls`, `TestContract_INV3_InternalDataToolsAreNotOfferedToPublicJobs`.
- **INV-4** Mức token ∈ {min, med, max}; trần chung `daily_cap` 1.000..5.000.000; trần riêng từng hồ sơ cùng khoảng. Vượt trần chung → tự hạ mức và ghi `ai_downgrades` + `core_audit`. Không hiện tiền (D-6). Ước lượng/ngày: min ≈ 10.000, med ≈ 60.000, max = `null` (phụ thuộc số cảnh báo). Hạ mức không bao giờ tăng quyền (max → med → min). **Ngày = ngày theo múi giờ của hộp** (`core_org.timezone`, mặc định `Asia/Ho_Chi_Minh`); đồng hồ lùi không bắt đầu ngày mới. Mức hiệu lực là hàm của tổng token hôm nay so với trần (mỗi lần vượt thêm một trần: hạ thêm một mức; vượt xa thì hạ nhiều mức một lúc), nên khởi động lại không đổi mức; **mức bị hạ kéo dài đến hết ngày địa phương**. Trần được kiểm và **giữ chỗ trước khi gọi** (`max_tokens` + ước lượng đầu vào) rồi quyết toán sau khi gọi, nên N lời gọi đồng thời không cùng vượt qua; lời gọi lỗi có số liệu (từ chối) và lần thử hồ sơ đều được tính; cộng bão hoà, giá trị token từ nhà cung cấp bị chặn ở 0..10.000.000. Test: `TestContract_INV4_*`.
- **INV-5** Mọi output AI mang `model`, `profile`, `tokens` và hiển thị nhãn "AI tạo, cần người xác nhận" (S-AI-6); không có nút hành động trực tiếp trên output AI. Output AI không bao giờ hiển thị như khuyến nghị đã xác nhận (S-MIT-1, D-21).
- **INV-6** Cache: `GET /ai/cve/{id}/cached` không gọi AI; `explain`/`news` mới tốn token. `news`: **hộp** fetch advisory/GitHub PoC/RSS, AI chỉ tóm tắt (S-AI-3); AI không tự duyệt web.

### Harness (D-39)
- **INV-7** Luật dựng sẵn (`br-scope`, `br-evidence`, `br-readonly`, `br-untrusted`) luôn đưa vào mọi lần gọi, không sửa/xoá/tắt được. Luật tuỳ chỉnh: 3..300 ký tự, `jobs=[]` nghĩa là mọi việc.
- **INV-8** Memory: AI chỉ **đề xuất** (`MemorySuggestion`); một đề xuất chưa được admin chấp nhận (`accept`) thì không vào ngữ cảnh. Mục memory 3..300 ký tự, xem/sửa/xoá/tắt được; `suggest_enabled=false` → AI không đề xuất.
- **INV-9** Skill là skill **của sản phẩm** (`skills/`, ký trong content pack); bật/tắt được; không phải skill Claude Code (D-13).
- **INV-10** Kho tri thức: PDF/MD/TXT/DOCX ≤ 10 MB; trạng thái `uploading → indexing → ready`; chỉ mục nằm trên hộp; mỗi tài liệu chọn việc nào được dùng (`jobs`); xoá tài liệu xoá cả chỉ mục. Tài liệu của khách là dữ liệu nội bộ: áp dụng INV-3 cho hồ sơ dựng chỉ mục (`index_profile`).
- **INV-11** ~~Kết nối ngoài do `ai` giữ (`ai_connectors`, `/ai/connections*`)~~ **Chuyển sang `core` (D-93, 2026-11-09)**: kết nối tới thiết bị và máy chủ MCP (kiểu chung D-58, công cụ `read`/`write` bật riêng, công cụ ghi luôn tắt khi tạo, bí mật chỉ `last4`) là bảng `core_connection*` của gói `core/conn`, quản lý ở Settings → Connections (`/core/connections*`, lát 13b-1/13b-4), dùng được khi `ai` tắt; hợp đồng của chúng ở `modules/core/CONTRACT.md` (thêm ở 13b-4) và D-93/D-94 (`mcp-stdio` bị từ chối). `ai` không có bảng, endpoint hay bí mật kết nối nào; về sau (WP-25) `ai` chỉ dùng **công cụ đọc** của kết nối qua một reader của `core`, và INV-14 vẫn đúng: công cụ ghi không bao giờ vào danh sách công cụ của mô hình.
- **INV-12** Hook chặn có ba thời điểm (`before_ai`, `after_ai`, `before_tool`) và ba hành động (`block`, `mask`, `approve`). Hook dựng sẵn: `block-pii` (che email/số điện thoại/tên cạnh tài khoản, kể cả tiếng Việt, chữ số toàn chiều rộng/Unicode và ký tự không độ rộng — so khớp trên bản chuẩn hoá, che trên văn bản gốc; chặn số định danh 9 hoặc 12 chữ số, cả khi viết cách nhóm), `security-only`, và **`write-approval` khoá luôn bật** (`locked=true`, tắt → 400 `locked`). Hook tuỳ chỉnh theo từ khoá (phân tách bằng dấu phẩy) hoặc regex, mẫu 1..200 ký tự, tên 1..40, thông báo 3..200 ký tự, tối đa 50 hook tuỳ chỉnh. **Regex là RE2 (Go)**: cú pháp chỉ có trong JavaScript (lookahead/lookbehind, backreference, ``) bị từ chối với thông báo rõ; chương trình biên dịch tối đa 2.000 lệnh (sau khi bung lặp), quá thì từ chối khi lưu. **Văn bản vào hook tối đa 1 MiB, quá thì lỗi và người gọi phải coi là chặn (fail closed)**; quét có ngữ cảnh nên hạn chót được tôn trọng ngay trong một lần khớp. Kết quả công cụ trả về cho mô hình đi qua hook `block-pii` và được bọc cùng hàng rào dữ liệu không tin cậy. Test: `TestContract_INV12_*`.
- **INV-13** Một câu hỏi bị chặn không được lưu nguyên văn (`[question hidden: contains personal data]`) và không tốn token. **Mọi** câu bị chặn đều lưu dạng ẩn, không riêng hook dữ liệu cá nhân; chỉ kết quả `pass` và `masked` được lưu (văn bản đã che); `held`, lỗi và giá trị rỗng đều ẩn. Test: `TestContract_INV13_*`.

### SYS-8: AI không có công cụ ghi
- **INV-14** Bộ công cụ mà mô hình **nhìn thấy** chỉ gồm công cụ `access=read` (tra tài sản, phát hiện, feed, log, kết nối chỉ-đọc). Công cụ `write` của kết nối **không bao giờ** được đưa vào danh sách công cụ gửi cho mô hình, không phụ thuộc cấu hình hay hook tuỳ chỉnh. Test: `TestContract_INV14_NoWriteToolInModelToolList`.
- **INV-15** Hook `write-approval` khoá: bất kỳ lời gọi công cụ ghi nào (kể cả nếu lọt tới `before_tool`) chỉ đi tiếp qua một hành động đã được người duyệt trong module `response`. Đây là **ngoại lệ duy nhất** của SYS-8 (D-41), thực thi và ràng buộc hoàn toàn trong `response` (xem `modules/response/CONTRACT.md`); module `ai` không tự thực thi ghi.
- **INV-16** AI gửi yêu cầu phản ứng chỉ bằng cổng Go `response.Service.Propose` với danh tính dịch vụ `ai:response` (D-97; `POST /response/ai/proposals` chỉ còn ở bản xem trước) gồm tên hành động + tham số có kiểu + bằng chứng; không gửi lệnh. Mọi chốt chặn nằm ở `response`, không ở prompt.

### Nhật ký AI, chống sửa (D-48)
- **INV-17** Mọi lần gọi AI (kể cả bị hook chặn, dùng dự phòng, lỗi) tạo đúng một `ActivityEntry`: `job, profile, model, trigger, hooks[], tools[] (read|write, tham số đã tóm tắt, không bí mật), input_hash, output_hash, summary, tokens, result, links[]`. Nội dung gửi/nhận **không lưu**, chỉ hash.
- **INV-18** Chuỗi hash dùng **một công thức chung** của `core/chain` (D-57 mục 14): `hash = SHA-256(prev_hash + "
" + JSON chuẩn hoá của entry bỏ trường hash)`; `prev_hash` nằm trong entry; JSON chuẩn hoá: khoá sắp theo **điểm mã Unicode** (thứ tự byte UTF-8), không khoảng trắng, chuỗi thoát như `JSON.stringify`, chỉ số nguyên; **UTF-8 không hợp lệ bị từ chối**, không được thu về U+FFFD. Vector chung: `modules/core/testdata/chain_vectors.json`. Không có endpoint sửa/xoá entry. `GET /ai/activity/verify` trả `ok` hoặc `broken_at` (vị trí 1-based) và `entry_id`; `core` giữ **bản ghi đầu mối đuôi** (`hash` mục mới nhất + số mục) cùng giao dịch với mỗi lần ghi/prune để phát hiện xoá các mục mới nhất (broken_at = vị trí mục đầu tiên bị thiếu). Test: `TestContract_INV18_*`, `TestChainVectorsSharedWithCore`.
- **INV-19** Giữ mặc định 365 ngày, tối thiểu 90 (`retention_days ≥ 90`); entry chỉ biến mất theo hết hạn lưu giữ, không theo yêu cầu sửa/xoá.
- **INV-20** Mọi mutation cấu hình (hồ sơ, phân việc, rule, memory, skill, tri thức, hook) ghi `core_audit` (SYS-3). Kết nối do `core` ghi kiểm toán (D-93).
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
| ~~GET/POST, PUT/DELETE~~ | ~~`/ai/connections`, `/ai/connections/{id}`; POST `/ai/connections/{id}/test`~~ chuyển thành `/core/connections*` của `core` ở lát 13b-1 (D-93); còn trong `contract.ts`/OpenAPI tới lát đó | admin |
| GET, POST, PUT/DELETE | `/ai/hooks`, `/ai/hooks/{id}`; PUT `/ai/hooks/builtin/{id}`; POST `/ai/hooks/test` | admin |

Việc `response-plan` (kế hoạch phản ứng) do `ai` chạy; endpoint `/response/plans` thuộc `response`.

## Tables owned
`ai_config, ai_profiles, ai_assign, ai_runs, ai_sample_runs, ai_downgrades, ai_explains, ai_news, ai_asks, ai_log_digests` (S-AI-1..6); `ai_rules, ai_memory, ai_memory_suggestions, ai_memory_settings, ai_skills, ai_knowledge, ai_knowledge_settings, ai_hooks, ai_hooks_builtin` (harness; `ai_connectors` chưa từng được tạo, thay bằng `core_connection*` theo D-93); `ai_activity, ai_activity_settings` (D-48). `ai_sample_runs` chỉ có trong bản xem trước.

## Events
- **Phát**: `ai.activity` (mỗi entry; tên đề xuất) cho export log; `ai.downgrade` (cũng đi vào `core_audit`).
- **Nhận**: yêu cầu việc từ `core` (UI), `reports` (`weekly-report`, `pdpl-assessment`), `response` (`response-plan`), `mitigation` (`mitigation-config`).

## Khi tắt module (SYS-5)
Không route `/ai/*`, không gọi provider, không job. Nút "Giải thích", "Hỏi AI của tôi", digest AI, nhận xét AI trong báo cáo, kế hoạch AI của `response` biến mất hoặc báo "module `ai` đang tắt". Hồ sơ, rule, memory, tri thức, nhật ký giữ nguyên (chuỗi hash vẫn kiểm được). Kết nối tới thiết bị thuộc `core` (D-93): tắt `ai` **không** làm `response` mất kết nối hay hành động lên thiết bị; chỉ mất đề xuất và kế hoạch của AI.

## Dependencies
- **DEPENDS ON**: `core` (`core/secrets`, `core/exec`, audit, scheduler), `feeds`/`inventory`/`logs`/`scan`/`notify` (dữ liệu, mềm).
- **DEPENDED ON BY**: `response` (`response-plan`; sẽ cung cấp tra cứu các lần đọc đã thực sự làm, `ConfigRead`, để sau, không quá 24 giờ, D-119; kết nối không còn ở đây, D-93), `reports` (nhận xét AI), `mitigation` (hỏi AI khi chưa có khuyến nghị đã xác nhận), `logs` (digest AI), GUI `findings`/`cve` (panel `cve.panels`), `mcp-server` (không), `core/logs export` (`ai_activity`).

## Câu hỏi mở
1. README của GUI nói "9 việc" còn `contract.ts` có 10 (`response-plan`): sửa README.
2. ~~Hai chuỗi hash khác công thức~~ **Đã chốt (D-57 mục 14)**: một công thức cho `core_audit`, `ai_activity`, `resp_log`, cài ở `core/chain`.
3. ~~Danh tính của "AI agent"~~ **Đã chốt (D-97)**: danh tính dịch vụ trong tiến trình `ai:response`, gọi cổng Go `response.Service.Propose`; không route HTTP trong bản thật.
5. ~~Hook tuỳ chỉnh: cú pháp regex~~ **Đã chốt**: RE2 (Go); cú pháp riêng của JavaScript bị từ chối khi lưu với thông báo rõ (INV-12). `contract.ts` và UI cần ghi "RE2" thay vì "JavaScript regular expression" (WP-25).
5. Hook tuỳ chỉnh: `contract.ts` ghi "JavaScript regular expression" còn backend Go dùng RE2 (không lookahead/backreference): chốt cú pháp và báo người dùng khi mẫu không hợp lệ.
6. ~~Giữ kết nối ngoài trong `ai` hay chuyển lên `core`~~ **Đã chốt (D-93)**: chuyển lên `core` (INV-11).
