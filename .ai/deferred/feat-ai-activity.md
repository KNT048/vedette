# Deferred: feat/ai-activity (WP-25 slice 3)

- [ ] 2026-11-11 — A scheduled verify of the activity log that raises an incident when it breaks (S-AI-8 "alert on a broken chain") — vì sao để sau: needs the notify/incident port; verify on demand works — ở đâu: modules/ai/activity_read.go VerifyActivity
- [ ] 2026-11-11 — `GET /ai/activity` has no paging: the newest 1000 rows after the filters; `total` is the whole log — vì sao để sau: ponytail, the GUI has no "older" control; add a cursor when it gets one — ở đâu: modules/ai/activity_read.go MaxActivityItems
- [ ] 2026-11-11 — The newest activity row is never pruned (chainhead.Prune keeps the head's row), so a box that stops using AI keeps its last row past the retention — vì sao để sau: needs a change in core's helper (the head would have to be emptied); one row, no content — ở đâu: modules/ai/activity_api.go PruneActivity

## Handoff: the rest of WP-25 (the `ai` backend), written 2026-11-11 when the AI work moved to a new setup

State: slices 1 (#123), 2 (#179) are merged; slice 3 (this branch, the activity log) is in review. Nothing of the slices below is started.
Order agreed with the coordinator: 4a, 4b, 4c, then 6 (CVE news) before 5 (ask and tools), 7 (proposals) last. One branch and one PR per slice
(`feat/ai-<slice>` from the previous merged one), tests written first and shown red, `heavy make check`, independent review before merge.
The step-1 plan of the work (ops per route, backend needs per slice) is in the first report of the session transcript of the ai-module agent.

- [ ] 4a — rules and hooks: `ai_rule`, `ai_hook`, `ai_hook_state` (built-in hooks loaded by migration; `write-approval` is locked, 400 `locked`; at most 50 custom hooks, RE2) and the routes `GET/POST /ai/rules`, `PUT/DELETE /ai/rules/{id}` (at most 30 rules, 3..300 characters), `GET/POST /ai/hooks`, `PUT/DELETE /ai/hooks/{id}`, `PUT /ai/hooks/builtin/{id}`, `POST /ai/hooks/test`. Decisions: the hook switches make `redact_pii` of `/ai/config` real (today the built-in block-pii hook is always on); the test of the after_ai path (blocked and masked answers) lands here; the RE2 wording replaces "JavaScript regular expression" in `web/src/features/ai/contract.ts` as its own commit with `api/openapi.json` and `core/api/oas` regenerated (shared files: tell the coordinator before touching).
- [ ] 4b — memory and skills: `ai_memory`, `ai_memory_suggestion`, `ai_setting` key `memory`, `ai_skill_state`; routes `GET/POST /ai/memory`, `PUT/DELETE /ai/memory/{id}`, `PUT /ai/memory/settings`, `POST /ai/memory/suggestions/{id}/accept|reject` (a suggestion that is not accepted never enters a prompt, INV-8; the AI only suggests when `suggest_enabled`), `GET /ai/skills`, `PUT /ai/skills/{id}`. Decision: the list of skills is in code (as the 11 entries of the mock `SKILL_DEFS`); the signed content pack in `skills/` is deferred (write one deferred line then).
- [ ] 4c — knowledge: `ai_knowledge_doc`, `ai_knowledge_chunk` with FTS5; routes `GET/POST /ai/knowledge`, `PUT/DELETE /ai/knowledge/{id}`, `PUT /ai/knowledge/settings`. PDF, MD, TXT, DOCX up to 10 MB, only text chunks kept; status uploading, indexing, ready; `index_profile` goes through INV-3. Check FTS5 in the SQLite driver before starting; if it is missing, stop and report (issue owner:kien).
- [ ] 6 — CVE news (`POST /ai/cve/{id}/news`): a new data flow out of the box, so `PRIVACY.md` and the Settings, Privacy text change in the same commit as the code (rules/legal.md). Needs a THIRD_PARTY_NOTICES line if a feed or dependency is added.
- [ ] 5 — ask and tools (`POST /ai/ask`, `GET /ai/asks`, log digest): tool loop with read tools only (`ForModel`/`Offered`, INV-14); device reads through the read port of `core/conn/read` (D-127); reads of feeds, findings and inventory use the exported reads that exist, and a small read method is added in Emily's modules when one is missing (report it if the module is Kiên's).
- [ ] 7 — proposals: `ai:response` service identity calling `response.Service.Propose` (D-97), after #113; every guard stays in `response`.

Decisions of this slice are recorded as D-184 and D-185 (docs/DECISIONS.md).
Open deferred lines of the earlier slices remain in `.ai/deferred/feat-ai-module.md` and `.ai/deferred/feat-ai-explain.md`.

## Step-1 plan of WP-25 (copied from the first report of the ai-module agent; sections 1 to 5)

Later coordinator decisions on it: singular table names (MANIFEST and CONTRACT fixed); skills in code; FTS5 checked before 4c; reads of other modules through the exported reads that exist (add a small read method in Emily modules when missing, report if the module is Kiên's); order 1, 2, 3, 4a, 4b, 4c, then 6 before 5, 7 last; the `aiOff` replacement and `privacyFacts.AIConfigured` were done in slice 2; the AI-provider flow in PRIVACY.md in slice 2, CVE news with slice 6; `core/conn/read` exists (#126, D-127); #113 is merged, so check the real signature of `response.Service.Propose` before slice 7.

## 1. Operation → story → cần gì → dùng gì

| Nhóm (operation) | Story | Backend cần | Tái dùng từ thư viện |
|---|---|---|---|
| `GET/PUT /ai/config`, `GET/POST /ai/profiles`, `PUT/DELETE /ai/profiles/{id}`, `POST /ai/profiles/test`, `GET/PUT /ai/assignments`, `GET /ai/assignments/suggestion` | S-AI-1 (+S-AI-4 cho tier/cap) | Bảng `ai_profile`, `ai_assignment`, `ai_setting`. Khoá qua `core/secrets` (purpose `ai_profile.api_key`, chỉ `last4`). Nhận `api_key` rỗng khi sửa thì giữ khoá cũ. Xoá hồ sơ trả `cleared_jobs`. Mã lỗi `privacy_rule`, `duplicate_name`, `daily_cap` (đều có trong API_CONVENTIONS). `jobs_ready` và `configured` tính từ router. Đồng bộ `Router.SetConfig` sau mỗi thay đổi; `Meter.SetConfig`. Test dùng `Router.Probe`, và **bắt buộc dùng fake httptest** | `Profile.Validate/Usable/Provider`, `Assignments.Validate`, `NewRouter`, `Router.SetConfig/Candidates/Probe`, `provider.IsInternalAddr`, `Tier.EstimatePerDay` |
| `GET /ai/usage`, `GET /ai/runs` | S-AI-4 | View trên `ai_activity` (DATA_MODEL §4.9, không có bảng `ai_run`). `ai_downgrade` + `core_audit` khi hạ mức. `Meter.Seed` từ `ai_activity` lúc khởi động (theo múi giờ `core_org.timezone`) | `Meter`, `LoadLocation`, `Downgrade` |
| `GET /ai/activity`, `GET /ai/activity/verify`, `GET/PUT /ai/activity/settings` | S-AI-8, D-48 | `ai_activity` (nối chuỗi trong giao dịch ghi, `chainhead.Advance` cùng giao dịch), prune theo `retention_days` kèm `core_chain_anchor` và giảm `count`; lọc job/result/from/to; export qua core logs export. `retention_days` 90..3650 | `Seal`, `VerifyChain`, `ChainHead`, `HashContent`, `SummarizeArgs`, `core/chain` |
| `GET /ai/cve/{id}/cached`, `POST /ai/cve/{id}/explain` | S-AI-2, S-AI-6 | Bảng `ai_result` (kind=explain, UQ một phần theo `(kind,key,inputs_hash)`). Input do hộp chuẩn bị: CVE + KEV/EPSS (từ `feeds`), asset/software khớp (từ `findings`/`inventory`), mitigation pack nếu có. Ra schema cứng (`affected`, `why`, `patch_steps`, ...), parse không được thì lỗi `schema_error` ghi `ai_runs`, không suy diễn. `404 unknown_cve`, `409 ai_unavailable`. Nhãn "AI tạo" ở UI | `PromptBuilder.Build` (dữ liệu không tin cậy qua `DataBlock`), `Router.Call`, `HookRunner`, `ActivityLog` |
| `POST /ai/cve/{id}/news` | S-AI-3 | Hộp fetch advisory / GitHub PoC / RSS bằng dialer riêng (SSRF-safe, giới hạn kích thước, allowlist host), AI chỉ tóm tắt (INV-6). Job `cve-news` không mang dữ liệu nội bộ, chỉ công cụ `Public` | `Router.Call`, `CarriesInternalData` |
| `GET/POST /ai/logs/digest` | S-AI-4 | Không có sự kiện log thì `empty=true`, không gọi AI (POST-3). Cần đọc log gộp từ `logs` | Router, Meter |
| `GET /ai/asks`, `POST /ai/ask` | S-AI-5, S-AI-6 | `ai_result` kind=ask. Hook `before_ai`/`after_ai`/`before_tool`, lưu dạng ẩn cho câu bị chặn (INV-13). Vòng lặp công cụ đọc: `ForModel` + `Offered` + `WrapToolResult`, kết quả công cụ mang `ToolCall`; `table` tính từ công cụ | `HookRunner`, `QuestionForStorage`, `ForModel`, `Offered`, `WrapToolResult` |
| `GET/POST /ai/rules`, `PUT/DELETE /ai/rules/{id}` | S-AI-7 | `ai_rule`, tối đa 30, 3..300 ký tự | `Rule.Validate`, `BuiltinRules` |
| `GET/POST /ai/memory`, `PUT/DELETE /ai/memory/{id}`, `PUT /ai/memory/settings`, `POST .../suggestions/{id}/accept\|reject` | S-AI-7 | `ai_memory`, `ai_memory_suggestion`, `ai_setting.memory`. Đề xuất chưa accept thì không vào prompt (INV-8). AI chỉ đề xuất, chỉ khi `suggest_enabled` | `MemoryEntry`, `PromptInput` |
| `GET /ai/skills`, `PUT /ai/skills/{id}` | S-AI-7 | `ai_skill_state` (id skill sản phẩm). Danh sách skill lấy từ mô tả sản phẩm; **cần xác định nguồn: `skills/` trong repo (content pack) hay danh sách trong mã** | `Job` |
| `GET/POST /ai/knowledge`, `PUT/DELETE /ai/knowledge/{id}`, `PUT /ai/knowledge/settings` | S-AI-7, INV-10 | `ai_knowledge_doc` + `ai_knowledge_chunk` + FTS5. PDF/MD/TXT/DOCX ≤ 10 MB, chỉ giữ đoạn văn bản. Trạng thái `uploading→indexing→ready`. `index_profile` phải qua INV-3 | `Assignments.AllowedFor` |
| `GET/POST /ai/hooks`, `PUT/DELETE /ai/hooks/{id}`, `PUT /ai/hooks/builtin/{id}`, `POST /ai/hooks/test` | S-AI-7 | `ai_hook`, `ai_hook_state` (builtin nạp bằng migration). `write-approval` khoá (400 `locked`). Tối đa 50 hook tuỳ chỉnh, regex RE2 | `CustomHook.Validate`, `ValidateBuiltinToggle`, `NewHookRunner` |

Việc nội bộ (không có route) cũng thuộc WP-25: cổng `mitigation.AIPort` (nút "Hỏi AI của tôi", `explain`/`mitigation-config`), `RunJob`, reader chỉ-đọc của `core/conn`, và `ConfigRead` cho `response`.

## 2. Kế hoạch lát (PR nhỏ, theo thứ tự)

Mọi lát đều có test `TestContract_*` đỏ trước, `heavy make check` cuối lát. Lát nào cũng ghi `core_audit` trong cùng giao dịch ghi (INV-20). Không đổi `contract.ts`/mock trừ khi ghi riêng (xem "Cần chốt").

1. **Hồ sơ, phân việc, khoá, cấu hình (S-AI-1).** Migration `0001`: `ai_profile`, `ai_assignment`, `ai_setting`. Handlers cho 11 operation nhóm đầu. Sau đó nối `Router`/`Meter` vào trạng thái sống. Chạm Kiên: **không** (chỉ thêm dòng embed vào `cmd/vedette/handler.go` và đăng ký migration sau core, theo phase1-common; `NewAIHandlers` cần `*secrets.Store`/`*audit.Log` từ `newHandler`, nếu #33 chưa đủ thì ghi dòng chờ trong báo cáo).
2. **Chạy việc + giải thích CVE (S-AI-2) + `usage`/`runs`.** `RunJob`, `ai_result` (explain), `ai_activity` ghi mỗi lần gọi (chỉ phần Append; export/verify ở lát 3), `ai_downgrade`, `Meter.Seed`. Cổng `mitigation.AIPort` thật (thay `aiOff`). **Chạm Kiên:** `cmd/vedette/wiring.go` (`aiOff`) và `privacyFacts.AIConfigured` do Kiên giữ; mô-đun `mitigation` thì ngoài scope Emily? (`mitigation` nằm trong danh sách của Emily). Phần wiring cần issue `owner:kien`. Nội dung issue: "Replace `aiOff` in `cmd/vedette/wiring.go` with `ai.NewMitigationPort(...)` and wire `privacyFacts.AIConfigured` to `ai.Service.Configured(ctx)`; add `ai` to handler.go and migrations list. The ai module exports the constructors." Dữ liệu ra ngoài: provider khách cấu hình, cần PRIVACY (xem §3).
3. **Nhật ký hoạt động, xem và export (S-AI-8, D-48).** `GET /ai/activity`, `verify`, `settings`, prune retention + anchor + `chainhead`, `ai.activity` cho export. Chạm Kiên: tích hợp `core/logs export` (core) cần hàm đọc từ `ai_activity`; nếu export nằm trong core, cần issue `owner:kien` "register `ai_activity` as an export source (rows via `ai.Service.ExportActivity`)". Cần xem `core/chain`/`chainhead` có API sẵn cho prune (đã có `core_chain_anchor`/`core_chain_head` ở DATA_MODEL).
4. **Harness (S-AI-7).** Hooks, rules, memory (+ đề xuất), skills, knowledge/RAG FTS5. Có thể chia 4a (rules, hooks, hook test), 4b (memory, skills), 4c (knowledge + FTS5 + chỉ mục). Chạm Kiên: **không**. Cần xem SQLite build có FTS5 (modernc/sqlite hay mattn): nếu không có thì ghi issue `owner:kien` / dùng bảng chunk + tìm LIKE tạm.
5. **Công cụ chỉ-đọc + hỏi tự do (S-AI-4/5).** `POST /ai/ask`, `GET /ai/asks`, vòng lặp công cụ với `ForModel`+`Offered`+`WrapToolResult`, `log-digest` + `log-investigate` + `GET/POST /ai/logs/digest`. Công cụ chỉ-đọc của sản phẩm: `search_assets`, `get_finding`, `lookup_cve`, `lookup_ioc`, `events_around`. **Chạm Kiên (core/conn):** công cụ `read` của kết nối cần một reader của `core/conn` (D-93 (3)); hiện `core/conn/access.go` chỉ có đường **ghi** (`WriteAccess`, `OpenCredential` cần `cred.Key`). Cần issue `owner:kien`: "Expose a read-only reader in `core/conn`: `ListReadTools(ctx) []ReadTool{ConnectionID, Name, Description, Schema}` and `CallRead(ctx, connID, tool, args) (string, error)`, enforcing the allow-list and the dialer policy, never exposing the credential, never listing a write tool." Cần thêm: nguồn dữ liệu log từ `logs` (cổng đọc), kết quả công cụ đi qua `block-pii`. Ghi `ai_read` vào bản ghi để lát 7 tra được.
6. **Tin CVE (S-AI-3).** Fetcher của hộp (`feeds`-style dialer, allowlist host, chặn redirect, giới hạn kích thước, bộ lọc injection), `POST /ai/cve/{id}/news`, `ai_result` news. Chạm Kiên: **không**. Dữ liệu ra: HTTPS tới advisory/GitHub/RSS, cần PRIVACY. Có thể đặt trước lát 5 nếu bạn muốn, vì không phụ thuộc công cụ.
7. **Đề xuất cho `response` (D-97).** Chỉ sau khi #113 merge. Công việc: job `response-plan`; gọi `response.Service.Propose` qua một cổng `proposer` nhỏ phía `ai` (fake khi test); `ConfigRead` thật trên cơ sở bản ghi các lần đọc (bảng nhẹ hoặc cột trong `ai_activity.tools`, ≤ 24 giờ); ghi `links[]` `{kind: proposal, id}` vào activity; nhãn "AI tạo". Chạm Kiên: **`response` và `cmd/vedette/response.go`**: nối `Config.Evidence.ConfigRead = ai.ConfigReadLookup`; issue `owner:kien`: "wire `response.Config.Evidence.ConfigRead` to `ai.Service.LookupConfigRead` (signature `func(ctx, id) (response.EvidenceRef, bool, error)`); wire `ai` as the caller of `Propose`; `IocHit` stays with logs". Phụ thuộc: INV-14 (không công cụ ghi), INV-16.

Thứ tự đã xếp: proposals cuối cùng, đúng chỉ đạo. Phần 6 có thể đảo với 5 nếu supervisor muốn.

## 3. Luồng dữ liệu ra cần cập nhật PRIVACY.md

`PRIVACY.md` hiện không có luồng nào cho AI provider (chỉ có "flow 3" được nhắc trong IMPACT, bảng hiện không liệt kê dòng 3 nguyên văn; tôi thấy dòng 1, 2, 4, 5, 9, 10 trong lần grep, nên cần mở file đầy đủ để biết dòng 3 có sẵn chưa).
- **Lát 2:** luồng "AI provider do khách cấu hình": nội dung gửi (CVE, asset/phiên bản khớp, log liên quan sau hook `block-pii`), tới `base_url` của hồ sơ, tắt được bằng cách không cấu hình/tắt module; hồ sơ `internal` không rời mạng. Kèm nhãn UI Settings → Privacy.
- **Lát 6:** luồng "Tin CVE": các host fetch cụ thể (advisory vendor, `api.github.com` search, RSS đã liệt kê), không có dữ liệu của khách trong request ngoài tên CVE.
- **Lát 4c:** nếu index dùng provider cloud: tài liệu khách tới `index_profile` (áp INV-3). Nếu chỉ FTS5 thì không có luồng ra.
- **Lát 5:** kết quả công cụ đọc của kết nối gửi tới mô hình (qua hook); ghi chú trong cùng dòng với lát 2.
- Lát 1, 3, 7: không thêm luồng (`Propose` là gọi trong tiến trình).
- `THIRD_PARTY_NOTICES.md`: chỉ khi thêm dependency (hiện dự định không thêm; FTS5 là tính năng SQLite).

## 4. Phần chạm khu vực của Kiên (tóm tắt)

| Việc | Lát | Chủ |
|---|---|---|
| Thêm `ai` vào handler.go, migration list, nối `newHandler` (chỉ thêm dòng) | 1 | Emily (ngoại lệ #25), chờ #33 nếu thiếu deps |
| Thay `aiOff` bằng cổng thật; `privacyFacts.AIConfigured` | 2 | Kiên (issue) |
| Đăng ký `ai_activity` vào export log của core | 3 | Kiên (issue) |
| Reader chỉ-đọc `core/conn` cho công cụ `read` | 5 | Kiên (issue, nội dung ở lát 5) |
| Nối `Evidence.ConfigRead`, caller của `Propose` | 7 | Kiên (issue, sau #113) |
| Mã lỗi mới nếu cần (ví dụ `schema_error`, `knowledge_too_large`) | 2, 4 | Kiên (shared doc `API_CONVENTIONS.md` §3.3) |

## 5. Quyết định cần ghi

- Dùng tên bảng số ít của DATA_MODEL (`ai_profile`, `ai_assignment`, `ai_setting`, `ai_result`, `ai_hook`, ...) và sửa `MANIFEST.yaml`/`CONTRACT.md` của `ai` cho khớp, vì DATA_MODEL là bản kỹ thuật chốt và có câu hỏi mở 19 đề xuất số ít.
- `/ai/runs` và `/ai/usage` là view trên `ai_activity` (không có bảng `ai_run`), theo DATA_MODEL §4.9 và câu hỏi mở 3 (chưa được xác nhận chính thức); `ai_downgrade` giữ 90 ngày.
- `contract.ts` ghi regex hook là "JavaScript regular expression" còn backend dùng RE2: sửa chuỗi mô tả trong contract.ts và UI thành "RE2" (CONTRACT câu hỏi mở 5). Đây là sửa chữ nhỏ nhưng nằm ở `web/src/features/ai` (của Emily), không phải `web/src/lib`. Nếu đổi `contract.ts` thì `api/openapi.json` sinh lại, phải tách ra lát riêng.
- Cổng `proposer` và `connReader` định nghĩa phía `ai` (tối thiểu) để test bằng fake và không phụ thuộc chữ ký thật cho đến khi #113 và issue conn đã merge.


## Rà độc lập #205 (2026-11-11, sau merge 974d5ed) — không chặn merge
- [ ] 2026-11-11 — `SetRetention` is not refused while the service is degraded, unlike every other settings write since #123 (L2) — vì sao để sau: harmless (its own `ai_setting` key), consistency only — ở đâu: modules/ai/activity_read.go:154
- [ ] 2026-11-11 — The prune trusts the box clock going forward: a clock far ahead deletes every row except the newest, and the delete cannot be undone; consider skipping when `now` is before the newest row or the clock is not synced — vì sao để sau: needs the time-sync state from host — ở đâu: modules/ai/activity_api.go:39-47
- [ ] 2026-11-11 — The cancelled-call row takes the model from the current profile, not the attempt, so an edit during the call names the new model; carry the model in `Attempt` — vì sao để sau: rare, cosmetic — ở đâu: modules/ai/run.go (failed, profile lookup)
