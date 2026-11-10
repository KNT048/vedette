# AI — Change Impact Map

> Thư viện WP-25a đã có (package `modules/ai` và `modules/ai/provider`, chưa có HTTP/DB). `RunJob` vẫn là kế hoạch của WP-25; các hàm bên dưới mục "Thư viện đã có" là chữ ký thật. Chưa ai gọi (WP-25 sẽ nối) — cột "người gọi" ghi dự kiến.

## Modifying: `RunJob(ctx, job AiJob, in JobInput) (JobResult, error)` — 6 người gọi
- **core UI handlers** (`/ai/cve/{id}/explain|news`, `/ai/ask`, `/ai/logs/digest`): đổi lỗi `ai_unavailable` → toàn bộ nút AI hiển thị sai trạng thái.
- **reports** (`weekly-report`, `pdpl-assessment`): đổi `JobResult` → nhận xét AI trong báo cáo vỡ.
- **response** (`response-plan`, qua cổng `Planner` của `response`, lát 13b-11): đổi cấu trúc kế hoạch → `/response/plans` và bước đề xuất hành động vỡ. Đề xuất hành động đi qua cổng Go `response.Service.Propose` với tác nhân `ai:response` (D-97), không qua HTTP.
- **mitigation** (`mitigation-config`, "Hỏi AI của tôi"), **logs** (`log-digest`): đổi nhãn "AI tạo" → vi phạm S-AI-6.
- Thêm việc mới: thêm vào `AiJob`, bảng phân việc, ghi `data: internal|public` (quyết định INV-3), cập nhật GUI.

## Modifying: `Profiles.Resolve(job) ([]Profile, error)` (chọn chính/dự phòng, INV-3)
- Mọi `RunJob`. Đổi logic loại hồ sơ cloud → có thể rò dữ liệu nội bộ; test INV-3 bắt buộc xanh.

## Modifying: `Tools.ForModel(job) []Tool` (INV-14)
- **mcp-server**: không dùng. **ask-my-data / log-investigate**: thêm công cụ chỉ-đọc mới = đổi bề mặt dữ liệu AI thấy; công cụ `write` không bao giờ vào danh sách.

## ~~Modifying: `Connections` (`Get`, `ToolsWrite`) — nhà cung cấp cho response~~ (chuyển sang `core/conn`, D-93)
- Kết nối không còn thuộc `ai`: `response` đọc danh sách, dấu vân tay và công cụ ghi từ `core/conn` (lát 13b-4). Về sau (WP-25) `ai` là **người dùng** của một reader chỉ-đọc của `core/conn` cho công cụ `read`; đổi reader đó = đổi bề mặt dữ liệu AI thấy (INV-14).

## Modifying: `Activity.Append(entry)` / `Activity.Verify()` (D-48)
- **core/logs export** (`ai_activity`), **GUI Activity panel**: đổi công thức hash → chuỗi cũ không kiểm lại được; phải có bước di trú (ghi `version` vào entry).

## Modifying: `Hooks.Run(when, text)`
- Mọi `RunJob`, `Ask`. Đổi thứ tự (block trước mask) hoặc thêm hook dựng sẵn → thay đổi dữ liệu rời hộp (PRIVACY luồng 3).

## Disabling this module
- Hết nút AI (Findings/CVE, Logs digest, báo cáo, Assistant); `response` mất kế hoạch và đề xuất của AI nhưng **giữ kết nối và hành động lên thiết bị** (kết nối thuộc `core`, D-93); `mitigation` chỉ hiện "Chưa có khuyến nghị đã xác nhận" + KEV requiredAction.
- Không cuộc gọi nào ra provider. `ai_*` và chuỗi nhật ký giữ nguyên.

## Thư viện đã có (WP-25a) — chữ ký thật, người gọi dự kiến là WP-25 (`RunJob`, handler `/ai/*`)

### `modules/ai/provider`
- `New(Config) (Provider, error)`, `Provider.Complete(ctx, Request) (Response, error)`, `Probe(ctx, p, now) (ProbeResult, error)`, `StyleForKind`, `DefaultBaseURL`, `ParseBaseURL`, `Secret` (`NewSecret`, `Reveal`, `Last4`, `IsSet`).
- Đổi `Request`/`Response` → router, `RunJob`, kế hoạch `response-plan`. Đổi nơi đặt khoá (header) hoặc thông điệp lỗi → có thể lộ khoá (INV-1): `TestContract_INV1_KeyNeverLeaks` phải xanh. Thêm kiểu API mới = thêm adapter + fake httptest + fuzz bộ giải mã.
- Lỗi: `ErrAuth`, `ErrRateLimited`, `ErrServer`, `ErrTimeout`, `ErrRequest`, `ErrTooLarge`, `ErrBadResponse`, `ErrNetwork` (đều không chứa khoá hay URL). Router chuyển dự phòng với mọi lỗi này, trừ khi ngữ cảnh của người gọi đã bị huỷ.

### `modules/ai` — định tuyến và đồng hồ
- `Profile.Validate`, `Profile.Usable`, `Profile.Provider`; `Assignments.Validate(profiles)`, `Assignments.Allowed(job, p)` (**điểm duy nhất quyết định INV-3**); `NewRouter(RouterConfig)`, `Router.Candidates(job)`, `Router.Call(ctx, job, req) (CallResult, error)`; `ErrUnavailable` (409 `ai_unavailable`), `ErrCapped` (429 `daily_cap`).
- Sửa `Allowed` hoặc vòng lặp trong `Call` → có thể gửi dữ liệu nội bộ lên cloud: `TestContract_INV3_InternalOnlyNeverReachesCloud` bắt buộc xanh. Việc mới phải khai `CarriesInternalData()` trong `jobs.go`.
- `NewMeter`, `Meter.Record/Seed/Tier/Used/ProfileUsed/Exhausted/SetConfig`, `LoadLocation`: ngày tính theo múi giờ của hộp (`core_org.timezone`, mặc định `Asia/Ho_Chi_Minh`); mức bị hạ chỉ kéo dài đến hết ngày địa phương. WP-25 phải `Seed` từ `ai_activity` khi khởi động và ghi `ai_downgrade` + `core_audit` từ `CallResult.Downgrade`.

### `modules/ai` — harness
- `NewHookRunner(builtinEnabled, custom)`, `HookRunner.Run(ctx, when, text)`, `HookRunner.CheckTool(ctx, access, args)`, `CustomHook.Validate`, `ValidateBuiltinToggle`, `QuestionForStorage`, `HiddenQuestion`. Mọi lỗi từ `Run` nghĩa là **không được gửi tiếp** (văn bản quá 1 MiB hoặc ngữ cảnh hết hạn). Đổi thứ tự (chặn trước che) hoặc thêm hook dựng sẵn → đổi dữ liệu rời hộp (PRIVACY luồng 3). Cú pháp regex của hook tuỳ chỉnh là RE2 (câu hỏi mở 5 đã chốt).
- `ForModel(job, tools) []provider.ToolDef`, `Offered(job, tools, name)`: **bắt buộc** dùng cả hai ở vòng lặp công cụ; không có tham số nào thêm được công cụ ghi (INV-14).
- `PromptBuilder.Build(PromptInput) (Prompt, error)`, `BuiltinRules()`, `Rule.Validate`: luật dựng sẵn luôn đi đầu; dữ liệu không tin cậy chỉ vào `PromptInput.Data` (hàng rào ngẫu nhiên mỗi lần gọi).

### `modules/ai` — nhật ký chuỗi hash
- Công thức băm và JSON chuẩn hoá **không còn ở đây**: dùng `core/chain` (`HashCanonical`, `NewVerifier`; D-57 mục 14). Còn lại ở `ai`: `HashContent`, `Genesis` (= `chain.Genesis`), `Seal(prev, entry)` (đổi `ActivityEntry` thành map để băm; UTF-8 sai bị `core/chain` từ chối), `VerifyChain(entries, anchor, head *ChainHead)`, `ChainHead{Hash, Count}`, `ActivityLog`, `NewActivityTool`, `SummarizeArgs`, `FormatTS`.
- Đổi `entryMap` (thêm/bớt cột của `ai_activity`) → đổi hash của mọi entry cũ; vector chung ở `modules/core/testdata/chain_vectors.json`, test `TestChainVectorsSharedWithCore`. `ChainHead` do `core` ghi cùng giao dịch với mỗi lần ghi/prune; không có thì không phát hiện được việc xoá các mục mới nhất.

### Sau review bảo mật (WP-25a, vòng 2) — hàm mới hoặc đổi chữ ký
- `Router.SetConfig(profiles, assignments)`, `Router.Probe(ctx, profile, now)`; `NewRouter` kiểm lại mọi hồ sơ; mỗi lần thử trong `Call` đọc lại cài đặt hiện hành. WP-25 gọi `SetConfig` sau mỗi thay đổi hồ sơ/phân việc/`internal_only`.
- `Meter.Reserve(profileID, profileCap, estimate) (*Reservation, error)` + `Reservation.Settle/Cancel`; `Meter.Record` chỉ còn cho lần gọi không giữ chỗ.
- `Profile.AnthropicVersion`; `provider.Config.InternalOnly`, `provider.IsInternalAddr`; `provider.ErrRefused` (+ `Error.Category`, `Error.Usage`), `Response.Raw`/`Message.Raw` (nội dung assistant của Anthropic, phát lại nguyên văn).
- `Tool.Public`, `Tool.ConnectorID`; `Offered` trả đúng công cụ `ForModel` đã đưa ra (có `ConnectorID`).
- `HookRunner.RunPersonalData`, `WrapToolResult(ctx, hooks, prompt, tool, content)`, `PromptInput.WithTools`, `MaxCustomHooks`, `MaxRegexProgram`.

## Service (WP-25 slice 1: profiles, keys, assignments, token settings) — chữ ký thật
- `New(ctx, Config{DB, Secrets, Audit, Log, Clock, Zone, Factory}) (*Service, error)`: nạp `ai_profile`, `ai_assignment`, `ai_setting`, mở khoá (purpose `ai_profile.api_key`), dựng `Meter` và `Router`; trạng thái đã lưu mà luật từ chối thì **không khởi động** (đóng khi lỗi). `Zone` chỉ đọc một lần lúc khởi động.
- `Profiles()`, `AddProfile/EditProfile(ctx, who, …)`, `DeleteProfile(ctx, who, id) []Job`, `TestProfile`, `Assignments()`, `SetAssignments`, `Suggestion(internalOnly)`, `Config()`, `SetConfig`. Mọi thay đổi: dựng trạng thái kế tiếp → kiểm bằng đúng luật của router (`snapshot.check`: `Profile.Validate` + `Assignments.Validate`) → ghi một giao dịch cùng dòng `core_audit` → `Router.SetConfig` → đổi con trỏ trạng thái. Trạng thái bị luật cấm không bao giờ được lưu hay đến router (INV-3).
- `AIHandlers` (`NewAIHandlers`): 11 thao tác `/ai/config`, `/ai/profiles*`, `/ai/assignments*`; vai trò lấy từ bảng route, handler không kiểm vai trò.
- Đổi chữ ký `Config`/`SetAssignments` → `cmd/vedette/ai.go`, mọi lát sau (chạy việc, hoạt động, harness) đọc `Service.snap`. Xoá hồ sơ: việc nhận lại hồ sơ dự phòng làm chính (hồ sơ đó đã hợp lệ cho việc) và `cleared_jobs` liệt kê mọi việc bị đổi; theo mock, không chọn hồ sơ khác thay.
- Không có sự kiện nào được phát ở lát này.

## Running a job (WP-25 slice 2: explain a CVE, usage, runs) — chữ ký thật
- `RunJob(ctx, JobSpec) (JobResult, error)`: một lần gọi = hook `before_ai` trên câu hỏi và từng khối dữ liệu (chặn/giữ/lỗi → không gửi, hàng nhật ký `blocked_by_hook`), `PromptBuilder` (luật dựng sẵn, dữ liệu không tin cậy chỉ trong `JobSpec.Data` có hàng rào), `Router.Call` (chính → dự phòng, `Meter`), hook `after_ai` trên câu trả lời, `JobSpec.Check` (sai schema → `ErrBadOutput`, bỏ câu trả lời), rồi **một** hàng `ai_activity` + `ai_downgrade` + kết quả (`JobSpec.Store`) trong một giao dịch ghi. Lỗi người dùng thấy là `*apierr.Error`: 409 `ai_unavailable` (kể cả hook chặn, trả lời hỏng), 429 `daily_cap`. Việc không có hồ sơ được phép thì **không** có hàng nhật ký (chưa thử gì). `connection-test` cũng ghi một hàng.
- `ExplainCVE`, `CachedCVE` (`/ai/cve/{id}/explain|cached`): cache theo `(CVE, hash của mục feed + thiết bị khớp)` trong `ai_result`; `affected` do hộp quyết (không khớp → no, có phát hiện đã xác nhận → yes, còn lại unknown), nguồn trích dẫn do hộp dựng từ liên kết của feed. `Config.Facts` (`ai.Facts`: `CVE`, `AffectedAssets`) do `cmd/vedette` nối với feeds, findings, inventory; thêm trường vào `CVEFacts`/`AssetFact` = đổi dữ liệu gửi cho nhà cung cấp (PRIVACY luồng 3).
- `Brief`, `Available`, `Configured`: cửa của `mitigation.AI` (`cmd/vedette/ai.go` `aiMitigation`) và của trang Quyền riêng tư (`privacyFacts.AIConfigured`). Đổi `BriefAnswer`/`JobSpec` → `mitigation` (`/findings/{id}/ai`) và `cmd/vedette/ai.go`.
- `Usage`, `Runs`: view trên `ai_activity` (`status`: ok / schema_error nếu tốn token mà không dùng được / capped nếu không tốn gì); `New` dựng lại đồng hồ từ `ai_activity` của hôm nay (`seedMeter`), nên mức đang áp dụng và trần từng hồ sơ không đổi khi khởi động lại.
- `ai_activity` có trigger cấm sửa và cấm `INSERT OR REPLACE` đè; xoá do retention (lát 3) cùng giao dịch với `core_chain_anchor` và giảm `core_chain_head.count`.
- `GET /ai/cve/{id}/cached`: mock không mô phỏng việc cache mất hiệu lực sau khi thiết bị đổi (mock does not model cache invalidation after a device change); backend chỉ trả hàng có inputs hash khớp với feed và thiết bị hiện tại, còn lại trả "chưa có gì trong cache" như lúc chưa từng giải thích (the backend serves only a row whose inputs hash matches). `contract.ts` không đổi.
