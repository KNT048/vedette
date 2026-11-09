# Response — Change Impact Map

> WP-13a đã có mã Go (package `modules/response`); chữ ký dưới đây còn là tên khái niệm: `Evaluate`/`fire` (engine.go), `approve`/`runItem` (requests.go; `runItem` là nơi duy nhất gửi bước tới thiết bị; `markRunning`/`failStuck` ghi trạng thái "đang chạy"), `Fill`/`CheckValue`/`ValidateTpl` (params.go), `appendLog`/`VerifyLog` (service.go, plans.go), `FetchBlocklist`/`renderBlocklist` (blocklist.go). Phần AI (`AIGate`) là 13b. Phần 2 (WP-13b, D-93…D-98) viết trước mã ở 13b-0: mỗi mục dưới đây ghi lát sẽ cài nó; tên hàm theo kế hoạch, mã có thể đặt tên khác thì sửa ở đây cùng PR. Module **rủi ro cao**: mọi thay đổi ở cổng chặn (INV-1…16) cần test hợp đồng và ghi rõ trong commit.

## Modifying: `Engine.Evaluate(ctx, Event) error` (khớp quy tắc, dựng yêu cầu) — 6 nguồn sự kiện
- **honeypot** (`Hits`/`honeypot.hit`), **logs** (`IocHits`), **findings** (`findings.finding.created|status_changed`, D-57 (6)), **inventory** (thiết bị chưa duyệt), **exposure** (cổng mới), **scheduler** (lịch): đổi tên/kiểu trường trigger → điều kiện và tham số `{{trigger.field}}` của quy tắc đang có không còn khớp, quy tắc im lặng. Danh mục trường (`/response/triggers`) là hợp đồng với GUI.

## Modifying: `Approve(ctx, reqID, Approver, items, code) (Request, error)` — 4 người gọi
- **HTTP** `/response/actions/{id}/approve` (app; yêu cầu AI rủi ro cao cần `TwoStep`, 13b-9); **kênh chat** (Slack Socket Mode, Telegram long polling, Zalo cá nhân) qua cổng `notify.Config.Decisions` → `DecideFromChat` (13b-8); **liên kết email** `/response/approve/{token}` → `DecideByLink` (13b-7; Zalo OA để sau); **rule engine** (`via=auto`, chỉ INV-5). Mọi đường dùng chung một hàm duyệt; chính sách kênh × rủi ro (INV-3, D-96) kiểm ở đó, không ở `notify`. Đổi thứ tự cổng (INV-9) hoặc điều kiện hai người → thay đổi ai có thể gây thay đổi trên thiết bị; test `TestContract_INV2_*`, `INV16_*` bắt buộc.

## Modifying: `RequestProposal` và hình dạng của `resp_plans.steps[].proposal` (job kế hoạch AI, 13b)
- Đề xuất chỉ chứa `action_id` + `params` có kiểu (+ `ttl_min`, `asset_id`, `asset_name`); mọi lệnh/đường dẫn/body do `planAction` dựng từ danh mục lúc xem và lúc yêu cầu. Job kế hoạch của 13b phải ghi đúng dạng này; dạng cũ (lệnh lưu sẵn) bị từ chối `tool_not_allowed`.

## Modifying: `Directory`, `ConnectionInfo` (cmd/vedette, 13b)
- `Directory.DevicesOfKind` nuôi danh sách không đụng (router, firewall) và **phải đọc không giới hạn số dòng** (`cmd/vedette` gọi `inventory.DevicesOfKind`, không phải `Devices` bị cắt ở 2000 dòng mới nhất trước: thiết bị cũ nhất, thường là gateway, sẽ rơi khỏi danh sách); lỗi đọc = từ chối hành động. `Directory.Device` còn nuôi chủ thể của đề xuất AI (tài sản của finding): lỗi tra = từ chối. Thiết bị loại khác cũng không vào danh sách nên không được đổi `kind` router/firewall mà không báo. `ConnectionInfo.UpdatedAt` phải đổi mỗi khi kết nối bị sửa (địa chỉ, thông tin xác thực, công cụ): nó nằm trong dấu vân tay lưu theo item (INV-9 `connection_changed`). **13b-4 (D-93)**: `Connections` do `core/conn` cung cấp (adapter ở `cmd/vedette`); `connFP` thay bằng `conn.Fingerprint` (vector dùng chung với `core`); `updated_at` của `core_connection` chỉ đổi theo trường bảo mật. Đổi danh sách trường bảo mật hay công thức dấu vân tay = mọi yêu cầu đang chờ bị từ chối `connection_changed` sau khi nâng cấp (chấp nhận, ghi trong PR).
- **13b-4 (D-93)**: `ConnectionInfo` do `cmd/vedette` (`responseConnections`) dựng từ `core/conn`; `connFP` là `conn.Fingerprint(id, kind, target, updated_at)` (vector dùng chung `TestConnFPIsTheSharedVector`), nên đổi nó làm mọi yêu cầu đang chờ thành `connection_changed`. **`(*Service).ChangesInForce(ctx, connectionID) (bool, error)`** là cổng `conn.Config.InUse`: đọc `resp_actions.items` (`connector_id`, và `status = executed`, hoặc `state_unknown = 1` (cờ rõ ràng của item mà bước đã gửi nhưng chưa biết kết quả: sweep hoặc hạn bước đặt nó, kết quả muộn xoá nó; không bao giờ so chữ), hoặc `pending` với `running_at` đã đặt); đổi hình dạng item hay nghĩa trạng thái là đổi điều kiện 409 `in_use` khi xoá kết nối. Test: `modules/response/conn_test.go`.

## Modifying: `Execute(ctx, Item) (Result, error)` — 1 người gọi (chỉ `Approve`)
- **13b-6 (D-94)**: `cmd/vedette` cài `Executor` bằng `responseExecutor{w}` bọc `core/conn/write` (không gói nào khác import gói này, FORBID-1); `DeviceStep` đổi thành `Step{ConnectionID, ConnFP, Phase, Tool, Lines, Method, URL, Body, Headers, Args}` và `DeviceResult{Detail, Output}`; `Output` chỉ để so `precheck_refuse`/`expect` rồi bỏ (INV-22). Trước đây ghi là "công cụ ghi của `ai.Connections`": không còn (D-93).
- Gọi **công cụ ghi** của kết nối. Là điểm duy nhất của FORBID-1; không thêm người gọi thứ hai. **Phải tôn trọng `ctx`** (mang hạn của item): `execute` chạy nó trong goroutine và thôi chờ đúng hạn, ghi "State unknown" và nhả khoá bước thiết bị; một `Execute` bỏ qua `ctx` vẫn có thể gửi bước sau đó, kết quả của nó bị bỏ. Một `Execute` panic thành lỗi, không sập tiến trình. Đổi chữ ký → kiểm tra mọi nơi ghi log (`executed`/`failed`) và `verify`.

## Modifying: `Tpl`, `ValidateTpl`, `precheckProblem`, `needsPrecheck`, `actionFP`, `resp_catalog.precheck*` (13b-2, D-95, D-94)
- **Catalog editor (GUI + `checkCatalog`)**, **thư viện mẫu** (`data/action-templates.json` và bản mock `action-templates.sample.json`, test lệch thư viện), **seed** (`seedCatalog` làm mới `precheck`, `precheck_refuse`, `verify.expect` của hàng dựng sẵn mỗi lần khởi động, không đụng `enabled`/`ai_may_propose`/`connection_id`), **`unavailable`** (lý do "chưa khả dụng": giá trị lúc chạy, `{interface}` thiếu kiểm trước), **`actionFP`** (mọi yêu cầu đang chờ từ trước 13b-2 bị từ chối khi duyệt vì dấu vân tay đổi; sửa chuỗi từ chối/`expect`/kiểm trước của hành động tuỳ chỉnh huỷ yêu cầu đang chờ của nó), **13b-6** (`Exec` lưu bản đã điền của `precheck`/`run`/`rollback`/`verify` và so `precheck_refuse`/`expect` với đầu ra; đổi giới hạn 5 × 80 / 200 ở đây thì đổi cả `contract.ts`, `logic.ts` của GUI, `api/openapi.json`).
- Đổi danh sách header bị cấm (`forbiddenHeader`) phải đổi cả `logic.ts` (`forbiddenHeader`) và D-94; `core/conn/write` (13b-6) lặp lại kiểm tra này trước khi gửi.
- Thêm cột vào `resp_catalog` phải thêm vào `catCols`, `scanCat`, `saveCat` và `seedCatalog` cùng lúc (bốn chỗ); `precheck_expect` (sau rà soát) đã vào migration `0002` (chưa phát hành nên sửa tại chỗ).
- `readonly.go` (`cliProblem`, `readBackProblem`, `normalizeOutput`, `precheckVerdict`, `readBackHolds`) + `data/cli-ban.json` (và bản mock `cli-ban.sample.json`, test lệch): đổi danh sách lệnh cấm hay luật so khớp đầu ra là đổi hợp đồng của 13b-6 (executor gọi `normalizeOutput`/`precheckVerdict`/`readBackHolds` với đầu ra thiết bị rồi bỏ đầu ra, INV-22). `normalizeOutput` phải giữ phân biệt hoa thường và không được nới lỏng so khớp.
- `portLikeParams` (`params.go`): thêm kiểu tham số mới có thể gọi tên cổng thì thêm vào đây.

## Modifying: `Fill(tpl, values, transport) (string, error)` / `ValidateParam(type, v)` (D-47, INV-14)
- **Rule engine**, **Catalog editor** (kiểm mẫu khi lưu), **Simulate**, **AI proposals**: đổi tập ký tự cho phép hoặc quy tắc escape → có thể mở đường tiêm lệnh từ dữ liệu của kẻ tấn công (tên máy, tên miền). Phải chạy lại fuzz với dữ liệu trigger độc hại.

## Modifying: `AIGate.Check(ctx, ProposeBody) (Outcome, error)` (INV-15)
- **ai** (cổng Go `Service.Propose(ProposeBody{Trigger, ActionID, Params, Confidence, Evidence ≤ 10, Why ≤ 400})` với tác nhân `ai:response`, 13b-10, D-97; `POST /response/ai/proposals` chỉ ở bản xem trước): đổi ngưỡng (0.8, 7 ngày, 2/giờ 5/ngày, 50%/10) → đổi lượng yêu cầu người duyệt nhận; ngưỡng là hằng số hợp đồng (`AI_MIN_CONFIDENCE`, `AI_REPEAT_DAYS`).

## Modifying: `Log.Append(kind, actor, detail)` / `Log.Verify()` (INV-19)
- **core/logs export** (`response`): công thức hash là hợp đồng với trình kiểm offline và GUI (`logic.ts`); đổi → chuỗi cũ không kiểm lại được. **ai** có chuỗi riêng (xem `ai` câu hỏi mở 2).

## Modifying: `Blocklist.Render(token) []byte` + token
- **Firewall của khách** (FortiGate External Block List, Palo Alto EDL, pfSense/OPNsense URL Table, MikroTik fetch) kéo URL này: đổi định dạng (một IP một dòng) hoặc đường dẫn → firewall khách ngừng cập nhật mà không báo lỗi. Tạo lại token vô hiệu ngay địa chỉ cũ.

## Modifying: `Settings` (envelope: breaker, multi-target, maintenance, expiry, AI gates)
- **GUI Settings → AI response**, **notify** (kênh sẵn sàng duyệt = `ready`): đổi khoảng giá trị → `SettingsInput` của GUI và OpenAPI.

## Disabling this module
- Trang Response, nút Respond (Findings, Incidents), kế hoạch AI trên Findings: "module đang tắt".
- **Firewall khách kéo danh sách chặn nhận 404, giữ bản đã nạp** (không gỡ chặn nào). Hành động đã chạy có TTL **không** tự hoàn tác trong lúc tắt.
- `notify`: không gửi yêu cầu duyệt; `Decide` từ chat bị từ chối. `ai`: `Propose` bị từ chối (module tắt), kế hoạch `response-plan` vẫn là việc AI nhưng không có nơi hiển thị. `core/conn`: kết nối vẫn sửa/xoá được; `ChangesInForce` vẫn đọc `resp_*` để từ chối xoá kết nối còn thay đổi đang hiệu lực.
- `resp_*`, `resp_log` giữ nguyên; export log vẫn có.

## Modifying: `claimItem`, `finishItem`, `failStuck` (requests.go: vòng đời một item)
- `claimItem` là compare-and-set duy nhất cho phép gửi bước: đọc lại công tắc thực thi, cầu dao, cửa sổ bảo trì **trong giao dịch** đánh dấu `running`. `failStuck` chỉ làm hỏng item theo dấu `running` nó đã đọc (`itemOutcome.sweep/ifRunning`); `finishItem` cho kết quả thật của `runItem` (`fromRun`) thay \"State unknown\" của sweep. Thêm cổng mới cho `runItem` = thêm vào cả `claimItem`, không chỉ `gateItem`. Dấu vân tay hành động (`actionFP`: mẫu + rủi ro) là cổng của `gateItem`; thêm trường vào danh mục ảnh hưởng mẫu/rủi ro thì thêm vào `actionFP` và vào điều kiện huỷ yêu cầu của `ChangeAction`.

## Modifying: `publishable` (bảng `notPublishable`) và `inventory.DevicesOfKind`
- **blocklist** (danh sách công bố cho firewall khách), **admin view** (không liệt kê mục không công bố). `inventory.DevicesOfKind`/`KindDevice` là đọc trung lập của kho cho danh sách không-bao-giờ-đụng (xem IMPACT của inventory).

## Cổng mới của phần 2 (WP-13b; kế hoạch, chưa có mã)
- **`Notifier.Approvers(ctx, channel)` + `Notifier.RequestApproval(ctx, ApprovalMessage{RequestID, Title, What ≤ 4 KiB, Risk, InAppOnly, Channels, Expires}) (sentTo, err)`** (13b-7, D-96): gọi sau commit với hạn 60 s; `cmd/vedette` nối tới `notify.SendApprovalRequest` (thêm `Channels`, `InAppOnly`). Đổi `InAppOnly`/`Channels` = đổi ai nhận nút hay liên kết duyệt; test INV-4, INV-16, POST-5.
- **`LinkTokens{ID, Verify}`, `RecordToken`, `LinkView`, `DecideByLink`** (13b-7): `Verify` = `notify.VerifyApprovalLink`; `RecordToken` là `notify.TokenRecorder` do `response` cài (bảng `resp_tokens` v2). Đổi thứ tự kiểm của `DecideByLink` (INV-4) = đổi ai duyệt được bằng thư.
- **`DecideFromChat(ChatDecision{Channel, ExternalID, RequestID, Decision, Code}) (ChatOutcome{Status, Approvals, Required, Message}, error)` và `RecordReplyCode`** (13b-8): người gọi duy nhất là listener của `notify` qua `notify.Config.Decisions` (adapter ở `cmd/vedette`). Với Zalo cá nhân `RequestID` có thể rỗng: `response` so băm mã với các bản ghi mã còn mở của đúng `(channel, address)` (`approval-tokens.md` §7). Đổi = đổi ai duyệt được từ chat.
- **`TwoStep.Verify(ctx, userID, code, purpose)`** (13b-9) = `core/auth.VerifyTwoStep` (D-98); nil = từ chối 403 `twofa_required`.
- **`Evidence{IocHit, ConfigRead}`, `Planner{Available, Plan}`** (13b-10, 13b-11): `logs` (WP-24) cài `IocHit`, `ai` (WP-25) cài `ConfigRead` và `Planner`; nil = bằng chứng không hợp lệ (422 `evidence_invalid`) / không có kế hoạch.
- **`ChangesInForce(ctx, connectionID) (bool, error)`** (13b-4): `core/conn` gọi trước khi xoá kết nối (409 `in_use`); lỗi đọc = từ chối xoá.
