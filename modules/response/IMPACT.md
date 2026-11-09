# Response — Change Impact Map

> WP-13a đã có mã Go (package `modules/response`); chữ ký dưới đây còn là tên khái niệm: `Evaluate`/`fire` (engine.go), `approve`/`runItem` (requests.go; `runItem` là nơi duy nhất gửi bước tới thiết bị; `markRunning`/`failStuck` ghi trạng thái "đang chạy"), `Fill`/`CheckValue`/`ValidateTpl` (params.go), `appendLog`/`VerifyLog` (service.go, plans.go), `FetchBlocklist`/`renderBlocklist` (blocklist.go). Phần AI (`AIGate`) là 13b. Module **rủi ro cao**: mọi thay đổi ở cổng chặn (INV-1…16) cần test hợp đồng và ghi rõ trong commit.

## Modifying: `Engine.Evaluate(ctx, Event) error` (khớp quy tắc, dựng yêu cầu) — 6 nguồn sự kiện
- **honeypot** (`Hits`/`honeypot.hit`), **logs** (`IocHits`), **findings** (`findings.finding.created|status_changed`, D-57 (6)), **inventory** (thiết bị chưa duyệt), **exposure** (cổng mới), **scheduler** (lịch): đổi tên/kiểu trường trigger → điều kiện và tham số `{{trigger.field}}` của quy tắc đang có không còn khớp, quy tắc im lặng. Danh mục trường (`/response/triggers`) là hợp đồng với GUI.

## Modifying: `Approve(ctx, reqID, Approver, items, code) (Request, error)` — 4 người gọi
- **HTTP** `/response/actions/{id}/approve` (app); **kênh chat** (Slack Socket Mode, Telegram long polling, Zalo cá nhân) qua `notify`; **liên kết email/Zalo OA** `/response/approve/{token}`; **rule engine** (`via=auto`, chỉ INV-5). Đổi thứ tự cổng (INV-9) hoặc điều kiện hai người → thay đổi ai có thể gây thay đổi trên thiết bị; test `TestContract_INV2_*`, `INV16_*` bắt buộc.

## Modifying: `RequestProposal` và hình dạng của `resp_plans.steps[].proposal` (job kế hoạch AI, 13b)
- Đề xuất chỉ chứa `action_id` + `params` có kiểu (+ `ttl_min`, `asset_id`, `asset_name`); mọi lệnh/đường dẫn/body do `planAction` dựng từ danh mục lúc xem và lúc yêu cầu. Job kế hoạch của 13b phải ghi đúng dạng này; dạng cũ (lệnh lưu sẵn) bị từ chối `tool_not_allowed`.

## Modifying: `Directory`, `ConnectionInfo` (cmd/vedette, 13b)
- `Directory.DevicesOfKind` nuôi danh sách không đụng (router, firewall); lỗi đọc = từ chối hành động. `ConnectionInfo.UpdatedAt` phải đổi mỗi khi kết nối bị sửa (địa chỉ, thông tin xác thực, công cụ): nó nằm trong dấu vân tay lưu theo item (INV-9 `connection_changed`).

## Modifying: `Execute(ctx, Item) (Result, error)` — 1 người gọi (chỉ `Approve`)
- Gọi **công cụ ghi** của `ai.Connections`. Là điểm duy nhất của FORBID-1; không thêm người gọi thứ hai. Đổi chữ ký → kiểm tra mọi nơi ghi log (`executed`/`failed`) và `verify`.

## Modifying: `Fill(tpl, values, transport) (string, error)` / `ValidateParam(type, v)` (D-47, INV-14)
- **Rule engine**, **Catalog editor** (kiểm mẫu khi lưu), **Simulate**, **AI proposals**: đổi tập ký tự cho phép hoặc quy tắc escape → có thể mở đường tiêm lệnh từ dữ liệu của kẻ tấn công (tên máy, tên miền). Phải chạy lại fuzz với dữ liệu trigger độc hại.

## Modifying: `AIGate.Check(ctx, ProposeBody) (Outcome, error)` (INV-15)
- **ai** (`POST /response/ai/proposals`): đổi ngưỡng (0.8, 7 ngày, 2/giờ 5/ngày, 50%/10) → đổi lượng yêu cầu người duyệt nhận; ngưỡng là hằng số hợp đồng (`AI_MIN_CONFIDENCE`, `AI_REPEAT_DAYS`).

## Modifying: `Log.Append(kind, actor, detail)` / `Log.Verify()` (INV-19)
- **core/logs export** (`response`): công thức hash là hợp đồng với trình kiểm offline và GUI (`logic.ts`); đổi → chuỗi cũ không kiểm lại được. **ai** có chuỗi riêng (xem `ai` câu hỏi mở 2).

## Modifying: `Blocklist.Render(token) []byte` + token
- **Firewall của khách** (FortiGate External Block List, Palo Alto EDL, pfSense/OPNsense URL Table, MikroTik fetch) kéo URL này: đổi định dạng (một IP một dòng) hoặc đường dẫn → firewall khách ngừng cập nhật mà không báo lỗi. Tạo lại token vô hiệu ngay địa chỉ cũ.

## Modifying: `Settings` (envelope: breaker, multi-target, maintenance, expiry, AI gates)
- **GUI Settings → AI response**, **notify** (kênh sẵn sàng duyệt = `ready`): đổi khoảng giá trị → `SettingsInput` của GUI và OpenAPI.

## Disabling this module
- Trang Response, nút Respond (Findings, Incidents), kế hoạch AI trên Findings: "module đang tắt".
- **Firewall khách kéo danh sách chặn nhận 404, giữ bản đã nạp** (không gỡ chặn nào). Hành động đã chạy có TTL **không** tự hoàn tác trong lúc tắt.
- `notify`: không gửi yêu cầu duyệt. `ai`: yêu cầu `/response/ai/proposals` bị từ chối (module tắt), kế hoạch `response-plan` vẫn là việc AI nhưng không có nơi hiển thị.
- `resp_*`, `resp_log` giữ nguyên; export log vẫn có.
