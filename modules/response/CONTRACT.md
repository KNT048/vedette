# Response Contract

> Tier: tuỳ chọn, **rủi ro cao**, tắt mặc định · Story: S-RESP-1..4, S-AI-8 · Quyết định: D-40, D-41, D-44, D-46, D-47, D-48, D-51 (**D-51 thắng khi mâu thuẫn**) · Last verified: 2026-11-09 (WP-13a: phần 1 đã có mã, xem "Trạng thái WP-13a")
> Nguồn hành vi thực tế: `web/src/features/response/{contract,state,engine,ai,logic,data,mocks}.ts` (mock đã có test cổng chặn).
> Module này là **ngoại lệ duy nhất** của SYS-8 (D-41): nơi duy nhất mã của Vedette thực thi công cụ ghi lên thiết bị khác, và chỉ sau khi một yêu cầu được duyệt.
> Mô hình: quy tắc của người dùng **KHI** (trigger có trường dữ liệu) **NẾU** (điều kiện) **THÌ** (chuỗi hành động có tham số kiểu) hoặc đề xuất của AI. Máy chủ giữ mẫu lệnh; client không bao giờ gửi lệnh.

## Invariants (luôn đúng)

### Duyệt (D-41, D-44, D-46, D-51)
- **INV-1** **Mặc định mọi yêu cầu cần người duyệt.** Một hành động lên thiết bị khác (`connector_id ≠ null`) chỉ chạy khi `status = approved` hoặc theo INV-5. Hành động "của hộp" (`blocklist_add`, `msg_send`, `webhook_call`: `connector_id = null`) cũng cần duyệt theo quy tắc mặc định nhưng không bị công tắc thực thi chặn (INV-9).
- **INV-2** **Rủi ro cao cần 2 người duyệt khác nhau**: `requires_approvals = 2` khi có item `risk=high`, hoặc một item có `targets` > `multi_target_max`, hoặc tổng `targets` > `multi_target_max` (`two_because` nêu lý do). Người thứ hai phải duyệt **đúng tập hành động** của người thứ nhất (409 `selection_differs`); cùng một `user_id` duyệt hai lần bị từ chối (409 `same_approver`). Một yêu cầu = một gói; duyệt một lần phủ cả gói (D-51 thay "một hành động mỗi lần duyệt" của D-41).
- **INV-3** Người duyệt phải là người dùng Vedette vai **operator trở lên**, có danh tính kênh nằm trong danh sách người duyệt của kênh đó (cấu hình ngay trong kênh, D-46). Duyệt từ chat chỉ tính khi `external_id` nằm trong danh sách đó. Nút bấm: Slack (Socket Mode), Telegram (bot, long polling). Zalo cá nhân (API không chính thức, cảnh báo rõ): trả lời mã. Email và Zalo OA: liên kết (INV-4).
- **INV-4** **Liên kết duyệt qua email/Zalo OA** (`/response/approve/{token}`): token ký, dùng một lần, hết hạn 30 phút, gắn đúng một yêu cầu và một người nhận; `GET` chỉ đọc (không bao giờ duyệt), phải `POST` với `decision` để trình quét liên kết không duyệt hộ; không duyệt bằng thư trả lời. Trạng thái xem: `ready | expired | used | decided | unknown`.
- **INV-5** **"Duyệt sẵn" (pre-approved)**, trường của quy tắc: TẮT mặc định; chỉ **admin** đặt được (vai tối thiểu của `POST/PUT /response/rules` là admin); `pre_approved = true` bị từ chối trừ khi **mọi** hành động của quy tắc có `risk = low`, **hoàn tác được** (có bước rollback) và `ttl_min ≤ 1440` (không `null`); kiểm lại khi chạy (không chỉ khi lưu). Yêu cầu sinh ra mang `pre_approved = true`, `via = auto`, ghi `resp_log`. Mọi cổng khác vẫn áp dụng (INV-9). Yêu cầu của AI không phải quy tắc nên không bao giờ được duyệt sẵn (INV-15, INV-16).
- **INV-6** Yêu cầu hết hạn sau `expiry_min` ∈ [15, 30] phút: `status = expired`, mọi item `skipped`, **không có gì bị đổi**, gửi thông báo; duyệt sau hạn → 409 `expired`. Yêu cầu không còn `pending` thì duyệt/từ chối → 409 `not_pending`.
- **INV-7** Công tắc thực thi (`Settings.execution`) **TẮT mặc định**. Bật cần: admin, đã bật đăng nhập hai bước, và gõ đúng `I ACCEPT THE RISK`; ghi `accepted_by/accepted_at`. Tắt: admin. Khi tắt: mọi hành động lên thiết bị bị từ chối ở cả duyệt lẫn hoàn tác (409 `execution_off`). `PUT /response/settings` **không** đổi công tắc này.
- **INV-8** Dừng khẩn cấp (`/response/emergency-stop`, vai operator): tắt thực thi ngay và huỷ mọi yêu cầu `pending` trong cùng một thao tác; trả số đã huỷ; ghi log. Cầu dao chung chỉ admin mở lại.

### Vỏ an toàn (D-51)
- **INV-9** Cổng chặn, theo thứ tự, áp dụng cho **mọi** nguồn (người duyệt, duyệt sẵn, AI) và kiểm lại ngay trước khi chạy: công tắc thực thi (chỉ hành động lên thiết bị); trạng thái (`pending`); hết hạn; chọn item hợp lệ; hai người khác nhau; (AI rủi ro cao) duyệt trong app + mã hai bước; hành động còn bật trong danh mục (403 `tool_not_allowed`) và kết nối chưa đổi/còn công cụ ghi (409 `tool_unavailable`); hạn mức `max_per_hour` ∈ [1,20] hành động thiết bị đã duyệt/giờ (429 `rate_limited`).
- **INV-10** **Danh sách không bao giờ đụng** (gateway, DNS, domain controller, chính hộp, IP quản trị, dịch vụ khách khai: IP, CIDR, hoặc domain): mục tiêu khớp → hành động bị từ chối `never_touch`, không chạy, ghi log. Kiểm lúc lập kế hoạch **và** lúc chạy. Danh sách chặn (INV-17) không bao giờ chứa mục khớp danh sách này.
- **INV-11** Gộp trùng: cùng (mục tiêu, hành động) đang mở (`pending/approved`) hoặc đang có hiệu lực → gộp, không tạo yêu cầu mới, ghi `deduped`. Một lần chạy quy tắc = **một** yêu cầu gộp.
- **INV-12** Giới hạn theo quy tắc `max_per_hour` ∈ [1,100]; **cầu dao chung** `breaker_max_per_hour` ∈ [1,200] (đếm hành động của quy tắc và AI): vượt → `breaker_tripped_at` đặt, **mọi quy tắc và đề xuất AI tạm dừng**, thông báo `breaker_notified`; chỉ admin `POST /response/breaker/reset`. Hành động chạm nhiều mục tiêu hơn `multi_target_max` cần người duyệt thứ hai (INV-2). Cửa sổ bảo trì: trong cửa sổ không quy tắc hay yêu cầu AI nào được tạo.
- **INV-13** Mỗi hành động có **hoàn tác**, `ttl_min` (tự gỡ, 5..43200 phút, hoặc `null` = giữ tới khi gỡ tay) và **kiểm lại sau khi chạy** (`verified {ok, detail}`; rỗng khi hành động không đọc lại được). Hoàn tác: operator; từ chối khi thực thi tắt. TTL hết hạn → tự hoàn tác và ghi `ttl_removed`.

### Tham số có kiểu (D-47, D-51, SYS-1, SYS-2)
- **INV-14a** Dữ liệu của tác nhân (trường trigger: IP nguồn, tên thiết bị, domain, nội dung log…) **do kẻ tấn công kiểm soát**: mọi giá trị đi vào mẫu phải qua **placeholder có kiểu** (`ip, cidr, domain, port, mac, vlan, interface, text`) và được kiểm theo kiểu trước khi dùng; sai kiểu → từ chối, ghi `refused`, **không chạy gì**. `text` chỉ gồm chữ, số, dấu cách và `. , : @ # / _ -`; không dấu nháy, không ký tự shell, không xuống dòng.
- **INV-14b** **Escape theo đường truyền** là lớp thứ hai (sau kiểm kiểu): `json` → escape chuỗi JSON; `url` → percent-encode; `header` → bỏ CR/LF; `cli` → chỉ giá trị đã qua kiểm kiểu. Ký tự shell `; | & $ \` < > ( ) \ ! ~ ^` **không bao giờ** được phép, kể cả trong phần cố định của mẫu (SYS-1). Mẫu lệnh do máy chủ giữ; `POST` từ client/AI chỉ gồm tên hành động và giá trị tham số; trường `cli/method/path/body/headers` trong yêu cầu AI → từ chối.
- **INV-14c** Danh mục hành động (D-47): hành động dựng sẵn chỉ cho đổi `enabled`, `ai_may_propose`, `connection_id`; hành động tuỳ chỉnh (thêm/sửa/xoá) khai: tên, mô tả, kết nối, mẫu `run/rollback/verify`, rủi ro. Trường mẫu phải hợp loại kết nối (API: `method/path/body`, HTTP thêm `headers`; SSH: `cli`; MCP: công cụ ghi + `body` là đối số JSON). Kết nối chỉ-đọc bị từ chối (409 `read_only`). Xoá chỉ khi không quy tắc nào dùng. Hành động `available=false` có `unavailable_reason`.
- **INV-14d** Quy tắc mới **luôn bắt đầu ở chạy khô** (`live=false`): ghi `dry_run`, không tạo yêu cầu, không chạy; mẫu (template) nhân bản ra quy tắc tắt + chạy khô. `simulate` (quy tắc đã lưu hoặc chưa) dựng đúng lệnh/yêu cầu sẽ chạy với sự kiện gần nhất và `executed = 0` luôn. Giới hạn: điều kiện ≤ 10, hành động 1..6, `schedule_min` 15..10080.

### AI gửi yêu cầu (D-40, D-51): chốt chặn ở máy chủ, không ở prompt
- **INV-15** Một đề xuất của AI (`POST /response/ai/proposals`) chỉ thành **yêu cầu** khi qua đủ: (1) trigger nằm trong `ai.triggers` và `ai_allowed`; (2) hành động có cờ `ai_may_propose`; (3) **bằng chứng có thật**: mỗi `evidence.id` tra được (finding/ioc_hit/config_read); (4) `confidence ≥ 0.8` (`AI_MIN_CONFIDENCE`); (5) một yêu cầu mở cho mỗi (mục tiêu, hành động); (6) bị từ chối thì **7 ngày** không lặp (`AI_REPEAT_DAYS`); (7) hạn mức giờ/ngày (mặc định **2/giờ, 5/ngày**; khoảng 1..20 và 1..100); (8) cầu dao chất lượng: nếu **> 50% của 10 đề xuất đã quyết gần nhất bị từ chối** thì AI bị tạm dừng tới khi admin `resume`; (9) **rủi ro cao**: bộ kiểm thứ hai tất định (`second_check`) phải qua. Không qua → kết quả là `suggestion`/`digest` (không phải yêu cầu), vẫn ghi log.
- **INV-16** Yêu cầu AI rủi ro cao: `in_app_only = true` → chỉ duyệt **trong app bằng mã hai bước**, **hai người khác nhau** (INV-2); duyệt từ chat/email → 403 `in_app_required`; thiếu hai bước → 403 `twofa_required`/`code_required`.
- **INV-17** Danh sách chặn (D-44): firewall **kéo** từ URL nội bộ có token (`/response/blocklist/{token}.txt`, văn bản thuần, mỗi dòng một IP); token là thông tin xác thực duy nhất; tạo lại token vô hiệu hoá địa chỉ cũ ngay; mỗi mục có `source, reason, added_at, expires_at` (TTL tự gỡ). Không cần quyền ghi lên firewall.
- **INV-18** Học từ từ chối: từ chối yêu cầu AI có thể lưu lý do thành gợi ý quy tắc hoặc memory (`remember`) — chỉ là **gợi ý**, không tự áp dụng. Đo tỉ lệ duyệt (`/response/metrics`).

### Nhật ký (D-48)
- **INV-19** `resp_log` chỉ thêm (append-only), chuỗi hash: `hash = SHA-256_hex(prev_hash + "\n" + canon(entry không có hash))`, cùng công thức với `core_audit` và `ai_activity` (D-57 (14); không còn dạng mảng vị trí); `prev_hash` của dòng đầu = 64 ký tự `0`; trả **cũ nhất trước** để kiểm từ đầu. **Không có endpoint sửa/xoá.** Ghi mọi sự kiện: `rule_fired, proposal, request, approved, rejected, executed, rolled_back, ttl_removed, refused, expired, failed, settings, emergency_stop, blocklist_token, dry_run, simulated, deduped, breaker, ai_note`. Mọi **từ chối** cũng được ghi. Giữ mặc định 1 năm (chỉnh được).
- **INV-20** Mọi mutation còn ghi `core_audit` (SYS-3). Không bí mật trong `detail` (SYS-4); bí mật kết nối ở `ai_connectors` (xem `ai`).

## Preconditions (trước khi gọi)
- **PRE-1** `POST /response/proposals/{id}/request` (từ kế hoạch AI): thực thi bật, hành động bật, chưa có yêu cầu mở cho đề xuất đó.
- **PRE-2** `POST /response/execution {enabled:true}`: admin + hai bước bật + đúng cụm `I ACCEPT THE RISK` (INV-7).
- **PRE-3** Tạo quy tắc: vai admin; `trigger` ∈ {honeypot, ioc_connection, finding, unknown_device, log_threshold, new_port, schedule, manual}; trường điều kiện thuộc catalogue trường của trigger đó.
- **PRE-4** Thêm hành động tuỳ chỉnh: kết nối có ít nhất một công cụ ghi đang bật.

## Postconditions (sau khi xong)
- **POST-1** Duyệt đủ số người → từng item được chạy qua kết nối, `status` chuyển `executed` hoặc `failed` (kết nối không trả lời → `failed`, không đổi gì), có `result` và `verified`.
- **POST-2** Hoàn tác → item `rolled_back`, `rolled_back_at` đặt; TTL hết → tự `rolled_back` (`ttl_removed`).
- **POST-3** Từ chối/hết hạn → không thiết bị nào bị đổi.
- **POST-4** `rules/{id}/manual` chạy quy tắc trigger `manual` trên thiết bị chọn; vẫn qua mọi cổng.
- **POST-5** `sent_to` ghi kênh đã nhận yêu cầu duyệt; kênh không "ready" (chưa bật duyệt/chưa có người duyệt) không nhận.

## Forbidden (không bao giờ)
- **FORBID-1** Thực thi bất kỳ công cụ ghi nào ngoài đường: yêu cầu → duyệt (hoặc INV-5) → cổng INV-9 → thực thi. Mọi nơi khác (ai, mcp-server, UI trực tiếp, job) gọi công cụ ghi bị cấm.
- **FORBID-2** Client hoặc AI gửi chuỗi lệnh/mẫu; chuỗi shell tự do; thay placeholder không qua kiểm kiểu và escape (INV-14).
- **FORBID-3** AI tự duyệt; duyệt-sẵn cho yêu cầu AI; hành động rủi ro cao/không hoàn tác được/TTL > 24 giờ ở "duyệt sẵn" (INV-5).
- **FORBID-4** Trả token duyệt, URL duyệt hay token danh sách chặn đầy đủ trong response danh sách/log/audit (bản xem trước mới có `email_links`, admin; **không** có trong bản thật).
- **FORBID-5** Điểm cuối chỉ xem trước (`/response/rules/run`, `/response/actions/{id}/chat-decision`) có trong bản dựng thật.
- **FORBID-6** Sửa/xoá dòng `resp_log`; ghi log mà không nối chuỗi.
- **FORBID-7** Chặn mục thuộc danh sách không đụng; chặn khi đang trong cửa sổ bảo trì; chạy khi cầu dao mở.
- **FORBID-8** Quét/gọi tới host ngoài scope kết nối đã khai (SYS-7).

## Trạng thái WP-13a (phần 1) so với bảng dưới
Đã cài: plans, actions, proposals/request, approve/reject/rollback (trong app), settings, execution, emergency-stop, breaker/reset, triggers, rules (+ simulate, manual), events, templates (+ clone), allowlist, blocklist (+ token, `{token}.txt`), catalog, metrics, log. **Trả 404 như đường lạ** (không có trong bản thật, FORBID-5): `POST /response/rules/run`, `POST /response/actions/{id}/chat-decision`. **Trả 501 `not_implemented` (phần 13b)**: `GET/POST /response/approve/{token}`, `GET /response/ai`, `POST /response/ai/proposals`, `POST /response/ai/resume`. Thiết bị chỉ qua giao diện `Executor` (fake trong test); chưa có kết nối nên hành động lên thiết bị đều "không khả dụng". Chi tiết quyết định: D-88.

## Endpoints owned (từ `contract.ts`)
| Method | Path | Vai tối thiểu | Story |
|---|---|---|---|
| GET | `/response/plans` | viewer | S-RESP-1 |
| GET | `/response/actions` | viewer | S-RESP-2, 3 |
| POST | `/response/proposals/{id}/request` | operator | S-RESP-2 |
| POST | `/response/actions/{id}/approve` | operator | S-RESP-2 |
| POST | `/response/actions/{id}/reject` | operator | S-RESP-2 |
| POST | `/response/actions/{id}/rollback` | operator | S-RESP-2 |
| POST | `/response/actions/{id}/chat-decision` | admin (**chỉ bản xem trước**) | S-RESP-2 |
| GET | `/response/approve/{token}` | public (token) | S-RESP-2 |
| POST | `/response/approve/{token}` | public (token) | S-RESP-2 |
| GET/PUT | `/response/settings` | admin | S-RESP-2, S-AI-8 |
| POST | `/response/execution` | admin | S-RESP-2 |
| POST | `/response/emergency-stop` | operator | S-RESP-2 |
| POST | `/response/breaker/reset` | admin | S-RESP-2 |
| GET | `/response/triggers`, `/response/rules`, `/response/events`, `/response/templates`, `/response/allowlist`, `/response/catalog` | viewer | S-RESP-3, 4 |
| POST/PUT/DELETE | `/response/rules`, `/response/rules/{id}` | admin | S-RESP-3 |
| POST | `/response/rules/run` | operator (**chỉ bản xem trước**) | S-RESP-3 |
| POST | `/response/rules/simulate`, `/response/rules/{id}/manual` | operator | S-RESP-3 |
| POST | `/response/templates/{id}/clone` | admin | S-RESP-3 |
| PUT | `/response/allowlist` | admin | S-RESP-3 |
| GET | `/response/blocklist` ; POST `/response/blocklist/token` | admin | S-RESP-3 |
| GET | `/response/blocklist/{token}.txt` | public (token) | S-RESP-3 |
| POST/PUT/DELETE | `/response/catalog`, `/response/catalog/{id}` | admin | S-RESP-4 |
| GET | `/response/ai`, `/response/metrics` | viewer | S-RESP-2, S-AI-8 |
| POST | `/response/ai/proposals` | operator | S-RESP-2 |
| POST | `/response/ai/resume` | admin | S-RESP-2 |
| GET | `/response/log` | operator | S-RESP-2, 3, S-AI-8 |

## Tables owned
`resp_settings, resp_plans, resp_actions` (yêu cầu gộp có `items`), `resp_catalog, resp_rules, resp_allowlist, resp_blocklist, resp_tokens` (token duyệt một lần), `resp_done` (khoá gộp trùng), `resp_ai_notes, resp_hints`, `resp_log`. Mock đã đặt `resp_*` (WP-06). WP-13a thêm `resp_block_entries` (mục danh sách chặn đang có hiệu lực, thêm lúc item chạy, xoá lúc hoàn tác/hết TTL) và `resp_events` (sự kiện trigger lấy từ bus); `resp_tokens`, `resp_ai_notes`, `resp_hints` đã tạo nhưng phần 1 không ghi. `resp_log` chống sửa/xoá bằng trigger SQLite (D-88).

## Events
- **Nhận (nguồn trigger)**: `honeypot.hit` (honeypot); `logs.ioc_hit` (logs, trigger `ioc_connection`; `confidence` 0..1 ở cả logs và trigger field, D-57 (13)); finding mới/xác nhận (module `findings`: `findings.finding.created`, `findings.finding.status_changed`; D-57 (6)); thiết bị chưa duyệt (`inventory.observation`); ngưỡng log (`log_threshold`); cổng mới trên IP public (`exposure`); lịch; chạy tay. Đọc qua interface của từng module (modules.md), không đọc bảng trực tiếp.
- **Phát** (sau commit, WP-13a, payload là struct trong `modules/response/events.go`, không bí mật/token): `response.request.created {request_id, source, title, risk, items, expires_at, approvals}`, `response.decision.made {request_id, decision: approved|rejected|expired|cancelled, by, final}`, `response.action.executed {request_id, item_id, action_id, device}`, `response.action.rolled_back {request_id, item_id, action_id, auto}`, `response.breaker.tripped {max_per_hour, tripped_at}` cho `notify` (gửi duyệt/thông báo kết quả, 13b) và export log.
- **Đã nối (WP-13a)**: `findings.finding.created`, `findings.finding.status_changed` (to=confirmed) → trigger `finding`; `inventory.asset.discovered` (thiết bị chưa duyệt) → `unknown_device`. Tên dành cho trigger về sau, chưa đăng ký: `honeypot.hit.created`, `logs.ioc_hit.detected`, `logs.threshold.exceeded`, `exposure.port.opened`.

## Khi tắt module (SYS-5)
Không route `/response/*` (kể cả `approve/{token}` và `blocklist/{token}.txt`), không job quy tắc, **firewall của khách kéo danh sách chặn sẽ nhận 404 và đứng yên với bản chặn đã nạp** (không gỡ gì khỏi thiết bị). Yêu cầu `pending` không còn duyệt được. Dữ liệu `resp_*` và chuỗi `resp_log` giữ nguyên. Hành động đã thực thi nhưng có TTL **không** tự hoàn tác khi module tắt (không job): UI/thông báo phải nêu danh sách việc còn hiệu lực trước khi tắt. Nút Respond trên Incidents/Findings báo "module `response` đang tắt".

## Dependencies
- **DEPENDS ON**: `core` (audit, vai, hai bước, scheduler, `core/exec`, `core/secrets`), `ai` (**kết nối ngoài `ai_connectors`** + việc `response-plan`), `notify` (kênh duyệt, danh sách người duyệt trong cấu hình kênh), `inventory` (thiết bị, danh sách không đụng). Mềm: `honeypot`, `logs`, `exposure`, `scan`, `sensor-passive`.
- **DEPENDED ON BY**: GUI `findings` (panel kế hoạch/Respond), `notify` (nhận yêu cầu duyệt), `ai` (`/response/ai/proposals`), `core/logs export` (`resp_log`).

## Câu hỏi mở
1. **Đã chuyển `ai` sang `soft_depends` ở WP-13a (D-88 (12)); còn lại: nối kết nối ở 13b.** MODULES.md ghi `response` phụ thuộc `ai` (đúng vì kết nối ở `ai_connectors`), dù quy tắc không cần AI (D-44). Đề xuất: giữ `depends: ai` hoặc chuyển kết nối lên `core` để `response` chạy khi `ai` tắt.
2. ~~Đổi tên bảng mock `response_*` thành `resp_*`~~ Đã đổi (WP-06; `db.ts` v4).
3. Đọc chéo: GUI dùng `peek` vào `notify_channels`, `logs_ioc_hits`, `hp_hits`; modules.md cấm đọc bảng module khác → thay bằng interface (IMPACT).
4. D-51 "AI rủi ro cao: bộ kiểm thứ hai + duyệt trong app bằng mã hai bước" và "rủi ro cao cần 2 người": hợp đồng đọc là **cả hai** (hai người, mỗi người trong app với mã hai bước), theo mock (`ai.ts`). Xác nhận.
5. Danh tính của "AI agent" khi gọi `/response/ai/proposals` (vai operator): xem `ai` câu hỏi mở 3.
6. ~~`Trigger.confidence` 0..100 so với `IocHit.confidence` 0..1~~ Đã thống nhất 0..1 (D-57 (13)); trường trigger `confidence` và mẫu quy tắc dùng 0.8, 0.9…
7. Mã hai bước "in-app" kiểm bởi `core` (TOTP/email code, D-35): cần hàm `core.VerifyTwoStep(user, code)` công khai.
8. Tắt module khi còn hành động đang có hiệu lực: chặn tắt hay cảnh báo (S-CORE-1)?
