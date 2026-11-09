# Notify Contract

> Tier: standard · Story: S-NOT-1, S-NOT-2, S-ALERT-1, S-ALERT-3, S-RESP-2 (phần kênh duyệt) · Last verified: 2026-11-09 (WP-22: dịch vụ, endpoint, job, sự kiện đã nối vào cmd/vedette; chưa nối người dùng/2FA email/người duyệt của core, xem IMPACT)

Nguồn hành vi: `web/src/features/notify/{contract,mocks}.ts`. Luồng dữ liệu: `PRIVACY.md` luồng 5.

## Invariants
- **INV-1**: Bí mật kênh (token bot, mật khẩu SMTP, webhook Slack, khoá ký, phiên Zalo cá nhân, `xapp-`/`xoxb-`) qua `core/secrets`; API chỉ trả `secret_last4` và `approval_last4` (SYS-4).
- **INV-2**: Tin lỗ hổng chỉ gửi cho finding khớp một thiết bị; KEV không khớp không gửi, chỉ đếm vào `HistoryResponse.suppressed {count, days}`. `TestContract_INV2_NoUnmatchedCVE`
- **INV-3**: Gộp tin: khi `grouping.enabled`, nhiều CVE cùng sản phẩm trong `window_min ∈ {15,60,240}` thành một tin.
- **INV-4**: Mỗi kênh chỉ nhận tin có mức ≥ `min_severity` của kênh (`critical|high|medium|low`).
- **INV-5**: Giờ im lặng: `from≠to` khi bật, có thể qua nửa đêm; `allow_critical=true` cho tin `critical` đi qua. Tin khác bị hoãn tới hết giờ rồi gửi gộp (D-57(8), D-67). `TestContract_INV5_QuietHoursHoldThenReleaseGrouped`
- **INV-6**: Từ lúc finding khớp tới lúc có tin ≤ 60 phút (S-ALERT-1). Mọi lần thử gửi ghi `SendRecord {channel, to, at, ok, error?}`; không có lần gửi nào không có bản ghi.
- **INV-7**: Duyệt trong kênh (D-46): nút hoặc mã trả lời trong kênh chỉ có ở `slack|telegram|zalo-personal`; webhook → 400 `approvals_unsupported`; Zalo OA không có nút trong kênh: yêu cầu duyệt chỉ tới Zalo OA dưới dạng liên kết ký dùng một lần (như email, `docs/specs/approval-tokens.md` §7), chỉ cho rủi ro thấp hoặc trung bình, rủi ro cao không bao giờ qua kênh có liên kết (D-57(20)); bật duyệt thì ≥ 1 người duyệt; người duyệt là người dùng Vedette đang bật, vai `operator|admin` (viewer → 400), không trùng, địa chỉ đúng định dạng của kênh. Email: liên kết ký dùng một lần, hết hạn 30 phút, gắn với hành động + người nhận, duyệt phải bấm POST trên trang xác nhận (trình quét liên kết không tự duyệt); không duyệt bằng thư trả lời. Slack Socket Mode và Telegram long polling chỉ mở kết nối ra, không cổng vào. `notify` chuyển quyết định cho `response`, không tự thực thi hành động.
- **INV-8**: Kiểm biên: webhook Slack phải `https://hooks.slack.com/services/…`; webhook chung `https` (http chỉ host nội bộ); SMTP: cổng 587 ↔ `starttls`, 465 ↔ `ssl`, host là tên miền/IPv4; email nhận hợp lệ.
- **INV-9**: Kênh email chở cả mã 2FA (D-35). `ChannelsResponse.email_code_users` = số người dùng 2FA email; khi tắt/xoá kênh email còn người dùng đó, phản hồi vẫn thực hiện nhưng giao diện cảnh báo; `core` trả 503 cho họ.
- **INV-10**: Incident (D-52): `kind ∈ {trap, bad_address, log_anomaly, unknown_device}`; không bao giờ có loại lỗ hổng; lặp lại gộp vào một incident (`count`, `first_seen`, `last_seen`); trạng thái `new → acknowledged → resolved` và mở lại, ghi `handled_by/handled_at/note` (note ≤ 500); mỗi PATCH ghi `core_audit`.
- **INV-11**: `resend` chỉ khi kênh đã cấu hình và bật (409 `channel_not_ready`); test gửi chỉ khi đã lưu cấu hình (400 `not_configured`) và ghi `last_test`.
- **INV-12**: Zalo cá nhân là kênh không chính thức: giao diện luôn nêu rủi ro khoá tài khoản; xoá kênh xoá luôn phiên.

## Preconditions / Postconditions
- **PRE-1** (`Publish(Notice)`): `Kind`, `Severity ∈ {critical,high,medium,low,info}`, `Link`. **POST-1**: mỗi kênh bật và đạt `min_severity` nhận tin (trừ giờ im lặng/gộp) và có `SendRecord`.
- **PRE-2** (`OpenIncident(in)`): `kind` hợp lệ. **POST-2**: tạo hoặc tăng `count` của incident trùng khoá (kind, nguồn, đích); phát `notify.incident.created` chỉ khi tạo mới.
- **PRE-3** (`PUT /notify/channels/{type}`): `admin`; `type` ∈ 6 loại, nếu không → 404. **POST-3**: cấu hình lưu, `last_test=null`, secret cũ giữ khi bỏ trống; `core_audit` không chứa secret.
- **PRE-4** (`SendApprovalRequest(req, channels)`): kênh có `approvals=true`. **POST-4**: phát `notify.approval.requested`; kết quả bấm nút → `notify.approval.decided {request_id, decision, approver, channel}`.
- **PRE-5** (`EmailReady()`): không. **POST-5**: `(ok, reason ∈ {module_off, channel_not_ready})` cho `core`.

## Forbidden
- **FORBID-1**: Gửi tin lỗ hổng không khớp thiết bị.
- **FORBID-2**: Trả hoặc log bí mật kênh; đưa bí mật vào xuất log.
- **FORBID-3**: Duyệt hành động bằng thư trả lời, hoặc bằng GET.
- **FORBID-4**: Mở cổng vào cho kênh chat.
- **FORBID-5**: Tự thực thi hành động đã duyệt (thuộc `response`).
- **FORBID-6**: Gửi dữ liệu ra ngoài các kênh khách đã cấu hình (PRIVACY luồng 5).

## Dependencies
- **DEPENDS ON**: `core`. Tuỳ chọn: `inventory` (tên thiết bị), `findings` (finding). Qua interface nhỏ trong `Config` (không đọc bảng module khác): `Users` (người dùng còn hoạt động + vai, số người dùng 2FA email: do `core/auth` cài), `Bus` (`core/events.Bus`), `FindingDirectory` (module findings), `DeviceDirectory` (inventory), `TokenRecorder` (module response lưu bản ghi token duyệt), `ModuleGate` (`modreg.Registry`).
- **DEPENDED ON BY**: `core` (mã 2FA email), `findings`/`honeypot`/`logs`/`response`/`reports` (gửi tin), `inventory` (báo thiết bị mới).

## Endpoints owned (role tối thiểu)
| Route | Vai |
|---|---|
| `GET /notify/incidents`, `/notify/incidents/{id}`, `/notify/findings/{id}/notices`, `/notify/alerts/{id}/target` | viewer |
| `PATCH /notify/incidents/{id}`; `POST /notify/history/{id}/resend` | operator |
| `GET /notify/history`, `/notify/channels`; `PUT,DELETE /notify/channels/{type}`; `POST /notify/channels/{type}/test`; `PUT /notify/rules` | admin |

## Tables owned (`notify_`)
`notify_channel`, `notify_approver`, `notify_setting` (giờ im lặng + gộp), `notify_incident` + `notify_incident_device`, `notify_notice` + `notify_notice_finding` (tin lỗ hổng), `notify_send` (mỗi lần gửi, giữ nguyên `channel.Message` để gửi lại) + `notify_send_notice`, `notify_suppressed_day` (đếm KEV không khớp), `notify_pending` (hàng đợi gửi: claim trong giao dịch trước khi gửi). Tên theo DATA_MODEL 4.4; khác biệt liệt kê ở IMPACT.

## Events
- **Phát**: `notify.incident.created {id, kind, severity}`, `notify.message.sent|failed {id, channel}`, `notify.approval.requested`, `notify.approval.decided`, `notify.channel.changed {type}`.
- **Yêu cầu cho WP-22 (D-78, đường cơ sở)**: khi `feeds` kéo danh sách CISA lần đầu vào bảng rỗng, nó phát `feeds.sync.baseline` (không phát từng `feeds.vuln.new_kev`); `inventory` khớp lại tất cả và `findings` tạo hàng loạt `findings.finding.created` từ đó. **notify không gửi tin nào cho đường cơ sở**: không cho sự kiện đó, cũng không cho các `findings.finding.created` do lượt khớp lại sinh ra (ví dụ: khi nhận `feeds.sync.baseline` thì im lặng tới khi lượt khớp lại xong, hoặc bỏ finding có `first_seen` trước mốc đó). Các lần kéo sau, và thiết bị mới, báo bình thường.
- **Nhận** (`core/events` bắt buộc tên 3 đoạn `<module>.<đối tượng>.<động từ>`, nên hai tên 2 đoạn của bản nháp đổi): `findings.finding.created {finding_id, asset_id, cve, severity, basis}` và `findings.finding.status_changed {finding_id, from, to}` (chỉ `to=confirmed` thành tin; cần `FindingDirectory`), `inventory.asset.discovered {asset_id, notify}` (chỉ khi `notify`), **`honeypot.hit.created`** (trước: `honeypot.hit`; `{id, ts, service, src_ip, label}`), **`logs.anomaly.detected`** và **`logs.bad_address.detected`** (trước: `logs.anomaly`, `logs.bad_address`; `{source, target, title, what, action, severity, devices[]}`, nhóm logs chốt lại tên); `response.approval.requested` và `reports.report.ready` chưa nối (chưa có payload). Handler chỉ ghi DB và xếp hàng đợi; việc gửi là của job `deliver` (15 s)

## Behaviour khi tắt
Không route, không job; không tin nào đi. Trang Incidents mất; panel "ai được báo" ở trang finding mất; `core` báo 2FA email `module_off`; `response` không có kênh duyệt (nó phụ thuộc `notify`). Cấu hình kênh và lịch sử giữ.

## Story và quyết định
S-NOT-1, S-NOT-2, S-ALERT-1, S-ALERT-3, S-RESP-2. D-35 mã email; D-38 Slack; D-46 duyệt từng kênh; D-52 Findings ≠ Incidents.

## Không khớp / câu hỏi mở
- ~~Giờ im lặng: tin không phải `critical` bị hoãn tới hết giờ hay bỏ?~~ Đã chốt (D-57(8), D-67): hoãn, hết giờ gửi một tin gộp theo sản phẩm; `critical` đi ngay khi `allow_critical`, còn không thì cũng hoãn.
- ~~Khoá khớp để gộp incident~~: `kind + nguồn + đích`, băm SHA-256, chỉ gộp vào incident **chưa `resolved`**; lặp lại sau khi đã `resolved` là incident mới. Chỉ incident mới được gửi; lặp lại chỉ tăng `count`/`last_seen` (không gửi lại, không ghi audit).
- Giới hạn đã biết: gửi là at-most-once. Hàng đợi bị claim mà hộp dừng trước khi gửi xong (quá 15 phút) được ghi thành lần gửi **thất bại** ("did not send again") và không tự gửi lại; người dùng bấm Resend.
- `notify.approval.decided` chưa phát: nút/mã trả lời trong kênh (Slack Socket Mode, Telegram long polling, mã trả lời Zalo cá nhân) chưa làm, xem `.ai/deferred/feat-notify-module.md`.
- Lịch sử gửi trả tối đa 500 dòng mới nhất (API_CONVENTIONS §6); chưa có phân trang trong `contract.ts`.
- ~~Nếu `mitigation` tắt thì không có finding~~: đã giải quyết bởi D-57(6) — finding thuộc module `findings`; tắt `mitigation` không làm mất tin lỗ hổng (S-ALERT-1). Tắt `findings` thì không có tin lỗ hổng.
