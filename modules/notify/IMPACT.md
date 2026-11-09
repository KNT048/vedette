# Notify — Change Impact Map

## Modifying: `notify.Service.Publish(ctx, Notice)`
- **findings** (tin lỗ hổng), **reports** (báo cáo tuần), **honeypot/logs** (qua `OpenIncident`), **inventory** (thiết bị mới). Đổi `Notice` hay quy tắc `min_severity`/gộp thay đổi thứ người dùng nhận; test `INV2`, `INV4` phải xanh.

## Modifying: `notify.Service.OpenIncident(ctx, IncidentInput)`
- **honeypot**, **logs**, **inventory**, **response** (nút Respond ở `/response?incident=<id>`). Đổi khoá gộp = đổi số incident người dùng thấy.

## Modifying: `notify.Service.EmailReady() (bool, reason)` và `SendEmailCode(ctx, to, code)`
- **core** (đăng nhập 2FA email, `/core/account` `twofa_email.available`). Đổi lý do trả về làm sai thông báo ở trang đăng nhập; không bao giờ để rơi về chỉ mật khẩu (core INV-8).

## Modifying: `notify.Service.SendApprovalRequest`, sự kiện `notify.approval.decided`
- **response** (người duyệt, hết hạn 15–30 phút, 2 người cho rủi ro cao). Đổi payload quyết định = phá luồng duyệt; `notify` không biết ngữ nghĩa hành động.

## Modifying: `GET /notify/channels` `approvals`, `approvers`
- **SPA** `ChannelsSettings`; module khác đọc cấu hình duyệt qua interface `ApprovalChannels()`, không đọc bảng `notify_*`.

## Modifying: lịch sử `HistoryItem.kind` (`incident|vuln|approval`) và `GET /notify/findings/{id}/notices`
- **findings** (panel `finding.panels` ở trang finding), **core** (`/core/logs/export` danh mục `alerts`).

## Disabling this module
- Không tin nào gửi; Incidents và Settings → Alert channels mất; panel thông báo ở finding mất.
- `core`: 2FA email báo `module_off`, người dùng 2FA email bị khoá cho tới khi quản trị đặt lại.
- `response`: không kênh duyệt. `reports`: không gửi tự động. Dữ liệu kênh/lịch sử giữ.

## Thư viện WP-22a (gói `modules/notify` và `modules/notify/channel`, chưa nối core)

Chưa có caller ngoài test; WP-22 nối vào `Service`. Đổi chữ ký dưới đây = sửa chỗ nối của WP-22.

### `channel` (adapter kênh)
- `channel.NewSlack|NewTelegram|NewEmail|NewZalo|NewWebhook|NewZaloPersonal(cfg) (Sender, error)`: kiểm biên (INV-8), lỗi là `*ConfigError{Code, Msg}` (mã giống mock API: `bad_webhook`, `bad_token`, `port_mismatch`, …; `errors.Is(err, ErrInvalidConfig)`). `Sender{Type, Dest, Send(ctx, Message) (Receipt, error)}`.
- Lỗi gửi: `*StatusError{Channel, Code, Reason}` (không bao giờ chứa bí mật hay URL), `ErrInvalidMessage`, `ErrUnsupported` (Zalo cá nhân). `Secret` che mọi cách in (fmt, slog, JSON); `Reveal()` chỉ dùng khi dựng request.
- `Message` là văn bản thuần; mỗi adapter tự escape: Slack (`& < >`, link `<url|Open in Vedette>`), Telegram (văn bản thuần, không `parse_mode`: không có gì để escape, không thể thành link/mention), email (một dòng Subject, RFC 2047 gập dòng; địa chỉ chỉ `local@domain`; body quoted-printable), Zalo OA (văn bản thuần, 2000 ký tự, link luôn giữ), webhook (JSON).
- `EmailConfig`: 587 ↔ `starttls`, 465 ↔ `ssl`; AUTH chỉ gửi sau khi TLS xong và chứng chỉ được kiểm; `none` chỉ cho host nội bộ và không bao giờ AUTH (khác mock: mock vẫn đòi username/mật khẩu cho `none`; adapter không đòi). `ParseRecipients("a@x, b@y")` tách trường `to`.
- **Webhook ký (người nhận kiểm)**: mỗi request có `X-Vedette-Timestamp: <Unix giây>` và `X-Vedette-Signature: sha256=<hex>` với `hex = HMAC-SHA256(khoá ký, timestamp + "." + body thô)`. Người nhận so sánh hằng thời gian và từ chối timestamp cũ (chống phát lại). Body JSON: `event` (= kind: incident|vuln|approval|test), `id`, `severity`, `title`, `device`, `what`, `action`, `items[]`, `url`. Redirect không được theo.
- Telegram/Zalo OA có `BaseURL` (chỉ test dùng); Slack không có (test đổi `http.Client.Transport`).

### `notify` (quy tắc và token)
- `MeetsMin(sev, floor)` (INV-4), `Quiet{Validate, Active, EndsAt}` và `Decide(now, minSev, quiet, sev) (Verdict, releaseAt)` (INV-4/5, D-57(8)): `Skip` dưới ngưỡng, `Hold` trong giờ im lặng (trừ critical khi `allow_critical`), `Send`. Đổi = đổi ai nhận tin lúc nào; test INV4, INV5.
- `Notice.Sendable`, `SplitSendable` (INV-2, FORBID-1), `Group(ns, Grouping)`, `GroupHeld(ns)`, `Batch.Message()`, `Batch.DueAt` (INV-3). Khoá gộp = sản phẩm (không phân biệt hoa thường), cửa sổ tính từ tin đầu của lô.
- `Deliver(ctx, id, sender, msg, now) SendRecord`: luôn trả bản ghi (INV-6).
- `MintApprovalToken(key, Binding{RequestID, UserID, Channel, ExpiresAt}, risk, now)`, `ParseApprovalToken`, `VerifyApprovalToken` (GET: không đổi gì), `ConsumeApprovalToken(ctx, NonceStore, …)` (POST: đốt một lần), `ApprovalExpiry`, `ApprovalViaChannelAllowed(channel, risk)`. Định dạng đúng `docs/specs/approval-tokens.md` §4.1; `Binding` đọc từ bản ghi `response_tokens` theo `token_id`; khoá chọn theo `key_id` của bản ghi (thư viện không giữ keyring). Rủi ro cao qua email bị từ chối ngay lúc ký (D-57(20)); core phải kiểm lại khi nhận quyết định.
