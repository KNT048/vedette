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
- `channel.NewSlack|NewTelegram|NewEmail|NewZalo|NewWebhook|NewZaloPersonal(cfg) (Sender, error)`: kiểm biên (INV-8), lỗi là `*ConfigError{Code, Msg}` (mã giống mock API: `bad_webhook`, `bad_token`, `port_mismatch`, …; thêm `blocked_host`, `insecure_url`, `insecure_smtp`; `errors.Is(err, ErrInvalidConfig)`). `Sender{Type, Dest, Send(ctx, Message) (Receipt, error)}`.
- Lỗi gửi: `*StatusError{Channel, Code, Reason}` (HTTP không 2xx, hoặc mã SMTP), `*ProviderError{Channel, Code, Reason}` (nhà cung cấp từ chối trong câu trả lời 2xx: Zalo `error ≠ 0`, Telegram `ok:false`; không phải "HTTP 200"), `ErrInvalidMessage`, `ErrUnsupported` (Zalo cá nhân). Không lỗi nào chứa bí mật hay URL. Bí mật dùng `core/secrets.Value` (SYS-4: che mọi cách in, fmt, slog, JSON; `Reveal()` chỉ dùng khi dựng request; gói chỉ thêm helper `isSet`). Mọi sender in ra là chuỗi cố định (`%v`, `%+v`, `%#v`) vì fmt không gọi được `Format` trên trường không xuất khẩu (giữ lại làm lớp thứ hai dù `Value` giấu chuỗi sau con trỏ).
- Client HTTP do caller đưa vào được sao chép nông và luôn đặt `CheckRedirect` không theo chuyển hướng; client mặc định có timeout 15 s.
- `Message` là văn bản thuần; mỗi adapter tự xử lý theo đích. Nội dung từ feed (title, device, what, action, items) và link của hộp được tách: link của hộp giữ nguyên là link thật.
  - **Slack**: escape `& < >`; ký tự định dạng mrkdwn `*`, `~`, backtick và `_` (trừ `_` giữa hai chữ/số, vd `snake_case`) trong nội dung feed được thay bằng ký tự giống hệt không định dạng (Slack không có cách escape khác); link `<url|Open in Vedette>`.
  - **Telegram, Zalo OA**: văn bản thuần, không `parse_mode`, nên không có định dạng nào được hiểu. Nhưng Telegram vẫn tự biến URL, `@mention` và `/command` trong văn bản thuần thành link/lệnh, nên trong nội dung feed mỗi `@` hoặc `/` không dính sau chữ/số (vd `://`, `@user`, `/start`, `(/cmd)`) được chèn một zero-width joiner. Phần còn lại không được trung hoà: tên miền trần, địa chỉ email, hashtag, số điện thoại vẫn có thể bị app tự link.
  - **Email**: một dòng Subject gập ≤ 78 ký tự (ASCII gập ở khoảng trắng; còn lại RFC 2047, 4 ký tự mỗi từ); địa chỉ chỉ `local@domain` (không `%`, không tên hiển thị, không ngoặc kép); body quoted-printable.
  - **Webhook**: JSON.
- `EmailConfig`: 587 ↔ `starttls`, 465 ↔ `ssl`; AUTH chỉ gửi sau khi TLS xong và chứng chỉ được kiểm; `none` chỉ cho host nội bộ và không bao giờ AUTH (khác mock: mock vẫn đòi username/mật khẩu cho `none`; adapter không đòi). Một phiên SMTP đọc tối đa 1 MiB từ máy chủ (net/smtp tự nó không giới hạn), tính dưới TLS. `ParseRecipients("a@x, b@y")` tách trường `to`.
- **Webhook ký (người nhận kiểm)**: mỗi request có `X-Vedette-Timestamp: <Unix giây>` và `X-Vedette-Signature: sha256=<hex>` với `hex = HMAC-SHA256(khoá ký, timestamp + "." + body thô)`. Người nhận so sánh hằng thời gian và từ chối timestamp cũ (chống phát lại). Body JSON: `event` (= kind: incident|vuln|approval|test), `id`, `severity`, `title`, `device`, `what`, `action`, `items[]`, `url`. Redirect không được theo.
- **Webhook URL là bí mật** (`WebhookConfig.URL` là `secrets.Value`: đường dẫn/query thường chứa token). `Dest()` và `Receipt.To` chỉ là `scheme://host`. Lịch sử gửi và UI vì vậy không lộ token.
- **Quy tắc đích của webhook** (`NewWebhook` kiểm khi lưu, client mặc định kiểm lại lúc kết nối, trên địa chỉ đã phân giải nên tên DNS trỏ vào địa chỉ cấm hoặc DNS rebinding cũng bị chặn):
  - https hoặc http; http chỉ cho danh sách nội bộ (`10/8`, `172.16/12`, `192.168/16`, `127/8`, `localhost`, `.local`, `.lan`, `.internal`, `.localhost`), giống feeds INV-2.
  - Luôn cấm: link-local (`169.254/16`, `fe80::/10`), không xác định (`0.0.0.0`, `::`), multicast, và địa chỉ của chính hộp (`WebhookConfig.BoxAddrs`, WP-22 điền từ cấu hình mạng). IPv4 nhúng trong IPv6 được tháo ra rồi kiểm.
  - Loopback (`127/8`, `::1`, `localhost`) bị cấm với **https**; chỉ **http** tới `127/8`/`localhost` được phép vì danh sách nội bộ có `127/8`.
  - Dải riêng RFC 1918 qua https được phép (SIEM nội bộ là đích bình thường).
  - Host viết dạng số (`2130706433`, `0x7f.1`, `127.1`) bị từ chối.
  - Client của caller (test) không đi qua bộ chặn lúc kết nối; chỉ kiểm lúc cấu hình.
- Địa chỉ API của Telegram và Zalo OA không cấu hình được (một địa chỉ tuỳ ý sẽ gửi token bot đi bất kỳ đâu); test trỏ vào máy giả bằng cách sửa trường không xuất khẩu trong gói, Slack bằng `http.Client.Transport`.

### `notify` (quy tắc và token)
- `MeetsMin(sev, floor)` (INV-4), `Quiet{Validate, Active, EndsAt}` và `Decide(now, minSev, quiet, sev) (Verdict, releaseAt)` (INV-4/5, D-57(8)): `Skip` dưới ngưỡng, `Hold` trong giờ im lặng (trừ critical khi `allow_critical`), `Send`. Đổi = đổi ai nhận tin lúc nào; test INV4, INV5.
- `Notice.Sendable` (tin lỗ hổng cần ≥ 1 thiết bị có tên; tên rỗng không tính), `SplitSendable` (INV-2, FORBID-1), `Group(ns, Grouping, floor)`, `GroupHeld(ns, floor)`, `Batch.Message() (channel.Message, error)`, `Batch.DueAt` (INV-3). `floor` là `min_severity` của **kênh đang gửi**: gộp theo từng kênh; `Group` bỏ tin không sendable và tin dưới `floor` trước khi gộp, `Batch.Message` từ chối (`ErrUnsendable`) lô rỗng, lô có tin không sendable/dưới ngưỡng, hoặc lô không do `Group` dựng. Khoá gộp = sản phẩm (không phân biệt hoa thường), cửa sổ tính từ tin đầu của lô.
- **D-62: critical không bao giờ bị gộp.** Tin `critical` luôn là một lô riêng, `DueAt` = chính thời điểm của nó, nên INV-6 (≤ 60 phút) đúng cho critical dù cửa sổ gộp là 240 phút. Trong giờ im lặng critical đi ngay khi `allow_critical` (D-57(8)). `high` trở xuống theo cửa sổ gộp đã cấu hình (15/60/240) và `DueAt` = tin đầu + cửa sổ: người gọi (WP-22) phải gửi lô khi tới `DueAt`.
- `Deliver(ctx, id, sender, msg, now) SendRecord`: luôn trả bản ghi (INV-6), kể cả khi sender panic (ghi `ok=false`, `error="internal error"`).
- `MintApprovalToken(key, Binding{RequestID, UserID, Channel, ExpiresAt}, risk, now)`, `ParseApprovalToken`, `VerifyApprovalToken` (GET: không đổi gì), `ConsumeApprovalToken(ctx, NonceStore, …)` (POST: đốt một lần), `ApprovalExpiry`, `ApprovalViaChannelAllowed(channel, risk)`. Định dạng đúng `docs/specs/approval-tokens.md` §4.1; `Binding` đọc từ bản ghi `response_tokens` theo `token_id`; khoá chọn theo `key_id` của bản ghi (thư viện không giữ keyring). Rủi ro cao hoặc không rõ bị từ chối ngay lúc ký trên mọi kênh có link (`email`, `zalo`; D-57(20)): link là thông tin xác thực mang theo người; core phải kiểm lại khi nhận quyết định. `TokenID.String()` không bao giờ được ghi log.
