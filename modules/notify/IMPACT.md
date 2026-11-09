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
