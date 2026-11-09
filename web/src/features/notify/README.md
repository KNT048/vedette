# features/notify

Story: S-ALERT-3 (D-52): trang Incidents `/incidents` (chạm bẫy, kết nối địa chỉ xấu, log bất thường, thiết bị lạ; gộp lặp, xác nhận/đóng, nút Respond → `/response?incident=<id>`, huy hiệu gửi tin). S-ALERT-1: tin về lỗ hổng hiện trên trang finding qua slot `finding.panels`; lịch sử gửi đầy đủ + gửi lại ở Cài đặt → Kênh cảnh báo → History. `/alerts` chuyển hướng. S-NOT-1 (Cài đặt, mục `channels`: Telegram, Slack (Incoming Webhook; Socket Mode khi duyệt hành động trong chat, D-38), Zalo OA, email SMTP, webhook; gửi thử; mức tối thiểu theo kênh; lịch im lặng qua nửa đêm; gộp tin).
Không hỗ trợ nhiều site/MSP (quyết định của chủ dự án): không có tin gộp nhiều khách.
Slot đăng ký: `finding.panels`. Bí mật chỉ lưu phía mock và không bao giờ trả ra (chỉ 4 ký tự cuối). Số lỗ hổng KEV không khớp thiết bị hiện ở History.
Bảng mock: `notify_channels`, `notify_rules`, `notify_incidents`, `notify_alerts` (tin lỗ hổng), `notify_approval_sends`. Cài sạch: không kênh, không sự cố. Luồng dữ liệu rời hộp: PRIVACY.md luồng 5.
Kênh Zalo cần OA ID, ID người nhận (user_id) và access token (token Zalo chỉ sống khoảng 25 giờ).
S-NOT-2 / S-RESP-2: kênh Slack, Zalo cá nhân (không chính thức), và công tắc "Approve actions from this channel" trong từng kênh (Slack, Telegram, email, Zalo cá nhân) kèm danh sách người duyệt (D-46). Module khác đọc bằng `peek('notify_channels')`: mỗi kênh có `approvals?: boolean` và `approvers?: {user_id, address}[]` (cài sạch: không có).
