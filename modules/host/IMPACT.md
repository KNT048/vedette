# Host (`vedette-host`) — Change Impact Map

> Chưa có mã Go; chữ ký là kế hoạch (package `host/client` cho người gọi, `cmd/vedette-host` cho tiến trình), chốt ở M2. Thay đổi ở đây có thể làm hộp **mất liên lạc quản trị**: mọi đổi ở allowlist/tham số cần test hợp đồng và đọc lại CONTRACT.

## Modifying: `Client.Run(ctx, Command, Args) (Result, error)` (phía `core`) — 5 nhóm người gọi
- **core/updates** (`/core/updates/os*`): đổi tên lệnh hoặc `OsRunResult` → màn hình Updates, trạng thái `busy`, tiến trình trực tiếp (`lines`) vỡ.
- **core/network** (Box network, D-56; endpoint chưa có): card quản trị/SPAN/IP phụ/NTP.
- **core/containers** (cập nhật phần mềm Vedette: `image.pull`, `container.rollback`, A/B): đổi → bản cập nhật có thể không hoàn tác được.
- **core/backup** (`backup.create`) và **core/data** (xuất/xoá).
- **inventory** (`pkg.list` cho "This box").

## Modifying: allowlist (thêm/bớt lệnh) hoặc kiểu tham số
- Mở rộng bề mặt root. Mỗi lệnh mới: CONTRACT, test từ chối tham số xấu (`; | & $ ...` và IP/tên sai), `THIRD_PARTY_NOTICES.md` nếu thêm công cụ.

## Modifying: kiểm cosign / danh sách registry
- **Mọi container** (`core`, `sensor`, `honeypot`, `scan`, `greenbone`): đổi → không khởi động được, hoặc (nguy hiểm hơn) chạy image chưa ký.

## Modifying: cách kiểm danh tính người gọi (socket)
- **core**: nếu lỏng ra, container khác có thể ra lệnh root. Test: tiến trình khác `core` bị từ chối.

## Absence of this component
- Kiểu "Chỉ container": Settings → Updates (OS) và Box network hiện "không hỗ trợ ở kiểu cài này"; honeypot không dựng được IP phụ (macvlan), SPAN không cấu hình được; cập nhật phần mềm Vedette làm tay.
- Appliance mất liên lạc với `host`: các module khác vẫn chạy; không cài bản vá, không đổi mạng, không đổi/hoàn tác image cho tới khi khôi phục.
