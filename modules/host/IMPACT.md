# Host (`vedette-host`) — Change Impact Map

> Khung WP-07a đã có mã Go (gói bên dưới); lệnh hệ thống (`docs/specs/host-api.md` §6) thêm ở WP-07b. Thay đổi ở đây có thể làm hộp **mất liên lạc quản trị**: mọi đổi ở allowlist/tham số cần test hợp đồng và đọc lại CONTRACT.

## Gói và chữ ký chính
- `host/api`: kiểu dây dùng chung (`Run`, `Event`, `Info`, `AuditRecord`, `ErrorBody`, hằng mã lỗi, `Proto`/`MinProto`, tên tiêu đề). Đổi trường = đổi hợp đồng với `core`.
- `host/config`: `Parse(io.Reader) (Config, error)`, `Load(path, ownerUID) (Config, error)`, `ValidSocketPath(string) error`.
- `host/peer`: `type Checker func(net.Conn) (Info, error)`, `New(coreUID, unit) (Checker, error)` (Linux; nơi khác `ErrUnsupportedOS`), `Decide(Cred, coreUID, unit, readCgroup)`, `InUnit(cgroupText, unit) bool` (thuần, fuzz).
- `host/server`: `New(Options) (*Server, error)`, `(*Server).Listen(ctx)`, `Serve(net.Listener)`, `Shutdown(ctx)`, `AuditError()`; bảng lệnh `Define[A](Spec[A]) Command`, `NewRegistry(...Command)`, `DefaultRegistry()` (nơi duy nhất 07b thêm lệnh), `Invalid`, `Refuse`, `Failure`, `RunContext.Log/Progress`; `NewCommandRunner(log, ...exec.Binary)` (môi trường sạch SYS-1 trên `core/exec`); `ParseOSRelease`. `host/server/servertest` chỉ cho test.
- `host/client`: `New(socket)`, `Info`, `Run(ctx, command, args, requestID, actor)`, `GetRun`, `ListRuns`, `Audit`, `Events(ctx, runID, after)` (`Stream.Next` nối lại bằng `Last-Event-ID`), `ErrUnreachable`, `ErrStreamLost`, `*Error`, `IsCode`.
- `core/exec`: thêm `Binary.Env` (KEY=value bổ sung sau `PATH`/`LANG`; không thừa hưởng môi trường cha, không ghi đè `PATH`/`LANG`).
- `cmd/vedette-host`: cờ `-config -socket -state-dir -audit-log -version`.

## Modifying: `Client.Run(ctx, command, args, requestID, actor) (api.Run, error)` (phía `core`) — 5 nhóm người gọi
- **core/updates** (`/core/updates/os*`): đổi tên lệnh hoặc `OsRunResult` → màn hình Updates, trạng thái `busy`, tiến trình trực tiếp (`lines`) vỡ.
- **core/network** (Box network, D-56; endpoint chưa có): card quản trị/SPAN/IP phụ/NTP.
- **core/containers** (cập nhật phần mềm Vedette: `container.pull`, `container.rollback`, A/B): đổi → bản cập nhật có thể không hoàn tác được.
- **core/backup** (`backup.create`) và **core/data** (xuất/xoá).
- **inventory** (danh sách gói cho "This box").
- Người gọi phải dùng `X-Request-Id` ổn định cho mỗi ý định (thử lại cùng id, không id mới) và nhớ nhịp 60 request/phút (dùng SSE, không hỏi từng giây).

## Modifying: bảng lệnh (`DefaultRegistry`, thêm/bớt lệnh) hoặc kiểu tham số
- Mở rộng bề mặt root. Mỗi lệnh mới: CONTRACT, `host-api.md` §6, danh sách `documentedCommands` trong test hợp đồng, test từ chối tham số xấu (`; | & $ ...` và IP/tên sai), `THIRD_PARTY_NOTICES.md` nếu thêm công cụ.

## Modifying: cách kiểm danh tính người gọi (`host/peer`, quyền socket)
- **core**: nếu lỏng ra, container khác có thể ra lệnh root. Test: tiến trình khác `core` bị từ chối (từng lớp), `TestContract_INV4_*`, `host/peer` fuzz.

## Modifying: định dạng kiểm toán hoặc chuỗi hash
- Phải khớp `core/chain` (D-57 (14)) và test vector; `GET /v1/audit` là nguồn cho "tải mọi log của hộp" (D-48): đổi trường làm vỡ người đọc. Tệp hỏng → host chặn lệnh ghi (`audit_unavailable`).

## Modifying: kiểm cosign / danh sách registry
- **Mọi container** (`core`, `sensor`, `honeypot`, `scan`, `greenbone`): đổi → không khởi động được, hoặc (nguy hiểm hơn) chạy image chưa ký. (Thuộc 07b.)

## Absence of this component
- Kiểu "Chỉ container": Settings → Updates (OS) và Box network hiện "không hỗ trợ ở kiểu cài này"; honeypot không dựng được IP phụ (macvlan), SPAN không cấu hình được; cập nhật phần mềm Vedette làm tay. `client.ErrUnreachable` là tín hiệu.
- Appliance mất liên lạc với `host`: các module khác vẫn chạy; không cài bản vá, không đổi mạng, không đổi/hoàn tác image cho tới khi khôi phục.
