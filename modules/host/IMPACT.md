# Host (`vedette-host`) — Change Impact Map

> Khung WP-07a và lệnh OS/sao lưu/xuất log của WP-07b phần 1 đã có mã Go (gói bên dưới); `net.*`, `decoy_ip.*`, `container.*` thêm ở các phần sau. Last verified: 2026-11-09 (sau rà soát bảo mật WP-07b phần 1, D-87). Thay đổi ở đây có thể làm hộp **mất liên lạc quản trị**: mọi đổi ở allowlist/tham số cần test hợp đồng và đọc lại CONTRACT.

## Gói và chữ ký chính
- `host/api`: kiểu dây dùng chung (`Run`, `Event`, `Info`, `AuditRecord`, `ErrorBody`, hằng mã lỗi, `Proto`/`MinProto`, tên tiêu đề). Đổi trường = đổi hợp đồng với `core`.
- `host/config`: `Parse(io.Reader) (Config, error)`, `Load(path, ownerUID) (Config, error)`, `ValidSocketPath(string) error`.
- `host/peer`: `type Checker func(net.Conn) (Info, error)`, `New(coreUID, unit, anchor) (Checker, error)` (Linux, dùng `SO_PEERPIDFD`; nơi khác `ErrUnsupportedOS`), `Decide(Cred, coreUID, unit, anchor, readCgroup)`, `InUnit(cgroupText, anchor) bool`, `ValidAnchor`, `PidFromFdinfo`, `StartTicks` (thuần, fuzz).
- `host/server`: `New(Options) (*Server, error)` (thêm `OwnerUID`, `AbandonCeiling`, `CheckTimeout`, `Exit`), `(*Server).Listen(ctx)`, `Serve(net.Listener)`, `Shutdown(ctx)`, `AuditError()`; bảng lệnh `Define[A](Spec[A]) Command`, `NewRegistry(...Command)`, `Invalid`, `Refuse`, `Failure`, `RunContext.Log/Progress`; `NewCommandRunner(log, ...exec.Binary)` (môi trường sạch SYS-1 trên `core/exec`); `ParseOSRelease`. `host/server/servertest` chỉ cho test.
- `host/ops` (WP-07b phần 1): `New(Config) (*Ops, error)`, `(*Ops).Commands()`, `Readers()`, `Start(ctx, Notifier)`, `Close()`; hàm thuần `ParseSimulation`, `ParseUpdateHosts`, `ParseAptConfig`, `RedactJournalLine`, `ReadArchive`, `ParseManifest`, bộ kiểm argv `ValidateApt|Systemctl|Journal`. `NewWithDeps(Config, Deps)` là cửa của test (đường dẫn gốc, đường dẫn binary giả, đồng hồ, hẹn giờ). Phụ thuộc: `core/exec`, `host/server`; **không** có SQL/SQLite trong `host/` (D-87, INV-13). `host/ops/opstest` chỉ cho test. `Ops.WriteGate()` là cổng reboot, nối vào `server.Options.WriteGate`.
- `host/server` thêm: `Options.Readers`, `Readers`, `File`, `ReadError`, `Server.Note`, `Server.WriteActive`, `RunContext.AfterFinish`, `Failure.Result`, `Reverted`, `RefuseRetry`, `Refuse` nhận 404; **bỏ** `DefaultRegistry()` (registry dựng ở `cmd/vedette-host` từ `ops.Commands()`).
- `host/config`: thêm khoá tuỳ chọn `core_data`, `ValidDataDir`; khoá bắt buộc `core_gid` (D-87: chủ tệp khôi phục là `core_uid:core_gid`).
- `host/api`: `ops.go` (args, kết quả, mã lỗi của lệnh hệ thống); `host/client`: `OSCheck`, `OSInstall` (nhận `snapshot`), `OSAutoSecuritySet`, `OSReboot`, `OSRebootCancel`, `BackupCreate`, `BackupRestore` (nhận `snapshot`), `LogsExport`, `StateOS`, `StateBackups`, `DownloadBackup`, `DownloadExport`, `ResultOf[T]`.
- `host/client`: `New(socket)`, `Info`, `Run(ctx, command, args, requestID, actor)`, `GetRun`, `ListRuns`, `Audit`, `Events(ctx, runID, after)` (`Stream.Next` nối lại bằng `Last-Event-ID`), `ErrUnreachable`, `ErrDenied`, `ErrStreamLost`, `ErrEventTooLarge`, `*Error`, `IsCode`.
- `core/exec`: thêm `Binary.Env` (KEY=value bổ sung sau `PATH`/`LANG`; chỉ khoá `DEBIAN_FRONTEND` được phép; không thừa hưởng môi trường cha).
- `host/config`: thêm khoá tuỳ chọn `core_cgroup`; `golang.org/x/sys` thành phụ thuộc trực tiếp (Linux).
- `cmd/vedette-host`: cờ `-config -socket -state-dir -audit-log -version`.

## Modifying: `Client.Run(ctx, command, args, requestID, actor) (api.Run, error)` (phía `core`) — 5 nhóm người gọi
- **core/updates** (`/core/updates/os*`): đổi tên lệnh hoặc `OsRunResult` → màn hình Updates, trạng thái `busy`, tiến trình trực tiếp (`lines`) vỡ.
- **core/network** (Box network, D-56; endpoint chưa có): card quản trị/SPAN/IP phụ/NTP.
- **core/containers** (cập nhật phần mềm Vedette: `container.pull`, `container.rollback`, A/B): đổi → bản cập nhật có thể không hoàn tác được.
- **core/backup** (`backup.create`) và **core/data** (xuất/xoá).
- **inventory** (danh sách gói cho "This box").
- Người gọi phải dùng `X-Request-Id` ổn định cho mỗi ý định (thử lại cùng id, không id mới) và nhớ nhịp 60 request/phút (dùng SSE, không hỏi từng giây).

## Modifying: bảng lệnh (`ops.Commands()`, thêm/bớt lệnh) hoặc kiểu tham số
- Mở rộng bề mặt root. Mỗi lệnh mới: CONTRACT, `host-api.md` §6, danh sách `documentedCommands` trong test hợp đồng, test từ chối tham số xấu (`; | & $ ...` và IP/tên sai), `THIRD_PARTY_NOTICES.md` nếu thêm công cụ.

## Modifying: cách kiểm danh tính người gọi (`host/peer`, quyền socket)
- **core**: nếu lỏng ra, container khác có thể ra lệnh root. Test: tiến trình khác `core` bị từ chối (từng lớp), `TestContract_INV4_*`, `host/peer` fuzz.

## Modifying: định dạng kiểm toán hoặc chuỗi hash
- Phải khớp `core/chain` (D-57 (14)) và test vector; `GET /v1/audit` là nguồn cho "tải mọi log của hộp" (D-48): đổi trường làm vỡ người đọc. Tệp hỏng → host chặn lệnh ghi (`audit_unavailable`).

## Modifying: `os.install`, `os.check`, bộ phân tích đầu ra apt
- **core/updates** (`OsState`, `OsRunResult`): đổi tên trường của `api.OSState`/`api.OSRunResult` làm màn hình Updates vỡ. `installed` và `security` đo bằng mô phỏng lại; đổi cách đo đổi nghĩa con số hiển thị. Đổi bộ phân tích (`ParseSimulation`) có thể làm `security` sai (gói vá bị coi là thường hoặc ngược lại): chạy lại bảng test và fuzz.
- Thêm một argv cho `apt-get` (ví dụ nâng cấp bản phát hành, `remove`) = mở bề mặt root; phải sửa bộ kiểm `validateApt`, `host-api.md` §16 và test `…FORBID_ReleaseUpgradesAndSourcesAreOutOfReach`.

## Modifying: hợp đồng bản chụp (`<core_data>/snapshots/<id>/`, `snapshot.json`, tham số `snapshot`)
- **core/backup, core/updates, core/data** (phía `core`, WP-07b phần 2): `core` phải tạo bản chụp ngay trước `backup.create`, `os.install`, `backup.restore` (tệp `vedette.db` tự đủ, `vedette.key` khi có, `snapshot.json` ghi cuối; tệp thường thuộc `core_uid`, một liên kết; tối đa 10 phút tuổi). Đổi tên tệp, thứ tự ghi, trần cỡ hay tuổi tối đa làm mọi lệnh sao lưu trả `snapshot_required|invalid`. Đổi chủ chạy `core` mà không đổi `core_uid`/`core_gid` trong `host.conf` làm bản chụp bị từ chối. Test: `TestContract_Backup_RefusalsAndHostileCore`, `host/ops` `TestParseSnapshotMeta`.

## Modifying: cổng reboot (`Ops.WriteGate`, `Options.WriteGate`, `reboot.json.pending`)
- **Mọi người gọi lệnh ghi** (core/updates, core/backup, core/network, core/containers): trong tối đa 10 phút sau khi host bắt đầu reboot, mọi lệnh ghi trả `409 rebooting`; họ phải coi đó là "chờ máy khởi động lại", không phải lỗi. Bỏ cổng = `core` bị chiếm có thể ngắt dpkg/khôi phục bằng cách xếp lệnh trước lúc tắt máy.

## Modifying: sao lưu và khôi phục (`backup.*`, định dạng tar.gz, `core_data`)
- **core/backup**, **core/data** (tải sao lưu, `GET /core/data/backup`), `os.install` (gọi `createBackup` nội bộ), `backup.restore` (dừng `core`): đổi tên thành viên, thứ tự hay manifest làm sao lưu cũ không khôi phục được; `manifest.version` là chỗ nâng cấp. Đổi `db_schema` đổi nghĩa `schema_newer`.
- Tên `vedette.db`/`vedette.key`/`snapshots` là hằng khớp mặc định của `cmd/vedette`; đổi ở `core` mà không đổi ở đây → `snapshot_required|invalid`. Installer (WP-08) phải ghi `core_data`, `core_uid`, `core_gid` và giữ thư mục cha của `core_data` thuộc root, không nhóm/người khác ghi được (nếu không mọi lệnh sao lưu trả `db_unreadable`).
- Lưu giữ (3 `pre_*`, 10 `manual`) xoá tệp: đổi con số đổi cái người dùng có thể quay về.

## Modifying: `os.reboot`, hẹn giờ, `reboot.json`
- **core/updates**: `reboot_scheduled_at` đọc từ `GET /v1/state/os`; sau khi đổi, hộp có thể reboot ngoài ý muốn (FORBID-3). Mọi lần reboot (cả theo lịch) tính vào trần 3/24 giờ.

## Modifying: `logs.export`, bộ lọc bí mật
- **core/data** ("tải mọi log của hộp", D-48): thêm mẫu bí mật vào `redactRules` mà không thêm test làm lọt; bớt mẫu làm lộ. Dòng JSON phải còn hợp lệ sau lọc (fuzz).

## Modifying: kiểm cosign / danh sách registry
- **Mọi container** (`core`, `sensor`, `honeypot`, `scan`, `greenbone`): đổi → không khởi động được, hoặc (nguy hiểm hơn) chạy image chưa ký. (Thuộc 07b.)

## Absence of this component
- Kiểu "Chỉ container": Settings → Updates (OS) và Box network hiện "không hỗ trợ ở kiểu cài này"; honeypot không dựng được IP phụ (macvlan), SPAN không cấu hình được; cập nhật phần mềm Vedette làm tay. `client.ErrUnreachable` là tín hiệu.
- Appliance mất liên lạc với `host`: các module khác vẫn chạy; không cài bản vá, không đổi mạng, không đổi/hoàn tác image cho tới khi khôi phục.
