# Host (`vedette-host`) — Change Impact Map

> Khung WP-07a và lệnh OS/sao lưu/xuất log của WP-07b phần 1 đã có mã Go (gói bên dưới); `net.*`, `decoy_ip.*`, `container.*` thêm ở phần 3 (thiết kế chốt ở lát 3-0, D-99…D-107, `host-api.md` §18; có mã: khung chờ xác nhận lát 3-1, phần đọc mạng và ARP lát 3-3, `net.apply`/`net.confirm`/`net.revert` và NTP lát 3-4). Last verified: 2026-11-10 (lát 3-4). Thay đổi ở đây có thể làm hộp **mất liên lạc quản trị**: mọi đổi ở allowlist/tham số cần test hợp đồng và đọc lại CONTRACT.

## Gói và chữ ký chính
- `host/api`: kiểu dây dùng chung (`Run`, `Event`, `Info`, `AuditRecord`, `ErrorBody`, hằng mã lỗi, `Proto`/`MinProto`, tên tiêu đề). Đổi trường = đổi hợp đồng với `core`.
- `host/config`: `Parse(io.Reader) (Config, error)`, `Load(path, ownerUID) (Config, error)`, `ValidSocketPath(string) error`.
- `host/peer`: `type Checker func(net.Conn) (Info, error)`, `New(coreUID, unit, anchor) (Checker, error)` (Linux, dùng `SO_PEERPIDFD`; nơi khác `ErrUnsupportedOS`), `Decide(Cred, coreUID, unit, anchor, readCgroup)`, `InUnit(cgroupText, anchor) bool`, `ValidAnchor`, `PidFromFdinfo`, `StartTicks` (thuần, fuzz).
- `host/server`: `New(Options) (*Server, error)` (thêm `OwnerUID`, `AbandonCeiling`, `CheckTimeout`, `Exit`), `(*Server).Listen(ctx)`, `Serve(net.Listener)`, `Shutdown(ctx)`, `AuditError()`; bảng lệnh `Define[A](Spec[A]) Command`, `NewRegistry(...Command)`, `Invalid`, `Refuse`, `Failure`, `RunContext.Log/Progress`; `NewCommandRunner(log, ...exec.Binary)` (môi trường sạch SYS-1 trên `core/exec`); `ParseOSRelease`. `host/server/servertest` chỉ cho test.
- `host/ops` (WP-07b phần 1): `New(Config) (*Ops, error)`, `(*Ops).Commands()`, `Readers()`, `Start(ctx, Notifier)`, `Close()`; hàm thuần `ParseSimulation`, `ParseUpdateHosts`, `ParseAptConfig`, `RedactJournalLine`, `ReadArchive`, `ParseManifest`, bộ kiểm argv `ValidateApt|Systemctl|Journal`. `NewWithDeps(Config, Deps)` là cửa của test (đường dẫn gốc, đường dẫn binary giả, đồng hồ, hẹn giờ). Phụ thuộc: `core/exec`, `host/server`; **không** có SQL/SQLite trong `host/` (D-87, INV-13). `host/ops/opstest` chỉ cho test. `Ops.WriteGate()` là cổng reboot, nối vào `server.Options.WriteGate`.
- `host/ops` thêm ở lát 3-3 (D-99, D-101, D-107): `Readers.Net` (`GET /v1/state/net`), `(*Ops).CheckBackend() *server.Refusal`, hàm dựng `renderNetplan`/`parseNetplan` và các kiểu `NetplanConfig`/`NetplanMgmt` (gọi bởi `net.apply` từ lát 3-4), `Prober` + `ProbeResult` + `ErrGatewaySilent` + `ErrARPUnsupported` (`Deps.Probe`), `HostIface` (`Deps.Interfaces`), `ValidateNetplan`, `ParseARP`; `host/api`: `NetState` và kiểu con (`net.go`); `host/client`: `StateNet`.
- `host/ops` thêm ở lát 3-4 (D-100, D-106): lệnh `net.apply` (`Spec.Awaits`), `net.confirm`, `net.revert` (`Spec.WhileAwaiting`), `(*Ops).Resume` (nối `server.Options.Resume`), `Notifier.Claim` (thêm vào `ops.Notifier`; `*server.Server` đã có), `Deps.NetPoll`/`Deps.NetWait`, `ValidateChronyc`, nguồn NTP `vedette.sources`; `host/api`: `NetApplyArgs`, `NetRunArgs`, `NetApplyResult`, các mã mạng (`CodeAddressConflict`, `CodeConnectivityCheckFail`, …); `host/client`: `NetApply`, `NetConfirm`, `NetRevert`.
- `host/server` thêm ở lát 3-1 (D-100): `Awaiting{RevertAt, Result}`, `(*Server).Claim` + `Claimed.Finish`, `(*Server).Settle`, `RunContext.OnParked`, `Spec.Awaits`, `AwaitingConfirm`, `ErrNotAwaiting`, `ErrShuttingDown`, `Spec.WhileAwaiting`, `Spec.MaxBody`, `Options.Resume`, `Readers.Net`, `Readers.Containers`; `host/api`: `CodePendingConfirm`, `CodeNotAwaitingConfirm`; `host/ops`: `Notifier.AwaitingConfirm()` (server thoả sẵn), `Deps.NetPending` nil = hỏi server. Đổi ngữ nghĩa khoá/`Settle`/`Resume` làm vỡ `net.apply|confirm|revert` (lát 3-4) và `os.reboot`.
- `host/server` thêm: `Options.Readers`, `Readers`, `File`, `ReadError`, `Server.Note`, `Server.WriteActive`, `RunContext.AfterFinish`, `Failure.Result`, `Reverted`, `RefuseRetry`, `Refuse` nhận 404; **bỏ** `DefaultRegistry()` (registry dựng ở `cmd/vedette-host` từ `ops.Commands()`).
- `host/config`: thêm khoá tuỳ chọn `core_data`, `ValidDataDir`; khoá bắt buộc `core_gid` (D-87: chủ tệp khôi phục là `core_uid:core_gid`).
- `host/api`: `ops.go` (args, kết quả, mã lỗi của lệnh hệ thống); `host/client`: `OSCheck`, `OSInstall` (nhận `snapshot`), `OSAutoSecuritySet`, `OSReboot`, `OSRebootCancel`, `BackupCreate`, `BackupRestore` (nhận `snapshot`), `LogsExport`, `StateOS`, `StateBackups`, `DownloadBackup`, `DownloadExport`, `ResultOf[T]`.
- `host/client`: `New(socket)`, `Info`, `Run(ctx, command, args, requestID, actor)`, `GetRun`, `ListRuns`, `Audit`, `Events(ctx, runID, after)` (`Stream.Next` nối lại bằng `Last-Event-ID`), `ErrUnreachable`, `ErrDenied`, `ErrStreamLost`, `ErrEventTooLarge`, `*Error`, `IsCode`.
- `core/exec`: thêm `Binary.Env` (KEY=value bổ sung sau `PATH`/`LANG`; chỉ khoá `DEBIAN_FRONTEND` được phép; không thừa hưởng môi trường cha).
- `host/config`: thêm khoá tuỳ chọn `core_cgroup`; `golang.org/x/sys` thành phụ thuộc trực tiếp (Linux).
- `cmd/vedette-host`: cờ `-config -socket -state-dir -audit-log -version`.

## Modifying: `Client.Run(ctx, command, args, requestID, actor) (api.Run, error)` (phía `core`) — 5 nhóm người gọi
- **core/updates** (`/core/updates/os*`): đổi tên lệnh hoặc `OsRunResult` → màn hình Updates, trạng thái `busy`, tiến trình trực tiếp (`lines`) vỡ.
- **core/network** (Box network, D-56, S-CORE-8; handler `core.NetworkHandlers`, `modules/core/CONTRACT.md` INV-25): card quản trị/SPAN/IP phụ/NTP.
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

## Modifying: kiểm chữ ký (`internal/release`), khoá nhúng, registry (D-103, D-104)
- **Mọi container** (`core`, `sensor`, `honeypot`, `scan`, `greenbone`): đổi → không khởi động được, hoặc (nguy hiểm hơn) chạy image chưa ký. `internal/release` dùng chung với **core/updates** (kiểm index/manifest để hiển thị): đổi định dạng index/manifest (`images[].cosign`, `update-manifest.md` §4.2) phải đổi cả CI phát hành (cosign `--new-bundle-format=false --use-signing-config=false`) và vector test cùng lúc. Thêm/thay khoá nhúng = bản binary mới; khoá dự phòng ngoại tuyến phải còn trong binary để xoay khoá. Hằng registry `ghcr.io/knt048/vedette-<service>` đổi → mọi manifest cũ thành `registry_not_allowed`.
- Thứ tự phiên bản (SemVer qua `golang.org/x/mod/semver`), `min_upgrade_from`, `rollback.min_version`: đổi cách so → hạ bản lọt qua hoặc cập nhật bị chặn.

## Modifying: `net.apply`/`net.confirm`/`net.revert`, lớp phủ `/run`, `net/pending.json` (D-99, D-100)
- **core/network** (Box network, S-CORE-8): GUI giả định đổi phần quản trị → `awaiting_confirm` có `revert_at`, chỉ DNS/NTP/SPAN thì xong ngay; `core` lấy `run_id` từ `state/net.pending` (không nhớ trong bộ nhớ) nên khởi động lại giữa cửa sổ không mất gì; địa chỉ cũ ở `core_setting` `core_network_pending`. Đổi trạng thái/mã (`pending_confirm`, `not_awaiting_confirm`, `not_confirmed`, `reverted_by_reboot`, `address_conflict`, `gateway_outside_subnet`, `net_backend_unsupported`) → làm vỡ bảng ánh xạ mã của `core` và lời GUI.
- **os.reboot** (`net_pending_confirm` qua `Deps.NetPending`) và **khoá ghi chung**: run chờ giữ khoá; bỏ điều đó cho phép lệnh ghi khác chen vào cửa sổ.
- **Installer (WP-08)**: host phải là chủ duy nhất của netplan (cloud-init tắt mạng, tệp khác dời đi); thiếu → mọi `net.apply` bị `net_backend_unsupported`. Ghi `/etc` ngoài `net.confirm` phá INV-16 (reboot giữ cấu hình chưa xác nhận). Với NTP, installer cài chrony, sở hữu `chrony.conf` có `sourcedir /etc/chrony/sources.d` và **không** pool của distro (D-106); thiếu chrony hay thiếu `sourcedir` thì `net.apply` thất bại `ntp_not_applied` (kiểm hiệu ứng thấy không có nguồn) và PRIVACY luồng 10 không còn đúng.
- **`ops.Notifier` và `server.Options.Resume`**: `Notifier.Claim` là đường duy nhất để confirm, revert, hẹn giờ và `Start` kết thúc run chờ (so-và-đổi trước mọi hiệu ứng); bỏ hay đổi nó thì hai bên cùng làm hiệu ứng (ghi `/etc` rồi hoàn tác). `Resume` phải được nối trong `cmd/vedette-host` (test `TestServesAndStopsOnSignal` kiểm bảng lệnh; test `…AHostCrashBefore…` kiểm hành vi): quên nối thì run chờ thành `failed host_restarted` và overlay `/run` bị `Start` hoàn tác như note mồ côi.
- **Sau review lát 3-4**: `Spec.Awaits` phụ thuộc cận 660 s đo trên đồng hồ đơn điệu (`liveRun.started`); lệnh `net.apply` phụ thuộc `RunContext.AfterFinish` chạy cả khi park bị từ chối hay lệnh lỗi (bỏ → overlay không ai canh, H-1); hoàn tác hỏng gọi đường reboot có lịch (`setSchedule`) và ghi `pending.reboot_at` (core cần hiện); `Check` đọc `/sys/class/net/<card>/device` cho `span_not_physical`.
- **`net/pending.json`** (ghi qua `os.Root`, 0600; có `started_at`, `reboot_at`) là ghi chú duy nhất sống qua host sập; đổi dạng trường làm host cũ coi note mới là không tin được và **hoàn tác** (an toàn, nhưng làm mất cửa sổ đang chạy).
- **`vedette-host.service`**: không dùng `ProtectSystem=strict` (`DEPLOYMENT.md` §12) vì host ghi `/etc/netplan`, `/run/netplan`, `/etc/chrony/sources.d` và chạy `netplan apply` (kéo theo `systemd-networkd`, `udevadm`); thêm sandbox chặn ghi các thư mục này hoặc chặn việc đó làm `netplan apply` hỏng và mọi `net.apply` bị hoàn tác.

## Modifying: `decoy_ip.*`, namespace `vedette-hp`, MAC (D-101, D-102)
- **honeypot** (unit Quadlet `Network=ns:/run/netns/vedette-hp`, bộ chuyển `cmd/vedette/honeypot.go`): đổi tên/đường dẫn namespace → container không lên; đổi cách sinh MAC (`hp/mac.key`, HMAC) → MAC của mọi decoy đổi sau khi cập nhật (thiết bị LAN thấy "máy mới"). `vedette-host.service` phải tạo namespace trước khi báo `READY=1` (`Type=notify`). Ruleset nft chặn đi ra là INV-1 của honeypot ở tầng mạng: bỏ nó thì container bị chiếm mở được kết nối ra LAN.
- **core/network**: `decoys [{ip, mac}]` trong `GET /v1/state/net` là nguồn để bộ chuyển honeypot so khác biệt; đổi dạng → bộ chuyển gửi lại mọi IP và chạm `rate_limited`.

## Modifying: mẫu unit Quadlet, `container.start|stop|rollback` (D-104, D-105)
- **core**: `User=<core_uid>:<core_gid>` (không `UserNS=auto`) là điều kiện của kiểm peer (`SO_PEERCRED`) và kiểm chủ sở hữu D-87; `PublishPort=8443:8443` không kèm IP để GUI còn tới được sau `net.apply`. Đổi một trong hai → mất GUI hoặc mọi lệnh bị `peer_not_allowed`.
- **sensor/scan/honeypot/greenbone**: capability và mạng nằm trong mẫu; test hợp đồng trên unit đã dựng chặn `--privileged`, `Network=host` ngoài `sensor`/`scan`. `snapshot` bắt buộc cho `container.start(core)`: `core` phải chụp bản trước khi gọi (như `os.install`).
- **core/updates**: `container.rollback` của `core` khi `rollback.safe=false` khôi phục DB trong cùng run: GUI phải xin xác nhận mất dữ liệu trước khi gọi.

## Modifying: `GET /v1/state/net` (D-101)
- **core** (`span_status`): host chỉ có bộ đếm giao diện; `other_macs`, `last_packet_at` lấy từ `sensor-passive` `SpanStats()`. Thêm đếm MAC vào host là đưa phân tích lưu lượng vào root (INV-18).

## Absence of this component
- Kiểu "Chỉ container": Settings → Updates (OS) và Box network hiện "không hỗ trợ ở kiểu cài này"; honeypot không dựng được IP phụ (macvlan), SPAN không cấu hình được; cập nhật phần mềm Vedette làm tay. `client.ErrUnreachable` là tín hiệu.
- Appliance mất liên lạc với `host`: các module khác vẫn chạy; không cài bản vá, không đổi mạng, không đổi/hoàn tác image cho tới khi khôi phục.

## Modifying: `GET /v1/state/net` (`host/api/net.go`, `host/ops/netstate.go`)
- **core** (`cmd/vedette` `hostNetSource`): đọc `interfaces[].addresses` và `decoys[].ip` để biết địa chỉ của chính hộp cho `core/conn` (`boxSources.BoxAddrs`, INV-23), `sensor-active` (`ProtectedIPs`) và địa chỉ hộp của `honeypot`. Đổi tên trường, đổi dạng địa chỉ (CIDR văn bản), hay bỏ giao diện khỏi danh sách (nay: mọi giao diện không phải loopback có địa chỉ, cộng card vật lý; tối đa 64 × 64) làm các nơi này **không còn thấy địa chỉ LAN của hộp**: kết nối có thể trỏ vào chính hộp, quét có thể quét hộp. Test: `TestHostNetSourceGivesSingleAddressPrefixes`, `TestBoxSourcesUseTheHostsAddresses`, `TestSensorProtectedIPsIncludeTheHostsAddresses`, `TestHostNetCache*`. Ba nơi dùng chung một `hostNetCache` (30 s, nhớ lỗi 10 s, một lời gọi cho mọi người gọi, không giữ khoá khi gọi socket) và `core` nhận tối đa 2048 địa chỉ.
- **core/network** (handler của `core`, INV-25): `interfaces[].role`, `config.mgmt`, `config.ntp`, `default_route`, `pending` (`{run_id, revert_at}`, chỉ khi run đang chờ và note đọc được) là nguồn màn hình mạng. Thêm trường `other_macs`/`last_packet_at` vào đây là phá D-101 (root không đọc lưu lượng): test `TestContract_Net_StateNetReportsCardsCountersAndRoute` bắt.
- Đường dẫn đọc: tệp `/run/netplan/90-vedette.yaml` nếu có (hỏng thì `config.mgmt` null, không lùi về `/etc`), mở bằng `O_NONBLOCK|O_NOFOLLOW`; `/sys` qua `os.OpenRoot(<root>/sys)` (không phải `/sys/class/net`: các link của kernel đi vào `/sys/devices`), `/proc/net/route`, tệp netplan của host. Đọc thêm tệp nào khác trong `/sys` hay tệp netplan lạ vi phạm "không phân tích cái ta không viết" (D-99).

## Modifying: bộ dựng netplan (`host/ops/netplan.go`)
- **Lát 3-4** (`net.apply`): dùng `renderNetplan`/`parseNetplan`/`CheckBackend`; mọi giá trị đã được kiểm ở đây, `net.apply` chỉ đổi `*fieldError` thành `args` details. Đổi quy tắc kiểm (độ dài tiền tố, DNS) đổi cái `net.apply` chấp nhận. Đổi định dạng đầu ra làm `parseNetplan` không đọc được tệp đã ghi trước đó (nó chỉ nhận đúng byte mà bản hiện tại dựng): sau khi nâng cấp host, `state/net` báo `config.mgmt = null` cho tệp cũ cho tới khi `net.apply` ghi lại. Golden: `host/ops/testdata/netplan_*.yaml`; chạy `go test ./host/ops -run TestNetplanGolden -update` rồi đọc diff.
- **Installer (WP-08)**: phải giao netplan độc quyền cho host (D-99); tệp lạ → `net_backend_unsupported`. `CheckBackend` không nhìn `/etc/systemd/network`, ifupdown hay NetworkManager: installer phải dọn.
- **Lát 3-4**: runner sản xuất có `netplan` chỉ với `apply` (`generate --root-dir` không có: văn phạm chỉ kiểm chuỗi, không ai gọi nó). Thêm lại `generate` cần thư mục do host tự tạo (root, mở không theo liên kết) và test thay cho `TestProductionRunnerOnlyAppliesNetplan`.

## Modifying: ARP (`arpframe.go`, `arpprobe.go`, `arp_linux.go`)
- **Lát 3-4** (`net.apply`: probe trước khi áp, kiểm gateway sau khi áp và sau mỗi hoàn tác) và **lát 3-5** (decoy `ip_in_use`) gọi `Deps.Probe`. Thời gian (3 probe cách 1 s + 2 s; gateway 1 s × 15 s) là D-101 và khớp `host-api.md` §6.5; đổi chúng đổi thời gian chờ của `net.apply` (60 s).
- **`vedette-host.service`** cần `AF_PACKET` trong `RestrictAddressFamilies` (`DEPLOYMENT.md` §12) và `CAP_NET_RAW`; thiếu thì `net.apply` đổi địa chỉ tĩnh không probe được (lỗi, không phải "không xung đột").
- Nới bộ đọc (nhận khung khác ARP, đọc quá 42 byte đầu của khung, bỏ kiểm `Ifindex` hay giao thức 0 lúc tạo socket) = mở bề mặt root đọc dữ liệu không tin cậy (INV-18): `FuzzParseARP`, `TestParseARPRefusesEveryOtherShape`, `TestContract_INV18_*`.
