# Host (`vedette-host`) Contract

> Loại: **thành phần** (component), không phải module bật/tắt · Story: S-CORE-7, S-INV-5 (+ D-56) · Quyết định: D-53, D-55, D-56, D-12, D-85, D-87, D-99…D-107 · Last verified: 2026-11-09 (WP-07b phần 1 sau rà soát bảo mật, D-87: lệnh OS, sao lưu, xuất log và đọc trạng thái có test hợp đồng trên máy giả; host không mở DB của `core`; chưa chạy trên Linux thật); 2026-11-10 (WP-07b phần 3, lát 3-0: `net.*`, `decoy_ip.*`, `container.*` chốt trên giấy, D-99…D-107, `host-api.md` §18; chưa có mã)
> Thay thế `vedette-updater` của D-53 (D-55). `contract.ts`, `osMock.ts`, `locales/en/core.json` và `PRIVACY.md` luồng 6 đã đổi sang tên mới (WP-06).
> Là phần duy nhất của hộp chạy **root**. Mọi thứ khác (core, sensor, honeypot, scan) chạy không root trong container.

## Invariants (luôn đúng)
- **INV-1** **Danh sách lệnh cố định (allowlist)**: chỉ các lệnh ở mục "Lệnh" dưới đây; lệnh lạ → từ chối `unknown_command`, không có đường "chạy chuỗi bất kỳ". Thêm lệnh = sửa CONTRACT này + test + `THIRD_PARTY_NOTICES.md` nếu thêm công cụ ngoài.
- **INV-2** **Không shell** (SYS-1): mọi tiến trình con chạy bằng `argv` cố định với tham số đã kiểm theo kiểu (`netip` cho IP/CIDR, regex `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$` cho tên card/container, enum cho `scope`/`when`, `HH:MM` cho giờ). Tham số sai kiểu → từ chối trước khi chạm hệ thống.
- **INV-3** **Một thao tác thay đổi tại một thời điểm** (khoá toàn cục): lệnh thứ hai khi đang chạy → 409 `busy` (kể cả khi lệnh trước đã báo `timeout` nhưng tiến trình của nó chưa trả về: khoá giữ tới khi trả về, quá trần thì host thoát để systemd khởi động lại); reboot trong lúc cài đặt → 409.
- **INV-4** **Chỉ `core` gọi được**: giao tiếp qua socket Unix nội bộ, quyền socket và kiểm danh tính tiến trình gọi; không cổng mạng. Người dùng/UI không bao giờ gọi trực tiếp; `core` kiểm vai (admin/operator) và ghi `core_audit` (SYS-3) **trước** khi gọi `host`.
- **INV-5** **Cài bản vá OS (D-53)**: chỉ danh sách lệnh apt cố định (`security` hoặc `all`); **sao lưu DB trước**, **kiểm sức khoẻ sau** (`health[]`), tiến trình hiện trực tiếp (`lines`), kết quả `installed`, `security`, `backup`, `reboot_required`. **Không bao giờ tự nâng bản phát hành OS** (chỉ trả hướng dẫn `release_upgrade`).
- **INV-6** Khởi động lại: `now`, `window`, hoặc `custom` với `at` (HH:MM) **nằm trong cửa sổ bảo trì**; huỷ lịch được; từ chối khi đang cài (INV-3). Tự cập nhật bảo mật = `unattended-upgrades` bật/tắt; cửa sổ bảo trì `always | window{days 1..7, from, to}` (`to < from` = qua nửa đêm).
- **INV-7** **Image container (D-55, D-103, D-104)**: chỉ kéo và chạy image có digest nằm trong một release manifest ký minisign đúng (khoá nhúng, chưa thu hồi theo index đã lưu) và có **chữ ký cosign hợp lệ** (đi trong manifest, `images[].cosign`); tham chiếu kéo dựng từ hằng `ghcr.io/knt048/vedette-<service>@sha256:<digest>`, không bao giờ từ chuỗi của request; chữ ký sai/thiếu → từ chối, không khởi động; không hạ bản bằng `container.start`; hoàn tác = chạy lại `previous` đã xác minh. **Cohort và rollout là việc của `core`** (`update-manifest.md` §6): host không biết cohort, chỉ kiểm chữ ký, thu hồi và thứ tự phiên bản.
- **INV-8** **Cấu hình mạng (D-56, D-99, D-102, D-106)**: card quản trị (DHCP hoặc tĩnh: IP, gateway, DNS), card SPAN/TAP (không IP, chế độ nghe), IP phụ cho bẫy (macvlan trong namespace `vedette-hp`), NTP (chrony). Host chỉ ghi **một** tệp netplan của mình (`90-vedette.yaml`, renderer `networkd`); tệp netplan khác → từ chối `net_backend_unsupported`, không phân tích. IP/CIDR hợp lệ qua `netip`; IP phụ phải nằm trong dải mạng của hộp, khác IP hộp (validate lại ở `host` dù `core` đã kiểm). Host chỉ báo **bộ đếm giao diện** của card SPAN; số MAC khác hộp và lần nhận gói cuối do container `sensor` đo (INV-18); không lưu nội dung gói.
- **INV-9** `pkg.list` (dpkg) chỉ đọc, là nguồn danh sách gói của chính hộp ("This box", độ tin cậy 1.0, D-53, S-INV-5).
- **INV-10** Sao lưu DB: tệp không chứa mật khẩu/khoá (như `/core/data/backup`); khoá/secret không bao giờ ra khỏi `host`/`core` dạng đọc được (SYS-4).
- **INV-13** **Root không bao giờ phân tích dữ liệu của `core` (D-87)**: `core` tự chụp DB vào `<core_data>/snapshots/<id>/` (hợp đồng ở `host-api.md` §6.11), host chỉ chép byte của bản chụp. Không gói nào dưới `host/` hay `cmd/vedette-host` nhập `database/sql` hoặc driver SQL; `db_schema` và `includes_key` là lời khai của `core`; DB hỏng hay schema mới hơn do `core` phát hiện lúc khởi động (kiểm sức khoẻ hỏng → host thay lại bản trước).
- **INV-14** **Chỉ truy cập cây của `core` theo descriptor (D-87)**: `core_data` được kiểm (thư mục thật, mọi thư mục cha thuộc root và không ai khác ghi được, kể cả sticky) rồi mở bằng `open(O_DIRECTORY|O_NONBLOCK)` + `os.Root` trên đường dẫn descriptor; mọi tệp mở với `O_NOFOLLOW|O_NONBLOCK` và kiểm trên descriptor (tệp thường, `nlink == 1`, chủ `core_uid`, trần cỡ); `chmod`/`chown` chỉ trên descriptor; chủ của tệp khôi phục là `core_uid:core_gid` từ `host.conf`. Không có lời gọi theo đường dẫn (`os.*`, `syscall.*`, `Root.Chmod|Chown|Lchown|Chtimes`) ở nơi xử lý cây của `core` ngoài `openCore`/`checkChain`, và `Config.CoreData` chỉ đọc ở `openCore`, `checkChain`, `checkCoreAtStart`, `NewWithDeps` (kiểm kiểu bằng `go/types`).
- **INV-15** **Không lệnh ghi nào chạy khi box sắp reboot**: từ lúc host quyết định reboot tới khi `boot_id` đổi (tối đa 10 phút), mọi lệnh ghi bị `409 rebooting`.
- **INV-11** Mạng ra của `host` chỉ gồm: kho gói apt của OS (host mirror liệt kê trong `OsInfo.mirrors`), registry image cố định `ghcr.io` qua `podman pull` (PRIVACY luồng 6; cập nhật PRIVACY ở lát 3-7) và khung ARP trong LAN để kiểm địa chỉ/gateway (D-101); không có luồng khác (SYS-7). NTP do chrony làm (D-106), không phải host.
- **INV-12** Mọi lệnh ghi một dòng kết quả (lệnh chạy được còn có dòng `accepted` ghi lúc bắt đầu; run chờ xác nhận mạng có thêm dòng `awaiting_confirm`) có cấu trúc (lệnh, tham số đã che bí mật, thời điểm, mã, người gọi do `core` truyền); lịch sử hiển thị ở Settings → Updates qua `core` (`core_os_run`).
- **INV-16** **Cấu hình mạng mới chỉ ghi bền khi được xác nhận (D-100)**: đổi phần quản trị ghi bản mới vào `/run/netplan/90-vedette.yaml` (tmpfs, che `/etc`) và `net/pending.json`; `/etc/netplan/90-vedette.yaml` chỉ được ghi ở `net.confirm`. Hết giờ, `net.revert`, host sập quá `revert_at` hay reboot đều đưa về cấu hình cũ; run chờ giữ khoá ghi (lệnh ghi khác → `409 pending_confirm`), chỉ `net.confirm`/`net.revert` đúng `run_id` đi qua; `Claim` rồi `Finish` (hay `Settle`) kết thúc run đúng một lần; confirm/revert phải Claim trước khi làm hiệu ứng (FW-2).
- **INV-17** **Unit là mã (D-105)**: host dựng **toàn bộ** unit `vedette-<service>.container` từ mẫu hằng trong binary; chỗ điền chỉ là digest, dòng `[Install] WantedBy=` và `core_uid`/`core_gid` của `host.conf`; không drop-in, không chuỗi tự do từ request. Ghi qua `os.Root` với tệp tạm `O_EXCL|O_NOFOLLOW` sau khi kiểm mọi thư mục cha thuộc root và không ai khác ghi được; test hợp đồng trên unit đã dựng: không `--privileged`, capability theo bảng service, `Network=host` chỉ `sensor`/`scan`, honeypot chỉ `ns:/run/netns/vedette-hp`, `core` có `User=` cố định và không `UserNS=auto`.
- **INV-18** **Root không bao giờ phân tích lưu lượng bắt được (D-101)**: socket `AF_PACKET` của host chỉ gửi và đọc khung ARP đúng 42 byte (probe địa chỉ, kiểm gateway), bộ đọc khung là hàm thuần có fuzz; host không đếm MAC, không đọc gói nào khác, không mở pcap. Số liệu lưu lượng SPAN (`other_macs`, `last_packet_at`) đến từ container `sensor` không đặc quyền qua `core`.

## Lệnh (allowlist)
Nguồn chốt là `docs/specs/host-api.md` §6 (tham số, hiệu ứng, mã từ chối); bảng này là bản tóm tắt và thay bảng nháp cũ (`os.status`, `pkg.list`, `net.list`, `image.pull`…, không còn dùng). Phần 1 của WP-07b đã cài tám lệnh OS/sao lưu/xuất log; `net.*`, `decoy_ip.*`, `container.*` chốt trên giấy ở phần 3 (D-99…D-107) và chưa có mã (test hợp đồng liệt kê chúng là "chưa").

| Nhóm | Lệnh | Tham số có kiểu | Trạng thái | Nguồn |
|---|---|---|---|---|
| OS | `os.check` | — | đã cài | D-53, §6.1 |
| OS | `os.install` | `scope ∈ {security, all}`, `snapshot hex32` | đã cài | D-53, D-87, §6.2 |
| OS | `os.auto_security.set` | `enabled bool` | đã cài | D-53, D-85, §6.3 |
| OS | `os.reboot`, `os.reboot.cancel` | `when ∈ {now, at}`, `at RFC 3339 UTC` | đã cài | D-53, §6.4 |
| Sao lưu | `backup.create`, `backup.restore` | `kind`, `include_secrets`, `label`, `backup_id hex32`, `snapshot hex32` | đã cài | D-85, D-87, §6.11–§6.12 |
| Log | `logs.export` | `units ⊂ 6 unit cố định`, `since`, `until` | đã cài | D-48, D-85, §6.13 |
| Mạng | `net.apply` | `mgmt {iface, mode, address cidr, gateway ip, dns ip[≤3]}`, `span.iface`, `ntp[≤4]`, `confirm_timeout_s 30..600` | phần 3 | D-56, D-99, D-100, D-106, §6.5 |
| Mạng | `net.confirm`, `net.revert` | `run_id` | phần 3 | D-100, §6.5 |
| Bẫy | `decoy_ip.add`, `decoy_ip.remove` | `ip`, `oui hex6?` (chỉ `add`) | phần 3 | D-50, D-101, D-102, §6.6 |
| Container | `container.pull` | `service`, `version`, `source`, `index`/`manifest` + `.minisig` (base64) | phần 3 | D-103, D-104, §6.7 |
| Container | `container.start` | `service`, `version?`, `restart?`, `snapshot hex32` (bắt buộc cho `core`) | phần 3 | D-104, D-105, §6.8 |
| Container | `container.stop` | `service` (≠ `core`), `persist bool` | phần 3 | D-105, §6.9 |
| Container | `container.rollback` | `service` | phần 3 | D-104, §6.10 |
| Đọc | `GET /v1/info`, `/v1/state/os`, `/v1/state/backups`, `/v1/audit`, tải sao lưu/xuất log | — | đã cài | §5 |
| Đọc | `GET /v1/state/net`, `/v1/state/containers` | — | phần 3 | D-101, §5 |

Không có `pkg.list`: danh sách gói của "This box" (INV-9) chưa có lệnh hay endpoint của host; cần thêm thì sửa §6 của `host-api.md` cùng CONTRACT này.

## Preconditions (trước khi gọi)
- **PRE-1** Cài kiểu **Appliance** (D-55). Kiểu "Chỉ container": không có `host`; `core` trả `unsupported` rõ ràng cho `/core/updates/os*` và cấu hình mạng sâu, **không giả vờ thành công**.
- **PRE-2** Người gọi (`core`) đã kiểm vai và ghi audit; có `request_id` để đối chiếu.
- **PRE-3** Không có thao tác khác đang chạy (INV-3).

## Postconditions (sau khi xong)
- **POST-1** `os.install` xong: số gói đã cài khớp `OsRunResult.installed`; sao lưu có thật; `health[]` phản ánh kiểm tra thật (không mặc định `ok`).
- **POST-2** `container.rollback` xong: container chạy lại với `previous` đã xác minh (đúng `ImageDigest`) và qua kiểm sức khoẻ; với `core` và `rollback.safe=false`, DB là bản `pre_update` của lần cập nhật đó, khôi phục trong cùng run (D-104); nếu sức khoẻ hỏng, bản đang chạy được đặt lại và run báo `reverted`/`failed`, không báo thành công.
- **POST-3** `net.*` thay đổi xong: trạng thái đọc lại (`GET /v1/state/net`) khớp giá trị vừa đặt và hiệu ứng đã kiểm (địa chỉ trên card, gateway trả lời ARP, `chronyc` thấy nguồn, decoy có trong `vedette-hp`); không khớp → hoàn tác hoặc báo lỗi. `net.apply` đổi phần quản trị kết thúc ở `awaiting_confirm` tới khi `net.confirm`/hoàn tác (INV-16).
- **POST-4** Mọi lệnh thất bại để hệ thống ở trạng thái cũ hoặc báo rõ trạng thái dở dang; không để thao tác treo giữ khoá vô hạn (có timeout theo lệnh, agent-safety).

## Forbidden (không bao giờ)
- **FORBID-1** Chạy lệnh ngoài allowlist; chạy qua shell; nối chuỗi lệnh từ tham số (INV-1, INV-2).
- **FORBID-2** Cổng mạng nghe; nhận lệnh từ tiến trình không phải `core`.
- **FORBID-3** Tự nâng bản phát hành OS; tự khởi động lại ngoài lệnh `os.reboot` / lịch đã đặt.
- **FORBID-4** Chạy image không qua kiểm chữ ký cosign.
- **FORBID-5** Chạm vào nội dung dữ liệu khách (DB, log, thiết bị) ngoài chép byte bản chụp theo lệnh `backup.create` (và `os.install`, `backup.restore` qua bản sao lưu nội bộ); không bao giờ mở hay phân tích DB.
- **FORBID-6** Mở cổng, sửa luật tường lửa ngoài danh sách lệnh (không "tự mở cổng vượt UFW": lý do chọn Podman, D-55). Ruleset nft hằng chặn đi ra trong namespace `vedette-hp` (D-102) là ngoại lệ duy nhất, không nhận tham số.

## Endpoints owned
Không có HTTP. Giao diện = socket Unix nội bộ với các lệnh ở trên. Các endpoint của **core** dựa vào `host` (không thuộc `host`, liệt kê để biết ai gọi):
`GET /core/updates/os`, `POST /core/updates/os/check`, `POST /core/updates/os/install`, `GET /core/updates/os/run`, `PATCH /core/updates/os/settings`, `POST|DELETE /core/updates/os/reboot`; Box network (D-56, S-CORE-8): `/core/network`, `/core/network/interfaces`, `/core/network/management` (+ `/confirm`, `/revert`), `/core/network/span` (+ `/status`), `/core/network/ntp`; cập nhật phần mềm (S-CORE-2): `/core/updates`, `/core/updates/check`, `/core/updates/apply`, `/core/updates/rollback`, `/core/updates/bundle`. Các endpoint mạng và cập nhật phần mềm có trong `contract.ts` nhưng backend còn trả 501 tới khi phần 3 có mã.

## Tables owned
Không. Lịch sử chạy và cài đặt cửa sổ bảo trì lưu ở `core` (`core_os`, `core_os_run`, `core_audit`).

## Events
- **Phát** (sang `core`): tiến trình cài (`lines`), hoàn tất, cần khởi động lại. **Nhận**: lệnh từ `core`.

## Khung đã cài (WP-07a)
Mã: `host/api` (kiểu dây), `host/config` (`/etc/vedette/host.conf`), `host/peer` (xác thực người gọi), `host/server` (máy chủ, bảng lệnh, run, kiểm toán), `host/client` (người gọi phía `core`), `cmd/vedette-host`. Chi tiết chốt ở `docs/specs/host-api.md` §15. Test hợp đồng: `modules/host/contract_test.go` (`go test ./modules/host/... -run Contract`):

| Điều | Test |
|---|---|
| INV-1, FORBID-1 | `TestContract_INV1_UnknownCommandIsRefusedAndRecorded`, `…_CommandTableIsClosedAndMatchesTheSpec`, `…_NothingTakesABinaryArgvOrPathFromTheRequest`, `TestContract_FORBID1_NoShellNoGenericExec` |
| INV-2 | `TestContract_INV2_BadArgsAreRefusedBeforeAnythingRuns` |
| INV-3 | `TestContract_INV3_OneWriteAtATime`, `…_ACommandThatIgnoresItsDeadlineStillHoldsTheLock` |
| INV-4 | `TestContract_INV4_EachPeerLayerDeniesAndIsAudited`, `…_NoRealCheckOffLinux`; `host/peer` (Linux) |
| INV-12 | `TestContract_INV12_EveryCommandLeavesOneChainedAuditLine` |
| POST-4 | `TestContract_POST4_TimeoutReleasesTheLock` |
| FORBID-2 | `TestContract_FORBID2_NoNetworkListener`, `…_TheListenerIsAUnixSocket` |

Các lỗi tìm thấy khi review bảo mật có test riêng trong `host/server/review_test.go`, `host/peer/peer_test.go`, `host/client/client_test.go`.

Chưa kiểm được trên máy phát triển (macOS): hiệu ứng thật trên Linux (quyền socket do root, `SO_PEERCRED`, cgroup của unit thật, unit systemd); xem `.ai/deferred/feat-host-framework.md`.

## Lệnh hệ thống đã cài (WP-07b phần 1)
Mã: `host/ops`. `GET /v1/info.commands` liệt kê **đúng** tám lệnh: `backup.create`, `backup.restore`, `logs.export`, `os.auto_security.set`, `os.check`, `os.install`, `os.reboot`, `os.reboot.cancel`. Test so danh sách này và các lệnh "chưa" (`net.apply|confirm|revert`, `decoy_ip.add|remove`, `container.pull|start|stop|rollback`) với các tiêu đề §6 của `host-api.md`. Test chạy trên máy giả (`host/ops/opstest`): thư mục gốc tạm, binary giả ghi argv và môi trường, DB là tệp byte và bản chụp do `opstest` ghi như `core` sẽ ghi (không SQL, INV-13); không bao giờ chạy apt/dpkg/systemctl thật.

| Điều | Hiện thực | Test |
|---|---|---|
| INV-2 (argv chặt) | một `exec.Runner`; bộ kiểm argv theo binary: `apt-get` ba dạng cố định, `apt-config dump`, `dpkg --audit`, `systemctl` vài động từ trên unit cố định, `journalctl` một dạng; tên gói qua regex gói Debian; môi trường đúng `PATH`, `LANG=C`, `DEBIAN_FRONTEND=noninteractive` | `TestContract_INV2_SystemCommandsRefuseBadArgsBeforeAnythingRuns`, `…_FORBID_ReleaseUpgradesAndSourcesAreOutOfReach`, `…OSCheck_ArgvEnvResult…`, `…OSInstall_HostRecomputes…` |
| INV-5, POST-1 | `os.install`: danh sách gói do host tính lại, sao lưu `pre_os_update` trước, `installed` đo bằng mô phỏng lại, `health[]` thật, run `failed` mang kết quả khi apt hoặc sức khoẻ hỏng; không bao giờ gỡ gói | `TestContract_OSInstall_*` |
| INV-6 | `os.reboot`/`os.reboot.cancel`: `now` chỉ sau khi run đã `succeeded`; lịch bền, duy nhất, sống qua restart; trần 3/24 giờ; `reboot_completed` sau boot mới | `TestContract_Reboot_*` |
| INV-10, FORBID-5 | sao lưu: bản không có khoá không chứa khoá; `pre_*` ép có khoá và không tải được (`403 contains_secrets`); chỉ tệp trong chỉ mục được phục vụ; mỗi lần tải có một dòng kiểm toán | `TestContract_Backup_*`, `TestContract_Restore_*`, `TestContract_LogsExport_KeepsAtMostThree…`, `TestContract_Downloads_AreRefused…` |
| INV-13 | bản chụp do `core` tạo, host chép byte; không SQL; `db_schema` là lời khai của `core`; bản chụp thiếu/cũ/sai hợp đồng bị từ chối | `TestContract_INV13_RootNeverImportsASQLDriver`, `TestContract_Backup_CopiesTheSnapshotBytes…`, `…NeverEvaluatesWhatCoreDefined`, `…RefusalsAndHostileCore`, `host/ops` `TestParseSnapshotMeta`, `FuzzParseSnapshotMeta` |
| INV-14 | symlink/FIFO/hardlink/chủ sai/quá cỡ ở bản chụp, `core_data` là symlink hoặc cha ghi được, FIFO đổi giữa chừng, tệp lạ tại tên đích khi khôi phục, chủ từ `host.conf`, không thao tác theo đường dẫn | `TestContract_INV14_NoPathBasedOperationsOnCoresTreeInHostOps`, `TestContract_INV14_ScannerCatchesPathBasedCallsOnCoresTree`, `TestContract_Backup_ASwapRaceWithAFIFONeverBlocks`, `TestContract_Restore_ReplacesWhateverCoreLeftAtTheLiveNames`, `…FilesGetCoreUIDAndGIDFromTheConfig`, `…RoundTrip`, `TestContract_Startup_*` |
| INV-15 | cổng `rebooting`: mọi lệnh ghi bị từ chối từ lúc bắt đầu reboot tới khi `boot_id` đổi; tự hạ sau 10 phút; sống qua restart của host; trần reboot không bị đồng hồ lùi đặt lại | `TestContract_Reboot_NoWriteStartsOnce…`, `…TheGateEndsWhen…`, `…TheGateSurvivesAHostRestart…`, `…ClockSetBackDoesNotResetTheLimit`, `TestContract_FORBID_ProductionWiringHasTheRebootGate` |
| POST-4 (lệnh dài) | khôi phục: run bền qua việc `core` dừng; hỏng → thay lại `pre_restore`, `reverted`; host chết giữa chừng → khôi phục lúc khởi động; chỗ trống kiểm theo cỡ thành viên khai báo trước khi giải nén | `…Restore_RunIsDurableAcrossAClientRestart`, `…UnhealthyCoreIsReverted…`, `…ACutShortRestoreIsPutBackAtStart` |
| INV-3 | mọi lệnh phần 1 là lệnh ghi dưới khoá chung | `TestContract_INV3_SystemWritesAreOneAtATime` |
| INV-12 | mỗi lệnh `accepted` + kết quả; dòng của chính host (`actor: system`); không bí mật trong tệp kiểm toán | `TestContract_INV12_SystemCommandsAreAuditedWithoutSecrets`, `…Reboot_…` |
| FORBID-3 | không có lệnh nâng bản phát hành; chỉ reboot do `os.reboot` hoặc lịch đã đặt | `…FORBID_ReleaseUpgradesAndSourcesAreOutOfReach` |
| Cấm seam test ở sản xuất | `cmd/vedette-host` và `host/server` không tham chiếu `ops.NewWithDeps`, không nhập `opstest` | `TestContract_FORBID_ProductionWiringNeverUsesTheTestSeams` |

Hàm thuần có fuzz (30 giây mỗi cái): `ParseSimulation`, `ParseUpdateHosts`, `ParseAptConfig`, `RedactJournalLine` (JSON hợp lệ ra JSON hợp lệ, lũy đẳng), `FilterJournal`, `ParseManifest`, `ReadArchive` (chỉ ba tên, mỗi tên một lần, không đường dẫn), `ParseSnapshotMeta` (`snapshot.json` của `core`), và `config.Parse` (có `core_gid`).

Chưa kiểm được trên máy phát triển (macOS): hiệu ứng thật trên Ubuntu 24.04/Debian 13 (apt, dpkg, timer, `journalctl`, `systemctl` của unit `core`), khoá `fcntl` của apt thật, `os.OpenRoot` và `fs.protected_symlinks/hardlinks` thật, phần `core` tạo bản chụp (WP-07b phần 2); xem `.ai/deferred/feat-host-os-commands.md`.

## Khung chờ xác nhận đã cài (WP-07b phần 3, lát 3-1, D-100)
Mã: `host/server/awaiting.go` (+ `registry.go`, `handlers.go`, `server.go`, `readers.go`), `host/api` (`pending_confirm`, `not_awaiting_confirm`). Chưa có lệnh sản xuất nào dùng (`net.apply` ở lát 3-4); test dùng lệnh chỉ có trong `_test.go`. Bất biến của khung (INV-16 là phần mạng dựa trên chúng):
- **FW-1 Run chờ giữ khoá ghi.** Chỉ lệnh khai `Spec.Awaits` (lệnh ghi, không phải `WhileAwaiting`; hai cờ loại trừ nhau, kiểm ở `NewRegistry`) mới được trả `server.Awaiting{RevertAt, Result}`, và chỉ khi nó đang giữ khoá, chưa có run chờ, `RevertAt` ở tương lai và không quá `started_at + 660 s`; ngược lại run `failed command_failed` ("Awaiting không hợp lệ") và khoá nhả như thường. Hợp lệ → run `awaiting_confirm` có `revert_at`, **không** nhả khoá; mọi lệnh ghi khác → `409 pending_confirm` kèm `run_id` của run đang chờ (trước cả `Check`, nên `net_pending_confirm` của `os.reboot` chỉ là lớp thứ hai); lệnh đọc không bị khoá. Run chờ có đúng ba dòng kiểm toán: `accepted`, `awaiting_confirm`, kết quả cuối. Sự kiện của run chờ được ghi ra đĩa sau **mỗi** sự kiện (kể cả dòng log của hẹn giờ). `rc.OnParked(fn)` chạy ngay sau khi run đã vào trạng thái chờ và khoá đã công bố: đặt hẹn giờ hoàn tác ở đó, nên hẹn giờ bắn sớm không bao giờ gặp run "chưa chờ". **Khoá không bao giờ hở**: khi run chờ nhả khoá mà một lệnh `WhileAwaiting` còn đang chạy, khoá được trao cho lệnh đó và nó nhả khi xong; `WriteActive()` và cổng lệnh ghi đếm cả lệnh đó.
- **FW-2 Kết thúc run chờ đúng một lần: Claim, làm, Finish.** `(*Server).Claim(runID)` là so-và-đổi: lấy run ra khỏi trạng thái chờ (mọi `Claim`/`Settle`/lệnh `WhileAwaiting` khác cho run đó nhận `ErrNotAwaiting` / `412`) nhưng **giữ khoá ghi**; người thắng làm hiệu ứng của mình rồi gọi `Claimed.Finish(status, *RunError)` (đúng một lần): dòng kiểm toán cuối, ghi run, nhả khoá, sự kiện cuối. `net.confirm` và `net.revert` **phải Claim trước, làm hiệu ứng, rồi Finish**, để cuộc đua xác nhận/hẹn giờ được phân định trước khi bất kỳ bên nào đụng vào hệ thống. `Settle(runID, status, *RunError)` = `Claim` + `Finish` cho kết thúc không có hiệu ứng ở giữa. Lần gọi thứ hai hay run không chờ → `ErrNotAwaiting`, không đổi gì. Sau khi `Shutdown` bắt đầu → `ErrShuttingDown`, không đổi gì (run vẫn chờ trên đĩa); `Settle` đã qua cửa kiểm đó được `Shutdown` đợi xong trước khi đóng nhật ký kiểm toán.
- **FW-3 `WhileAwaiting` chỉ qua cửa cho đúng run.** Lệnh có cờ này (chỉ `net.confirm`, `net.revert`; phải là lệnh ghi) chạy khi và chỉ khi `args.run_id` là run đang chờ; ngược lại `412 not_awaiting_confirm` và lệnh **không** chạy (run sai, đã `Settle`, hoặc không có run chờ). Mỗi lần chỉ một lệnh như vậy chạy (lệnh thứ hai `busy` kèm `run_id` của lệnh đang chạy). Gửi lại cùng `X-Request-Id` trả đúng run cũ, không chạy lại (idempotency).
- **FW-4 Khởi động lại.** `recover()` (trong `New`, nên xong trước `Listen`) hỏi `Options.Resume(run)` cho mỗi run `awaiting_confirm`: `true` → run vẫn chờ và giữ khoá, sự kiện đã lưu được nối tiếp (seq không lặp); `false`, `nil`, panic, hoặc run chờ thứ hai → `failed host_restarted` như run bị cắt ngang. Run được giữ luôn coi là run ghi (nhả khoá khi kết thúc), và `revert_at` lưu quá `started_at + 660 s` bị kẹp về mốc đó (ghi log), không bao giờ tin hơn. Callback `AfterFinish` và `OnParked` **không** được khôi phục sau khi khởi động lại: người gọi dựng lại hẹn giờ **sau** `New` (`Resume` rồi `Ops.Start` từ `pending.json`) và kết thúc run bằng `Claim`/`Finish` hay `Settle`. `Shutdown` không kết thúc run chờ.
- **FW-5 Giới hạn thân theo lệnh.** `Spec.MaxBody` (0 = 512 KiB, tối đa 4 MiB; `NewRegistry` từ chối ngoài khoảng); vượt → `400 invalid_args` nói đúng giới hạn của lệnh đó.
- **FW-6 Đọc.** `Readers.Net`, `Readers.Containers` nối vào `GET /v1/state/net|containers`; chưa gắn (`nil`) → `404 unknown_command` như mọi đường chưa có.

| Điều | Test |
|---|---|
| FW-1 | `TestAwaiting_HoldsTheWriteLockAndAnswersPendingConfirm`, `…_AuditHasThreeLinesAcceptedAwaitingFinal`, `TestContract_INV16_AwaitingRunBlocksSystemWrites` (lệnh OS thật), `TestNetPendingFollowsTheServersAwaitingRun` (`host/ops`) |
| FW-1 (hẹn giờ, khoá hở, `Awaits`) | `…_LockStaysHeldWhenTheTimerSettlesWhileAConfirmStillRuns`, `…_LockStaysHeldWhenAConfirmSettledItselfAndStillHasWork`, `…_AwaitingFromAReadCommandIsInvalid`, `…_AwaitingFromAWhileAwaitingCommandIsInvalidAndDoesNotOrphanTheWaitingRun`, `…_AwaitingFromACommandThatIsNotDeclaredAwaitsFails`, `…_RegistryRulesForAwaitsAndWhileAwaiting`, `…_RevertAtMustBeInTheFutureAndWithinTheConfirmWindow`, `…_OnParkedRunsAfterTheRunIsParkedSoAnEarlyTimerCanSettle` |
| FW-2 | `…_ClaimDecidesTheRaceBeforeAnyEffectRuns`, `…_ClaimAfterShutdownIsRefusedAndTheRunStaysAwaiting`, `…_SettleWorksExactlyOnceUnderConcurrency` (50 goroutine + confirm qua socket), `…_SettleRejectsBadStatusWithoutConsumingTheRun`, `…_SettleRacingShutdownLeavesAConsistentRun`, `…_SettleAfterShutdownIsRefused` |
| FW-3 | `…_WhileAwaitingGetsThroughOnlyForTheMatchingRun`, `…_OneWhileAwaitingCommandAtATime`, `…_IdempotentReplayOfConfirm`, `…_InvalidAwaitingFailsTheRunAndFreesTheLock` |
| FW-4 | `…_ResumedStreamContinuesAfterEventsLoggedWhileWaiting`, `…_ResumedRunWithWriteFalseStillReleasesTheLockAtSettle`, `…_ResumeClampsAStoredRevertAtBeyondTheWindow`, `…_RunSurvivesARestartWhenResumeSaysSo` (cả thứ tự trước `Listen`), `…_RunIsFailedHostRestartedWithoutResume`, `…_OnlyTheFirstAwaitingRunIsResumed` |
| FW-5, FW-6 | `…_MaxBodyIsPerCommand`, `…_NetAndContainersReadersAnswerOnlyWhenWired`; `TestContract_Part1_TheCommandTableMatchesSection6OfTheSpec` (bảng "chưa có" không đổi: lát này không đăng ký lệnh nào) |

## Phần 3: `net.*`, `decoy_ip.*`, `container.*` (WP-07b, chốt trên giấy ở lát 3-0; khung ở lát 3-1 đã có mã, phần còn lại chưa)
Thiết kế: `docs/specs/host-api.md` §6.5–§6.10 và §18; quyết định D-99…D-107. Lát 3-1 (khung chờ xác nhận), 3-2 (`internal/release`), 3-3…3-5 (mạng, decoy), 3-6…3-8 (Quadlet, kéo, khởi động, hoàn tác). Test hợp đồng dự kiến cho từng bất biến mới, chạy trên máy giả (D-107: `Deps.Root`, binary giả, giả reboot bằng xoá `Root/run` và đổi `boot_id`):

| Điều | Test dự kiến |
|---|---|
| INV-16 | đổi phần quản trị → `awaiting_confirm`, `/etc` không đổi tới `net.confirm`; hẹn giờ → `reverted not_confirmed`; giả reboot → `reverted_by_reboot`; host sập trước/sau `revert_at`; lệnh ghi khác → `409 pending_confirm`; `confirm` đua với hẹn giờ: bên `Claim` thắng quyết định trước mọi hiệu ứng, bên kia nhận `412`, run kết thúc đúng một lần; chỉ đổi DNS/NTP/SPAN → `succeeded` ngay |
| INV-17 | golden unit theo service; quét unit đã dựng (capability, mạng, `--privileged`, `User=` của `core`); symlink ở tên unit hoặc thư mục, thư mục cha ghi được → từ chối; `persist` bật/tắt dòng `[Install]` |
| INV-18 | không gói nào dưới `host/` mở pcap hay đọc gói ngoài bộ đọc khung ARP 42 byte (quét mã nguồn); fuzz bộ đọc khung |
| INV-7 | `registry_not_allowed`, `sequence_regress`, `key_revoked`, `release_revoked`, `digest_not_in_manifest`, `platform_mismatch`, `downgrade_not_allowed`, `previous_revoked`, `rollback_not_allowed`; vector chữ ký sinh bằng `minisign` và `cosign` thật |

## Khi vắng mặt / lỗi
Không có "tắt" (không phải module). Phía `core`, `host/client` trả `client.ErrUnreachable` khi socket vắng hoặc không nối được: đó là tín hiệu "không phải appliance / host không chạy", khác với lỗi của host (`*client.Error` có mã §11). Kiểu "Chỉ container": mọi tính năng cần `host` trả `unsupported` có lý do. Appliance mà `host` không phản hồi: Settings → Updates và Box network hiện "Không liên lạc được với vedette-host" kèm trạng thái cuối cùng biết được; các module khác chạy bình thường nhưng không thay đổi được OS/mạng/image.

## Dependencies
- **DEPENDS ON**: systemd, apt, Podman (Quadlet), netplan (renderer `networkd`, D-99), iproute2 (`ip`), nftables (`nft`), procps (`sysctl`), chrony (`chronyc`, D-106), socket `AF_PACKET` của kernel (D-101); installer (WP-08) cài và giao quyền (`THIRD_PARTY_NOTICES.md`); `core` chỉ là **người gọi**.
- **DEPENDED ON BY**: `core` (Updates, Box network, sao lưu), `honeypot` (IP phụ), `sensor-passive`/`logs` (card SPAN), `inventory` ("This box", INV-9; lệnh chưa có), `scan`/`scan-credentialed`/`honeypot`/`sensor` (vòng đời container).

## Câu hỏi mở
1. ~~Cấu hình mạng/SPAN (D-56) chưa có story ID và endpoint~~ **Đã có:** story S-CORE-8, endpoint `/core/network*` trong `contract.ts`.
2. ~~Đổi card quản trị có thể cắt đứt chính kết nối quản trị~~ **Đã chốt (D-100):** cửa sổ xác nhận 30–600 s (mặc định 120 s) với lớp phủ `/run`, tự hoàn tác khi hết giờ hay reboot (INV-16).
3. Tên lệnh ở bảng trên là đề xuất; chốt cùng lúc viết `host`. **Trả lời một phần (WP-07a, 07b phần 1):** dạng tên đã chốt ở khung (`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,3}$`), bảng lệnh là một `Registry` đóng dựng một lần (không có hàm thêm/bớt), và nguồn chốt tên là `host-api.md` §6 (`os.check`, `os.install`, `os.auto_security.set`, `os.reboot`, `os.reboot.cancel`, `net.apply|confirm|revert`, `decoy_ip.add|remove`, `container.pull|start|stop|rollback`, `backup.create|restore`, `logs.export`; đọc trạng thái qua `GET /v1/state/*`), thay cho bảng nháp ở trên khi 07b đăng ký từng lệnh. `DefaultRegistry()` đã bỏ: registry dựng ở `cmd/vedette-host` từ `ops.Commands()`; test hợp đồng so danh sách đã cài và danh sách "chưa" với các tiêu đề §6 của tài liệu.
4. ~~`vedette-updater` còn trong `contract.ts`, `osMock.ts`, `locales/en/core.json`, `PRIVACY.md` luồng 6~~ Đã đổi sang `vedette-host` (WP-06).
5. ~~Registry image cho phép và khoá cosign công khai đặt ở đâu?~~ **Đã chốt:** `ghcr.io/knt048/vedette-<service>` là hằng biên dịch (D-57 (3), D-104); khoá minisign (đang dùng + dự phòng ngoại tuyến) và khoá cosign nhúng trong binary (D-103). kien tạo khoá ngoại tuyến trước lát 3-2.
