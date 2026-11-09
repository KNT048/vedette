# Host (`vedette-host`) Contract

> Loại: **thành phần** (component), không phải module bật/tắt · Story: S-CORE-7, S-INV-5 (+ D-56) · Quyết định: D-53, D-55, D-56, D-12 · Last verified: 2026-11-09 (khung WP-07a: INV-1/2/3/4/12, POST-4, FORBID-1/2 có test; lệnh hệ thống chờ WP-07b)
> Thay thế `vedette-updater` của D-53 (D-55). `contract.ts`, `osMock.ts`, `locales/en/core.json` và `PRIVACY.md` luồng 6 đã đổi sang tên mới (WP-06).
> Là phần duy nhất của hộp chạy **root**. Mọi thứ khác (core, sensor, honeypot, scan) chạy không root trong container.

## Invariants (luôn đúng)
- **INV-1** **Danh sách lệnh cố định (allowlist)**: chỉ các lệnh ở mục "Lệnh" dưới đây; lệnh lạ → từ chối `unknown_command`, không có đường "chạy chuỗi bất kỳ". Thêm lệnh = sửa CONTRACT này + test + `THIRD_PARTY_NOTICES.md` nếu thêm công cụ ngoài.
- **INV-2** **Không shell** (SYS-1): mọi tiến trình con chạy bằng `argv` cố định với tham số đã kiểm theo kiểu (`netip` cho IP/CIDR, regex `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$` cho tên card/container, enum cho `scope`/`when`, `HH:MM` cho giờ). Tham số sai kiểu → từ chối trước khi chạm hệ thống.
- **INV-3** **Một thao tác thay đổi tại một thời điểm** (khoá toàn cục): lệnh thứ hai khi đang chạy → 409 `busy` (kể cả khi lệnh trước đã báo `timeout` nhưng tiến trình của nó chưa trả về: khoá giữ tới khi trả về, quá trần thì host thoát để systemd khởi động lại); reboot trong lúc cài đặt → 409.
- **INV-4** **Chỉ `core` gọi được**: giao tiếp qua socket Unix nội bộ, quyền socket và kiểm danh tính tiến trình gọi; không cổng mạng. Người dùng/UI không bao giờ gọi trực tiếp; `core` kiểm vai (admin/operator) và ghi `core_audit` (SYS-3) **trước** khi gọi `host`.
- **INV-5** **Cài bản vá OS (D-53)**: chỉ danh sách lệnh apt cố định (`security` hoặc `all`); **sao lưu DB trước**, **kiểm sức khoẻ sau** (`health[]`), tiến trình hiện trực tiếp (`lines`), kết quả `installed`, `security`, `backup`, `reboot_required`. **Không bao giờ tự nâng bản phát hành OS** (chỉ trả hướng dẫn `release_upgrade`).
- **INV-6** Khởi động lại: `now`, `window`, hoặc `custom` với `at` (HH:MM) **nằm trong cửa sổ bảo trì**; huỷ lịch được; từ chối khi đang cài (INV-3). Tự cập nhật bảo mật = `unattended-upgrades` bật/tắt; cửa sổ bảo trì `always | window{days 1..7, from, to}` (`to < from` = qua nửa đêm).
- **INV-7** **Image container (D-55)**: chỉ kéo và chạy image có **chữ ký cosign hợp lệ** từ danh sách registry cho phép; chữ ký sai/thiếu → từ chối, không khởi động; hoàn tác = chạy lại **tag cũ** đã có sẵn. Phát hành theo lô (cohort, D-12).
- **INV-8** **Cấu hình mạng (D-56)**: card quản trị (DHCP hoặc tĩnh: IP, gateway, DNS), card SPAN/TAP (không IP, chế độ nghe), IP phụ cho bẫy (macvlan), NTP. IP/CIDR hợp lệ qua `netip`; IP phụ phải nằm trong dải mạng của hộp, khác IP hộp (validate lại ở `host` dù `core` đã kiểm). Trạng thái SPAN (gói/giây, số MAC khác hộp thấy được, lần nhận gói cuối) là **chỉ đọc** từ bộ đếm giao diện; không lưu nội dung gói.
- **INV-9** `pkg.list` (dpkg) chỉ đọc, là nguồn danh sách gói của chính hộp ("This box", độ tin cậy 1.0, D-53, S-INV-5).
- **INV-10** Sao lưu DB: tệp không chứa mật khẩu/khoá (như `/core/data/backup`); khoá/secret không bao giờ ra khỏi `host`/`core` dạng đọc được (SYS-4).
- **INV-11** Mạng ra của `host` chỉ gồm: kho gói apt của OS (host mirror liệt kê trong `OsInfo.mirrors`) và registry image đã khai báo (PRIVACY luồng 6); không có luồng khác (SYS-7).
- **INV-12** Mọi lệnh ghi một dòng kết quả (lệnh chạy được còn có dòng `accepted` ghi lúc bắt đầu) có cấu trúc (lệnh, tham số đã che bí mật, thời điểm, mã, người gọi do `core` truyền); lịch sử hiển thị ở Settings → Updates qua `core` (`core_os_run`).

## Lệnh (allowlist) — *bảng này là bản nháp; danh sách chốt là `docs/specs/host-api.md` §6, hiện thực ở WP-07b*
| Nhóm | Lệnh | Tham số có kiểu | Nguồn |
|---|---|---|---|
| OS | `os.status` | — | D-53 |
| OS | `os.check` (tương đương `apt update`) | — | D-53 |
| OS | `os.install` | `scope ∈ {security, all}` | D-53 |
| OS | `os.settings` | `auto_security bool`, `window` | D-53 |
| OS | `os.reboot`, `os.reboot.cancel` | `when ∈ {now, window, custom}`, `at HH:MM` | D-53 |
| Gói | `pkg.list` | — | D-53 (4) |
| Mạng | `net.list`, `net.admin.set`, `net.span.set`, `net.span.stats`, `net.decoy_ip.set`, `net.decoy_ip.remove`, `net.ntp.set` | `interface`, `ip`, `cidr`, `mode` | D-56 |
| Container | `image.pull` (kèm kiểm cosign), `container.start`, `container.stop`, `container.restart`, `container.rollback` | tên container/tag đã allowlist | D-55 |
| Sao lưu | `backup.create`, `backup.list` | — | D-55 |

## Preconditions (trước khi gọi)
- **PRE-1** Cài kiểu **Appliance** (D-55). Kiểu "Chỉ container": không có `host`; `core` trả `unsupported` rõ ràng cho `/core/updates/os*` và cấu hình mạng sâu, **không giả vờ thành công**.
- **PRE-2** Người gọi (`core`) đã kiểm vai và ghi audit; có `request_id` để đối chiếu.
- **PRE-3** Không có thao tác khác đang chạy (INV-3).

## Postconditions (sau khi xong)
- **POST-1** `os.install` xong: số gói đã cài khớp `OsRunResult.installed`; sao lưu có thật; `health[]` phản ánh kiểm tra thật (không mặc định `ok`).
- **POST-2** `container.rollback` xong: container chạy lại với tag trước và qua kiểm sức khoẻ; nếu sức khoẻ hỏng, trạng thái báo hỏng, không báo thành công.
- **POST-3** `net.*` thay đổi xong: trạng thái đọc lại (`net.list`) khớp giá trị vừa đặt; không khớp → báo lỗi.
- **POST-4** Mọi lệnh thất bại để hệ thống ở trạng thái cũ hoặc báo rõ trạng thái dở dang; không để thao tác treo giữ khoá vô hạn (có timeout theo lệnh, agent-safety).

## Forbidden (không bao giờ)
- **FORBID-1** Chạy lệnh ngoài allowlist; chạy qua shell; nối chuỗi lệnh từ tham số (INV-1, INV-2).
- **FORBID-2** Cổng mạng nghe; nhận lệnh từ tiến trình không phải `core`.
- **FORBID-3** Tự nâng bản phát hành OS; tự khởi động lại ngoài lệnh `os.reboot` / lịch đã đặt.
- **FORBID-4** Chạy image không qua kiểm chữ ký cosign.
- **FORBID-5** Chạm vào nội dung dữ liệu khách (DB, log, thiết bị) ngoài sao lưu theo lệnh `backup.create`.
- **FORBID-6** Mở cổng, sửa luật tường lửa ngoài danh sách lệnh (không "tự mở cổng vượt UFW": lý do chọn Podman, D-55).

## Endpoints owned
Không có HTTP. Giao diện = socket Unix nội bộ với các lệnh ở trên. Các endpoint của **core** dựa vào `host` (không thuộc `host`, liệt kê để biết ai gọi):
`GET /core/updates/os`, `POST /core/updates/os/check`, `POST /core/updates/os/install`, `GET /core/updates/os/run`, `PATCH /core/updates/os/settings`, `POST|DELETE /core/updates/os/reboot`, và (D-56) Cài đặt → Box network (**chưa có trong `contract.ts`**).

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

## Khi vắng mặt / lỗi
Không có "tắt" (không phải module). Phía `core`, `host/client` trả `client.ErrUnreachable` khi socket vắng hoặc không nối được: đó là tín hiệu "không phải appliance / host không chạy", khác với lỗi của host (`*client.Error` có mã §11). Kiểu "Chỉ container": mọi tính năng cần `host` trả `unsupported` có lý do. Appliance mà `host` không phản hồi: Settings → Updates và Box network hiện "Không liên lạc được với vedette-host" kèm trạng thái cuối cùng biết được; các module khác chạy bình thường nhưng không thay đổi được OS/mạng/image.

## Dependencies
- **DEPENDS ON**: systemd, apt, Podman, netlink của OS; `core` chỉ là **người gọi**.
- **DEPENDED ON BY**: `core` (Updates, Box network, sao lưu), `honeypot` (IP phụ), `sensor-passive`/`logs` (card SPAN), `inventory` ("This box" qua `pkg.list`), `scan`/`scan-credentialed`/`honeypot`/`sensor` (vòng đời container).

## Câu hỏi mở
1. Cấu hình mạng/SPAN (D-56) chưa có story ID trong `USER_STORIES.md` và chưa có endpoint trong `contract.ts` (no-imagined-features: cần story trước khi code).
2. Đổi card quản trị có thể cắt đứt chính kết nối quản trị: cần cơ chế tự hoàn tác sau N giây nếu `core` không xác nhận? (chưa nêu trong D-56).
3. Tên lệnh ở bảng trên là đề xuất; chốt cùng lúc viết `host`. **Trả lời một phần (WP-07a):** dạng tên đã chốt ở khung (`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,3}$`), bảng lệnh là một `Registry` đóng dựng một lần (không có hàm thêm/bớt), và nguồn chốt tên là `host-api.md` §6 (`os.check`, `os.install`, `os.auto_security.set`, `os.reboot`, `os.reboot.cancel`, `net.apply|confirm|revert`, `decoy_ip.add|remove`, `container.pull|start|stop|rollback`, `backup.create|restore`, `logs.export`; đọc trạng thái qua `GET /v1/state/*`), thay cho bảng nháp ở trên khi 07b đăng ký từng lệnh. Hiện `DefaultRegistry()` rỗng và test hợp đồng so với danh sách tài liệu.
4. ~~`vedette-updater` còn trong `contract.ts`, `osMock.ts`, `locales/en/core.json`, `PRIVACY.md` luồng 6~~ Đã đổi sang `vedette-host` (WP-06).
5. Registry image cho phép (tên/host) và khoá cosign công khai đặt ở đâu (nhúng trong gói cài, D-12)?
