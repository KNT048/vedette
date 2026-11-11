# Sensor-passive — Change Impact Map

## Modifying: `sensorpassive.Service` — `Status() []Sensor`, `SetInterface(ctx,id,iface,span)`, `SpanStats()`
- **SPA** (`SensorsSection`, Devices → Scope and sensors), **host** (Box network hiển thị `SpanStats`), **core** (`/core/logs/export` không dùng). Đổi `Sensor` phải sửa `inventory/contract.ts`. Từ SP-4 `Status()`/`SpanStats()` đọc heartbeat của vai `passive` (không còn đọc `Engine`): đổi ngưỡng `online` (90 s) hay cách tính verdict là đổi điều GUI hiện, giữ tiêu chí S-INV-1 ("offline trong 90 s").

## Modifying: `Engine` (parser, thang tin cậy, bộ lọc) và `MetaItem`
- **inventory** (giá trị "đang dùng"), **logs** (trường metadata): thêm trường vào `MetaItem` = lưu thêm về lưu lượng; test `TestContract_INV3` chặn, phải sửa CONTRACT INV-3 trước. Đổi thang `Conf*` đổi thứ tự hiển thị. Thêm parser = thêm `Fuzz*` (test INV-4 kiểm danh sách).
- **cmd/vedette** (`sensorpassive.go`): `netHost` là chỗ thay bằng module `host`; `sensorBackend` (`sensorwire.go`) và handler dùng chung một `Service`. `Engine` chạy trong `cmd/vedette-sensor passive` (gói `capture`); từ SP-5a (D-141) job `capture` không còn trong `core`, `netHost.Interfaces` chỉ để `SetInterface` kiểm card.

## Modifying: `content/oui` (bảng OUI) và `make oui`
- **inventory**: quan sát `vendor` 0.4 của thiết bị mới. `make oui` ghim nguồn theo commit + SHA-256 (`scripts/oui`, hằng `pinnedCommit`/`pinnedSHA256`), làm sạch tên hãng (bỏ C0/C1, bidi, zero-width, dấu gạch nối mềm, tag), lỗi nếu hai hãng cùng một tiền tố; `TestEveryVendorIsCleanText` canh bảng. Đổi bảng (chạy lại `make oui`) đổi tên hãng hiển thị cho thiết bị mới, không sửa quan sát cũ. THIRD_PARTY_NOTICES ghi nguồn runZero/IEEE.

## Modifying: `deviceBook` (`book.go`, hạn mức MAC mới)
- **inventory** (số thiết bị `discovered` mỗi ngày, bản ghi kiểm toán, sự kiện `asset.discovered`): đổi `maxNewMACsPerMinute/Hour`, `confirmAfter`, `firstSightingTTL`, `maxFirstSightings` đổi tốc độ thiết bị thật xuất hiện và cận "ít hơn 20.000 MAC mới giữa hai khung" (CONTRACT, Giới hạn chống ngập); `maxNewValuesPerHour` đổi tốc độ một thiết bị đổi tên/model. Sổ (thiết bị, khung đầu, hãng còn nợ, hạn mức giá trị) nằm trong `Service`, không trong `Engine`. `Record` của inventory cắt còn 32 dòng mỗi (thiết bị, trường, nguồn) (INV-16): đổi hằng đó đổi độ dài lịch sử giá trị.

## Modifying: gọi `inventory.RecordObservation`
- **inventory**: `source=passive` và thang `confidence` quyết định giá trị "đang dùng". Đổi thang tin cậy làm đổi `summary` và thứ tự hiển thị ở mọi thiết bị.

## Modifying: sự kiện `sensor.span.metadata_batch`
- **logs** (khớp IOC, nhóm B): đổi trường = mất cảnh báo "máy nào liên lạc IP/domain độc hại". Test hợp đồng ở bên phát.

## Modifying: quyền `net_raw`, `pcap` trong MANIFEST và container `sensor`
- **vedette-host/Quadlet** (cấp CAP_NET_RAW): thêm quyền = thay đổi bảo mật cần sửa CONTRACT; bỏ quyền = module không khởi động. Unit `sensor` (D-114, `host-api.md` §18): `User=<sensor_uid>:<sensor_gid>`, không `UserNS`, chỉ `NET_RAW`; thêm `UserNS` làm raw socket hỏng trên mạng host; thêm `NET_BIND_SERVICE`/`NET_ADMIN` phải sửa D-114 và host CONTRACT INV-17.

## Modifying: giao thức sensor vai `passive` (`core/sensorlink`, `docs/specs/sensor-protocol.md` §6.1–§6.3)
- **core** (handler, `core_sensor_cert`), **sensor** (`capture` + client), **host** (unit, volume khoá `vedette-creds-passive`). Giải mã chặt hai phía: thêm hay đổi một trường dây = tăng `X-Vedette-Proto` (D-109 (4)); trong cửa sổ cập nhật sensor mới nhận `426` và giữ hàng đợi. Đổi trần thân, `items` ≤ 500, `value` ≤ 200 B, cửa sổ `seen_at` phải sửa spec §9 cùng test hợp đồng.
- Hạn mức chống ngập có **hai nơi**: `book.go` (lớp thứ nhất trong `capture`) và handler `observations` của `core` (`budget_exhausted`, D-111 (2)); đổi một nơi phải đổi nơi kia, nếu không hoặc `core` từ chối điều sensor cho qua (mất thiết bị thật), hoặc lớp `core` không còn chặn được sensor bị chiếm.
- Gói `capture` không được nhập `core/store`, `database/sql`, SQLite (test `go list -deps` của `cmd/vedette-sensor`, SP-5).

## Disabling this module
- Devices ngừng nhận thiết bị mới thụ động; "Scope and sensors" trống; S-INV-3 chỉ còn nguồn khác.
- `logs` mất metadata SPAN; không ảnh hưởng `sensor-active`, `agent-intake`, `honeypot`.
- **Container `sensor` theo module (D-260)**: `cmd/vedette/modulecontainer.go` + `modreg.NewOnGuard`/`OffGuard` gọi `container.start`/`container.stop persist` của host; bỏ hai guard này (hoặc xoá `[Install]` khỏi hợp đồng) thì sau cài mới container không lên và sau reboot nó chạy khi module tắt (lỗi M3 của rà RUNBOOK). Mỗi lần bật/tắt tốn một lệnh ghi của host (10/phút cho cả `core`).
- Quan sát/thiết bị đã có giữ nguyên.

## SP-4 xong: nửa `capture` và nửa `core` đã tách (D-122)
- **`capture.Link`** (ba hàm: `Config`, `PostObservations`, `PassiveHeartbeat`) là chỗ nối hai nửa: `*sensorlink.Client` (sensor) và `sensorpassive.Service` (job `capture` trong `core` tới SP-5) đều thoả nó. Đổi hàm nào là đổi cả hai và `cmd/vedette-sensor passive`; đổi dây thì tăng `X-Vedette-Proto`.
- **`Service.Observations`** là đường vào duy nhất của quan sát thụ động (không còn `SubmitBatch`): kiểm mục, `FloodBudget`, kẹp `confidence`, epoch/seq. Đổi trần tin cậy (`capture.MaxConfidence`, các hằng `Conf*`) hay hạn mức (`capture.NewMACsPerMinute`… dùng chung cho sổ của sensor và `FloodBudget` của `core`) là đổi hai lớp cùng lúc: test của `capture` và `backend_test.go` canh sự lệch.
- **`sensorlink.DropKeys`** (34 khoá) là hợp đồng giữa bộ đếm của `capture` và heartbeat: thêm một bộ đếm mới (`drop("...")`, `CountDrop`, `count`) mà không thêm khoá thì test `TestEveryCounterIsInTheClosedSetOfTheProtocol` đỏ; thêm khoá là đổi dây (tăng proto vì `core` cũ từ chối khoá lạ).
- **`Status`, `SpanStats`** đọc heartbeat: GUI (`SensorsSection`, `SpanCard`) thấy `interfaces` rỗng và `offline` cho tới nhịp đầu của sensor. **`SetInterface` và danh sách địa chỉ của hộp (từ chối mục về hộp) đọc `Host.Interfaces`** (host là nguồn có thẩm quyền, D-118): gỡ `Host.Interfaces` ở SP-5 phải thay bằng `GET /v1/state/net` của host, không bằng heartbeat.
- **`modules/inventory`**: `Record` bỏ quan sát về MAC/IP của `is_box` và `claimIP` không dời IP của `manual`/`is_box` cho nguồn không phải `agent`; `RecomputeAsset` đặt MAC của hộp chỉ từ `agent`. Đổi một trong ba là đổi điều test `TestSensorsCannotChangeTheBox` canh.
- **`cmd/vedette-sensor`**: gói `capture` vào binary; test `TestBinaryDependencies` cho phép thêm `content/oui`, `core/observe`, `modules/sensor-passive/capture` và `golang.org/x/sys/unix` (một tuỳ chọn socket nhận), cấm `database/sql`, SQLite, `core/store`, `core/audit`, `core/secrets`, `core/pki`, `modules/inventory`.
