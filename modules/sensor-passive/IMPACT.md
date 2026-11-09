# Sensor-passive — Change Impact Map

## Modifying: `sensorpassive.Service` — `Status() []Sensor`, `SetInterface(ctx,id,iface,span)`, `SpanStats()`
- **SPA** (`SensorsSection`, Devices → Scope and sensors), **host** (Box network hiển thị `SpanStats`), **core** (`/core/logs/export` không dùng). Đổi `Sensor` phải sửa `inventory/contract.ts`.

## Modifying: `Engine` (parser, thang tin cậy, bộ lọc) và `MetaItem`
- **inventory** (giá trị "đang dùng"), **logs** (trường metadata): thêm trường vào `MetaItem` = lưu thêm về lưu lượng; test `TestContract_INV3` chặn, phải sửa CONTRACT INV-3 trước. Đổi thang `Conf*` đổi thứ tự hiển thị. Thêm parser = thêm `Fuzz*` (test INV-4 kiểm danh sách).
- **cmd/vedette** (`sensorpassive.go`): `netHost` là chỗ thay bằng module `host`; job `capture` và handler dùng chung một `Service`.

## Modifying: `content/oui` (bảng OUI) và `make oui`
- **inventory**: quan sát `vendor` 0.4 của thiết bị mới. `make oui` ghim nguồn theo commit + SHA-256 (`scripts/oui`, hằng `pinnedCommit`/`pinnedSHA256`), làm sạch tên hãng (bỏ C0/C1, bidi, zero-width, dấu gạch nối mềm, tag), lỗi nếu hai hãng cùng một tiền tố; `TestEveryVendorIsCleanText` canh bảng. Đổi bảng (chạy lại `make oui`) đổi tên hãng hiển thị cho thiết bị mới, không sửa quan sát cũ. THIRD_PARTY_NOTICES ghi nguồn runZero/IEEE.

## Modifying: `deviceBook` (`book.go`, hạn mức MAC mới)
- **inventory** (số thiết bị `discovered` mỗi ngày, bản ghi kiểm toán, sự kiện `asset.discovered`): đổi `maxNewMACsPerMinute/Hour`, `confirmAfter`, `firstSightingTTL`, `maxFirstSightings` đổi tốc độ thiết bị thật xuất hiện và cận "ít hơn 20.000 MAC mới giữa hai khung" (CONTRACT, Giới hạn chống ngập); `maxNewValuesPerHour` đổi tốc độ một thiết bị đổi tên/model. Sổ (thiết bị, khung đầu, hãng còn nợ, hạn mức giá trị) nằm trong `Service`, không trong `Engine`. `Record` của inventory cắt còn 32 dòng mỗi (thiết bị, trường, nguồn) (INV-16): đổi hằng đó đổi độ dài lịch sử giá trị.

## Modifying: gọi `inventory.RecordObservation`
- **inventory**: `source=passive` và thang `confidence` quyết định giá trị "đang dùng". Đổi thang tin cậy làm đổi `summary` và thứ tự hiển thị ở mọi thiết bị.

## Modifying: sự kiện `sensor.span.metadata_batch`
- **logs** (khớp IOC, nhóm B): đổi trường = mất cảnh báo "máy nào liên lạc IP/domain độc hại". Test hợp đồng ở bên phát.

## Modifying: quyền `net_raw`, `pcap` trong MANIFEST và container `sensor`
- **vedette-host/Quadlet** (cấp CAP_NET_RAW): thêm quyền = thay đổi bảo mật cần sửa CONTRACT; bỏ quyền = module không khởi động.

## Disabling this module
- Devices ngừng nhận thiết bị mới thụ động; "Scope and sensors" trống; S-INV-3 chỉ còn nguồn khác.
- `logs` mất metadata SPAN; không ảnh hưởng `sensor-active`, `agent-intake`, `honeypot`.
- Quan sát/thiết bị đã có giữ nguyên.
