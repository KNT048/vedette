# Sensor-active — Change Impact Map

## Modifying: `sensoractive.Service` — `DiscoverRanges(ctx)`, `ScanDevice(ctx, assetID, reason)`, `Tick`, `Enqueue`, `SettingsChanged`
- **core/jobs** (`window-tick` mỗi phút, `prune-probes` mỗi ngày: `cmd/vedette/sensoractive.go`), **inventory** (không gọi trực tiếp: sự kiện `inventory.asset.discovered` và `inventory.settings.changed` đi qua `core/events`, đăng ký ở `cmd/vedette/sensoractive.go`). Đổi điều kiện từ chối hoặc cửa sổ = đổi số gói thực sự rời hộp: sửa CONTRACT + test INV-1…5 (`TestContract_INV*`, `TestWindow`).

## Modifying: dựng argv nmap (`buildNmapArgs`, `ValidateNmapArgs`, `NmapBinary`)
- **core/exec** allowlist: `ValidateNmapArgs` chỉ chấp nhận ba mẫu của `flagsFor` (quét dò, thường, nhẹ) + `-oX -` + 1..64 IPv4 riêng: đổi một mẫu = sửa `flagsFor`, ba biến `shape*` và oracle của `FuzzValidateNmapArgs`, `TestBuildNmapArgs`, `TestValidateNmapArgs` và dòng chữ INV-4/INV-5/FORBID-6; `-sV` chạy script NSE nhóm `version` nên không bao giờ thêm vào mẫu quét nhẹ; đổi dòng lệnh quét nhẹ = đổi tác động lên thiết bị mong manh (D-45, D-84 (7)). **scan** không dùng chung hàm này (Nuclei riêng). Từ SP-2 (xong) ba hàm này (`Flags`, `Build`, `Validate`; tên cũ `flagsFor`, `buildNmapArgs`, `ValidateNmapArgs`) nằm ở gói lá `modules/sensor-active/nmapargv`, dùng chung bởi `core` (kiểm trước khi giao job) và worker trong container `scan` (dựng lại argv + kiểm): đổi một mẫu = đổi cả hai bên trong cùng bản phát hành; thêm `shape` mới = đổi dây, tăng `X-Vedette-Proto` (D-109 (4)).

## Modifying: parser XML (`parseNmapXML`)
- Mọi trường mới đọc từ XML thêm giới hạn và `FuzzParseNmapXML`; chuỗi chỉ qua `text()`/`cpeText()`. Đổi thang `confidence` (`results.go`) đổi giá trị "đang dùng" của thiết bị trong `inventory`.

## Modifying: cổng `sensoractive.Inventory` (`InScope`, `ScanPolicy`, `MarkFirstScan`, `Settings`, `Asset`, `Addresses`, `ProtectedIPs`) và `core/observe`
- **inventory** (adapter `sensorInventory` ở `cmd/vedette/sensoractive.go`, nơi `ProtectedIPs` thêm địa chỉ giao diện của hộp; quét dò thử phạm vi trong bộ nhớ bằng `Settings.InScope` của module, phải khớp `inventory.InScope`: `TestSensorActiveScopeRuleMatchesTheInventory`; chính sách `unknown` → quét nhẹ do `inventory.ScanPolicy`; `ScanPolicy` từ chối `box` và `regular_scan_never`; sự kiện `inventory.asset.updated`/`.deleted` dừng lượt quét thiết bị đang chạy qua `AssetChanged`: thêm lý do hoặc đổi chính sách phải giữ `TestSensorActiveDeviceChangeStopsTheRunningScan`): đổi chữ ký hay ngữ nghĩa `ScanPolicy`/`InScope`/`Settings`/`DeviceRefs`/`Devices` của inventory phải sửa adapter và chạy `TestSensorActive*`. sensor-active là bên ghi duy nhất của `source=nmap` (`snmp` chưa có).

## Modifying: nhật ký `sa_probe` (`Service.Probes`), `sa_sweep` (con trỏ lượt quét dò) và danh mục `scan_probes`
- **core** (`/core/logs/export`: đăng ký `scan_probes` qua `sensoractive.ExportProbes`, D-132), **scan** (trang Probes hiển thị nhật ký của chính `scan`; hai nguồn cùng danh mục, chưa gộp).

## Modifying: seam `Prober`, bộ điều phối và worker (D-113, giao thức sensor vai `active`)
- **core** (`sensoractive.probe()` gọi `Prober` sau khi ghi `sa_probe`; bộ điều phối trong bộ nhớ), **scan** (container, `cmd/vedette-sensor active`), **host** (unit `scan`, volume khoá `vedette-creds-active`, dựng image `scan` tại chỗ: `host-api.md` §18). SP-2 (xong) là refactor thuần (`prober.go`: `Prober`, `NewLocalProber`; `Config.Prober`; `cmd/vedette/sensoractive.go` nối bản cục bộ): đổi thứ tự kiểm phạm vi/ghi `sa_probe` quanh `Prober` phá INV-1/INV-9 (`TestContract_INV*` phải chạy không đổi).
- SP-3 (xong): `dispatch.go` (`Dispatcher`: `Prober` + `Backend` vai `active`), `worker/` (worker trong `scan`), `cmd/vedette-sensor` (lệnh con `active`), `core/sensorlink` (`ResultRejector` tùy chọn của `Backend`; gói `linktest` cho test). Sửa `Dispatcher` đụng: hợp đồng dây (spec §6.4–§6.5), `Service.Health` (qua `nmapHealther`), chuỗi kết quả của `sa_probe`; sửa `worker/` đụng binary `vedette-sensor` và `TestBinaryDependencies` (binary không được link `database/sql`, SQLite, ogen, `core/store`, `core/pki`). `cmd/vedette` chưa dùng chúng tới SP-5.
- Đổi lease (60 s), hạn chờ lấy job (60 s), một job một lúc, hay cách `core` xử lý `status` của worker là đổi bảo đảm "một nmap trên hộp, không nmap mồ côi" (INV-3, POST-3): sửa CONTRACT ("Seam `Prober` và worker") và spec §6.4–§6.5 cùng test.
- Kết quả đi về dạng XML thô (`xml_b64`) và được phân tích trong `core`: chuyển phân tích sang worker (đường nâng cấp bị bỏ ở D-113) thêm một schema dây mà `core` phải kiểm lại.
- Sức khoẻ (`Health`) từ SP-3 lấy từ heartbeat vai `active`; không có heartbeat 90 s → `unavailable`.

## Modifying: job nuclei, hai khe, `Scanner` và `worker/nuclei.go` (D-125, D-133, giao thức bản 2)
- **scan** (người gọi `Scanner.RunNuclei`/`Ready`; adapter ở `cmd/vedette` do SP-5 nối; `nucleiargv`, `nucleiout`, `pack` là gói lá của `scan` mà `core` và worker dùng chung: đổi văn phạm ở đó = đổi cả hai bên cùng bản phát hành), **core/sensorlink** (`Job`, `NucleiJob`, `JobResult.JSONLB64`, `ActiveHeartbeat.Nuclei`, `Backend.Jobs(…, running []string)`: đổi trường dây = tăng `X-Vedette-Proto`), **core/exec** (khoá `HOME` của `Binary.Env`), **host** (unit `scan`: `Tmpfs=/tmp` phải còn, vì `--nuclei-home` mặc định `/tmp/vedette-nuclei`; test `TestScanUnitLeavesNucleiToItsDefaultsOnItsTmpfs`), **release/SP-5** (image `scan-base` đặt `/usr/local/bin/nuclei` ghim phiên bản và sha256, `/usr/share/vedette/nuclei-templates` và `/usr/local/share/vedette/nuclei-pack/index.json`; thiếu cái nào thì heartbeat báo `present=false` hay `pack` rỗng và `scan` không sẵn sàng).
- Đổi trần JSONL (4 MiB) là đổi `nucleiargv.MaxOutput`, `sensorlink.MaxResultJSONL` (`TestNucleiOutputCapsAgree`) và spec §9. Đổi số khe hay thêm loại job thứ ba là đổi `running` trên dây, `pollLocked` và worker `slotOf`. Đổi cách worker kiểm gói (`Lstat` cả cây, băm tệp được chọn) đụng INV-4 của `scan`.
- Worker không đọc `~/.config/nuclei` và không kế thừa môi trường: thêm biến cho nuclei = đổi `core/exec` allowlist (`allowedEnv`) và CONTRACT `scan` INV-4.

## Disabling this module
- Devices không còn OS/dịch vụ/phiên bản mới; thiết bị mong manh mới không được quét lần đầu.
- `inventory`, `scan`, `findings` chạy với dữ liệu cũ; số finding theo phiên bản giảm dần theo thời gian. Bảng `sa_*` giữ nguyên.
