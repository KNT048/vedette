# Sensor-active — Change Impact Map

## Modifying: `sensoractive.Service` — `DiscoverRanges(ctx)`, `ScanDevice(ctx, assetID, reason)`, `Tick`, `Enqueue`, `SettingsChanged`
- **core/jobs** (`window-tick` mỗi phút, `prune-probes` mỗi ngày: `cmd/vedette/sensoractive.go`), **inventory** (không gọi trực tiếp: sự kiện `inventory.asset.discovered` và `inventory.settings.changed` đi qua `core/events`, đăng ký ở `cmd/vedette/sensoractive.go`). Đổi điều kiện từ chối hoặc cửa sổ = đổi số gói thực sự rời hộp: sửa CONTRACT + test INV-1…5 (`TestContract_INV*`, `TestWindow`).

## Modifying: dựng argv nmap (`buildNmapArgs`, `ValidateNmapArgs`, `NmapBinary`)
- **core/exec** allowlist: `ValidateNmapArgs` chỉ chấp nhận ba mẫu của `flagsFor` (quét dò, thường, nhẹ) + `-oX -` + 1..64 IPv4 riêng: đổi một mẫu = sửa `flagsFor`, ba biến `shape*` và oracle của `FuzzValidateNmapArgs`, `TestBuildNmapArgs`, `TestValidateNmapArgs` và dòng chữ INV-4/INV-5/FORBID-6; `-sV` chạy script NSE nhóm `version` nên không bao giờ thêm vào mẫu quét nhẹ; đổi dòng lệnh quét nhẹ = đổi tác động lên thiết bị mong manh (D-45, D-84 (7)). **scan** không dùng chung hàm này (Nuclei riêng).

## Modifying: parser XML (`parseNmapXML`)
- Mọi trường mới đọc từ XML thêm giới hạn và `FuzzParseNmapXML`; chuỗi chỉ qua `text()`/`cpeText()`. Đổi thang `confidence` (`results.go`) đổi giá trị "đang dùng" của thiết bị trong `inventory`.

## Modifying: cổng `sensoractive.Inventory` (`InScope`, `ScanPolicy`, `MarkFirstScan`, `Settings`, `Asset`, `Addresses`, `ProtectedIPs`) và `core/observe`
- **inventory** (adapter `sensorInventory` ở `cmd/vedette/sensoractive.go`, nơi `ProtectedIPs` thêm địa chỉ giao diện của hộp; quét dò thử phạm vi trong bộ nhớ bằng `Settings.InScope` của module, phải khớp `inventory.InScope`: `TestSensorActiveScopeRuleMatchesTheInventory`; chính sách `unknown` → quét nhẹ do `inventory.ScanPolicy`; `ScanPolicy` từ chối `box` và `regular_scan_never`; sự kiện `inventory.asset.updated`/`.deleted` dừng lượt quét thiết bị đang chạy qua `AssetChanged`: thêm lý do hoặc đổi chính sách phải giữ `TestSensorActiveDeviceChangeStopsTheRunningScan`): đổi chữ ký hay ngữ nghĩa `ScanPolicy`/`InScope`/`Settings`/`DeviceRefs`/`Devices` của inventory phải sửa adapter và chạy `TestSensorActive*`. sensor-active là bên ghi duy nhất của `source=nmap` (`snmp` chưa có).

## Modifying: nhật ký `sa_probe` (`Service.Probes`), `sa_sweep` (con trỏ lượt quét dò) và danh mục `scan_probes`
- **core** (`/core/logs/export`; chưa đăng ký, deferred), **scan** (trang Probes hiển thị nhật ký của chính `scan`; hai nguồn cùng danh mục, chưa gộp).

## Disabling this module
- Devices không còn OS/dịch vụ/phiên bản mới; thiết bị mong manh mới không được quét lần đầu.
- `inventory`, `scan`, `findings` chạy với dữ liệu cũ; số finding theo phiên bản giảm dần theo thời gian. Bảng `sa_*` giữ nguyên.
