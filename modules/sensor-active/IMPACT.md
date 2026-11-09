# Sensor-active — Change Impact Map

## Modifying: `sensoractive.Service` — `DiscoverRanges(ctx)`, `ScanDevice(ctx, assetID, reason)`, `Tick`, `Enqueue`, `SettingsChanged`
- **core/jobs** (`window-tick` mỗi phút, `prune-probes` mỗi ngày: `cmd/vedette/sensoractive.go`), **inventory** (không gọi trực tiếp: sự kiện `inventory.asset.discovered` và `inventory.settings.changed` đi qua `core/events`, đăng ký ở `cmd/vedette/sensoractive.go`). Đổi điều kiện từ chối hoặc cửa sổ = đổi số gói thực sự rời hộp: sửa CONTRACT + test INV-1…5 (`TestContract_INV*`, `TestWindow`).

## Modifying: dựng argv nmap (`buildNmapArgs`, `ValidateNmapArgs`, `NmapBinary`)
- **core/exec** allowlist: mọi cờ mới phải thêm vào `ValidateNmapArgs` (ngữ pháp: `--privileged`, cờ, `-oX -`, 1..64 IPv4), vào oracle của `FuzzValidateNmapArgs` và vào `TestBuildNmapArgs`; đổi dòng lệnh quét nhẹ = đổi tác động lên thiết bị mong manh (D-45, D-84 (7)). **scan** không dùng chung hàm này (Nuclei riêng).

## Modifying: parser XML (`parseNmapXML`)
- Mọi trường mới đọc từ XML thêm giới hạn và `FuzzParseNmapXML`; chuỗi chỉ qua `text()`/`cpeText()`. Đổi thang `confidence` (`results.go`) đổi giá trị "đang dùng" của thiết bị trong `inventory`.

## Modifying: cổng `sensoractive.Inventory` (`InScope`, `ScanPolicy`, `MarkFirstScan`, `Settings`, `Asset`, `Addresses`) và `core/observe`
- **inventory** (adapter `sensorInventory` ở `cmd/vedette/sensoractive.go`): đổi chữ ký hay ngữ nghĩa `ScanPolicy`/`InScope`/`Settings`/`DeviceRefs`/`Devices` của inventory phải sửa adapter và chạy `TestSensorActive*`. sensor-active là bên ghi duy nhất của `source=nmap` (`snmp` chưa có).

## Modifying: nhật ký `sa_probe` (`Service.Probes`) và danh mục `scan_probes`
- **core** (`/core/logs/export`; chưa đăng ký, deferred), **scan** (trang Probes hiển thị nhật ký của chính `scan`; hai nguồn cùng danh mục, chưa gộp).

## Disabling this module
- Devices không còn OS/dịch vụ/phiên bản mới; thiết bị mong manh mới không được quét lần đầu.
- `inventory`, `scan`, `findings` chạy với dữ liệu cũ; số finding theo phiên bản giảm dần theo thời gian. Bảng `sa_*` giữ nguyên.
