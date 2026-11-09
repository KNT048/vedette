# Sensor-active — Change Impact Map

## Modifying: `sensoractive.Service` — `DiscoverRanges(ctx)`, `ScanDevice(ctx, assetID, reason)`
- **core/jobs** (lịch trong cửa sổ), **inventory** (gọi `ScanDevice` khi thiết bị mới là mong manh, qua sự kiện). Đổi điều kiện từ chối = đổi số gói thực sự rời hộp: sửa CONTRACT + test INV-1…5.

## Modifying: dựng argv nmap (`buildNmapArgs`)
- **core/exec** allowlist; mọi cờ mới phải thêm vào allowlist, test fuzz tham số. **scan** không dùng chung hàm này (Nuclei riêng).

## Modifying: gọi `inventory.InScope`, `ScanPolicy`, `RecordObservation`, `UpsertSoftware`
- **inventory**: sensor-active là bên gọi duy nhất của `source=nmap|snmp`. Đổi thang `confidence` đổi giá trị "đang dùng" của thiết bị.

## Modifying: nhật ký `sa_probe` và danh mục `scan_probes`
- **core** (`/core/logs/export`), **scan** (trang Probes hiển thị nhật ký của chính `scan`; hai nguồn cùng danh mục, chưa gộp).

## Disabling this module
- Devices không còn OS/dịch vụ/phiên bản mới; thiết bị mong manh mới không được quét lần đầu.
- `inventory`, `scan`, `mitigation` chạy với dữ liệu cũ; số finding theo phiên bản giảm dần theo thời gian. Bảng `sa_*` giữ nguyên.
