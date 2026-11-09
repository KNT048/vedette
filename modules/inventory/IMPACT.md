# Inventory — Change Impact Map

## Modifying: `inventory.Service.RecordObservation(ctx, Observation)`
- **sensor-passive** (DHCP/mDNS/SSDP/ARP/LLDP/OUI), **sensor-active** (nmap, SNMP, Recog), **agent-intake** (osquery, Wazuh), **scan** (`source=scan`). Đổi `Observation` hay lỗi trả về = sửa cả bốn; `confidence` ngoài [0,1] bị từ chối nên cảm biến phải chuẩn hoá.

## Modifying: `inventory.Service.UpsertSoftware(ctx, assetID, []Software, source)`
- **agent-intake** (danh sách gói), **sensor-active** (Recog), `POST …/software` (khai tay). Đổi khoá khớp KEV (`vendorproject|product`) làm lệch "Do you have it?" và finding.

## Modifying: `inventory.Service.ScanPolicy(ctx, assetID)` và `InScope(netip.Addr)`
- **sensor-active** (mọi probe nmap/SNMP), **scan** (chọn mục tiêu, `reason`), **scan-credentialed**. Đây là rào chắn SYS-7 phía LAN: đổi/nới phải sửa CONTRACT + test của cả ba module.

## Modifying: `inventory.Service.Settings()` (dải, cửa sổ, loại mong manh, `scope_confirmed_at`)
- **sensor-active**, **scan** (`scope.commitment`, `can_scan`), **SPA** (`NetworkForm`, Scan → Safety). Đổi định dạng ngày (1..7) phải đồng bộ với `scan` (0..6).

## Modifying: `inventory.Service.GetAsset/ListAssets/Names`
- **mitigation** (`FindingAsset`), **notify** (`devices[]` của incident), **honeypot/logs/response** (thiết bị nguồn), **reports**, **ai**, **mcp-server** (`search_assets`).

## Modifying: sự kiện `inventory.asset.deleted`, `inventory.match.changed`, `inventory.asset.discovered`
- **mitigation** (xoá/tạo finding), **notify** (incident `unknown_device`), **sensor-active** (quét lần đầu thiết bị mong manh).

## Disabling this module
- Devices, Scope and sensors, màn hình agent trống; cột "Do you have it?" của feeds thành `null`.
- `sensor-passive`, `sensor-active`, `agent-intake`, `mitigation`, `exposure`, `scan`, `honeypot`, `logs`, `response`, `reports` chạy suy giảm hoặc báo thiếu phụ thuộc.
- Không finding mới; không quét nội bộ. Bảng `inv_*` giữ nguyên.
