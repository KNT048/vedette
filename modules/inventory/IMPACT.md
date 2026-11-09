# Inventory — Change Impact Map

## Modifying: `core/observe` (`Observation`, `AssetHint`, `Source`, `Field`, `Sink`, `Software`, `SoftwareSink`) và `inventory.Service.Record`, `RecordObservation`, `ReplaceSoftware`, `UpsertSoftware`
- **sensor-passive** (DHCP/mDNS/SSDP/ARP/LLDP/OUI), **sensor-active** (nmap, SNMP, Recog), **agent-intake** (osquery, Wazuh), **scan** (`source=scan`) ghi qua `observe.Sink`/`observe.SoftwareSink` (họ không import `modules/inventory`); `cmd/vedette` đưa `*inventory.Service` cho họ. Đổi `Observation`/`AssetHint`, các hằng nguồn/trường hay lỗi trả về (`ErrInvalid`, `observe.ErrRejected` với chỉ số dòng bị từ chối: sensor-passive dựa vào nó để bỏ đúng dòng, mọi lỗi khác nó thử lại cả lô) = sửa cả bốn. `confidence` ngoài [0,1] và nguồn `manual` bị từ chối nên cảm biến phải chuẩn hoá; MAC nhận mọi cách viết, IP chỉ IPv4; một lô tối đa 5000, một giao dịch.
- Khoá khớp KEV (`vendorproject|product`, chữ thường) trong `inv_software_kev` là cái `findings` đọc để tạo finding: đổi cách tạo khoá làm lệch "Do you have it?" và finding.
- `UpsertSoftware`/`ReplaceSoftware` thay **cả danh sách của một nguồn**: agent phải gửi danh sách đầy đủ, không gửi phần chênh.

## Modifying: `inventory.Service.ScanPolicy(ctx, assetID)` và `InScope(netip.Addr)`
- **sensor-active** (mọi probe nmap/SNMP), **scan** (chọn mục tiêu, `reason`), **scan-credentialed**. Đây là rào chắn SYS-7 phía LAN: đổi/nới phải sửa CONTRACT + test của cả ba module.

## Modifying: `inventory.Service.Settings()` (dải, cửa sổ, loại mong manh, `scope_confirmed_at`)
- **sensor-active**, **scan** (`scope.commitment`, `can_scan`), **SPA** (`NetworkForm`, Scan → Safety). Ngày 1..7 (Thứ Hai=1) dùng chung với `scan` (D-57 (9)); đổi phải đồng bộ.

## Modifying: `inventory.Service.Device/Devices/Detail/Names` (GetAsset/ListAssets của bản nháp)
- **findings** (`FindingAsset`; D-57 (6)), **notify** (`devices[]` của incident), **honeypot/logs/response** (thiết bị nguồn), **reports**, **ai**, **mcp-server** (`search_assets`).

## Modifying: sự kiện `inventory.asset.deleted`, `inventory.match.changed`, `inventory.asset.discovered`
- **findings** (xoá/tạo finding qua `inventory.asset.deleted`, `inventory.match.changed`), **notify** (incident `unknown_device`), **sensor-active** (quét lần đầu thiết bị mong manh).

## Modifying: các interface phía dùng (`modules/inventory/types.go`) và `inventory.Config`
- `Publisher` (`Publish(ctx, Event{Name, Data}) error`): `cmd/vedette` nối với `core/events.Bus` (WP-04b) bằng `inventory.PublisherFunc`; nil = không ai nghe. Đổi tên/kiểu dữ liệu sự kiện: `findings`, `notify`, `sensor-active` im lặng, không lỗi biên dịch (có test ở bên phát).
- `KEV` (`Products`, `CVEs`): `cmd/vedette` cài `feedsKEV` (đọc `feeds.Store`; bảng rỗng hoặc `feeds` tắt → `EmbeddedKEV`: cặp hãng/sản phẩm nhúng, không CVE; version đổi từ `embedded` sang số hàng khi có dữ liệu thì danh mục dựng lại). `BoxPackages`: `vedette-host` (WP-07). `FindingCounter`: `findings` (đếm theo thiết bị; inventory không đọc `fnd_*`); **chưa nối** (findings chưa có hàm đếm), nên `findings_count` là 0 (deferred). `ModuleGate`: `modreg.Registry` (cho `notify_available`).
- `EnsureBox`/`RefreshBoxPackages`: job `box` trong `cmd/vedette/inventory.go`; `MarkFirstScan`: `sensor-active` sau lần quét nhẹ đầu.
- `Handlers`: nhúng trong `cmd/vedette/handler.go`; vai của 16 route lấy từ bảng route, handler không kiểm lại.

## Modifying: `inventory.Service` đọc/ghi cho module khác (`wiring.go`): `DeviceRefs`, `MatchInput`, `HasDevice`, `DevicesRunning`, `AddManualDevice`+`Settle`, `RematchAll`, `RematchCVE`
- Kiểu trung lập (`DeviceRef`, `MatchDevice`, `ProductQuery`, `DeviceMatch`, `ManualDevice`) không import module nào; `cmd/vedette/wiring.go` đổi sang cổng của từng bên: **feeds** (`feedsInventory`: `you_have`, `matched_assets`, "I have it"), **findings** (`findingsInventory`: `AssetView`, đầu vào bộ khớp), **mitigation** (`mitigationVendors`: `firewall[].detected`, gồm loại `firewall` và `router`). Đổi nghĩa của "yes/maybe", tên hiển thị (`DeviceRef.Display` = phần mềm đầu theo tên, nếu không thì loại) hay khoá khớp sẽ đổi cột "Do you have it?", danh sách finding và nhãn "detected" của hướng dẫn tường lửa.
- `AddManualDevice` giữ sự kiện trong `Service.pending[tx]` tới `Settle`: người gọi **phải** gọi `Settle` sau mỗi giao dịch có gọi nó (feeds làm trong `writeDeclaring`), không thì bộ nhớ giữ lại và sự kiện không bao giờ phát.
- `RematchAll`/`RematchCVE` phát `inventory.match.changed` cho **findings** (`OnMatchChanged` tính lại cả thiết bị mỗi lần: baseline = một lần gọi cho mỗi cặp thiết bị×CVE). Nếu baseline chậm, gộp theo thiết bị ở người nghe.

## Modifying: `content/catalog/{curated,kev-products}.json`
- **SPA** (`catalog.ts` nhập cùng hai file), **Go** (`content/catalog` nhúng). Đổi file = chạy lại `UPDATE_GOLDEN=1 pnpm vitest run src/features/inventory/catalog.golden.test.ts` rồi `go test ./modules/inventory -run Catalog`; `make fixtures` ghi `kev-products.json`.

## Disabling this module
- Devices, Scope and sensors, màn hình agent trống; cột "Do you have it?" của feeds thành `null`.
- `sensor-passive`, `sensor-active`, `agent-intake`, `findings` (kéo theo `mitigation`), `exposure`, `scan`, `honeypot`, `logs`, `response`, `reports` chạy suy giảm hoặc báo thiếu phụ thuộc.
- Không finding mới; không quét nội bộ. Bảng `inv_*` giữ nguyên.
