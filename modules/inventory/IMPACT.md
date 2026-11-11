# Inventory — Change Impact Map

## Modifying: `core/observe` (`Observation`, `AssetHint`, `Source`, `Field`, `Sink`, `Software`, `SoftwareSink`) và `inventory.Service.Record`, `RecordObservation`, `ReplaceSoftware`, `UpsertSoftware`
- **sensor-passive** (DHCP/mDNS/SSDP/ARP/LLDP/OUI), **sensor-active** (nmap, SNMP, Recog), **agent-intake** (osquery, Wazuh), **scan** (`source=scan`) ghi qua `observe.Sink`/`observe.SoftwareSink` (họ không import `modules/inventory`); `cmd/vedette` đưa `*inventory.Service` cho họ. Đổi `Observation`/`AssetHint`, các hằng nguồn/trường hay lỗi trả về (`ErrInvalid`, `observe.ErrRejected` với chỉ số dòng bị từ chối: sensor-passive dựa vào nó để bỏ đúng dòng, mọi lỗi khác nó thử lại cả lô) = sửa cả bốn. `confidence` ngoài [0,1] và nguồn `manual` bị từ chối nên cảm biến phải chuẩn hoá; MAC nhận mọi cách viết, IP chỉ IPv4; một lô tối đa 5000, một giao dịch.
- `Record` xoá quan sát cũ, chỉ giữ 32 dòng mới nhất mỗi (thiết bị, trường, nguồn) (INV-16, `pruneObs`): lịch sử giá trị trong chi tiết thiết bị bị cắt theo đó; truy vấn cắt dựa vào prefix của `inv_observation_uq`, đổi chỉ mục này phải kiểm lại.
- Khoá khớp KEV (`vendorproject|product`, chữ thường) trong `inv_software_kev` là cái `findings` đọc để tạo finding: đổi cách tạo khoá làm lệch "Do you have it?" và finding.
- `UpsertSoftware`/`ReplaceSoftware` thay **cả danh sách của một nguồn**: agent phải gửi danh sách đầy đủ, không gửi phần chênh.

## Modifying: `inventory.Config.BoxOwnedIPs` và `Record`/`ReplaceSoftware`/`ProtectedIPs`
- **`Config.BoxOwnedMACs`** (D-296, WP-31 M7): `cmd/vedette/inventory.go` nối tới `hostMACs.Get` (vedette-host `state/net`: card + macvlan decoy), dùng chung với `response` (`BoxMACs`). Danh sách MAC thiếu macvlan của một decoy → khung tin của chính decoy thành thiết bị và decoy tự rơi vào `conflict`; LAB: MAC macvlan host báo phải trùng MAC sensor thấy trên dây.
- **honeypot** (`Service.DecoyIPs` qua `cmd/vedette/inventory.go`): danh sách rỗng/sai → trả lời ARP của chính bẫy thành thiết bị ma và bẫy tự rơi vào `conflict`, hoặc IP bẫy bị sweep thăm dò. **sensor-passive/sensor-active/agent-intake**: quan sát có IP của hộp bị bỏ im lặng (đếm `BoxOwnedSkipped`), nên một thiết bị thật chiếm đúng IP bẫy chỉ lộ ra qua ARP probe của host, không qua kho.

## Modifying: `inventory.Service.ScanPolicy(ctx, assetID)`, `ProtectedIPs(ctx)` và `InScope(netip.Addr)`
- **sensor-active** (mọi probe nmap/SNMP; `ProtectedIPs` là danh sách địa chỉ quét dò bỏ qua, đi qua adapter `sensorInventory` ở `cmd/vedette/sensoractive.go`; sensor-active còn kiểm phạm vi trong bộ nhớ theo `Settings` bằng quy tắc riêng, `TestSensorActiveScopeRuleMatchesTheInventory` giữ hai nơi khớp nhau), **scan** (chọn mục tiêu, `reason`), **scan-credentialed**. Đây là rào chắn SYS-7 phía LAN: đổi/nới phải sửa CONTRACT + test của cả ba module. Lý do `scanning_off`/`scope_not_confirmed` được `sensor-active` coi là trạng thái của hộp (thiết bị ở lại hàng đợi), các lý do khác là của thiết bị (rời hàng đợi); `first_gentle_scan` chỉ cho quét nhẹ: `scan` phải coi nó là từ chối.

## Modifying: `inventory.Service.VulnScanPolicy(ctx, assetID, explicit)` (D-126)
- **scan** (Emily; chọn mục tiêu của quét lỗ hổng theo lịch, quét lại KEV và "Scan now"; nối ở `cmd/vedette` khi module `scan` vào; `explicit` chỉ true cho thiết bị người dùng chọn tay, và người gọi ghi `core_audit` kèm tên người). Dùng chung `ScanDecision`, các hằng `Reason*` và `InScope` với `ScanPolicy`: đổi các thứ đó là đổi cả hai. Đổi/nới luật này (nhất là `regular_scan=never`, thiết bị mong manh/khai tay) là rào chắn SYS-7: sửa CONTRACT + test của `scan`. `sensor-active` không dùng hàm này. `ScanDecision` có thêm `Careful` và `IP` (chỉ `VulnScanPolicy` đặt; thêm trường, không đổi nghĩa trường cũ nên `sensor-active` không bị ảnh hưởng); adapter `cmd/vedette/scan.go` lấy `Careful`/`IP` từ đó, không đọc lại thiết bị. `VulnScanPolicies` là đường đọc theo lô (chưa có người gọi: `scan.Inventory` chưa có hàm lô).

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

## Modifying: `inventory.Service` đọc/ghi cho module khác (`wiring.go`): `DeviceRefs`, `MatchInput`, `HasDevice`, `DevicesOfKind`, `AssetIDs`, `DevicesRunning`, `AddManualDevice`+`Settle`, `RematchAll`, `RematchCVE`
- (D-177, D-178) `KindDevice.Approved/KindSource/TrustedKind`: `cmd/vedette` `responseDirectory.DevicesOfKind` bỏ thiết bị không `TrustedKind()` (đổi quy tắc tin = đổi INV-20 và danh sách không-bao-giờ-đụng của response); `logsInventory` dùng `DevicesOfKind` mà không lọc (chỉ tra tên). `PatchDevice` ghi quan sát `manual` cả khi loại không đổi nhưng nguồn khác `manual`. `AddressInUse` (`inventoryHasAddress` của trang mạng hộp), `AddressMap` và `KnownMACs` (`sensorInventory` của sensor-active, `cfg.KnownMACs` của sensor-passive), `AllDevices` (`honeypotInventory.Devices`) và `BoxName` (`honeypotInventory.Box`) thay `Devices` cho mọi câu hỏi "đã dùng/đã biết". `AllDevices` nạp cả phần mềm và dịch vụ của mọi thiết bị mỗi lần honeypot `load`: tốt tới khoảng 1.000 thiết bị, 10k–50k tốn khoảng 100–300 ms mỗi lần; nâng cấp = một đọc hẹp (id, IP, hostname, loại, approved, is_box, OS, cổng).
- `AssetIDs(ctx)` đọc id của **mọi** thiết bị (không lọc loại, không giới hạn): **findings** (`findingsInventory.AssetIDs` ở `cmd/vedette/wiring.go`) dùng cho job đối soát D-144 (INV-19). Đổi nó (lọc, giới hạn, nuốt lỗi) → đối soát xoá phát hiện của thiết bị còn tồn tại.
- `DevicesOfKind(ctx, kinds)` (kiểu `KindDevice`: id, hostname, IP, MAC, loại) đọc **mọi** thiết bị của các loại, **không giới hạn dòng** (khác `Devices` cắt ở `MaxListed`, mới nhất trước): **response** (`responseDirectory` ở `cmd/vedette/response.go`) dùng nó cho danh sách không-bao-giờ-đụng (router/firewall); thêm giới hạn hay đổi thứ tự im lặng làm gateway cũ nhất rơi khỏi danh sách. Lỗi đọc phải trả lỗi, không trả danh sách ngắn.
- Kiểu trung lập (`DeviceRef`, `MatchDevice`, `ProductQuery`, `DeviceMatch`, `ManualDevice`) không import module nào; `cmd/vedette/wiring.go` đổi sang cổng của từng bên: **feeds** (`feedsInventory`: `you_have`, `matched_assets`, "I have it"), **findings** (`findingsInventory`: `AssetView`, đầu vào bộ khớp), **mitigation** (`mitigationVendors`: `firewall[].detected`, gồm loại `firewall` và `router`). Đổi nghĩa của "yes/maybe", tên hiển thị (`DeviceRef.Display` = phần mềm đầu theo tên, nếu không thì loại) hay khoá khớp sẽ đổi cột "Do you have it?", danh sách finding và nhãn "detected" của hướng dẫn tường lửa.
- `AddManualDevice` giữ sự kiện trong `Service.pending[tx]` tới `Settle`: người gọi **phải** gọi `Settle` sau mỗi giao dịch có gọi nó (feeds làm trong `writeDeclaring`), không thì bộ nhớ giữ lại và sự kiện không bao giờ phát.
- `RematchAll`/`RematchCVE` phát `inventory.match.changed` cho **findings** (`OnMatchChanged` tính lại cả thiết bị mỗi lần: baseline = một lần gọi cho mỗi cặp thiết bị×CVE). Nếu baseline chậm, gộp theo thiết bị ở người nghe.

## Modifying: `content/catalog/{curated,kev-products}.json`
- **SPA** (`catalog.ts` nhập cùng hai file), **Go** (`content/catalog` nhúng). Đổi file = chạy lại `UPDATE_GOLDEN=1 pnpm vitest run src/features/inventory/catalog.golden.test.ts` rồi `go test ./modules/inventory -run Catalog`; `make fixtures` ghi `kev-products.json`.

## Disabling this module
- Devices, Scope and sensors, màn hình agent trống; cột "Do you have it?" của feeds thành `null`.
- `sensor-passive`, `sensor-active`, `agent-intake`, `findings` (kéo theo `mitigation`), `exposure`, `scan`, `honeypot`, `logs`, `response`, `reports` chạy suy giảm hoặc báo thiếu phụ thuộc.
- Không finding mới; không quét nội bộ. Bảng `inv_*` giữ nguyên.
