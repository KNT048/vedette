# Ids — Change Impact Map

> Package `modules/ids`. Cổng vào: `Inventory`, `Findings`, `Incidents`, `Publisher`, `Modules`; nối ở `cmd/vedette/ids.go`.

## Modifying: `Parse` / `profileKinds` / định dạng của một hãng
- Thêm hay đổi định dạng: thêm dòng vào `testdata/ips_lines.json` (địa chỉ tài liệu, example.com) cho cả dòng là sự kiện và dòng không phải; `TestCountIPSLinesPerProfile` in số theo profile. Loại nguồn mới phải là một `KIND_IDS` của module logs (`content/logs/kinds.json`).
- `NativeIPS` quyết watcher `ips_events` của tổng quan (`cmd/vedette/detection.go`) và `IPS_KINDS` của mock (`web/src/features/detection/mocks.ts`): đổi cùng lượt.

## Modifying: `Attacked(ctx, since)` — cổng của findings
- Người đọc duy nhất: bộ chuyển `idsFindings` ở `cmd/vedette/ids.go` (`recentlyAttacked`, cửa sổ `AttackWindow`), nó ánh xạ trạng thái của findings sang `under_attack`/`exploited` cho `Findings.Linked`; module findings không gọi `Attacked`. Đổi nhóm hàng (CVE, địa chỉ đích) hay ý nghĩa `since` → trạng thái finding trong cảnh báo và mức critical sai mà không lỗi.

## Modifying: sự kiện `ids.alert.detected` (`AlertEvent`)
- **notify** (`modules/notify/events.go` `intrusionEvent`): đọc qua JSON `source, target, title, what, action, severity, link, at, devices`; `link` phải bắt đầu `/detection/`. Đổi `IncidentKey` → sự cố cũ không còn được đếm tiếp và `incident` của cảnh báo đọc (notify `IncidentOf`) mất liên kết.

## Modifying: `Findings.Linked` (cổng gộp: thiết bị → CVE)
- Cài ở `idsFindings` (`cmd/vedette/ids.go`), đọc `findings.Service.List` của từng thiết bị.
- Gọi một lần mỗi trang, mỗi `Summarize` và mỗi flush (không theo từng thiết bị); bộ chuyển `idsFindings` đọc `Attacked` một lần mỗi lời gọi.
- Devices a person ignored are left out (one `inventory.IgnoredIDs` read per call): their findings never make an alert critical or count as affected. `TestWiringIPSEventAtAnIgnoredDeviceIsNotCriticalOrAffected`.

## Modifying: `Inventory.DevicesAt`/`Names` (cổng thiết bị)
- `idsInventory` ghép `logsInventory` (cmd/vedette/logs.go: IP trong danh sách và địa chỉ đọc SNMP từ sensor-active `ReadAddresses`, hai thiết bị cùng địa chỉ → không thiết bị) và `notifyDevices.DeviceStates` cho tên. Đổi quy tắc ghép địa chỉ ở logs → thiết bị của cảnh báo đổi theo.

## Modifying: `List`/`Get`/`Summarize`
- **web/features/detection** (`contract.ts` là hợp đồng; `into` của handler từ chối phản hồi lệch schema). `Summarize` → tổng quan (`alerts.total/affected`, watcher `ips_events`) ở `cmd/vedette/detection.go`, cùng `NativeIPS`.
- Route `/detection/alerts*` gắn với module ở `core/server/modules.go` và `web/src/lib/apiModules.ts` (404 khi module tắt); `cmd/vedette/handler.go` nhúng `IDSHandlers`, `cmd/vedette/modules.go` đăng ký migrations + jobs, `cmd/vedette/devicelifecycle.go` đăng ký `DeviceMerged`.

## Modifying: `logs.Config.Received` (module logs)
- `cmd/vedette/ids.go` `idsReceived` nối nó vào `Offer` (chỉ các dòng của loại nguồn `Reads`).
- Gọi sau commit của lô với dòng đã làm sạch; nếu logs đổi thời điểm gọi hay nội dung `Text` (ví dụ cắt khác), INV-1 của ids (dòng bị cắt không đọc) phải đổi theo.

## Modifying: `Attacked` / `ReadAttacked` (layer 1 of a finding's urgency)
- findings' urgency pass reads `ReadAttacked(since now − 14 days)` while the module is on; a finding becomes "under attack here" for an
  attack aimed at its device or at any address while the device is affected. The selfcheck reads the same function as of the last pass.

