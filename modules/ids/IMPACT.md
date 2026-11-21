# Ids — Change Impact Map

> Package `modules/ids`. Cổng vào: `Inventory`, `Findings`, `Incidents`, `Publisher`, `Modules`; nối ở `cmd/vedette/ids.go`.

## Modifying: `Parse` / `profileKinds` / định dạng của một hãng
- Thêm hay đổi định dạng: thêm dòng vào `testdata/ips_lines.json` (địa chỉ tài liệu, example.com) cho cả dòng là sự kiện và dòng không phải; `TestCountIPSLinesPerProfile` in số theo profile. Loại nguồn mới phải là một `KIND_IDS` của module logs (`content/logs/kinds.json`).
- `NativeIPS` quyết watcher `ips_events` của tổng quan (`cmd/vedette/detection.go`) và `IPS_KINDS` của mock (`web/src/features/detection/mocks.ts`): đổi cùng lượt.

## Modifying: `Attacked(ctx, since)` — cổng của findings
- Người đọc: findings (lớp 1 của `Urgency`, mục "under attack"), và tới khi findings có lớp đó, bộ chuyển `idsFindings` ở `cmd/vedette/ids.go` (ánh xạ trạng thái cũ của findings sang từ vựng mới). Đổi nhóm hàng (CVE, địa chỉ đích) hay ý nghĩa `since` → trạng thái finding sai mà không lỗi.

## Modifying: sự kiện `ids.alert.detected` (`AlertEvent`)
- **notify** (`modules/notify/events.go` `intrusionEvent`): đọc qua JSON `source, target, title, what, action, severity, link, at, devices`; `link` phải bắt đầu `/detection/`. Đổi `IncidentKey` → sự cố cũ không còn được đếm tiếp và `incident` của cảnh báo đọc (notify `IncidentOf`) mất liên kết.

## Modifying: `Findings.Linked` (cổng gộp: thiết bị → CVE)
- Gọi một lần mỗi trang, mỗi `Summarize` và mỗi flush (không theo từng thiết bị); bộ chuyển `idsFindings` đọc `Attacked` một lần mỗi lời gọi.

## Modifying: `List`/`Get`/`Summarize`
- **web/features/detection** (`contract.ts` là hợp đồng; `into` của handler từ chối phản hồi lệch schema). `Summarize` → tổng quan (`alerts.total/affected`, watcher `ips_events`).

## Modifying: `logs.Config.Received` (module logs)
- Gọi sau commit của lô với dòng đã làm sạch; nếu logs đổi thời điểm gọi hay nội dung `Text` (ví dụ cắt khác), INV-1 của ids (dòng bị cắt không đọc) phải đổi theo.

## Modifying: `Attacked` / `ReadAttacked` (layer 1 of a finding's urgency)
- findings' urgency pass reads `ReadAttacked(since now − 14 days)` while the module is on; a finding becomes "under attack here" for an
  attack aimed at its device or at any address while the device is affected. The selfcheck reads the same function as of the last pass.

