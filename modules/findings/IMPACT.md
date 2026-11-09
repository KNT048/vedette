# Findings — Change Impact Map

## Modifying: `findings.Service.UpsertFromMatch(ctx, assetID, cve, basis)`
- **inventory** (qua sự kiện `inventory.match.changed`), **core/jobs** (khớp lại sau `feeds.vuln.new_kev`). Đổi quy tắc khớp/tạo/độ nghiêm trọng đổi số finding và tin `notify`.

## Modifying: `findings.Service.ConfirmFromScan(ctx, assetID, cve, Evidence)`
- **scan** (kết quả `matched`), **scan-credentialed** (tương lai). Đổi `Evidence` hay điều kiện `confirmed` làm lệch bảng kết quả quét (`finding_id`) và trang finding.

## Modifying: `findings.Service.SetStatus(ctx, id, action, note)`
- **SPA** (`POST /findings/{id}/status`, mã lỗi `note_required`, `already_open`, `bad_action`, `note_too_long`), **notify** (sự kiện `status_changed`), **response**/**reports** (đếm finding mở). Đổi bảng chuyển trạng thái = đổi hành vi nút trên trang finding.

## Modifying: `findings.Findings` (đọc: `List(filter)`, `Get(id)`, `ByAsset(id)`)
- **mitigation** (gói theo finding), **notify** (`vuln` tin + panel `GET /notify/findings/{id}/notices`), **response** (đề xuất cho Critical), **reports**, **ai** (explain), **mcp-server** (`get_finding`), SPA Devices (`device.panels`). Đổi `FindingRow` phải sửa `findings/contract.ts` (nguồn OpenAPI).

## Modifying: sự kiện `findings.finding.created|status_changed`
- **notify** (tin lỗ hổng, `min_severity`), **response** (trigger finding). Đổi tên/trường = người nhận im lặng, không lỗi biên dịch.

## Disabling this module
- Mất trang Findings và panel finding ở Devices; không finding mới; `notify` mất tin lỗ hổng; `scan` không nối được `finding_id`; `response` không có phát hiện Critical để đề xuất; `reports` thiếu mục lỗ hổng; `mitigation` mất đầu vào.
- Finding cũ và lịch sử giữ trong `fnd_*`.
