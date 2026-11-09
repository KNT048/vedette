# Mitigation — Change Impact Map

## Modifying: `mitigation.Service.UpsertFromMatch(ctx, assetID, cve, basis)`
- **inventory** (qua sự kiện `inventory.match.changed`), **core/jobs** (khớp lại sau `feeds.vuln.new_kev`). Đổi quy tắc tạo/độ nghiêm trọng đổi số finding và tin `notify`.

## Modifying: `mitigation.Service.ConfirmFromScan(ctx, assetID, cve, Evidence)`
- **scan** (kết quả `matched`), **scan-credentialed** (tương lai). Đổi `Evidence` hay điều kiện `confirmed` làm lệch bảng kết quả quét (`finding_id`) và trang finding.

## Modifying: `mitigation.Findings` (đọc: `List(filter)`, `Get(id)`, `ByAsset(id)`)
- **notify** (`vuln` tin + panel `GET /notify/findings/{id}/notices`), **response** (đề xuất cho Critical), **reports**, **ai** (explain), **mcp-server** (`get_finding`), SPA Devices (`device.panels`). Đổi `FindingRow` phải sửa `findings/contract.ts` (nguồn OpenAPI).

## Modifying: nạp gói (`packs.Load`) và định dạng `MitigationPack`
- **tooling `vedette-author`** (S-MIT-4) và builder phát hành: schema chung; đổi trường = đổi cả công cụ lẫn bộ nạp. **core/updates**: gói đi cùng bản cập nhật ký.

## Modifying: gọi `ai.Run(skill, input)` (`explain`, `mitigation-config`)
- **ai** (nhóm B): đổi tên skill/schema đầu ra làm `ai_available` sai và kết quả mất nhãn.

## Disabling this module
- Mất trang Findings và panel "What to do" ở Devices; không finding mới.
- `notify` mất toàn bộ tin lỗ hổng; `scan` không nối được finding; `response` không có phát hiện Critical để đề xuất; `reports` thiếu mục lỗ hổng.
- Finding cũ, lịch sử, kết quả AI giữ trong `mit_*`.
