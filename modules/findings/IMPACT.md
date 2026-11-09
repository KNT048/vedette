# Findings — Change Impact Map

## Modifying: thư viện thuần `modules/findings` (không DB; service WP-21 bọc ngoài)
- `MatchAsset(Asset, []Vuln, have, now) MatchResult{New, Existing}` — bộ khớp. Gọi từ service khi nhận `inventory.match.changed`/`feeds.vuln.updated`. Đổi quy tắc ⇒ đổi số finding và tin `notify`; test `Contract_INV4/5/6`.
- `NewFinding`, `Finding.ApplyMatch`, `Finding.Apply(action, note, user, now)`, `Finding.ConfirmFromScan(evidence, now)`, `ScanClear`, `Finding.Validate` — vòng đời. Lỗi `*APIError` (`ErrBadAction`, `ErrNoteTooLong`, `ErrNoteRequired`, `ErrAlreadyOpen`, `ErrNotFound`) ánh xạ 1:1 mã lỗi API; đổi mã = đổi `findings/contract.ts` và mock.
- `ParseCPE`, `CPE.Matches|SameProduct`, `CompareVersions`, `VersionRange.Contains` — dùng bởi bộ khớp; `feeds` phải đưa khoảng phiên bản NVD vào `Vuln.Affected` (chuỗi CPE 2.3 + `VersionRange`), `inventory` đưa `Software.KevKeys` (khoá `vendorproject|product` chữ thường) và tuỳ chọn `Software.CPE`.
- `KevKey`/`NormalizeKevKey` phải khớp cách `feeds` chuẩn hoá khoá.

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
