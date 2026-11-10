# Findings — Change Impact Map

## Modifying: thư viện thuần `modules/findings` (không DB; service WP-21 bọc ngoài)
- `MatchAsset(Asset, []Vuln, have, now) MatchResult{New, Existing}` — bộ khớp. Gọi từ service khi nhận `inventory.match.changed`/`feeds.vuln.updated`. Đổi quy tắc ⇒ đổi số finding và tin `notify`; test `Contract_INV4/5/6`.
- `NewFinding`, `Finding.ApplyMatch`, `Finding.Apply(action, note, user, now)`, `Finding.ConfirmFromScan(evidence, now)`, `ScanClear`, `Finding.Validate` — vòng đời. Lỗi `*APIError` (`ErrBadAction`, `ErrNoteTooLong`, `ErrNoteRequired`, `ErrAlreadyOpen`, `ErrNotFound`) ánh xạ 1:1 mã lỗi API; đổi mã = đổi `findings/contract.ts` và mock.
- `ParseCPE`, `CPE.Matches|SameProduct`, `CompareVersions`, `VersionRange.Contains` — dùng bởi bộ khớp; `feeds` phải đưa khoảng phiên bản NVD vào `Vuln.Affected` (chuỗi CPE 2.3 + `VersionRange`), `inventory` đưa `Software.KevKeys` (khoá `vendorproject|product` chữ thường) và tuỳ chọn `Software.CPE`.
- `KevKey`/`NormalizeKevKey` phải khớp cách `feeds` chuẩn hoá khoá. Hãng/sản phẩm chứa `|` không bao giờ khớp.
- Quy tắc "không đoán": phiên bản trống/không đọc được/toàn số 0, tail build ở ranh giới khoảng, cấu hình ghim `update`/`edition`/`target_sw`… mà phần mềm không mang, và mục `Affected` không đọc được đều cho `Unknown` ⇒ `basis=product`, không bao giờ làm mất khớp KEV. Chỉ `No` chắc chắn mới bỏ finding. `feeds` đưa CPE sai/thiếu ⇒ finding `product`, không mất.
- `ConfirmFromScan` trên `false_positive`/`not_relevant`: lần đầu một `template` khớp thì ghi bằng chứng (basis scan, history `rescanned`) và `Notify=true`; cùng `template` lần sau không đổi gì, `Notify=false` (service không cần tự chống trùng). Trường bằng chứng quá 4096 byte bị cắt, có dấu `...[truncated]`.
- Ghi chú trạng thái đo như GUI: `trim` của JavaScript và độ dài UTF-16 (ngưỡng 3 và 500).

## Modifying: `findings.Service.UpsertFromMatch(ctx, Asset, []Vuln)` và `OnMatchChanged(ctx, assetID)`
- **inventory** (sự kiện `inventory.match.changed`; phải cài `findings.Inventory{Assets, MatchInput}`), **feeds** (phải cài `findings.Feeds{KevInfo, Vulns}`; `cmd/vedette/wiring.go` cài từ `feeds.Store.KevVulns/KevVulnsByCVE`, chỉ hàng `cisa-kev`, chưa có khoảng bị ảnh hưởng nên chỉ `basis=product`; `findings.Inventory` từ `inventory.DeviceRefs/MatchInput`), **core/jobs** (khớp lại sau `feeds.vuln.new_kev`). Interface do `findings` định nghĩa, `cmd/vedette` nối cài đặt thật. Đổi quy tắc khớp/tạo/độ nghiêm trọng đổi số finding và tin `notify`.

## Modifying: `findings.Service.Reconcile(ctx)` và `findings.Jobs(svc)` (job `reconcile`, mỗi giờ)
- **inventory**: phải cài `findings.Inventory.AssetIDs` (mọi id thiết bị, không giới hạn dòng, lỗi đọc là lỗi, không bao giờ trả danh sách ngắn: reconcile coi finding của thiết bị vắng là mồ côi và xoá sau khi hỏi lại `Assets`). Sửa `DevicesOfKind` hay `Kinds` (loại thiết bị mới) thì sửa adapter ở `cmd/vedette/wiring.go`, nếu không thiết bị loại mới không được khớp lại và finding của nó bị coi là mồ côi chỉ khi `Assets` cũng không thấy.
- **cmd/vedette**: `wiredModules` có `Jobs: findingsJobs` cho `findings`; job chạy khi module bật rồi mỗi `ReconcileEvery`. Tắt module = job dừng, dữ liệu giữ.
- **notify**: finding do reconcile tạo mới phát `findings.finding.created` như mọi finding mới; reconcile không mang dấu baseline D-78 (`notify.WithBaseline`), nên một lượt đường cơ sở bị mất sự kiện mà reconcile bù sẽ có thể gửi tin. Chấp nhận (hiếm), xem PR.
- **feeds**: `Feeds.Vulns` rỗng (chưa kéo KEV) thì không khớp gì, chỉ chạy bước dọn mồ côi.

## Modifying: `findings.Service.ConfirmFromScan(ctx, assetID, cve, Evidence)`
- **scan** (kết quả `matched`), **scan-credentialed** (tương lai). Đổi `Evidence` hay điều kiện `confirmed` làm lệch bảng kết quả quét (`finding_id`) và trang finding.

## Modifying: `findings.Service.OnAssetDeleted(ctx, assetID)`
- **inventory** (sự kiện `inventory.asset.deleted`). Xoá `fnd_finding` của thiết bị; `fnd_finding_history`, `mit_applied`, `mit_ai_output` đi theo qua FK cascade (mitigation phụ thuộc điều này). Đổi thành xoá mềm = sửa cả `mitigation`.

## Modifying: `findings.FindingHandlers.SetGuidance(Guidance)` và `Guide`/`Row`/`Detail`
- **mitigation** (đăng ký nhà cung cấp, dựng `Guide`; gọi `Detail` để trả lời `applied|ai`). Đổi hình `Guide` = đổi `FindingDetail` trong `contract.ts`; `findings.Into` giải mã vào kiểu sinh của ogen nên lệch schema báo lỗi ngay trong test.

## Modifying: `findings.Service.SetStatus(ctx, id, action, note, user)`
- **SPA** (`POST /findings/{id}/status`, mã lỗi `note_required`, `already_open`, `bad_action`, `note_too_long`), **notify** (sự kiện `status_changed`), **response**/**reports** (đếm finding mở). Đổi bảng chuyển trạng thái = đổi hành vi nút trên trang finding.

## Modifying: `findings.Findings` (đọc: `List(filter)`, `Get(id)`, `ByAsset(id)`)
- **mitigation** (gói theo finding), **notify** (`vuln` tin + panel `GET /notify/findings/{id}/notices`), **response** (đề xuất cho Critical), **reports**, **ai** (explain), **mcp-server** (`get_finding`), SPA Devices (`device.panels`). Đổi `FindingRow` phải sửa `findings/contract.ts` (nguồn OpenAPI).

## Modifying: sự kiện `findings.finding.created|status_changed`
- **notify** (tin lỗ hổng, `min_severity`), **response** (trigger finding). Đổi tên/trường = người nhận im lặng, không lỗi biên dịch.

## Disabling this module
- Mất trang Findings và panel finding ở Devices; không finding mới; `notify` mất tin lỗ hổng; `scan` không nối được `finding_id`; `response` không có phát hiện Critical để đề xuất; `reports` thiếu mục lỗ hổng; `mitigation` mất đầu vào.
- Finding cũ và lịch sử giữ trong `fnd_*`.
