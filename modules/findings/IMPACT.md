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

## Modifying: khoảng phiên bản và mục "add the version" (D-500)
- **feeds** (feed `nvd-kev`, `Store.KevAffected`) → `cmd/vedette` `findingsFeeds.Vulns` điền `Vuln.Affected`; sự kiện `feeds.ranges.updated` → `Inventory.RematchAll` (lần đầu trong ngữ cảnh baseline của notify, D-78).
- **inventory**: `MatchDevice.OS` → `findings.Asset.OS` (loại trừ CVE chỉ nêu bản phát hành OS). Đổi cách gấp OS (`inv_asset.os`) làm lệch `osIdentity` (Ubuntu/Debian).
- **content/catalog/nvd-cpe.json**: khoá là vendor|product của danh mục và của `agent-intake/pkgmap.json`; đổi tên sản phẩm ở hai nơi đó phải đổi khoá ở đây (`TestAliases_DataIsValid`, `TestGolden_*`).
- **GUI/contract**: `FindingList.version_needed` (`contract.ts`, mock `web/src/mocks/match.ts` `versionNeeded`, `FindingsPage` khối "Add the version"); mock không có khoảng nên phần mềm có phiên bản → `medium` theo sản phẩm.
- **notify**: finding theo sản phẩm nay `medium` (trước `high/critical`); quy tắc báo theo mức nghiêm trọng nhận ít tin hơn cho khớp không so được phiên bản.
- **core export** (`export_policy.go`): `fnd_version_needed` được xuất.
- **D-530 tự đóng/mở lại** (`autoResolve`, `Finding.AutoResolve/ReopenOnMatch`, cột `resolution_reason`, migration `0004_resolution_reason.sql`): **GUI** thấy `not_relevant` với `resolved_by=system` và ghi chú bắt đầu "Not affected:" (bộ lọc Unresolved mặc định ẩn nó; API không đổi hình); **logs/SIEM** nhận `finding.status_changed` suspected→not_relevant và ngược lại (trường `reason` = `not_affected_version` / `matches_again`); **notify** bỏ qua status_changed không phải `confirmed` (không tin nào khi tự đóng/mở lại cho tới khi notify dùng `reason`); **reports**/đếm finding mở giảm; **core export** xuất `resolution_reason`; nhãn audit `findings.auto_resolved` trong `locales/en/core.json`. `updateRecord` nay ghi cả `severity`.

## Modifying: `findings.Service.Reconcile(ctx)` và `findings.Jobs(svc)` (job `reconcile`, mỗi giờ)
- **inventory**: phải cài `findings.Inventory.AssetIDs` (mọi id thiết bị, không giới hạn dòng, lỗi đọc là lỗi, không bao giờ trả danh sách ngắn: reconcile coi finding của thiết bị vắng là mồ côi và xoá sau khi hỏi lại `Assets`). Sửa `DevicesOfKind` hay `Kinds` (loại thiết bị mới) thì sửa adapter ở `cmd/vedette/wiring.go`, nếu không thiết bị loại mới không được khớp lại và finding của nó bị coi là mồ côi chỉ khi `Assets` cũng không thấy.
- **cmd/vedette**: `wiredModules` có `Jobs: findingsJobs` cho `findings`; job chạy khi module bật rồi mỗi `ReconcileEvery`. Tắt module = job dừng, dữ liệu giữ.
- **notify** (D-78): reconcile có thể phải tạo hàng loạt finding khi sự kiện đường cơ sở bị mất (findings tắt lúc kéo CISA đầu, `RematchAll` bị cắt bởi `rematchTimeout`, một thiết bị hết hạn ghi). Để không gửi một tin cho mỗi finding, finding do reconcile tạo mới được ghi dưới `ServiceConfig.Backlog` (`cmd/vedette` cài `notify.WithBaseline`; `findings` không import `notify`) **trừ** khi mục KEV được CISA thêm trong `RecentKEV` (7 ngày) gần nhất: đó là tin thật mà một sự kiện `new_kev` bị mất vẫn phải báo, và phát `findings.finding.created` không dấu. Ngày thêm không rõ (`Vuln.DateAdded` zero) coi như tồn đọng. Đổi `RecentKEV` hay bỏ `Backlog` là đổi số tin `notify` gửi sau một lần mất sự kiện. `findings.Vuln.DateAdded` do adapter `findingsFeeds.Vulns` điền từ `feeds` (`date_added`).
- **`last_seen`** của finding nay là lần cuối bộ khớp thấy cặp đó, từ sự kiện hoặc từ reconcile (mỗi giờ), không chỉ từ sự kiện; trang finding hiện "last seen" theo nghĩa này.
- **feeds**: `Feeds.Vulns` rỗng (chưa kéo KEV) thì không khớp gì, chỉ chạy bước dọn mồ côi.

## Modifying: `findings.Service.ConfirmFromScan(ctx, assetID, cve, Evidence)`
- **scan** (kết quả `matched`), **scan-credentialed** (tương lai). Đổi `Evidence` hay điều kiện `confirmed` làm lệch bảng kết quả quét (`finding_id`) và trang finding.

## Modifying: `findings.Service.OnAssetDeleted(ctx, assetID)`
- **inventory** (sự kiện `inventory.asset.deleted`). Xoá `fnd_finding` của thiết bị; `fnd_finding_history`, `mit_applied`, `mit_ai_output` đi theo qua FK cascade (mitigation phụ thuộc điều này). Đổi thành xoá mềm = sửa cả `mitigation`.

## Modifying: `findings.FindingHandlers.SetGuidance(Guidance)` và `Guide`/`Row`/`Detail`
- **mitigation** (đăng ký nhà cung cấp, dựng `Guide`; gọi `Detail` để trả lời `applied|ai`). Đổi hình `Guide` = đổi `FindingDetail` trong `contract.ts`; `findings.Into` giải mã vào kiểu sinh của ogen nên lệch schema báo lỗi ngay trong test.

## Modifying: `findings.Service.SetStatus(ctx, id, action, note, user)`
- **SPA** (`POST /findings/{id}/status`, mã lỗi `note_required`, `already_open`, `bad_action`, `note_too_long`), **notify** (sự kiện `status_changed`), **response**/**reports** (đếm finding mở). Đổi bảng chuyển trạng thái = đổi hành vi nút trên trang finding.

## Modifying: `findings.Service.SetStatusMany(ctx, ids, action, note, user)` (D-484, INV-10)
- **SPA** (`POST /findings/status`: thanh chọn của danh sách Findings; `{updated, skipped}`), **notify** (một `status_changed` mỗi finding), **core_audit** (một dòng mỗi finding: 500 dòng một lần; trần nhật ký kiểm toán là W1-34). Đổi `MaxBulk` = đổi `MAX_BULK` trong `findings/contract.ts`.

## Modifying: `ServiceConfig.HaveSince` và `haveScope` (D-484, INV-11)
- **feeds** (`Store.HaveSince`, đọc `feeds_weekly_answer.device_id/have_since`), **cmd/vedette** (`findingsHave` trong `wiring.go`; `feedsInventory.AddManualDevice` phải trả id thiết bị thì phạm vi mới bật), **inventory** (id thiết bị khai tay). Đổi luật = đổi số finding (và tin `notify`) của sản phẩm khách bấm "I have this" trên Home; text Home (`feeds.json` `weekly.*`) nói luật này.

## Modifying: `AssetView.Name` / `HasIP` (D-484, INV-12)
- **cmd/vedette** (`findingsInventory.Assets` điền `Name` từ `inventory.Names`; `MatchInput` dùng tên đó khi thiết bị không có tên máy lẫn IP), **mitigation** (`genericRecheck` dùng `Name`, chỉ nhắc "Rescan this device" khi `HasIP`), SPA (`findings/basis.ts` `deviceName`, `hasIp`).

## Modifying: `findings.Service.CountByAsset(ctx) (map[string]int, error)`
- **inventory** (`FindingCounter`, `findings_count` ở danh sách và trang thiết bị, hộp thoại xoá): một lần đọc gộp theo `asset_id`, **mọi trạng thái** (đúng số bị xoá cùng thiết bị, INV-11 của inventory). Nối ở `cmd/vedette` `findingCounts`; module findings tắt → 0 (khi tắt không gì xoá chúng cùng thiết bị). Đổi nghĩa (ví dụ chỉ đếm finding mở) là đổi câu "deleting the device also deletes these findings" của `inventory/contract.ts`.

## Modifying: `findings.Findings` (đọc: `List(filter)`, `Get(id)`, `ByAsset(id)`)
- **mitigation** (gói theo finding), **notify** (`vuln` tin + panel `GET /notify/findings/{id}/notices`), **response** (đề xuất cho Critical), **reports**, **ai** (explain), **mcp-server** (`get_finding`), SPA Devices (`device.panels`). Đổi `FindingRow` phải sửa `findings/contract.ts` (nguồn OpenAPI).

## Modifying: sự kiện `findings.finding.created|status_changed|severity_raised`
- **notify** (tin lỗ hổng, `min_severity`), **response** (trigger finding), **logs** (SIEM). Đổi tên/trường = người nhận im lặng, không lỗi biên dịch.
- `severity_raised` (review M-a của #663) thay cho `status_changed` `from = to` kèm `severity` của review H2: **notify** và **logs** chưa nghe nó (module của nhóm khác); tới lúc đó việc nâng mức không ra tin và không ra SIEM. Dòng trong `.ai/deferred/fix-cve-version-ranges.md`.

## Disabling this module
- Mất trang Findings và panel finding ở Devices; không finding mới; `notify` mất tin lỗ hổng; `scan` không nối được `finding_id`; `response` không có phát hiện Critical để đề xuất; `reports` thiếu mục lỗ hổng; `mitigation` mất đầu vào.
- Finding cũ và lịch sử giữ trong `fnd_*`.
