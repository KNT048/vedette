# Findings Contract

> Tier: standard · Story: S-MIT-1 (danh sách, vòng đời), S-INV-2, S-SCAN-3, S-ALERT-1 · Last verified: 2026-11-09 (WP-21 + nối vào `cmd/vedette`: `Inventory`, `Feeds`, `Publisher` thật, nghe `inventory.match.changed`/`inventory.asset.deleted`; chưa nghe `scan.finding.confirmed`, `feeds.vuln.updated`; xem `.ai/deferred/feat-module-wiring-2.md`)

Tách từ `mitigation` theo D-57(6): phát hiện (finding) là module riêng, tắt `mitigation` không làm mất phát hiện hay cảnh báo (S-ALERT-1). GUI là `web/src/features/findings/` (danh sách, trang finding, panel Devices). Nguồn hành vi: `findings/{contract,mocks,basis}.ts` (phần `Finding`, `FindingRow`, `/findings`, `/findings/{id}/status`), `web/src/mocks/match.ts`. Phần "What to do" (gói, đã áp dụng, AI) thuộc `mitigation`.

## Invariants
- **INV-1**: Finding = cặp `(asset_id, cve)` duy nhất; không có hai finding cho cùng cặp. `TestContract_INV1_UniquePair`
- **INV-2**: `status ∈ {confirmed, suspected, mitigated, patched, false_positive, not_relevant}`; `basis ∈ {scan, version, product}`; `confidence` ∈ [0,1]. `confirmed` chỉ khi `basis=scan` và có `evidence` (template + `checked_at`); khớp chỉ theo kho thiết bị cho `suspected` với `basis ∈ {version, product}`. `basis` chỉ nâng `product → version → scan`, không hạ.
- **INV-3**: Đổi trạng thái qua `POST /findings/{id}/status` với `action ∈ {patched, mitigated, false_positive, not_relevant, reopen}`; `note` ≤ 500 (400 `note_too_long`); `false_positive` và `not_relevant` cần note ≥ 3 ký tự (400 `note_required`); `reopen` trên finding đang mở → 409 `already_open`; action lạ → 400 `bad_action`. Mỗi lần đổi thêm một dòng `history {ts, user, action, note}` (chỉ thêm) và `core_audit`.
- **INV-4**: Bộ khớp so khoá KEV `vendorproject|product` (chữ thường, cắt khoảng trắng, đúng cách chuẩn hoá của `feeds`); KEV ghi "Multiple products" khớp theo hãng (`basis=product`, confidence thấp hơn). Khi `feeds` có khoảng phiên bản/CPE cho CVE: phiên bản đã biết **nằm ngoài mọi khoảng bị ảnh hưởng ⇒ không tạo finding**; nằm trong khoảng ⇒ `basis=version`; không so sánh được ⇒ không đoán "bị" hay "không bị", rơi về `basis=product` (chưa biết phiên bản). "Không so sánh được" gồm: phiên bản trống, không đọc được hoặc toàn số 0 (giá trị giữ chỗ); hai phiên bản chỉ khác phần đuôi build/bản sửa (`13.1-48.47`, `7.0.0 build 1234`) mà không so được số-với-số; cấu hình ghim `update`/`edition`/`target_sw`… mà phần mềm không mang; mục khoảng phiên bản của `feeds` không đọc được. Chỉ "không" chắc chắn mới bỏ finding. `TestContract_INV4_*`
- **INV-5**: Độ nghiêm trọng lúc tạo: `critical` khi `ransomware` hoặc `epss ≥ 0.5`, ngược lại `high` (⚠ lấy từ mock `match.ts`, chưa có quyết định).
- **INV-6**: Tạo finding là idempotent theo `(asset_id, cve)`: nhận `inventory.match.changed` hoặc `scan.finding.confirmed`; cặp đã có (kể cả đã đóng) không bị tạo lại hay mở lại âm thầm; bộ khớp chỉ thêm, không bao giờ xoá hay đóng. Ngoại lệ ghi chú (D-439): finding `suspected` mà CVE của nó nằm trong danh sách vừa khớp nhưng bộ khớp không còn tạo ra cặp đó (phần mềm đổi, hoặc CISA đổi hãng/sản phẩm của mục) nhận **một** dòng history `no_longer_matches` (dòng cuối đã là nó thì không ghi lại); khi cặp khớp lại mà dòng history cuối là `no_longer_matches` thì ghi đúng một dòng `matches_again` (audit `findings.matches_again`) và dòng audit `findings.no_longer_matches`; trạng thái không đổi (FORBID-2). CVE không có trong danh sách thì không bị xét; finding `basis=scan` không bị xét. `TestUpsert_NoLongerMatchesIsNotedOnceAndNeverClosed`.
- **INV-7**: Xoá thiết bị xoá finding của nó (nhận `inventory.asset.deleted`).
- **INV-8**: `FindingRow.kev` đọc từ `feeds`, không từ gói khuyến nghị của `mitigation`.
- **INV-9** (D-144, issue #160): bus sự kiện là best-effort, nên `findings` tự bù. Job `reconcile` (`findings.Jobs`, chạy khi module bật rồi mỗi giờ) gọi `Service.Reconcile`: (a) khớp lại **mọi** thiết bị như `OnMatchChanged` (đọc qua `Inventory.AssetIDs` + `MatchInput`, `Feeds.Vulns`, không đọc `inv_*`/`feeds_*`), (b) xoá finding của thiết bị đã mất như `OnAssetDeleted`. Idempotent: cặp đã có (kể cả đã đóng) chỉ làm tươi `last_seen`, không tạo lại, không mở lại, không phát lại `findings.finding.created`; chỉ finding do reconcile **tạo mới** (vì sự kiện bị mất) mới phát `created`. Chặn việc xoá nhầm: `AssetIDs` lỗi thì dừng, không xoá gì; thiết bị vắng trong danh sách vẫn phải được `Inventory.Assets` xác nhận là không còn mới xoá. Mỗi thiết bị một giao dịch ghi (không giữ người ghi cả lượt), tôn trọng `ctx` (tắt module thì dừng), mỗi lần ghi tối đa `eventWriteTimeout`. Lỗi của một thiết bị được ghi log và bỏ qua, lượt chạy vẫn đi tiếp (cả bước dọn mồ côi) rồi trả lỗi tổng hợp ở cuối. **Im lặng cho tồn đọng (D-78)**: finding do reconcile tạo mới được ghi dưới `ServiceConfig.Backlog` (binary cài `notify.WithBaseline`), trừ khi mục KEV được CISA thêm trong `RecentKEV` (7 ngày) gần nhất (ngày thêm không rõ thì coi là tồn đọng); nhờ vậy một lượt đường cơ sở bị mất không thành hàng nghìn tin. `last_seen` là lần cuối bộ khớp thấy cặp, từ sự kiện hoặc reconcile. `TestContract_INV9_*`, `TestReconcile*`.

## Preconditions / Postconditions
- **PRE-1** (`UpsertFromMatch(ctx, Asset, []Vuln)`, gọi từ `OnMatchChanged(ctx, assetID)` khi nhận `inventory.match.changed`): tài sản tồn tại (`ErrUnknownAsset`); `cve` không hợp lệ bị bộ khớp bỏ qua (`^CVE-\d{4}-\d{4,}$`). **POST-1**: mỗi cặp mới thành finding `suspected` kèm history `created`, `core_audit` và event; cặp đã có chỉ làm tươi `last_seen` (và nâng `basis` nếu đang mở); chỉ phát `findings.finding.created` khi mới. Mọi thứ trong một giao dịch; event phát sau commit.
- **PRE-2** (`ConfirmFromScan(assetID, cve, evidence)`): `evidence` đã rút gọn và gồm `template`. **POST-2**: finding đang mở → `status=confirmed`, `basis=scan`; finding đã `false_positive|not_relevant` không tự mở lại: lần đầu một `template` khớp thì ghi bằng chứng (`basis=scan`, history `rescanned`) và phát `findings.finding.status_changed` để người dùng quyết, cùng `template` lần sau không phát lại; finding đã `patched|mitigated` → `confirmed` kèm history `reopened` (ghi chú scan) và `status_changed` (**[ĐX]** DATA_MODEL §5.2, chưa chốt). Quét không còn khớp chỉ ghi history `rescan_clear`, không đổi trạng thái.
- **PRE-3** (`GET /findings/{id}`): id 1…64 ký tự. **POST-3**: trả `FindingDetail`; id lạ → 404. Các trường "What to do" (`pack`, `compromise`, `recheck`, `ai`, `ai_available`, `applied`) do `mitigation` cấp theo cơ chế: `findings` hỏi một nhà cung cấp "What to do" tuỳ chọn (`findings.Guidance`, interface của chính `findings`; `mitigation` đăng ký bằng `FindingHandlers.SetGuidance` lúc khởi động và `findings` bỏ qua nó khi cổng module báo `mitigation` tắt; `findings` không import `mitigation`). Khi `mitigation` tắt, nhà cung cấp vắng: các trường là `null`/rỗng (xem câu hỏi mở về cờ GUI).
- **PRE-4** (`POST …/status`): `operator`. **POST-4**: trả `FindingDetail` mới; thất bại không đổi gì.

## Forbidden
- **FORBID-1**: Ghi lên thiết bị hoặc firewall của khách, chặn traffic (D-3). Thực thi hành động thuộc `response`.
- **FORBID-2**: Tự đóng finding mà không có hành động người dùng (`patched` do người xác nhận); quét không còn khớp cũng không tự đóng. Cố ý chặt hơn FORBID-5 cũ của `mitigation` ("hoặc bằng chứng quét rõ ràng"): quét sạch chỉ ghi history `rescan_clear` (DATA_MODEL §5.2), người dùng mới đóng.
- **FORBID-3**: Tạo loại "lỗ hổng" trong Incidents (D-52).
- **FORBID-4**: Khẳng định bị ảnh hưởng hoặc không bị ảnh hưởng khi phiên bản không so sánh được.
- **FORBID-5**: Module khác ghi `fnd_*` trực tiếp; đọc qua interface của `findings`.

## Dependencies
- **DEPENDS ON**: `core`, `feeds` (KevInfo, khoảng phiên bản), `inventory` (tài sản, phần mềm, sự kiện khớp; `Inventory.AssetIDs` cho reconcile, `cmd/vedette` cài bằng `DevicesOfKind(inventory.Kinds)`: không giới hạn dòng). Tuỳ chọn: `scan` (xác nhận), `notify` (người được báo).
- **DEPENDED ON BY**: `mitigation` (gói theo finding), `notify` (tin lỗ hổng), `scan` (nối `finding_id`), `scan-credentialed`, `response`, `reports`, `ai` (giải thích finding), `mcp-server` (`get_finding`), SPA Devices (panel `device.panels`).

## Endpoints owned (role tối thiểu)
| Route | Vai |
|---|---|
| `GET /findings`, `GET /findings/{id}` | viewer |
| `POST /findings/{id}/status` | operator |

`POST /findings/{id}/applied|ai` nằm dưới cùng tiền tố `/findings` nhưng do `mitigation` định tuyến, mất khi `mitigation` tắt.

## Tables owned (`fnd_`)
`fnd_finding`, `fnd_finding_history`.

## Events
- **Phát**: `findings.finding.created {finding_id, asset_id, cve, severity, basis}`, `findings.finding.status_changed {finding_id, from, to}`.
- **Nhận**: `inventory.match.changed` → `OnMatchChanged` (tính lại cả thiết bị; thiết bị đã bị xoá thì bỏ qua), `inventory.asset.deleted` → `OnAssetDeleted` (INV-7), đều đăng ký ở `cmd/vedette/wiring.go` và chỉ chạy khi `findings` bật (tắt lúc đó thì bỏ lỡ, finding mồ côi được INV-9 dọn trong lượt reconcile kế tiếp); `scan.finding.confirmed` → `ConfirmFromScan` **chưa nối** (chưa có module scan); `feeds.vuln.updated` (làm tươi KevInfo) chưa nghe: KevInfo đọc trực tiếp lúc hiển thị nên không cần.
- **Hạn của bus không áp cho việc ghi**: bus cho mỗi handler 5 giây và không giao lại sự kiện đã lỗi; trong lúc kéo KEV lần đầu một lần ghi dài giữ người ghi duy nhất quá 5 giây, nên `OnMatchChanged` và `OnAssetDeleted` chạy trên hạn riêng `eventWriteTimeout` (1 phút), tách khỏi hạn của bus. Trước đó "store: begin: context deadline exceeded" làm mất sự kiện, tức finding không được tạo hoặc finding của thiết bị đã xoá còn lại (log 2026-11-10: 3 lần khi nạp 1773 bản ghi KEV). `TestMatchIsNotLostWhenTheWriterIsBusyPastTheBusDeadline`, `TestDeviceDeleteIsNotLostWhenTheWriterIsBusyPastTheBusDeadline`. Hết 1 phút vẫn mất sự kiện, nhưng INV-9 (reconcile mỗi giờ) bù lại.
- **Từ đường cơ sở D-78**: lần kéo CISA đầu làm `inventory` khớp lại mọi thiết bị, nên `findings.finding.created` có thể phát hàng loạt. **`notify` (WP-22) không được gửi tin cho các finding sinh ra từ đường cơ sở.**

## Behaviour khi tắt
Không route `/findings*`; không finding mới/cập nhật; `notify` không có gì để gửi cho S-ALERT-1; kết quả `scan` có `finding_id=null`; Devices mất panel finding; `reports` thiếu mục lỗ hổng; `mitigation` mất đầu vào (phụ thuộc, báo `affected`). Bảng giữ nguyên.

## Story và quyết định
S-MIT-1 (danh sách, trạng thái), S-INV-2, S-SCAN-3, S-ALERT-1. D-3 không chặn; D-52 Findings ≠ Incidents; D-57(6) tách module; D-57(13) `confidence` thang 0–1.

## Không khớp / câu hỏi mở
- `fnd_finding_history` chỉ chặn UPDATE bằng trigger (chỉ thêm, không sửa); DELETE không bị chặn vì xoá finding (INV-7) cần cascade xoá history. Chỉ có `findings.Service` xoá finding.
- `GET /findings/{id}` thêm mỗi mục "Đã áp dụng" của `mitigation` vào `history` dưới dạng dòng `applied:<item>` (như mock, sắp theo `ts`, ổn định); `GET /findings` thì không (chỉ history đã lưu).
- `fnd_finding.asset_id` **không** có FK tới `inv_asset` (quy tắc `modules.md`: không ràng buộc chéo module, FK buộc migration và trạng thái bật/tắt của hai module): INV-7 do `Service.OnAssetDeleted` (sự kiện) đảm nhiệm. Sự kiện không bền: việc đối chiếu định kỳ (hỏi `Inventory` id nào còn, xoá mồ côi) là INV-9, cho trường hợp lỡ sự kiện hoặc `findings` tắt lúc xoá.
- `bad_action` và `note_too_long` (khi vượt 500 ký tự ngay trong thân) bị schema OpenAPI chặn trước handler (400 `invalid` chung của ogen): mã riêng chỉ còn tới được qua service, và `note_too_long` qua HTTP chỉ khi ghi chú ≤ 500 ký tự Unicode nhưng > 500 đơn vị UTF-16.
- ARCHITECTURE §4 đặt bảng `inv_finding`; hợp đồng này dùng `fnd_finding` (khớp DATA_MODEL). DATA_MODEL §4.3 và §5.2 còn ghi "chỉ `mitigation` ghi bảng" và `mitigation.finding.*`: cần sửa theo hợp đồng này.
- `GET /findings/{id}` gộp dữ liệu của `mitigation` (shape `FindingDetail` giữ nguyên, GUI-first). Khi `mitigation` tắt, `pack:null` giống hệt "chưa có khuyến nghị đã xác nhận": GUI chưa phân biệt được (S-CORE-1 yêu cầu nói rõ vì module tắt). Cần quyết: thêm cờ vào `FindingDetail` (đổi GUI = story mới) hay ẩn panel.
- `basis=version` chưa có trong mock (`feeds_vuln` chưa có khoảng phiên bản); `confidence` cho `version` là **[ĐX]** 0.7 (DATA_MODEL §5.2 ghi "≥ 0.7").
- Basis của kết quả credentialed (Greenbone) chưa định nghĩa (chỉ `scan|version|product`).
