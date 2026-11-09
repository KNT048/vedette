# Findings Contract

> Tier: standard · Story: S-MIT-1 (danh sách, vòng đời), S-INV-2, S-SCAN-3, S-ALERT-1 · Last verified: 2026-11-09 (WP-21: thư viện thuần + service + migration `fnd_*` + 3 handler, có test; chưa nối vào `cmd/vedette`: thiếu cài đặt `Inventory`/`Feeds` thật, xem `.ai/deferred/feat-findings-module.md`)

Tách từ `mitigation` theo D-57(6): phát hiện (finding) là module riêng, tắt `mitigation` không làm mất phát hiện hay cảnh báo (S-ALERT-1). GUI là `web/src/features/findings/` (danh sách, trang finding, panel Devices). Nguồn hành vi: `findings/{contract,mocks,basis}.ts` (phần `Finding`, `FindingRow`, `/findings`, `/findings/{id}/status`), `web/src/mocks/match.ts`. Phần "What to do" (gói, đã áp dụng, AI) thuộc `mitigation`.

## Invariants
- **INV-1**: Finding = cặp `(asset_id, cve)` duy nhất; không có hai finding cho cùng cặp. `TestContract_INV1_UniquePair`
- **INV-2**: `status ∈ {confirmed, suspected, mitigated, patched, false_positive, not_relevant}`; `basis ∈ {scan, version, product}`; `confidence` ∈ [0,1]. `confirmed` chỉ khi `basis=scan` và có `evidence` (template + `checked_at`); khớp chỉ theo kho thiết bị cho `suspected` với `basis ∈ {version, product}`. `basis` chỉ nâng `product → version → scan`, không hạ.
- **INV-3**: Đổi trạng thái qua `POST /findings/{id}/status` với `action ∈ {patched, mitigated, false_positive, not_relevant, reopen}`; `note` ≤ 500 (400 `note_too_long`); `false_positive` và `not_relevant` cần note ≥ 3 ký tự (400 `note_required`); `reopen` trên finding đang mở → 409 `already_open`; action lạ → 400 `bad_action`. Mỗi lần đổi thêm một dòng `history {ts, user, action, note}` (chỉ thêm) và `core_audit`.
- **INV-4**: Bộ khớp so khoá KEV `vendorproject|product` (chữ thường, cắt khoảng trắng, đúng cách chuẩn hoá của `feeds`); KEV ghi "Multiple products" khớp theo hãng (`basis=product`, confidence thấp hơn). Khi `feeds` có khoảng phiên bản/CPE cho CVE: phiên bản đã biết **nằm ngoài mọi khoảng bị ảnh hưởng ⇒ không tạo finding**; nằm trong khoảng ⇒ `basis=version`; không so sánh được ⇒ không đoán "bị" hay "không bị", rơi về `basis=product` (chưa biết phiên bản). "Không so sánh được" gồm: phiên bản trống, không đọc được hoặc toàn số 0 (giá trị giữ chỗ); hai phiên bản chỉ khác phần đuôi build/bản sửa (`13.1-48.47`, `7.0.0 build 1234`) mà không so được số-với-số; cấu hình ghim `update`/`edition`/`target_sw`… mà phần mềm không mang; mục khoảng phiên bản của `feeds` không đọc được. Chỉ "không" chắc chắn mới bỏ finding. `TestContract_INV4_*`
- **INV-5**: Độ nghiêm trọng lúc tạo: `critical` khi `ransomware` hoặc `epss ≥ 0.5`, ngược lại `high` (⚠ lấy từ mock `match.ts`, chưa có quyết định).
- **INV-6**: Tạo finding là idempotent theo `(asset_id, cve)`: nhận `inventory.match.changed` hoặc `scan.finding.confirmed`; cặp đã có (kể cả đã đóng) không bị tạo lại hay mở lại âm thầm; bộ khớp chỉ thêm, không bao giờ xoá.
- **INV-7**: Xoá thiết bị xoá finding của nó (nhận `inventory.asset.deleted`).
- **INV-8**: `FindingRow.kev` đọc từ `feeds`, không từ gói khuyến nghị của `mitigation`.

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
- **DEPENDS ON**: `core`, `feeds` (KevInfo, khoảng phiên bản), `inventory` (tài sản, phần mềm, sự kiện khớp). Tuỳ chọn: `scan` (xác nhận), `notify` (người được báo).
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
- **Nhận**: `inventory.match.changed`, `inventory.asset.deleted`, `scan.finding.confirmed`, `feeds.vuln.updated` (làm tươi KevInfo, khớp lại).

## Behaviour khi tắt
Không route `/findings*`; không finding mới/cập nhật; `notify` không có gì để gửi cho S-ALERT-1; kết quả `scan` có `finding_id=null`; Devices mất panel finding; `reports` thiếu mục lỗ hổng; `mitigation` mất đầu vào (phụ thuộc, báo `affected`). Bảng giữ nguyên.

## Story và quyết định
S-MIT-1 (danh sách, trạng thái), S-INV-2, S-SCAN-3, S-ALERT-1. D-3 không chặn; D-52 Findings ≠ Incidents; D-57(6) tách module; D-57(13) `confidence` thang 0–1.

## Không khớp / câu hỏi mở
- `fnd_finding.asset_id` chưa có FK tới `inv_asset` (inventory chưa có): INV-7 do `Service.OnAssetDeleted` đảm nhiệm. Khi `inventory` có bảng thì thêm FK bằng migration mới.
- `bad_action` và `note_too_long` (khi vượt 500 ký tự ngay trong thân) bị schema OpenAPI chặn trước handler (400 `invalid` chung của ogen): mã riêng chỉ còn tới được qua service, và `note_too_long` qua HTTP chỉ khi ghi chú ≤ 500 ký tự Unicode nhưng > 500 đơn vị UTF-16.
- ARCHITECTURE §4 đặt bảng `inv_finding`; hợp đồng này dùng `fnd_finding` (khớp DATA_MODEL). DATA_MODEL §4.3 và §5.2 còn ghi "chỉ `mitigation` ghi bảng" và `mitigation.finding.*`: cần sửa theo hợp đồng này.
- `GET /findings/{id}` gộp dữ liệu của `mitigation` (shape `FindingDetail` giữ nguyên, GUI-first). Khi `mitigation` tắt, `pack:null` giống hệt "chưa có khuyến nghị đã xác nhận": GUI chưa phân biệt được (S-CORE-1 yêu cầu nói rõ vì module tắt). Cần quyết: thêm cờ vào `FindingDetail` (đổi GUI = story mới) hay ẩn panel.
- `basis=version` chưa có trong mock (`feeds_vuln` chưa có khoảng phiên bản); `confidence` cho `version` là **[ĐX]** 0.7 (DATA_MODEL §5.2 ghi "≥ 0.7").
- Basis của kết quả credentialed (Greenbone) chưa định nghĩa (chỉ `scan|version|product`).
