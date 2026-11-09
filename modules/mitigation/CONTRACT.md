# Mitigation (Findings) Contract

> Tier: standard · Story: S-MIT-1, S-MIT-3, S-MIT-4, S-SCAN-3, S-AI-2, S-ALERT-1 · Last verified: 2026-11-09 (docs-first, chưa có code)

GUI là thư mục `web/src/features/findings/`: **findings thuộc module `mitigation`**. Nguồn hành vi: `findings/{contract,mocks,packs}.ts`, `web/src/mocks/match.ts`.

## Invariants
- **INV-1**: Finding = cặp `(asset_id, cve)` duy nhất; không có hai finding cho cùng cặp. `TestContract_INV1_UniquePair`
- **INV-2**: `status ∈ {confirmed, suspected, mitigated, patched, false_positive, not_relevant}`. `confirmed` chỉ khi `basis=scan` và có `evidence` (template + `checked_at`); khớp chỉ theo kho thiết bị cho `suspected` với `basis ∈ {version, product}`. `confidence` ∈ [0,1].
- **INV-3**: Đổi trạng thái qua `POST /findings/{id}/status` với `action ∈ {patched, mitigated, false_positive, not_relevant, reopen}`; `note` ≤ 500; `false_positive` và `not_relevant` cần note ≥ 3 ký tự (400 `note_required`); `reopen` trên finding đang mở → 409 `already_open`. Mỗi lần đổi thêm một dòng `history {ts, user, action, note}` (chỉ thêm) và `core_audit`.
- **INV-4**: "Đã áp dụng" chỉ ghi nhận cho CVE có gói đã xác nhận (400 `no_pack`), thêm `AppliedEntry {item, ts, user}`, **không** đổi `status`.
- **INV-5**: Gói đáng tin (D-21): chỉ hiện "Vedette confirmed" khi gói có `status: confirmed`, `confirmed_by`, `confirmed_at`, `drafted_with`, `sources[]` và chữ ký hợp lệ của bản cập nhật; bộ nạp từ chối gói `draft` hoặc không ký. CVE không có gói ⇒ `pack:null` và UI hiện "no confirmed recommendation yet" + thông tin gốc KEV + nút "Ask my AI" chỉ khi AI dùng được.
- **INV-6**: Kết quả AI luôn mang nhãn "AI generated", ghi `model`, `profile`, `tokens`, `citations`; không bao giờ hiện như khuyến nghị đã xác nhận (S-AI-6). `POST /findings/{id}/ai` khi chưa gán hồ sơ AI cho việc đó hoặc `ai` tắt → 409 `ai_unavailable`. `mitigation` không có công cụ ghi cho AI (SYS-8).
- **INV-7**: Mỗi `CodeStep` có `side_effect` phải hiện trước khi người dùng sao chép lệnh; `{IP}`/`{HOST}` thay bằng giá trị thiết bị, đã escape (giá trị thiết bị là dữ liệu không tin cậy).
- **INV-8**: `FindingRow.kev` đọc từ `feeds`, không từ gói. `firewall[].detected=true` khi `inventory` có thiết bị của hãng đó.
- **INV-9**: Tạo finding là idempotent theo `(asset_id, cve)`: nhận `inventory.match.changed` hoặc `scan.finding.confirmed`; độ nghiêm trọng `critical` khi `ransomware` hoặc `epss ≥ 0.5`, ngược lại `high` (⚠ lấy từ mock `match.ts`, chưa có quyết định).
- **INV-10**: Xoá thiết bị xoá finding của nó (nhận `inventory.asset.deleted`).
- **INV-11**: Dấu hiệu "Tôi đã bị chưa?" và lệnh kiểm tra chỉ là văn bản từ nội dung ký; Vedette không bao giờ chạy chúng.

## Preconditions / Postconditions
- **PRE-1** (`UpsertFromMatch(assetID, cve, basis)`): `cve` khớp `^CVE-\d{4}-\d{4,}$`, tài sản tồn tại. **POST-1**: finding tạo/cập nhật `last_seen`; chỉ phát `mitigation.finding.created` khi mới.
- **PRE-2** (`ConfirmFromScan(assetID, cve, evidence)`): `evidence` đã rút gọn và gồm `template`. **POST-2**: `status=confirmed`, `basis=scan`; finding đã `false_positive|not_relevant` không tự mở lại, phát `mitigation.finding.status_changed` để người dùng quyết.
- **PRE-3** (`GET /findings/{id}`): id 1…64 ký tự. **POST-3**: trả `pack`, `compromise`, `recheck`, `ai`, `ai_available {explain, config}`, `applied`; id lạ → 404.
- **PRE-4** (`POST …/status`, `…/applied`, `…/ai`): `operator`. **POST-4**: trả `FindingDetail` mới; thất bại không đổi gì.

## Forbidden
- **FORBID-1**: Ghi lên thiết bị hoặc firewall của khách, chặn traffic (D-3). Thực thi hành động thuộc `response`.
- **FORBID-2**: Hiện nội dung AI như "Vedette confirmed" hoặc gộp vào gói đã xác nhận.
- **FORBID-3**: Nạp gói chưa `confirmed` hoặc chưa ký.
- **FORBID-4**: Gói rule "vá ảo" Suricata/CRS/CrowdSec/nftables (S-MIT-2, D-31).
- **FORBID-5**: Tự đóng finding mà không có hành động người dùng hoặc bằng chứng quét rõ ràng (`patched` do người xác nhận).
- **FORBID-6**: Tạo loại "lỗ hổng" trong Incidents (D-52).

## Dependencies
- **DEPENDS ON**: `core`, `feeds` (KevInfo, `has_template`), `inventory` (tài sản, khớp). Tuỳ chọn: `scan` (xác nhận), `ai` (giải thích), `notify` (panel ai được báo).
- **DEPENDED ON BY**: `notify` (tin lỗ hổng), `scan` (nối `finding_id`), `response`, `reports`, `ai`, `mcp-server` (`get_finding`), SPA Devices (panel `device.panels`).

## Endpoints owned (role tối thiểu)
| Route | Vai |
|---|---|
| `GET /findings`, `GET /findings/{id}` | viewer |
| `POST /findings/{id}/status`, `/findings/{id}/applied`, `/findings/{id}/ai` | operator |

## Tables owned (`mit_`)
`fnd_finding`, `fnd_finding_history`, `mit_applied`, `mit_ai_output`, `mit_pack` (chỉ mục gói đã nạp từ bản cập nhật; nội dung là tệp ký, không phải dữ liệu khách).

## Events
- **Phát**: `mitigation.finding.created {finding_id, asset_id, cve, severity, basis}`, `mitigation.finding.status_changed {finding_id, from, to}`.
- **Nhận**: `inventory.match.changed`, `inventory.asset.deleted`, `scan.finding.confirmed`, `feeds.vuln.updated` (làm tươi KevInfo), `core.update.applied` (nạp lại gói).

## Behaviour khi tắt
Không route `/findings*`; không finding mới/cập nhật; `notify` không có gì để gửi cho S-ALERT-1; kết quả `scan` có `finding_id=null`; Devices mất panel finding; `reports` thiếu mục lỗ hổng. Bảng giữ nguyên.

## Story và quyết định
S-MIT-1, 3, 4, S-SCAN-3, S-AI-2, S-ALERT-1. D-3 không chặn; D-21 gói xác nhận qua PR; D-29 hồ sơ AI theo việc; D-31 bỏ vá ảo; D-52 Findings ≠ Incidents.

## Không khớp / câu hỏi mở
- **Lớn**: nếu finding sống trong `mitigation` thì tắt nó cắt luôn cảnh báo KEV khớp thiết bị (S-ALERT-1, module `notify` chuẩn). Cân nhắc để việc tạo finding ở `core`/`inventory` còn `mitigation` chỉ lo nội dung "What to do".
- ARCHITECTURE §4 đặt bảng `inv_finding`; hợp đồng này dùng `fnd_finding`.
- S-MIT-1 liệt kê 8 hãng firewall; GUI/gói mẫu chỉ có `fortigate`, `mikrotik`, `generic`.
- Basis của kết quả credentialed (Greenbone) chưa định nghĩa (chỉ `scan|version|product`).
