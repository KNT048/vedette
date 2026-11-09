# Inventory Contract

> Tier: standard · Story: S-INV-1, 2, 3, 5 (+ cột "Do you have it?" của S-FEED-1) · Last verified: 2026-11-09 (docs-first, chưa có code)

Nguồn hành vi: `web/src/features/inventory/{contract,mocks,validate}.ts`. Phần agent (osquery, Wazuh, `/install/*`, `/intake/*`) trong cùng `contract.ts` thuộc `agent-intake`; phần cảm biến (`/inventory/sensors*`) thuộc `sensor-passive`.

## Invariants
- **INV-1**: Quan sát chỉ thêm, không ghi đè (`inv_observation`). Giá trị "đang dùng" của một trường chọn theo: khai tay > độ tin cậy cao > mới hơn. `confidence ∈ [0,1]`; `summary.source` = nguồn của giá trị đáng tin nhất, `summary.confidence` = của giá trị yếu nhất. `TestContract_INV1_ObservationsAppendOnly`
- **INV-2**: Mọi ghi vào `inv_*` đi qua `inventory.Service` (cảm biến, agent, feeds không ghi trực tiếp).
- **INV-3**: Có đúng một tài sản `is_box=true` ("This box"), tạo lúc cài (cả dữ liệu mẫu và cài sạch), gói lấy từ dpkg với confidence 1.0; `DELETE` nó → 409 `box_device` (D-53, S-INV-5).
- **INV-4**: Khai tay: `ip` IPv4 duy nhất (409 nếu trùng), `name` ≤ 64 ký tự không có `<` `>`, `vendor/product` ≤ 64, `version` ≤ 40 ký tự chỉ gồm chữ, số, `. - + ( )` và khoảng trắng; trùng phần mềm trên cùng thiết bị → 409 `duplicate_software`. Chỉ phần mềm `source=manual` xoá được (400 `not_manual`).
- **INV-5**: Thiết bị khai tay (`origin=manual`) không bao giờ bị quét (`first_scan_at=null`).
- **INV-6**: Dải mạng (`lan_ranges`): tối đa 16; mỗi dải **phải có tiền tố** (400 `no_prefix`, không đoán /24, D-32), không bit máy (`host_bits`), chỉ dải riêng RFC 1918 (`public_range`, chỉ đường tới `exposure`), không chồng nhau (`overlap_range`); giữ đúng tiền tố người gõ.
- **INV-7**: Bật quét chủ động (`active.enabled=true`) cần ≥1 dải, ≥1 ngày và `scope_confirmed=true`; lưu `scope_confirmed_at/by` (D-26). `days ∈ 1..7` (1=Thứ Hai), `from≠to` (có thể qua nửa đêm), `rate ∈ 1..1000` gói/giây, `exclusions` là IPv4 hoặc CIDR không bit máy.
- **INV-8**: Thiết bị mong manh (D-45): loại thuộc `fragile_kinds` hoặc `fragile=true` được quét nhẹ **đúng một lần** khi thấy lần đầu (`first_scan_at` đặt), sau đó chỉ thụ động trừ khi `regular_scan=allow` hoặc loại ∈ `regular_scan_kinds`; `regular_scan=never` thắng cài đặt theo loại. `regular_scan_kinds ⊂ fragile_kinds`.
- **INV-9**: Thiết bị mới do cảm biến thấy: `approved=false`, vào hàng "pending" (S-INV-3); `notify_new` bật ⇒ phát `inventory.asset.discovered`.
- **INV-10**: Thêm sản phẩm khớp ngay với `feeds` (`kev_cves`); khớp chỉ theo sản phẩm/phiên bản cho `basis ∈ {product, version}`, không bao giờ cho "confirmed" (chỉ `scan` xác nhận).
- **INV-11**: Xoá tài sản xoá luôn finding của nó (`findings_count` hiện trước khi xoá); `findings` nhận `inventory.asset.deleted` (D-57 (6)).
- **INV-12**: Danh mục `GET /inventory/catalog`: trả tối đa 30 mục kèm `total`; id mục tuyển chọn cố định, mục từ KEV là `kev:<vendor>:<product>`; chứa mọi cặp hãng/sản phẩm từng có trong KEV + sản phẩm SMB phổ biến; nhập tự do vẫn được (D-30).
- **INV-13**: Nhập CSV ≤ 200 KB và ≤ 500 dòng; dòng lỗi báo theo số dòng, dòng hợp lệ vẫn thêm; tiêu đề cần cột `name` hoặc `product`. Xuất CSV UTF-8 có BOM.

## Preconditions / Postconditions
- **PRE-1** (`RecordObservation(obs)`): `source ∈ {manual,agent,snmp,nmap,passive,scan}`, `field ∈ {hostname,mac,vendor,model,os,kind}`, `confidence ∈ [0,1]`. **POST-1**: quan sát thêm; tài sản tạo nếu MAC/IP mới (`approved=false`); `last_seen` cập nhật.
- **PRE-2** (`UpsertSoftware(assetID, items, source)`): tài sản tồn tại. **POST-2**: `inv_software` thay theo nguồn; phát `inventory.match.changed` khi tập khớp KEV đổi.
- **PRE-3** (`ScanPolicy(assetID)`): tài sản tồn tại. **POST-3**: trả `{allowed, rate, reason}` theo INV-5, 7, 8 và `exclusions`; `InScope(ip)` đúng khi ip ∈ `lan_ranges` ∖ `exclusions`.
- **PRE-4** (`PATCH /inventory/devices/{id}`): `operator`. **POST-4**: sửa `kind/fragile` thêm observation `manual`, không xoá giá trị cũ.
- **PRE-5** (`PUT /inventory/settings`): `admin`, qua INV-6/7. **POST-5**: `scope_confirmed_at` giữ nếu không đổi dải; phát `inventory.settings.changed`.

## Forbidden
- **FORBID-1**: Ghi đè hoặc xoá quan sát cũ.
- **FORBID-2**: Xoá thiết bị "This box".
- **FORBID-3**: Tự đoán tiền tố dải mạng.
- **FORBID-4**: Module khác đọc/ghi bảng `inv_*` trực tiếp.
- **FORBID-5**: Gửi dữ liệu tài sản ra ngoài hộp (trừ khi `ai`/`notify` được cấu hình, qua module đó).

## Dependencies
- **DEPENDS ON**: `core`, `feeds` (khớp KEV, danh mục).
- **DEPENDED ON BY**: `sensor-passive`, `sensor-active`, `agent-intake`, `findings` (khớp KEV, finding), `mitigation` (hãng thiết bị cho `firewall[].detected`), `exposure`, `scan`, `scan-credentialed`, `honeypot`, `logs`, `response`, `reports`, `ai`, `mcp-server`; tuỳ chọn `notify` (tên thiết bị trong tin).

## Endpoints owned (role tối thiểu)
| Route | Vai |
|---|---|
| `GET /inventory/devices`, `/inventory/devices/{id}`, `/inventory/catalog`, `/inventory/export.csv`, `/inventory/import-template.csv` | viewer |
| `POST /inventory/devices`, `PATCH,DELETE /inventory/devices/{id}`, `POST …/approve`, `…/suspicious`, `…/software`; `DELETE …/software/{sid}`; `PUT /inventory/notify-new`; `POST /inventory/import` | operator |
| `GET,PUT /inventory/settings` | admin |

## Tables owned (`inv_`)
`inv_asset`, `inv_observation`, `inv_service`, `inv_software`, `inv_setting` (dải, cửa sổ, xác nhận phạm vi, loại mong manh), `inv_meta` (suspicious, regular_scan, notify_new).

## Events
- **Phát**: `inventory.asset.discovered {asset_id}`, `inventory.asset.updated`, `inventory.asset.deleted {asset_id}`, `inventory.software.changed {asset_id}`, `inventory.match.changed {asset_id, cve, basis}`, `inventory.settings.changed {scope}`.
- **Nhận**: `feeds.vuln.new_kev`, `feeds.vuln.updated` (khớp lại).

## Behaviour khi tắt
Không route; Devices trống; `sensor-*`/`agent-intake` mất nơi ghi (chúng phụ thuộc, `affected`); `findings` không có finding mới; `scan` không mục tiêu nội bộ; "Do you have it?" thành `null`; honeypot/logs không tra tên thiết bị. Dữ liệu giữ.

## Story và quyết định
S-INV-1, 2, 3, 5; D-30 danh mục, D-32 tiền tố, D-45 mong manh, D-53 hộp là thiết bị đầu tiên.

## Không khớp / câu hỏi mở
- `SettingsSaved.adjusted` ("192.168.18.0 → /24") mâu thuẫn D-32 và mock (từ chối `no_prefix`). Hợp đồng theo D-32; bỏ `adjusted`.
- ~~ARCHITECTURE §4 xếp ưu tiên nguồn; GUI dùng "khai tay > tin cậy cao > mới hơn"~~ Đã thống nhất theo DATA_MODEL §5.1: manual > agent > snmp > nmap = scan > passive, rồi `confidence`, `seen_at`, `id` (mock `markCurrent` đã sửa, WP-06).
- Danh mục ~880 mục là fixture biên dịch sẵn hay dựng từ `feeds`? Khi `feeds` tắt dùng gì?
- Cửa sổ quét ở `inventory` (gói/giây) và `scan` (request/giây): hai cấu hình riêng, chưa gộp; ngày đã thống nhất 1..7 (D-57 (9)).
