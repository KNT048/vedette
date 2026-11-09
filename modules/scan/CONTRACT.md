# Scan Contract

> Tier: optional · Story: S-SCAN-1…4 · Last verified: 2026-11-09 (docs-first, chưa có code)

Nguồn hành vi: `web/src/features/scan/{contract,mocks}.ts`. Phần `/scans/credentialed*` trong cùng `contract.ts` thuộc module `scan-credentialed`.

## Invariants
- **INV-1**: Mục tiêu quét ⊆ (`inventory` `lan_ranges` ∖ `exclusions` ∖ `scan.config.exclusions`) ∪ mục tiêu `exposure` đang `scannable`. Mỗi mục tiêu được kiểm lại ngay trước khi gửi request: ngoài phạm vi → bỏ, không gửi. Lý do không chọn được: `unapproved | excluded | out_of_scope | unverified | expired`. `TestContract_INV1_TargetsInScope`
- **INV-2**: Không quét nếu `inventory.scope_confirmed_at=null` (400 `no_commitment`; `can_scan=false`, `block_reason`). Mục tiêu ngoài: gọi `exposure.CheckScannable` ngay trước lần quét (SYS-7).
- **INV-3**: Một lần chạy tại một thời điểm (409 `already_running`); mỗi `POST /scans/runs` có 1…200 mục tiêu (400 `no_targets`/`too_many`); id lạ 400 `unknown_target`; mục tiêu không chọn được 400 `out_of_scope`.
- **INV-4**: An toàn: chỉ template Nuclei thuộc tập `kev,vkev` ∩ tag an toàn trong gói nội dung ký; không khai thác, không DoS. `dangerous_checks` luôn `false`; `PUT /scans/config` với `true` → 400 `dangerous_locked`.
- **INV-5**: Cấu hình: `window.days ∈ 0..6` (0=Chủ Nhật) ít nhất một ngày, `from/to` HH:MM; `rate ∈ 1..20` request/giây; `exclusions` ≤ 200 IP/CIDR; `unresponsive_after ∈ 2..20`; `schedule {enabled, frequency daily|weekly, weekday, at}`. Sai → 400 `invalid_config`.
- **INV-6**: Tự dừng: khi `stop_on_unresponsive` và một thiết bị không phản hồi `unresponsive_after` lần liên tiếp, lượt quét chuyển `auto_stopped` với `stop_reason`; thiết bị đó không bị tiếp tục dồn request. "Stop now": trạng thái `stopping` rồi `stopped` trong ≤ 5 giây; dừng lượt đã kết thúc → 409 `not_running`.
- **INV-7**: Mỗi request thăm dò ghi `ProbeEntry {ts, run_id, ip, label, template, request, result}`, giữ ≥ 90 ngày (`retention_days`), tải được dạng CSV; ghi cả khi bị dừng.
- **INV-8**: Kết quả mỗi thiết bị thuộc `matched | not_matched | not_applicable | no_template | no_response | skipped`. "Xác nhận có" (`matched`) tách khỏi "nghi theo phiên bản": chỉ `matched` gọi `findings.ConfirmFromScan` và mang `finding_id`, bằng chứng rút gọn (request/response), `confidence`, cách tự kiểm tra lại (S-SCAN-3).
- **INV-9**: Quét lại theo KEV (S-SCAN-2): khi `feeds.vuln.new_kev` có `has_template`, chỉ quét tài sản liên quan trong ≤ 60 phút nếu `auto_rescan=true`; mỗi sự kiện ghi `RescanEvent {cve, product, devices, latency_min, run_id, result ∈ matched|clear|skipped_off|no_match}`. `auto_rescan=false` ⇒ ghi `skipped_off`, không quét.
- **INV-10**: Phản hồi từ thiết bị ngoài/trong là dữ liệu không tin cậy (SYS-6): bằng chứng cắt ngắn theo trần cố định, lưu như văn bản, escape khi hiển thị.
- **INV-11**: `scope.commitment` chỉ đọc từ `inventory`; `scan` không tự ghi cam kết.

## Preconditions / Postconditions
- **PRE-1** (`StartRun(targets, trigger)`): INV-1…3; `operator` cho `manual`. **POST-1**: `ScanRun {status:running, total, done:0}`; `core_audit` ghi người bắt đầu; tiến độ poll 1 giây được.
- **PRE-2** (`StopRun(id)`): `operator`, lượt đang `running|stopping`. **POST-2**: không request mới sau khi `stopped`; kết quả đã có giữ.
- **PRE-3** (`PUT /scans/config`): `admin`, INV-5. **POST-3**: lưu một phần (`partial`); `next_run` tính trong cửa sổ.
- **PRE-4** (`OnNewKEV(ev)`): `auto_rescan` và `has_template`. **POST-4**: lượt `trigger=new_kev` với `trigger_note` hoặc ghi `skipped_off`.

## Forbidden
- **FORBID-1**: Quét mục tiêu ngoài phạm vi hoặc chưa xác nhận; quét khi chưa có cam kết phạm vi.
- **FORBID-2**: Template ngoài tập an toàn; bật `dangerous_checks`.
- **FORBID-3**: Chạy hai lượt đồng thời; vượt `rate`.
- **FORBID-4**: Ghi trực tiếp bảng `inv_*`, `mit_*`, `exp_*` (qua interface).
- **FORBID-5**: Gửi kết quả quét ra ngoài hộp.

## Dependencies
- **DEPENDS ON**: `core`, `inventory` (phạm vi, chính sách), `feeds` (`has_template`, KEV mới). Tuỳ chọn: `exposure` (mục tiêu ngoài), `findings` (finding), `notify` (qua `findings`).
- **DEPENDED ON BY**: `scan-credentialed` (cửa sổ/phạm vi), `mitigation` (xác nhận), `reports`.

## Endpoints owned (role tối thiểu)
| Route | Vai |
|---|---|
| `GET /scans/config`, `/scans/targets`, `/scans/runs`, `/scans/probes`, `/scans/probes.csv`, `/scans/events` | viewer |
| `POST /scans/runs`, `POST /scans/runs/{id}/stop` | operator |
| `PUT /scans/config` | admin |

## Tables owned (`scan_`)
`scan_config`, `scan_run`, `scan_result`, `scan_probe`, `scan_event`.

## Events
- **Phát**: `scan.run.started|finished|stopped {run_id, status, matched}`, `scan.finding.confirmed {asset_id, cve, template, evidence}`, `scan.rescan.triggered {cve, devices}`.
- **Nhận**: `feeds.vuln.new_kev`, `inventory.settings.changed`, `inventory.asset.deleted`, `exposure.target.expired`.

## Behaviour khi tắt
Không route `/scans*`, không job lịch/quét lại; không probe nào. Findings chỉ còn `suspected` (không xác nhận mới); "Scan" mất ở Devices. Cấu hình, lịch sử, nhật ký probe giữ ≥ 90 ngày.

## Story và quyết định
S-SCAN-1…4. D-4 công cụ; D-26 cam kết; D-45 mong manh; D-55 container `scan`.

## Không khớp / câu hỏi mở
- Cửa sổ giờ `scan` (ngày 0..6, Chủ Nhật=0) khác `inventory.active`/bảo trì OS (ngày 1..7, Thứ Hai=1).
- `no_commitment`: `scan` 400, `exposure` 409.
- Quét lại theo KEV và quét theo lịch có bị ràng buộc cửa sổ giờ không (GUI chỉ nói cho lượt thủ công)?
- Thiết bị mong manh (D-45) có bị Nuclei quét khi người dùng chọn tay không? GUI chỉ gắn cờ `fragile`.
- Hai nơi ghi nhật ký probe (`scan_probe`, `sa_probe`) cùng danh mục xuất `scan_probes`.
