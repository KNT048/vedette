# Sensor-active Contract

> Tier: standard · Story: S-INV-1, S-SCAN-4 (cửa sổ giờ, tốc độ, loại trừ cho khám phá) · Last verified: 2026-11-09 (docs-first, chưa có code)

Không có endpoint riêng: cấu hình nằm ở `GET/PUT /inventory/settings` và `PATCH /inventory/devices/{id}` (module `inventory`). Module này **thực thi** chính sách đó. Nguồn hành vi: `web/src/features/inventory/{contract,mocks}.ts`.

## Invariants
- **INV-1**: `sensor-active` không bao giờ gửi gói tới IP ngoài `lan_ranges` đã lưu hoặc nằm trong `exclusions` (SYS-7). Mọi mục tiêu đi qua `inventory.InScope(ip)` ngay trước khi dựng argv. `TestContract_INV1_NeverOutsideScope`
- **INV-2**: Không quét khi `active.enabled=false` hoặc `scope_confirmed_at=null`; không quét khi `lan_ranges` rỗng.
- **INV-3**: Chỉ chạy trong cửa sổ (`days` 1..7, `from`–`to`, có thể qua nửa đêm); việc đang chạy dừng khi hết cửa sổ; ngoài cửa sổ `ScanDevice` bị từ chối trừ quét nhẹ lần đầu của thiết bị mong manh (xem INV-5; ⚠ chưa chốt, câu hỏi mở).
- **INV-4**: Tốc độ không vượt `rate` gói/giây (truyền thành `--max-rate`); argv dựng từ `netip`, số nguyên và cờ allowlist, không bao giờ qua shell (SYS-1, SYS-2).
- **INV-5**: Thiết bị mong manh (D-45): quét nhẹ đúng một lần ở tốc độ thấp nhất khi thấy lần đầu, ghi `first_scan_at`; sau đó chỉ khi `ScanPolicy` cho phép (`regular_scan=allow` hoặc loại ∈ `regular_scan_kinds`); `never` thắng. Thiết bị khai tay không bao giờ bị quét.
- **INV-6**: Nmap chạy trong container `scan` với đúng `CAP_NET_RAW`; binary là gói OS ghim phiên bản, không ship cùng Vedette. Thiếu binary ⇒ `Health` = unavailable với thông điệp rõ, không có đường lùi.
- **INV-7**: Đầu ra nmap (XML), banner, `sysDescr` là dữ liệu không tin cậy (SYS-6): parser fail-closed, giới hạn kích thước; chuỗi chỉ lưu như văn bản.
- **INV-8**: Quan sát ghi `source ∈ {nmap, snmp}` với `confidence` theo kết quả (Recog khớp = sản phẩm + phiên bản có độ tin cậy < 1), qua `inventory.RecordObservation/UpsertSoftware`.
- **INV-9**: Mỗi lần thăm dò ghi một dòng nhật ký (thời điểm, đích, tham số đã duyệt, kết quả) giữ ≥ 90 ngày, xuất ở danh mục `scan_probes` của `/core/logs/export` (legal.md: probe ghi log).
- **INV-10**: SNMP chỉ đọc `sysDescr`; thông tin xác thực SNMP qua `core/secrets`.

## Preconditions / Postconditions
- **PRE-1** (`DiscoverRanges(ctx)`): INV-2, INV-3 đúng. **POST-1**: mỗi IP trong phạm vi được thăm dò tối đa một lần/lượt; kết quả vào `inventory`; sự kiện `sensor.scan.finished {job_id, targets, new_devices}`.
- **PRE-2** (`ScanDevice(ctx, assetID, reason)`): `ScanPolicy.allowed=true`. **POST-2**: `first_scan_at` đặt nếu là lần đầu của thiết bị mong manh; nếu bị chặn, phát `sensor.scan.blocked {asset_id, reason}`, không gói nào được gửi.
- **PRE-3** (hết cửa sổ giữa chừng). **POST-3**: tiến trình nmap bị kết thúc, kết quả đã có vẫn lưu, job đánh dấu dừng.

## Forbidden
- **FORBID-1**: Quét IP ngoài `inventory` scope; quét dải công cộng (đó là việc của `exposure`).
- **FORBID-2**: Quét khi chưa có xác nhận phạm vi.
- **FORBID-3**: Gọi nmap bằng chuỗi lệnh shell; thêm cờ ngoài allowlist.
- **FORBID-4**: Ship hoặc nhúng nmap (NPSL, D-4).
- **FORBID-5**: Quét lặp định kỳ thiết bị mong manh khi chưa được phép.
- **FORBID-6**: Chạy khai thác hoặc script NSE nguy hiểm (chỉ `-sV -O` và phát hiện dịch vụ).

## Dependencies
- **DEPENDS ON**: `core` (exec, jobs, secrets), `inventory` (`InScope`, `ScanPolicy`, `RecordObservation`).
- **DEPENDED ON BY**: không module nào phụ thuộc cứng; `scan` đọc kết quả qua `inventory`.

## Endpoints owned
Không có. Dùng `GET/PUT /inventory/settings` (admin), `PATCH /inventory/devices/{id}` (operator) của `inventory`.

## Tables owned (`sa_`)
`sa_job` (lượt khám phá: bắt đầu, kết thúc, trạng thái, số mục tiêu), `sa_probe` (nhật ký thăm dò), `sa_snmp` (thông tin xác thực SNMP, ghi qua `core/secrets`).

## Events
- **Phát**: `sensor.scan.started|finished|blocked`.
- **Nhận**: `inventory.asset.discovered` (quét nhẹ lần đầu), `inventory.settings.changed` (đổi dải/cửa sổ), `core.module.disabled`.

## Behaviour khi tắt
Không job, không tiến trình nmap/SNMP; thiết bị chỉ có dữ liệu thụ động/agent/khai tay (thiếu OS, dịch vụ, phiên bản); thiết bị mong manh mới không được quét lần đầu. `scan` vẫn chạy với dữ liệu hiện có nhưng ít phát hiện sản phẩm hơn.

## Story và quyết định
S-INV-1, S-SCAN-4. D-4 nmap tiến trình riêng; D-26 xác nhận phạm vi; D-32 tiền tố; D-45 mong manh; D-55 container `scan`.

## Không khớp / câu hỏi mở
- Cấu hình SNMP (community/v3) chưa có trong GUI (`contract.ts` không có endpoint).
- Quét nhẹ lần đầu có được chạy ngoài cửa sổ giờ không? D-45 không nói.
- Thiết bị `approved=false` có bị nmap quét để phân loại không (hợp đồng này cho phép; `scan` thì không, `reason: unapproved`)?
- Hai cửa sổ giờ: `inventory.active` (ngày 1..7, gói/giây) và `scan.config.window` (ngày 0..6, request/giây).
- `MODULES.md` ghi bảng `inv_*`; đề xuất `sa_` và ghi qua `inventory`.
