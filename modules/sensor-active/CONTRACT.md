# Sensor-active Contract

> Tier: standard · Story: S-INV-1, S-SCAN-4 (cửa sổ giờ, tốc độ, loại trừ cho khám phá) · Last verified: 2026-11-09 (WP-12: code + test; SNMP chưa xây, D-84)

Không có endpoint riêng: cấu hình nằm ở `GET/PUT /inventory/settings` và `PATCH /inventory/devices/{id}` (module `inventory`). Module này **thực thi** chính sách đó. Nguồn hành vi: `web/src/features/inventory/{contract,mocks}.ts`. Các quyết định mở của hợp đồng này đã chốt ở **D-84**.

Module không import module khác: kho thiết bị đi qua cổng `sensoractive.Inventory` và `core/observe` (adapter ở `cmd/vedette/sensoractive.go`). nmap chạy chỉ qua `core/exec` (tên `nmap`, đường dẫn tuyệt đối, `ValidateNmapArgs` kiểm lại cả argv).

## Invariants
- **INV-1**: `sensor-active` không bao giờ gửi gói tới IP ngoài `lan_ranges` đã lưu hoặc nằm trong `exclusions` (SYS-7). Mọi mục tiêu đi qua `inventory.InScope(ip)` ngay trước khi vào argv (quét dò: từng địa chỉ của lô; quét thiết bị: địa chỉ của nó); đổi phạm vi giữa chừng thì `SettingsChanged` kiểm lại các địa chỉ đang chạy và dừng. Host nmap báo ngoài danh sách đã hỏi bị bỏ, không ghi. `TestContract_INV1_NeverOutsideScope`, `TestContract_INV1_ReportedHostsOutsideTheRunAreIgnored`, `TestContract_INV1_ExclusionAddedMidRunStopsIt`
- **INV-2**: Không quét khi `active.enabled=false` hoặc `scope_confirmed_at=null`; không quét khi `lan_ranges` rỗng (cả quét dò lẫn quét thiết bị; ngoài ra `ScanPolicy` của kho cũng chặn). `TestContract_INV2_NothingWithoutScopeAndSwitch`
- **INV-3**: Chỉ chạy trong cửa sổ (`days` 1..7 thứ Hai = 1, `from`–`to` theo giờ cục bộ của hộp, có thể qua nửa đêm: cửa sổ thuộc ngày bắt đầu); **không có ngoại lệ ngoài cửa sổ, kể cả quét nhẹ lần đầu của thiết bị mong manh** (D-84 (1)). Hạn mỗi lần chạy nmap = min(hết cửa sổ, 2 giờ); hết hạn hoặc đổi cài đặt không còn cho phép → giết nhóm tiến trình ngay. `TestContract_INV3_OnlyInsideTheWindow`, `TestContract_INV3_StopsWhenTheWindowCloses`, `TestContract_INV3_SettingsChangeStopsTheRunningScan`, `TestWindow`
- **INV-4**: Tốc độ không vượt `rate` gói/giây (`--max-rate`; quét thiết bị lấy min(quyết định của kho, `rate`)); argv dựng từ `netip.Addr`, số nguyên và cờ allowlist, không bao giờ qua shell (SYS-1, SYS-2); `ValidateNmapArgs` kiểm lại toàn bộ argv trước khi tiến trình chạy. `TestContract_INV4_RateAndFlags`, `TestBuildNmapArgs`, `TestValidateNmapArgs`, `FuzzValidateNmapArgs`
- **INV-5**: Thiết bị mong manh (D-45): quét nhẹ đúng một lần ở tốc độ thấp nhất (`--max-rate 1`, không `-O`, không NSE) khi thấy lần đầu, **trong cửa sổ kế tiếp**; `first_scan_at` chỉ đặt khi lần quét chạy xong (nmap lỗi thì thử lại); sau đó chỉ khi `ScanPolicy` cho phép (`regular_scan=allow` hoặc loại ∈ `regular_scan_kinds`); `never` thắng. Thiết bị khai tay không bao giờ bị quét. Thiết bị `approved=false` trong phạm vi vẫn được quét khám phá (D-84 (2)). `TestContract_INV5_*`, và `TestSensorActiveFragileDevicePolicy`, `TestSensorActiveScansADiscoveredDevice` (kho thật) ở `cmd/vedette`
- **INV-6**: nmap là gói OS (`/usr/bin/nmap`), không ship cùng Vedette; chạy với `--privileged` nhờ `CAP_NET_RAW` (WP-08 cấp cho container; ở WP-12 nmap chạy từ tiến trình core, D-84 (5)). Thiếu binary hoặc không thực thi được ⇒ `Service.Health` = `unavailable` với thông điệp rõ, mọi lần chạy trả `ErrUnavailable`, job `window-tick` báo lỗi vào lịch sử job; không có đường lùi. `TestContract_INV6_MissingNmapIsUnavailable`
- **INV-7**: Đầu ra nmap (XML) là dữ liệu không tin cậy (SYS-6): đọc theo luồng, trần `MaxOutput` 8 MiB (`Truncated` → bỏ cả lô), giới hạn độ sâu 12, thuộc tính 24, host 256, cổng 1500, directive chỉ `DOCTYPE nmaprun`, charset khác UTF-8 bị từ chối, tài liệu cụt bị từ chối; lỗi giới hạn thì bỏ cả lô, không cắt cho vừa; chuỗi chỉ lưu như văn bản in được ≤ 200 ký tự. `TestContract_INV7_UntrustedOutputIsDiscarded`, `TestParseRefusesBadOutput`, `FuzzParseNmapXML`
- **INV-8**: Quan sát ghi `source=nmap` với `confidence` < 1 (độ chính xác OS của nmap × 0,95; `conf` dịch vụ 1..10 × 0,095; kiểu thiết bị ×0,8), qua `core/observe` (`Record`, `ReplaceSoftware`): hostname/vendor/os/kind, phần mềm từ `<cpe>` của dịch vụ và OS (không có CPE thì tên sản phẩm đứng cho hãng). Quét dò ghi MAC và hãng của host trả lời; host không có MAC (ngoài đoạn mạng) không ghi được vì `core/observe` không có trường "đã thấy IP" (deferred). `source=snmp` **chưa xây** (D-84 (3)). `TestContract_INV8_ObservationsAndSoftwareFromTheScan`, `TestSoftwareAndObservations`
- **INV-9**: Mỗi lần chạy nmap ghi một dòng `sa_probe` (thời điểm, đích, argv đã duyệt dạng JSON, kết quả, job), **ghi trước khi tiến trình chạy**, kết quả cập nhật sau; giữ 365 ngày (≥ 90), job `prune-probes` hằng ngày xoá cũ hơn. `Service.Probes(since, limit)` là phương thức đọc cho danh mục `scan_probes` của `/core/logs/export` (chưa đăng ký: `logexport.Register` chưa có, deferred). `TestContract_INV9_ProbeLog`, `TestProbeRowExistsWhileTheRunIsInProgress`
- **INV-10**: SNMP chỉ đọc `sysDescr`; thông tin xác thực qua `core/secrets`. **Chưa xây** (D-84 (3)): không có màn hình/endpoint nhập (gui-first). Không có `sa_snmp`, không có gói SNMP nào được gửi.

## Preconditions / Postconditions
- **PRE-1** (`DiscoverRanges(ctx)`): INV-2, INV-3 đúng, nmap có mặt. **POST-1**: mỗi IP trong phạm vi (trừ địa chỉ mạng/quảng bá của dải rộng hơn /31) được thăm dò tối đa một lần/lượt, theo lô ≤ 64; cài đặt và cửa sổ đọc lại trước mỗi lô; kết quả vào `inventory`; sự kiện `sensor.scan.finished {job_id, targets, new_devices, status}`.
- **PRE-2** (`ScanDevice(ctx, assetID, reason)`): `ScanPolicy.allowed=true`, cửa sổ đang mở, địa chỉ còn trong phạm vi. **POST-2**: `first_scan_at` đặt nếu là lần đầu của thiết bị mong manh; nếu bị chặn, phát `sensor.scan.blocked {asset_id, reason}`, không gói nào được gửi.
- **PRE-3** (hết cửa sổ giữa chừng, đổi cài đặt không còn cho phép, tắt module). **POST-3**: nhóm tiến trình nmap bị giết, lô đang chạy bị bỏ, các lô đã xong vẫn lưu, job đánh dấu `stopped` (job còn `running` sau khi khởi động lại được đóng ở lần tick kế tiếp).

## Forbidden
- **FORBID-1**: Quét IP ngoài `inventory` scope; quét dải công cộng (đó là việc của `exposure`).
- **FORBID-2**: Quét khi chưa có xác nhận phạm vi.
- **FORBID-3**: Gọi nmap bằng chuỗi lệnh shell; thêm cờ ngoài allowlist.
- **FORBID-4**: Ship hoặc nhúng nmap (NPSL, D-4).
- **FORBID-5**: Quét lặp định kỳ thiết bị mong manh khi chưa được phép.
- **FORBID-6**: Chạy khai thác hoặc script NSE nguy hiểm (chỉ `-sV -O` và phát hiện dịch vụ).

## Dependencies
- **DEPENDS ON**: `core` (exec, jobs, observe, events), `inventory` (qua cổng `Inventory`: `Settings`, `InScope`, `ScanPolicy`, `MarkFirstScan`, và `core/observe`).
- **DEPENDED ON BY**: không module nào phụ thuộc cứng; `scan` đọc kết quả qua `inventory`.

## Endpoints owned
Không có. Dùng `GET/PUT /inventory/settings` (admin), `PATCH /inventory/devices/{id}` (operator) của `inventory`.

## Tables owned (`sa_`)
`sa_job` (lượt chạy: loại sweep|device, bắt đầu, kết thúc, trạng thái running|done|stopped|failed, số mục tiêu, thiết bị mới, lý do, lỗi), `sa_probe` (nhật ký thăm dò), `sa_queue` (thiết bị chờ quét trong cửa sổ). `sa_snmp` chưa tạo (SNMP chưa xây).

## Events
- **Phát** (sau khi giao dịch ghi xong): `sensor.scan.started {job_id, kind: "sweep"|"device", targets}` (quét dò: `targets` = số địa chỉ của các dải trước khi trừ loại trừ), `sensor.scan.finished {job_id, targets, new_devices, status: "done"|"stopped"|"failed"}`, `sensor.scan.blocked {asset_id, reason}` (reason là lý do của `ScanPolicy`, hoặc `scanning_off`, `scope_not_confirmed`, `out_of_scope`; không gói nào được gửi). Kiểu Go: `StartedEvent`, `FinishedEvent`, `BlockedEvent`. `TestEventPayloads`
- **Nhận** (đăng ký ở `cmd/vedette/sensoractive.go`, chỉ hành động khi module bật): `inventory.asset.discovered` → xếp thiết bị vào hàng đợi `sa_queue`; `inventory.settings.changed` → `SettingsChanged` (dừng lượt đang chạy nếu cài đặt không còn cho phép). Tắt module → `core/jobs` huỷ lượt đang chạy ngay.

## Lịch
`window-tick` mỗi phút: khi cửa sổ mở, chạy **một** lượt quét dò cho mỗi cửa sổ (một lượt `stopped` không tính là đã xong, nên bật module/quét giữa cửa sổ thì chạy), rồi quét lần lượt các thiết bị trong hàng đợi (nmap lỗi thì thử lại tối đa 3 lần, bị chặn bởi chính sách thì bỏ khỏi hàng đợi). `prune-probes` mỗi ngày. Một lần chỉ một tiến trình nmap trên hộp.

## Behaviour khi tắt
Không job, không tiến trình nmap/SNMP; thiết bị chỉ có dữ liệu thụ động/agent/khai tay (thiếu OS, dịch vụ, phiên bản); thiết bị mong manh mới không được quét lần đầu. `scan` vẫn chạy với dữ liệu hiện có nhưng ít phát hiện sản phẩm hơn.

## Story và quyết định
S-INV-1, S-SCAN-4. D-4 nmap tiến trình riêng; D-26 xác nhận phạm vi; D-32 tiền tố; D-45 mong manh; D-55 container `scan`; D-84 chốt các câu hỏi mở của WP-12.

## Đã chốt và còn lại
Đã chốt ở D-84: quét nhẹ lần đầu chờ cửa sổ (1); thiết bị `approved=false` được quét khám phá (2); không SNMP ở WP-12 (3); bảng `sa_` (4); nmap chạy từ tiến trình core, chuyển vào container `scan` ở WP-08 (5); một lượt quét dò mỗi ngày có cửa sổ (6); dòng lệnh (7); `--privileged` (8); giữ nhật ký 365 ngày (9).

Còn lại (ghi ở `.ai/deferred/feat-sensor-active.md`):
- Cấu hình SNMP (community/v3) cần story và màn hình trước (`contract.ts` chưa có endpoint).
- Múi giờ: cửa sổ dùng `time.Local` của hộp; nếu cài đặt chung của `core` thêm múi giờ thì đổi `Service.local()`.
- Hai cửa sổ giờ: `inventory.active` (ngày 1..7, gói/giây) và `scan.config.window` (ngày 1..7, request/giây; cùng quy ước ngày D-57 (9)) vẫn là hai cài đặt riêng.
- Host trả lời nhưng không có MAC (ngoài đoạn mạng) không tạo được thiết bị từ quét dò; thiết bị đã biết trước khi bật module không được quét lại định kỳ (chưa có yêu cầu nhịp).
