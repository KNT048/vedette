# Scan Contract

> Tier: optional · Story: S-SCAN-1…4 · Last verified: 2026-11-10 (WP-23 phần 2 lát S3: cấu hình, mục tiêu, lượt quét, dừng, nhật ký probe; S4 jobs, S5 engine từ xa)

Nguồn hành vi: `web/src/features/scan/{contract,mocks}.ts`. Phần `/scans/credentialed*` trong cùng `contract.ts` thuộc module `scan-credentialed`.

## Invariants
- **INV-1**: Mục tiêu trong: `inventory` `lan_ranges` ∖ `exclusions` ∖ `scan.config.exclusions`, `approved`, và `inventory.VulnScanPolicy(asset, explicit)` (D-126; không phải `ScanPolicy` của quét dò, công tắc `scanning_off` không áp). Luôn từ chối: hộp (`box`), `regular_scan=never` (`regular_scan_never`), không IP, ngoài phạm vi. Thiết bị mong manh, chưa phân loại (`kind=unknown`) và khai tay chỉ được quét khi người dùng **chọn tay** trong "Scan now" (`explicit=true`, ghi `core_audit` kèm người bấm); mong manh và chưa phân loại chạy ở `max(1, rate/4)` (`fragile=true` trên `ScanTarget` cho cả hai); quét lịch và quét lại KEV bỏ qua chúng (dòng kết quả `skipped` kèm lý do). Các thiết bị này mang `pick_only=true` trên `ScanTarget`; GUI **không bao giờ tick sẵn** chúng (không theo "có phát hiện", không theo "Select all"/"Only devices with findings", không theo `?target=`), nên mọi id trong `POST /scans/runs` là do người dùng tự tick và backend coi mỗi id là một lần chọn (supervisor 2026-11-10). Mục tiêu ngoài (`exposure`) được liệt kê nhưng **chưa quét ở bản này** (`not_supported`; deferred). Mỗi mục tiêu được kiểm lại ngay trước khi gửi job: không còn đủ điều kiện → bỏ, không gửi. Lý do không chọn được: `unapproved | excluded | out_of_scope | box | regular_scan_never | unverified | expired | not_supported`. `TestContract_INV1_TargetsInScope`, `TestContract_INV1_PolicyD126`
- **INV-2**: Không quét nếu `inventory.scope_confirmed_at=null` (400 `commitment_required`; `can_scan=false`, `block_reason`). Mục tiêu ngoài: gọi `exposure.CheckScannable` ngay trước lần quét (SYS-7). Máy quét không sẵn sàng (không heartbeat của worker `scan`, hoặc heartbeat báo thiếu nuclei hay gói mẫu; D-125 (5)): `can_scan=false` kèm `block_reason`, `POST /scans/runs` → 503 `scanner_unavailable`, job lịch và quét lại KEV không gửi gì (sự kiện ở lại chờ).
- **INV-3**: Một lần chạy tại một thời điểm (409 `already_running`); mỗi `POST /scans/runs` có 1…200 mục tiêu (400 `no_targets`/`too_many`); id lạ 400 `unknown_target`; mục tiêu không chọn được 400 `out_of_scope`.
- **INV-4**: An toàn: chỉ template Nuclei thuộc tập `kev,vkev` ∩ tag an toàn trong gói nội dung ký; không khai thác, không DoS. `dangerous_checks` luôn `false`; `PUT /scans/config` với `true` → 400 `dangerous_locked`. nuclei là binary ghim trong image `vedette-scan`, chạy ở worker qua giao thức sensor (D-125); job chỉ mang id mẫu và hash gói, argv dựng và kiểm bởi `modules/scan/nucleiargv`. Văn phạm của worker (`nucleiargv`, rào cuối khi `core` bị chiếm, D-113 (3)) hẹp như `nmapargv`: chỉ IPv4 riêng dạng số (RFC 1918, không .0/.255), không tên miền, không IP công cộng; giao thức chỉ `-pt http,tcp,ssl` (không dns/whois/javascript/websocket/headless/code/file), `-dr` (không theo chuyển hướng), `-nh` (không dò httpx), `-ni`, `-duc`; mỗi mẫu là một `-t <TemplatesDir>/<path>` lấy từ chỉ mục đã kiểm (không nạp cả thư mục). Worker chạy nuclei với môi trường sạch: không `ENABLE_CLOUD_UPLOAD`, `PDCP_API_KEY`, `*_PROXY`, không `~/.config/nuclei` (HOME trên tmpfs), thư mục làm việc rỗng chỉ đọc (rà soát bảo mật S2, 2026-11-10).
- **INV-5**: Cấu hình: `window.days ∈ 1..7` (1=Thứ Hai, 7=Chủ Nhật; D-57 (9)) ít nhất một ngày, `from/to` HH:MM; `rate ∈ 1..20` request/giây; `exclusions` ≤ 200 IP/CIDR; `unresponsive_after ∈ 2..20`; `schedule {enabled, frequency daily|weekly, weekday, at}`. Sai → 400 `invalid_config`.
- **INV-6**: Tự dừng: khi `stop_on_unresponsive` và một thiết bị không phản hồi `unresponsive_after` lần liên tiếp, lượt quét chuyển `auto_stopped` với `stop_reason`; thiết bị đó không bị tiếp tục dồn request. "Stop now": trạng thái `stopping` rồi `stopped` trong ≤ 5 giây; dừng lượt đã kết thúc → 409 `not_running`.
- **INV-7**: Mỗi request thăm dò ghi `ProbeEntry {ts, run_id, ip, label, template, request, result}` **trước** khi job rời `core` (cùng giao dịch xếp job), `result ∈ matched|not_matched|no_response|banner|stopped` (`stopped`: đang trên đường khi bấm "Dừng ngay"), giữ ≥ 90 ngày (`retention_days`), tải được dạng CSV; ghi cả khi bị dừng. Một dòng mỗi (thiết bị, mẫu); dòng còn đang gửi có `result=NULL`: `GET /scans/probes` chưa liệt kê, CSV ghi `in_progress`; khởi động lại giữa lượt thì dòng đó thành `stopped` (lượt mồ côi được đóng trước lượt kế tiếp). CSV chặn công thức bảng tính (ô bắt đầu bằng `= + - @`, tab, CR được thêm `'`).
- **INV-8**: Kết quả mỗi thiết bị thuộc `matched | not_matched | not_applicable | no_template | no_response | skipped`. "Xác nhận có" (`matched`) tách khỏi "nghi theo phiên bản": chỉ `matched` gọi `findings.ConfirmFromScan` và mang `finding_id`, bằng chứng rút gọn (request/response), `confidence`, cách tự kiểm tra lại (S-SCAN-3). `scan` gọi thẳng `findings.ConfirmFromScan`/`RescanClear` qua cổng `Findings` (lấy `finding_id` ngay, lỗi được ghi log) và vẫn phát `scan.finding.confirmed` cho bên khác; `findings` không đăng ký sự kiện đó (tránh xác nhận hai lần). Mẫu được chọn theo finding của thiết bị ∩ gói mẫu; CVE không có mẫu → `no_template`, không gói nào rời hộp; bằng chứng: request ≤ 2 KiB, response ≤ 4 KiB, UTF-8 hợp lệ, bỏ ký tự điều khiển/bidi, `summary` có câu "To check it yourself, run: nuclei -t … -u …". Một mẫu trên một thiết bị: một dòng khớp là đủ (`matched`); "không khớp" chỉ khi có dòng trả lời không lỗi; mẫu cần tương tác ngoài băng (tag `oast`) bị gói từ chối nên với `-ni` không bao giờ có "không khớp" giả. Câu tự kiểm tra dùng chính đích của job đã khớp (`-t <path> -u <input>`), không bao giờ dùng trường của output (rà soát bảo mật S2, L3, L7).
- **INV-9**: Quét lại theo KEV (S-SCAN-2): khi `feeds.vuln.new_kev` có `has_template` và mẫu có trong gói đã cài, chỉ quét tài sản liên quan trong ≤ 60 phút nếu `auto_rescan=true`; mỗi sự kiện ghi `RescanEvent {cve, product, devices, latency_min, run_id, result ∈ matched|clear|skipped_off|no_match}`. `auto_rescan=false` ⇒ ghi `skipped_off`, không quét. Không chịu cửa sổ giờ (D-126 (3)); quét theo lịch thì chịu.
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
`scan_setting` (một dòng, cột có CHECK như `exp_setting`), `scan_run` (kết quả từng thiết bị là JSON trong dòng, DATA_MODEL phụ lục A), `scan_probe`, `scan_event`.

## Events
- **Phát**: `scan.run.started|finished|stopped {run_id, status, matched}`, `scan.finding.confirmed {asset_id, cve, template, evidence}` (thông tin; `findings` được gọi thẳng, INV-8). `scan.rescan.triggered` chưa phát: chưa có bên nhận (lát S4 ghi `scan_event`).
- **Nhận**: `feeds.vuln.new_kev`, `inventory.settings.changed`, `inventory.asset.deleted`, `exposure.target.expired`.

## Behaviour khi tắt
Không route `/scans*`, không job lịch/quét lại; không probe nào. Findings chỉ còn `suspected` (không xác nhận mới); "Scan" mất ở Devices. Cấu hình, lịch sử, nhật ký probe giữ ≥ 90 ngày.

## Story và quyết định
S-SCAN-1…4. **Seam của máy quét (SP-3b, D-133)**: `sensoractive.Scanner` (`Ready`, `RunNuclei(ctx, NucleiRequest) ([]nucleiout.Result, error)`) do `*sensoractive.Dispatcher` hiện thực; `scan.Engine.Ready` được nó thoả nguyên văn, còn bước chạy do adapter ở `cmd/vedette` nối (S5/SP-5); `ErrScannerUnavailable` → 503 `scanner_unavailable`. D-4 công cụ; D-26 cam kết; D-45 mong manh; D-55 container `scan`; D-113 giao thức job; D-125 nuclei là binary trong container `scan`; D-126 chính sách quét lỗ hổng và cửa sổ của quét lại KEV.

## Không khớp / câu hỏi mở
- ~~Cửa sổ giờ `scan` (ngày 0..6)~~ Đã thống nhất ngày 1..7 (Thứ Hai=1) theo D-57 (9); GUI/mock đã khớp.
- ~~`no_commitment`: `scan` 400, `exposure` 409~~ Đã thống nhất: `400 commitment_required` (D-57 (10)).
- ~~Quét lại theo KEV có chịu cửa sổ giờ không~~ Không (D-126 (3)); quét lịch thì chịu, "Scan now" chạy ngay.
- ~~Thiết bị mong manh có bị quét khi chọn tay không~~ Có, ở một phần tư tốc độ; cả chưa phân loại và khai tay; lịch và KEV không (D-126 (2)).
- Mục tiêu ngoài và `exposure.Runner` để lát sau (D-126 (4)); GUI nói rõ "chưa quét".
- Hai nơi ghi nhật ký probe (`scan_probe`, `sa_probe`) cùng danh mục xuất `scan_probes`.

## Rà soát bảo mật S3 (2026-11-10)
- Chọn tay tính theo **từng thiết bị** (M1): chỉ id đang `pick_only` lúc `StartRun` mới mang lần chọn (`scan_run.picked`); mọi thiết bị khác của lượt được kiểm lại như lượt tự động, nên thiết bị bị đánh dấu mong manh giữa lượt "Select all" bị bỏ qua. GUI lọc lựa chọn theo danh sách mỗi lần làm mới; chỉ tick tay giữ thiết bị `pick_only`. Mỗi lần chọn là một dòng `scan.pick` trong `core_audit`; dòng `scan.start` ghi số đích, số thiết bị chọn tay và tiền tố SHA-256 của cả danh sách (L2).
- Sau "Dừng ngay", lượt có thể hiện `stopped` trong 5 giây trước khi worker xác nhận, nhưng không lượt mới nào bắt đầu tới khi lời gọi engine trả về (M2, 409 `already_running`).
- Bằng chứng không chứa tên thiết bị (đến từ mạng); câu tự kiểm tra chỉ dựng từ đường dẫn mẫu đã kiểm, địa chỉ qua văn phạm argv và đầu vào của job (M3).
- Lượt bị khởi động lại bỏ dở được đóng ngay khi module chạy (job `recover`); khi Vedette tắt, `Close` dừng lượt đang chạy và chờ nó (M4).
- Địa chỉ dùng cho job phải đúng địa chỉ inventory đã quyết định; khác → bỏ qua (L1). Một job 15 phút không được kiểm lại giữa chừng.
- Phát hiện đã bị người đóng (`false_positive`, `not_relevant`, `patched`) không bị thăm dò lại; `mitigated` vẫn được quét lại để kiểm tra biện pháp (L3).
- Probe còn mở khi lượt kết thúc được đóng trong `finish` (L4). Thiết bị quá 15 phút có lý do riêng (L5). Thiết bị bị xoá giữa lúc dựng danh sách thì rời danh sách (L6).
