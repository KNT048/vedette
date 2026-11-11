# Logs — Change Impact Map

> WP-24 L1, L2 và L3 có mã (L2: gói `listen`, job `syslog`; L3: gói `signature`, bộ đếm chữ ký, digest, job `anomaly`, `Counts`): `Service` (nguồn, sự kiện, lưu giữ, `Ingest`, `Purge`, `ExportDeviceLogs`), `LogsHandlers`, `Jobs`. Phần còn lại là kế hoạch, chốt theo từng lát.

## Modifying: `logs.Service.Ingest(ctx, []Line) (IngestResult, error)` (L1) — người gọi: listener (L2), sau này `sensorlink` (L6)
- Duy nhất đường vào của dòng log. Từ L3 mỗi dòng còn qua `signature.Of` (theo `kind` của nguồn, đọc một lần mỗi lô cùng `sourceKinds`) và cộng vào `logs_signature_daily` / `logs_signature_buckets` trong **cùng** giao dịch (một câu lệnh mỗi khoá; hạn mức riêng cho chữ ký bounded và chữ ký của bộ tìm mẫu): thêm việc vào đường nóng thì đo lại với `-race` (bộ nhớ đệm theo lô làm trận lụt dòng giống nhau chỉ tốn một chữ ký). Ghi **một** giao dịch trên `logs.db` mỗi lô (≤ `MaxBatch`), không bao giờ ghi cơ sở chính (INV-12): đổi sang ghi cơ sở chính là đưa lại rủi ro người ghi bị đói (#159/#160). Dòng của nguồn chưa khai bị bỏ và đếm (FORBID-5). Khi tổng byte vượt `MaxEventBytes`, `Ingest` đánh thức job `purge` (kênh `kick` đệm 1, gộp, không chờ): lượt đó ghi audit vào cơ sở chính (người ghi của core) nên dùng chung với mọi thứ khác; đổi trần hay mức 90% là đổi dung lượng đĩa tối đa của hộp. `Line.At` ngoài [bây giờ − lưu giữ, bây giờ] thành bây giờ: listener không thể ghi dòng cũ hơn lưu giữ. Lượt dọn chỉ chạy trong `Run` của job `purge` (vòng lặp dài, `Housekeeping`: chạy cả khi module tắt, dừng khi tắt máy): đổi `Jobs` hay `kick` là đổi lúc nào dọn chạy, và lịch sử job chỉ có một dòng cho cả thời gian tiến trình chạy. Lần tính lại bộ đếm ở lượt dọn đầu tiên sau khởi động dùng ảnh chụp đọc và không giữ người ghi; khi có lũ lúc khởi động, WAL phình ra trong lúc quét. Đổi `Line`/`IngestResult` = sửa listener. Đổi `sanitizeLine` đổi nội dung lưu và xuất (`device_logs`).

## Modifying: `logs.Service` (nguồn, `Events`, `SetRetention`, `Purge`), `logs.LogsHandlers`, `logs.Jobs`
- **web/features/logs** (mock là hợp đồng): mã lỗi `bad_kind|bad_name|bad_ip|bad_proto|bad_port|duplicate|not_found|bad_window|bad_days` và thông báo của mock; giới hạn mà `contract.ts` nói được bị bộ kiểm sinh trả `invalid` trước (D-73). Danh mục loại nguồn và giao thức cho phép là **một dữ liệu**: `content/logs/kinds.json`, `web/src/features/logs/catalog.ts` phải khớp (`kinds.parity.test.ts`).
- **cmd/vedette**: `logsService` (dùng chung bởi handler, job, xuất log), `logsInventory` (`DevicesOfKind(inventory.Kinds)`: một loại thiết bị mới ngoài `Kinds` thì không được đặt tên trong danh sách nguồn), `logsBox` (đọc `inventory.Settings` và `HostNet`), mở `logs.db` cạnh `vedette.db` trong `run` và `newStackWith`.
- **core/logexport**: nguồn `device_logs` đăng ký ở `registerLogSources`; đổi tên cột của `logs_events` là đổi tệp xuất. `device_logs` có trần riêng `ExportMaxBytes` (32 MiB) và dòng đánh dấu `id: "cut"` ở cuối; đổi trần của core (128 MiB) xuống dưới trần này sẽ làm nguồn này lại gây 413.
- **core (Kiên)**: `POST /core/data/purge` xoá `logs.db` từ danh sách tên tệp dữ liệu module của `cmd/vedette` (D-151); bản sao lưu không chứa nó. **Migration của `logs.db` phải chỉ thêm** (D-151): thêm cột/bảng/chỉ mục, không bao giờ DROP/RENAME/DELETE/UPDATE; `TestVolumeMigrationsAreAddOnly` chặn.

## Modifying: `IocHits(ctx, since time.Time, minConf float64) ([]IocHit, error)` — 3 người gọi
- **response** (sự kiện trigger `ioc_connection`; quy tắc chỉ tự hành động khi độ tin cậy cao): đổi tên/đơn vị `confidence` (0..1 ↔ 0..100; trigger field `confidence` của response là 0..100) → ngưỡng `gte 80` sai. Đổi `seen_via` → mất ngữ cảnh SPAN/syslog.
- **notify** (cảnh báo kết nối xấu): đổi trường → nội dung tin sai.
- **ai** (`ask-my-data`, `log-investigate` qua công cụ chỉ-đọc).

## Modifying: `Digest(ctx) (Digest, error)` — 2 người gọi
- **GUI logs** và **ai** (`log-digest` tóm tắt digest). Đổi cấu trúc `new/spikes/bad_connections` → sinh lại OpenAPI, sửa mock, sửa prompt skill. `new` và `spikes` có thật từ L3 (`NewItem`, `SpikeItem` khớp `contract.ts`; `TestDigestWithItemsOverHTTP` đi qua kiểu sinh của API); `bad_connections` vẫn rỗng tới L4. Đổi hằng số (`WarmUp`, `SpikeFloor`, `SpikeFactor`, `BaselineDays`) là đổi cái người dùng thấy là "bất thường": ghi quyết định.

## Modifying: signature profiles (`modules/logs/data/profiles/*.json`) và `modules/logs/signature` (L3)
- **Chữ ký là khoá của mọi thứ phía sau**: digest, `Counts` (response `log_threshold` lưu chữ ký trong quy tắc), `logs_anomaly_sent`. Đổi luật của một profile hay bộ tìm mẫu làm **mọi chữ ký của loại đó đổi một lần**: digest thấy mọi dòng là "new" (sau 7-8 ngày thì ổn), quy tắc `log_threshold` đang lưu chữ ký cũ ngừng khớp, sự kiện gửi lại. Đổi luật = ghi vào CONTRACT và báo `response`.
- Thêm profile cho một loại: một tệp JSON có `samples` (và `vocab`/bảng id nếu muốn chữ ký được coi là bounded: thiếu từ vựng thì dòng đi vào hạn mức của bộ tìm mẫu) (bộ nạp chạy chúng), `reads` của loại đó trong `content/logs/kinds.json` đổi sang `parsed` và `catalog.ts` khớp (`TestCatalogReadsMatchProfiles`, `kinds.parity.test.ts`); thêm hạt giống fuzz tự có (mẫu của profile đã là hạt giống `FuzzSignature`).
- **Từ vựng là dữ liệu**: thêm một log id FortiGate vào `data/profiles/fortigate.json` làm chữ ký của id đó đổi từ chữ của bộ tìm mẫu sang `logid=… action=…` một lần (quy tắc `log_threshold` đã lưu chữ ký cũ ngừng khớp).
- Gói `signature` không được import `database/sql` hay `core/store` (sẽ chuyển sang sensor cùng `listen`).

## Modifying: `Counts(ctx, source, signature, window) (int, error)` (L3) — 1 người gọi (sau này)
- **response** (`log_threshold`, Kiên): cổng đọc duy nhất vào bộ đếm chữ ký. Cửa sổ [5 phút, 24 giờ], làm tròn ra bucket 5 phút (phủ cả cửa sổ và tối đa 5 phút trước nó: ngưỡng "≥ N trong 5 phút" có thể thấy tới 10 phút dòng). Đổi độ rộng bucket (`bucketSeconds`, dùng chung với `logs_source_buckets`) hay thời gian giữ (24 giờ và một bucket) là đổi mọi câu trả lời. Module tắt thì không còn dòng mới nên `Counts` chỉ trả số cũ.

## Modifying: job `anomaly` và sự kiện `logs.anomaly.detected` (L3)
- **notify** (`logEvent`): đọc `source`, `target`, `title` (≤ 200 ký tự), `what`, `action`, `severity`, `devices[{id,name}]`; `source` + `target` là khoá gộp incident. Đổi tên trường hay nghĩa của `target` là đổi cách notify gộp. Tối đa 20 sự kiện mỗi giờ mỗi nguồn: nâng trần là nâng lượng thông báo của khách.
- Hai phòng 20 sự kiện mỗi giờ mỗi nguồn (bounded; bộ tìm mẫu), một bản tóm tắt mỗi giờ khi bộ tìm mẫu có nhiều nhóm hơn phòng (chỉ bao trùm mục chưa được bao trùm: dòng `covered`), và một bản tóm tắt tồn đọng mỗi giờ khi chữ ký bounded chờ nhiều hơn phòng; `target` của bản tóm tắt có giờ UTC để notify mở incident mới, hạn mức giờ là cửa sổ trượt 60 phút; `target` của sự kiện bounded là `sig:<chữ ký>` (vùng tên riêng, không bao giờ trùng đích của incident bộ tìm mẫu). Đổi cách đặt `target` hay bỏ giờ khỏi nó là làm notify cộng dồn lặng lẽ (khoá gộp của notify là loại + nguồn + target, `modules/notify/incidents.go` `dedupeKey`).
- Không `Housekeeping`: biến nó thành housekeeping là gửi sự kiện khi module tắt (SYS-5); `TestContract_SYS5_NoEventsWhileTheModuleIsOff` chặn.
- **Sửa nguồn** (`UpdateSource`): đổi `kind` hoặc `sender_ip` đặt `logs_sources.signatures_since` và khởi động lại 24 giờ của nguồn; một đường sửa nguồn mới (import hàng loạt) phải làm như vậy.
- **cmd/vedette** (`logs.go`): `Config.Events` là `d.Bus`; thiếu thì job không làm gì.

## Modifying: `Subscribe(bus)`, job `siem`, `SiemEvents/SiemFormats` — 4 lớp sự kiện
- **findings** (`findings.finding.created|status_changed`), **notify** (`notify.incident.created`), **honeypot** (`honeypot.hit.created`), **logs** (`logs.bad_address.detected`, L4 phát): đổi tên hay trường của các sự kiện này làm bản ghi SIEM thiếu trường (handler đọc JSON, không import module khác). Đổi enum `SiemEvent`, định dạng syslog/CEF/JSON hay chữ ký → SIEM của khách phân tích sai; ghi vào CONTRACT, D-291 và thông báo khách. Đổi `core/secrets` purpose `logs_siem.secret` → mất khoá đã niêm.
- **cmd/vedette** (`logs.go`): `Config.Secrets`, `Config.BoxAddrs` (= `notifyBoxAddrs`, địa chỉ hộp mà SIEM không được là), `svc.Subscribe(d.Bus)`. **core/export_policy**: bảng `logs_siem`. **PRIVACY.md** luồng 7 và `privacy.flow.7.*`: đổi dữ liệu gửi đi thì sửa cùng lúc.

## Modifying: `Sources` CRUD / `SourceKind` (`KIND_IDS`)
- **web/features/logs** (`catalog.ts` bắt buộc có mục cho mỗi mã; `logs.test.tsx` kiểm). Thêm loại: thêm parser + mục catalog + test, không phải sửa chỗ khác.

## Modifying: `Retention(days)`
- **core/logs export** (`/core/logs/export?categories=device_logs,known_bad`): phạm vi dữ liệu xuất giảm theo lưu giữ. **core/data purge** phải xoá `logs_*`.

## Disabling this module
- Trang Logs, mục Cài đặt → SIEM, panel AI digest trong `logs.panels` trống/"đang tắt".
- `response`: trigger `ioc_connection`, `log_threshold`; mẫu `tpl-ioc-*`, `tpl-vpn-ban`, `tpl-ssh-acl`, `tpl-iot-shut` không có sự kiện. `notify`: mất cảnh báo kết nối xấu. `ai`: mất `log-digest`/`log-investigate`.
- Cổng 514/6514 đóng; thiết bị đang gửi syslog bị từ chối kết nối. `logs_*` giữ nguyên.

## Modifying: `modules/logs/listen` (L2) — gói không có cơ sở dữ liệu, sẽ chạy trong `vedette-sensor` ở L6
- **logs** (`listener.go`): `listen.Server`, `Config`, `Limits`, `Source`, `Line`, `Status`, `Stats`. Gói **không được import `database/sql` hay `core/store`** (nó phải chuyển sang sensor không đổi mã, như `sensor-passive/capture`); mọi thứ lưu trữ đi qua `Sink` → `Service.Ingest`. Đổi `Line` là đổi `Service.sink`. Một lô tối đa 500 dòng khớp `MaxBatch` của `Ingest`: nâng một bên mà không nâng bên kia làm `ErrBatchTooLarge` và mất lô.
- **Giới hạn** (`Limits`): đổi là đổi bộ nhớ và độ chịu lũ của hộp: 1.000 kết nối × bộ đệm 4 KiB, hàng đợi 4.096 dòng × tối đa 8 KiB. Dòng cắt ở 8 KiB rồi `Ingest` cắt ở 2 KiB: giảm `MaxLine` xuống dưới 2 KiB làm mất chữ đã lưu được.
- **Job `syslog`** (`Jobs`): không `Housekeeping`. Đổi thành housekeeping là mở cổng khi module tắt (SYS-5); `TestNoSocketWhileTheModuleIsOff` chặn. Thêm/sửa/xoá nguồn gọi `sourcesChanged`: một đường sửa nguồn mới (import hàng loạt) phải gọi nó, nếu không socket chỉ theo sau khi có một lần đánh thức khác hoặc khi job khởi động lại (job không tự đọc lại nguồn; nó chỉ thử lại socket lỗi và lần đọc nguồn lỗi mỗi 30 giây).
- **cmd/vedette**: cờ `-syslog-port` và `deps.SyslogPort` (Kiên sở hữu Quadlet của `core`: cổng 514 cần quyền bind hoặc publish cổng; không có thì dùng 5514 và phải publish `5514/udp`, `5514/tcp`). `logsJobs` giờ trả hai job.
- **Hộp**: một cổng cho UDP và TCP, mọi địa chỉ IPv4. Tường lửa/NAT của hộp phải cho thiết bị tới cổng đó; listener không tự mở gì ngoài socket.
- **web/features/logs**: trang Nguồn nói thiết bị gửi tới cổng của nguồn (mặc định 514) trong khi hộp có thể nghe ở 5514: GUI chưa biết cổng thật (dòng hoãn của L2, cần tiêu chí story).
