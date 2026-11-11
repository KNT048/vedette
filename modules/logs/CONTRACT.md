# Logs Contract

> Tier: tuỳ chọn (tắt mặc định) · Story: S-LOG-1, S-LOG-2, S-LOG-3, S-LOG-4 · Quyết định: D-18, D-30, D-43, D-55, D-56 · Last verified: 2026-11-11 (fix/logs-production-safety: trần byte, xuất có trần, kẹp giờ) (WP-24 L1: nguồn, sự kiện, lưu giữ, `Ingest`, xuất `device_logs`; chưa có listener, digest đầy đủ, IOC, SIEM)
> Nguồn hành vi thực tế: `web/src/features/logs/{contract,types,mocks,kinds,catalog}.ts`.

## Invariants (luôn đúng)
- **INV-1** Log và metadata là dữ liệu không tin cậy (SYS-6): parser fail-closed (dòng không parse được chỉ lưu thô, không bỏ cả lô), giới hạn kích thước dòng/lô, dòng lỗi được đếm; nội dung dòng không bao giờ được diễn giải thành lệnh. Test: fuzz parser theo từng `SourceKind`.
- **INV-2** Không cài IDS/IPS (Zeek, Suricata) trên hộp (D-43). Nguồn phát hiện mạng chỉ gồm (1) metadata SPAN: truy vấn DNS, TLS SNI, HTTP Host, luồng IP; không lưu payload; (2) syslog. Giá trị `seen_via`: `span_dns | span_sni | span_http | span_flow | syslog:<tên thiết bị>`.
- **INV-3** Nguồn log: `name` khớp `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`; `sender_ip` là IPv4 hợp lệ; `proto` ∈ {udp,tcp,tls}; `port` 1..65535 (mặc định 514, tls 6514); `kind` thuộc `KIND_IDS` (danh mục D-30, 48 loại, mỗi loại có cấu hình đã đối chiếu tài liệu hãng). `state` ∈ {receiving, silent, never}; `asset_id` là thiết bị trong kho cùng IP, `null` nếu không có.
- **INV-4** Lưu giữ (`retention_days`) ∈ {7, 30, 90, 180}; mặc định 30. Hết hạn → xoá sự kiện. Xoá một nguồn **không** xoá log đã nhận (giữ tới hết lưu giữ).
- **INV-5** `GET /logs/events` trả tối đa 200 dòng mới nhất, `total` là số khớp thật; `q` ≤ 200 ký tự; cửa sổ ∈ {1h, 24h, 7d} và không vượt `retention_days`.
- **INV-6** Digest: baseline = 7 ngày (`baseline_days = 7`); gộp theo (signature, nguồn, đích); "new" = chưa thấy trong baseline; "spike" = tăng so với `baseline_per_day`. Cài sạch: digest rỗng (`new`, `spikes`, `bad_connections` = []).
- **INV-7** `IocHit`: `confidence` ∈ [0,1]; `dest_kind` ∈ {ip, domain}; `feeds` là các feed đang liệt kê đích; `asset_id` tra từ IP nguồn tại lúc đọc. Hàng lưu `logs_ioc_hits = { id, ts, asset_id, src_ip, dest, dest_kind, seen_via, feeds, confidence }`. Danh sách IOC lấy từ `feeds` qua interface, không tự kéo feed.
- **INV-8** SIEM: bật chỉ khi đã cấu hình; `events` ≥ 1 trong {findings, alerts, honeypot, bad_conn}; khoá ký `secret` ≥ 16 ký tự, lưu qua `core/secrets` (SYS-4), API chỉ trả `secret_last4`; bỏ trống khi sửa = giữ khoá cũ. Mặc định tắt, không gửi gì (PRIVACY luồng 7).
- **INV-9** Đích SIEM do khách khai (`host:port` hoặc URL); mọi lần gửi thử và gửi thật chỉ tới đích đó (SYS-7). Ba định dạng: `syslog`, `cef`, `json` (webhook có ký).
- **INV-10** `GET /logs/siem` chỉ admin (có cấu hình); mọi mutation ghi `core_audit` (SYS-3).
- **INV-11** Log do thiết bị khách gửi **không** tự đi tới AI: chỉ qua module `ai` với hook và luật dữ liệu nội bộ (D-29, D-39).

## Preconditions (trước khi gọi)
- **PRE-1** `POST /logs/sources` / `PUT /logs/sources/{id}`: vai admin; đầu vào qua schema (SYS-2). Port 514 cần `net_bind_low` được cấp cho container `sensor`.
- **PRE-2** `POST /logs/siem/test`: đã có cấu hình lưu.
- **PRE-3** Module `feeds` bật thì mới có đối chiếu IOC; nếu tắt, digest vẫn chạy nhưng `bad_connections` rỗng và UI nói rõ vì sao.

## Postconditions (sau khi xong)
- **POST-1** Thêm nguồn → trong cùng lượt, listener của `sensor` nhận gói từ `sender_ip` tới cổng/giao thức đó; `state = never` tới khi có dòng đầu.
- **POST-2** Kết nối từ LAN tới IP/domain nằm trong feed độc hại → tạo `logs_ioc_hits` và phát `logs.ioc_hit`, kèm thiết bị nguồn (S-LOG-2, S-LOG-4).
- **POST-3** Lưu giữ đổi → áp dụng cho lượt dọn kế tiếp; trả `retention_days` mới.
- **POST-4** `POST /logs/siem/test` trả `{ok, at, detail}` và lưu `last_test`.
- **POST-5** Với SPAN: không có gói nhân bản thật → trạng thái sensor cảnh báo (cấu hình ở Cài đặt → Box network, D-56), không âm thầm báo "không có gì".

## Forbidden (không bao giờ)
- **FORBID-1** Lưu payload gói SPAN (chỉ metadata, INV-2).
- **FORBID-2** Trả khoá ký SIEM qua API/export; ghi vào log.
- **FORBID-3** Gửi sự kiện tới SIEM khi `enabled=false`.
- **FORBID-4** Đưa log thô cho AI không qua module `ai`.
- **FORBID-5** Nhận syslog từ IP chưa khai làm nguồn rồi lưu như nguồn hợp lệ. (Đề xuất; xem câu hỏi mở 2.) Gán nguồn qua UDP/TCP chỉ là cố gắng tối đa (IP gửi UDP giả được, và máy bất kỳ trong LAN nhận được IP khác); listener TLS của L2 (cổng 6514) sẽ ghim chứng chỉ khách cho từng nguồn.

## Endpoints owned (từ `contract.ts`)
| Method | Path | Vai tối thiểu | Story |
|---|---|---|---|
| GET | `/logs/sources` | viewer | S-LOG-1 |
| POST | `/logs/sources` | admin | S-LOG-1 |
| PUT | `/logs/sources/{id}` | admin | S-LOG-1 |
| DELETE | `/logs/sources/{id}` | admin | S-LOG-1 |
| GET | `/logs/digest` | viewer | S-LOG-1, 2, 4 |
| GET | `/logs/events` | viewer | S-LOG-1 |
| PUT | `/logs/retention` | admin | S-LOG-1 |
| GET | `/logs/siem` | admin | S-LOG-3 |
| PUT | `/logs/siem` | admin | S-LOG-3 |
| POST | `/logs/siem/test` | admin | S-LOG-3 |

## Tables owned
Hai cơ sở dữ liệu (INV-12). **Cơ sở chính (`vedette.db`)**: `logs_sources`, `logs_retention`, `logs_siem` (cấu hình, ghi audit cùng giao dịch, nằm trong bản sao lưu). **`logs.db`** (tệp riêng cạnh `vedette.db`, người ghi riêng): `logs_events`, `logs_source_buckets`, `logs_source_seen`, và về sau `logs_ioc_hits`, `logs_signature_daily`. `response` đọc `logs_ioc_hits` qua interface (IMPACT), không đọc bảng trực tiếp.

## Lưu trữ và người ghi duy nhất (INV-12, WP-24 L1)
- **INV-12** Khối lượng log (`logs_events` và các bộ đếm) ở `logs.db`, **không** ở cơ sở chính: mỗi `store.DB` có một người ghi, và 2.000 dòng/giây/nguồn không được chờ hay giữ người ghi của core (các sự kiện findings bị mất vì người ghi bận, #159/#160). Hai cơ sở không tham chiếu nhau: dòng chỉ gọi nguồn bằng id, và dòng sống lâu hơn nguồn (INV-4). `NewService` từ chối khi hai cơ sở là một. `Ingest` ghi tối đa một giao dịch trên `logs.db` cho mỗi lô (≤ `MaxBatch` = 500 dòng) và không bao giờ ghi cơ sở chính. Test: `TestIngestNeverWaitsForTheCoreWriter` (giữ người ghi của core, ingest vẫn xong).
- **Làm sạch (INV-1)**: mọi dòng qua `sanitizeLine`: UTF-8 sai → U+FFFD, ký tự điều khiển trừ tab → khoảng trắng, cắt ở `MaxLineBytes` = 2.048 byte tại ranh giới ký tự và đánh dấu `...[cut]`. Fuzz: `FuzzSanitizeLine`, `FuzzNormalizeSource`.
- **Làm sạch, bản đầy đủ (rà soát #186)**: mọi ký tự thuộc `unicode.Cc`, `Cf`, `Zl`, `Zp` trừ tab đều thành khoảng trắng (điều khiển C0/C1 gồm NEL và DEL, ghi đè và cô lập hai chiều, ký tự độ rộng 0, BOM, dấu gạch nối mềm, U+2028/2029): chúng làm dòng hiển thị ngược, trốn khỏi tìm kiếm, hoặc giả dòng thứ hai trong trang và tệp xuất.
- **Tìm kiếm có trần**: tối đa `MaxSearches` = 2 lần tìm cùng lúc trên một hộp, mỗi lần `SearchTimeout` = 5 giây; quá một trong hai → 503 `server_busy` (cũng khi bộ điều khiển báo "interrupted" giữa lúc quét: hạn của lần tìm đã qua thì luôn là `server_busy`) (mã đã có; thông báo nói thu hẹp khoảng thời gian hoặc từ khoá). GUI hiện lỗi API qua `QueryState` (có nút thử lại), mock không đổi. **Không phân biệt hoa thường chỉ cho chữ ASCII** (`asciiLower` ở Go khớp `lower()` của SQLite); các ký tự khác phải đúng chữ (tiếng Việt gõ đúng như trong dòng thì khớp). Đường nâng cấp: chỉ mục FTS5 với tokenizer `unicode61`.
- **Audit của purge (SYS-3, hai cơ sở không chung giao dịch)**: lượt dọn có gì để xoá ghi `logs.purge_started` (mốc cắt, trần byte) vào cơ sở chính **trước**; không ghi được thì không xoá gì. Rồi, mọi đường ra (xong, lỗi, ctx bị huỷ, kể cả trước khúc đầu), luôn ghi `logs.purge` kèm số dòng bằng `context.WithoutCancel`. Sập giữa hai dòng để lại dòng "started" không có dòng kết: nghĩa là đang dọn dở.
- **Id dòng** là `AUTOINCREMENT`: `le-N` không bao giờ dùng lại cho dòng khác, kể cả sau purge.
- **Thời gian**: `ts` là giờ nhận (giờ của thiết bị trôi, RFC 3164 không có năm), kẹp trong [bây giờ − lưu giữ, bây giờ]: trống hoặc ở tương lai = bây giờ; cũ hơn lưu giữ = mốc cũ nhất còn giữ (lỗi của listener không được ghi dòng mà lượt dọn kế tiếp xoá ngay). Một dòng dài hơn 4 × `MaxLineBytes` bị cắt **trước** khi làm sạch (bộ làm sạch đi qua cả chuỗi).
- **Dọn**: job `purge` (mỗi giờ, và khi module bật) xoá dòng quá hạn lưu giữ theo từng khúc 10.000 dòng (mỗi khúc một giao dịch, nên người ghi của `logs.db` được nhả giữa hai khúc, tôn trọng `ctx`), giữ tổng **byte chữ của dòng** không quá `MaxEventBytes` = 4 GiB dù lưu giữ thế nào (chống đầy đĩa; tệp thật lớn hơn khoảng 1,6 lần vì chỉ mục), bỏ bộ đếm quá 2 ngày và dấu "lần nhận cuối" của nguồn đã xoá. Số byte nằm ở bảng một hàng `logs_volume` (migration 0002): `Ingest` cộng trong giao dịch của lô, lượt dọn trừ trong giao dịch xoá. **`Ingest` tự bắt đầu một lượt dọn nền** khi tổng vượt trần (không chờ, gộp: tối đa một lượt do `Ingest` khởi động tại một thời điểm, không bao giờ chờ người ghi của core, INV-12); lượt dọn xoá dòng cũ nhất tới còn 90% trần để không lượt nào bị khởi động bởi mỗi lô. Không có gì hết hạn và không vượt trần: không lệnh xoá dòng, không audit. Có gì để xoá: một dòng `logs.purge_started`, và **luôn** một dòng kết `logs.purge` (kể cả số đếm 0, kể cả bị huỷ trước khúc đầu). Giới hạn đã biết: bộ đếm byte chỉ đúng khi mọi người ghi là binary này (binary cũ chạy trên `logs.db` mới không cộng vào đó).
- **Xuất `device_logs`** (`ExportDeviceLogs`): có trần riêng `ExportMaxBytes` = 32 MiB (ước lượng: mỗi dòng tính gấp đôi số byte cộng 128), để nguồn này không bao giờ làm cả `GET /core/logs/export` trả 413 (trần chung 128 MiB của core, D-132). Quá trần: giữ dòng **mới nhất**, theo thứ tự cũ → mới, và dòng cuối là `{"id":"cut","ts","source_id":"","line":"[device_logs cut: ...]"}` nói rằng có dòng cũ bị bỏ; cần đủ thì xuất khoảng ngày ngắn hơn.
- **Tìm kiếm** (`GET /logs/events`): cửa sổ ≤ lưu giữ; `q` khớp trong dòng và trong tên nguồn; 200 dòng mới nhất; `total` đếm chính xác tới `CountCap` = 100.000 (đo với 5 triệu dòng trước khi nâng).
- **Sao lưu, khôi phục, xoá dữ liệu (D-151, #187)**: `logs.db` **không** nằm trong bản sao lưu; khôi phục và quay lại bản cũ không đụng tới nó; chữ trong RUNBOOK và màn hình sao lưu là của Kiên; phần xoá dữ liệu do `core` làm từ danh sách tên tệp dữ liệu module mà `cmd/vedette` đưa (logs không đăng ký gì). Vì quay lại bản cũ có thể chạy **binary cũ trên `logs.db` mới**, mọi migration của `logs.db` (`migrations/volume`) phải **chỉ thêm** (bảng, cột, chỉ mục mới; không DROP, RENAME, DELETE, UPDATE, không đổi nghĩa cột). Test chặn: `TestVolumeMigrationsAreAddOnly` (bỏ chuỗi và comment trong một lượt trái→phải; cấm thêm REPLACE INTO, INSERT OR REPLACE, CREATE TRIGGER, CREATE UNIQUE INDEX). Thay đổi không tương thích = tệp mới `logs-v2.db` và một quyết định mới.
- **Còn thiếu so với CONTRACT đầy đủ (các lát sau)**: digest chỉ có `lines_24h` (INV-6, L3), `bad_connections` (INV-7, L4), SIEM (INV-8..10, L5), listener (POST-1, L2).

## Events
- **Phát**: `logs.batch` (sensor → server, idempotent theo `seq`, `ARCHITECTURE.md`); `logs.ioc_hit` (tên đề xuất; chưa có trong ARCHITECTURE); **`logs.anomaly.detected`** và **`logs.bad_address.detected`** cho `notify` mở incident (D-52; tên 3 đoạn `<module>.<object>.<verb>` như `core/events` đòi; payload do logs mô tả sẵn nội dung, vì chỉ logs hiểu log): `{source, target, title, what, action, severity, devices: [{id, name}]}`. `source` và `target` là khoá gộp incident (cùng loại + nguồn + đích đang mở thì chỉ tăng `count`), `title` ≤ 200 ký tự bằng tiếng Anh một câu "ai làm gì", `severity ∈ critical|high|medium|low|info`, `devices` là thiết bị inventory khớp (có thể rỗng). Mọi chuỗi là dữ liệu từ log (không tin cậy); notify cắt và hiển thị như văn bản thuần. Hai tên này thay cho `logs.anomaly` và `logs.bad_address` trong CONTRACT của `notify`.
- **Nhận**: `inventory` (kho thiết bị để tra IP); danh sách IOC từ `feeds`; (khi bật) sự kiện `honeypot.hit`, finding, incident để chuyển SIEM.

## Khi tắt module (SYS-5)
Không route `/logs*`, không nghe cổng 514/6514, không phân tích SPAN, không đẩy SIEM. `logs_*` giữ nguyên. Trigger `ioc_connection`, `log_threshold` của `response` không còn sự kiện; trang Logs và panel `logs.panels` nói "module đang tắt".

## Dependencies
- **DEPENDS ON**: `core`, `feeds` (IOC), `inventory` (tra thiết bị), `host` (card SPAN, D-56).
- **DEPENDED ON BY**: `response` (trigger `ioc_connection`, `log_threshold`), `ai` (digest AI, `log-digest`/`log-investigate`, panel `logs.panels`), `notify` (cảnh báo kết nối xấu), `reports` (chưa dùng).

## Câu hỏi mở
1. Container: syslog listener nằm ở `sensor` (giả định theo ARCHITECTURE: "logs chạy được ở chế độ sensor") hay `core`? Ảnh hưởng cổng <1024 và quyền.
2. Syslog từ IP không khai báo: bỏ, lưu vào "chưa phân loại", hay tự đề xuất nguồn? GUI chưa nói.
3. `log_threshold` của `response` ("10 đăng nhập VPN lỗi trong 5 phút") ai đánh giá: `logs` hay `response`? `contract.ts` của logs chưa có endpoint/bảng cho quy tắc ngưỡng.
4. `SiemEvent = 'alerts'` còn tên cũ sau D-52 (Alerts → Incidents); đổi tên enum hay giữ để tương thích?
5. Giới hạn kích thước dòng/lô và tốc độ tối đa (SYS-6): chưa có số.
