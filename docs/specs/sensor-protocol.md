# Sensor protocol: `sensor`/`scan` ↔ `core` (hồ sơ appliance)

Trạng thái: **chốt trên giấy ở lát SP-0** (2026-11-10), **mã của SP-1** (`core/pki`, `core/sensorlink`; chưa nối module) làm rõ vài chỗ, đánh dấu "SP-1" dưới đây; thay bản nháp trước (2026-11-09). Văn xuôi tiếng Việt; tên trường, mã lỗi, đường dẫn bằng tiếng Anh.
Truy vết: `ARCHITECTURE.md` §2, §6, TB-9; `DEPLOYMENT.md` §2.2, §2.4, §6.1; story S-INV-1, S-INV-3, S-SCAN-4.

## 1. Mục đích và phạm vi

Hồ sơ **appliance**: hai container trên cùng một hộp nói với `core` qua `127.0.0.1:8444`:

- `sensor`: bắt gói thụ động (nửa `capture` của module `sensor-passive`), mạng host, `NET_RAW`;
- `scan`: worker nmap của module `sensor-active`, mạng host, `NET_RAW`.

Cả hai chạy cùng binary `vedette-sensor` (lệnh con `passive`, `active`, `healthcheck`). Chiều khởi tạo **chỉ một**: sensor gọi ra, `core` không bao giờ gọi vào sensor; lệnh từ `core` tới bằng long-poll.

Ngoài phạm vi hồ sơ này:
- sensor đặt ở máy khác, enroll, gia hạn qua mạng, thu hồi bằng tay (thiết kế cũ ở phụ lục A);
- syslog (metadata SPAN đi trên dây từ §6.7, khớp ở `core` bởi `logs`), honeypot (đi qua tệp), osquery (`osquery-intake.md`). (Job nuclei của module `scan` là loại job thứ hai từ bản 2; đọc SNMP là loại thứ ba từ bản 5, xem khối "Đọc SNMP" ở §6.5.)

## 2. Actors và vai

| Actor | Vai | Ghi chú |
|---|---|---|
| `core` | máy chủ giao thức; CA của sensor; giữ DB, chính sách, sự đồng ý quét | container `core`, listener thứ hai `:8444`, publish `127.0.0.1:8444` |
| `sensor` | vai **`passive`**: nhận `config`, gửi quan sát và heartbeat | `User=<sensor_uid>:<sensor_gid>`, không `UserNS`, chỉ `NET_RAW` |
| `scan` | vai **`active`**: nhận job nmap, gửi kết quả và heartbeat | như `sensor`; image dựng trên hộp |
| `vedette-host` | dựng unit hằng gắn volume khoá theo vai | không bao giờ thấy khoá |

Mô hình tin cậy: sensor là **máy bị tấn công được** (nằm trên LAN, đọc gói và phản hồi do kẻ tấn công điều khiển). `core` tin **danh tính vai** sau mTLS, không tin **nội dung** (SYS-6): mọi thứ sensor gửi bị kiểm kích thước, kiểu, hạn mức và kẹp độ tin cậy ở `core`.

## 3. Transport

- HTTPS, JSON (`Content-Type: application/json`), không nén (`Content-Encoding` bất kỳ → `400 invalid_request`). TLS **1.3** tối thiểu; HTTP/2 khi ALPN đề nghị, không bắt buộc.
- Listener riêng của `core`, bật bằng `-sensor-listen :8444` (trong container) cùng `-sensor-creds <thư mục>` (rỗng = không nghe), tách khỏi listener UI 8443; `core` mở PKI, ghi hai bó khoá, **rồi mới** nghe, và việc `sensor-cert-renew` hằng ngày gọi `Authority.Renew`; trên appliance chỉ publish `127.0.0.1:8444` (`DEPLOYMENT.md` §6.1). `ClientAuth = RequireAndVerifyClientCert`, pool chỉ chứa CA sensor.
- Tiền tố `/sensor/v1/`. Mọi request mang `X-Vedette-Proto: 5` (bản 5: loại job `snmp`, `snmp` trong heartbeat `active` và trong kết quả, `running` tới 3 id; bản 4: `capture_error` trong heartbeat thụ động; bản 3: `host_errors` của kết quả nuclei; bản 2: loại job `nuclei`). `core` nhận bản của mình và **bản liền trước** (`4`), không bao giờ bản mới hơn. Bản 5 thêm một loại job vào **phản hồi** `jobs`, nhưng `core` chỉ gửi job `snmp` cho worker có heartbeat `"snmp": true` (trường của bản 5), nên worker bản 4 nhận phản hồi đúng dạng bản 4.
- `ReadHeaderTimeout` 5 s, `WriteTimeout` 35 s (long-poll giữ tối đa 30 s).
- Thân: `http.MaxBytesReader` theo trần của route (§9) **trước** khi giải mã; giải mã bằng `internal/jsonstrict` (trường lạ, khoá trùng, khoá trùng sau gập chữ, độ sâu > 32 → `400 invalid_request`). Query lạ → `400 invalid_request`.
- SP-1 (làm rõ): thân POST phải có `Content-Type: application/json` (thiếu hoặc khác → `400 invalid_request`); thân đọc tối đa **10 s** (đồng hồ ổ cắm, không phải seam; `ReadTimeout` toàn yêu cầu 15 s; 10 s cho 11 MiB tức ~9 Mbit/s, chỉ đúng cho sensor cục bộ, tính lại khi dựng sensor từ xa) và kết nối bị đóng khi thân dừng giữa chừng hoặc vượt trần (net/http không có hạn đọc thân nào mà không làm hỏng long-poll); `IdleTimeout` 2 phút; `MaxHeaderBytes` 16 KiB. `If-None-Match` phải có dạng `"<1…64 ký tự [A-Za-z0-9._:-]>"`, không thì `400`. `wait` là một số nguyên 0…30 (một giá trị, không lặp); `running` là 32 hex hoặc rỗng.
- Listener nhận tối đa **64 kết nối** cùng lúc (`PendingListener`, viết bằng thư viện chuẩn): **16 đang bắt tay** (chưa xác thực; đầy thì kết nối mới thay chỗ kết nối chờ lâu nhất nếu nó đã chờ ≥ 250 ms, không thì kết nối mới bị đóng ngay; mỗi kết nối chờ bị đóng sau 3 s bắt tay), rồi theo vai tại bắt tay TLS: `passive` ≤ 32, `active` ≤ 16; `ErrorLog` của `http.Server` đi qua slog như server 8443 (lỗi handshake bị từ chối vào log, không ra stderr). Client **không theo redirect**: một 3xx là lỗi của request, `Location` không được gọi (không đưa chứng chỉ client cho máy khác).
- Sensor đọc phản hồi của `core` cũng có trần (config ≤ 64 KiB, jobs ≤ 64 KiB, phản hồi khác ≤ 16 KiB) và giải mã chặt như `core`.

## 4. Chứng chỉ và danh tính

| Mục | Quy tắc |
|---|---|
| CA | ECDSA P-256, 10 năm, do `core` tạo lần đầu; khoá lưu qua `core/secrets` (AES-256-GCM, `master.key`). **Chỉ** ký lá cho listener 8444 và cho sensor; tách khỏi chứng chỉ 8443 và CA osquery tương lai (`osquery-intake.md` §4). Khôi phục không có `master.key` → CA mới, lá mới |
| Lá máy chủ | EKU **chỉ** `serverAuth`; SAN `IP:127.0.0.1` và `DNS:core` (profile compose); 7 ngày |
| Lá sensor | EKU **chỉ** `clientAuth`; **đúng một** URI SAN: `vedette:sensor:passive` hoặc `vedette:sensor:active`; không dùng CN để quyết định gì; 7 ngày; serial ghi ở `core_sensor_cert(role, serial, not_after, retired_at)` |
| Xoay vòng | `core` kiểm lúc khởi động và mỗi ngày; lá còn ≤ 1/3 thời hạn thì cấp mới; serial cũ hơn "ngay trước" được đặt `retired_at` |
| Giao khoá | lúc khởi động, **trước khi nghe**, và mỗi lần xoay: `core` sinh khoá, ghi **một** bó PEM (khoá, lá, CA) vào `<creds>/<role>/sensor.pem` qua `os.OpenRoot`, tệp tạm `O_EXCL\|O_NOFOLLOW`, fsync, `Rename`; mode `0640`, chủ `core_uid:sensor_gid`. `core` **không bao giờ đọc lại** tệp |
| Phía sensor | gắn volume khoá của đúng vai **chỉ đọc**; đọc lại bó trong `GetClientCertificate` khi mtime đổi; sau khi đổi, đóng kết nối rảnh. Bó hỏng hoặc đang ghi dở → giữ bó cũ trong bộ nhớ, thử lại sau 5 s |
| Phía sensor kiểm máy chủ | chuỗi tới CA trong bó, EKU `serverAuth`, tên `127.0.0.1` (hoặc `core` ở compose) |

**SP-1 (làm rõ).** `core` luôn cấp lá mới cho máy chủ và hai vai ở lúc khởi động (`Authority.Start`), vì nó không bao giờ đọc lại bó nên không có khoá của lá lần trước; serial trước đó vẫn sống (là "ngay trước"). Việc hằng ngày (`Authority.Renew`) chỉ thay lá còn ≤ 1/3 thời hạn. Bó cấp rồi mà ghi không được (volume lỗi, thư mục vai bị đặt symlink) được giữ trong bộ nhớ và ghi lại ở lần `Renew` kế, không cấp lại. `NotBefore` lùi 1 phút so với giờ `core`. Handshake và mỗi request kiểm EKU **đúng** `[clientAuth]`, đúng một URI SAN, lá không phải CA; mỗi request còn kiểm `NotBefore ≤ giờ ≤ NotAfter` của lá (kết nối keep-alive sống lâu hơn chứng chỉ) → `403 cert_retired`.

**Kiểm của `core`** (thứ tự):
1. Handshake: chuỗi tới CA sensor (hạn, chữ ký), EKU `clientAuth`, đúng một URI SAN thuộc hai vai, serial là serial **hiện hành hoặc ngay trước** của vai đó. Sai bất kỳ → handshake hỏng (không có phản hồi HTTP). `VerifyConnection` chạy cả trên kết nối nối lại (TLS 1.3 resumption).
2. **Mỗi request**: kiểm lại serial (một kết nối keep-alive sống lâu hơn lần về hưu của serial) → `403 cert_retired`.

**CA không dùng được thì thay (M2 của rà soát SP-1).** Hàng CA không giải mã được với `master.key` hiện tại (mất khoá, hoặc khôi phục bản sao lưu không kèm khoá lên khoá của hộp: `host-api.md` §16), hỏng, hết hạn hoặc chưa tới `NotBefore` → `pki.Open` tạo CA mới **trong cùng giao dịch ghi** đã phát hiện ra nó (ghi đè hàng `core_secret`), thu hồi mọi serial còn sống của CA cũ, ghi audit `sensor-ca.replace` (lý do: `cannot_decrypt`, `damaged`, `expired`, `not_yet_valid`) và log cảnh báo `sensor_ca_replaced`; `Start` cấp lại và ghi lại mọi bó. Lỗi của DB không phải lý do để bỏ CA.

**Audit.** Mọi thay đổi PKI là một hàng `core_audit` (người làm `system`) trong cùng giao dịch: `sensor-ca.create`, `sensor-ca.replace`, `sensor-cert.issue` (vai, serial, `not_after`), `sensor-cert.retire` (vai, serial). Tên nhóm dùng gạch nối vì `audit` không nhận dấu gạch dưới ở nhóm. Không bao giờ có khoá hay PEM trong audit hay log.

**Dọn và ghi bó (L3, L6).** `Start` xoá các tệp tạm `.sensor.pem.*` (tệp thường; thư mục, symlink và tên khác để nguyên) còn lại sau một lần sập giữa lúc ghi. Thư mục gốc và thư mục vai được kiểm không phải symlink **và**, sau khi mở, phải đúng là thư mục đã kiểm (`os.SameFile`): bị tráo ở giữa thì từ chối (`ErrCredsPath`). `ParseBundle` kiểm lá chuỗi tới chính CA trong bó (CA là gốc duy nhất, EKU `clientAuth`).

**Long-poll mở trước một lần xoay vòng.** Request đang giữ khi serial bị về hưu vẫn chạy tới hết (serial được kiểm lúc nó bắt đầu); request kế tiếp trên kết nối đó bị từ chối `403 cert_retired` (máy chủ đóng kết nối), client đọc lại bó và nối lại với chứng chỉ mới. Chừng đó là đủ: không có thao tác nào bị mất, vì sensor gửi lại cùng lô và long-poll tự lặp.

Thu hồi chủ động không có giao diện; thu hồi = xoay vòng (serial cũ về hưu) cộng hạn 7 ngày (thu hồi thụ động).

## 5. Quy ước chung

- Thời điểm: RFC 3339 UTC. Id job: 32 hex chữ thường (128 bit ngẫu nhiên). `epoch`: 32 hex chữ thường.
- Lỗi: `{ "error": { "code": "snake_case", "message": "English text" } }`; `code` là hợp đồng, `message` chỉ để đọc. 429 và 503 có tiêu đề `Retry-After` (giây).
- `version`: SemVer 2.0, ≤ 64 byte.
- Tên card: `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`; MAC: `^([0-9a-f]{2}:){5}[0-9a-f]{2}$`; IP qua `netip` (IPv4/IPv6 unicast); địa chỉ của card dạng tiền tố (`192.168.10.5/24`) qua `netip.ParsePrefix`.
- Chuỗi văn bản tự do: UTF-8 hợp lệ, không ký tự điều khiển C0/C1, bidi, phân cách dòng/đoạn, Unicode Cf (như sensor-passive INV-3); sai → mục bị từ chối, không cắt ở `core`.

## 6. Route theo vai

| Vai | Route | Thân request (trần) | Trả |
|---|---|---|---|
| `passive` | `GET /sensor/v1/config?wait=<0..30>` | — | `200` cấu hình + `ETag`, hoặc `304` |
| `passive` | `POST /sensor/v1/observations` | ≤ 1 MiB | `200 {ack_seq, rejected[]}` |
| `passive` | `POST /sensor/v1/metadata` (§6.7) | ≤ 512 KiB | `204` |
| `passive`, `active` | `POST /sensor/v1/heartbeat` | ≤ 64 KiB | `200 {instance}` |
| `active` | `GET /sensor/v1/jobs?wait=<0..30>&running=<id[,id]>` (`running` rỗng hoặc bỏ trống khi rảnh; ≤ 2 id, bản 2) | — | `200 {instance, jobs[], cancel[]}` |
| `active` | `POST /sensor/v1/jobs/{id}/result` | ≤ 11 MiB | `204` |

Mọi cặp (method, đường dẫn) khác, kể cả route của vai kia → `403 forbidden_route`, kiểm **trước khi đọc thân**. Mỗi vai tối đa **một** long-poll đang mở; cái thứ hai → `409 poll_in_progress`. Module của vai tắt (`sensor-passive` cho `passive`, `sensor-active` cho `active`) → mọi route của vai `409 module_off`.

### 6.1 `GET /sensor/v1/config` (passive)

Long-poll có điều kiện: sensor gửi `If-None-Match: "<etag>"` của bản đang dùng (lần đầu không có). `core` trả ngay `200` khi ETag khác; còn lại giữ tới `wait` giây (mặc định 25) rồi trả `304` không thân. `SetInterface` (đổi card/SPAN ở Box network) và đổi bộ lọc đánh thức long-poll đang mở (thay kênh `reload` trong tiến trình).

```json
{ "interface": "enp2s0", "span": true,
  "extract": { "dns": true, "sni": true, "http": false, "flows": true },
  "filters": [ { "type": "cidr", "value": "10.0.5.0/24" }, { "type": "port", "value": "443" } ] }
```

| Trường | Quy tắc |
|---|---|
| `interface` | tên card hoặc `""` = **không bắt gói** (module chưa cấu hình, hoặc fail-closed) |
| `span` | card là cổng SPAN/TAP (không IP) |
| `extract` | bốn công tắc trích metadata SPAN. sensor trích theo công tắc rồi gửi phần khớp cần qua `POST /metadata` (§6.7) |
| `filters[]` | luật loại trừ `{type: cidr\|host\|port, value}` (sensor-passive INV-7) |

Fail-closed: `core` không đọc được bộ lọc → `interface: ""`. Sensor nhận `interface` khác bản đang chạy → đóng card cũ, mở card mới; `""` → dừng bắt gói ngay, không xả lô cuối.

### 6.2 `POST /sensor/v1/observations` (passive)

```json
{ "epoch": "3f9c…(32 hex)", "seq": 41,
  "items": [ { "mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.10.23", "field": "hostname", "value": "printer-3f",
               "confidence": 0.6, "seen_at": "2026-11-10T08:00:01Z" } ] }
```

| Trường | Quy tắc |
|---|---|
| `epoch` | 32 hex ngẫu nhiên, sinh mỗi lần tiến trình sensor khởi động |
| `seq` | số nguyên 1 … 2^53−1, tăng dần trong một epoch |
| `items` | 1 … 500 mục |
| `items[].mac`, `.ip` | tuỳ chọn, ít nhất một trong hai; IP phải unicast |
| `items[].field` | ∈ `observe.Field`: `hostname`, `mac`, `vendor`, `model`, `os`, `kind` |
| `items[].value` | 1 … 200 byte, văn bản sạch (§5) |
| `items[].confidence` | 0 … 1; `core` kẹp theo trần của thang thụ động cho từng trường (sensor-passive CONTRACT, "Thang tin cậy") |
| `items[].seen_at` | RFC 3339 (sai định dạng hoặc kiểu → `400` cả lô, SP-1); trong khoảng 24 giờ trước tới 5 phút sau giờ `core` (ngoài → `out_of_window` từng mục) |
| (không có) `source` | `core` đặt `passive` theo vai; trường `source` trong thân → `400 invalid_request` (trường lạ) |

**Epoch và seq**. `core` giữ `sp_seq(sensor_id, epoch, last_seq)` với `sensor_id = sn-local` (sensor của chính hộp) và chỉ **2 epoch mới nhất** (epoch thứ ba xoá cái cũ nhất). Lô có `seq ≤ last_seq` của epoch đó → `200`, `ack_seq = seq`, `rejected: []`, không ghi lại (POST-3). Không có `seq_gap`: seq chỉ chống phát lại, khoảng trống là bình thường (lô bị bỏ).

**Xử lý** (một lô): (1) kiểm từng mục (§5, bảng trên) → mục sai vào `rejected[]`; (2) hạn mức chống ngập ở `core`: MAC chưa từng thấy ≤ 60 mỗi phút và ≤ 200 mỗi giờ, giá trị mới ≤ 4 mỗi (MAC, trường) mỗi giờ, map trong bộ nhớ theo MAC (lặp lại giá trị đã cho qua không tính là mới); vượt → `budget_exhausted`; (3) `SubmitBatch` với các mục còn lại; `observe.ErrRejected{Index}` của inventory → mục đó vào `rejected[]` với `refused`, gửi lại phần còn lại trong cùng request; (4) lưu `seq`.

Trả `200 { "ack_seq": 41, "rejected": [ { "index": 3, "code": "budget_exhausted" } ] }`: **thành công một phần, không bao giờ thử lại**. Mã của mục (tập đóng):

| `code` | Nghĩa |
|---|---|
| `invalid_item` | sai kiểu/regex/trần, `field` lạ, thiếu cả `mac` lẫn `ip`, văn bản bẩn |
| `out_of_window` | `seen_at` ngoài cửa sổ thời gian |
| `budget_exhausted` | vượt hạn mức chống ngập của `core` |
| `refused` | inventory từ chối ở biên (`observe.ErrRejected`) |

Kho bận (SQLite busy, `Write` hết hạn, hay kết nối ghi bị giữ quá 5 s: `store.ErrBusy`) → `503 store_busy` cho cả lô, không mục nào được ghi hay tính hạn mức.

### 6.3 `POST /sensor/v1/heartbeat` (cả hai vai)

Mỗi 30 s. Thân theo vai (giải mã chặt: trường của vai kia là trường lạ):

```json
{ "version": "1.4.0",
  "interfaces": [ { "name": "enp1s0", "mac": "aa:bb:cc:00:00:01", "link": true, "ipv4": ["192.168.10.5/24"] },
                  { "name": "enp2s0", "mac": "aa:bb:cc:00:00:02", "link": true, "ipv4": [] } ],
  "span": { "pps": 1200, "other_macs": 37, "last_packet_at": "2026-11-10T08:00:29Z" },
  "drops": { "malformed_dhcp": 2, "new_macs_dropped": 0 },
  "devices_seen": 214, "capture_error": "no_permission" }
```

```json
{ "version": "1.4.0", "nmap": { "present": true, "version": "7.94SVN" },
  "nuclei": { "present": true, "version": "v3.3.7", "pack": { "version": "2026.11.10", "sha256": "9f…(64 hex)" } } }
```

| Trường | Quy tắc |
|---|---|
| `interfaces` (passive) | ≤ 32 card; `ipv4` ≤ 8 tiền tố mỗi card |
| `span` (passive) | `pps` ≥ 0; `other_macs` = số MAC khác hộp thấy trong 5 phút (chỉ khung unicast giữa hai máy không phải hộp, sensor-passive INV-9); `last_packet_at` hoặc `null` |
| `drops` (passive) | ≤ 64 khoá thuộc **tập đóng** của bộ đếm bỏ trong `capture` (`malformed_*`, `excluded`, `value_empty`, `fragment_skipped`, `new_macs_unconfirmed`, `new_macs_dropped`, `values_dropped`, `observation_failed`…; 35 khoá, danh sách ở khối "SP-4" của §6 và `sensorlink.DropKeys`); giá trị ≥ 0 |
| `devices_seen` (passive) | ≥ 0 |
| `capture_error` (passive, bản 4) | vì sao bắt gói trên card được chọn không chạy lúc này: tập đóng `sensorlink.CaptureErrors` = `no_permission` (mở socket bị EPERM/EACCES: không có `CAP_NET_RAW`, như container rootless), `no_interface` (card không có trên máy), `filters_invalid` (bộ lọc không đọc được), `capture_failed` (mọi lỗi khác); vắng hoặc `""` khi đang bắt gói hay không có card nào được chọn. Sensor đặt nó khi mở card hay một phiên hỏng, xoá khi card mở được hay khi thôi bắt gói. Không bao giờ là chữ của lỗi (chữ đó ở log của sensor). Dạng: chữ thường `[a-z][a-z0-9_]{0,47}`, khác dạng → `400`; đúng dạng mà `core` không biết → `core` hiện `capture_failed` và log một lần (giữ tối đa 64 tên lạ) |
| `nmap` (active) | `present` = `/usr/bin/nmap` có và chạy được `--version`; `version` ≤ 32 byte; `full` (bản 5) = `true` khi nmap của worker đúng `nmapargv.ReviewedNmapVersion` (7.95) và worker chạy hai mẫu `external_full` và `external_disruptive` (sau rào IP của chính hộp), vắng = `false` (worker cũ hơn): `core` không bao giờ giao mẫu đó cho worker chưa nói `full` (`ErrFullUnsupported` trước khi xếp job; job đang chờ cũng bị giữ lại nếu heartbeat sau đó thôi nói `full`) |
| `nuclei` (active, bản 2) | `present` = `/usr/local/bin/nuclei` có và chạy được `-version -duc` (nuclei in phiên bản ra stderr); `version` ≤ 32 byte; `pack` = `version` (`AAAA.M.N`) và `sha256` (64 hex) của chỉ mục gói mẫu nằm sẵn trong image, **cả hai rỗng** khi chưa có chỉ mục dùng được (không đọc được hoặc không qua `pack.Parse`); một rỗng một không → `400`; `own_ip` (bản 5) = `true` khi worker chạy job nuclei phạm vi `own_ip` (có rào IP của chính hộp), vắng = `false` (worker cũ hơn): `core` không bao giờ giao job `own_ip` cho worker chưa nói `own_ip`; `full` (bản 5, thêm trước lần phát hành đầu như `own_ip`) = `true` khi worker chạy job nuclei `depth` `full`, vắng = `false`: `core` không bao giờ giao job full cho worker chưa nói `full` |
| `domain_ip` (active, bản 5) | `true` khi worker giữ khoá rào domain của hộp (vedette-host gắn chỉ đọc vào container scan, `/var/lib/vedette-fence/fence.key`) và tự kiểm rào domain; vắng = `false` (sensor từ xa, cài chỉ container, worker cũ): `core` không bao giờ gửi job `domain_ip` cho nó |

Trả `200 { "instance": "<32 hex>" }`: nonce sinh mỗi lần tiến trình `core` khởi động (lease của §6.4).

`core` dùng heartbeat cho:
- `Sensor.status`: `online` khi có heartbeat trong **90 s**; `last_seen`, `version`, `devices_seen`, `interfaces` (tên card) của `GET /inventory/sensors` lấy từ heartbeat thụ động mới nhất; `capture_error` cũng vậy nhưng **chỉ khi `online`** (heartbeat cũ không nói gì về lúc này; giữ trong bộ nhớ, không vào DB; GUI: "Reporting, not capturing" kèm lý do);
- `SpanStats()` / `span_status`: `off` (cấu hình `span=false`), `no_link` (card SPAN `link=false`), `no_traffic` (`last_packet_at` cũ hơn 30 s, `null`, hoặc sensor `offline`), `own_only` (`other_macs = 0`), `ok`;
- `SetInterface`: `interface` phải là một card của host; chỉ khi core chạy không có host thì là một card trong heartbeat thụ động mới nhất; `400 bad_interface` (sensor-passive INV-9); không có host và chưa có heartbeat → `bad_interface`;
- địa chỉ của hộp (`ProtectedIPs` của sensor-active, kiểm IP bẫy của honeypot, `conn`) **tới khi** lát host 3-3 có `GET /v1/state/net`;
- sức khoẻ `sensor-active`: `unavailable` khi 90 s không có heartbeat `active` hoặc `nmap.present=false` (INV-6);
- sức khoẻ của máy quét nuclei (`scan`): `scanner_unavailable` (503 ở API) khi 90 s không có heartbeat `active`, `nuclei.present=false`, `nuclei.pack.sha256` rỗng, hoặc một job nuclei chạy quá hạn mà worker chưa dừng được; nmap và nuclei độc lập: thiếu cái này không làm cái kia `unavailable`.

Heartbeat không có trong 90 s không xoá dữ liệu nào; chỉ đổi trạng thái hiển thị.

### 6.4 `GET /sensor/v1/jobs` (active): job, huỷ, lease

`core` giữ request tới `wait` giây (mặc định 25) và trả **ngay** khi có job mới hoặc lệnh huỷ; hết giờ trả mảng rỗng (luôn `200`, để worker luôn nhận `instance`).

```json
{ "instance": "9b1d…(32 hex)",
  "jobs": [ { "id": "c0ffee…(32 hex)", "kind": "nmap", "shape": "normal", "rate": 100,
              "targets": ["192.168.10.20", "192.168.10.21"], "timeout_s": 5400 },
            { "id": "badc0de…(32 hex)", "kind": "nuclei", "timeout_s": 600,
              "pack": { "version": "2026.11.10", "sha256": "9f…(64 hex)" },
              "templates": ["CVE-2024-1234", "CVE-2023-9999"],
              "targets": [ { "host": "192.168.10.20", "port": 8080, "scheme": "http" },
                           { "host": "192.168.10.21", "port": 22, "scheme": "" } ],
              "rate": 5, "max_host_errors": 3 } ],
  "cancel": [] }
```

| Trường | Quy tắc |
|---|---|
| query `running` | id các job worker đang chạy, cách nhau bằng dấu phẩy: rỗng, một id, hai hay (bản 5) ba id (một nmap, một nuclei; bản 2; một snmp, bản 5), mỗi id 32 hex, không trùng; khác → `400` |
| `jobs` | 0 … 3 phần tử, **tối đa một job mỗi loại** |
| `jobs[].kind` | `nmap` \| `nuclei` (bản 2) \| `snmp` (bản 5, trường của nó ở khối "Đọc SNMP" §6.5). Thiếu `kind` = `nmap`. Loại lạ: giải mã chỉ lấy `id` và `kind`, worker trả `refused` (`invalid_job`) mà không làm hỏng cả poll |
| `jobs[].shape` | (nmap) `sweep` \| `normal` \| `gentle` (ba mẫu gốc) \| `versions` (`-sV` không `-O`: lượt chọn tay thiết bị chưa rõ loại; worker cũ không biết mẫu này từ chối job `invalid_job`, nhận dạng báo `unavailable`) \| `gentle_titles` (lần quét nhẹ của thiết bị chưa rõ loại không mong manh, cộng `--script http-title,ssl-cert,http-hp-ilo-info,vmware-version --script-timeout 20s`; như `versions`, worker cũ từ chối `invalid_job` trong lúc cập nhật, lần quét nhẹ đó chạy lại ở cửa sổ sau; không tăng proto) \| `external` (quét mặc định đúng IP công khai của chính hộp cho exposure, hai job cùng tên: **dò cổng** `--privileged -sS -Pn -n --max-rate 100 --max-retries 2 --host-timeout 2m --top-ports 1000` (job không mang `ports`; nmap tự chọn 1000 cổng từ `nmap-services` của nó, core đọc lại cổng đã dò từ `<scaninfo services>`), rồi **`-sV`** `--privileged -sS -sV -Pn -n --max-rate 100 --max-retries 2 --host-timeout 3m -p <ports>` (job mang `ports`: mọi cổng của `nmapargv.ExtraPortNumbers` (commonports và cổng quản trị đã rà) cộng tối đa 40 cổng lượt dò thấy mở ngoài đó, tăng dần; worker dựng `-p` từ đó và văn phạm từ chối danh sách khác); không `-O`, không `--script`; worker **tự kiểm** ngay trước nmap rằng hộp ra Internet qua địa chỉ đó (ba dịch vụ công khai, 2/3, tối đa 5 vòng, nhớ 5 phút; `core/egressip`; chỉ qua IPv4: `tcp4`), dịch vụ nêu địa chỉ khác → `refused`/`not_own_ip`, không vòng nào có câu trả lời (không tới được, TLS, không đồng thuận) → `refused`/`egress_unverified`, nmap không chạy; worker cũ không biết mẫu này → `invalid_job`; worker cũ biết mẫu chạy dòng cũ của nó (`-sV` trên 99 cổng) cho job dò, core nhận ra `<scaninfo>` đó và báo worker cũ, không gửi job `-sV`; exposure báo "may be older"; không tăng proto) \| `external_full`, `external_disruptive` (bản 5 trước lần phát hành đầu: quét sâu IP công khai của chính hộp khi điều khoản kiểm thử của mục tiêu đã được chấp nhận; `--privileged -sS -sV -Pn -n -p- --script "<danh sách>" --script-timeout 5m --max-rate 300 --max-retries 2 --host-timeout 60m`, danh sách là **đúng một** trong hai danh sách script cố định đã rà: `nmapargv.FullScripts` cho `external_full`, `nmapargv.DisruptiveScripts` cho `external_disruptive`; không `--script-args`; cùng luật đích và cùng rào own-IP của worker như `external`, và worker **hỏi lại rào đó mỗi 3 phút** trong lúc nmap chạy: lần đầu không phải "có" thì giết nmap, bỏ cả kết quả, trả `stopped`/`not_own_ip` hoặc `stopped`/`egress_unverified` (`stopped` vì nmap đã chạy, `refused` chỉ khi nmap chưa chạy); worker chỉ chạy mẫu sâu khi nmap của nó đúng `nmapargv.ReviewedNmapVersion` (khác → `invalid_job`); chỉ giao cho worker có heartbeat `nmap.full=true`). \| `extra_ports` (theo sau mỗi lần quét `normal`/`versions` của một thiết bị, cùng tốc độ: `--privileged -sS -sV --script <nmapargv.Scripts> -n --max-rate R --max-retries 3 -p <nmapargv.ExtraPorts: 98 cổng của commonports cộng danh sách cổng quản trị đã rà> --host-timeout 30m`, đích IP riêng như mẫu LAN) \| `all_ports` (chỉ dò mọi cổng TCP mỗi tuần một lần cho thiết bị không mong manh, `--privileged -sS -n --max-rate R --max-retries 1 -p- --host-timeout 90m`, `R` ≤ 100, không `-sV`, không script; đích IP riêng) \| `port_versions` (`-sV` sau `all_ports` trên đúng các cổng job mang: `--privileged -sS -sV --script <nmapargv.Scripts> -n --max-rate R --max-retries 3 -p <cổng> --host-timeout 30m`, đúng một đích IP riêng; job nmap mang thêm `ports` (1..20 số nguyên tăng dần ở mẫu này; cũng ở job `-sV` của `external` như trên; `omitempty` ở mọi job khác) và chỉ giao cho worker có heartbeat `nmap.ports=true`, như `nmap.full`). Như `gentle_titles`, `extra_ports` và `all_ports` không tăng proto: worker cũ từ chối `invalid_job` trong lúc cập nhật (lần `extra_ports` đó bỏ, kết quả top 1000 vẫn giữ; thiết bị của lần `all_ports` đó chờ cửa sổ sau); worker cũ không nói `nmap.ports` nên không bao giờ nhận `port_versions` (cổng được ghi không phiên bản). `normal` và `versions` mang đúng `--script rdp-ntlm-info,http-ntlm-info,http-title,ssl-cert,http-hp-ilo-info,vmware-version` (`nmapargv.Scripts`: hai script NTLM type 1, không thông tin đăng nhập; tiêu đề trang và chủ thể chứng chỉ TLS); tên mẫu không đổi nên không tăng proto: worker của bản cũ dựng hai mẫu đó không script (chỉ trong lúc cập nhật; `sa_probe.flags` khi đó ghi thừa script, không bao giờ thiếu) |
| `jobs[].rate` | (nmap) 1 … 1000; `gentle` luôn `1`; `external` luôn `100`; `external_full` và `external_disruptive` luôn `300` |
| `jobs[].targets` | (nmap) 1 … 64 IPv4 riêng (RFC 1918 hoặc dải chung RFC 6598 100.64/10, `core/localnet.Addr`), chính tắc, không trùng (văn phạm `ValidateNmapArgs`); `external` (và `external_full`, `external_disruptive`): **đúng một** IPv4 công khai chính tắc (`egressip.IsPublicIPv4`: không riêng, CGNAT, loopback, link-local, tài liệu, multicast, dành riêng), và chỉ ba mẫu này nhận địa chỉ công khai |
| `jobs[].timeout_s` | nmap: 1 … 7200 = min(hết cửa sổ, 2 giờ); nuclei: 1 … 3600 = min(hạn của ngữ cảnh probe, 1 giờ); do `core` tính lúc giao |
| `jobs[].pack` (nuclei) | `{version, sha256}` của gói mẫu mà `core` đã chọn mẫu theo; worker từ chối khi chỉ mục trong image khác (`pack_mismatch`). `sha256` là **nhãn** do bộ dựng gói ghi trong chỉ mục (`pack.Index.SHA256`), không phải hàm băm worker tự tính; thứ được băm lại là từng tệp mẫu được chọn, so với `sha256` của mục tương ứng trong chỉ mục. `core` cũng so nhãn này với heartbeat **trước khi giao** (`ErrPackMismatch`, không thử lại); `pack_invalid` (băm lệch, link trong gói) là tín hiệu toàn vẹn: `ErrPackInvalid`, log ERROR, không thử lại |
| `jobs[].templates` (nuclei) | 1 … 32 **id** mẫu (`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`), không trùng; không đường dẫn, không URL, không YAML. Worker đổi id thành đường dẫn bằng chỉ mục đã kiểm; id không có trong chỉ mục → `invalid_job` |
| `jobs[].targets` (nuclei) | (phạm vi `lan`; `own_ip`: xem `scope`) 1 … 16 `{host, port, scheme}`: `host` là IPv4 riêng RFC 1918 hoặc RFC 6598 (100.64/10; trừ 100.100.100.200, metadata Alibaba Cloud) dạng chuẩn, không `.0`/`.255` (**không tên miền**, không IP công khai, phần 100/8 ngoài 100.64/10, loopback, link-local, benchmark, 240/4), `port` 1..65535, `scheme` `"http"` \| `"https"` \| `""` (mẫu mạng, `host:port`); không trùng |
| `jobs[].rate` / `max_host_errors` (nuclei) | `rate` 1 … 20 (`-rl`), `max_host_errors` 2 … 20 (`-mhe`) |
| `jobs[].scope` (nuclei, bản 5) | vắng hoặc `"lan"` = các quy tắc trên (`scan`); `"own_ip"` = kiểm lỗ hổng an toàn của `exposure` trên IP công khai của chính hộp: **đúng một** đích, `host` là IPv4 công khai chính tắc (`localnet.Public`, cùng luật `egressip.IsPublicIPv4`), `port` là cổng của job, `rate` luôn `5`, 1 … 32 mẫu của gói đã kiểm (mỗi mẫu là mẫu của một CVE mà `core` đã khớp, không chọn theo tag), **mỗi mẫu phải được đánh dấu `own_ip: true` trong chỉ mục của image** (quyết lúc dựng gói từ chính tệp mẫu: chỉ yêu cầu chỉ đọc, GET hoặc HEAD không thân, không thông tin đăng nhập, không lệnh) và tệp mẫu phải qua `pack.OwnIPText` do worker tự đọc; `-etags` của argv thêm `default-login,brute-force,sqli,time-based-sqli,xss,injection,code-injection,argument-injection,ssti,file-upload,rce,authenticated,login` (chưa kiểm ở lab với `-t`, không dựa vào); giá trị khác → `invalid_job`. `core` **bỏ trống** `scope` ở job LAN, nên worker cũ hơn nhận đúng dạng nó biết; job `own_ip` chỉ giao cho worker có heartbeat `nuclei.own_ip=true`, và không xếp hàng sau job nuclei khác (khe bận → `ErrNucleiBusy`, không gửi gì). Worker cũ hơn nếu nhận được job có `scope` thì giải mã chặt báo lỗi: không chạy gì |
| `jobs[].depth`, `jobs[].disruptive` (nuclei `own_ip`, bản 5) | vắng = job `own_ip` ở trên; `depth` `"full"` = quét sâu mục tiêu đã chấp nhận điều khoản kiểm thử (exposure): cùng **một** IPv4 công khai và cùng rào own-IP, `rate` luôn `20`, 1 … 200 mẫu, mỗi mẫu phải thuộc tập `deep` của chỉ mục **của image** (cộng `disruptive` khi `disruptive: true`; mẫu chỉ ở `kev`, như mẫu PUT/PATCH của KEV, không bao giờ), tệp mẫu (đã băm) phải qua `pack.FullText` (không method ghi, không ngoài băng); argv: cờ cố định như LAN trừ `-c 10`, `-etags dos,intrusive,fuzz,brute-force,default-login,authenticated` (với `disruptive`: `intrusive,fuzz`), thêm `-or -ot`; `disruptive` không có `depth` hay `depth` ngoài `own_ip` → `invalid_job`. `core` bỏ trống cả hai ở mọi job khác và chỉ giao job full cho worker có heartbeat `nuclei.full=true`; worker cũ hơn nhận được thì giải mã chặt báo lỗi: không chạy gì |
| `jobs[].scope`, `jobs[].domain` (nmap full và nuclei `depth` `full`, bản 5) | `scope` `"domain_ip"` + `domain` `{domain, name, token, proof_at?}` = quét sâu **một** IPv4 công khai **không** phải IP ra Internet của hộp, vì một tên dưới domain đã xác thực phân giải ra nó: nmap chỉ dạng `external_full`/`external_disruptive`, nuclei chỉ `depth` `"full"` (argv là dạng full của `own_ip`); `domain` theo regex domain của exposure, `name` là domain hay tên dưới nó, `token` 16 hex; `proof_at` (tuỳ chọn) là một tên cha của `domain` (đỉnh zone) nơi bản ghi của chính `domain` nằm. Worker không biết trường này từ chối job; worker kiểm `proof_at` nằm giữa `domain` và tên miền đã đăng ký của nó (`proofat.Within`, PSL cả hai phần) trước rào, không thì `invalid_job`. Không job nào khác mang `scope`/`domain` của nmap hay `domain` của nuclei; `core` chỉ gửi cho worker có heartbeat `domain_ip` |
| `cancel` | ≤ 8 id job phải dừng |

**External -sV batches** (this supersedes what the `jobs[].shape` row says about the `external` -sV job): the default scan's -sV runs in batches, each its own nmap job (`nmapargv.BatchFlags`: `--privileged -sS -sV -Pn -n --max-rate 100 --max-retries 2 --host-timeout <N>s -p <ports>`, 1 to 40 ascending ports, N whole seconds from 60 to 120, never `--version-light`), because nmap's `--host-timeout` drops every result of a host that times out. An `external` job with `ports` is one batch and also carries `host_timeout_s` (60..120; only on this job, `omitempty` on every other); the worker builds the argv from both (`nmapargv.BuildBatch`) and refuses other values as `invalid_job`. A worker built before `host_timeout_s` decodes jobs strictly and fails its poll on it, so the batch job expires unread (`worker_lost`); only while the box updates.

Trên dây **không** có argv, cờ, đường dẫn, URL hay phạm vi: worker dựng argv bằng chính `buildNmapArgs` + `ValidateNmapArgs` (gói lá `modules/sensor-active/nmapargv`); với job nuclei bằng `nucleiargv.Build` + `Validate` (gói lá `modules/scan/nucleiargv`).

**Bộ điều phối** (`core`, trong bộ nhớ):
- `sensoractive` gọi `Prober` **sau khi** ghi dòng `sa_probe` (INV-9 giữ nguyên thứ tự); không có heartbeat `active` trong 90 s → `ErrUnavailable` ngay, không tạo job.
- Hai **khe** riêng, nmap và nuclei (bản 2): mỗi khe một job đang chạy = một tiến trình trên hộp; một job nmap và một job nuclei chạy cùng lúc, nên "Scan now" và quét lại KEV không chờ sau một lượt quét dò 2 giờ. Job mới của một khe chỉ được giao khi khe đó rảnh và poll không còn nêu tên job vừa xong của khe đó hay một id mà `core` không biết (id lạ giữ cả hai khe tới khi worker hết báo nó); job thứ hai của cùng một loại chờ (vẫn chịu hạn của nó). Mọi quy tắc dưới đây (lease, chờ lấy, 30 s, hủy) áp cho từng khe.
- Job chưa được lấy trong 60 s → probe `failed` (`worker_unavailable`). Job đã giao mà poll sau đó báo `running` khác id đó và chưa có kết quả → probe `failed` (`worker_lost`: sensor khởi động lại giữa chừng hoặc phản hồi bị mất).
- Ngữ cảnh probe kết thúc (hết cửa sổ, `SettingsChanged`, hạ `rate`, thiết bị đổi, tắt module; INV-3) → job chưa giao thì bỏ; đã giao thì `cancel:[id]` ở long-poll kế tiếp (long-poll đang mở được đánh thức). `core` coi probe là `stopped` sau tối đa 30 s dù worker chưa xác nhận; job mới vẫn chờ `running` rỗng.

**Worker** (`vedette-sensor active`):
- Kiểm lại job (văn phạm bảng trên, `ValidateNmapArgs` trên argv đã dựng, hạn ≤ 2 giờ); sai → kết quả `refused` (`invalid_job`), không chạy gì. Nhận job khi khe cùng loại đang chạy job khác → `refused` (`busy`); khe kia không bị đụng.
- Chạy `/usr/bin/nmap` qua `core/exec` (allowlist binary + argv, không shell), nhóm tiến trình riêng, hạn `timeout_s`, stdout trần 8 MiB (`Truncated`).
- Job `nuclei` (bản 2): kiểm lại bằng `nucleiargv` (số lượng, mục tiêu IPv4 riêng, `rate`, `max_host_errors`), `timeout_s` 1..3600, **gói** (`pack.version` và `pack.sha256` phải bằng chỉ mục trong image, không thì `refused`/`pack_mismatch`), từng id mẫu phải có trong chỉ mục (không thì `invalid_job`); rồi đi qua **cả cây gói** bằng `Lstat`: chỉ thư mục và tệp thường, một symlink, fifo, socket hay thiết bị ở bất cứ đâu → `refused`/`pack_invalid`; băm SHA-256 từng tệp mẫu được chọn (mở bằng `os.Root`) và so với chỉ mục (lệch → `pack_invalid`). Chạy `/usr/local/bin/nuclei` qua `core/exec` với argv của `nucleiargv.Build` (mỗi mẫu một `-t <TemplatesDir>/<đường dẫn>`, không bao giờ cả thư mục), **môi trường sạch** (chỉ `PATH`, `LANG=C` và `HOME` do `core/exec` đặt; không `*_PROXY`, `ENABLE_CLOUD_UPLOAD`, `PDCP_API_KEY`, không gì của tiến trình cha), `HOME` là thư mục rỗng mới trên tmpfs (xoá và tạo lại trước mỗi lần chạy; không có `~/.config/nuclei`), nhóm tiến trình riêng, hạn `timeout_s`, stdout trần 4 MiB (`Truncated`); **stderr không bao giờ gửi** (nó chứa nhật ký lỗi `-elog`; worker chỉ đếm timeout theo đích vào `host_errors`). Thiếu binary → `failed`/`nuclei_missing`. Kết quả là JSONL thô trong `jsonl_b64`; `core` phân tích đóng khi lỗi (`nucleiout`).
- Job `nuclei` `own_ip` `depth` `full` (bản 5): văn phạm full của `nucleiargv`; mẫu ngoài tập mà độ sâu cho phép trong chỉ mục của image, hoặc tệp không qua `pack.FullText` → `invalid_job`; rồi đúng rào own-IP của job `own_ip` dưới đây. Job không full chỉ nhận mẫu tập `kev`.
- Job `nuclei` mọi phạm vi: tệp mẫu (đã băm) không qua `pack.NoChangeText` (method ghi, `@Host:`, ghi đè method, `INTO OUTFILE`, `xp_cmdshell`, `file_put_contents`, tải tệp multipart, `gopher://`/`dict://`) → `invalid_job`; nuclei không chạy (không tăng proto: chỉ worker từ chối thêm).
- Job `nuclei` phạm vi `own_ip` (bản 5): văn phạm `own_ip` của `nucleiargv` (một IPv4 công khai, `rate` 5, cờ cố định như LAN trừ `-etags`), mẫu không có `own_ip: true` trong chỉ mục của image hoặc tệp mẫu (đã băm) không qua `pack.OwnIPText` → `invalid_job`; rồi, **ngay trước nuclei**, worker tự kiểm rằng hộp ra Internet qua địa chỉ đó (cùng rào của mẫu nmap `external`: ba dịch vụ công khai, 2/3, tối đa 5 vòng, nhớ 5 phút, `core/egressip`): địa chỉ khác → `refused`/`not_own_ip`, không vòng nào trả lời → `refused`/`egress_unverified`; nuclei không chạy.
- Job `domain_ip` (nmap full hay nuclei full, bản 5): **không** hỏi rào own-IP; ngay trước khi công cụ chạy worker tự kiểm rào domain (`core/domainfence`): văn phạm (sai → `invalid_job`), `token` phải bằng 16 ký tự hex đầu của HMAC-SHA256(khoá của worker, `"vedette-verify\x00"+domain`) (khác, hay `domain` không có trong bản chép danh sách của host `/var/lib/vedette-fence/domains`, đọc lại mỗi lần kiểm; bản chép không đọc được thì đọc lại một lần sau 1 s rồi mới từ chối → `token_foreign`), TXT của `domain` (hay của `proof_at` khi có; luật `domainfence.Owned`: cả `_vedette-verify.<tên>`, không qua CNAME, không wildcard, tên hỏi dạng gốc) chứa `vedette-verify=<token>` (không → `target_not_owned`), `name` phân giải A (resolver hệ thống, 10 s) ra tập có đích (không → `name_moved`), tra CNAME (job gây gián đoạn và tên chính tắc ra ngoài domain → `cname_outside`); lỗi DNS → `ownership_unchecked`; câu "có" giữ 5 phút cho mỗi `(domain, name, ip)`. Worker không có khoá → `invalid_job`. Job nmap sâu và job nuclei `domain_ip` kiểm lại (không cache) mỗi 3 phút khi công cụ chạy; câu không phải "có" → giết công cụ, `stopped` với mã đó, bỏ đầu ra. Mỗi lần từ chối/dừng là một dòng log của worker kèm chuỗi CNAME.
- **Huỷ**: id có trong `cancel` → giết nhóm tiến trình, kết quả `stopped` (`cancelled`).
- **Lease**: 60 s không có lần poll `200` nào, hoặc `instance` khác `instance` lúc nhận job → giết nhóm tiến trình và **bỏ** kết quả (bên giao job đã không còn). `core` sập không để lại nmap mồ côi.
- Trong lúc chạy vẫn long-poll liên tục với `running=<id>` (bản 2: `running=<id>,<id>` khi cả hai khe bận).
- Trong lúc một kết quả đang được gửi, vòng poll chờ (`waitPost`, tối đa bằng lease): khe kia không được poll trong thời gian đó, nên một job mới của nó chờ tới khi kết quả gửi xong (chấp nhận: kết quả ≤ 11 MiB, 60 s).

### 6.5 `POST /sensor/v1/jobs/{id}/result` (active)

```json
{ "status": "done", "reason": "", "exit_code": 0, "truncated": false, "xml_b64": "PD94bWwg…" }
{ "status": "done", "reason": "", "exit_code": 0, "truncated": false, "xml_b64": "", "jsonl_b64": "eyJ0ZW1w…" }
```

| Trường | Quy tắc |
|---|---|
| `status` | `done` \| `failed` \| `stopped` \| `refused` |
| `reason` | `""` hoặc một trong `invalid_job`, `busy`, `nmap_missing`, `exec_failed`, `deadline`, `cancelled`; bản 2 thêm `nuclei_missing`, `pack_mismatch`, `pack_invalid`; sau đó thêm `not_own_ip` và `egress_unverified` (chỉ cho job `external`, chỉ `core` cùng bản phát hành gửi job đó: không tăng proto); job nuclei `own_ip` dùng hai mã đó; job nmap sâu dùng chúng với `status` `stopped` khi worker kiểm lại giữa chừng một job nmap sâu và dừng nó (nmap đã chạy, đầu ra bị bỏ), với `refused` khi chưa chạy; `token_foreign`, `target_not_owned`, `name_moved`, `ownership_unchecked`, `cname_outside` là của job `domain_ip` (`refused` khi chưa chạy, `stopped` khi kiểm lại giữa chừng dừng nmap) |
| `exit_code` | −1 … 255 (−1 = không chạy hoặc bị giết) |
| `truncated` | stdout chạm trần (nmap 8 MiB, nuclei 4 MiB) |
| `xml_b64` | base64 chuẩn của stdout nmap; sau giải mã ≤ 8 MiB; rỗng khi không phải `done` (khác → `400`); luôn có mặt, rỗng ở kết quả nuclei |
| `jsonl_b64` (bản 2) | base64 chuẩn của stdout nuclei (`-jsonl`); sau giải mã ≤ 4 MiB; chỉ khi `done`, và **không cùng `xml_b64`** (cả hai → `400`); vượt 4 MiB → `413` |
| `host_errors` (bản 3, nuclei) | tuỳ chọn, bỏ trống khi không đích nào có timeout: mảng ≤ 16 mục `{target "host:port", errors 1..1048576, unreachable bool}`, mỗi đích một mục, chỉ khi `done` (khác → `400`). Worker đếm từ nhật ký lỗi của nuclei (`-elog /dev/stderr`) các dòng `kind` = `network-temporary-error` của từng đích; `unreachable` = `errors` ≥ `max_host_errors` của job. `core` từ chối (`ErrResultRejected`) đích ngoài job, hay `unreachable` không đúng với `errors`; kết quả nmap mang `host_errors` cũng bị từ chối |

`{id}` phải là job **đang chạy** do chính `core` này giao cho vai `active`; còn lại (id lạ, job đã xong, gửi lại lần hai) → `404 unknown_job`. Thân > 11 MiB, XML giải mã > 8 MiB hoặc JSONL giải mã > 4 MiB → `413 payload_too_large` và probe `failed`. Trả `204`.

`core` **không tin** `status` của worker: `done` mà `exit_code ≠ 0` hoặc `truncated` → probe `failed`, cả lô bị bỏ (INV-7); XML phân tích bằng `parseNmapXML` (đã fuzz) và `onlyTargets` trong `core`, nên quan sát và phần mềm từ nmap không bao giờ đi trên dây. `refused` → probe `failed` và log ERROR (worker và `core` bất đồng về văn phạm là lỗi hoặc bị chiếm); `nmap_missing` → sức khoẻ `unavailable` (INV-6).

**SP-3b (bản 2, nuclei; mã `modules/sensor-active/{dispatch.go,nuclei.go,worker/}`, `core/sensorlink`).**
- `Job` mang `kind`; hai khe trong `Dispatcher` (nmap, nuclei) và hai `cur` trong worker; `running` của poll là danh sách ≤ 2 id (`Backend.Jobs(ctx, wait, running []string)`, `Client.Jobs(ctx, running []string, wait)`). Một poll mà worker nêu id của một khe, id vừa xong của một khe, hay id lạ được xử lý như SP-3 nhưng theo từng khe; id lạ nhận `cancel` ngay lần đầu và giữ cả hai khe.
- Giao hạn: nuclei `timeout_s` = min(hạn ctx còn lại, 3600); trần phía `core` `timeout_s` + 30 s như nmap, `Health` của nuclei nói "quá hạn" riêng.
- Seam cho `scan`: `sensoractive.Scanner` (`Ready(ctx) error`, `RunNuclei(ctx, NucleiRequest) (nucleiout.Outcome, error)`), `*Dispatcher` thoả. `RunNuclei` kiểm văn phạm (như `nucleiargv.Build`) trước khi giao; trả `ErrScannerUnavailable` (và các lỗi bọc nó: `ErrScanWorkerUnavailable`, `ErrNucleiMissing`, `ErrPackMismatch`) khi máy quét không sẵn sàng (503 `scanner_unavailable`); `ErrWorkerLost`, `ErrWorkerRefused`, `ErrResultRejected` (kể cả JSONL bị `nucleiout` từ chối), `ErrOutputTruncated`, `*exec.ExitError` làm lượt chạy `failed`.
- `core` chỉ tin mã thoát, `truncated` và các byte JSONL; mọi dòng ngoài mẫu hay đích (host:port) của job là cả lượt bị bỏ ((7)). Một kết quả nuclei có `xml_b64` (hay ngược lại) bị từ chối.

**Đọc SNMP (bản 5; mã `core/sensorlink/wire.go`, `modules/sensor-active/{snmp_dispatch.go,snmp.go,worker/snmp.go}`).**
- Heartbeat `active` thêm `"snmp": true` (worker bản 5 luôn gửi: gosnmp nằm trong binary). Thiếu = worker bản 4: `SNMPHealth` nói worker cũ hơn `core`, không job `snmp` nào được tạo.
- Job (đổi trước lần phát hành đầu của bản 5): `{ "id", "kind": "snmp", "timeout_s" 1..3600, "rate" 1..1000, "targets": [ 1..64 × {"ip", "credential": {"version": "v2c", "community"} | {"version": "v3", "user", "auth": "sha"|"sha256", "auth_pass", "priv": "aes128"|"", "priv_pass"} (thêm `"port"` 1..65535 tuỳ chọn: cổng UDP của agent; vắng = 161)} ] }`. **Mỗi credential nằm trong đúng một đích**: không có danh sách credential chung, không chỉ số; worker chỉ gửi credential của một đích tới địa chỉ của chính đích đó (bí mật của một thiết bị chỉ đi tới địa chỉ đọc của nó; `core` từ chối dựng job cho địa chỉ khác địa chỉ đọc đã lưu của thiết bị, sensor-active INV-10 (d)). Community 1..64, user 1..64, mật khẩu v3 8..64 ký tự ASCII in được; không v1, MD5, DES, noAuthNoPriv. IP: IPv4 chính tắc, không trùng, local (`core/localnet`). `sensorlink.CheckSNMPJob` là văn phạm chung; `core` kiểm trước khi giao, worker kiểm lại (`refused`/`invalid_job`, không gói nào). **Không có OID trên dây**: worker luôn GET đúng danh sách của nó (sysDescr, sysObjectID, sysName, entPhysicalClass/ModelName/SoftwareRev/SerialNum.1, MIKROTIK-MIB mtxrLicVersion.0). Bí mật đi trên dây chỉ trong link mTLS này; `SNMPCredential` tự in ra `[redacted]`.
- Worker: từng đích một, gửi credential của đích tới cổng UDP của nó (`port`, vắng = 161); timeout 2 s, thử lại 1; sau mỗi đích nghỉ `2/rate` giây (một lần đọc v3 là hai gói). Khe thứ ba (`slotSNMP`), job `snmp` thứ hai khi khe bận → `busy`. Hết `timeout_s` → `done` với `reason: "deadline"` và các đích đã xong.
- Kết quả: `{"status": "done", …, "xml_b64": "", "snmp": [ ≤ 64 × {"target", "status": "ok"|"no_answer"|"auth_failed"|"unknown_user"|"error", "values": {"sys_descr", "sys_object_id", "sys_name", "ent_class", "ent_model", "ent_software", "ent_serial", "os_version" (MIKROTIK-MIB mtxrLicVersion.0; vắng khi rỗng)}} ]}`; mỗi giá trị ≤ 512 byte (worker cắt 255, UTF-8 hợp lệ), giá trị chỉ khi `ok`; `snmp` chỉ khi `done`, không cùng `xml_b64`/`jsonl_b64`/`host_errors` (khác → `400`). `core` từ chối câu trả lời cho đích job không nêu (`ErrResultRejected`) và tự phân tích giá trị (không tin cậy, sensor-active INV-10).
- `core`: `sensoractive.Service` ghi dòng `sa_probe` (`shape` `snmp`) **trước** khi mở bí mật và giao job; một job snmp một lúc (`snmpMu`).

**SP-3 (làm rõ, mã `modules/sensor-active/{dispatch.go,worker/}`).**
- `timeout_s` được tính lúc **giao** job (`min(hạn của ngữ cảnh probe còn lại, 7200)`, làm tròn lên), không phải lúc xếp hàng, để job chờ lấy lâu không chạy quá hạn của probe.
- `wait` của worker tối thiểu 1 s: dây chỉ mang số giây nguyên, `wait=0` là poll trả ngay và sẽ lặp.
- Reply `jobs` mang `cancel:[id]` **mỗi lần** cho tới khi worker báo xong, nhưng chỉ lần đầu đánh thức long-poll đang mở. Một poll còn gọi tên job **vừa xong** được trả lời ngay một lần (để worker poll lại với `running` rỗng; job kế tiếp không phải chờ hết `wait`).
- Thân kết quả bị máy chủ từ chối (`413` hoặc `400`) khi `{id}` đang chạy: `Backend` được báo qua giao diện tùy chọn `sensorlink.ResultRejector` và probe `failed` ngay (worker không gửi lại kết quả); `404` không báo gì (không có job nào bị ảnh hưởng).
- `cancel` đến cùng reply với job: worker không chạy nmap, gửi `stopped`/`cancelled`. Job thứ hai đến khi đang chạy job khác: `refused`/`busy`, gửi ngay, job đang chạy không bị đụng. Cả `refused` cũng giữ `running=<id>` trong các poll tới khi kết quả đã gửi xong, để `core` không báo nhầm `worker_lost`.
- Worker không gửi kết quả khi bị giết vì lease, `instance` đổi, `409 module_off` hay tắt tiến trình; gửi `stopped`/`deadline` khi hết `timeout_s`.
- Sống/chết của job đang chạy do **poll cuối nêu tên nó** quyết định (90 s không poll → `worker_lost`), cộng trần phía `core` `timeout_s` + 30 s. Poll nêu một `running` mà `core` không giữ (job đã bỏ, hoặc `core` vừa khởi động lại) nhận ngay `cancel:[id]`.
- Worker gửi lại kết quả khi 429, 503 hoặc lỗi kết nối (sau `Retry-After`/quãng lùi, trong 60 s), không gửi lại khi 400, 403, 404, 409, 413; vòng poll chờ cho tới khi kết quả đã gửi xong. Id job không khớp `^[0-9a-f]{32}$` bị bỏ, không dùng trong URL hay log.
- Bó khoá phải là tệp thường, trong thư mục không phải symlink, mode nằm trong `0640` (core ghi `0640`; bit nào ngoài đó, như nhóm ghi hay người khác đọc, bị từ chối); client mở qua `os.OpenRoot` của thư mục chứa.
- Hậu quả của kết quả trong `core`: mã thoát `> 0` → probe `failed` (nmap thoát mã đó); `< 0` hoặc `status ≠ done` → `failed`; `refused` → `failed`, log ERROR; `reason=nmap_missing` → `unavailable` tới heartbeat kế tiếp. Dòng `sa_probe.result` ghi mã: `worker_unavailable`, `worker_lost`, `nmap_missing`.

**SP-4 (làm rõ, mã `modules/sensor-passive/{capture,backend.go}`).**
- Mỗi lần gửi `observations` dùng một `seq` mới trong cùng một `epoch`, kể cả khi gửi lại các mục đã gửi hụt: lô gửi lại có thể là tập mục khác (đã chia đôi, đã bỏ mục độc), và `core` bỏ `seq` đã thấy. Sensor thử lại **sau** `Retry-After` của `core` nhưng không quá 60 s; một lỗi kết nối, `426`, `429`, `503` và `403 cert_retired` là "thử lại" (chỉ `503 store_busy` cùng một heartbeat vừa thành công mới dẫn tới chia lô; `503 not_ready` không bao giờ); `413` chia đôi (một mục vẫn `413` thì bỏ); mọi mã khác bỏ lô và đếm `batch_dropped`. Một lô hỏng 3 lần liên tiếp bị chia đôi cho tới khi một mục đứng riêng; mục đó bị bỏ (đếm `observation_failed`) chỉ khi một heartbeat vừa thành công.
- Kiểm mục ở `core`: một dòng `mac` phải có `mac` và `value == mac`; `kind` chỉ nhận `ap`, `switch`, `router`, `printer`, `iot` (kẹp 0.6, 0.6, 0.6, 0.5, 0.3); mục có MAC hoặc IP của chính hộp (theo card của host) là `refused`; `mac` đúng dạng (chữ thường) và không phải địa chỉ nhóm hay toàn không; `ip` IPv4 unicast (IPv6 là `invalid_item`, vì tài sản chỉ có địa chỉ IPv4); `confidence` ngoài [0,1] là `invalid_item`, trong khoảng thì kẹp theo trần của trường: `mac` 0.9, `hostname` 0.7, `kind` 0.6, `model` 0.5, `vendor` 0.4, `os` 0.3; thiếu `seen_at` là `out_of_window`.
- Bộ lọc lặp: cùng (MAC, IP, trường, giá trị) trong 15 phút được xác nhận mà không ghi (không nằm trong `rejected[]`); trần 6000 mục mỗi phút cho vai `passive` (phần vượt: `budget_exhausted`, không đọc). Thêm hạn mức 4 địa chỉ IP mới mỗi MAC mỗi giờ.
- Hạn mức chống ngập tính **trước** khi ghi và áp vào hạn mức **sau** khi inventory nhận: kho lỗi (`503`) không tốn hạn mức. Mục không có MAC tính theo địa chỉ IP. "Hết hạn mức" được ghi log một lần mỗi phút.
- `drops` mang **35 khoá đã biết**: `arp_mac_mismatch`, `batch_dropped`, `capture_failed`, `dhcp_mac_mismatch`, `dns_name_rejected`, `excluded`, `filters_invalid`, `flows_dropped`, `fragment_skipped`, `malformed_{arp,dhcp,dns,ethernet,http,ipv4,lldp,mdns,ssdp,tcp,tls,udp}`, `metadata_dropped`, `metadata_failed`, `new_macs_dropped`, `new_macs_unconfirmed`, `non_unicast_ip`, `observation_failed`, `observation_rejected`, `observations_dropped`, `unusable_record`, `value_empty`, `value_meaningless`, `value_truncated`, `values_dropped`, `vendor_rejected`; khoá lạ nhưng đúng dạng (`^[a-z][a-z0-9_]{0,47}$`) được `core` **bỏ qua và ghi log một lần mỗi khoá** (tương thích về sau); giá trị âm, kiểu sai hoặc khoá sai dạng là `400`; tên card trùng trong `interfaces` cũng `400`. Giá trị là bộ đếm cộng dồn từ lúc tiến trình sensor khởi động. `filters_invalid` tăng mỗi lần sensor nhận một bộ lọc nó không biên dịch được; lúc đó nó không bắt gói.
- Sensor gửi heartbeat ngay khi khởi động và mỗi 30 s, kể cả khi `config` nói `interface ""`; trong lúc `module_off` nó không gửi. Danh sách `interfaces` bị lọc theo hình dạng của dây (tên card theo regex, MAC chữ thường, ≤ 32 card, ≤ 8 tiền tố IPv4 mỗi card).
- `config` long-poll: `core` đọc lại cài đặt (bộ lọc của trang network) mỗi 5 s trong lúc giữ request, và `SetInterface` đánh thức ngay. Bộ lọc `core` không đọc được cho `interface ""` (cùng ETag với cấu hình "không bắt gói" thường).
- `Client.PostObservations` là một lần thử, không lùi, không ngủ, và là đường duy nhất gửi quan sát (không còn `SendObservations`).

### 6.6 `POST /sensor/v1/jobs/{id}/progress` (active, #830)

How far a running nmap or nuclei job is, so the scan page shows a phase, a bar and an estimate instead of "0/1 devices done" until the device ends. Added to protocol 5 before its first release, like the nuclei `own_ip` fields (no new number: the latest release speaks 4); optional on both sides.

- Body (`JobProgress`, ≤ 1 KiB, strict decoding): `{phase, percent, done, total, remaining_s}`. `phase` ∈ `discovery`, `ports`, `services`, `scripts`, `vulns`; `percent` is `-1` (none) or 0 … 100; `0 ≤ done ≤ total ≤ 2^20` (nuclei's template × target checks; `0`/`0` = no count); `remaining_s` 0 … 86400 (the tool's own estimate, 0 = none). Anything else is `400`.
- Source, no extra work asked of the tools: nmap gets `--stats-every 5s` (part of every shape in `nmapargv`, before `-oX -`), which writes `<taskprogress task percent remaining etc/>` into the XML on stdout; the worker reads those lines while nmap runs (task names map to phases; an unknown task, a malformed line or one over 512 bytes is ignored) and `core`'s XML parser skips them. nuclei: no new flag. Its `-ms` lines (one per template and target that ran) are counted while it runs, through the same `nucleiout` reader `core` uses; a line over 64 KiB is not counted. nuclei's own `-stats` is not used: it starts a `/metrics` HTTP listener (clistats) inside the scan container.
- nmap runs on a terminal of its own (`core/exec` `Binary.TTY`: a new pseudo-terminal is its stdin and controlling terminal, in a new session; stdout and stderr stay the pipes). nmap 7.95 prints `--stats-every` only when `/dev/tty` opens and its process group is the terminal's foreground one (`nmap_tty.cc`; nmap lifted that in 2026-06, nmap#3175, after 7.95): without a terminal, a test box got no `<taskprogress>` at all (#830). Where no terminal can be opened nmap runs as before, and the worker still names the phase: the one its command line starts with (`discovery`, or `ports` with `-Pn`) as nmap starts, then `ports` at nmap's first `<hosthint>` (written and flushed when discovery finds a host up); these only move forward, a `<taskprogress>` is taken as it is.
- Throttle: the worker keeps only the latest state of a job and posts it as the job starts, then at most every `ProgressEvery` (5 s), one attempt, never retried, never after the job's result (the reporter is joined before the result is posted). `core` enforces it too: a report of a job sooner than `ProgressEvery` − 1 s after the last one it took is answered `204` and dropped. A report takes a body slot like any body, without waiting: none free → `503 store_busy`, unread and dropped (the worker does not retry it).
- `core`: answered before the body is read like a result (`404 unknown_job` for a job that is not running; a `core` without the receiver answers `404` too, and an older build of protocol 5 without the route `403 forbidden_route`; the worker logs both at debug). The `Dispatcher` passes the report to the `progress.Sink` the probe's context carried (the scan run or the exposure scan waiting for that job), under its lock so no report lands after the job's result, and stores nothing (the first report of a job opens a new pass of its phase); a report of a job being cancelled is dropped. Advisory only: nothing is decided from it.

### 6.7 `POST /sensor/v1/metadata` (passive)

The mirror-port metadata the capture extracted (DNS query names, TLS server names, HTTP hosts, IPv4 flows), reduced to what core's bad-address matching needs. Added to protocol 5 before its first release, like §6.6 (no new number); optional on both sides.

- Body (`MetadataRequest`, ≤ 512 KiB, strict decoding): `{items: [{kind, at, src, dest}]}`, 1 … 1000 items. `kind` ∈ `dns`, `sni`, `http`, `flow`; `at` is when it was seen; `src` is the LAN device's IPv4 address in canonical form; `dest` is the name (lower case, no trailing dot, ≤ 253 bytes of `a-z 0-9 - _` in non-empty labels of ≤ 63 bytes) or, for `flow`, the destination IPv4 address in canonical form. One item that is not of this shape refuses the whole body (`400`): the sensor checks its items with the same rule (`sensorlink.ValidMetadataItem`) before it sends them. No epoch, no seq: a batch sent twice makes the same matches, which core keeps once.
- Nothing else of a packet is on the wire: no port, no counter, no resolver address, no payload. A flow is sent only in the direction that started the conversation (a TCP SYN without ACK; a SYN-ACK or RST is an answer; mid-connection, and for a UDP datagram from a port below 1024 to one above, the side with the higher port is the client; otherwise the first packet seen) and only to an address a feed could list (not private, shared, loopback, link-local, multicast or broadcast): a LAN server answering a scan is never a flow to the scanner. Each (kind, src, dest) is sent once per 10 minutes.
- Pacing: the capture loop only queues (at most 10,000 items; more are dropped); a goroutine of its own posts batches of at most 1000 items, at least 2.5 s apart (2 per 5 s), waiting as long as a `429`/`503` `Retry-After` asks (capped at 60 s) and doubling up to 60 s while core does not answer. `503 store_busy` is offered 5 times, then dropped; `400`, `403` and `413` drop the batch; `409 module_off` drops the queue. Every loss is counted as `metadata_failed`.
- `core`: a Backend without the receiver answers `403 forbidden_route` before the body is read. `sensor-passive` hands the batch to the logs module's matching (`logs.MatchMirror`), which looks up each destination in the threat feeds as it does for a firewall line and stores only the matches (`logs_ioc_hits`, `seen_via` `span_dns`, `span_sni`, `span_http`, `span_flow`). With the logs module off the batch is answered `204` and dropped; a matching that cannot store its hits, or could not look at the whole batch (a feed lookup failed, or the batch reached the 50 new hits one batch stores), is `503 store_busy`: the sensor sends the batch again, and the pairs already stored are skipped as repeats.

## 7. Bảng lỗi

| HTTP | `code` | Khi nào | Sensor làm gì |
|---|---|---|---|
| — | (handshake hỏng) | sai CA, hết hạn/chưa hiệu lực, sai EKU, sai/thiếu URI SAN, serial về hưu, TLS < 1.3 | đọc lại bó khoá; lùi 1 → 60 s có jitter, thử lại |
| 200 | `rejected[].code` | thành công một phần (§6.2) | **không thử lại** |
| 304 | — | `config` không đổi | poll lại ngay |
| 400 | `invalid_request` | không phải JSON, trường lạ, khoá trùng, quá sâu, thiếu/sai kiểu, query lạ, có `Content-Encoding` | bỏ lô, đếm, không thử lại |
| 403 | `forbidden_route` | route không thuộc vai (trước khi đọc thân) | lỗi lập trình: log ERROR, không thử lại route đó |
| 403 | `cert_retired` | serial của lá không còn là hiện hành/ngay trước (kiểm mỗi request) | đọc lại bó, đóng kết nối rảnh, lùi rồi thử lại |
| 404 | `unknown_job` | kết quả cho job không đang chạy hoặc không do `core` này giao | bỏ kết quả |
| 409 | `module_off` | module của vai tắt | **dừng ngay**, bỏ hàng đợi, không xả lô cuối (SYS-5); hỏi lại `config`/`jobs` mỗi 60 s (thường thì host đã dừng hẳn container) |
| 409 | `poll_in_progress` | long-poll thứ hai của cùng vai | lỗi lập trình: đợi poll đang mở xong |
| 413 | `payload_too_large` | thân vượt trần route; XML > 8 MiB | quan sát: chia đôi lô (lô một mục vẫn 413 → bỏ, đếm); kết quả job: không gửi lại (probe đã `failed`) |
| 426 | `proto_unsupported` | thiếu `X-Vedette-Proto`, hoặc không phải bản của `core` hay bản liền trước (mới hơn `core`, hay cũ hơn hai bản) | giữ hàng đợi, lùi tới 60 s, thử lại (§10) |
| 429 | `rate_limited` | quá 10 request/giây, burst 20, mỗi vai | chờ `Retry-After` |
| 503 | `store_busy` | kho của `core` bận | chờ `Retry-After`, gửi lại **cùng** lô |
| 503 | `not_ready` | `core` chưa đủ dữ kiện để xét lô: vai `passive` chưa biết card của chính hộp (host đã cấu hình mà chưa đưa danh sách; không có host và không có heartbeat dưới 90 s) | chờ `Retry-After` (5 s), gửi lại cả lô; **không** chia lô, không đổ cho mục nào |
| 500 | `internal` | lỗi khác của `core` | bỏ lô, đếm (OTLP: không thử lại) |
| — | (không có phản hồi) | lỗi kết nối, `core` đang khởi động lại | gửi lại cùng lô sau quãng lùi 1 → 60 s có jitter (`holdOff`); quá trần hàng đợi trong bộ nhớ thì bỏ cũ nhất và đếm |

SP-1 (làm rõ): chỉ request qua được bước 1 đến 3 (kể cả `module_off`) mới tiêu một token của nhịp; `Retry-After` của `429` là số giây tới token kế (làm tròn lên, ít nhất 1). Mọi mã trong bảng do `core/sensorlink/errors.go` (`codes`) định nghĩa; thân lỗi có thông điệp cố định theo mã. Bảng này **không** vào `API_CONVENTIONS` §3.3 (đó là API công khai của GUI; dây sensor là nội bộ).

Thứ tự kiểm ở `core` cho mỗi request: serial (`cert_retired`) → `X-Vedette-Proto` (`426`) → route theo vai (`403`) → module (`409 module_off`) → nhịp (`429`) → long-poll duy nhất (`409 poll_in_progress`) → (chỉ kết quả job) id đúng dạng (`400`) rồi là job đang chạy (`404 unknown_job`), **không đọc thân** → chỗ chứa thân của vai (`503 store_busy`, **không đọc thân**) → trần thân (`413`) → giải mã chặt (`400`) → handler.

**Thân trong bộ nhớ có trần theo vai (M1 của rà soát SP-1; SYS-6).** Tốc độ 10/s không giới hạn số thân `core` đang giữ cùng lúc: một chứng chỉ bị chiếm sẽ giữ hàng chục thân 11 MiB mở trong 10 s. Nên trước khi đọc **bất kỳ** thân nào, request lấy một chỗ: tối đa **2 thân đang đọc cùng lúc mỗi vai** (`MaxBodiesPerRole`), và **1** cho `POST /jobs/{id}/result` (`MaxResultBodies`; worker chạy một job một lần). Không có chỗ → `503 store_busy` với `Retry-After: 1`, thân không được đọc, kết nối bị đóng; chỗ trả lại khi request kết thúc (kể cả khi kết nối đứt hay thân quá hạn). Kết quả job: trước khi đọc thân, `core` hỏi `Backend.JobRunning(id)`; id sai dạng → `400`, job không đang chạy → `404 unknown_job`, cả hai không đọc thân và đóng kết nối. Sensor xử lý `503` như cũ: chờ `Retry-After`, gửi lại cùng lô.

**Một sensor không giữ được các chỗ kết nối (WP-31).** `MaxConns` = 64 = 16 chỗ cho kết nối đang bắt tay (`MaxPending`) + phần của vai **tại bắt tay TLS** (vai đọc từ chứng chỉ đã xác minh): `passive` tối đa 32, `active` tối đa 16 (`MaxConnsPassive`, `MaxConnsActive`); kết nối vượt phần của vai hỏng bắt tay, kể cả khi nó không gửi byte nào, trên HTTP/1 và h2. Trên HTTP/1 mọi từ chối trước khi đọc thân trả `Connection: close` kèm hạn đọc 1 s (`DrainGrace`) khi yêu cầu có thể mang thân (h2: không đóng cả kết nối); `GET` có thân = `400 invalid_request`. `ReadTimeout` toàn yêu cầu = `ReadHeaderTimeout + BodyTimeout` (15 s); long poll gỡ hạn đó cho chính nó. Giới hạn đã biết: dòng TCP/TLS chưa xác thực trước bắt tay chưa tính theo vai được.

## 8. Sequence

```mermaid
sequenceDiagram
    participant H as vedette-host
    participant C as core
    participant S as sensor (passive)
    participant W as scan (active)
    H->>H: dựng unit hằng (volume khoá theo vai)
    C->>C: CA + lá; ghi creds/passive/sensor.pem, creds/active/sensor.pem; rồi mới nghe 127.0.0.1:8444
    S->>C: GET /config?wait=25 (mTLS vai passive)
    C-->>S: 200 {interface, span, extract, filters} ETag "e1"
    loop mỗi 30 s
        S->>C: POST /heartbeat {interfaces, span, drops}
        W->>C: POST /heartbeat {nmap}
    end
    S->>C: POST /observations {epoch, seq 41, items}
    C-->>S: 200 {ack_seq 41, rejected [{3, budget_exhausted}]}
    W->>C: GET /jobs?wait=25&running=
    Note over C: sensoractive ghi sa_probe, Prober giao job
    C-->>W: 200 {instance, jobs [j1], cancel []}
    W->>C: GET /jobs?wait=25&running=j1
    Note over C: cửa sổ đóng (INV-3)
    C-->>W: 200 {instance, jobs [], cancel [j1]}
    W->>W: giết nhóm tiến trình nmap
    W->>C: POST /jobs/j1/result {stopped, cancelled}
    C-->>W: 204
```

## 9. Giới hạn

| Mục | Giới hạn |
|---|---|
| Thân `observations` | 1 MiB; 1 … 500 mục; `value` ≤ 200 byte |
| Cửa sổ `seen_at` | 24 giờ trước … 5 phút sau giờ `core` |
| Thân `heartbeat` | 64 KiB; ≤ 32 card, ≤ 8 tiền tố IPv4 mỗi card, ≤ 64 khoá `drops` |
| Thân kết quả job | 11 MiB; XML ≤ 8 MiB, JSONL ≤ 4 MiB sau giải mã base64 |
| Thân `metadata` (§6.7) | 512 KiB; 1 … 1000 mục; `dest` ≤ 253 byte; at most one request per 2.5 s, longer when core asks |
| Thân `progress` (§6.6) | 1 KiB; at most one per job every 5 s (core drops one within 4 s of the last); a body slot taken without waiting, none free → `503`, dropped |
| Job nmap | 1 … 64 đích, `rate` 1 … 1000, `timeout_s` 1 … 7200 |
| Job nuclei (bản 2) | 1 … 32 id mẫu, 1 … 16 đích IPv4 riêng, `rate` 1 … 20, `max_host_errors` 2 … 20, `timeout_s` 1 … 3600; JSONL ≤ 1024 dòng |
| Job chạy cùng lúc | một nmap và một nuclei (`running` ≤ 2 id); một job mỗi loại trong một reply |
| `cancel` mỗi phản hồi | 8 |
| Phản hồi `core` (sensor đọc) | `config`, `jobs` 64 KiB; khác 16 KiB |
| `wait` | 0 … 30 s (mặc định 25) |
| Nhịp request | 10/giây, burst 20, mỗi vai (long-poll cũng tính) |
| Long-poll mở | 1 mỗi vai |
| Thân đang đọc cùng lúc | 2 mỗi vai, 1 cho kết quả job; không có chỗ → `503 store_busy`, `Retry-After: 1` |
| Kết nối cùng lúc | 64 cho cả listener (`PendingListener`: 16 đang bắt tay + 32 passive + 16 active) |
| Hạn mức chống ngập (`core`) | MAC mới 60/phút và 200/giờ; giá trị mới và địa chỉ IP mới 4 mỗi (MAC, trường) mỗi giờ; 6000 mục/phút cho vai `passive`; lặp trong 15 phút không ghi |
| Heartbeat | mỗi 30 s; `online` khi ≤ 90 s |
| Lease của worker | 60 s không poll thành công |
| Job chờ lấy | 60 s |
| Chứng chỉ | 7 ngày; cấp mới khi còn ≤ 1/3 |
| Epoch giữ lại | 2 mỗi sensor |
| Timeout máy chủ | `ReadHeaderTimeout` 5 s, `WriteTimeout` 35 s |

Các số là điểm xuất phát để đo lại khi có mã (ARCHITECTURE §11), không phải kết quả đo.

## 10. Versioning

- Đường dẫn `/sensor/v1`; `X-Vedette-Proto` là số nguyên, hiện `5` (bản 5: job `snmp`, và, trước lần phát hành đầu của bản 5, `scope` của job nuclei và `nuclei.own_ip` trong heartbeat, rồi `nmap.full` trong heartbeat và hai mẫu `external_full`, `external_disruptive`, theo cùng cách: chỉ giao cho worker đã nói `full`; rồi `port` của credential SNMP: `core` bỏ nó khi là 161, nên worker bản 5 dựng trước nhận đúng dạng nó biết cho mọi credential cổng mặc định; credential cổng khác gửi tới worker đó bị `refused`/`invalid_job` (giải mã chặt, không gói nào đi), chỉ trong cửa sổ cập nhật vì `core` và `scan` cùng một bản phát hành; bản 4: `capture_error` trong heartbeat thụ động; bản 3: `host_errors` trên kết quả nuclei; bản 2: `Job.kind`, job và kết quả nuclei, heartbeat `nuclei`, `running` nhiều id). Vì giải mã chặt, mọi đổi dây (kể cả thêm trường hay thêm `shape`) tăng proto, **trừ** khi số đó chưa từng được phát hành (job nuclei `own_ip` được thêm vào bản 5 trước lần phát hành đầu của nó, xem gạch đầu dòng sau).
- **Lệch bản (như version skew của Kubernetes: kubelet không bao giờ mới hơn kube-apiserver, được cũ hơn):** `core` nhận proto của mình (`sensorlink.ProtoVersion`) **và bản liền trước** (`sensorlink.ProtoPrevious`, hiện `4`; `TestProtoPreviousIsOneBelow` giữ nó đúng bằng bản trừ một); sensor hay worker **mới hơn** `core` và cũ hơn hai bản → `426`. Một lần tăng proto phải giữ cho `core` phục vụ được bên bản cũ: trường mới của request là tuỳ chọn (vắng = nghĩa cũ; proto 3 không có `capture_error` = không có lỗi bắt gói); đổi thứ `core` **trả** (reply) thì trước hết phải thêm cái chưa có: truyền proto của request vào handler và trả dạng cũ cho bên `ProtoPrevious`, kèm test. Bản 4 so với bản 3 chỉ thêm `capture_error` vào request, nên reply không khác. Job nuclei `own_ip` được thêm vào bản 5 **trước lần phát hành đầu của nó** (không tăng lên 6: bản phát hành mới nhất `v0.1.0-beta.1` nói 4, và một bản 6 sẽ không còn đường cập nhật từ nó): `own_ip` trong heartbeat là tuỳ chọn (vắng = `false`); `scope` chỉ có ở job `own_ip`, và `core` chỉ giao job đó cho worker có `own_ip=true`, nên worker bản 4 (và worker bản 5 dựng trước khi có `own_ip`) nhận đúng reply nó biết (`sensoractive` `TestOwnIPNucleiNeverGoesToAWorkerWithoutOwnIP`).
- **Thứ tự cập nhật:** Apply đổi `core` **trước** rồi mới `sensor`/`scan`/`honeypot` (`modules/core/updates_run.go` `planApply`, CONTRACT core INV-35): health check của sensor/worker là heartbeat được `core` nhận (`cmd/vedette-sensor/health.go`), nên chỉ được xét sau khi `core` đã ở bản mới; trong cửa sổ đó sensor cũ (N-1) vẫn được nhận. Rollback ngược lại: `sensor`/`scan` về trước (về proto mà `core` đang chạy vẫn nhận), `core` sau cùng, nên không lúc nào sensor mới hơn `core`. Sensor tự quay về sau một lần đổi hỏng ở lại N-1, vẫn được nhận. Một bản phát hành tăng proto lên N phải đặt `min_upgrade_from` (`update-manifest.md`) không thấp hơn bản phát hành đầu tiên có proto N-1, để không hộp nào nhảy hai bản proto một lần; `release-manifest` kiểm luật này từ git (proto ở tag của bản này và của mọi bản trước) và từ chối khi `min_upgrade_from` còn để lọt một bản có proto dưới N-1.
- Giới hạn: kế hoạch cập nhật do bản **đang chạy** lập, nên chỉ cập nhật đi **từ** một bản đã có thứ tự này mới theo thứ tự này; hộp chạy bản cũ hơn (như `0.0.1-test.16`) vẫn đổi sensor trước và bị đặt lại khi proto tăng: cài lại bằng `install.sh` bản mới.
- Sensor gặp `shape` hay trường không biết: `refused` (`invalid_job`) / `400` khi giải mã, không crash.
- Nới tập đích của văn phạm mà không đổi dây (thêm 100.64/10) không tăng proto: dây giữ nguyên; trong cửa sổ cập nhật (core trước), worker cũ trả `refused`/`invalid_job` cho job có đích mới như mọi job sai văn phạm (không tiến trình nào chạy), không bao giờ quét gì ngoài văn phạm của nó. Vì `nextBatch` (`modules/sensor-active/service.go`) đi các dải đã gộp theo thứ tự địa chỉ, một lô quét dò trộn địa chỉ RFC 1918 và 100.64/10 bị từ chối **cả lô**: trong cửa sổ đó vài máy RFC 1918 chưa được quét dò tới lượt sau, mỗi job bị từ chối để lại một dòng log Error và một hàng probe thất bại; không gì ngoài văn phạm chạy.

## 11. Cân nhắc bảo mật (ánh xạ SYS)

| SYS | Áp dụng ở đây |
|---|---|
| SYS-1 | Không lệnh tổng quát; worker chỉ chạy `/usr/bin/nmap` qua `core/exec` với argv dựng từ job đã kiểm và `ValidateNmapArgs` |
| SYS-2 | Trần thân trước giải mã, `jsonstrict`, `netip`, regex ở biên của `core`; worker kiểm lại job |
| SYS-3 | Cấp, xoay, cho về hưu chứng chỉ sensor ghi `core_audit` (actor `system`); mỗi lần chạy nmap có dòng `sa_probe` **trước** khi job được giao (INV-9) |
| SYS-4 | Khoá CA qua `core/secrets`; khoá sensor chỉ ở volume của vai (0640, chỉ đọc trong container), không log, không xuất, GUI không hiện |
| SYS-5 | Module tắt → `409 module_off` và host dừng container; dữ liệu giữ nguyên |
| SYS-6 | Mọi thứ từ sensor là không tin cậy: trần, giải mã chặt, hạn mức, kẹp độ tin cậy, XML phân tích ở `core` |
| SYS-7 | `core` là bên đồng ý duy nhất; worker chỉ nhận IPv4 riêng trong văn phạm ba mẫu |
| SYS-8 | Không liên quan (AI không nằm trong giao thức) |

Rủi ro còn lại:
- `sensor` bị chiếm vẫn giả được quan sát **hợp lý** (cố hữu): bị chặn bởi hạn mức của `core`, trần 32 dòng mỗi (thiết bị, trường, nguồn) của inventory, thiết bị mới `approved=false` (S-INV-3) và mọi hành động đều cần duyệt.
- `scan`/`sensor` bị chiếm giữ `NET_RAW` trên namespace mạng của host: gửi và đọc được khung trên LAN (cố hữu với quyền đó); không có `NET_ADMIN`, không root, rootfs chỉ đọc, không DB, không khoá của vai kia.
- Chứng chỉ bị lấy cắp: chỉ mở route của vai đó, hết hạn trong ≤ 7 ngày, về hưu ở lần xoay kế tiếp.
- `core` khởi động lại giữa lúc quét: lô dở bị bỏ (lease giết nmap), lô đã xong giữ (như INV-3).

## 12. Câu hỏi của bản nháp (đã đóng)

1. ~~Không có story cho enroll sensor tách rời~~ **Đã đóng:** không xây; §3.1 cũ chuyển sang phụ lục A; trên appliance không enroll qua mạng, `core` giao khoá bằng tệp.
2. ~~Cổng listener và CA chung hay tách~~ **Đã đóng:** listener riêng `:8444`, chỉ `127.0.0.1:8444` trên appliance; một CA **riêng cho sensor** ký cả lá máy chủ 8444 và lá sensor, EKU tách vai; tách khỏi chứng chỉ 8443 và CA osquery.
3. ~~Honeypot có danh tính mTLS riêng hay đi qua sensor~~ **Đã đóng:** không cách nào; hit đi qua tệp JSON-lines một chiều, honeypot không có đường mạng tới `core`.
4. ~~Khớp IOC ở sensor hay ở `core`~~ **Đã đóng:** khớp ở `core` (module `logs`, như dòng syslog); sensor chỉ gửi (kind, src, dest) qua §6.7, không gửi IOC xuống sensor.
5. ~~Phân tích syslog ở `core` hay sensor~~ **Đã đóng cho hồ sơ này:** không nhận syslog, không `NET_BIND_SERVICE` tới khi `logs` được xây.
6. ~~Thời hạn chứng chỉ 90 ngày, trần/WAL chưa đo~~ **Đã đóng:** 7 ngày, cấp mới ở 1/3 cuối; không WAL; trần ở §9 là điểm xuất phát để đo.

## 13. Lát

Mỗi lát một PR, sau SP-0 (tài liệu này): SP-1 `core/pki` + `core/sensorlink` (máy chủ, client, chưa nối module); SP-2 seam `Prober` và gói `nmapargv` (refactor thuần, song song SP-1); SP-3 bộ điều phối + `vedette-sensor active` (cần SP-1, SP-2); SP-4 tách sensor-passive + `vedette-sensor passive` (cần SP-1); SP-5 đóng gói, profile compose `dev`, nguồn địa chỉ của hộp (cần SP-3, SP-4); SP-6 unit `sensor`/`scan` và dựng `scan` tại chỗ trong `vedette-host` (cần lát host 3-6, 3-7).

## Phụ lục A. Để sau: sensor đặt ở máy khác

Không xây. Không có story; test GUI `inventory.test.tsx` khẳng định không có endpoint sensor từ xa. Khi có story, đường đi xa giữ dây, URI vai và CA sensor của tài liệu này, và thêm: bootstrap kiểu kubelet (token bootstrap → CSR do sensor tạo, khoá ở lại sensor, gia hạn gần hết hạn), bind trên LAN, hành động thu hồi có giao diện, hàng đợi đĩa có trần (thay "không WAL" hiện nay), và danh tính theo từng sensor thay cho hai URI theo vai.

Văn bản §3.1 của bản nháp trước (2026-11-09), giữ để tham khảo; chỗ khác với quyết định hiện tại ghi trong ngoặc vuông:

> **Enroll.** Token enroll của sensor: một lần dùng, hết hạn mặc định 1 giờ, thu hồi được, **chỉ trong header `Authorization: Bearer`**, không bao giờ trong URL. Trên appliance, installer sinh token cục bộ vào volume dùng chung; người dùng không thấy. [Appliance không còn enroll.]
>
> `POST /sensor/v1/enroll` (TLS một chiều, chưa có chứng chỉ client)
>
> | Trường (request) | Kiểu | Bắt buộc | Quy tắc |
> |---|---|---|---|
> | `csr` | string (PEM PKCS#10) | có | khoá ECDSA P-256; core bỏ mọi subject/SAN do sensor đặt và tự ghi |
> | `name` | string | có | regex `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$` |
> | `version` | string | có | semver |
> | `interfaces` | string[] | không | tên card (`^[a-z0-9._-]{1,15}$`), tối đa 16 |
> | `capabilities` | string[] | không | tập con của `passive`, `span`, `active_scan`, `syslog` |
>
> Response `201`: `{ "sensor_id": "sn_…", "certificate": "<PEM>", "ca": "<PEM>", "not_after": "<RFC3339>", "poll": { "commands_wait_s": 25 } }`.
>
> Lỗi: `401 invalid_token`, `403 token_expired | token_used`, `400 invalid_csr`, `409 name_taken`.
>
> Gia hạn: `POST /sensor/v1/renew` (mTLS, body `{ "csr": "…" }`) khi còn ≤ 1/3 thời hạn; trả chứng chỉ mới cùng `sensor_id`. Chứng chỉ hết hạn → phải enroll lại bằng token mới.
>
> **Chứng chỉ (bản nháp §3).** Sensor ghim CA bằng vân tay SHA-256 truyền lúc enroll (`--ca-sha256`), không có vân tay thì từ chối enroll (không TOFU âm thầm). Chứng chỉ client `CN=sensor:<sensor_id>`, SAN URI `vedette:sensor:<sensor_id>`, 90 ngày. Thu hồi: core giữ `sensor_id → active|revoked`, kiểm mỗi request, `403 sensor_revoked`. [CA là CA sensor riêng, không phải CA osquery; thời hạn 7 ngày; trên appliance danh tính theo vai.]

#### Phạm vi IP công khai do người dùng gõ (`domain_ip` với `typed`)

`jobs[].domain.typed` `{method, ptr_name?, cover_domain?, cover_token?, cover_proof_at?}` biến một job `domain_ip` thành job của một IPv4 công khai người dùng đã gõ vào exposure: `domain` và `name` là chính IP, `token` là token gắn hộp của IP đó (`HMAC` của khoá rào trên IP, cùng hàm với token domain) và worker tự kiểm bằng chứng của IP ngay trước công cụ và mỗi `domainfence.Recheck` khi đang chạy: `method` `"file"` là tệp `/.well-known/vedette-verify.txt` phục vụ trên chính IP (http hoặc https, chuyển hướng chỉ tới chính IP và cổng web, thân tối đa 512 byte) chứa token; `"ptr"` là reverse DNS xác nhận hai chiều: PTR của IP là `ptr_name`, và `ptr_name` được chứng minh bởi domain `cover_domain` của hộp (cùng luật một job domain, với `cover_token` và `cover_proof_at`). Token lạ hoặc IP không có trong danh sách của host → `token_foreign`; không thấy bằng chứng → `target_not_owned`; tra cứu lỗi → `ownership_unchecked`; văn phạm sai → `invalid_job`. Heartbeat `typed_ip` `true` khi worker giữ khoá rào (và biết trường này); core chỉ gửi job `typed` tới worker có `typed_ip`, worker cũ hơn không nhận job nào.
