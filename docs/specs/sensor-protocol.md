# Sensor protocol: `sensor`/`scan` ↔ `core` (hồ sơ appliance)

Trạng thái: **chốt trên giấy ở lát SP-0** (2026-11-10, D-109…D-116), **mã của SP-1** (`core/pki`, `core/sensorlink`; chưa nối module) làm rõ vài chỗ, đánh dấu "SP-1" dưới đây; thay bản nháp M2-0 (2026-11-09). Văn xuôi tiếng Việt (D-28 cho tài liệu nội bộ); tên trường, mã lỗi, đường dẫn bằng tiếng Anh.
Truy vết: D-24, D-26, D-43, D-55, D-56, D-57 (2)(5)(18), D-80, D-84, D-89, D-105, D-109…D-116; `ARCHITECTURE.md` §2, §6, TB-9; `DEPLOYMENT.md` §2.2, §2.4, §6.1; story S-INV-1, S-INV-3, S-SCAN-4.

## 1. Mục đích và phạm vi

Hồ sơ **appliance**: hai container trên cùng một hộp nói với `core` qua `127.0.0.1:8444`:

- `sensor`: bắt gói thụ động (nửa `capture` của module `sensor-passive`), mạng host, `NET_RAW`;
- `scan`: worker nmap của module `sensor-active`, mạng host, `NET_RAW`.

Cả hai chạy cùng binary `vedette-sensor` (lệnh con `passive`, `active`, `healthcheck`; D-114). Chiều khởi tạo **chỉ một**: sensor gọi ra, `core` không bao giờ gọi vào sensor; lệnh từ `core` tới bằng long-poll (D-109).

Ngoài phạm vi hồ sơ này:
- sensor đặt ở máy khác, enroll, gia hạn qua mạng, thu hồi bằng tay (D-115; thiết kế cũ ở phụ lục A);
- syslog và metadata SPAN (`logs` chưa xây), honeypot (đi qua tệp, D-89), osquery (`osquery-intake.md`). (Job nuclei của module `scan` là loại job thứ hai từ bản 2; đọc SNMP là loại thứ ba từ bản 5, D-512, xem khối "D-512" ở §6.5.)

## 2. Actors và vai

| Actor | Vai | Ghi chú |
|---|---|---|
| `core` | máy chủ giao thức; CA của sensor (D-110); giữ DB, chính sách, sự đồng ý quét | container `core`, listener thứ hai `:8444`, publish `127.0.0.1:8444` |
| `sensor` | vai **`passive`**: nhận `config`, gửi quan sát và heartbeat | `User=<sensor_uid>:<sensor_gid>`, không `UserNS`, chỉ `NET_RAW` (D-114) |
| `scan` | vai **`active`**: nhận job nmap, gửi kết quả và heartbeat | như `sensor`; image dựng trên hộp (D-113 (7)) |
| `vedette-host` | dựng unit hằng gắn volume khoá theo vai | không bao giờ thấy khoá (D-87, D-110 (6)) |

Mô hình tin cậy: sensor là **máy bị tấn công được** (nằm trên LAN, đọc gói và phản hồi do kẻ tấn công điều khiển). `core` tin **danh tính vai** sau mTLS, không tin **nội dung** (SYS-6): mọi thứ sensor gửi bị kiểm kích thước, kiểu, hạn mức và kẹp độ tin cậy ở `core`.

## 3. Transport (D-109)

- HTTPS, JSON (`Content-Type: application/json`), không nén (`Content-Encoding` bất kỳ → `400 invalid_request`). TLS **1.3** tối thiểu; HTTP/2 khi ALPN đề nghị, không bắt buộc.
- Listener riêng của `core`, bật bằng `-sensor-listen :8444` (trong container) cùng `-sensor-creds <thư mục>` (D-141; rỗng = không nghe), tách khỏi listener UI 8443; `core` mở PKI, ghi hai bó khoá, **rồi mới** nghe, và việc `sensor-cert-renew` hằng ngày gọi `Authority.Renew`; trên appliance chỉ publish `127.0.0.1:8444` (`DEPLOYMENT.md` §6.1). `ClientAuth = RequireAndVerifyClientCert`, pool chỉ chứa CA sensor.
- Tiền tố `/sensor/v1/`. Mọi request mang `X-Vedette-Proto: 5` (bản 5: loại job `snmp`, `snmp` trong heartbeat `active` và trong kết quả, `running` tới 3 id, D-512; bản 4: `capture_error` trong heartbeat thụ động, D-399; bản 3: `host_errors` của kết quả nuclei, D-165; bản 2: loại job `nuclei`, D-125/D-133). `core` nhận bản của mình và **bản liền trước** (`4`), không bao giờ bản mới hơn (§10, D-459). Bản 5 thêm một loại job vào **phản hồi** `jobs`, nhưng `core` chỉ gửi job `snmp` cho worker có heartbeat `"snmp": true` (trường của bản 5), nên worker bản 4 nhận phản hồi đúng dạng bản 4.
- `ReadHeaderTimeout` 5 s, `WriteTimeout` 35 s (long-poll giữ tối đa 30 s).
- Thân: `http.MaxBytesReader` theo trần của route (§9) **trước** khi giải mã; giải mã bằng `internal/jsonstrict` (trường lạ, khoá trùng, khoá trùng sau gập chữ, độ sâu > 32 → `400 invalid_request`). Query lạ → `400 invalid_request`.
- SP-1 (làm rõ): thân POST phải có `Content-Type: application/json` (thiếu hoặc khác → `400 invalid_request`); thân đọc tối đa **10 s** (đồng hồ ổ cắm, không phải seam; `ReadTimeout` toàn yêu cầu 15 s, D-176; 10 s cho 11 MiB tức ~9 Mbit/s, chỉ đúng cho sensor cục bộ, tính lại khi dựng sensor từ xa) và kết nối bị đóng khi thân dừng giữa chừng hoặc vượt trần (net/http không có hạn đọc thân nào mà không làm hỏng long-poll); `IdleTimeout` 2 phút; `MaxHeaderBytes` 16 KiB. `If-None-Match` phải có dạng `"<1…64 ký tự [A-Za-z0-9._:-]>"`, không thì `400`. `wait` là một số nguyên 0…30 (một giá trị, không lặp); `running` là 32 hex hoặc rỗng.
- Listener nhận tối đa **64 kết nối** cùng lúc (`PendingListener`, viết bằng thư viện chuẩn): **16 đang bắt tay** (chưa xác thực; đầy thì kết nối mới thay chỗ kết nối chờ lâu nhất nếu nó đã chờ ≥ 250 ms, không thì kết nối mới bị đóng ngay; mỗi kết nối chờ bị đóng sau 3 s bắt tay, D-326), rồi theo vai tại bắt tay TLS: `passive` ≤ 32, `active` ≤ 16 (D-176); `ErrorLog` của `http.Server` đi qua slog như server 8443 (lỗi handshake bị từ chối vào log, không ra stderr). Client **không theo redirect**: một 3xx là lỗi của request, `Location` không được gọi (không đưa chứng chỉ client cho máy khác).
- Sensor đọc phản hồi của `core` cũng có trần (config ≤ 64 KiB, jobs ≤ 64 KiB, phản hồi khác ≤ 16 KiB) và giải mã chặt như `core`.

## 4. Chứng chỉ và danh tính (D-110)

| Mục | Quy tắc |
|---|---|
| CA | ECDSA P-256, 10 năm, do `core` tạo lần đầu; khoá lưu qua `core/secrets` (AES-256-GCM, `master.key`). **Chỉ** ký lá cho listener 8444 và cho sensor; tách khỏi chứng chỉ 8443 và CA osquery tương lai (`osquery-intake.md` §4). Khôi phục không có `master.key` → CA mới, lá mới |
| Lá máy chủ | EKU **chỉ** `serverAuth`; SAN `IP:127.0.0.1` và `DNS:core` (profile compose); 7 ngày |
| Lá sensor | EKU **chỉ** `clientAuth`; **đúng một** URI SAN: `vedette:sensor:passive` hoặc `vedette:sensor:active`; không dùng CN để quyết định gì; 7 ngày; serial ghi ở `core_sensor_cert(role, serial, not_after, retired_at)` |
| Xoay vòng | `core` kiểm lúc khởi động và mỗi ngày; lá còn ≤ 1/3 thời hạn thì cấp mới; serial cũ hơn "ngay trước" được đặt `retired_at` |
| Giao khoá | lúc khởi động, **trước khi nghe**, và mỗi lần xoay: `core` sinh khoá, ghi **một** bó PEM (khoá, lá, CA) vào `<creds>/<role>/sensor.pem` qua `os.OpenRoot`, tệp tạm `O_EXCL\|O_NOFOLLOW`, fsync, `Rename`; mode `0640`, chủ `core_uid:sensor_gid`. `core` **không bao giờ đọc lại** tệp (mẫu D-89) |
| Phía sensor | gắn volume khoá của đúng vai **chỉ đọc** (D-114 (4)); đọc lại bó trong `GetClientCertificate` khi mtime đổi; sau khi đổi, đóng kết nối rảnh. Bó hỏng hoặc đang ghi dở → giữ bó cũ trong bộ nhớ, thử lại sau 5 s |
| Phía sensor kiểm máy chủ | chuỗi tới CA trong bó, EKU `serverAuth`, tên `127.0.0.1` (hoặc `core` ở compose) |

**SP-1 (làm rõ).** `core` luôn cấp lá mới cho máy chủ và hai vai ở lúc khởi động (`Authority.Start`), vì nó không bao giờ đọc lại bó nên không có khoá của lá lần trước; serial trước đó vẫn sống (là "ngay trước"). Việc hằng ngày (`Authority.Renew`) chỉ thay lá còn ≤ 1/3 thời hạn. Bó cấp rồi mà ghi không được (volume lỗi, thư mục vai bị đặt symlink) được giữ trong bộ nhớ và ghi lại ở lần `Renew` kế, không cấp lại. `NotBefore` lùi 1 phút so với giờ `core`. Handshake và mỗi request kiểm EKU **đúng** `[clientAuth]`, đúng một URI SAN, lá không phải CA; mỗi request còn kiểm `NotBefore ≤ giờ ≤ NotAfter` của lá (kết nối keep-alive sống lâu hơn chứng chỉ) → `403 cert_retired`.

**Kiểm của `core`** (thứ tự):
1. Handshake: chuỗi tới CA sensor (hạn, chữ ký), EKU `clientAuth`, đúng một URI SAN thuộc hai vai, serial là serial **hiện hành hoặc ngay trước** của vai đó. Sai bất kỳ → handshake hỏng (không có phản hồi HTTP). `VerifyConnection` chạy cả trên kết nối nối lại (TLS 1.3 resumption).
2. **Mỗi request**: kiểm lại serial (một kết nối keep-alive sống lâu hơn lần về hưu của serial) → `403 cert_retired`.

**CA không dùng được thì thay (M2 của rà soát SP-1).** Hàng CA không giải mã được với `master.key` hiện tại (mất khoá, hoặc khôi phục bản sao lưu không kèm khoá lên khoá của hộp: `host-api.md` §16), hỏng, hết hạn hoặc chưa tới `NotBefore` → `pki.Open` tạo CA mới **trong cùng giao dịch ghi** đã phát hiện ra nó (ghi đè hàng `core_secret`), thu hồi mọi serial còn sống của CA cũ, ghi audit `sensor-ca.replace` (lý do: `cannot_decrypt`, `damaged`, `expired`, `not_yet_valid`) và log cảnh báo `sensor_ca_replaced`; `Start` cấp lại và ghi lại mọi bó. Lỗi của DB không phải lý do để bỏ CA.

**Audit (M3).** Mọi thay đổi PKI là một hàng `core_audit` (người làm `system`) trong cùng giao dịch: `sensor-ca.create`, `sensor-ca.replace`, `sensor-cert.issue` (vai, serial, `not_after`), `sensor-cert.retire` (vai, serial). Tên nhóm dùng gạch nối vì `audit` không nhận dấu gạch dưới ở nhóm. Không bao giờ có khoá hay PEM trong audit hay log.

**Dọn và ghi bó (L3, L6).** `Start` xoá các tệp tạm `.sensor.pem.*` (tệp thường; thư mục, symlink và tên khác để nguyên) còn lại sau một lần sập giữa lúc ghi. Thư mục gốc và thư mục vai được kiểm không phải symlink **và**, sau khi mở, phải đúng là thư mục đã kiểm (`os.SameFile`): bị tráo ở giữa thì từ chối (`ErrCredsPath`). `ParseBundle` kiểm lá chuỗi tới chính CA trong bó (CA là gốc duy nhất, EKU `clientAuth`).

**Long-poll mở trước một lần xoay vòng.** Request đang giữ khi serial bị về hưu vẫn chạy tới hết (serial được kiểm lúc nó bắt đầu); request kế tiếp trên kết nối đó bị từ chối `403 cert_retired` (máy chủ đóng kết nối), client đọc lại bó và nối lại với chứng chỉ mới. Chừng đó là đủ: không có thao tác nào bị mất, vì sensor gửi lại cùng lô và long-poll tự lặp.

Thu hồi chủ động không có giao diện (D-115); thu hồi = xoay vòng (serial cũ về hưu) cộng hạn 7 ngày (thu hồi thụ động).

## 5. Quy ước chung

- Thời điểm: RFC 3339 UTC. Id job: 32 hex chữ thường (128 bit ngẫu nhiên). `epoch`: 32 hex chữ thường.
- Lỗi: `{ "error": { "code": "snake_case", "message": "English text" } }`; `code` là hợp đồng, `message` chỉ để đọc. 429 và 503 có tiêu đề `Retry-After` (giây).
- `version`: SemVer 2.0, ≤ 64 byte.
- Tên card: `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`; MAC: `^([0-9a-f]{2}:){5}[0-9a-f]{2}$`; IP qua `netip` (IPv4/IPv6 unicast); địa chỉ của card dạng tiền tố (`192.168.10.5/24`) qua `netip.ParsePrefix`.
- Chuỗi văn bản tự do: UTF-8 hợp lệ, không ký tự điều khiển C0/C1, bidi, phân cách dòng/đoạn, Unicode Cf (như sensor-passive INV-3); sai → mục bị từ chối, không cắt ở `core`.

## 6. Route theo vai (D-111)

| Vai | Route | Thân request (trần) | Trả |
|---|---|---|---|
| `passive` | `GET /sensor/v1/config?wait=<0..30>` | — | `200` cấu hình + `ETag`, hoặc `304` |
| `passive` | `POST /sensor/v1/observations` | ≤ 1 MiB | `200 {ack_seq, rejected[]}` |
| `passive`, `active` | `POST /sensor/v1/heartbeat` | ≤ 64 KiB | `200 {instance}` |
| `active` | `GET /sensor/v1/jobs?wait=<0..30>&running=<id[,id]>` (`running` rỗng hoặc bỏ trống khi rảnh; ≤ 2 id, bản 2) | — | `200 {instance, jobs[], cancel[]}` |
| `active` | `POST /sensor/v1/jobs/{id}/result` | ≤ 11 MiB | `204` |

Mọi cặp (method, đường dẫn) khác, kể cả route của vai kia → `403 forbidden_route`, kiểm **trước khi đọc thân**. Mỗi vai tối đa **một** long-poll đang mở; cái thứ hai → `409 poll_in_progress`. Module của vai tắt (`sensor-passive` cho `passive`, `sensor-active` cho `active`) → mọi route của vai `409 module_off`.

### 6.1 `GET /sensor/v1/config` (passive)

Long-poll có điều kiện: sensor gửi `If-None-Match: "<etag>"` của bản đang dùng (lần đầu không có). `core` trả ngay `200` khi ETag khác; còn lại giữ tới `wait` giây (mặc định 25) rồi trả `304` không thân. `SetInterface` (đổi card/SPAN ở Box network) và đổi bộ lọc đánh thức long-poll đang mở (thay kênh `reload` trong tiến trình; D-114 (1)).

```json
{ "interface": "enp2s0", "span": true,
  "extract": { "dns": true, "sni": true, "http": false, "flows": true },
  "filters": [ { "type": "cidr", "value": "10.0.5.0/24" }, { "type": "port", "value": "443" } ] }
```

| Trường | Quy tắc |
|---|---|
| `interface` | tên card hoặc `""` = **không bắt gói** (module chưa cấu hình, hoặc fail-closed) |
| `span` | card là cổng SPAN/TAP (không IP; D-56) |
| `extract` | bốn công tắc trích metadata SPAN (D-43). Metadata **không** đi trên dây ở hồ sơ này (D-112 (7)): sensor trích theo công tắc cho bộ đếm và hạn mức, rồi bỏ |
| `filters[]` | luật loại trừ `{type: cidr\|host\|port, value}` (sensor-passive INV-7) |

Fail-closed (D-80 (3)): `core` không đọc được bộ lọc → `interface: ""`. Sensor nhận `interface` khác bản đang chạy → đóng card cũ, mở card mới; `""` → dừng bắt gói ngay, không xả lô cuối.

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

**Epoch và seq** (D-112 (2)). `core` giữ `sp_seq(sensor_id, epoch, last_seq)` với `sensor_id = sn-local` (sensor của chính hộp) và chỉ **2 epoch mới nhất** (epoch thứ ba xoá cái cũ nhất). Lô có `seq ≤ last_seq` của epoch đó → `200`, `ack_seq = seq`, `rejected: []`, không ghi lại (POST-3). Không có `seq_gap`: seq chỉ chống phát lại, khoảng trống là bình thường (lô bị bỏ).

**Xử lý** (một lô): (1) kiểm từng mục (§5, bảng trên) → mục sai vào `rejected[]`; (2) hạn mức chống ngập ở `core` (D-111 (2)): MAC chưa từng thấy ≤ 60 mỗi phút và ≤ 200 mỗi giờ, giá trị mới ≤ 4 mỗi (MAC, trường) mỗi giờ, map trong bộ nhớ theo MAC (lặp lại giá trị đã cho qua không tính là mới); vượt → `budget_exhausted`; (3) `SubmitBatch` với các mục còn lại; `observe.ErrRejected{Index}` của inventory → mục đó vào `rejected[]` với `refused`, gửi lại phần còn lại trong cùng request; (4) lưu `seq`.

Trả `200 { "ack_seq": 41, "rejected": [ { "index": 3, "code": "budget_exhausted" } ] }`: **thành công một phần, không bao giờ thử lại** (D-112 (3)). Mã của mục (tập đóng):

| `code` | Nghĩa |
|---|---|
| `invalid_item` | sai kiểu/regex/trần, `field` lạ, thiếu cả `mac` lẫn `ip`, văn bản bẩn |
| `out_of_window` | `seen_at` ngoài cửa sổ thời gian |
| `budget_exhausted` | vượt hạn mức chống ngập của `core` |
| `refused` | inventory từ chối ở biên (`observe.ErrRejected`) |

Kho bận (SQLite busy, `Write` hết hạn, hay kết nối ghi bị giữ quá 5 s: `store.ErrBusy`, D-246) → `503 store_busy` cho cả lô, không mục nào được ghi hay tính hạn mức.

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
| `drops` (passive) | ≤ 64 khoá thuộc **tập đóng** của bộ đếm bỏ trong `capture` (`malformed_*`, `excluded`, `value_empty`, `fragment_skipped`, `new_macs_unconfirmed`, `new_macs_dropped`, `values_dropped`, `observation_failed`…; 34 khoá, danh sách ở khối "SP-4" của §6 và `sensorlink.DropKeys`); giá trị ≥ 0 |
| `devices_seen` (passive) | ≥ 0 |
| `capture_error` (passive, bản 4, D-399) | vì sao bắt gói trên card được chọn không chạy lúc này: tập đóng `sensorlink.CaptureErrors` = `no_permission` (mở socket bị EPERM/EACCES: không có `CAP_NET_RAW`, như container rootless), `no_interface` (card không có trên máy), `filters_invalid` (bộ lọc không đọc được), `capture_failed` (mọi lỗi khác); vắng hoặc `""` khi đang bắt gói hay không có card nào được chọn. Sensor đặt nó khi mở card hay một phiên hỏng, xoá khi card mở được hay khi thôi bắt gói. Không bao giờ là chữ của lỗi (chữ đó ở log của sensor). Dạng: chữ thường `[a-z][a-z0-9_]{0,47}`, khác dạng → `400`; đúng dạng mà `core` không biết → `core` hiện `capture_failed` và log một lần (giữ tối đa 64 tên lạ) |
| `nmap` (active) | `present` = `/usr/bin/nmap` có và chạy được `--version`; `version` ≤ 32 byte |
| `nuclei` (active, bản 2) | `present` = `/usr/local/bin/nuclei` có và chạy được `-version -duc` (nuclei in phiên bản ra stderr); `version` ≤ 32 byte; `pack` = `version` (`AAAA.M.N`) và `sha256` (64 hex) của chỉ mục gói mẫu nằm sẵn trong image, **cả hai rỗng** khi chưa có chỉ mục dùng được (không đọc được hoặc không qua `pack.Parse`); một rỗng một không → `400`; `own_ip` (bản 5, D-520) = `true` khi worker chạy job nuclei phạm vi `own_ip` (có rào IP của chính hộp), vắng = `false` (worker cũ hơn): `core` không bao giờ giao job `own_ip` cho worker chưa nói `own_ip` |

Trả `200 { "instance": "<32 hex>" }`: nonce sinh mỗi lần tiến trình `core` khởi động (lease của §6.4).

`core` dùng heartbeat cho (D-112 (5)):
- `Sensor.status`: `online` khi có heartbeat trong **90 s**; `last_seen`, `version`, `devices_seen`, `interfaces` (tên card) của `GET /inventory/sensors` lấy từ heartbeat thụ động mới nhất; `capture_error` cũng vậy nhưng **chỉ khi `online`** (heartbeat cũ không nói gì về lúc này; giữ trong bộ nhớ, không vào DB; GUI: "Reporting, not capturing" kèm lý do, D-399);
- `SpanStats()` / `span_status`: `off` (cấu hình `span=false`), `no_link` (card SPAN `link=false`), `no_traffic` (`last_packet_at` cũ hơn 30 s, `null`, hoặc sensor `offline`), `own_only` (`other_macs = 0`), `ok`;
- `SetInterface`: `interface` phải là một card của host (D-118); chỉ khi core chạy không có host thì là một card trong heartbeat thụ động mới nhất (D-263); `400 bad_interface` (sensor-passive INV-9); không có host và chưa có heartbeat → `bad_interface`;
- địa chỉ của hộp (`ProtectedIPs` của sensor-active, kiểm IP bẫy của honeypot, `conn`) **tới khi** lát host 3-3 có `GET /v1/state/net` (D-114 (5));
- sức khoẻ `sensor-active`: `unavailable` khi 90 s không có heartbeat `active` hoặc `nmap.present=false` (INV-6);
- sức khoẻ của máy quét nuclei (`scan`, D-125 (5)): `scanner_unavailable` (503 ở API) khi 90 s không có heartbeat `active`, `nuclei.present=false`, `nuclei.pack.sha256` rỗng, hoặc một job nuclei chạy quá hạn mà worker chưa dừng được; nmap và nuclei độc lập: thiếu cái này không làm cái kia `unavailable`.

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
| `jobs[].kind` | `nmap` \| `nuclei` (bản 2) \| `snmp` (bản 5, trường của nó ở khối "D-512" §6.5). Thiếu `kind` = `nmap`. Loại lạ: giải mã chỉ lấy `id` và `kind`, worker trả `refused` (`invalid_job`) mà không làm hỏng cả poll |
| `jobs[].shape` | (nmap) `sweep` \| `normal` \| `gentle` (ba mẫu của D-84 (7)) \| `versions` (`-sV` không `-O`, D-501: lượt chọn tay thiết bị chưa rõ loại; worker cũ không biết mẫu này từ chối job `invalid_job`, nhận dạng báo `unavailable`) \| `gentle_titles` (D-511: lần quét nhẹ của thiết bị chưa rõ loại không mong manh, cộng `--script http-title,ssl-cert --script-timeout 20s`; như `versions`, worker cũ từ chối `invalid_job` trong lúc cập nhật, lần quét nhẹ đó chạy lại ở cửa sổ sau; không tăng proto) \| `external` (D-514: `-sV` trên đúng IP công khai của chính hộp cho exposure, `--privileged -sS -sV -Pn -n --max-rate 100 --max-retries 2 --host-timeout 3m -p <98 cổng của commonports>`, không `-O`, không `--script`; worker **tự kiểm** ngay trước nmap rằng hộp ra Internet qua địa chỉ đó (ba dịch vụ công khai, 2/3, tối đa 5 vòng, nhớ 5 phút; `core/egressip`; chỉ qua IPv4: `tcp4`), dịch vụ nêu địa chỉ khác → `refused`/`not_own_ip`, không vòng nào có câu trả lời (không tới được, TLS, không đồng thuận) → `refused`/`egress_unverified`, nmap không chạy; worker cũ không biết mẫu này → `invalid_job`, exposure báo "may be older"; không tăng proto). `normal` và `versions` mang đúng `--script rdp-ntlm-info,http-ntlm-info,http-title,ssl-cert` (D-504, D-511, `nmapargv.Scripts`: hai script NTLM type 1, không thông tin đăng nhập; tiêu đề trang và chủ thể chứng chỉ TLS); tên mẫu không đổi nên không tăng proto: worker của bản cũ dựng hai mẫu đó không script (chỉ trong lúc cập nhật; `sa_probe.flags` khi đó ghi thừa script, không bao giờ thiếu) |
| `jobs[].rate` | (nmap) 1 … 1000; `gentle` luôn `1`; `external` luôn `100` (D-514) |
| `jobs[].targets` | (nmap) 1 … 64 IPv4 riêng (RFC 1918 hoặc dải chung RFC 6598 100.64/10, `core/localnet.Addr`, D-461), chính tắc, không trùng (văn phạm `ValidateNmapArgs`); `external`: **đúng một** IPv4 công khai chính tắc (`egressip.IsPublicIPv4`: không riêng, CGNAT, loopback, link-local, tài liệu, multicast, dành riêng), và chỉ mẫu này nhận địa chỉ công khai |
| `jobs[].timeout_s` | nmap: 1 … 7200 = min(hết cửa sổ, 2 giờ); nuclei: 1 … 3600 = min(hạn của ngữ cảnh probe, 1 giờ); do `core` tính lúc giao |
| `jobs[].pack` (nuclei) | `{version, sha256}` của gói mẫu mà `core` đã chọn mẫu theo; worker từ chối khi chỉ mục trong image khác (`pack_mismatch`). `sha256` là **nhãn** do bộ dựng gói ghi trong chỉ mục (`pack.Index.SHA256`), không phải hàm băm worker tự tính; thứ được băm lại là từng tệp mẫu được chọn, so với `sha256` của mục tương ứng trong chỉ mục. `core` cũng so nhãn này với heartbeat **trước khi giao** (`ErrPackMismatch`, không thử lại); `pack_invalid` (băm lệch, link trong gói) là tín hiệu toàn vẹn: `ErrPackInvalid`, log ERROR, không thử lại |
| `jobs[].templates` (nuclei) | 1 … 32 **id** mẫu (`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`), không trùng; không đường dẫn, không URL, không YAML (D-111 (3)). Worker đổi id thành đường dẫn bằng chỉ mục đã kiểm (D-136 (6)); id không có trong chỉ mục → `invalid_job` |
| `jobs[].targets` (nuclei) | (phạm vi `lan`; `own_ip`: xem `scope`) 1 … 16 `{host, port, scheme}`: `host` là IPv4 riêng RFC 1918 hoặc RFC 6598 (100.64/10, D-461; trừ 100.100.100.200, metadata Alibaba Cloud) dạng chuẩn, không `.0`/`.255` (**không tên miền**, không IP công khai, phần 100/8 ngoài 100.64/10, loopback, link-local, benchmark, 240/4; D-136 (4)), `port` 1..65535, `scheme` `"http"` \| `"https"` \| `""` (mẫu mạng, `host:port`); không trùng |
| `jobs[].rate` / `max_host_errors` (nuclei) | `rate` 1 … 20 (`-rl`), `max_host_errors` 2 … 20 (`-mhe`) |
| `jobs[].scope` (nuclei, bản 5, D-520) | vắng hoặc `"lan"` = các quy tắc trên (`scan`); `"own_ip"` = kiểm lỗ hổng an toàn của `exposure` trên IP công khai của chính hộp (D-561): **đúng một** đích, `host` là IPv4 công khai chính tắc (`localnet.Public`, cùng luật `egressip.IsPublicIPv4`), `port` là cổng của job, `rate` luôn `5`, 1 … 32 mẫu của gói đã kiểm (mỗi mẫu là mẫu của một CVE mà `core` đã khớp, không chọn theo tag), **mỗi mẫu phải được đánh dấu `own_ip: true` trong chỉ mục của image** (quyết lúc dựng gói từ chính tệp mẫu: chỉ yêu cầu chỉ đọc, GET hoặc HEAD không thân, không thông tin đăng nhập, không lệnh, D-520 (3)) và tệp mẫu phải qua `pack.OwnIPText` do worker tự đọc; `-etags` của argv thêm `default-login,brute-force,sqli,time-based-sqli,xss,injection,code-injection,argument-injection,ssti,file-upload,rce,authenticated,login` (chưa kiểm ở lab với `-t`, không dựa vào); giá trị khác → `invalid_job`. `core` **bỏ trống** `scope` ở job LAN, nên worker cũ hơn nhận đúng dạng nó biết; job `own_ip` chỉ giao cho worker có heartbeat `nuclei.own_ip=true`, và không xếp hàng sau job nuclei khác (khe bận → `ErrNucleiBusy`, không gửi gì). Worker cũ hơn nếu nhận được job có `scope` thì giải mã chặt báo lỗi: không chạy gì |
| `cancel` | ≤ 8 id job phải dừng |

Trên dây **không** có argv, cờ, đường dẫn, URL hay phạm vi (D-111 (3)): worker dựng argv bằng chính `buildNmapArgs` + `ValidateNmapArgs` (gói lá `modules/sensor-active/nmapargv`, D-113 (3)); với job nuclei bằng `nucleiargv.Build` + `Validate` (gói lá `modules/scan/nucleiargv`, D-125 (2), D-136).

**Bộ điều phối** (`core`, trong bộ nhớ; D-113 (4)):
- `sensoractive` gọi `Prober` **sau khi** ghi dòng `sa_probe` (INV-9 giữ nguyên thứ tự); không có heartbeat `active` trong 90 s → `ErrUnavailable` ngay, không tạo job.
- Hai **khe** riêng, nmap và nuclei (bản 2, D-125 (3)): mỗi khe một job đang chạy = một tiến trình trên hộp; một job nmap và một job nuclei chạy cùng lúc, nên "Scan now" và quét lại KEV không chờ sau một lượt quét dò 2 giờ. Job mới của một khe chỉ được giao khi khe đó rảnh và poll không còn nêu tên job vừa xong của khe đó hay một id mà `core` không biết (id lạ giữ cả hai khe tới khi worker hết báo nó); job thứ hai của cùng một loại chờ (vẫn chịu hạn của nó). Mọi quy tắc dưới đây (lease, chờ lấy, 30 s, hủy) áp cho từng khe.
- Job chưa được lấy trong 60 s → probe `failed` (`worker_unavailable`). Job đã giao mà poll sau đó báo `running` khác id đó và chưa có kết quả → probe `failed` (`worker_lost`: sensor khởi động lại giữa chừng hoặc phản hồi bị mất).
- Ngữ cảnh probe kết thúc (hết cửa sổ, `SettingsChanged`, hạ `rate`, thiết bị đổi, tắt module; INV-3) → job chưa giao thì bỏ; đã giao thì `cancel:[id]` ở long-poll kế tiếp (long-poll đang mở được đánh thức). `core` coi probe là `stopped` sau tối đa 30 s dù worker chưa xác nhận; job mới vẫn chờ `running` rỗng.

**Worker** (`vedette-sensor active`):
- Kiểm lại job (văn phạm bảng trên, `ValidateNmapArgs` trên argv đã dựng, hạn ≤ 2 giờ); sai → kết quả `refused` (`invalid_job`), không chạy gì. Nhận job khi khe cùng loại đang chạy job khác → `refused` (`busy`); khe kia không bị đụng.
- Chạy `/usr/bin/nmap` qua `core/exec` (allowlist binary + argv, không shell), nhóm tiến trình riêng, hạn `timeout_s`, stdout trần 8 MiB (`Truncated`).
- Job `nuclei` (bản 2): kiểm lại bằng `nucleiargv` (số lượng, mục tiêu IPv4 riêng, `rate`, `max_host_errors`), `timeout_s` 1..3600, **gói** (`pack.version` và `pack.sha256` phải bằng chỉ mục trong image, không thì `refused`/`pack_mismatch`), từng id mẫu phải có trong chỉ mục (không thì `invalid_job`); rồi đi qua **cả cây gói** bằng `Lstat`: chỉ thư mục và tệp thường, một symlink, fifo, socket hay thiết bị ở bất cứ đâu → `refused`/`pack_invalid`; băm SHA-256 từng tệp mẫu được chọn (mở bằng `os.Root`) và so với chỉ mục (lệch → `pack_invalid`). Chạy `/usr/local/bin/nuclei` qua `core/exec` với argv của `nucleiargv.Build` (mỗi mẫu một `-t <TemplatesDir>/<đường dẫn>`, không bao giờ cả thư mục), **môi trường sạch** (chỉ `PATH`, `LANG=C` và `HOME` do `core/exec` đặt; không `*_PROXY`, `ENABLE_CLOUD_UPLOAD`, `PDCP_API_KEY`, không gì của tiến trình cha), `HOME` là thư mục rỗng mới trên tmpfs (xoá và tạo lại trước mỗi lần chạy; không có `~/.config/nuclei`), nhóm tiến trình riêng, hạn `timeout_s`, stdout trần 4 MiB (`Truncated`); **stderr không bao giờ gửi** (nó chứa nhật ký lỗi `-elog`; worker chỉ đếm timeout theo đích vào `host_errors`, D-165). Thiếu binary → `failed`/`nuclei_missing`. Kết quả là JSONL thô trong `jsonl_b64`; `core` phân tích đóng khi lỗi (`nucleiout`).
- Job `nuclei` mọi phạm vi (D-528): tệp mẫu (đã băm) không qua `pack.NoChangeText` (method ghi, `@Host:`, ghi đè method, `INTO OUTFILE`, `xp_cmdshell`, `file_put_contents`, tải tệp multipart, `gopher://`/`dict://`) → `invalid_job`; nuclei không chạy (không tăng proto: chỉ worker từ chối thêm).
- Job `nuclei` phạm vi `own_ip` (bản 5, D-520): văn phạm `own_ip` của `nucleiargv` (một IPv4 công khai, `rate` 5, cờ cố định như LAN trừ `-etags`), mẫu không có `own_ip: true` trong chỉ mục của image hoặc tệp mẫu (đã băm) không qua `pack.OwnIPText` → `invalid_job`; rồi, **ngay trước nuclei**, worker tự kiểm rằng hộp ra Internet qua địa chỉ đó (cùng rào của mẫu nmap `external`: ba dịch vụ công khai, 2/3, tối đa 5 vòng, nhớ 5 phút, `core/egressip`): địa chỉ khác → `refused`/`not_own_ip`, không vòng nào trả lời → `refused`/`egress_unverified`; nuclei không chạy.
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
| `reason` | `""` hoặc một trong `invalid_job`, `busy`, `nmap_missing`, `exec_failed`, `deadline`, `cancelled`; bản 2 thêm `nuclei_missing`, `pack_mismatch`, `pack_invalid`; D-514 thêm `not_own_ip` và `egress_unverified` (chỉ cho job `external`, chỉ `core` cùng bản phát hành gửi job đó: không tăng proto); D-520 dùng hai mã đó cho job nuclei `own_ip` |
| `exit_code` | −1 … 255 (−1 = không chạy hoặc bị giết) |
| `truncated` | stdout chạm trần (nmap 8 MiB, nuclei 4 MiB) |
| `xml_b64` | base64 chuẩn của stdout nmap; sau giải mã ≤ 8 MiB; rỗng khi không phải `done` (khác → `400`); luôn có mặt, rỗng ở kết quả nuclei |
| `jsonl_b64` (bản 2) | base64 chuẩn của stdout nuclei (`-jsonl`); sau giải mã ≤ 4 MiB; chỉ khi `done`, và **không cùng `xml_b64`** (cả hai → `400`); vượt 4 MiB → `413` |
| `host_errors` (bản 3, nuclei) | tuỳ chọn, bỏ trống khi không đích nào có timeout: mảng ≤ 16 mục `{target "host:port", errors 1..1048576, unreachable bool}`, mỗi đích một mục, chỉ khi `done` (khác → `400`). Worker đếm từ nhật ký lỗi của nuclei (`-elog /dev/stderr`) các dòng `kind` = `network-temporary-error` của từng đích; `unreachable` = `errors` ≥ `max_host_errors` của job. `core` từ chối (`ErrResultRejected`) đích ngoài job, hay `unreachable` không đúng với `errors`; kết quả nmap mang `host_errors` cũng bị từ chối (D-165) |

`{id}` phải là job **đang chạy** do chính `core` này giao cho vai `active`; còn lại (id lạ, job đã xong, gửi lại lần hai) → `404 unknown_job`. Thân > 11 MiB, XML giải mã > 8 MiB hoặc JSONL giải mã > 4 MiB → `413 payload_too_large` và probe `failed`. Trả `204`.

`core` **không tin** `status` của worker: `done` mà `exit_code ≠ 0` hoặc `truncated` → probe `failed`, cả lô bị bỏ (INV-7); XML phân tích bằng `parseNmapXML` (đã fuzz) và `onlyTargets` trong `core`, nên quan sát và phần mềm từ nmap không bao giờ đi trên dây (D-113 (5)). `refused` → probe `failed` và log ERROR (worker và `core` bất đồng về văn phạm là lỗi hoặc bị chiếm); `nmap_missing` → sức khoẻ `unavailable` (INV-6).

**SP-3b (bản 2, nuclei; mã `modules/sensor-active/{dispatch.go,nuclei.go,worker/}`, `core/sensorlink`, D-125, D-133).**
- `Job` mang `kind`; hai khe trong `Dispatcher` (nmap, nuclei) và hai `cur` trong worker; `running` của poll là danh sách ≤ 2 id (`Backend.Jobs(ctx, wait, running []string)`, `Client.Jobs(ctx, running []string, wait)`). Một poll mà worker nêu id của một khe, id vừa xong của một khe, hay id lạ được xử lý như SP-3 nhưng theo từng khe; id lạ nhận `cancel` ngay lần đầu và giữ cả hai khe.
- Giao hạn: nuclei `timeout_s` = min(hạn ctx còn lại, 3600); trần phía `core` `timeout_s` + 30 s như nmap, `Health` của nuclei nói "quá hạn" riêng.
- Seam cho `scan`: `sensoractive.Scanner` (`Ready(ctx) error`, `RunNuclei(ctx, NucleiRequest) (nucleiout.Outcome, error)`), `*Dispatcher` thoả. `RunNuclei` kiểm văn phạm (như `nucleiargv.Build`) trước khi giao; trả `ErrScannerUnavailable` (và các lỗi bọc nó: `ErrScanWorkerUnavailable`, `ErrNucleiMissing`, `ErrPackMismatch`) khi máy quét không sẵn sàng (503 `scanner_unavailable`); `ErrWorkerLost`, `ErrWorkerRefused`, `ErrResultRejected` (kể cả JSONL bị `nucleiout` từ chối), `ErrOutputTruncated`, `*exec.ExitError` làm lượt chạy `failed`.
- `core` chỉ tin mã thoát, `truncated` và các byte JSONL; mọi dòng ngoài mẫu hay đích (host:port) của job là cả lượt bị bỏ (D-136 (1), (7)). Một kết quả nuclei có `xml_b64` (hay ngược lại) bị từ chối.

**D-512 (bản 5, đọc SNMP; mã `core/sensorlink/wire.go`, `modules/sensor-active/{snmp_dispatch.go,snmp.go,worker/snmp.go}`).**
- Heartbeat `active` thêm `"snmp": true` (worker bản 5 luôn gửi: gosnmp nằm trong binary). Thiếu = worker bản 4: `SNMPHealth` nói worker cũ hơn `core`, không job `snmp` nào được tạo.
- Job: `{ "id", "kind": "snmp", "timeout_s" 1..3600, "rate" 1..1000, "credentials": [ ≤ 8 × {"version": "v2c", "community"} | {"version": "v3", "user", "auth": "sha"|"sha256", "auth_pass", "priv": "aes128"|"" , "priv_pass"} ], "targets": [ ≤ 64 × {"ip", "credentials": [1..4 chỉ số, không trùng]} ] }`. Community 1..64, user 1..64, mật khẩu v3 8..64 ký tự ASCII in được; không v1, MD5, DES, noAuthNoPriv. IP: IPv4 chính tắc, không trùng, local (`core/localnet`). `sensorlink.CheckSNMPJob` là văn phạm chung; `core` kiểm trước khi giao, worker kiểm lại (`refused`/`invalid_job`, không gói nào). **Không có OID trên dây**: worker luôn GET đúng danh sách của nó (sysDescr, sysObjectID, sysName, entPhysicalClass/ModelName/SoftwareRev/SerialNum .1). Bí mật đi trên dây chỉ trong link mTLS này; `SNMPCredential` tự in ra `[redacted]`.
- Worker: từng đích một, thử các credential của đích theo thứ tự tới khi được trả lời; timeout 2 s, thử lại 1; sau mỗi đích nghỉ `2/rate` giây (một lần đọc v3 là hai gói). Khe thứ ba (`slotSNMP`), job `snmp` thứ hai khi khe bận → `busy`. Hết `timeout_s` → `done` với `reason: "deadline"` và các đích đã xong.
- Kết quả: `{"status": "done", …, "xml_b64": "", "snmp": [ ≤ 64 × {"target", "status": "ok"|"no_answer"|"auth_failed"|"unknown_user"|"error", "credential" (chỉ số), "values": {"sys_descr", "sys_object_id", "sys_name", "ent_class", "ent_model", "ent_software", "ent_serial"}} ]}`; mỗi giá trị ≤ 512 byte (worker cắt 255, UTF-8 hợp lệ), giá trị chỉ khi `ok`; `snmp` chỉ khi `done`, không cùng `xml_b64`/`jsonl_b64`/`host_errors` (khác → `400`). `core` từ chối câu trả lời cho đích hay credential job không nêu (`ErrResultRejected`) và tự phân tích giá trị (không tin cậy, sensor-active INV-10).
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

**SP-4 (làm rõ, mã `modules/sensor-passive/{capture,backend.go}`, D-122).**
- Mỗi lần gửi `observations` dùng một `seq` mới trong cùng một `epoch`, kể cả khi gửi lại các mục đã gửi hụt: lô gửi lại có thể là tập mục khác (đã chia đôi, đã bỏ mục độc), và `core` bỏ `seq` đã thấy. Sensor thử lại **sau** `Retry-After` của `core` nhưng không quá 60 s; một lỗi kết nối, `426`, `429`, `503` và `403 cert_retired` là "thử lại" (chỉ `503 store_busy` cùng một heartbeat vừa thành công mới dẫn tới chia lô; `503 not_ready` không bao giờ, D-385); `413` chia đôi (một mục vẫn `413` thì bỏ); mọi mã khác bỏ lô và đếm `batch_dropped`. Một lô hỏng 3 lần liên tiếp bị chia đôi cho tới khi một mục đứng riêng; mục đó bị bỏ (đếm `observation_failed`) chỉ khi một heartbeat vừa thành công.
- Kiểm mục ở `core`: một dòng `mac` phải có `mac` và `value == mac`; `kind` chỉ nhận `ap`, `switch`, `router`, `printer`, `iot` (kẹp 0.6, 0.6, 0.6, 0.5, 0.3); mục có MAC hoặc IP của chính hộp (theo card của host) là `refused`; `mac` đúng dạng (chữ thường) và không phải địa chỉ nhóm hay toàn không; `ip` IPv4 unicast (IPv6 là `invalid_item`, vì tài sản chỉ có địa chỉ IPv4); `confidence` ngoài [0,1] là `invalid_item`, trong khoảng thì kẹp theo trần của trường: `mac` 0.9, `hostname` 0.7, `kind` 0.6, `model` 0.5, `vendor` 0.4, `os` 0.3; thiếu `seen_at` là `out_of_window`.
- Bộ lọc lặp: cùng (MAC, IP, trường, giá trị) trong 15 phút được xác nhận mà không ghi (không nằm trong `rejected[]`); trần 6000 mục mỗi phút cho vai `passive` (phần vượt: `budget_exhausted`, không đọc). Thêm hạn mức 4 địa chỉ IP mới mỗi MAC mỗi giờ.
- Hạn mức chống ngập tính **trước** khi ghi và áp vào hạn mức **sau** khi inventory nhận: kho lỗi (`503`) không tốn hạn mức. Mục không có MAC tính theo địa chỉ IP. "Hết hạn mức" được ghi log một lần mỗi phút.
- `drops` mang **34 khoá đã biết**: `arp_mac_mismatch`, `batch_dropped`, `capture_failed`, `dhcp_mac_mismatch`, `dns_name_rejected`, `excluded`, `filters_invalid`, `flows_dropped`, `fragment_skipped`, `malformed_{arp,dhcp,dns,ethernet,http,ipv4,lldp,mdns,ssdp,tcp,tls,udp}`, `metadata_dropped`, `metadata_failed`, `new_macs_dropped`, `new_macs_unconfirmed`, `non_unicast_ip`, `observation_failed`, `observation_rejected`, `observations_dropped`, `unusable_record`, `value_empty`, `value_truncated`, `values_dropped`, `vendor_rejected`; khoá lạ nhưng đúng dạng (`^[a-z][a-z0-9_]{0,47}$`) được `core` **bỏ qua và ghi log một lần mỗi khoá** (tương thích về sau); giá trị âm, kiểu sai hoặc khoá sai dạng là `400`; tên card trùng trong `interfaces` cũng `400`. Giá trị là bộ đếm cộng dồn từ lúc tiến trình sensor khởi động. `filters_invalid` tăng mỗi lần sensor nhận một bộ lọc nó không biên dịch được; lúc đó nó không bắt gói.
- Sensor gửi heartbeat ngay khi khởi động và mỗi 30 s, kể cả khi `config` nói `interface ""`; trong lúc `module_off` nó không gửi. Danh sách `interfaces` bị lọc theo hình dạng của dây (tên card theo regex, MAC chữ thường, ≤ 32 card, ≤ 8 tiền tố IPv4 mỗi card).
- `config` long-poll: `core` đọc lại cài đặt (bộ lọc của trang network) mỗi 5 s trong lúc giữ request, và `SetInterface` đánh thức ngay. Bộ lọc `core` không đọc được cho `interface ""` (cùng ETag với cấu hình "không bắt gói" thường).
- `Client.PostObservations` là một lần thử, không lùi, không ngủ, và là đường duy nhất gửi quan sát (không còn `SendObservations`).

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
| 409 | `module_off` | module của vai tắt | **dừng ngay**, bỏ hàng đợi, không xả lô cuối (SYS-5, D-80 (4)); hỏi lại `config`/`jobs` mỗi 60 s (thường thì host đã dừng hẳn container) |
| 409 | `poll_in_progress` | long-poll thứ hai của cùng vai | lỗi lập trình: đợi poll đang mở xong |
| 413 | `payload_too_large` | thân vượt trần route; XML > 8 MiB | quan sát: chia đôi lô (lô một mục vẫn 413 → bỏ, đếm); kết quả job: không gửi lại (probe đã `failed`) |
| 426 | `proto_unsupported` | thiếu `X-Vedette-Proto`, hoặc không phải bản của `core` hay bản liền trước (mới hơn `core`, hay cũ hơn hai bản; D-459) | giữ hàng đợi, lùi tới 60 s, thử lại (§10) |
| 429 | `rate_limited` | quá 10 request/giây, burst 20, mỗi vai | chờ `Retry-After` |
| 503 | `store_busy` | kho của `core` bận | chờ `Retry-After`, gửi lại **cùng** lô |
| 503 | `not_ready` | `core` chưa đủ dữ kiện để xét lô: vai `passive` chưa biết card của chính hộp (host đã cấu hình mà chưa đưa danh sách; không có host và không có heartbeat dưới 90 s; D-385) | chờ `Retry-After` (5 s), gửi lại cả lô; **không** chia lô, không đổ cho mục nào |
| 500 | `internal` | lỗi khác của `core` | bỏ lô, đếm (OTLP: không thử lại) |
| — | (không có phản hồi) | lỗi kết nối, `core` đang khởi động lại | gửi lại cùng lô sau quãng lùi 1 → 60 s có jitter (`holdOff`); quá trần hàng đợi trong bộ nhớ thì bỏ cũ nhất và đếm |

SP-1 (làm rõ): chỉ request qua được bước 1 đến 3 (kể cả `module_off`) mới tiêu một token của nhịp; `Retry-After` của `429` là số giây tới token kế (làm tròn lên, ít nhất 1). Mọi mã trong bảng do `core/sensorlink/errors.go` (`codes`) định nghĩa; thân lỗi có thông điệp cố định theo mã. Bảng này **không** vào `API_CONVENTIONS` §3.3 (đó là API công khai của GUI; dây sensor là nội bộ).

Thứ tự kiểm ở `core` cho mỗi request: serial (`cert_retired`) → `X-Vedette-Proto` (`426`) → route theo vai (`403`) → module (`409 module_off`) → nhịp (`429`) → long-poll duy nhất (`409 poll_in_progress`) → (chỉ kết quả job) id đúng dạng (`400`) rồi là job đang chạy (`404 unknown_job`), **không đọc thân** → chỗ chứa thân của vai (`503 store_busy`, **không đọc thân**) → trần thân (`413`) → giải mã chặt (`400`) → handler.

**Thân trong bộ nhớ có trần theo vai (M1 của rà soát SP-1; SYS-6).** Tốc độ 10/s không giới hạn số thân `core` đang giữ cùng lúc: một chứng chỉ bị chiếm sẽ giữ hàng chục thân 11 MiB mở trong 10 s. Nên trước khi đọc **bất kỳ** thân nào, request lấy một chỗ: tối đa **2 thân đang đọc cùng lúc mỗi vai** (`MaxBodiesPerRole`), và **1** cho `POST /jobs/{id}/result` (`MaxResultBodies`; worker chạy một job một lần). Không có chỗ → `503 store_busy` với `Retry-After: 1`, thân không được đọc, kết nối bị đóng; chỗ trả lại khi request kết thúc (kể cả khi kết nối đứt hay thân quá hạn). Kết quả job: trước khi đọc thân, `core` hỏi `Backend.JobRunning(id)`; id sai dạng → `400`, job không đang chạy → `404 unknown_job`, cả hai không đọc thân và đóng kết nối. Sensor xử lý `503` như cũ: chờ `Retry-After`, gửi lại cùng lô.

**Một sensor không giữ được các chỗ kết nối (WP-31 M3, D-176).** `MaxConns` = 64 = 16 chỗ cho kết nối đang bắt tay (`MaxPending`, D-326) + phần của vai **tại bắt tay TLS** (vai đọc từ chứng chỉ đã xác minh): `passive` tối đa 32, `active` tối đa 16 (`MaxConnsPassive`, `MaxConnsActive`); kết nối vượt phần của vai hỏng bắt tay, kể cả khi nó không gửi byte nào, trên HTTP/1 và h2. Trên HTTP/1 mọi từ chối trước khi đọc thân trả `Connection: close` kèm hạn đọc 1 s (`DrainGrace`) khi yêu cầu có thể mang thân (h2: không đóng cả kết nối); `GET` có thân = `400 invalid_request`. `ReadTimeout` toàn yêu cầu = `ReadHeaderTimeout + BodyTimeout` (15 s); long poll gỡ hạn đó cho chính nó. Giới hạn đã biết: dòng TCP/TLS chưa xác thực trước bắt tay chưa tính theo vai được (D-176 (5)).

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
| Job nmap | 1 … 64 đích, `rate` 1 … 1000, `timeout_s` 1 … 7200 |
| Job nuclei (bản 2) | 1 … 32 id mẫu, 1 … 16 đích IPv4 riêng, `rate` 1 … 20, `max_host_errors` 2 … 20, `timeout_s` 1 … 3600; JSONL ≤ 1024 dòng |
| Job chạy cùng lúc | một nmap và một nuclei (`running` ≤ 2 id); một job mỗi loại trong một reply |
| `cancel` mỗi phản hồi | 8 |
| Phản hồi `core` (sensor đọc) | `config`, `jobs` 64 KiB; khác 16 KiB |
| `wait` | 0 … 30 s (mặc định 25) |
| Nhịp request | 10/giây, burst 20, mỗi vai (long-poll cũng tính) |
| Long-poll mở | 1 mỗi vai |
| Thân đang đọc cùng lúc | 2 mỗi vai, 1 cho kết quả job (M1); không có chỗ → `503 store_busy`, `Retry-After: 1` |
| Kết nối cùng lúc | 64 cho cả listener (`PendingListener`: 16 đang bắt tay + 32 passive + 16 active; D-326) |
| Hạn mức chống ngập (`core`) | MAC mới 60/phút và 200/giờ; giá trị mới và địa chỉ IP mới 4 mỗi (MAC, trường) mỗi giờ; 6000 mục/phút cho vai `passive`; lặp trong 15 phút không ghi |
| Heartbeat | mỗi 30 s; `online` khi ≤ 90 s |
| Lease của worker | 60 s không poll thành công |
| Job chờ lấy | 60 s |
| Chứng chỉ | 7 ngày; cấp mới khi còn ≤ 1/3 |
| Epoch giữ lại | 2 mỗi sensor |
| Timeout máy chủ | `ReadHeaderTimeout` 5 s, `WriteTimeout` 35 s |

Các số là điểm xuất phát để đo lại khi có mã (ARCHITECTURE §11), không phải kết quả đo.

## 10. Versioning

- Đường dẫn `/sensor/v1`; `X-Vedette-Proto` là số nguyên, hiện `5` (bản 5: job `snmp`, D-512, và, trước lần phát hành đầu của bản 5, `scope` của job nuclei và `nuclei.own_ip` trong heartbeat, D-520; bản 4: `capture_error` trong heartbeat thụ động, D-399; bản 3: `host_errors` trên kết quả nuclei, D-165; bản 2: `Job.kind`, job và kết quả nuclei, heartbeat `nuclei`, `running` nhiều id). Vì giải mã chặt, mọi đổi dây (kể cả thêm trường hay thêm `shape`) tăng proto, **trừ** khi số đó chưa từng được phát hành (D-520 thêm vào bản 5 trước lần phát hành đầu của nó, xem gạch đầu dòng sau).
- **Lệch bản (D-459, như version skew của Kubernetes: kubelet không bao giờ mới hơn kube-apiserver, được cũ hơn):** `core` nhận proto của mình (`sensorlink.ProtoVersion`) **và bản liền trước** (`sensorlink.ProtoPrevious`, hiện `4`; `TestProtoPreviousIsOneBelow` giữ nó đúng bằng bản trừ một); sensor hay worker **mới hơn** `core` và cũ hơn hai bản → `426`. Một lần tăng proto phải giữ cho `core` phục vụ được bên bản cũ: trường mới của request là tuỳ chọn (vắng = nghĩa cũ; proto 3 không có `capture_error` = không có lỗi bắt gói); đổi thứ `core` **trả** (reply) thì trước hết phải thêm cái chưa có: truyền proto của request vào handler và trả dạng cũ cho bên `ProtoPrevious`, kèm test. Bản 4 so với bản 3 chỉ thêm `capture_error` vào request, nên reply không khác. D-520 thêm vào bản 5 **trước lần phát hành đầu của nó** (không tăng lên 6: bản phát hành mới nhất `v0.1.0-beta.1` nói 4, và một bản 6 sẽ không còn đường cập nhật từ nó theo D-410): `own_ip` trong heartbeat là tuỳ chọn (vắng = `false`); `scope` chỉ có ở job `own_ip`, và `core` chỉ giao job đó cho worker có `own_ip=true`, nên worker bản 4 (và worker bản 5 dựng trước D-520) nhận đúng reply nó biết (`sensoractive` `TestOwnIPNucleiNeverGoesToAWorkerWithoutOwnIP`).
- **Thứ tự cập nhật:** Apply đổi `core` **trước** rồi mới `sensor`/`scan`/`honeypot` (`modules/core/updates_run.go` `planApply`, CONTRACT core INV-35): health check của sensor/worker là heartbeat được `core` nhận (`cmd/vedette-sensor/health.go`), nên chỉ được xét sau khi `core` đã ở bản mới; trong cửa sổ đó sensor cũ (N-1) vẫn được nhận. Rollback ngược lại: `sensor`/`scan` về trước (về proto mà `core` đang chạy vẫn nhận), `core` sau cùng, nên không lúc nào sensor mới hơn `core`. Sensor tự quay về sau một lần đổi hỏng ở lại N-1, vẫn được nhận. Một bản phát hành tăng proto lên N phải đặt `min_upgrade_from` (`update-manifest.md`) không thấp hơn bản phát hành đầu tiên có proto N-1, để không hộp nào nhảy hai bản proto một lần; `release-manifest` kiểm luật này từ git (proto ở tag của bản này và của mọi bản trước) và từ chối khi `min_upgrade_from` còn để lọt một bản có proto dưới N-1 (D-410).
- Giới hạn: kế hoạch cập nhật do bản **đang chạy** lập, nên chỉ cập nhật đi **từ** một bản đã có D-459 mới theo thứ tự này; hộp chạy bản trước D-459 (như `0.0.1-test.16`) vẫn đổi sensor trước và bị đặt lại khi proto tăng: cài lại bằng `install.sh` bản mới.
- Sensor gặp `shape` hay trường không biết: `refused` (`invalid_job`) / `400` khi giải mã, không crash.
- Nới tập đích của văn phạm mà không đổi dây (D-461: thêm 100.64/10) không tăng proto: dây giữ nguyên; trong cửa sổ cập nhật (core trước), worker cũ trả `refused`/`invalid_job` cho job có đích mới như mọi job sai văn phạm (không tiến trình nào chạy), không bao giờ quét gì ngoài văn phạm của nó. Vì `nextBatch` (`modules/sensor-active/service.go`) đi các dải đã gộp theo thứ tự địa chỉ, một lô quét dò trộn địa chỉ RFC 1918 và 100.64/10 bị từ chối **cả lô**: trong cửa sổ đó vài máy RFC 1918 chưa được quét dò tới lượt sau, mỗi job bị từ chối để lại một dòng log Error và một hàng probe thất bại; không gì ngoài văn phạm chạy.

## 11. Cân nhắc bảo mật (ánh xạ SYS)

| SYS | Áp dụng ở đây |
|---|---|
| SYS-1 | Không lệnh tổng quát; worker chỉ chạy `/usr/bin/nmap` qua `core/exec` với argv dựng từ job đã kiểm và `ValidateNmapArgs` |
| SYS-2 | Trần thân trước giải mã, `jsonstrict`, `netip`, regex ở biên của `core`; worker kiểm lại job |
| SYS-3 | Cấp, xoay, cho về hưu chứng chỉ sensor ghi `core_audit` (actor `system`); mỗi lần chạy nmap có dòng `sa_probe` **trước** khi job được giao (INV-9) |
| SYS-4 | Khoá CA qua `core/secrets`; khoá sensor chỉ ở volume của vai (0640, chỉ đọc trong container), không log, không xuất, GUI không hiện |
| SYS-5 | Module tắt → `409 module_off` và host dừng container; dữ liệu giữ nguyên |
| SYS-6 | Mọi thứ từ sensor là không tin cậy: trần, giải mã chặt, hạn mức, kẹp độ tin cậy, XML phân tích ở `core` |
| SYS-7 | `core` là bên đồng ý duy nhất (D-26, D-84); worker chỉ nhận IPv4 riêng trong văn phạm ba mẫu |
| SYS-8 | Không liên quan (AI không nằm trong giao thức) |

Rủi ro còn lại:
- `sensor` bị chiếm vẫn giả được quan sát **hợp lý** (cố hữu): bị chặn bởi hạn mức của `core`, trần 32 dòng mỗi (thiết bị, trường, nguồn) của inventory, thiết bị mới `approved=false` (S-INV-3) và mọi hành động đều cần duyệt (D-51).
- `scan`/`sensor` bị chiếm giữ `NET_RAW` trên namespace mạng của host: gửi và đọc được khung trên LAN (cố hữu với quyền đó); không có `NET_ADMIN`, không root, rootfs chỉ đọc, không DB, không khoá của vai kia.
- Chứng chỉ bị lấy cắp: chỉ mở route của vai đó, hết hạn trong ≤ 7 ngày, về hưu ở lần xoay kế tiếp.
- `core` khởi động lại giữa lúc quét: lô dở bị bỏ (lease giết nmap), lô đã xong giữ (như INV-3).

## 12. Câu hỏi của bản nháp (đã đóng)

1. ~~Không có story cho enroll sensor tách rời~~ **Đã đóng (D-115):** không xây; §3.1 cũ chuyển sang phụ lục A; trên appliance không enroll qua mạng, `core` giao khoá bằng tệp (D-110 (4)).
2. ~~Cổng listener và CA chung hay tách~~ **Đã đóng (D-109, D-110):** listener riêng `:8444`, chỉ `127.0.0.1:8444` trên appliance; một CA **riêng cho sensor** ký cả lá máy chủ 8444 và lá sensor, EKU tách vai; tách khỏi chứng chỉ 8443 và CA osquery.
3. ~~Honeypot có danh tính mTLS riêng hay đi qua sensor~~ **Đã đóng (D-89, D-112 (7)):** không cách nào; hit đi qua tệp JSON-lines một chiều, honeypot không có đường mạng tới `core`.
4. ~~Khớp IOC ở sensor hay ở `core`~~ **Đã đóng cho hồ sơ này (D-112 (7)):** không có metadata SPAN hay IOC trên dây tới khi module `logs` được xây; chọn nơi khớp cùng `logs` (deferred).
5. ~~Phân tích syslog ở `core` hay sensor~~ **Đã đóng cho hồ sơ này (D-112 (7), D-114 (3)):** không nhận syslog, không `NET_BIND_SERVICE` tới khi `logs` được xây.
6. ~~Thời hạn chứng chỉ 90 ngày, trần/WAL chưa đo~~ **Đã đóng (D-110 (3), D-112 (6)):** 7 ngày, cấp mới ở 1/3 cuối; không WAL; trần ở §9 là điểm xuất phát để đo.

## 13. Lát

Mỗi lát một PR, sau SP-0 (tài liệu này): SP-1 `core/pki` + `core/sensorlink` (máy chủ, client, chưa nối module); SP-2 seam `Prober` và gói `nmapargv` (refactor thuần, song song SP-1); SP-3 bộ điều phối + `vedette-sensor active` (cần SP-1, SP-2); SP-4 tách sensor-passive + `vedette-sensor passive` (cần SP-1); SP-5 đóng gói, profile compose `dev`, nguồn địa chỉ của hộp (cần SP-3, SP-4); SP-6 unit `sensor`/`scan` và dựng `scan` tại chỗ trong `vedette-host` (cần lát host 3-6, 3-7). Bản đồ lát, rủi ro lab và việc để sau: `.ai/deferred/feat-sensor-protocol.md`.

## Phụ lục A. Để sau: sensor đặt ở máy khác (D-115)

Không xây. Không có story (D-24, D-57 (18)); test GUI `inventory.test.tsx` khẳng định không có endpoint sensor từ xa. Khi có story, đường đi xa giữ dây, URI vai và CA sensor của tài liệu này, và thêm: bootstrap kiểu kubelet (token bootstrap → CSR do sensor tạo, khoá ở lại sensor, gia hạn gần hết hạn), bind trên LAN, hành động thu hồi có giao diện, hàng đợi đĩa có trần (thay "không WAL" của D-112 (6)), và danh tính theo từng sensor thay cho hai URI theo vai.

Văn bản §3.1 của bản nháp M2-0 (2026-11-09), giữ để tham khảo; chỗ khác với quyết định hiện tại ghi trong ngoặc vuông:

> **Enroll.** Token enroll của sensor: một lần dùng, hết hạn mặc định 1 giờ, thu hồi được, **chỉ trong header `Authorization: Bearer`**, không bao giờ trong URL (cùng nguyên tắc D-34). Trên appliance, installer sinh token cục bộ vào volume dùng chung; người dùng không thấy. [Appliance không còn enroll: D-110 (4).]
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
> **Chứng chỉ (bản nháp §3).** Sensor ghim CA bằng vân tay SHA-256 truyền lúc enroll (`--ca-sha256`), không có vân tay thì từ chối enroll (không TOFU âm thầm). Chứng chỉ client `CN=sensor:<sensor_id>`, SAN URI `vedette:sensor:<sensor_id>`, 90 ngày. Thu hồi: core giữ `sensor_id → active|revoked`, kiểm mỗi request, `403 sensor_revoked`. [CA là CA sensor của D-110, không phải CA osquery; thời hạn 7 ngày; trên appliance danh tính theo vai.]
