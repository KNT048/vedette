# Logs Contract

> Tier: tuỳ chọn (tắt mặc định) · Story: S-LOG-1, S-LOG-2, S-LOG-3, S-LOG-4 · Quyết định: D-18, D-30, D-43, D-55, D-56 · Last verified: 2026-11-09
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
- **FORBID-5** Nhận syslog từ IP chưa khai làm nguồn rồi lưu như nguồn hợp lệ. (Đề xuất; xem câu hỏi mở 2.)

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
`logs_sources`, `logs_events`, `logs_retention`, `logs_siem`, `logs_ioc_hits`. `response` đọc `logs_ioc_hits` qua interface (IMPACT), không đọc bảng trực tiếp.

## Events
- **Phát**: `logs.batch` (sensor → server, idempotent theo `seq`, `ARCHITECTURE.md`); `logs.ioc_hit` (tên đề xuất; chưa có trong ARCHITECTURE).
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
