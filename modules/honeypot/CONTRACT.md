# Honeypot Contract

> Cài đặt: WP-14 (2026-11-09, D-89, D-90). Mọi điểm lệch/chốt thêm nằm ở D-90.
> Tier: tuỳ chọn (tắt mặc định) · Story: S-HP-1, S-HP-2 · Quyết định: D-10, D-18, D-43, D-50, D-55, D-56 · Last verified: 2026-11-09
> Nguồn hành vi thực tế: `web/src/features/honeypot/{contract,types,mocks}.ts`. OpenAPI sinh từ `contract.ts` (D-18); mọi khác biệt dưới đây là lỗi của một trong hai bên.

## Invariants (luôn đúng)
- **INV-1** Bẫy chỉ nghe và ghi log, không bao giờ chủ động kết nối ngược về nguồn và không chạy dịch vụ thật (LEGAL §3, S-HP-2). Test: phía mã `TestContract_INV1_NoDialer` (module không import `net` dial/`os/exec`/`net/http`); phía gói tin `TestContract_INV1_NoOutboundToSource` (bắt gói ra từ container `honeypot` tới IP nguồn = 0) thuộc WP-08.
- **INV-2** Cổng cố định theo dịch vụ: smb 445, rdp 3389, ssh 22, mssql 1433, http 80. Chỉ 5 dịch vụ trong enum `HpService`.
- **INV-3** Kết nối của chính máy quét Vedette (IP của hộp) bị loại trừ: không tạo `hp_hits`, không cảnh báo, chỉ tăng `ignored_7d`. Broadcast không tạo hit.
- **INV-4** Hit thử (`is_test=true`: test-hit, test-scan, tokens/{id}/test) không vào `summary`, `hits_7d`, `last_hit_at`, tín hiệu ẩn danh; không gửi cảnh báo.
- **INV-5** IP phụ (`secondary_ip`) và IP bẫy (`decoys[].ip`) phải: là IPv4 hợp lệ không số 0 đứng đầu; nằm trong dải mạng của hộp (`HpOverview.lan`), không phải địa chỉ mạng/broadcast; khác IP của hộp; không trùng thiết bị nào trong kho (409 `ip_in_use`); không trùng nhau. `lan = null` (cài mới chưa khai dải) → từ chối đặt IP.
- **INV-6** Bật bẫy (`PATCH /honeypot/traps/{service}` enabled=true) cần có `secondary_ip` (409 `no_secondary_ip`) và không đụng thiết bị trong kho (409 `ip_in_use`). Nếu IP phụ về sau trùng thiết bị mới nhập kho, `Trap.state = conflict` và bẫy không lắng nghe.
- **INV-7** `Trap.state` ∈ {off, listening, conflict}; `listening` ⇔ enabled ∧ không conflict ∧ container `honeypot` đang nghe cổng đó.
- **INV-8** Thiết bị nguồn (`src_asset_id`, `src_name`) tra từ kho tại lúc đọc; `src_name = null` ⇔ IP không có trong kho. Hàng lưu `hp_hits` có thêm `source_ip` = `src_ip` (cho `response` đọc qua interface, xem IMPACT).
- **INV-9** `GET /honeypot/hits` trả mới nhất trước; `HitDetail.events` là các sự kiện log trong khoảng `window_minutes` (60) quanh hit; `mark=true` đúng một dòng là hit.
- **INV-10** `Token.password` chỉ có khi `type=credential`, còn lại `null`. `HitKind=token` chỉ sinh từ token còn tồn tại; xoá token → bản đã rải không còn sinh hit.
- **INV-11** Gợi ý vai giả (`DecoySuggestion`) chỉ gồm loại thiết bị có thật trong kho; vai ∈ {windows_fs, nas, printer, camera, linux}.
- **INV-12** `excerpt`, `label`, `src_*` đến từ kẻ chạm bẫy: không tin cậy (SYS-6): cắt độ dài, không diễn giải thành lệnh, hiển thị dạng text.
- **INV-13** Mọi mutation (config, bật/tắt bẫy, decoy, token) ghi `core_audit` (SYS-3).
- **INV-14** Tín hiệu ẩn danh (PRIVACY luồng 2) chỉ nhận từ module này **số lần chạm theo loại**; không IP, không tên thiết bị, không nội dung.

## Preconditions (trước khi gọi)
- **PRE-1** `POST /honeypot/test-hit`: bẫy của dịch vụ đó đang bật và không conflict (409 `trap_off` / `ip_in_use`).
- **PRE-2** `PUT /honeypot/config` và `POST /honeypot/decoys`: vai admin; đầu vào qua schema trước service (SYS-2).
- **PRE-3** Module `honeypot` bật, `inventory` bật.

## Postconditions (sau khi xong)
- **POST-1** Một kết nối thật vào bẫy đang `listening`: sinh đúng một `hp_hits` (kind=service), phát `honeypot.hit.created`, và trong ≤ 60 s `notify` có cảnh báo kèm IP nguồn, thiết bị nguồn, 1 giờ sự kiện quanh đó (S-HP-1).
- **POST-2** Chạm honey token / quét cổng tới IP bẫy: sinh hit kind=token / scan với `label` nêu cái bị chạm (S-HP-2).
- **POST-3** Hit thật là nguồn của trigger `honeypot` trong `response` (D-50): trường `source_ip`, `source_device`, `decoy`, `kind`.
- **POST-4** Tạo token loại `file` với `ext` (docx|xlsx) trả `value` là tên tệp để rải; `plant_at` do chủ hộp ghi.
- **POST-5** Xoá decoy → IP bẫy ngừng nghe; xoá token → ngừng cảnh báo; không xoá `hp_hits` cũ.

## Forbidden (không bao giờ)
- **FORBID-1** Lắng nghe trên IP quản trị của hộp hoặc trên IP của thiết bị trong kho.
- **FORBID-2** Trả nội dung dịch vụ thật (file thật, banner thật của hộp); mở cổng ngoài 5 cổng của INV-2 trên IP bẫy.
- **FORBID-3** Gọi lệnh mạng/OS trực tiếp; dựng IP phụ chỉ qua `vedette-host` (SYS-1, D-55).
- **FORBID-4** Gửi IP/tên thiết bị trong tín hiệu ẩn danh (INV-14).
- **FORBID-5** Endpoint sửa/xoá `hp_hits` (hit là chứng cứ).

## Endpoints owned (từ `contract.ts`)
| Method | Path | Vai tối thiểu | Story |
|---|---|---|---|
| GET | `/honeypot` | viewer | S-HP-1 |
| PUT | `/honeypot/config` | admin | S-HP-1 |
| PATCH | `/honeypot/traps/{service}` | admin | S-HP-1 |
| GET | `/honeypot/hits` (`?asset=`) | viewer | S-HP-1 |
| GET | `/honeypot/hits/{id}` | viewer | S-HP-1 |
| POST | `/honeypot/test-hit` | operator | S-HP-1 |
| GET | `/honeypot/decoys` | viewer | S-HP-2 |
| POST | `/honeypot/decoys` | admin | S-HP-2 |
| PATCH | `/honeypot/decoys/{id}` | admin | S-HP-2 |
| DELETE | `/honeypot/decoys/{id}` | admin | S-HP-2 |
| POST | `/honeypot/test-scan` | operator | S-HP-2 |
| GET | `/honeypot/tokens` | viewer | S-HP-2 |
| POST | `/honeypot/tokens` | admin | S-HP-2 |
| DELETE | `/honeypot/tokens/{id}` | admin | S-HP-2 |
| POST | `/honeypot/tokens/{id}/test` | operator | S-HP-2 |

## Tables owned
`hp_config` (IP phụ, hostname, trạng thái bẫy, `ignored_7d`), `hp_hits` (+ `kind`, `source_ip`, `token_id`), `hp_decoys`, `hp_tokens`. Không module nào khác đọc trực tiếp (modules.md); `response` đọc `hp_hits` qua interface (IMPACT).

## Events
- **Phát**: `honeypot.hit.created` (tên 3 đoạn theo `core/events`, issue #62; `notify` đã nghe tên này). Chỉ cho hit thật, sau khi commit; hit thử không phát gì (INV-4). Trường: `id, ts, kind, service, port, src_ip, label`.
- **Nhận**: `inventory.asset.discovered|updated` (gợi ý: áp lại trạng thái lên host, thiết bị mới trùng IP phụ/IP bẫy → `conflict`). Đọc kho (`inventory`) qua cổng `Inventory` để tra nguồn và kiểm tra trùng IP.
- **Đường vào của hit (D-89)**: tệp JSON-lines `opencanary.jsonl` trên volume dùng chung (`-honeypot-dir`), core chỉ đọc; không cổng mạng nào vào core.

## Khi tắt module (SYS-5)
Không route `/honeypot*`, container `honeypot` dừng, IP phụ/IP bẫy được gỡ qua `vedette-host`, không cổng nào mở. Dữ liệu `hp_*` giữ nguyên. Trigger `honeypot` trong `response` không còn sự kiện; UI báo "đang tắt" ở trang Incidents/Rules (S-CORE-1).

## Dependencies
- **DEPENDS ON**: `core` (auth, audit, scheduler, `core/secrets` không dùng), `inventory` (tra nguồn, kiểm tra IP), `host` (dựng IP phụ).
- **DEPENDED ON BY**: `response` (trigger), `notify` (cảnh báo), `logs` (SIEM kênh `honeypot`), `reports` (chưa dùng, xem câu hỏi mở), `ai` (đọc hit qua công cụ chỉ-đọc), GUI `inventory` (panel `device.panels`).

## Câu hỏi mở
1. Phát hiện "quét cổng tới IP bẫy" (D-50): container `honeypot` (OpenCanary không log SYN) hay `sensor` (pcap) làm? Quyết định vì quyền `net_raw`.
2. Có cần chặn `sensor-passive`/`inventory` lập thiết bị từ IP bẫy không? GUI mock chưa nói.
3. URL token/DNS token kích hoạt bằng cách nào khi người chạm ở ngoài LAN (cần tên miền/điểm thu của dự án)? Nếu cần thì thêm luồng ra → `PRIVACY.md` (legal.md).
4. Hit thử có kích hoạt trigger `response` không? Hợp đồng đề xuất: không (INV-4).
