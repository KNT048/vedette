# Sensor-passive Contract

> Tier: standard · Story: S-INV-1, S-INV-3, S-LOG-4 (phần trích metadata SPAN) · Last verified: 2026-11-09 (docs-first, chưa có code)

Nguồn hành vi: `web/src/features/inventory/{contract,SensorsSection}` (`/inventory/sensors*`) và D-43/D-56 (Box network). GUI chưa có màn Box network (không có endpoint/mock): phần đó nằm ở module `host` (nhóm B), module này chỉ đọc trạng thái.

## Invariants
- **INV-1**: Thụ động tuyệt đối: sensor không gửi khung nào lên LAN (không ARP probe, không mDNS/SSDP query, không DHCP). Mở bắt gói chỉ đọc; bộ đếm `tx_packets` của card nghe không đổi do Vedette. `TestContract_INV1_NeverTransmits`
- **INV-2**: Chỉ cần `CAP_NET_RAW`; không chạy root, không mở cổng nghe (SYS-1 không áp dụng vì không spawn; ARCHITECTURE §6).
- **INV-3**: Không lưu nội dung gói. Với SPAN chỉ trích: truy vấn DNS (tên), TLS SNI, HTTP Host, luồng IP (5-tuple + đếm); test với pcap fixture khẳng định mọi hàng lưu chỉ có các trường đó (D-43, D-56).
- **INV-4**: Gói là dữ liệu không tin cậy (SYS-6): parser DHCP/mDNS/SSDP/LLDP/ARP/DNS/TLS fail-closed, giới hạn kích thước; gói méo bị bỏ và đếm, không panic. Fuzz mỗi parser 60 s trong CI.
- **INV-5**: Mỗi quan sát ghi `source=passive` với `confidence ∈ [0,1]` theo giao thức (hostname từ DHCP/mDNS, vendor từ OUI, model từ SSDP…), gửi qua `inventory.RecordObservation`; không bao giờ ghi trực tiếp `inv_*`.
- **INV-6**: MAC mới ⇒ tài sản `approved=false` (S-INV-3). Quan sát về chính hộp không tạo tài sản trùng với thiết bị "This box".
- **INV-7**: Bộ lọc loại trừ (dải, máy, cổng; D-56) áp trước khi trích; lưu lượng bị loại không để lại hàng nào.
- **INV-8**: Sensor chỉ gọi ra server (mTLS khi tách), lô idempotent theo `seq`; server không bao giờ gọi vào sensor; ở chế độ `vedette all` gọi trong process (ARCHITECTURE §3).
- **INV-9**: `PATCH /inventory/sensors/{id}`: `interface` phải ∈ `Sensor.interfaces` (400 `bad_interface`), `span` boolean; card đánh dấu SPAN không có IP. Cảnh báo "không thấy lưu lượng nhân bản" khi chỉ thấy MAC của chính hộp.
- **INV-10**: Fingerbank (tuỳ chọn): tắt mặc định, khoá BYOK, mọi lần gọi nằm trong PRIVACY.md.

## Preconditions / Postconditions
- **PRE-1** (`Start(iface, opts)`): card tồn tại, có `CAP_NET_RAW`. **POST-1**: đang bắt gói; `Sensor.status=online`, `last_seen` cập nhật theo nhịp tim.
- **PRE-2** (`SetInterface(id, iface, span)`): `admin`. **POST-2**: bắt gói chuyển sang card mới trong cùng yêu cầu; `core_audit` ghi.
- **PRE-3** (`SubmitBatch(seq, obs[])`): `seq` tăng dần. **POST-3**: gửi lại cùng `seq` không tạo quan sát thứ hai.
- **PRE-4** (`SpanStats()`): không. **POST-4**: `{pps, other_macs, last_packet_at}` đo thật, không suy ra.

## Forbidden
- **FORBID-1**: Phát bất kỳ gói nào lên mạng.
- **FORBID-2**: Lưu payload, cookie, nội dung HTTP/TLS.
- **FORBID-3**: Ghi trực tiếp `inv_*`.
- **FORBID-4**: Chạy Zeek/Suricata hoặc bộ IDS khác (D-43).
- **FORBID-5**: Gửi MAC/vân tay thiết bị ra ngoài khi Fingerbank tắt.

## Dependencies
- **DEPENDS ON**: `core` (events, jobs, hostclient), `inventory` (`RecordObservation`).
- **DEPENDED ON BY**: `logs` (nhận metadata SPAN để khớp IOC, S-LOG-4; nhóm B), `honeypot` (không), SPA Devices → Scope and sensors.

## Endpoints owned (role tối thiểu)
| Route | Vai |
|---|---|
| `GET /inventory/sensors` | admin |
| `PATCH /inventory/sensors/{id}` | admin |

Box network (card quản trị/SPAN, hướng dẫn mirror, IP phụ, NTP — D-56): `host`, nhóm B.

## Tables owned (`sp_`)
`sp_sensor` (id, interface, span, version, last_seen), `sp_span_stat` (đo SPAN), `sp_seq` (seq đã nhận).

## Events
- **Phát**: `sensor.status.changed {id, online}`, `sensor.span.metadata_batch {seq, items[]}` (tiêu thụ bởi `logs`).
- **Nhận**: `host.network.changed` (mở lại bắt gói; nhóm B), `core.module.disabled`.

## Behaviour khi tắt
Không bắt gói, không job; thiết bị mới chỉ phát hiện qua quét chủ động/agent/khai tay; mất S-INV-3 "thiết bị lạ" thụ động và S-LOG-4 (khớp IOC từ SPAN). Danh sách thiết bị và quan sát cũ giữ.

## Story và quyết định
S-INV-1, S-INV-3, S-LOG-4; D-43 SPAN thay Zeek/Suricata; D-45; D-55 container `sensor`; D-56 Box network.

## Không khớp / câu hỏi mở
- `MODULES.md` ghi "Zeek/Suricata EVE reader" và `PRIVACY.md` luồng 2 còn "IDS matches by CVE": trái D-43.
- `MODULES.md` ghi bảng `inv_*` cho sensor; rule `modules.md` cấm module đọc bảng module khác nên đề xuất `sp_` + ghi qua `inventory`.
- Ai khớp IOC từ metadata SPAN: đề xuất `logs` nhận `sensor.span.metadata_batch`.
- Fingerbank chưa nằm trong bảng luồng PRIVACY (luồng 4 chỉ nói IP/domain/hash).
