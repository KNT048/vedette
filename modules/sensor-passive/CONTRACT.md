# Sensor-passive Contract

> Tier: standard · Story: S-INV-1, S-INV-3, S-LOG-4 (phần trích metadata SPAN) · Last verified: 2026-11-09 (WP-11: code + test hợp đồng + fuzz 35 s mỗi parser; bắt gói trực tiếp AF_PACKET chưa kiểm bằng hiệu ứng, xem `.ai/deferred/feat-sensor-passive.md`)

Nguồn hành vi: `web/src/features/inventory/{contract,SensorsSection}` (`/inventory/sensors*`) và D-43/D-56 (Box network). GUI chưa có màn Box network (không có endpoint/mock): phần đó nằm ở module `host` (nhóm B), module này chỉ đọc trạng thái.

## Invariants
- **INV-1**: Thụ động tuyệt đối: sensor không gửi khung nào lên LAN (không ARP probe, không mDNS/SSDP query, không DHCP). Mở bắt gói chỉ đọc; bộ đếm `tx_packets` của card nghe không đổi do Vedette. `TestContract_INV1_NeverTransmits`
- **INV-2**: Chỉ cần `CAP_NET_RAW`; không chạy root, không mở cổng nghe (SYS-1 không áp dụng vì không spawn; ARCHITECTURE §6).
- **INV-3**: Không lưu nội dung gói. Với SPAN chỉ trích: truy vấn DNS (tên), TLS SNI, HTTP Host, luồng IP (5-tuple + đếm); test với pcap fixture khẳng định mọi hàng lưu chỉ có các trường đó (D-43, D-56).
- **INV-4**: Gói là dữ liệu không tin cậy (SYS-6): parser DHCP/mDNS/SSDP/LLDP/ARP/DNS/TLS fail-closed, giới hạn kích thước; gói méo bị bỏ và đếm, không panic. Mỗi parser có một `Fuzz*` (ARP, DHCP, DNS/mDNS, SSDP, LLDP, TLS SNI, HTTP Host, đọc pcap, cả đường ống); chạy cục bộ ≥ 30 s mỗi cái, CI 60 s (chưa nối CI). Bộ đếm gói bỏ theo lý do (`malformed_*`, `excluded`, …).
- **INV-5**: Mỗi quan sát ghi `source=passive` với `confidence ∈ [0,1]` theo giao thức (hostname từ DHCP/mDNS, vendor từ OUI, model từ SSDP…), gửi qua `inventory.RecordObservation`; không bao giờ ghi trực tiếp `inv_*`.
- **INV-6**: MAC mới ⇒ tài sản `approved=false` (S-INV-3). Quan sát về chính hộp không tạo tài sản trùng với thiết bị "This box".
- **INV-7**: Bộ lọc loại trừ (dải, máy, cổng; D-56) áp trước khi trích; lưu lượng bị loại không để lại hàng nào.
- **INV-8**: Sensor chỉ gọi ra server (mTLS khi tách), lô idempotent theo `seq`; server không bao giờ gọi vào sensor; ở chế độ `vedette all` gọi trong process (ARCHITECTURE §3).
- **INV-9**: `PATCH /inventory/sensors/{id}`: `interface` phải ∈ `Sensor.interfaces` (400 `bad_interface`), `span` boolean; card đánh dấu SPAN không có IP. Cảnh báo "không thấy lưu lượng nhân bản" khi chỉ thấy MAC của chính hộp.
- **INV-10**: Fingerbank (tuỳ chọn): tắt mặc định, khoá BYOK, mọi lần gọi nằm trong PRIVACY.md.

## Thực hiện (WP-11)
- **Nguồn gói**: `Source{Next, Close}` không có hàm ghi/gửi. `FileSource` đọc pcap/pcapng (thuần Go, dev macOS và mọi test); `OpenLive` (`afpacket_linux.go`) là socket AF_PACKET chỉ nhận, promiscuous (bộ lọc nhận của card, không phát), chỉ cần CAP_NET_RAW. Nơi khác Linux: `ErrNoLiveCapture`.
- **Thang tin cậy** (INV-5, `engine.go`): MAC↔IP từ ARP/DHCP ACK/LLDP 0.9 · tên LLDP 0.7 · tên DHCP opt 12 và tên mDNS (bản ghi A đúng IP nguồn) 0.6 · loại từ LLDP capabilities 0.6 · model từ SSDP SERVER, mô tả LLDP, TXT mDNS `model`/`md` 0.5 · loại từ dịch vụ mDNS máy in / SSDP InternetGatewayDevice 0.5 · dịch vụ mDNS iot 0.3. OUI→hãng 0.4: chưa có (không có bảng OUI giấy phép rõ).
- **Trích SPAN** (`MetaItem`, kiểu đóng): DNS (tên + qtype), TLS SNI, HTTP Host (bỏ cổng), luồng IPv4 5-tuple + đếm (cộng dồn 60 s). Bật theo `Extract`; hộp tự thân (MAC/IP của mọi card) không tạo tài sản và không tạo metadata (INV-6).
- **Giới hạn**: mỗi lần xả tối đa 5000 quan sát, 20000 metadata, 20000 luồng; tràn thì đếm, không âm thầm. Lô ≤ 500 phần tử. Quan sát trùng chỉ gửi lại sau 15 phút (D-80).
- **Vòng bắt gói** chạy như job `capture` của `core/jobs`: chỉ khi module bật, tắt thì dừng ngay và không xả lô cuối. `SetInterface` đánh thức vòng để đổi card ngay.
- **API**: chỉ `GET /inventory/sensors`. `PATCH /inventory/sensors/{id}` chưa có trong `contract.ts`; luật INV-9 nằm ở `Service.SetInterface` (D-80 (5)). Lỗi `ErrBadInterface` → `bad_interface` khi route được nối.
- **Verdict SPAN**: `off` (SPAN tắt), `no_link` (card mất cáp), `no_traffic` (không gói trong 30 s hoặc không bắt gói), `own_only` (có gói nhưng không MAC nào khác hộp trong 5 phút), `ok`.

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
- `MODULES.md` ghi "Zeek/Suricata EVE reader" và ~~`PRIVACY.md` luồng 2 còn "IDS matches by CVE"~~ Đã đổi sang `cve_matches` (WP-06); phần `MODULES.md` còn mở.
- `MODULES.md` ghi bảng `inv_*` cho sensor; rule `modules.md` cấm module đọc bảng module khác nên đề xuất `sp_` + ghi qua `inventory`.
- Ai khớp IOC từ metadata SPAN: đề xuất `logs` nhận `sensor.span.metadata_batch`.
- Fingerbank chưa nằm trong bảng luồng PRIVACY (luồng 4 chỉ nói IP/domain/hash).
