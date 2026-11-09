# Sensor-passive Contract

> Tier: standard · Story: S-INV-1, S-INV-3, S-LOG-4 (phần trích metadata SPAN) · Last verified: 2026-11-09 (WP-11: code + test hợp đồng + fuzz 35 s mỗi parser; bắt gói trực tiếp AF_PACKET chưa kiểm bằng hiệu ứng, xem `.ai/deferred/feat-sensor-passive.md`)

Nguồn hành vi: `web/src/features/inventory/{contract,SensorsSection}` (`/inventory/sensors*`) và D-43/D-56 (Box network). GUI chưa có màn Box network (không có endpoint/mock): phần đó nằm ở module `host` (nhóm B), module này chỉ đọc trạng thái.

## Invariants
- **INV-1**: Thụ động tuyệt đối: sensor không gửi khung nào lên LAN (không ARP probe, không mDNS/SSDP query, không DHCP). Mở bắt gói chỉ đọc; bộ đếm `tx_packets` của card nghe không đổi do Vedette. `TestContract_INV1_NeverTransmits`
- **INV-2**: Chỉ cần `CAP_NET_RAW`; không chạy root, không mở cổng nghe (SYS-1 không áp dụng vì không spawn; ARCHITECTURE §6).
- **INV-3**: Không lưu nội dung gói. Với SPAN chỉ trích truy vấn DNS (tên, qtype), TLS SNI, HTTP Host, luồng IP (5-tuple + đếm). `MetaItem` có đúng các trường `Kind, At, SrcMAC, SrcIP, DstIP, Name, QType, Proto, SrcPort, DstPort, Packets, Bytes, First`, không trường nào là slice/map/con trỏ; `TestContract_INV3` khóa danh sách và dò chuỗi bí mật của fixture HTTP trong mọi nơi lưu (D-43, D-56). Giá trị văn bản tự do bị cắt ở 200 byte (inventory từ chối dài hơn); giá trị cắt xong mà rỗng (tên toàn dấu chấm/gạch) bị bỏ và đếm `value_empty`, không vào hàng đợi. Không chứa ký tự điều khiển C0/C1, ký tự đảo chiều bidi, dấu phân cách dòng/đoạn, và mọi ký tự định dạng vô hình (Unicode Cf: zero-width, joiner, BOM, dấu gạch nối mềm, tag). **Hãng từ bảng OUI** đi qua cùng kiểm tra `printable()` trước khi vào hàng đợi (bảng cũng được `make oui` làm sạch; `TestEveryVendorIsCleanText`).
- **INV-4**: Gói là dữ liệu không tin cậy (SYS-6): parser DHCP/mDNS/SSDP/LLDP/ARP/DNS/TLS fail-closed, giới hạn kích thước; gói méo bị bỏ và đếm, không panic. Mỗi parser có một `Fuzz*` (ARP, DHCP, DNS/mDNS, SSDP, LLDP, TLS SNI, HTTP Host, đọc pcap, cả đường ống); chạy cục bộ ≥ 30 s mỗi cái, CI 60 s (chưa nối CI). Bộ đếm gói bỏ theo lý do (`malformed_*`, `excluded`, …).
- **INV-5**: Mỗi quan sát ghi `source=passive` với `confidence ∈ [0,1]` theo giao thức (hostname từ DHCP/mDNS, vendor từ OUI, model từ SSDP…), gửi qua `inventory.RecordObservation`; không bao giờ ghi trực tiếp `inv_*`.
- **INV-6**: MAC mới ⇒ tài sản `approved=false` (S-INV-3). Quan sát về chính hộp không tạo tài sản trùng với thiết bị "This box".
- **INV-7**: Bộ lọc loại trừ (dải, máy, cổng; D-56) áp trước khi trích; lưu lượng bị loại không để lại hàng nào. Áp cả cho địa chỉ nằm trong DHCP (`ciaddr`, `yiaddr`, option 50). **Khoảng hở đã biết**: DHCP DISCOVER/REQUEST không có `ciaddr` và option 50 thì không có địa chỉ nào để áp luật loại trừ; MAC (đã khớp MAC nguồn Ethernet) và hostname (option 12) vẫn được ghi, vì không có gì để loại trừ theo địa chỉ. Muốn loại một máy khỏi mọi dấu vết, dùng lọc theo cổng/lưu lượng trên SPAN, không phải luật IP. Mảnh IP không phải mảnh đầu không có cổng: có luật cổng thì bỏ qua (fail closed, đếm `fragment_skipped`). **Giới hạn**: LLDP không có địa chỉ IP nên luật IP/dải/cổng không áp được cho LLDP (mô hình bộ lọc chưa có MAC).
- **INV-8**: Sensor chỉ gọi ra server (mTLS khi tách), lô idempotent theo `seq`; server không bao giờ gọi vào sensor; ở chế độ `vedette all` gọi trong process (ARCHITECTURE §3).
- **INV-9**: `PATCH /inventory/sensors/{id}`: `interface` phải ∈ `Sensor.interfaces` (400 `bad_interface`), `span` boolean; card đánh dấu SPAN không có IP. Cảnh báo "không thấy lưu lượng nhân bản" khi chỉ thấy MAC của chính hộp.
- **INV-10**: Fingerbank (tuỳ chọn): tắt mặc định, khoá BYOK, mọi lần gọi nằm trong PRIVACY.md. Chưa làm; bảng OUI nhúng sẵn (D-83) không phải Fingerbank và không gọi ra ngoài.

## Thực hiện (WP-11)
- **Nguồn gói**: `Source{Next, Close}` không có hàm ghi/gửi. `FileSource` đọc pcap/pcapng (thuần Go, dev macOS và mọi test); `OpenLive` (`afpacket_linux.go`) là socket AF_PACKET chỉ nhận, promiscuous (bộ lọc nhận của card, không phát), chỉ cần CAP_NET_RAW. Nơi khác Linux: `ErrNoLiveCapture`.
- **Giới hạn chống ngập (SYS-6)**, `book.go`. Mọi thao tác của `deviceBook` là O(1) dưới khoá, không quét map trên đường nóng (chạy trong `Engine.Handle`, goroutine bắt gói). Sổ thuộc `Service`, sống qua mọi lần dựng lại Engine (đổi cài đặt, mở lại card sau lỗi); nằm trong bộ nhớ nên khởi động lại tiến trình thì rỗng (nạp từ kho cần giao diện mới trong `core/observe`, `.ai/deferred/feat-sensor-passive.md`).
  - **Khung đầu tiên**: vòng FIFO dung lượng cố định **20.000 ô** + map MAC→ô. Chèn vào vòng đầy thì **đẩy khung đầu tiên cũ nhất ra, không bao giờ từ chối**. Một MAC chỉ là "mới" khi nghe lại ở khung thứ hai cách khung đầu **≥ 2 giây** mà khung đầu còn trong vòng (MAC ngẫu nhiên chỉ một khung thì không tạo gì; đếm `new_macs_unconfirmed`; mốc thời gian lùi không tính là khung thứ hai). **TTL của khung đầu: 2 giờ** (thiết bị nói theo loạt cách nhau hàng chục phút, như SSDP NOTIFY max-age 1800, DHCP gia hạn, mDNS announce, vẫn được xác nhận). **Cận cho thiết bị thật**: một thiết bị thật được xác nhận miễn là giữa hai khung của nó (cách nhau tối đa 2 giờ) đến **ít hơn 20.000 MAC mới khác**; kẻ ngập cần > 20.000 MAC khác nhau giữa hai khung của mỗi thiết bị thật để chặn nó, và vẫn không tạo được thiết bị nào (xem hạn mức bên dưới).
  - **Thiết bị đã báo**: LRU (`container/list` + map) tối đa **50.000**; `admit` đưa mục lên đầu, đầy thì bỏ mục **lâu không thấy nhất**. Thiết bị bị bỏ mà quay lại là thiết bị mới (luật hai khung + hạn mức). Thiết bị đã báo luôn qua, kể cả khi hai hạn mức đã cạn và vòng đã đầy.
  - **Hạn mức MAC mới**: **60 mỗi phút và 200 mỗi giờ** (cửa sổ mở từ lần dùng đầu, chỉ thời gian đi tới mới đặt lại; mốc lùi không đặt lại); quá thì chỉ đếm `new_macs_dropped`. Cơn ngập chặn được thiết bị thật mới nhiều nhất đến hết giờ đó. GUI chưa hiện "new-device budget exhausted" (cần story, `.ai/deferred/feat-sensor-passive.md`).
  - **Hạn mức giá trị theo MAC** (H3): với mỗi MAC đã báo và mỗi trường, tối đa **4 giá trị mới mỗi giờ**; lặp lại giá trị đã cho qua trong cửa sổ không phải giá trị mới; quá thì bỏ và đếm `values_dropped`. Giá trị lưu dạng băm có khoá (8 byte), nên 50.000 thiết bị x 6 trường vẫn cỡ vài MB. Lớp thứ hai nằm ở inventory: mỗi (thiết bị, trường, nguồn) giữ tối đa 32 dòng `inv_observation`, `Record` xoá dòng cũ trong cùng giao dịch (inventory INV-16), bảo vệ cả khi nguồn là cảm biến khác.
  - **Hãng (vendor) còn nợ**: cờ "còn nợ hãng" nằm trong sổ cùng mục thiết bị: đặt khi thiết bị được báo lần đầu, xoá khi dòng hãng đã tới inventory, bị inventory từ chối hẳn, hoặc MAC không có hãng. Lỗi bắt gói giữa chừng hay lần xả cuối thất bại không làm mất hãng: khung kế tiếp của MAC đó, kể cả qua Engine mới, xếp lại dòng hãng.
  - Bộ đếm `new_macs_unconfirmed`, `new_macs_dropped`, `values_dropped` nằm trong bộ đếm gói bỏ. IP không phải unicast (broadcast, multicast, loopback, 0.0.0.0/8, 240.0.0.0/4) không bao giờ tới sink (giữ quan sát, bỏ IP); DHCP: `chaddr` của client phải bằng MAC nguồn Ethernet, ACK phải gửi tới MAC đó hoặc broadcast; `other_macs` chỉ đếm khung unicast giữa hai máy không phải hộp (phản hồi cho hộp và broadcast không tính, INV-9). Bộ đếm gói bỏ được ghi INFO định kỳ (5 phút, chỉ khi đổi); `contract.ts` chưa có trường để hiện.
- **Thang tin cậy** (INV-5, `engine.go`): MAC↔IP từ ARP/DHCP ACK/LLDP 0.9 · tên LLDP 0.7 · tên DHCP opt 12 và tên mDNS (bản ghi A đúng IP nguồn) 0.6 · loại từ LLDP capabilities 0.6 · model từ SSDP SERVER, mô tả LLDP, TXT mDNS `model`/`md` 0.5 · loại từ dịch vụ mDNS máy in / SSDP InternetGatewayDevice 0.5 · dịch vụ mDNS iot 0.3. hãng từ bảng OUI của IEEE (`content/oui`, D-83) 0.4, một lần cho mỗi MAC mới (còn nợ đến khi tới inventory, xem trên); MAC quản trị cục bộ (ngẫu nhiên) và MAC nhóm không có hãng.
- **Trích SPAN** (`MetaItem`, kiểu đóng): DNS (tên + qtype), TLS SNI, HTTP Host (bỏ cổng), luồng IPv4 5-tuple + đếm (cộng dồn 60 s). Bật theo `Extract`; hộp tự thân (MAC/IP của mọi card) không tạo tài sản và không tạo metadata, kể cả lưu lượng gửi tới hộp (INV-6).
- **Giới hạn**: mỗi lần xả tối đa 5000 quan sát, 20000 metadata, 20000 luồng; tràn thì đếm, không âm thầm. Lô ≤ 500 phần tử. Quan sát trùng chỉ gửi lại sau 15 phút (D-80).
- **Vòng bắt gói** chạy như job `capture` của `core/jobs`: chỉ khi module bật, tắt thì dừng ngay và không xả lô cuối. `SetInterface` đánh thức vòng để đổi card ngay.
- **API**: chỉ `GET /inventory/sensors`. `PATCH /inventory/sensors/{id}` chưa có trong `contract.ts`; luật INV-9 nằm ở `Service.SetInterface` (D-80 (5)). Lỗi `ErrBadInterface` → `bad_interface` khi route được nối.
- **Verdict SPAN**: `off` (SPAN tắt), `no_link` (card mất cáp), `no_traffic` (không gói trong 30 s hoặc không bắt gói), `own_only` (có gói nhưng không MAC nào khác hộp trong 5 phút), `ok`.

## Preconditions / Postconditions
- **PRE-1** (`Run(ctx)`, job `capture` của `core/jobs`; card do `SetInterface` chọn): card tồn tại, có `CAP_NET_RAW`. **POST-1**: đang bắt gói; `Sensor.status=online`, `last_seen` cập nhật theo nhịp tim (30 s). Mở card lỗi thì thử lại với quãng nghỉ 5 s, 10 s … tối đa 10 phút; một phiên đã nhận được khung rồi mới lỗi thì quãng nghỉ bắt đầu lại từ 5 s.
- **PRE-2** (`SetInterface(id, iface, span)`): `admin`. **POST-2**: bắt gói chuyển sang card mới trong cùng yêu cầu; `core_audit` ghi.
- **PRE-3** (`SubmitBatch(sensorID, seq, obs[])`): `seq` tăng dần; mọi quan sát có `source=passive`. Một dãy `seq` cho mỗi cảm biến chung cho lô quan sát và lô metadata (như sensor-protocol §5.2: một dãy mỗi (sensor, epoch)); `sp_seq` giữ số cao nhất. Inventory từ chối một mục ở biên (`observe.ErrRejected{Index}`, bọc `ErrInvalid`) thì vòng bắt gói bỏ đúng mục đó (đếm `observation_rejected`, mục bị từ chối vẫn bị bộ lọc lặp giữ 15 phút nên không gửi lại ngay) rồi gửi phần còn lại: một mục xấu không làm mù cả lô (sensor-protocol §5.5), và không có một giao dịch ghi cho mỗi mục. Lỗi khác (kho bận, I/O) không nói gì về các mục: cả lô quay lại hàng đợi của Engine và được gửi lại nguyên lô sau quãng nghỉ gấp đôi mỗi lần lỗi (tối đa 1 phút); lần xả cuối (hết bản ghi, đổi cài đặt) chỉ thử một lần rồi quên và đếm `observation_failed`. Lô lỗi 3 lần liên tiếp thì được chia đôi và thử từng nửa (tìm nhị phân); mục đứng riêng mà vẫn làm lô lỗi trong khi kho vẫn nhận ghi thì bị bỏ và đếm `observation_failed`, hàng đợi không bao giờ bị chặn mãi. Xả bị ngắt do tắt (ctx huỷ) không phải lỗi của kho, không làm tăng bộ đếm lỗi hay quãng nghỉ. `ensureSensor` chạy một lần mỗi lần `deliver`, không phải mỗi lần thử lại. Lô đã được inventory nhận không bao giờ ghi lại lần hai, kể cả khi lưu số lô lỗi (`SubmitBatch` trả `applied=true` cùng lỗi). **POST-3**: gửi lại cùng `seq` không tạo quan sát thứ hai.
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
