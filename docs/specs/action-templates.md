# Gói hành động theo hãng (action packs)

> **D-58 (2026-11-09): đây là thư viện MẪU hành động ở dạng dữ liệu, không phải code.** Lõi Vedette chỉ có các kiểu kết nối chung (HTTP API, SSH/CLI, NETCONF/RESTCONF, nền tảng tự động hoá như Ansible AWX/n8n, MCP, danh sách chặn). Mỗi mục dưới đây là một template ví dụ phát hành kèm bản cập nhật; khách sửa/thêm được, AI soạn được cho thiết bị khác rồi người duyệt. Tên hãng chỉ là ví dụ.


Trạng thái: bản nháp M2-0, viết 2026-11-09. Căn cứ: D-41, D-44, D-46, D-47, D-51 trong `docs/DECISIONS.md`; danh mục hiện tại của GUI ở `web/src/features/response/data.ts`, `logic.ts`, `CatalogEditor.tsx`. Danh sách chặn cho firewall kéo: `docs/specs/blocklist-format.md` (spec riêng).

Tài liệu này là hợp đồng của backend cho module `response`: mỗi hành động gồm lệnh/API chính xác, tham số có kiểu, hoàn tác, kiểm lại, quyền tối thiểu, rủi ro. Thay đổi GUI nêu ở mục 12 là việc của kien duyệt (quy tắc gui-first), không tự sửa.

## 0. Cách đọc nhãn xác minh

Mỗi lệnh, đường dẫn API, trường JSON thuộc một trong hai loại:

- **[xác minh]**: đã đọc trong tài liệu chính thức của hãng (URL ghi ngay dưới mục). Nếu chỉ thấy qua trang không chính thức của hãng (cộng đồng Fortinet, wrapper) thì ghi rõ "nguồn cộng đồng".
- **chưa xác minh**: viết từ kiến thức chung hoặc nguồn không chính thức, chưa tìm thấy trong tài liệu chính thức khi soạn. **Không đưa vào mã sản xuất** trước khi chạy thử trên thiết bị thật/lab và đổi nhãn thành [xác minh] kèm URL hoặc "đã thử trên <model, phiên bản> ngày <ngày>".

Hai trang tài liệu Fortinet rất dài (hàng trăm nghìn ký tự) nên công cụ tải trang chỉ trả về menu; các điểm lấy từ đó được ghi nguồn là kết quả tìm kiếm tới trang `docs.fortinet.com`. Tham chiếu REST API đầy đủ của FortiOS nằm sau đăng nhập Fortinet Developer Network, nên các đường dẫn `cmdb`/`monitor` của FortiGate mặc định ở mức chưa xác minh cho tới khi thử trên máy.

## 1. Quy ước chung cho mọi gói

### 1.1 Bản ghi một hành động (schema logic)

| Trường | Ý nghĩa |
|---|---|
| `id` | định danh ổn định, chữ thường, ví dụ `fgt_addrgrp_add` |
| `pack`, `name`, `description` | gói, tên và mô tả bằng lời người thường (D-47) |
| `connection` | loại kết nối cần (fortigate-rest, mikrotik-rest, ssh-cisco...) |
| `params` | danh sách tham số có kiểu, xem 1.2 |
| `run`, `rollback`, `verify` | mẫu lệnh/API cho từng bước |
| `precheck` | bước đọc trạng thái trước khi ghi (để quyết định idempotent và để lưu giá trị cũ cho hoàn tác) |
| `ttl` | thời hạn tự gỡ, xem 1.4 |
| `risk` | `low`, `medium`, `high` (1.5) |
| `ai_may_propose` | cờ D-51 |
| `min_version` | khoảng phiên bản hỗ trợ |

### 1.2 Tham số có kiểu và cách escape

Dữ liệu tác nhân (IP nguồn, tên miền, tên thiết bị, SNI, nội dung log) do kẻ tấn công kiểm soát. Hai lớp bắt buộc: (1) kiểm kiểu, từ chối nếu sai; (2) escape theo đường truyền khi đặt vào mẫu. Giá trị không qua lớp 1 thì không bao giờ tới lớp 2.

| Kiểu | Kiểm (lớp 1) | Ghi chú theo đường truyền (lớp 2) |
|---|---|---|
| `ip` | `netip.ParseAddr`, bỏ zone, `Unmap()`, dạng chuẩn do Go in ra; từ chối unspecified, loopback, multicast, link-local, và mọi IP nằm trong danh sách không bao giờ đụng | đã chuẩn hoá nên chỉ gồm `[0-9a-f.:]`; vẫn escape theo JSON/URL/CLI bên dưới |
| `cidr` | `netip.ParsePrefix` rồi `Masked()`; chặn prefix rộng hơn trần cấu hình (mặc định IPv4 `/16`, IPv6 `/48`) và mọi dải giao với danh sách không bao giờ đụng | dạng mask đặt theo hãng (FortiGate `a.b.c.d m.m.m.m`, Cisco wildcard); backend tự đổi, không để người dùng gõ |
| `domain` | chữ thường, đổi punycode, regex nhãn RFC 1123 (`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`), tối đa 253 ký tự, không wildcard, không IP | nếu hành động dùng regex (Pi-hole `regex`): chèn `regexp.QuoteMeta` rồi mới ghép; **bản đầu không hỗ trợ regex**, chỉ `exact` |
| `port` | số nguyên 1 đến 65535 | số, không escape |
| `mac` | 6 byte, chuẩn hoá `aa:bb:cc:dd:ee:ff` | đổi định dạng theo hãng ở backend (Cisco `aabb.ccdd.eeff`) |
| `vlan` | số nguyên 1 đến 4094, loại VLAN quản trị và VLAN khai báo trong danh sách không đụng | số, không escape |
| `interface` | regex theo hãng (xem từng gói) **và** phải có trong ảnh chụp danh sách cổng đọc từ thiết bị (`precheck`), **và** không nằm trong danh sách không đụng (uplink, cổng nối hộp Vedette) | chỉ ký tự `[A-Za-z0-9/.:-]` |
| `name` | `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$` (security.md) | an toàn trong dấu nháy kép của CLI FortiOS và RouterOS |
| `id` (đề xuất mới) | số nguyên 1 đến 2^31-1; dùng cho `policyid` của FortiGate | số, không escape. Hiện GUI chưa có kiểu này, xem mục 12 |

Escape theo đường truyền (khớp `escapeFor` trong `logic.ts`, chặt hơn ở chỗ ghi rõ):

- **JSON**: không ghép chuỗi vào văn bản JSON. Phân tích mẫu thành cây JSON, gán giá trị vào nút chuỗi hoặc mảng, rồi serialize (Go `encoding/json`). Không đổi được cấu trúc, không thêm trường.
- **Đường dẫn URL**: `url.PathEscape` cho từng đoạn; cấm tham số làm cả đoạn có `/`. Không đặt tham số vào scheme, host, port, userinfo.
- **Query**: `url.Values.Encode`.
- **Header**: không cho tham số vào tên header; giá trị header từ chối `\r`, `\n`.
- **CLI qua SSH**: mỗi dòng lệnh là một lần gửi riêng; tham số đã qua lớp 1 nên không chứa khoảng trắng, `"`, `\`, `;`, `|`, `?`, `$`, `[`, `]`, ký tự điều khiển (`?` mở trợ giúp trong CLI FortiOS/Cisco; `[` `]` `$` có nghĩa trong script RouterOS). Giá trị cuối cùng phải khớp từng dòng của mẫu đã lưu: sau khi thay, số dòng bằng số dòng mẫu.

### 1.3 Dấu vết sở hữu (chống gỡ nhầm của quản trị viên)

Mọi đối tượng Vedette tạo trên thiết bị phải có dấu: tiền tố tên `vedette-` hoặc `comment`/`description` = `vedette:<request_id>`. Hoàn tác chỉ gỡ đối tượng có dấu này **và** khớp request. Nếu cùng IP đã tồn tại do quản trị viên tạo (không có dấu): hành động báo "đã có, không phải của Vedette", không ghi, không hoàn tác.

### 1.4 TTL

- Ưu tiên TTL **của thiết bị** (còn chạy khi hộp Vedette tắt): MikroTik `timeout=`, FortiGate banned `expiry`, danh sách chặn kéo (mục vào/ra theo `expires_at`).
- Thiết bị không có TTL gốc (FortiGate address group, pfSense/OPNsense alias qua API, Cisco/Aruba ACL, Pi-hole, AdGuard): Vedette lưu `expires_at` và chạy hoàn tác khi đến hạn. Hộp tắt lúc đến hạn: chạy bù khi khởi động lại, hiện "quá hạn" trên màn hình Phản ứng. Hoàn tác tự động tới hạn cũng ghi kiểm toán và vẫn cần mục chặn nằm trong danh sách "hoàn tác được không cần duyệt" (D-51: hoàn tác không làm thêm hại).
- TTL tối đa theo rủi ro: low 30 ngày, medium 7 ngày, high 24 giờ. Không TTL chỉ cho hành động có cờ `permanent` do quản trị viên đặt tay.

### 1.5 Mức rủi ro

- **low**: thêm mục vào danh sách chặn ngoài LAN (IP/domain đích), thông báo; gỡ lại không ảnh hưởng gì khác.
- **medium**: chặn một IP **nguồn** trong LAN hoặc trên cổng vào; tắt/bật cổng switch; thêm dòng ACL ở switch.
- **high**: chuyển VLAN cách ly; tắt VIP/chính sách đang phục vụ người dùng thật; mọi thứ cắt dịch vụ. Cần 2 người duyệt (D-51).

Rủi ro còn tăng bậc khi nhiều mục tiêu (rule của D-51) hoặc mục tiêu là thiết bị cùng nhóm dịch vụ.

### 1.6 Đọc lại sau khi chạy (verify)

Mỗi hành động có một `verify` chỉ-đọc, chạy sau `run` và sau `rollback`, so với kỳ vọng cụ thể (ví dụ "mục có trong danh sách", "trạng thái là disable"). Sai khác thì: đánh dấu hành động `chưa chắc`, không tự thử lại quá 1 lần, thông báo người duyệt, dừng chuỗi. Mã trả về HTTP 2xx hoặc dòng lệnh không lỗi **không** được coi là xác minh (ships-as-code).

### 1.7 Đường kéo ưu tiên

Chặn IP/domain đích: ưu tiên hành động `blocklist_add` rồi để firewall kéo (D-44), vì không cần quyền ghi lên firewall. Gói bên dưới là đường đẩy, dùng khi (a) cần chặn ngay (chu kỳ kéo chậm), (b) thiết bị không kéo được, (c) cần hành động không phải danh sách (VIP, cổng, VLAN). Chu kỳ kéo khác nhau rõ rệt: FortiGate 1 đến 43200 phút [xác minh], OPNsense có "Refresh frequency" [xác minh nhưng đơn vị chưa rõ], pfSense URL Table chưa xác minh (có thể tính theo ngày), MikroTik tự viết lịch `fetch`.

---

## 2. FortiGate (FortiOS REST API)

**Phiên bản**: mục tiêu FortiOS 7.2 đến 7.6; 7.0 chỉ cố gắng. Lệnh CLI `diagnose user banned-ip` có từ 7.2; bản 6.0/7.0 dùng `diagnose user quarantine list` [xác minh, nguồn cộng đồng Fortinet]. Đã thấy hướng dẫn quản trị 7.2.7, 7.4.6, 7.6.5 cho trang REST API.

**Nguồn**:
- Dùng API, token Bearer, quản trị viên REST API: https://docs.fortinet.com/document/fortigate/7.4.6/administration-guide/940602 và https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/399023
- Threat feed (External Block List): https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/891236/external-blocklist-threat-feed
- CLI `config system external-resource`: https://docs.fortinet.com/document/fortigate/7.4.0/cli-reference/72620
- Danh sách banned IP: https://community.fortinet.com/fortigate-3/technical-tip-how-to-list-or-remove-a-banned-ip-from-the-list-on-a-fortigate-92714 (cộng đồng Fortinet, không phải tài liệu chính thức)
- Tham chiếu REST API đầy đủ: Fortinet Developer Network, cần đăng nhập (chưa đọc được)

### 2.1 Kết nối và quyền tối thiểu

- Xác thực: token API gửi bằng header `Authorization: Bearer <token>` [xác minh]. Token **chỉ hiện một lần** khi tạo, FortiGate không cung cấp lại [xác minh]. Không dùng token trong URL (từ 7.6 phải bật cài đặt toàn cục mới cho phép) [xác minh]. Chỉ quản trị viên hồ sơ `super_admin` mới tạo được quản trị viên REST API [xác minh].
- Trusted hosts: bắt buộc chỉ IP hộp Vedette; `0.0.0.0/0` không được phép [xác minh]. FortiGate kiểm trusted host của quản trị viên thường trước rồi mới tới trusted host của api-user (nguồn cộng đồng).
- Hồ sơ quản trị (`accprofile`) chỉ cấp những gì cần. Đề xuất tối thiểu (chưa xác minh tên trường; xác nhận trong CLI của đúng phiên bản):

```
config system accprofile
    edit "vedette-response"
        set fwgrp custom
        config fwgrp-permission
            set address read-write
            set policy read-write
        end
        set authgrp read-write
    next
end
config system api-user
    edit "vedette"
        set accprofile "vedette-response"
        config trusted-hosts
            edit 1
                set ipv4-trusted-host <ip-hop-vedette>/32
            next
        end
    next
end
execute api-user generate-key vedette
```

  Ghi chú: `authgrp` chỉ cần cho `user/banned`; bỏ nếu không dùng hành động ban. `policy` chỉ cần cho tắt/bật chính sách và VIP. Hộp Vedette chỉ yêu cầu đúng quyền của hành động khách bật (giao diện hiện "quyền cần cấp" theo hành động đã bật). Tuyệt đối không dùng hồ sơ `super_admin` và không cấp `sysgrp` (cấu hình hệ thống) cho Vedette.
- Khoá sai nhiều lần có thể khoá quản trị viên API một thời gian (tiêu đề bài cộng đồng "administrative lockout durations for FortiGate API users", chưa đọc nội dung): hộp không thử lại token sai, báo lỗi xác thực ngay.
- VDOM: mọi lệnh REST thêm `?vdom=<name>` khi dùng VDOM (chưa xác minh). Lưu `vdom` trong kết nối.
- Không có bước commit: REST `cmdb` có hiệu lực ngay. CLI qua SSH cũng có hiệu lực khi `next` hoặc `end` (chưa xác minh). HA: thay đổi trên máy chủ đạo được đồng bộ sang máy phụ (chưa xác minh); FortiGate do FortiManager quản lý có thể ghi đè đối tượng cục bộ khi cài lại chính sách (chưa xác minh), cần lab nếu khách dùng FortiManager.

### 2.2 `fgt_addrgrp_add` / `fgt_addrgrp_remove`: thêm/gỡ địa chỉ trong nhóm địa chỉ

- Mô tả: "Thêm IP hoặc dải vào nhóm địa chỉ `Vedette-Blocked`; chính sách chặn có sẵn dùng nhóm đó sẽ cắt IP đó". Chính sách chặn khách tạo một lần (hộp có thể in sẵn đoạn CLI hướng dẫn, không tự tạo).
- Tham số: `ip` hoặc `cidr` (một trong hai, kiểu cố định theo mẫu); `name` của nhóm mặc định `Vedette-Blocked` cấu hình ở kết nối, không lấy từ tác nhân.
- Tên đối tượng địa chỉ: `vedette-<ip>` với IPv4 (dấu `.` hợp lệ); CIDR: `vedette-<ip>_<len>`. Chiều dài tên tối đa chưa xác minh (nghĩ 79 ký tự). Tên sinh bởi backend từ giá trị đã kiểm, không từ tác nhân.
- Truyền tải REST (đường dẫn chưa xác minh, theo quy ước `cmdb` của FortiOS):
  1. `precheck`: `GET /api/v2/cmdb/firewall/address/vedette-{ip}` và `GET /api/v2/cmdb/firewall/addrgrp/Vedette-Blocked`. Nếu địa chỉ đã là thành viên: `đã có`, không ghi.
  2. `POST /api/v2/cmdb/firewall/address` body `{"name":"vedette-{ip}","type":"ipmask","subnet":"{ip} 255.255.255.255","comment":"vedette:<request_id>"}`
  3. `POST /api/v2/cmdb/firewall/addrgrp/Vedette-Blocked/member` body `{"name":"vedette-{ip}"}`
- CLI tương đương (chưa xác minh):

```
config firewall address
    edit "vedette-{ip}"
        set subnet {ip} 255.255.255.255
        set comment "vedette:<request_id>"
    next
end
config firewall addrgrp
    edit "Vedette-Blocked"
        append member "vedette-{ip}"
    next
end
```

- Hoàn tác (đúng thứ tự: gỡ khỏi nhóm trước, xoá đối tượng sau, vì đối tượng đang được nhóm tham chiếu thì không xoá được):
  1. `DELETE /api/v2/cmdb/firewall/addrgrp/Vedette-Blocked/member/vedette-{ip}`
  2. `DELETE /api/v2/cmdb/firewall/address/vedette-{ip}`
  CLI: `config firewall addrgrp` / `edit "Vedette-Blocked"` / `unselect member "vedette-{ip}"` / `next` / `end`, rồi `config firewall address` / `delete "vedette-{ip}"` / `end`.
- Kiểm lại: `GET /api/v2/cmdb/firewall/addrgrp/Vedette-Blocked`; kỳ vọng `member[]` chứa/không chứa `vedette-{ip}`. CLI: `show firewall addrgrp Vedette-Blocked`.
- Rủi ro: `medium` nếu `ip` là nguồn trong LAN; `low` nếu là IP ngoài. Phân loại theo cờ "nguồn/đích" của trigger.
- Điểm vấp:
  - **Nhóm địa chỉ FortiOS cần ít nhất một thành viên** (chưa xác minh trong tài liệu, nhưng là hành vi phổ biến): gỡ thành viên cuối sẽ lỗi. Giải pháp: nhóm luôn có thành viên neo `vedette-anchor` = `192.0.2.1/32` (TEST-NET-1, địa chỉ tài liệu, không bao giờ định tuyến). Hộp dựng neo ở bước hướng dẫn một lần và không bao giờ gỡ nó.
  - Chính sách chặn phải nằm **trên** các chính sách cho phép; hộp chỉ kiểm sau cùng (`GET /api/v2/cmdb/firewall/policy`, chưa xác minh) và cảnh báo nếu thứ tự sai, không tự đổi.
  - Đối tượng địa chỉ có trần số lượng tuỳ model; hộp đặt `max_per_hour` thấp và đếm thành viên nhóm, từ chối khi quá 80% trần cấu hình.
  - Không có TTL gốc: Vedette tự hoàn tác (1.4).
  - Idempotent: hai lần `run` cho cùng IP không tạo bản sao nhờ `precheck`; POST trùng tên trả lỗi nên không được coi là thành công im lặng.
- Phiên bản: REST API token từ FortiOS 5.6 trở lên (chưa xác minh); mục tiêu 7.2 đến 7.6.

### 2.3 `fgt_ban_ip` / `fgt_unban_ip`: cấm (ban) một IP

- Mô tả: "Đưa IP vào danh sách cấm của FortiGate: mọi phiên của IP bị ngắt và phiên mới bị từ chối đến khi hết hạn hoặc bị gỡ". Không cần chính sách riêng và có TTL gốc, nên là cách chặn nguồn trong LAN gọn nhất.
- Tham số: `ip`; `ttl` giây (bước quy ra giây bởi backend, không phải người dùng gõ); `ttl` nên khớp TTL của hành động.
- REST (chưa xác minh đường dẫn và trường):
  - `POST /api/v2/monitor/user/banned/add_users` body `{"ip_addresses":["{ip}"],"expiry":<giây>}`
  - Căn cứ: mô-đun Ansible `fortios_monitor` liệt kê hành động `add_users.user.banned`, `clear_users.user.banned`, `clear_all.user.banned`, `add_users` nhận mảng IP, hỗ trợ IPv4 và IPv6 [xác minh qua tài liệu Ansible, không phải tài liệu Fortinet]: https://docs.ansible.com/ansible/latest/collections/fortinet/fortios/fortios_monitor_module.html . Trường `expiry` suy ra từ wrapper bên thứ ba (hfortix), **chưa xác minh**.
- CLI (nguồn cộng đồng Fortinet cho `list`, `stat`, `clear`, `delete`; **lệnh `add` chưa xác minh**, bài đó nói rõ không đề cập lệnh thêm tay):
  - Xem: `diagnose user banned-ip list`; đếm: `diagnose user banned-ip stat`
  - Gỡ một mục: `diagnose user banned-ip delete src4 {ip}` (IPv6: `src6`) [xác minh, cộng đồng]
  - Thêm: `diagnose user banned-ip add src4 {ip}` là lệnh GUI hiện đang dùng, **chưa xác minh**; hỏi `diagnose user banned-ip ?` trên máy thật để lấy cú pháp có `expiry`.
- Hoàn tác: `POST /api/v2/monitor/user/banned/clear_users` body `{"ip_addresses":["{ip}"]}` (chưa xác minh), CLI `diagnose user banned-ip delete src4 {ip}`.
- Kiểm lại: `GET /api/v2/monitor/user/banned` (chưa xác minh) kỳ vọng IP có/không trong `results`; CLI `diagnose user banned-ip list`.
- Rủi ro: `medium` (cắt hoàn toàn một máy trong LAN); đích ngoài LAN không dùng được cách này.
- Điểm vấp: danh sách cấm có thể **không giữ qua khởi động lại** trừ khi `config firewall global` / `set banned-ip-persistency {disabled|permanent-only|all}` [xác minh, cộng đồng]. Với `ban` có TTL ngắn thì chấp nhận mất khi khởi động lại; hộp phải đọc lại và coi mục đã mất là "đã gỡ", không báo lỗi. Cấm không thay thế được "không bao giờ đụng": hộp tự chặn IP trong danh sách không đụng trước khi gọi.
- Phiên bản: lệnh CLI 7.2 trở lên; 6.0/7.0 dùng `diagnose user quarantine` (khác cú pháp, không hỗ trợ ở M2).

### 2.4 `fgt_vip_disable` / `fgt_vip_enable`: tắt/bật một VIP (chuyển tiếp cổng/NAT)

- Mô tả: "Tắt ánh xạ VIP đưa dịch vụ ra Internet; người dùng ngoài mất truy cập tới khi bật lại; mạng trong văn phòng không đổi".
- Tham số: `name` (tên VIP, phải có trong danh sách VIP đọc được ở `precheck`).
- **Cảnh báo**: trường `status` trên `firewall vip` **chưa xác minh**; GUI hiện giả định `set status disable`. Nếu trên máy thật không có, dùng cách thay thế dưới đây (tắt chính sách, 2.5).
- REST (chưa xác minh): `PUT /api/v2/cmdb/firewall/vip/{name}` body `{"status":"disable"}`; hoàn tác `{"status":"enable"}`. Lưu trạng thái cũ ở `precheck` (`GET /api/v2/cmdb/firewall/vip/{name}`); nếu VIP đã `disable` từ trước, hành động không hoàn tác thành `enable`.
- CLI (chưa xác minh): `config firewall vip` / `edit "{name}"` / `set status disable` / `next` / `end`.
- Kiểm lại: `GET /api/v2/cmdb/firewall/vip/{name}` kỳ vọng `status`.
- Rủi ro: `high`. Điểm vấp: VIP đang được chính sách tham chiếu; tắt VIP không xoá phiên đang mở (có thể cần `diagnose sys session clear` bằng tay, hộp không làm).
- Phiên bản: mục tiêu 7.2 đến 7.6, chờ xác nhận lab.

### 2.5 `fgt_policy_disable` / `fgt_policy_enable`: tắt/bật một chính sách tường lửa

- Mô tả: "Tắt hẳn một chính sách firewall theo số chính sách; lưu lượng khớp chính sách đó rơi xuống chính sách kế tiếp".
- Tham số: `id` (policyid, kiểu số nguyên mới), danh sách policyid cho phép do quản trị viên khai báo cho hành động (hộp không cho chọn policyid ngoài danh sách đó).
- REST (chưa xác minh): `PUT /api/v2/cmdb/firewall/policy/{id}` body `{"status":"disable"}`; hoàn tác `{"status":"enable"}`.
- CLI (chưa xác minh): `config firewall policy` / `edit {id}` / `set status disable` / `next` / `end`.
- Kiểm lại: `GET /api/v2/cmdb/firewall/policy/{id}` kỳ vọng `status`.
- Rủi ro: `high` (tắt chính sách "cho phép" làm mất dịch vụ; tắt chính sách "từ chối" mở thêm lưu lượng). Hộp từ chối nếu chính sách có `action` = `deny` (đọc ở `precheck`): tắt chính sách chặn không bao giờ là hành động an toàn.
- Điểm vấp: `policyid` là số, không phải tên; số có thể đổi nếu quản trị viên xoá và tạo lại chính sách; lưu cả `name` của chính sách ở `precheck` và so khớp trước khi hoàn tác.

### 2.6 `fgt_ebl_setup`: kết nối External Block List (Threat Feed)

- Mô tả: "Tạo kết nối danh sách chặn ngoài trên FortiGate trỏ tới URL danh sách chặn của hộp Vedette; FortiGate tự kéo theo chu kỳ". Đây là đường ưu tiên của D-44.
- Khác các hành động trên: đây là **thiết lập một lần**, không gắn sự kiện. Cấu hình `system external-resource` thuộc nhóm quyền hệ thống (chưa xác minh); Vedette **không** xin quyền đó. Mặc định hộp **hiển thị đoạn CLI để quản trị viên dán**, không gọi API.
- Cú pháp [xác minh] (trang CLI FortiOS và bài cộng đồng Fortinet):

```
config system external-resource
    edit "Vedette-Blocklist"
        set type address
        set resource "https://<ip-hop>:<port>/blocklist/<token>/ip.txt"
        set refresh-rate 5
    next
end
```

  `refresh-rate` 1 đến 43200 phút, mặc định 5 [xác minh]. Loại feed trên FortiOS 7.4: IP address, domain name, MAC address (mới), malware hash, FortiGuard category [xác minh, từ mục lục tài liệu]. Định dạng tệp (một mục một dòng) và đường dẫn URL do `docs/specs/blocklist-format.md` quy định, không nhắc lại ở đây.
- Dùng trong chính sách: feed loại `address` đưa vào chính sách như đối tượng địa chỉ (chưa xác minh); dùng trong DNS filter qua `set external-ip-blocklist "<tên>"` [xác minh, bài cộng đồng].
- Tuỳ chọn REST nếu quản trị viên tự cấp token tạm: `POST /api/v2/cmdb/system/external-resource` (chưa xác minh). Khuyến nghị không làm.
- Hoàn tác: `config system external-resource` / `delete "Vedette-Blocklist"` / `end`.
- Kiểm lại: bước kiểm nằm ở phía hộp: hộp thấy **yêu cầu tải đầu tiên** từ IP firewall tới URL có token (ghi log truy cập) trong 2 chu kỳ `refresh-rate`. Không thấy thì báo "firewall chưa kéo". Trạng thái kéo trên firewall: `diagnose sys external-resource` kiểu lệnh chưa xác minh.
- Rủi ro: `low` cho hộp (không ghi vào firewall); `medium` cho firewall (chính sách chặn dựa trên feed). Token trong URL xem `blocklist-format.md` về xoay vòng; HTTPS với chứng chỉ của hộp phải được FortiGate tin (FortiGate kiểm chứng chỉ, tuỳ phiên bản, chưa xác minh).
- Điểm vấp: thiết bị không tới được địa chỉ hộp (NAT, VLAN quản trị) thì feed trống; chu kỳ kéo là độ trễ chặn tối thiểu.

---

## 3. MikroTik RouterOS (REST API v7 và CLI)

**Phiên bản**: REST có từ RouterOS v7.1beta4 [xác minh]; truy cập HTTP (không TLS) từ v7.9 [xác minh] (không dùng). Mục tiêu RouterOS 7.9 trở lên; v6 không có REST nên chỉ SSH/API cũ (ngoài phạm vi M2).

**Nguồn**:
- REST API: https://help.mikrotik.com/docs/spaces/ROS/pages/47579162/REST+API
- Address lists: https://help.mikrotik.com/docs/spaces/ROS/pages/130220135/Address-lists (trang trỏ sang https://manual.mikrotik.com/docs/ , bản đóng băng)
- Firewall matchers/actions: https://help.mikrotik.com/docs/spaces/ROS/pages/250708064/Common+Firewall+Matchers+and+Actions

### 3.1 Kết nối và quyền tối thiểu

- Xác thực: HTTP Basic với người dùng RouterOS [xác minh]; gốc đường dẫn `https://<router>/rest` qua dịch vụ `www-ssl` [xác minh]. Ánh xạ: `GET`=print, `PUT`=add (một bản ghi mỗi yêu cầu), `PATCH`=set, `DELETE`=remove theo ID, `POST`=mọi lệnh console [xác minh].
- Chứng chỉ: dùng chứng chỉ do quản trị viên nhập vào Vedette (CA hoặc ghim vân tay); không `-k`.
- Người dùng riêng `vedette` trong nhóm riêng, chỉ quyền cần (chưa xác minh tên chính sách; xác nhận bằng `/user group print` của đúng phiên bản):

```
/user group add name=vedette-response policy=read,write,rest-api,api comment="Vedette response"
/user add name=vedette group=vedette-response address=<ip-hop-vedette>/32 password=<mạnh> comment="Vedette response"
/ip service set www-ssl disabled=no address=<ip-hop-vedette>/32
```

  Không cấp `policy`, `ftp`, `sniff`, `sensitive`, `password`, `reboot`, `test`. Giới hạn `address=` ở người dùng và dịch vụ về IP hộp. Giả thuyết `rest-api` là tên chính sách riêng và `write` đủ để `address-list add` đều **chưa xác minh**.
- Firewall bắt buộc có trước, khách tạo một lần: một luật `drop` (input/forward, hoặc `raw` prerouting để tiết kiệm CPU) khớp `src-address-list=vedette-block` và/hoặc `dst-address-list=vedette-block`. Vedette không tạo luật này bằng REST (cần quyền `policy`/`write` rộng hơn).

### 3.2 `mt_addrlist_add`: thêm địa chỉ vào address-list kèm timeout

- Mô tả: "Thêm IP/dải vào danh sách địa chỉ `vedette-block` của router, router tự gỡ sau thời hạn".
- Tham số: `ip` hoặc `cidr` (RouterOS nhận `1.2.3.0/24` ở trường `address`); `ttl` đổi sang dạng RouterOS (`1d`, `1h30m`, `00:30:00`); tên danh sách `vedette-block` cố định ở kết nối. Không dùng `domain` ở bản đầu (RouterOS phân giải tên và gắn nhiều IP vào mục, TTL của tên có thể bị gỡ cùng lúc, chưa xác minh).
- REST: `PUT /rest/ip/firewall/address-list` body `{"list":"vedette-block","address":"{ip}","timeout":"<ttl>","comment":"vedette:<request_id>"}` [xác minh phương thức/đường dẫn; trường lấy từ ví dụ `PUT /rest/ip/address` của tài liệu; tên trường `list`, `address`, `timeout`, `comment` chưa xác minh trong trang REST nhưng trùng thuộc tính CLI]. Trả về đối tượng vừa tạo có `.id`, **lưu `.id` làm bằng chứng cho hoàn tác** [xác minh: PUT trả về đối tượng với `.id`].
- CLI: `/ip firewall address-list add list=vedette-block address={ip} timeout=<ttl> comment="vedette:<request_id>"`
- `precheck`: `GET /rest/ip/firewall/address-list?list=vedette-block&address={ip}` [xác minh kiểu lọc bằng tham số query, ví dụ `GET /rest/ip/address?network=...&dynamic=true` trong tài liệu]. Có sẵn thì bỏ qua và ghi "đã có".
- Hoàn tác: `DELETE /rest/ip/firewall/address-list/<id>` [xác minh `DELETE` theo ID; lặp lại trả `{"error":404,"message":"Not Found"}`, hoàn tác coi 404 là đã gỡ]. Không biết `id` (hộp khởi động lại): `GET` lọc như `precheck` để tìm `id` trước, chỉ gỡ mục có `comment` bắt đầu bằng `vedette:`. CLI: `/ip firewall address-list remove [find list=vedette-block address={ip} comment~"^vedette:"]` (chưa xác minh toán tử `~`).
- Kiểm lại: `GET /rest/ip/firewall/address-list?list=vedette-block&address={ip}` kỳ vọng có/không có mục.
- Rủi ro: `low` nếu IP ngoài LAN và luật chỉ dùng `dst-address-list`; `medium` nếu IP nguồn trong LAN và luật dùng `src-address-list`.
- Điểm vấp:
  - **Mục có `timeout` nằm trong RAM và mất khi router khởi động lại**; không `timeout` thì lưu vĩnh viễn [xác minh, wiki MikroTik: https://wiki.mikrotik.com/Address_list]. Với chặn tạm thì đây là điều mong muốn; đừng bỏ `timeout`.
  - Thêm trùng (cùng `list`+`address`) trên RouterOS thường báo lỗi "already have such entry" (chưa xác minh): `precheck` tránh va chạm, và lỗi này vẫn đi qua bước đọc lại chứ không bị bỏ qua.
  - Một yêu cầu `PUT` chỉ tạo một bản ghi [xác minh]; chuỗi nhiều IP là nhiều yêu cầu, nằm dưới giới hạn mục/giờ của quy tắc.
  - `address-list-timeout` của luật firewall có hành vi khác (mục động do luật tạo); Vedette không đụng tới.
- Quyền: xem 3.1. Phiên bản: 7.9 trở lên.

### 3.3 `mt_addrlist_remove`: gỡ địa chỉ

- Đây là hoàn tác của 3.2, và cũng là hành động độc lập cho "gỡ chặn". Mẫu REST/CLI như hoàn tác ở 3.2; `precheck` bắt buộc đọc `comment` (không gỡ mục của quản trị viên); `verify` như 3.2. Rủi ro `low`.

---

## 4. pfSense và OPNsense

Cả hai có đường **kéo** chính thức (URL Table). Đường đẩy khác nhau nhiều: OPNsense có REST API chính thức; pfSense **không** có REST API chính thức của Netgate.

### 4.1 OPNsense (REST API chính thức)

**Nguồn**:
- API firewall (alias, alias_util): https://docs.opnsense.org/development/api/core/firewall.html
- Cách dùng API, khoá/bí mật: https://docs.opnsense.org/development/how-tos/api.html
- Alias và loại External: https://docs.opnsense.org/manual/aliases.html

**Kết nối và quyền**
- Xác thực: HTTP Basic, khoá là tên người dùng, bí mật là mật khẩu; tạo ở quản lý người dùng, bí mật **tải về một lần** [xác minh]. Quyền của khoá = quyền người dùng sở hữu (tài liệu không nói cách tính chi tiết) [xác minh một phần].
- Người dùng riêng `vedette-api` chỉ thuộc nhóm có quyền trang cần cho alias (tên quyền chính xác chưa xác minh, thử bằng cách cấp tối thiểu rồi kiểm lỗi 403). Không cấp quyền quản trị toàn bộ.
- Chứng chỉ HTTPS hợp lệ cho môi trường thật; không bỏ kiểm chứng chỉ [xác minh khuyến nghị trong tài liệu].
- Khách tạo trước một alias loại **External (advanced)** tên `Vedette_Blocklist` và một luật chặn trên alias đó. Chỉ alias loại Host, Network, External mới nhận `alias_util/add` [xác minh]; loại External là loại tạo để chương trình bên ngoài đẩy mục [xác minh]. Vedette không tạo alias bằng REST (cần `alias/add_item` và `reconfigure`, quyền rộng hơn).

**`opn_alias_add` / `opn_alias_remove`**
- Mô tả: "Thêm/gỡ IP trong alias `Vedette_Blocklist` của OPNsense; luật chặn trên alias làm phần còn lại".
- Tham số: `ip` hoặc `cidr`; tên alias `name` cố định ở kết nối.
- REST [xác minh phương thức/đường dẫn từ tài liệu và trang alias]:
  - Thêm: `POST /api/firewall/alias_util/add/Vedette_Blocklist` body `{"address":"{ip}"}`
  - Gỡ: `POST /api/firewall/alias_util/delete/Vedette_Blocklist` body `{"address":"{ip}"}`
  - Danh sách: `GET /api/firewall/alias_util/list/Vedette_Blocklist`
  - Làm rỗng: `POST /api/firewall/alias_util/flush/Vedette_Blocklist` (không dùng; ngoài danh sách cho phép vì xoá cả mục của người khác)
  - Chưa xác minh: tên trường của mảng `address` khi thêm nhiều IP, và dạng phản hồi.
- `precheck`/`verify`: `GET /api/firewall/alias_util/list/Vedette_Blocklist` kỳ vọng IP có/không có trong mảng phản hồi.
- Rủi ro: `low` (IP ngoài) / `medium` (nguồn trong LAN).
- Điểm vấp:
  - **Mục thêm bằng API không được giữ qua khởi động lại; `flush` cũng không bền** [xác minh, trang aliases]. Chấp nhận với chặn tạm; hộp đồng bộ lại danh sách theo bảng yêu cầu đang mở sau khi phát hiện OPNsense khởi động lại (giữ `connection.last_seen_boot`, chưa xác minh cách đọc).
  - Cần xoá trạng thái (states) đã có nếu luật dùng theo dõi trạng thái, nếu không kết nối đang mở vẫn sống [xác minh, trang aliases]. Hộp **không** tự xoá states ở bản đầu; ghi trong kết quả "kết nối đang mở có thể còn".
  - Báo cáo diễn đàn về phiên bản cũ (19.1): thêm mục thứ ba làm mất mục cũ (kết quả tìm kiếm, nguồn diễn đàn); cần kiểm lại trên phiên bản đích bằng bài thử "thêm 3 mục rồi đọc lại" trước khi bật.
  - Không có TTL gốc: Vedette tự hoàn tác.
- Phiên bản: chưa xác minh phiên bản đầu tiên có `alias_util`; mục tiêu OPNsense 24.x trở lên, lab xác nhận.

**`opn_urltable_setup`** (thiết lập một lần, đường kéo): tạo alias loại **URL Table (IPs)** trỏ tới URL danh sách chặn của hộp, đặt "Refresh frequency" [xác minh tồn tại loại và tuỳ chọn; đơn vị chưa rõ]. Hộp in hướng dẫn, quản trị viên làm trong giao diện. Kiểm lại phía hộp: thấy yêu cầu tải đầu tiên từ IP firewall. Rủi ro `low`.

### 4.2 pfSense

**Thực trạng, nói thẳng**: Netgate không phát hành REST API chính thức cho pfSense. Gói REST API (`pfsense-pkg-restapi`, tài liệu pfrest.org, người bảo trì Jared Hendrickson) là **không chính thức**, "không liên kết hay được hỗ trợ bởi Netgate hay đội pfSense" [xác minh: https://pfrest.org/]. Netgate có lưu một đặc tả OpenAPI tại https://netgate.github.io/pfsense-api/ (phạm vi và mức hỗ trợ chưa xác minh). FauxAPI là gói bên thứ ba khác, không dùng. Không tìm thấy trang `docs.netgate.com` nào nói về REST API.

Vì thế Vedette xếp ba lựa chọn theo mức tin cậy:

1. **Kéo (chính thức)**: alias loại URL Table (IPs) trỏ tới danh sách chặn của hộp. Mô tả loại alias nằm ở https://docs.netgate.com/pfsense/en/latest/firewall/aliases.html (trang chỉ nhắc có URL Table, chi tiết ở trang "Alias Types", chưa đọc được). **Chu kỳ cập nhật tối thiểu của pfSense URL Table chưa xác minh** (có thể theo ngày, nghĩa là quá chậm cho chặn tức thì): kiểm trước khi giới thiệu cho khách như cách chính.
2. **Đẩy qua gói REST không chính thức**: dùng khi khách đã tự cài gói. Ghi "không chính thức" trên giao diện (tương tự cách D-46 ghi Zalo cá nhân). Gói v2: đường dẫn `/api/v2/firewall/alias` (cập nhật mảng `address` của alias) và `/api/v2/firewall/apply` (áp dụng) **chưa xác minh** (trang pfrest.org không liệt kê endpoint ở phần đọc được; Swagger tự phục vụ ở System > REST API > Documentation sau khi cài [xác minh]). GUI hiện dùng `/api/v1/firewall/alias/entry`, nhánh v1 cũ, **không** dùng trong spec này.
3. **Đẩy qua SSH + `pfctl`** (chưa xác minh trong tài liệu Netgate; `pfctl` là công cụ FreeBSD): `pfctl -t Vedette_Blocklist -T add {ip}`, `pfctl -t Vedette_Blocklist -T delete {ip}`, `pfctl -t Vedette_Blocklist -T show`. Điểm vấp: chạy `pfctl` cần quyền root nên tài khoản SSH quyền rất cao (không có quyền tối thiểu nhỏ hơn), mục thêm bằng `pfctl` thường mất khi bộ lọc được nạp lại (chưa xác minh). Chỉ cho vào danh sách "mẫu tuỳ chỉnh" với cảnh báo, không đưa vào mẫu dựng sẵn.

**`pf_alias_add` / `pf_alias_remove` (cách 2, không chính thức)**
- Mô tả: "Thêm/gỡ IP trong alias `Vedette_Blocklist` của pfSense qua gói REST không chính thức".
- Tham số: `ip`; tên alias cố định ở kết nối.
- Run/rollback: đọc alias rồi `PATCH` mảng `address` (thêm/bớt đúng một phần tử) rồi `POST /api/v2/firewall/apply`. Tất cả **chưa xác minh**; viết mã chỉ sau khi đọc Swagger của chính gói trên máy lab.
- Quyền: gói dùng người dùng pfSense; cấp quyền trang `Firewall: Aliases` tối thiểu (chưa xác minh tên quyền). Không dùng `admin`.
- Rủi ro: `low` (IP ngoài) / `medium` (nguồn trong LAN). Điểm vấp: phải gọi `apply` sau mỗi thay đổi, apply tải lại bộ lọc và có thể ngắt kết nối thoáng chốc; gộp thay đổi và dùng `max_per_hour`.
- Hoàn tác và kiểm lại: gỡ phần tử rồi `apply`; đọc lại alias.

---

## 5. Cisco IOS / IOS-XE (SSH)

**Nguồn**:
- Số thứ tự ACL (named standard/extended): https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/sec-vpn/b-security-vpn/m_sec-acl-seq-num.html và https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_data_acl/configuration/xe-3s/sec-data-acl-xe-3s-book/sec-acl-seq-num.html
- Cấu hình ACL trên Catalyst: https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960xr/software/15-2_4_e/configuration_guide/b_1524e_consolidated_2960xr_cg/b_1524e_consolidated_2960xr_cg_chapter_01100000.html

**Phiên bản**: IOS 15.x, IOS-XE 16.x/17.x (dùng được cho Catalyst 9000, 2960-XR trở lên). Các lệnh bên dưới ghi theo thiết kế; từng lệnh đã nêu rõ nhãn.

### 5.1 Kết nối, quyền tối thiểu

- SSH v2 qua thư viện Go (không qua shell của hộp), khoá máy chủ được ghim lần đầu và **dừng nếu khoá đổi** (không bỏ qua), ưu tiên khoá công khai, không gửi mật khẩu `enable` trong mẫu. Mỗi kết nối một phiên tại một thời điểm (hàng đợi theo thiết bị). Khởi đầu: `terminal length 0`, `terminal width 511` (chưa xác minh `width` ở mọi nền tảng).
- Đọc đầu ra theo dấu nhắc lệnh với timeout; mọi dòng bắt đầu bằng `%` (lỗi IOS như `% Invalid input detected`) là **thất bại**, dừng chuỗi và chạy `end`.
- Quyền tối thiểu: tạo người dùng cục bộ cấp đặc quyền riêng chỉ có các lệnh cần. Mẫu dựa trên `privilege` (**chưa xác minh**, tên chế độ con của ACL khác nhau theo phiên bản; thử trên máy lab):

```
username vedette privilege 7 secret <mạnh>
privilege exec level 7 configure terminal
privilege exec level 7 show ip access-lists
privilege exec level 7 show interfaces
privilege exec level 7 show running-config
privilege exec level 7 write memory
privilege configure level 7 ip access-list extended
privilege configure level 7 interface
privilege interface level 7 shutdown
privilege interface level 7 switchport access vlan
```

  Cách mạnh hơn: AAA với TACACS+/ISE ủy quyền từng lệnh (`aaa authorization commands`), hoặc `parser view`; cả hai chưa xác minh chi tiết. Nếu khách dùng cấp 15 vì tiện: giao diện cảnh báo và ghi vào kiểm toán.
- Bảo vệ danh sách cổng không đụng: uplink, Port-channel, cổng nối hộp Vedette và AP/camera quan trọng khách khai báo.
- Danh sách lệnh **cấm** trong mọi mẫu Cisco (hộp từ chối lưu): `reload`, `erase`, `write erase`, `delete`, `format`, `copy` (trừ `copy running-config startup-config` ở hành động lưu), `no ip access-list`, `no interface`, `crypto`, `username`, `enable`, `aaa`.

### 5.2 `cisco_acl_deny` / `cisco_acl_remove`: chặn IP bằng ACL (extended có tên, chèn ở đầu)

- Mô tả: "Thêm dòng `deny` cho IP vào ACL `VEDETTE-BLOCK` trước mọi dòng khác; ACL đã được khách gắn vào cổng uplink (một lần)". Hộp **không** gắn ACL vào cổng, khách làm một lần.
- Thiết kế ACL (khách tạo một lần, hộp in mẫu):

```
ip access-list extended VEDETTE-BLOCK
 2147483000 permit ip any any
!
interface <uplink>
 ip access-group VEDETTE-BLOCK in
```

  Điểm quan trọng: ACL kết thúc bằng `deny ip any any` ngầm; một ACL chỉ có dòng `deny` sẽ chặn **toàn bộ** lưu lượng. Dòng `permit ip any any` ở số thứ tự rất lớn là bắt buộc, và Vedette chỉ chèn ở số **nhỏ hơn** nó. Số thứ tự tối đa của IOS là chưa xác minh trong nguồn đã đọc (kỳ vọng 2147483647).
- Tham số: `ip` (nguồn) hoặc `cidr` (đổi sang `wildcard`); tên ACL cố định ở kết nối (`name`).
- Chèn ở đầu: thiết kế quy ước số thứ tự: dòng Vedette dùng số trong khoảng `1`-`1000000`, cấp bằng "số nhỏ nhất đang dùng trừ 1" (`precheck`: `show ip access-lists VEDETTE-BLOCK` rồi tính). Nếu số nhỏ nhất đã là `1`, chạy `ip access-list resequence VEDETTE-BLOCK 100 10` (tạo khoảng trống, **không** đổi thứ tự; dòng cũ giữ nguyên thứ tự) [xác minh: resequence chỉ tạo/nới khoảng cách, không sắp lại; ví dụ `ip access-list resequence 150 1 2`, nguồn cộng đồng Cisco]. Vì ACL của Vedette chỉ chứa dòng `deny host` rời nhau nên thứ tự giữa chúng không ảnh hưởng.
- Run (dòng lệnh, mỗi dòng gửi riêng):

```
configure terminal
ip access-list extended VEDETTE-BLOCK
{seq} deny ip host {ip} any log
end
```

  Dạng có số thứ tự trong ACL có tên [xác minh: tính năng áp dụng cho ACL standard/extended có tên, số mặc định cách nhau 10]. Từ khoá `log` chưa xác minh trên mọi nền tảng, bỏ nếu máy báo lỗi. Với `cidr`: `{seq} deny ip <mạng> <wildcard> any`.
- Hoàn tác (theo **số thứ tự đã lưu**, không theo nội dung, để không gỡ nhầm): `configure terminal` / `ip access-list extended VEDETTE-BLOCK` / `no {seq}` / `end`. Số thứ tự **không được lưu qua khởi động lại** (đánh lại từ đầu) [xác minh] nên sau khi thiết bị khởi động lại hộp đọc lại ACL và dò theo nội dung `deny ip host {ip} any` để lấy lại số.
- Kiểm lại: `show ip access-lists VEDETTE-BLOCK`; kỳ vọng dòng `{seq} deny ip host {ip} any` có/không có. Số lần khớp (`(N matches)`) là thông tin phụ, chưa dùng làm tiêu chí.
- Rủi ro: `medium`. Rủi ro tăng nếu `ip` là nguồn nội bộ cần thiết (gateway, DNS) nên danh sách không đụng áp dụng mạnh.
- Điểm vấp:
  - **Không lưu cấu hình sẽ mất khi khởi động lại**: mặc định hộp không lưu (xem 5.5). Với chặn có TTL thì mất khi reload là hành vi an toàn.
  - Trùng nội dung với số thứ tự khác vẫn được IOS chấp nhận (chưa xác minh); `precheck` đọc ACL để tránh.
  - ACL lớn tốn TCAM trên switch; đặt `max_per_hour` và trần số mục (ví dụ 200) ở kết nối.
  - Chỉ hiệu lực với hướng/giao diện đã gắn ACL; hộp không biết trước, nên `verify` chỉ khẳng định dòng có trong ACL chứ **không** khẳng định lưu lượng đã bị chặn.
  - Không có TTL gốc: Vedette tự hoàn tác (có thể dùng `time-range absolute end`, chưa xác minh, tốn một đối tượng thời gian mỗi mục: chưa dùng).

### 5.3 `cisco_port_shut` / `cisco_port_noshut`: tắt/bật cổng

- Mô tả: "Tắt một cổng switch; thứ cắm vào mất mạng đến khi bật lại".
- Tham số: `interface` (regex `^(Fa|Gi|Te|Twe|Fo|Hu|Eth)[A-Za-z]*\d+(/\d+){0,3}$`, không Port-channel và không cổng nằm trong danh sách không đụng ở bản đầu); phải có trong ảnh chụp `show interfaces status` ở `precheck`.
- Run: `configure terminal` / `interface {interface}` / `shutdown` / `end`. Hoàn tác: `no shutdown`. Cả hai [lệnh chuẩn IOS, chưa xác minh trên trang đã đọc].
- `precheck`: `show interfaces {interface} status` ghi trạng thái cũ; nếu đã `disabled`, hành động ghi "đã tắt từ trước" và hoàn tác **không** bật lại (không phải do Vedette tắt).
- Kiểm lại: `show interfaces {interface} status`, kỳ vọng cột Status `disabled` sau tắt, `connected`/`notconnect` sau bật.
- Rủi ro: `medium` (tắt) ; thiết bị PoE (camera, điện thoại, AP) mất cả nguồn. Rủi ro `high` nếu cổng có nhiều thiết bị phía sau (ảnh chụp thấy nhiều MAC: `show mac address-table interface {interface}`, chưa xác minh dạng lệnh); hộp tự nâng bậc.
- Điểm vấp: tắt cổng mà hộp Vedette/khách đang SSH qua đó sẽ cắt chính phiên điều khiển: cổng nối hộp nằm trong danh sách không đụng.

### 5.4 `cisco_port_vlan_quarantine` / `cisco_port_vlan_restore`: chuyển cổng truy cập sang VLAN cách ly

- Mô tả: "Chuyển một cổng truy cập sang VLAN cách ly (không có đường tới máy chủ); thiết bị còn liên kết nhưng mất mọi thứ khác".
- Tham số: `interface`, `vlan` (VLAN cách ly do khách chọn ở kết nối, không lấy từ tác nhân).
- `precheck` bắt buộc (không có thì không chạy):
  1. `show interfaces {interface} switchport`: phải ở chế độ **access** tĩnh (`Administrative Mode: static access`); trunk hoặc dynamic thì từ chối.
  2. Ghi VLAN truy cập hiện tại (`Access Mode VLAN: <n>`) làm giá trị hoàn tác.
  3. `show vlan id {vlan}`: VLAN cách ly phải **đã tồn tại** (trên một số switch, `switchport access vlan` tới VLAN chưa có sẽ tạo VLAN mới, nên tự kiểm; chưa xác minh trong nguồn Cisco đã đọc).
- Run: `configure terminal` / `interface {interface}` / `switchport access vlan {vlan}` / `end`.
- Hoàn tác: `switchport access vlan <giá trị cũ đã lưu>` (khi cũ là 1 mặc định: `no switchport access vlan`).
- Kiểm lại: `show interfaces {interface} switchport`, kỳ vọng `Access Mode VLAN: {vlan}`; sau hoàn tác kỳ vọng VLAN cũ.
- Rủi ro: `high` (2 người duyệt, D-51). Gắn nhãn `ai_may_propose` theo cờ D-51 (GUI hiện bật `true` cho hành động này).
- Điểm vấp:
  - Thiết bị giữ địa chỉ DHCP của VLAN cũ tới khi liên kết nhấp nháy; VLAN cách ly vì thế có thể phải có DHCP riêng. Không tự `shutdown`/`no shutdown` trong cùng hành động.
  - 802.1X/MAB gán VLAN động có thể ghi đè giá trị tĩnh (chưa xác minh), `verify` đọc lại cả `Operational Mode`/VLAN thực tế.
  - Cổng có VLAN thoại hoặc `port-security` cần kiểm riêng (chưa xác minh).

### 5.5 `cisco_save_config`: lưu cấu hình

- Mô tả: "Ghi cấu hình đang chạy vào bộ nhớ khởi động để còn sau khi khởi động lại".
- Run: `write memory` hoặc `copy running-config startup-config` (chưa xác minh trong nguồn đã đọc; chuẩn IOS). Kiểm lại: kết quả `[OK]`, cộng đọc `show startup-config | include VEDETTE` (chưa xác minh).
- **Mặc định hộp KHÔNG lưu** sau các hành động ở 5.2 đến 5.4. Lý do: lưu cũng ghi luôn mọi thay đổi chưa lưu của quản trị viên khác, và chặn tạm đã nên biến mất khi khởi động lại. Chỉ hành động `permanent` hoặc người duyệt chọn "lưu" mới gọi hành động này.
- Rủi ro: `medium` (hậu quả vĩnh viễn nếu cấu hình có lỗi). Hoàn tác: không có hoàn tác tự động (cần bản sao lưu cấu hình); hộp ghi `show running-config | include <đối tượng của Vedette>` vào kiểm toán trước khi lưu.

---

## 6. Aruba CX và ArubaOS-Switch / HPE

Hai nền tảng **khác nhau hoàn toàn**: AOS-CX (CX 6000/6100/6200/6300/8xxx, có REST) và ArubaOS-Switch (ProVision, 2530/2920/2930F/5400R, chủ yếu CLI). Cả hai ở bản đầu: SSH CLI; REST của AOS-CX là đường phụ.

**Nguồn**:
- AOS-CX REST API (v10.04 đến v10.16 có trang tham chiếu): https://developer.arubanetworks.com/aoscx/v10.13/reference/get_system
- POST ACL: https://developer.arubanetworks.com/aoscx/v10.13/reference/post_system-acls
- ACL entry: https://developer.arubanetworks.com/aoscx/v10.13/reference/acl_entry
- ArubaOS-Switch: không tìm thấy trang chính thức khi soạn

### 6.1 Aruba AOS-CX

- Quyền: AOS-CX có nhóm người dùng dựng sẵn (administrators, operators, auditors), **chưa xác minh** nhóm nào cho phép cấu hình ACL/cổng với quyền nhỏ nhất. Mặc định phải dùng `administrators`: nêu rõ trên giao diện, và khuyên giảm rủi ro bằng (a) VRF quản trị và ACL chỉ cho IP hộp vào SSH/REST, (b) TACACS+/RADIUS ủy quyền lệnh nếu khách có.
- Kết nối SSH: mô hình như 5.1 (khoá máy chủ ghim, mỗi dòng gửi riêng, lỗi bắt đầu bằng `%` hoặc dòng thông báo lỗi riêng của CX được coi là thất bại, kiểu thông báo chưa xác minh).
- **ACL chặn IP (SSH, cú pháp chưa xác minh, thử trên máy lab)**:

```
configure terminal
access-list ip VEDETTE-BLOCK
    {seq} deny any {ip}/32 any
exit
```

  Hoàn tác: `no {seq}` trong chế độ `access-list ip VEDETTE-BLOCK`. Gắn một lần: `interface <uplink>` / `apply access-list ip VEDETTE-BLOCK in`. ACL AOS-CX cũng có `deny` ngầm cuối: cần `permit any any any` ở số thứ tự lớn (chưa xác minh dạng viết). Kiểm lại: `show access-list ip VEDETTE-BLOCK` (chưa xác minh).
- **ACL qua REST** (đường dẫn theo trang tham chiếu): `POST /rest/v10.xx/system/acls/{name},{list_type}/cfg_aces` tạo dòng, và sửa/xoá từng dòng theo số thứ tự (`.../cfg_aces/{sequence_number}`) [xác minh: tồn tại đường dẫn và địa chỉ hoá theo số thứ tự; **chưa xác minh** các trường của thân yêu cầu, tên ACL 1 đến 64 ký tự]. Phiên đăng nhập `POST /rest/v10.xx/login` là chưa xác minh trong nguồn đã tải (bài đã thấy trang `post_login` nhưng chưa đọc). Bật REST trên switch (`https-server rest access-mode read-write`, `https-server vrf mgmt`) chưa xác minh.
- **Tắt/bật cổng** (CLI, chưa xác minh): `interface 1/1/{n}` / `shutdown`; hoàn tác `no shutdown`; kiểm lại `show interface 1/1/{n}`. Tên cổng AOS-CX có dạng `1/1/1`; regex `^\d{1,2}/\d{1,2}/\d{1,3}$`. Lưu ý trên AOS-CX giao diện chưa dùng có thể đang `shutdown` mặc định (chưa xác minh): `precheck` đọc trạng thái cũ như 5.3.
- **Chuyển cổng sang VLAN cách ly** (CLI, chưa xác minh): `interface 1/1/{n}` / `vlan access {vlan}`; hoàn tác trả giá trị cũ đã đọc (`show interface 1/1/{n}` hoặc `show running-config interface 1/1/{n}`); điều kiện `precheck` như 5.4 (cổng access, VLAN cách ly tồn tại).
- **Lưu cấu hình**: AOS-CX tách cấu hình chạy và khởi động; `write memory` hoặc `copy running-config startup-config` (chưa xác minh). Nguyên tắc 5.5 áp dụng nguyên văn: mặc định không lưu.
- Rủi ro, TTL, hoàn tác: như Cisco (5.2 đến 5.5), `high` cho VLAN cách ly.

### 6.2 ArubaOS-Switch (HPE ProVision)

- **Chưa tìm được tài liệu chính thức khi soạn**: mọi lệnh dưới đây chưa xác minh. Không có xác nhận về REST v7 cho ACL; bản đầu **chỉ SSH**.
- Quyền: vai trò `operator` chỉ xem, `manager` đầy đủ (chưa xác minh); cần `manager`. Giảm rủi ro bằng TACACS+ ủy quyền lệnh và danh sách `ip authorized-managers` chỉ chứa IP hộp (chưa xác minh tên lệnh).
- ACL chặn IP (cú pháp suy đoán):

```
configure
ip access-list extended VEDETTE-BLOCK
    {seq} deny ip {ip} 0.0.0.0 any
exit
```

  GUI hiện ghi `deny any {ip} 0.0.0.0` (thứ tự hướng nguồn/đích đáng ngờ). Phải thử trên máy thật. Gắn ACL: `vlan <n>` / `ip access-group VEDETTE-BLOCK in` hoặc theo cổng (chưa xác minh). Hoàn tác: `no {seq}` (chưa xác minh).
- Tắt/bật cổng: `interface {n}` / `disable`; hoàn tác `enable` (chưa xác minh). Tên cổng dạng `5`, `A1` (chưa xác minh).
- Chuyển VLAN: gắn **untagged** vào VLAN cách ly: `vlan {vlan}` / `untagged {n}`; hoàn tác `vlan <VLAN cũ>` / `untagged {n}` (chưa xác minh; lệnh này tự rút cổng khỏi VLAN untagged cũ, nên VLAN cũ phải đọc ở `precheck` bằng `show vlans ports {n} detail`, chưa xác minh).
- Lưu: `write memory` (chưa xác minh); nguyên tắc 5.5.
- Rủi ro như Cisco. Cho ArubaOS-Switch: không đưa vào mẫu dựng sẵn, chỉ làm mẫu tuỳ chỉnh có cảnh báo "chưa kiểm thử" cho tới khi lab xác nhận.

---

## 7. Pi-hole v6

**Phiên bản**: Pi-hole v6 (API REST tích hợp trong FTL). Bản v5 không có API này.

**Nguồn**:
- Tổng quan API: https://docs.pi-hole.net/api/
- Xác thực: https://docs.pi-hole.net/api/auth/
- Đặc tả máy đọc được của `domains`: https://github.com/pi-hole/FTL/blob/master/src/api/docs/content/specs/domains.yaml (tệp YAML; đã đọc nội dung)
- Tài liệu tương tác chạy trên chính máy: `http://pi.hole/api/docs` [xác minh]

### 7.1 Kết nối và quyền

- Đăng nhập: `POST /api/auth` body `{"password":"<mật khẩu ứng dụng>"}` (thêm `"totp":123456` nếu bật 2FA). Trả `session.sid`, `session.csrf`, `session.validity` giây [xác minh]. Gửi sid bằng header `X-FTL-SID: <sid>` (ngoài ra có thể qua query, JSON, cookie) [xác minh]; dùng header, không dùng query (tránh vào log).
- Mật khẩu ứng dụng: sinh ở trang cài đặt web; trang tài liệu nói chỉ có **một** mật khẩu ứng dụng [xác minh]. Số phiên đồng thời bị giới hạn (không rõ con số) [xác minh]: hộp **luôn** `DELETE /api/auth` (204) khi xong [xác minh] và dùng lại một phiên cho cả lô, không đăng nhập mỗi yêu cầu. Quá giới hạn đăng nhập trả 429 [xác minh]: không thử lại liên tục.
- Quyền tối thiểu: tài liệu đã đọc **không** có khái niệm mật khẩu ứng dụng chỉ-ghi-miền hay quyền theo điểm cuối; mật khẩu ứng dụng coi như quyền quản trị Pi-hole (chưa xác minh `app_sudo`). Giảm rủi ro: Pi-hole chạy trên máy riêng cho DNS, giao diện web/API chỉ nghe từ IP hộp (tường lửa), không dùng cùng mật khẩu ở nơi khác.
- HTTPS: Pi-hole v6 có thể phục vụ HTTPS; dùng, ghim chứng chỉ do quản trị viên nhập.

### 7.2 `pihole_block` / `pihole_unblock`: chặn/gỡ chặn tên miền

- Mô tả: "Thêm tên miền vào danh sách từ chối của Pi-hole; thiết bị trong mạng không phân giải được tên đó nữa".
- Tham số: `domain` (chuẩn hoá và kiểm ở 1.2). Chỉ `exact`; **không** hỗ trợ `regex` ở bản đầu (escape regex của giá trị do tác nhân điều khiển là rủi ro riêng).
- Run [xác minh từ đặc tả FTL]: `POST /api/domains/deny/exact` body `{"domain":"{domain}","comment":"vedette:<request_id>","groups":[0],"enabled":true}`. Thành công: 201 kèm header `Location`; lỗi 400/401. `groups: [0]` (nhóm mặc định) là suy luận, chưa xác minh giá trị nhóm.
- `precheck`/`verify`: `GET /api/domains/deny/exact/{domain}` (đường dẫn `{domain}` phải qua `url.PathEscape`) trả 200 với mảng `domains` (mỗi phần tử có `domain`, `type`, `kind`, `comment`, `enabled`, `id`) [xác minh]. Chưa có thì phản hồi lỗi không phải 200 (mã chính xác chưa xác minh, coi 404/400 là "chưa có").
- Hoàn tác: `DELETE /api/domains/deny/exact/{domain}` → 204 khi xong, 404 khi không có, 400 khi thiếu/không chính xác [xác minh]. Chỉ gỡ khi `comment` của mục đọc được bắt đầu bằng `vedette:` (mục của quản trị viên không đụng).
- Cũng có xoá lô `POST` (thân là mảng `{item, type, kind}`) nhưng đường dẫn không hiện trong đặc tả [xác minh một phần]; bản đầu dùng xoá từng mục.
- Rủi ro: `low`. Điểm vấp:
  - **Thêm trùng trả 400** `database_error` "The item is already present." [xác minh]: hộp phân biệt "đã có" và "lỗi thật" bằng `precheck`, không bỏ qua mọi 400.
  - Chặn `exact` chỉ chặn đúng tên đó, không chặn miền con (cần regex để chặn cả cây; chưa hỗ trợ).
  - Bộ nhớ đệm DNS ở máy khách và trình phân giải trước đó vẫn có thể còn đáp án cũ đến hết TTL; kết quả giải thích rõ "áp dụng ở truy vấn mới".
  - Domain danh sách cho phép (`allow`) thắng hay thua `deny` theo quy tắc Pi-hole (chưa xác minh); `precheck` cảnh báo nếu tên có trong `allow`.
  - Cần cập nhật "gravity" để domain danh sách có hiệu lực: chưa xác minh (khả năng không cần với domain tuỳ chỉnh). `verify` thật sự kiểm bằng truy vấn DNS thử (`dig @<pihole> {domain}`) chỉ khi hộp có quyền gọi DNS tới Pi-hole; không bắt buộc.
  - Không có TTL gốc: Vedette tự hoàn tác.
- Phiên bản: Pi-hole v6.0 trở lên.

---

## 8. AdGuard Home

**Phiên bản**: đặc tả OpenAPI đã đọc ghi phiên bản 0.107 [xác minh]. Gốc đường dẫn `/control` [xác minh].

**Nguồn**: đặc tả OpenAPI chính thức: https://github.com/AdguardTeam/AdGuardHome/blob/master/openapi/openapi.yaml (đọc qua `raw.githubusercontent.com`); mô tả: https://github.com/AdguardTeam/AdGuardHome/wiki/Configuration và https://adguard-dns.io/kb/adguard-home/ (chưa đọc).

### 8.1 Kết nối và quyền

- Xác thực mặc định HTTP Basic cho mọi điểm cuối [xác minh]; có `POST /login` (`name`, `password`) và `GET /logout` [xác minh]. Dùng Basic với người dùng riêng; AdGuard Home **không có quyền theo vai trò**: người dùng đã xác thực là quản trị toàn phần (chưa xác minh, không thấy trong đặc tả). Giảm rủi ro: AdGuard Home chạy riêng, API chỉ nghe từ IP hộp (tường lửa), HTTPS.

### 8.2 `adguard_block` / `adguard_unblock`: chặn/gỡ chặn tên miền

- Mô tả: "Thêm luật chặn tên miền vào bộ luật của người dùng trong AdGuard Home".
- Tham số: `domain` (1.2). Luật sinh ra: `||{domain}^` [xác minh ví dụ cú pháp trong đặc tả; chặn cả miền và miền con theo cú pháp AdGuard, bảng cú pháp đầy đủ chưa đọc]. Hộp **tự sinh** chuỗi luật từ `domain` đã kiểm, không nhận chuỗi luật từ tác nhân. Thêm dòng chú thích `# vedette:<request_id>` trước luật để hoàn tác (đặc tả có ví dụ `# comment` [xác minh]).
- Giao thức: **không có điểm cuối "thêm một luật"** trong phần đã đọc. Chỉ có `POST /control/filtering/set_rules` body `{"rules":[ ... ]}` ("Set user-defined filter rules"), mà đặc tả không nói rõ có thay thế toàn bộ không [xác minh một phần]. Coi như **thay toàn bộ**.
  1. `GET /control/filtering/status` → mảng `user_rules` [xác minh].
  2. Hộp tính danh sách mới = cũ + (chú thích + luật), bỏ nếu luật đã có.
  3. `POST /control/filtering/set_rules` body `{"rules":<danh sách mới>}`.
  4. Lưu danh sách cũ nguyên văn vào kiểm toán (có thể phục hồi toàn bộ nếu hỏng).
- Hoàn tác: đọc lại `user_rules`, bỏ đúng cặp (chú thích, luật) mang `request_id`, ghi lại toàn bộ.
- Kiểm lại: `GET /control/filtering/check_host?name={domain}` (`name` bắt buộc) trả `reason` và `rules` [xác minh tên trường; giá trị `reason` chưa xác minh]; kỳ vọng mảng `rules` chứa luật của Vedette hoặc `reason` biểu thị bị lọc. Bước kiểm thay thế: đọc lại `user_rules` có chứa luật.
- Rủi ro: `low`. Điểm vấp:
  - **Đọc-sửa-ghi toàn bộ** nên có thể ghi đè thay đổi đồng thời của quản trị viên hoặc hộp khác: khoá theo kết nối (một người ghi một lúc), đọc lại ngay trước khi ghi, và từ chối ghi nếu số dòng cũ đã đổi giữa lúc đọc và lúc ghi (so sánh băm).
  - Sai sót làm mất toàn bộ luật người dùng: bắt buộc lưu bản sao trước khi ghi và có nút "khôi phục luật người dùng" trong kiểm toán.
  - Tham số `domain` phải qua kiểm tra chặt: các ký tự `||`, `^`, `$`, `*`, `/`, `@@` có nghĩa trong cú pháp luật, không được lọt vào (kiểm tra regex ở 1.2 đã loại).
  - Không có TTL gốc: Vedette tự hoàn tác.
- Cách kéo thay thế: `POST /control/filtering/add_url` body `{"name":"Vedette","url":"https://<ip-hop>/blocklist/<token>/domains.txt","whitelist":false}` để AdGuard tự kéo danh sách của hộp [xác minh điểm cuối và các trường; `url` có thể là URL hoặc đường dẫn tệp]. Chu kỳ kéo là cài đặt chung của AdGuard (`interval` trong `filtering/status`, giờ). Định dạng tệp theo `blocklist-format.md`. Đường này là cách ưu tiên theo D-44; là thiết lập một lần.
- Phiên bản: AdGuard Home 0.107 trở lên (đặc tả đã đọc).

---

## 9. Hành động chung (mẫu HTTP và SSH tuỳ chỉnh, D-47)

Hành động tuỳ chỉnh do khách thêm cũng bắt buộc cùng quy tắc như hành động dựng sẵn. Máy chủ kiểm khi **lưu** mẫu và lần nữa khi **chạy**; vi phạm = từ chối lưu, không có "cảnh báo rồi cho qua".

### 9.1 Quy tắc chung

1. Mẫu chỉ chứa tham số có kiểu trong bảng 1.2; không có `{text}` trong lệnh/API (chỉ được dùng ở hành động gửi tin).
2. Có `rollback`, trừ khi người tạo ghi "không hoàn tác được"; khi đó rủi ro tối thiểu `high`, bắt buộc 2 người duyệt, không `ai_may_propose`, không "duyệt sẵn".
3. Có `verify` chỉ-đọc; không có `verify` thì hành động mang nhãn "chưa kiểm lại" và rủi ro nâng một bậc.
4. Có `ttl` bắt buộc cho mọi hành động chặn, trừ cờ `permanent` của quản trị viên.
5. Có `precheck` đọc trạng thái cũ cho mọi hành động ghi đè giá trị hiện có.
6. Dấu sở hữu (1.3) bắt buộc trong mọi đối tượng tạo ra.
7. Người tạo mẫu phải chạy khô (dry run) với sự kiện mẫu trước khi bật; mẫu tuỳ chỉnh tắt mặc định và không bao giờ `ai_may_propose` cho tới khi quản trị viên bật.
8. Không bao giờ để bí mật (token, mật khẩu, khoá) nằm trong mẫu; chỉ tham chiếu tới `core/secrets` qua kết nối. Không ghi bí mật vào log hay kiểm toán (security.md).

### 9.2 HTTP tuỳ chỉnh

> **D-94 (2026-11-09) thay các điểm sau của mục này**: chỉ HTTPS, không có "kết nối phòng thí nghiệm" HTTP thường (để sau); chứng chỉ không qua kho gốc hệ thống thì ghim SHA-256 chứng chỉ lá ở lần Test đầu; **không theo chuyển hướng nào** (kể cả cùng host); **không thử lại**, kể cả `GET`; header bị cấm: `Authorization`, `Cookie`, `Host`, `Proxy-*`, hop-by-hop, `Forwarded`, `X-Forwarded-*`. Các số 64 KB / 1 MB, 5 s / 15 s giữ nguyên.

- Chỉ HTTPS, kiểm chứng chỉ bật, cho phép ghim CA/vân tay. HTTP thường chỉ ở "kết nối phòng thí nghiệm" được quản trị viên đánh dấu và hiện cảnh báo.
- Scheme, host, cổng lấy **từ kết nối**, không từ mẫu hay tham số. Mẫu chỉ có phần đường dẫn (có tham số ở đoạn riêng, `url.PathEscape`), query (`url.Values`), thân JSON.
- Phương thức: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`. Không cho `CONNECT`, `TRACE`, phương thức lạ.
- Header: danh sách cho phép (`Content-Type`, `Accept`, header xác thực do kết nối đặt); từ chối `\r`, `\n` trong giá trị; không tham số trong tên header.
- Thân: bắt buộc JSON hợp lệ; thay giá trị trên cây JSON, không nối chuỗi. Kích thước thân và phản hồi giới hạn (đề xuất 64 KB / 1 MB).
- Không theo chuyển hướng (30x) trừ cùng host; timeout 15 giây (kết nối 5 giây); tối đa 1 lần thử lại cho `GET`, không thử lại `POST`/`PUT`/`DELETE` tự động (kết quả mơ hồ nên đọc lại bằng `verify` thay vì gửi lại).
- Phản hồi coi là dữ liệu không tin cậy: parser giới hạn độ sâu và kích thước, không đưa nguyên văn vào lời nhắc AI hay HTML.
- Trạng thái thành công xác định bằng `verify`, không bằng mã 2xx.
- Giới hạn tốc độ theo kết nối (mặc định 30 yêu cầu/phút) và một yêu cầu đồng thời.

### 9.3 SSH tuỳ chỉnh

> **D-94 (2026-11-09) thay**: hết giờ **20 giây mỗi dòng, 60 giây mỗi phiên** (thay 30 giây và 2 phút), cả item tối đa 90 giây; đầu ra thiết bị **không** ghi vào kiểm toán (chỉ một dòng đã làm sạch ≤ 200 ký tự trong kết quả item), không còn "ghi log đầu ra sau khi lọc bí mật"; khoá máy chủ đổi bị từ chối trước khi gửi thông tin xác thực; chỉ thuật toán mặc định của `x/crypto/ssh`.

- Dùng thư viện SSH của Go; không gọi `ssh` qua shell của hộp (`core/exec` allowlist, security.md). Khoá máy chủ ghim, đổi khoá thì dừng.
- Thiết bị mạng dùng phiên tương tác có PTY; mỗi dòng lệnh gửi **riêng**, chờ dấu nhắc, có timeout mỗi dòng (30 giây) và tổng (2 phút). Mẫu lưu theo từng dòng; tham số thay vào một dòng không bao giờ làm tăng số dòng (kiểm sau thay thế).
- Mẫu có số dòng tối đa (đề xuất 20) và danh sách lệnh **cấm** theo hãng (xem 5.1), cộng chặn chung: `reload`, `reboot`, `erase`, `format`, `delete`, `factory`, `write erase`, `no username`, `username`, `enable secret`, `crypto key`, `copy` tới đích mạng.
- Mọi phiên cấu hình luôn kết thúc bằng lệnh thoát chế độ cấu hình (`end` trên Cisco/Aruba, `exit` trên FortiOS...), kể cả khi lỗi.
- Lỗi của thiết bị (dòng bắt đầu `%`, `Error`, `Invalid`, `Unknown command`) = thất bại, dừng chuỗi.
- Lưu cấu hình là hành động **riêng** (5.5), không gộp vào hành động khác.
- Ghi log đầu ra của thiết bị vào kiểm toán sau khi lọc bí mật (mật khẩu, khoá, SNMP community).

### 9.4 Bảo vệ ở tầng quy tắc và cầu dao

Mẫu tuỳ chỉnh dùng chung vỏ an toàn của D-51: danh sách không đụng, gộp trùng, `max_per_hour`, cầu dao, cửa sổ bảo trì, nút dừng khẩn cấp, nhật ký chuỗi băm. Hành động tuỳ chỉnh không được tắt các bảo vệ này.

---

## 10. Quyền tối thiểu: tóm tắt để in trên giao diện

| Gói | Tài khoản cần tạo | Quyền | Không được cấp |
|---|---|---|---|
| FortiGate | quản trị viên REST API + `accprofile` riêng | `fwgrp custom`: `address`, `policy` read-write; `authgrp` nếu dùng ban (tên trường chưa xác minh) | `super_admin`, `sysgrp`; không `0.0.0.0/0` ở trusted host |
| MikroTik | người dùng + nhóm riêng | `read`, `write`, `rest-api` (chưa xác minh) | `policy`, `ftp`, `sniff`, `sensitive`, `password`, `reboot` |
| OPNsense | người dùng + khoá API | chỉ quyền alias cần (tên chưa xác minh) | quyền quản trị toàn bộ |
| pfSense | người dùng riêng cho gói REST không chính thức | chỉ alias (chưa xác minh) | `admin`, root qua SSH |
| Cisco | người dùng cục bộ cấp đặc quyền riêng hoặc ủy quyền lệnh AAA | cấu hình ACL, giao diện, `show` cần thiết (chưa xác minh tên chế độ) | cấp 15 |
| Aruba CX | nhóm quản trị (hiện chưa xác minh quyền nhỏ hơn) | ACL, giao diện | |
| ArubaOS-Switch | `manager` (chưa xác minh) | ACL, cổng, VLAN | |
| Pi-hole v6 | mật khẩu ứng dụng (một cái) | coi như quản trị | dùng chung mật khẩu khác |
| AdGuard Home | người dùng Basic | coi như quản trị | |

Ở mọi nền: giới hạn nguồn truy cập về IP hộp Vedette (trusted host, `address=`, ACL quản trị, tường lửa).

---

## 11. Phiên bản và thử nghiệm bắt buộc trước khi chuyển nhãn

| Gói | Mục tiêu | Việc bắt buộc thử trên máy thật |
|---|---|---|
| FortiGate | FortiOS 7.2 đến 7.6 | tên trường `accprofile`; đường dẫn `monitor/user/banned/add_users` và trường `expiry`; có/không `status` trên `firewall vip`; nhóm địa chỉ không rỗng; hành vi sau reboot (`banned-ip-persistency`) |
| MikroTik | RouterOS 7.9 trở lên | tên chính sách `rest-api`; lỗi trùng mục; lọc `?list=&address=`; hành vi `timeout` sau reboot |
| OPNsense | 24.x trở lên | `alias_util` thêm nhiều mục; mất mục sau reboot; tên quyền tối thiểu; thêm nhiều IP một lần |
| pfSense | CE 2.7.x / Plus (gói REST v2) | chu kỳ tối thiểu URL Table; endpoint v2; `apply` |
| Cisco | IOS 15.x, IOS-XE 16.x/17.x | `privilege` cho từng chế độ con; số thứ tự tối đa; `log`; tạo VLAN tự động |
| Aruba CX | 10.04 đến 10.16 | cú pháp ACL CLI; thân REST ACE; quyền nhỏ nhất |
| ArubaOS-Switch | còn hỗ trợ (2530/2930) | toàn bộ lệnh |
| Pi-hole | v6.0 trở lên | `groups`; chặn/cho phép ưu tiên; gravity |
| AdGuard Home | 0.107 trở lên | `set_rules` thay thế hay thêm; giá trị `reason` |

---

## 12. Chênh lệch với GUI hiện tại (kien duyệt, không tự sửa)

> **WP-06 (2026-11-09) đã áp dụng** 11 điểm dưới đây vào thư viện mẫu (dữ liệu, D-58) `web/src/features/response/templates/action-templates.sample.json` (kèm test `templates.test.ts`). Cách thể hiện: mỗi `{...}` là tham số có kiểu (`ip`, `cidr`, `domain`, `port`, `mac`, `vlan`, `interface`, `id`, `name`; `text` chỉ cho hành động gửi tin) hoặc **giá trị Vedette tự đọc/tính khi chạy** (`{seq}`, `{previous_vlan}`, `{found_id}`, `{expiry_s}`, `{timeout}`, `{rules_before}`; luật không cung cấp, giao diện hiện `<seq>`...). Mẫu nào spec còn ghi "chưa xác minh" mang câu "Not verified on a device yet — test in a lab first" trong mô tả. **Còn thiếu so với spec** (mô hình mẫu hiện là một lời gọi mỗi bước): chuỗi nhiều lời gọi REST (tạo đối tượng địa chỉ rồi thêm vào nhóm FortiGate; apply của pfSense; đọc-sửa-ghi AdGuard), `precheck` và `ttl` gốc của thiết bị chỉ nằm trong mô tả/giá trị runtime. Backend (WP-13) cần `steps[]`.

Danh mục hiện tại ở `web/src/features/response/data.ts`:

1. `nat_off` (FortiGate VIP): dùng `{text}` cho tên VIP; spec dùng `{name}`. `set status` trên `firewall vip` chưa xác minh; đề xuất lab trước khi giữ hành động này; thay thế `fgt_policy_disable` (2.5).
2. `fgt_ban_ip`: lệnh CLI `diagnose user banned-ip add src4 {ip}` chưa xác minh; GUI chưa có tham số TTL gốc (`expiry`).
3. `block_ip` (FortiGate nhóm địa chỉ): rollback chưa gỡ đối tượng địa chỉ; nhóm FortiOS cần thành viên neo (2.2).
4. `mt_addrlist_add`: rollback REST đang trống (chỉ CLI); REST cần `GET` rồi `DELETE /rest/ip/firewall/address-list/<id>`.
5. `pf_alias_add`: dùng nhánh API v1 cũ và gói không chính thức; cần ghi "không chính thức" trên giao diện và nhắm tới v2.
6. `opn_alias_add`: đúng đường dẫn, nhưng cần alias loại **External** và hộp báo "mất sau khởi động lại" (4.1).
7. `sw_acl_deny`: dùng một mẫu cho Cisco và Aruba/HPE; cú pháp ACL khác nhau, cần tách `cisco_acl_deny`, `aoscx_acl_deny`, `arubasw_acl_deny`; thiếu dòng `permit ip any any` cuối; thiếu số thứ tự để chèn ở đầu (5.2); hoàn tác nên theo số thứ tự.
8. `sw_port_shut`, `sw_vlan_quarantine`: dùng chung mẫu cho ba hãng; cú pháp khác nhau (AOS-CX `vlan access`, ArubaOS-Switch `untagged`); `sw_vlan_quarantine.rollback` dùng `no switchport access vlan` thay vì khôi phục VLAN cũ đã đọc (GUI mô tả có đọc VLAN cũ, mẫu chưa thể hiện).
9. `pihole_block`: mô tả nói "AdGuard Home người dùng sao chép và đổi lệnh API", nhưng AdGuard khác bản chất (đọc-sửa-ghi toàn bộ luật, 8.2); nên là hành động riêng.
10. Kiểu tham số: thiếu `id` (policyid) và `name`; `{text}` đang lẫn vào mẫu thiết bị.
11. Thiếu hành động `cisco_save_config` (5.5) và `fgt_ebl_setup`/`opn_urltable_setup`/`adguard_add_url` (thiết lập một lần, kéo) dưới dạng hướng dẫn.

### 12.1 Sửa dữ liệu ở lát 13b-2 (D-94, D-95; 13b-0 chốt) — **đã làm ở 13b-2**

**Trạng thái (13b-2):** cả sáu mục dưới đây đã nằm trong dữ liệu và có test (Go: `TestContract_INV14c_LibraryDataFixes`, `TestBuiltinActionsNeedingADeviceReadAreNotAvailableYet`; GUI: `templates.test.ts` §12.1). Mục 5 được cài ở `unavailable()` (tính từ mẫu, không có cờ trong dữ liệu). Các dòng lệnh, chuỗi từ chối và `expect` vẫn mang nhãn chưa thử trên máy; chưa có mã nào chạy chúng (13b-6).

Áp dụng cho cả `modules/response/data/action-templates.json` và bản mock `web/src/features/response/templates/action-templates.sample.json` (test lệch thư viện phải xanh). Nhãn "chưa xác minh" giữ nguyên như các mục trên.

1. **`tool` chỉ dành cho kết nối MCP** (D-94). `fgt_addrgrp_add` (`block_address`), `fgt_vip_disable` (`disable_virtual_ip`), `fgt_policy_disable` (`disable_firewall_policy`) đổi thành `tool: null`. Kiểu HTTP và SSH dùng công cụ cố định của loại kết nối (`send_request`, `run_approved_command`, `apply_config`, `launch_job`); giữ tên kiểu MCP trên hành động HTTP thì hành động bị coi là không khả dụng trên kết nối HTTP thật.
2. **Chuỗi dòng SSH đầy đủ.** Lõi không biết lệnh của hãng (D-58), nên tắt phân trang và vào/ra chế độ cấu hình nằm trong dữ liệu. Mỗi bước (`precheck`, `run`, `rollback`, `verify`) là một phiên riêng:

| Nền | Dòng đầu của mọi bước | Bọc `run`/`rollback` | Nhãn |
|---|---|---|---|
| Cisco IOS/IOS-XE | `terminal length 0` | `configure terminal` … `end` | lệnh chuẩn IOS (5.1), chưa thử trên máy |
| Aruba AOS-CX | `no page` | `configure terminal` … `end` | chưa xác minh |
| ArubaOS-Switch | `no page` | `configure` … `end` | chưa xác minh |

   Ví dụ `cisco_port_shut`: `run` = `terminal length 0` / `configure terminal` / `interface {interface}` / `shutdown` / `end`; `rollback` như vậy với `no shutdown`; `verify` = `terminal length 0` / `show interfaces {interface} status`. `cisco_save_config`: `run` = `terminal length 0` / `write memory`; `verify` = `terminal length 0` / `show startup-config` (thiếu dòng đầu thì phiên dừng ở `--More--` tới hết 20 s).
3. **Kiểm trước và chuỗi từ chối cho hành động cổng** (D-95 (3); đóng M4 của rà WP-13a: không đụng cổng trunk/uplink):

| Hành động | `precheck` | `precheck_refuse` | Nhãn |
|---|---|---|---|
| `cisco_port_shut`, `cisco_port_vlan_quarantine` | `terminal length 0` / `show interfaces {interface} switchport` | `Administrative Mode: trunk`, `Operational Mode: trunk`, `Administrative Mode: dynamic` | dạng dòng theo 5.4 (`Administrative Mode: static access`); chưa thử trên máy |
| `aoscx_port_shut`, `aoscx_vlan_quarantine` | `no page` / `show interface {interface}` | `VLAN Mode: trunk`, `VLAN Mode: native-untagged`, `VLAN Mode: native-tagged` | chưa xác minh |
| `arubasw_port_shut`, `arubasw_vlan_quarantine` | `no page` / `show vlans ports {interface} detail` | `Tagged` (phân biệt hoa thường, không khớp `Untagged`) | chưa xác minh |

   Uplink ở chế độ access không bị chuỗi trên bắt: vẫn phải khai trong danh sách không bao giờ đụng (INV-10).
4. **`expect` ở `verify`** (D-95 (2); so chuỗi con, JSON đã nén, sau hoàn tác chuỗi phải mất):

| Hành động | `verify.expect` | Ghi chú |
|---|---|---|
| `fgt_addrgrp_add` | `"vedette-{ip}"` | dấu nháy để `1.2.3.4` không khớp `vedette-1.2.3.45`; đúng cho cả JSON và `show firewall addrgrp` |
| `fgt_ban_ip` | `{ip}` | khớp cả IP dài hơn cùng tiền tố (chấp nhận: `verified` là thông tin, không phải cổng) |
| `fgt_vip_disable`, `fgt_policy_disable` | `"status":"disable"` | chỉ đường API (`verify.cli` rỗng) |
| `opn_alias_add` | `"{ip}"` | |
| `pihole_block` | `"domain":"{domain}"` | |
| `cisco_port_shut` | `disabled` | cột Status của `show interfaces status` |
| `aoscx_port_shut` | `Admin state is down` | chưa xác minh |
| `cisco_acl_deny` | `deny ip host {ip} any` | chưa khả dụng (mục 5) |
| `cisco_port_vlan_quarantine` | `Access Mode VLAN: {vlan} ` (dấu cách cuối) | chưa khả dụng (mục 5) |
| `cisco_save_config`, `pf_alias_add`, ArubaOS-Switch | không đặt | `verified = null` ("not checked") |

5. **Giá trị lúc chạy chưa có tới 13c** (D-94 (4)): mẫu còn `{seq}`, `{previous_vlan}`, `{found_id}`, `{rules_before}` hoặc `{timeout}` là "không khả dụng" kèm lý do: `cisco_acl_deny`, `aoscx_acl_deny`, `arubasw_acl_deny`, `cisco_port_vlan_quarantine`, `aoscx_vlan_quarantine`, `arubasw_vlan_quarantine`, `mt_addrlist_add`, `adguard_block`. Chỉ `{expiry_s}` = `ttl_min` × 60 được tính ở 13b-6 (`fgt_ban_ip`; item không có TTL thì hành động này không khả dụng).
6. **Mẫu dựng sẵn chưa thử trên máy thì tắt mặc định** (rủi ro của kế hoạch WP-13b): `fgt_addrgrp_add`, `fgt_ban_ip`, `fgt_vip_disable` đang `enabled: true` dù `unverified: true`; đổi `enabled: false` cho bản cài mới (`enabled` của hộp đã cài vẫn là của người dùng, D-88 (1)).

## 13. Câu hỏi mở

1. FortiGate: cấp `sysgrp` cho thiết lập External Block List bằng REST, hay luôn để quản trị viên dán CLI? Đề xuất: luôn dán CLI (2.6).
2. pfSense: có chấp nhận đường dẫn không chính thức (gói REST) làm đường đẩy mặc định, hay chỉ kéo và cho khách tự bật gói?
3. Nhóm địa chỉ FortiOS cần thành viên neo `192.0.2.1/32`: chấp nhận cách này hay dùng cách khác (đối tượng địa chỉ cô lập cho từng mục)?
4. Kiểu tham số `id` (policyid): thêm vào danh sách `PARAM_TYPES` (story mới, kien duyệt).
5. Cisco: có cho phép hành động `cisco_save_config` tự động sau chặn kéo dài (TTL lớn) không, hay luôn là bước duyệt riêng?
6. Hộp có tự `clear` trạng thái kết nối đang mở (OPNsense states, FortiGate session) sau khi chặn không? Đề xuất: không ở bản đầu.
7. Thêm kiểu `regex` cho Pi-hole để chặn cả cây miền con (cần quy tắc escape regex riêng, 7.2).

Mọi mục "chưa xác minh" ở trên cần một lượt lab (FortiGate-VM, CHR của MikroTik, OPNsense VM, Cisco CML/Catalyst, AOS-CX OVA) trước khi viết mã; lab nằm dưới `rules/agent-safety.md` (không quét mạng thật).
