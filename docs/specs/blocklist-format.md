# Block list: danh sách chặn mà firewall tự kéo

Trạng thái: bản nháp M2-0 (docs-first), 2026-11-09. Văn xuôi tiếng Việt; tên trường, định dạng, đường dẫn bằng tiếng Anh.
Truy vết: D-44 (ưu tiên cách kéo), D-51 (hành động `blocklist_add`, TTL, hoàn tác), D-43, D-47; story S-RESP-3; GUI mock `web/src/features/response` (`BlocklistTab.tsx`, `guides.ts`, `mocks.ts`, `contract.ts`).

## 1. Mục đích

Hộp **phát hành** một danh sách địa chỉ cần chặn tại một URL nội bộ có token; firewall/DNS filter của khách **tự kéo** định kỳ. Vedette không cần quyền ghi lên thiết bị (D-44), không đứng trên đường mạng (D-3). Mỗi mục vào danh sách là kết quả của một hành động đã được duyệt (D-51: mọi hành động cần duyệt; ngoại lệ "duyệt sẵn" theo quy tắc), có TTL tự gỡ và hoàn tác được.

Danh sách chỉ phục vụ **hướng đích** (chặn kết nối ra tới địa chỉ độc hại). Cô lập một máy trong LAN (chạm bẫy → chặn nguồn) là hành động đẩy qua API/SSH (D-44, D-51), không đi qua danh sách này.

## 2. Actors

| Actor | Vai trò |
|---|---|
| `core` (module `response`) | giữ danh sách, phát hành, quay token |
| Firewall / DNS filter | client kéo danh sách (FortiGate, Palo Alto, pfSense, OPNsense, MikroTik, Pi-hole, AdGuard Home) |
| Quản trị viên | sao chép URL, thiết lập phía firewall theo hướng dẫn trong GUI, quay token |
| Engine phản ứng | thêm/gỡ mục qua hành động `blocklist_add` / `blocklist remove` |

## 3. Transport và xác thực

- `GET` qua HTTPS tới `https://<IP hộp>:8443/api/v1/response/blocklist/<token>.<ext>`; chứng chỉ do CA nội bộ của hộp ký (tự ký với firewall; hướng dẫn GUI yêu cầu nhập CA vào firewall, trừ MikroTik script dùng `check-certificate=no`; xem §8 và §12).
- **Không có header xác thực.** Token trong đường dẫn là credential duy nhất; lý do: các cơ chế kéo của firewall thường chỉ nhận URL (FortiGate tắt HTTP basic auth trong hướng dẫn GUI). Hệ quả: URL phải coi như bí mật, chỉ tới được từ LAN, **không bao giờ** hiển thị trong log truy cập, referrer, hay gói báo lỗi (D-42).
- Token: 128 bit ngẫu nhiên từ CSPRNG, hex thường 32 ký tự (`^[a-f0-9]{32}$`, như `TOKEN_RE` trong mock). Lưu băm (SHA-256) phía core; GUI chỉ cho thấy URL đầy đủ cho admin và 4 ký tự cuối ở nơi khác. Token sai → `404 Not found` (không phân biệt với đường dẫn sai).
- Giới hạn tốc độ: 60 request/phút/IP nguồn; 20 lần sai token/phút/IP trước khi `429`. Mỗi request thành công ghi `last_fetch {at, from}` (hiện ở GUI: "from a device on the LAN").
- Không phục vụ trên listener công khai: listener này chỉ bind vào card quản trị (D-56) và từ chối nguồn ngoài dải RFC1918/ULA của mạng quản trị (SYS-7 phản chiếu: không mở cho Internet).

## 4. Biến thể và định dạng

| URL | `Content-Type` | Nội dung | Dùng cho |
|---|---|---|---|
| `<token>.txt` | `text/plain; charset=utf-8` | IP và CIDR, mỗi dòng một mục | FortiGate, Palo Alto, pfSense, OPNsense, MikroTik |
| `<token>.json` | `application/json` | cùng nội dung có đủ trường | tích hợp tự viết, kiểm tra, GUI |
| `<token>.domains.txt` | `text/plain; charset=utf-8` | domain, mỗi dòng một tên | Pi-hole, AdGuard Home (danh sách chặn domain) |

`.txt` và `.json` đã có ở mock (chỉ `.txt` thực sự xuất hiện trong GUI). `.domains.txt` là suy ra từ yêu cầu Pi-hole/AdGuard của D-51 và **chưa có trong mock**; xem §12.

### 4.1 Trường của một mục

| Trường | Kiểu | Quy tắc |
|---|---|---|
| `value` | string | IPv4 đơn (`netip.ParseAddr`), CIDR (`netip.ParsePrefix`, độ dài tiền tố bắt buộc, D-32), hoặc domain ASCII (IDNA đã chuyển punycode, ≤ 253 ký tự, mỗi nhãn ≤ 63, chữ thường) |
| `kind` | enum | `ip` \| `cidr` \| `domain` (suy ra từ `value`, không do người gọi chọn) |
| `source` | string | nhãn quy tắc/hành động đã tạo mục, ≤ 120 ký tự (ví dụ `Rule: Known-bad IP`) |
| `reason` | string | ≤ 200 ký tự (ví dụ `IPsum, confidence 85`) |
| `added` | datetime | RFC 3339 UTC (mock gọi là `added_at`) |
| `expires` | datetime \| null | `null` = không hết hạn (chỉ cho phép khi hành động **không** có TTL; D-51 đặt TTL ≤ 24 giờ cho duyệt sẵn) (mock: `expires_at`) |

Tên trường JSON thống nhất với `BlockEntry` trong `contract.ts`: `added_at`, `expires_at`. Bảng trên dùng tên ngắn của yêu cầu; **tên chính thức trên dây là `added_at`/`expires_at`** để khớp mock.

`kind` **chưa có** trong `BlockEntry` của mock (chỉ `value, source, reason, added_at, expires_at`); thêm vào hợp đồng khi viết backend (xem §12).

### 4.2 Biến thể `.txt`

```
# vedette blocklist
# generated 2026-11-09T07:12:41.000Z
# entries 2
203.0.113.77
198.51.100.9
```

- Ba dòng comment đầu (rà bảo mật WP-13a, D-88, thay dạng cũ có `# <source> | <reason> | expires …` trước từng mục): tên danh sách, giờ máy chủ, số mục. **Không có tên thiết bị, quy tắc, tóm tắt sự kiện hay lý do** trong tệp công khai (§12 (a)); `source`, `reason`, `expires_at` nằm ở màn hình quản trị và `.json`. Sau đó mỗi mục một dòng giá trị.
- Kết thúc dòng `\n` (LF), mã hoá UTF-8 không BOM; dòng trống không có.
- Danh sách rỗng: vẫn `200` với riêng ba dòng comment (`# entries 0`; không `404`, không thân rỗng).
- **Chống tiêm dòng.** (Chỉ còn quan trọng cho `.json`/màn hình quản trị: `.txt` không in `source`/`reason` nữa.) `source` và `reason` có thể chứa dữ liệu do kẻ tấn công kiểm soát (D-51). Trước khi phát hành, mọi ký tự điều khiển (`\r`, `\n`, `\t`, NUL, U+0085, U+2028/2029…) bị thay bằng khoảng trắng, `|` bị thay bằng `/`, và cắt theo giới hạn. Nhờ vậy một `reason` chứa xuống dòng **không bao giờ** tạo ra một dòng `value` giả. Đây là bất biến phải có test (§12).
- Chỉ `ip` và `cidr` trong `.txt`; mục `domain` không bao giờ xuất hiện ở `.txt` (một firewall không hiểu domain sẽ bỏ qua hoặc lỗi cả danh sách).

### 4.3 Biến thể `.json`

```json
{
  "generated_at": "2026-11-09T07:12:41Z",
  "version": "9f2c4a1e03b7d5a8",
  "entries": [
    {
      "value": "203.0.113.77",
      "kind": "ip",
      "source": "Rule: Known-bad IP: add to the block list",
      "reason": "IPsum, confidence 85",
      "added_at": "2026-11-09T07:10:02Z",
      "expires_at": "2026-11-10T07:10:02Z"
    }
  ]
}
```

`version` = 16 ký tự hex đầu của SHA-256 nội dung `entries` đã chuẩn hoá (cũng là cơ sở cho `ETag`).

### 4.4 Biến thể `.domains.txt`

Mỗi dòng một domain, comment `#` như `.txt`. Pi-hole chấp nhận danh sách domain một-tên-một-dòng; AdGuard Home chấp nhận cú pháp danh sách chặn DNS. Dùng dạng domain thuần để cả hai đọc được; cú pháp `||example.org^` của AdGuard là câu hỏi mở (§12).

## 5. TTL, loại bỏ, và nhất quán

- **Hết hạn được áp dụng lúc phục vụ**, không chỉ lúc dọn: khi tạo response, core lọc các mục có `expires_at <= now`. Một firewall kéo lúc 00:00:01 không nhận mục hết hạn 00:00:00 dù job dọn chưa chạy.
- Job dọn (`ttl_removed` trong nhật ký phản ứng, D-48) xoá mục khỏi kho và ghi một dòng vào chuỗi hash.
- Gỡ chủ động (hoàn tác, D-51): hành động `blocklist remove {ip}` xoá mục ngay; mọi nguồn tạo ra cùng một `value`: mục chỉ gỡ khi **không còn** hành động nào còn hiệu lực giữ nó (đếm tham chiếu theo `value`; mục lấy `expires_at` xa nhất).
- Thêm trùng một `value`: gộp (không tạo dòng thứ hai), cập nhật `expires_at` thành giá trị lớn hơn.
- Danh sách không bao giờ chặn (D-44): **kiểm lại lúc phát hành**, ngoài kiểm lúc thêm. Một mục khớp danh sách (gateway, DNS, máy chủ xác thực, chính hộp, IP quản trị, dịch vụ khách khai) bị **loại khỏi phản hồi** và ghi `refused` vào nhật ký; đồng thời loại mọi loopback, link-local, multicast, `0.0.0.0/8`, và dải RFC1918/CGNAT `100.64.0.0/10` (tránh khoá chính LAN do tập IOC bị đầu độc; cùng tinh thần D-25).
- Giới hạn mục mỗi giờ theo quy tắc và cầu dao chung (D-44, D-51): thuộc engine phản ứng, ngoài spec này.

## 6. Header phản hồi và bộ nhớ đệm

| Header | Giá trị | Lý do |
|---|---|---|
| `ETag` | `"<version>"` (16 hex đầu của SHA-256 nội dung) | firewall thông minh hỏi lại bằng `If-None-Match` → `304` |
| `Last-Modified` | thời điểm thay đổi gần nhất của tập mục | |
| `Cache-Control` | `no-store` (D-88: URL chứa token, không lưu ở đâu cả) | URL chứa token; proxy chung không được lưu; luôn xác thực lại |
| `Content-Type` | như §4 | |
| `X-Content-Type-Options` | `nosniff` | |
| `Referrer-Policy` | `no-referrer` | |
| `Content-Length` | luôn có | một số firewall nhúng không hiểu chunked |

Không dùng `Content-Encoding` (nhiều client nhúng không giải nén). Nhiều firewall bỏ qua điều kiện và luôn tải lại: server luôn trả đủ `200` khi không có `If-None-Match`.

**Fail-static (quan trọng).** Khi core không đọc được kho (DB lỗi), phục vụ `503 Service Unavailable` với `Retry-After: 60`, **không bao giờ** trả danh sách rỗng: nhiều firewall coi rỗng là "gỡ hết" nhưng giữ bản cũ khi nhận lỗi. Khi module `response` tắt: `404` (SYS-5; dữ liệu giữ nguyên, firewall giữ bản cũ theo cách riêng của nó).

## 7. Giới hạn

| Mục | Giới hạn mặc định |
|---|---|
| Số mục tối đa | 10 000 (đạt giới hạn: từ chối thêm mục mới, ghi `refused`, báo qua kênh; không âm thầm cắt) |
| Cỡ phản hồi | ≤ 1 MiB (mục đủ chỗ vì dòng comment tối đa ~400 byte) |
| `source` / `reason` | 120 / 200 ký tự |
| TTL tối đa của mục | theo quy tắc: duyệt sẵn ≤ 24 giờ (D-51); thủ công ≤ 30 ngày; `null` (không hết hạn) chỉ khi người duyệt chọn rõ |
| Thêm mục | ≤ 100/giờ toàn hộp (cầu dao chung D-51 chặn sớm hơn) |

Giới hạn của từng nền tảng khác nhau theo kiểu máy và phiên bản (FortiGate, Palo Alto EDL, pfSense alias, MikroTik address-list). Con số 10 000 là trần an toàn của Vedette, **chưa được đối chiếu** với tài liệu từng hãng: bước này phải làm khi xây (theo D-23: xác minh bằng nguồn chính thức) và ghi vào `guides.ts`.

## 8. Cách từng thiết bị kéo

Hướng dẫn từng bước đã có trong GUI (`guides.ts`); bảng này tóm tắt điều kiện của spec.

| Thiết bị | Cơ chế | Biến thể | Chu kỳ (hướng dẫn GUI) | Ghi chú |
|---|---|---|---|---|
| FortiGate | Security Fabric → External Connectors → Threat Feeds → IP Address | `.txt` | 5 phút | tắt HTTP basic auth (token là credential); tạo policy `DENY` có đích là feed; nhập CA hộp để khỏi lỗi chứng chỉ |
| Palo Alto | Objects → External Dynamic Lists, kiểu IP List | `.txt` | Every Five Minutes | Certificate Profile chứa CA hộp; Commit sau khi tạo rule |
| pfSense | Firewall → Aliases → URLs, `URL Table (IPs)` | `.txt` | 1 ngày (thấp nhất pfSense cho) | nhập CA hộp; floating rule `Block`, hướng out |
| OPNsense | Firewall → Aliases, `URL Table (IPs)` | `.txt` | ≥ 1 giờ (OPNsense nhận ngày+giờ) | rule `Block` trên LAN |
| MikroTik | script `/tool fetch` + scheduler, nạp vào `address-list` | `.txt` | 5 phút | script bỏ dòng `#`; `check-certificate=no` vì tự ký (rủi ro: kẻ chen giữa LAN lấy được token **và** chèn danh sách); khuyến nghị nhập CA và bật kiểm chứng chỉ |
| Pi-hole | Adlists, thêm URL | `.domains.txt` | theo lịch Pi-hole (gravity) | cần CA hộp tin cậy trong Pi-hole |
| AdGuard Home | DNS blocklists, thêm URL | `.domains.txt` | chu kỳ của AdGuard (≥ 1 giờ) | |

pfSense/OPNsense: chu kỳ dài (1 ngày/1 giờ) nghĩa là **độ trễ chặn** tới hàng giờ/ngày; mục TTL ngắn hơn chu kỳ kéo có thể chưa kịp có hiệu lực. GUI nên nói điều này. Thiết bị không có API/SSH và không kéo URL (modem nhà mạng) không áp dụng (D-44).

Với lệnh tạo alias qua API (pfSense `Vedette_Blocklist`, OPNsense) thì dùng gói hành động đẩy, không phải spec này (xem `action-packs.md`).

## 9. Xoay token

- `POST /response/blocklist/token` (admin, ghi `core_audit` + nhật ký phản ứng `blocklist_token`): sinh token mới, **vô hiệu token cũ ngay** (mock: `blockMeta` thay token, `last_fetch` về `null`), trả URL mới.
- Vì mọi firewall phải đổi URL, GUI hiện cảnh báo trước khi quay (`regenerateBody`). **Không có giai đoạn chuyển tiếp** hai token cùng sống (giữ spec đơn giản; câu hỏi mở §12).
- Dấu hiệu cần quay: nghi lộ URL, nhân sự rời đi, firewall bị thay.
- Sau khi quay, mọi request bằng token cũ nhận `404` và tăng bộ đếm "kéo bằng token cũ" để quản trị viên thấy thiết bị nào chưa cập nhật (bộ đếm theo IP nguồn, không lưu token cũ nguyên văn).
- Quay lại cũng khởi động lại `last_fetch` nên GUI hiện "never fetched" cho tới khi firewall kéo.

## 10. Sequence

```mermaid
sequenceDiagram
    participant E as Engine phản ứng
    participant C as core (response)
    participant F as Firewall
    E->>C: blocklist_add {ip, ttl} (đã được duyệt)
    C->>C: kiểm không-bao-giờ-chặn, validate netip, gộp trùng
    C-->>E: executed (mục + expires_at)
    loop mỗi chu kỳ của firewall
        F->>C: GET /response/blocklist/<token>.txt (If-None-Match)
        alt không đổi
            C-->>F: 304
        else có đổi
            C-->>F: 200 text/plain + ETag
        end
        F->>F: nạp địa chỉ, áp dụng rule DENY
    end
    Note over C: hết TTL: job dọn xoá mục;<br/>lần kéo sau không còn mục đó
```

## 11. Xử lý lỗi

| Điều kiện | Phản hồi |
|---|---|
| Token sai / đã quay | `404 Not found` (text/plain) |
| Module `response` tắt | `404` |
| Kho không đọc được | `503` + `Retry-After: 60` (không bao giờ danh sách rỗng) |
| Quá giới hạn tốc độ | `429` + `Retry-After` |
| Method khác `GET`/`HEAD` | `405` |
| Giá trị thêm vào sai kiểu (không phải IP/CIDR/domain hợp lệ) | từ chối ở bước **thêm** (hành động fail), không bao giờ vào danh sách |

## 12. Cân nhắc bảo mật (ánh xạ SYS)

| SYS | Áp dụng |
|---|---|
| SYS-1 | Không có đường thực thi; danh sách là dữ liệu thuần |
| SYS-2 | `value` validate bằng `netip`/IDNA trước khi lưu; `source`/`reason` làm sạch; token theo regex |
| SYS-3 | Thêm/gỡ/quay token ghi `core_audit` + nhật ký hash-chain của phản ứng (D-48) |
| SYS-4 | Token lưu băm, không log URL, không xuất trong export/báo lỗi (GUI chỉ 4 ký tự cuối) |
| SYS-5 | Module tắt → không route |
| SYS-6 | IOC/hit là dữ liệu không tin cậy (có thể đầu độc để chặn Google, bài học UPDATES §5): never-touch + danh sách loại trừ private/CGNAT + bài kiểm top-10k domain trước khi dùng feed + engine cần duyệt |
| SYS-7 | Kéo chỉ tới được từ LAN; không phải luồng ra Internet nên không thêm PRIVACY |
| SYS-8 | AI chỉ **đề xuất** hành động (cờ "AI được đề xuất", D-51); mục vào danh sách chỉ sau duyệt của người |

Rủi ro đã biết: (a) lộ URL cho phép người trong LAN đọc danh sách (không ghi được); danh sách chỉ lộ địa chỉ độc hại đã chặn, không lộ dữ liệu khách; (b) token trong URL dễ nằm trong lịch sử/log của firewall: chấp nhận vì đó là cơ chế duy nhất các thiết bị hỗ trợ; (c) danh sách bị đầu độc dẫn tới tự DoS: lớp bảo vệ ở §5; (d) kẻ chen giữa LAN: TLS + CA ghim, trừ MikroTik script nếu để `check-certificate=no`.

**Test hợp đồng (rule `contracts.md`) phải có:** mục có `reason` chứa `\n198.51.100.1` không tạo dòng giá trị mới; mục hết hạn không nằm trong phản hồi; `503` khi kho lỗi thay vì rỗng; token cũ `404` ngay sau khi quay; mục trùng `never-touch` không xuất hiện.

## 13. Versioning

- Đường dẫn gắn `/api/v1`. Định dạng `.txt` là **hợp đồng cứng** vì firewall của khách không cập nhật theo Vedette: không đổi cú pháp dòng; chỉ được thêm dòng comment `#`.
- `.json` được thêm trường (tương thích tiến); đổi nghĩa/bỏ trường = `/api/v2/…` chạy song song một thời gian.
- Đổi token không đổi định dạng.

## 14. Câu hỏi mở

1. **`kind` và `.domains.txt` chưa có trong mock** (mock chỉ IP, `ipOnly` trong locale nói rõ "IP addresses only"). D-44 nói "chặn IP/domain đích" và D-51 nhắc Pi-hole/AdGuard. Cần quyết: thêm `kind` + biến thể domain ở M2 (đổi FE một chút), hay giữ IP-only và để Pi-hole/AdGuard qua gói hành động đẩy.
2. Cú pháp danh sách của AdGuard Home (`||domain^` hay domain thuần) và Pi-hole: đối chiếu tài liệu chính thức khi xây.
3. Cần hai token chồng nhau trong thời gian chuyển (grace) khi quay, hay cắt ngay (spec này: cắt ngay)?
4. Trần 10 000 mục, và giới hạn từng hãng chưa đối chiếu (§7).
5. Có cần danh sách theo hướng **nguồn** (cô lập máy LAN) tách riêng không (spec này: không, dùng đẩy).
6. Token 128 bit đủ không so với 256 bit; mock đang dùng 16 byte hex.
7. MikroTik: khuyến nghị nhập CA thay `check-certificate=no` trong hướng dẫn GUI.
8. Chu kỳ kéo thật của pfSense/OPNsense quá dài so với TTL ngắn; có nên cảnh báo trong GUI khi TTL < chu kỳ không.
