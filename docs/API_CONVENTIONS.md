# Quy ước API (M2-0)

Trạng thái: **bản thảo spec, chưa có backend.** Nguồn, theo thứ tự thắng: `docs/DECISIONS.md` (D-18 spec-first, D-22, D-46, D-48, D-51…) → `docs/MODULE_CONTRACTS.md` (SYS-1…8) → mock API hiện tại (`web/src/features/*/contract.ts`, `mocks.ts`, `web/src/mocks/*.ts`; mock là hợp đồng thực tế) → `api/openapi.json` (sinh ra từ contract: **267 thao tác**, 12 tag) → `docs/ARCHITECTURE.md` §5 (đã cũ).
Số liệu trong file này (số thao tác, mã lỗi, vai tối thiểu) **đo từ mã ngày 2026-11-09**, không đoán; chỗ tôi tự quyết ghi **[ĐX]** (đề xuất), chỗ còn thiếu nằm ở "Câu hỏi mở". Kiểu dữ liệu và bảng DB xem `docs/DATA_MODEL.md`.
Tên endpoint, mã lỗi, tên trường giữ tiếng Anh; văn xuôi tiếng Việt (D-28).

## 1. Tài nguyên: đặt tên, phương thức, mã trạng thái

**Gốc:** `/api/v1` (`servers: [{url: '/api/v1'}]`). Nội dung `application/json; charset=utf-8`, trừ tải tệp (mục 11).

| Quy tắc | Chi tiết (đo từ `openapi.json`) |
|---|---|
| Phân nhóm theo module | Phần đầu đường dẫn = nhóm của module: `/ai`, `/core`, `/exposure`, `/feeds`, `/findings`, `/honeypot`, `/inventory`, `/logs`, `/notify`, `/reports`, `/response`, `/scans`. Ngoại lệ có chủ đích, đều thuộc `core` hoặc `inventory`: `/auth/*`, `/me`, `/modules`, `/setup` (core); `/install/*`, `/intake/*` (inventory, tệp cài và nhận dữ liệu agent). `/findings` thuộc module `mitigation` (README `features/findings`); `/scans` (số nhiều) thuộc module `scan`. |
| Số thao tác mỗi nhóm | core 57 · ai 52 · response 39 · inventory 29 · honeypot 15 · feeds 13 · scan 13 · notify 12 · exposure 11 · reports 11 · logs 10 · findings 5 (GET 103, POST 97, PUT 33, DELETE 22, PATCH 12). |
| Danh từ, kebab-case | Đường dẫn là danh từ số nhiều cho tập hợp (`/core/users`, `/inventory/devices`, `/honeypot/decoys`), số ít cho đối tượng cấu hình một-bản (`/core/general`, `/core/privacy`, `/scans/config`, `/logs/siem`, `/honeypot/config`). Đoạn đường dẫn kebab-case (`box-ip`, `chat-decision`, `sample-data`, `auth-options`). Tham số đường dẫn `{id}`, trừ khoá tự nhiên: `{type}` (kênh), `{service}` (bẫy), `{date}`, `{token}`. |
| Tên trường, tham số | JSON và query: `snake_case`. Định danh **của một thứ** (id module, kênh, việc AI, loại): kebab-case (`explain-finding`, `zalo-personal`, `sensor-passive`, `netconf-restconf`). **Trạng thái / enum trạng thái**: snake_case (`false_positive`, `auto_stopped`, `blocked_by_hook`). |
| Hành động = POST vào tài nguyên con | `POST /{tài nguyên}/{id}/{động từ}`: `verify`, `scan`, `stop`, `approve`, `reject`, `rollback`, `test`, `resend`, `commitment`, `status`, `applied`, `suspicious`, `reset-password`, `2fa/reset`. Hành động trên cả tập hợp: `POST /scans/runs`, `/response/rules/run`, `/response/rules/simulate`, `/feeds/parse-test`, `/ai/hooks/test`, `/ai/profiles/test`. Không có động từ trong đường dẫn của GET/PUT/DELETE. |
| GET | Đọc, không tác dụng phụ (kể cả `GET /response/approve/{token}`: chỉ hiện trạng thái). Tải tệp cũng là GET (mục 12). |
| POST | Tạo mới (trả 201), hoặc hành động có tác dụng phụ (trả 200/202/204). |
| PUT | **Thay cả đối tượng** (cấu hình, hồ sơ, quy tắc, kênh). Trả 200 + đối tượng đã lưu. Bí mật bỏ trống = giữ bí mật đã lưu (SYS-4). |
| PATCH | **Sửa một phần** (`/modules/{id}`, `/core/users/{id}`, `/core/account`, `/core/updates`, `/inventory/devices/{id}`, `/honeypot/*`, `/notify/incidents/{id}`). |
| Ngoại lệ PUT-như-PATCH đang có | `PUT /feeds/sources/{id}`, `PUT /ai/memory/{id}`, `PUT /scans/config`, `PUT /ai/knowledge/{id}` nhận thân mọi trường tuỳ chọn. Giữ nguyên (đã nằm trong hợp đồng); **endpoint mới** theo quy tắc PUT = đủ, PATCH = một phần. |
| DELETE | Xoá. 204 không thân; ngoại lệ có thân: `DELETE /ai/profiles/{id}` trả `{cleared_jobs}` (200) vì xoá hồ sơ làm trống phân việc. |

### Mã trạng thái (đo trong mock)

| Mã | Dùng cho | Ghi chú |
|---|---|---|
| 200 | Đọc, sửa, hành động trả tài nguyên mới | Hầu hết `POST …/approve\|reject\|status\|verify` trả tài nguyên đã cập nhật |
| 201 | Tạo (16 chỗ trong mock) | Đã khai bằng `status: 201` trong `contract.ts` và có trong `openapi.json` (WP-06; test `contract.test.ts` đối chiếu mock). Hai endpoint trả 201 hoặc 200 tuỳ trường hợp (`POST /exposure/box-ip/verify`, `POST /response/ai/proposals`) giữ mặc định 200 và nói rõ trong `summary`. Kèm `Location` **[ĐX]** |
| 202 | Việc dài chạy nền (`POST /core/updates/os/install`, khai `status: 202`) | Thân = tài nguyên "lần chạy" (`id`, `status`); theo dõi bằng `GET …/run` hoặc SSE (mục 11) |
| 204 | Xoá, hành động không có kết quả | Không thân |
| 400 | Dữ liệu vào sai ở biên (SYS-2) | Gần như mọi lỗi kiểm tra (211 mã, mục 3). `invalid_credentials` khi đăng nhập sai cũng là 400, **không** phải 401 |
| 401 | Chưa đăng nhập / phiên hết hạn (`unauthenticated`), hoặc cần mã 2 bước (`twofa_required` ở `POST /auth/login`, kèm `method`) | |
| 403 | Đủ phiên nhưng không đủ quyền hoặc bị cấm theo trạng thái (`forbidden`, `disabled`, `tool_not_allowed`, `token_expired`, `approver_not_listed`…) | |
| 404 | Không có đối tượng (`not_found`, 51 endpoint) hoặc liên kết sai (`unknown`) | Không phân biệt "không tồn tại" và "không được xem" với token công khai |
| 409 | Trạng thái hiện tại không cho phép (64 mã: `already_*`, `busy`, `expired`, `not_pending`, `ip_in_use`…) | Thao tác có thể thành công sau khi người dùng sửa trạng thái |
| 413 | Tệp/thân quá lớn (`too_large` ở `POST /feeds/parse-test`) | Mock còn trả 400 `too_large` ở 3 endpoint tải tệp: thống nhất về 413 **[ĐX]** |
| 422 | Dịch vụ ngoài từ chối thông tin hợp lệ về hình thức (`wazuh_auth`) | Hiện đúng 1 chỗ; dùng cho "đúng dạng nhưng bên kia từ chối" |
| 429 | Giới hạn tần suất / trần (`rate_limited`, `resend_too_soon`, `too_many_codes`, `daily_cap`) | Kèm `Retry-After` (mục 8) |
| 502 / 503 | Hệ thống ngoài không tới được / kênh cần thiết đang hỏng (`unreachable`, `address_refused`, `device_error`, `pin_mismatch`, `discovery_failed`, `wazuh_unreachable`, `twofa_email_unavailable`, `server_busy`) | `server_busy` kèm `Retry-After` (mục 8) |

**Bất biến:** (1) mọi mutation ghi `core_audit` (SYS-3); (2) thân phản hồi của PUT/PATCH/POST-hành-động là **tài nguyên sau khi đổi**, để client không phải gọi lại GET (ngoại lệ có sẵn: `PATCH /core/account` và vài POST trả `{ok:true}`; giữ nguyên); (3) `GET` không bao giờ ghi, trừ `last_fetch` của danh sách chặn (mục 11.3) và các GET xuất dữ liệu (`…/export*`) ghi một dòng `core_audit` không chứa dữ liệu (D-72).

### Danh sách bọc trong thân

Danh sách trả đối tượng, không phải mảng trần (cho phép thêm `total`, `next_cursor` sau này mà không phá). Khoá bọc **đang khác nhau** và là một phần hợp đồng từng endpoint: `items` (đa số), `channels` (`/notify/channels`), `incidents`, `sensors`, `modules`, `events` (`/logs/events`), `sources` (`/logs/sources`, cùng `box`), `sends`. **Endpoint mới dùng `items`.** Không đổi khoá của endpoint cũ (phá hợp đồng).

## 2. Định dạng dữ liệu, thời gian, ID

| Kiểu | Quy tắc |
|---|---|
| Thời điểm | ISO-8601 UTC đuôi `Z` (`2026-11-09T04:12:30.123Z`), khớp `z.iso.datetime()`. Máy chủ **từ chối** thời điểm có offset (`+07:00`) ở thân và query (`bad_from`, `bad_to`). Phản hồi luôn có 3 chữ số ms. |
| Ngày | `YYYY-MM-DD` (`date_added`, snapshot `{date}`). |
| Giờ trong ngày | `HH:MM` 24 giờ (`/^([01]\d|2[0-3]):[0-5]\d$/`), hiểu theo `core_org.timezone` (IANA, mặc định `Asia/Ho_Chi_Minh`). Cửa sổ qua nửa đêm hợp lệ (`from=23:00`, `to=05:00`); `from == to` bị từ chối (`empty_window`, `bad_quiet`). |
| Khoảng thời gian | Số nguyên, đơn vị nằm trong tên trường: `*_min`, `*_hours`, `*_days`, `*_ms`, `resend_after` (giây). Không dùng chuỗi `"15m"`. |
| Độ tin cậy | số thực 0–1 (`confidence`, `score`). |
| ID | chuỗi `^[\w.-]{1,96}$`, do máy chủ cấp, **không suy luận cấu trúc** (client coi là mờ). |
| IP, CIDR | IPv4 chấm thập phân; dải mạng **bắt buộc có độ dài tiền tố** (D-32, `no_prefix`, `host_bits`). Kiểm bằng `netip` ở biên (SYS-2). IPv6 chưa có trong hợp đồng. |
| Chuỗi bí mật | Không bao giờ trong phản hồi: chỉ `*_last4`. Gửi lên bằng trường `secret`/`api_key`/`password`/`private_key`; bỏ trống = giữ nguyên. |
| Chuỗi người dùng | Cắt khoảng trắng hai đầu; giới hạn độ dài ghi trong `contract.ts`; từ chối ký tự điều khiển. Dữ liệu từ feed/log/agent không bao giờ nội suy vào lệnh (SYS-1, SYS-6). |
| Tên trong cấu hình | `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$` khi tên dùng làm định danh (SYS-2); tên hiển thị cho người (hồ sơ, quy tắc) cho phép chữ có dấu và khoảng trắng trong giới hạn từng trường. |

## 3. Lỗi

### 3.1 Định dạng

```json
{ "error": { "code": "ip_in_use", "message": "IP 192.168.10.21 belongs to device NAS-PHOTOS in the inventory. Pick an unused address." } }
```

- `code`: `snake_case`, ổn định, **dành cho máy** (client rẽ nhánh theo `code`, không theo `message`). `message`: tiếng Anh (D-28), nói **chuyện gì sai và sửa thế nào**, an toàn để hiện nguyên văn cho người dùng; không chứa bí mật, không rò thông tin nội bộ (đường dẫn, câu SQL, stack).
- **Trường mở rộng** nằm cạnh `code`/`message` trong `error` (client đọc vào `ApiError.details`): `missing: string[]` (`missing_dependencies`, module cần bật trước); `method: 'app'|'email'`, `sent_to`, `resend_after` (`twofa_required`); `retry_after: number` (giây; `resend_too_soon`). **Chỉ thêm, không bỏ.** `preview_code` trong `twofa_required` của mock là **chỉ có ở mock**: backend không bao giờ trả mã trong lỗi.
- Trường mở rộng đề xuất cho lỗi kiểm tra: `field: string` (tên trường sai) **[ĐX]**; thêm dần, không bắt buộc. Lỗi do bộ kiểm schema sinh tự động (`400 invalid`) luôn kèm `field` là đường dẫn đầy đủ (`active.days[0]`); thân yêu cầu sai kiểu hoặc có khoá lạ (`400 invalid`) cũng kèm `field` (không kèm chỉ số phần tử mảng, vì bộ giải mã sinh tự động không báo; khoá lạ không hợp lệ thì không được lặp lại); ranh giới giữa `invalid` và mã riêng của module: D-73.
- Tạo lỗi chỉ qua một hàm (`fail(status, code, message)` trong mock, tương đương trong Go); handler không tự dựng JSON lỗi.
- Hợp đồng OpenAPI khai `default` → `Error` cho mọi thao tác (`components.schemas.Error`); **chưa** khai từng mã lỗi theo thao tác (mục 12, câu hỏi mở 2).

### 3.2 Quy tắc đặt mã mới

1. Tìm trong mục 3.3 trước; dùng lại mã cùng nghĩa.
2. Mã mới `snake_case`, nêu **điều kiện** chứ không nêu cách sửa; lỗi kiểm tra trường mới ưu tiên `invalid_<trường>` (kèm `field`).
3. Chọn HTTP theo bảng mục 1 (kiểm tra → 400; trạng thái → 409; quyền → 403; vắng → 404).
4. Thêm vào bảng 3.3 trong **cùng commit**; test hợp đồng (mục 12.1) so mã trả về với bảng này.
5. Một mã có thể xuất hiện ở nhiều endpoint với **cùng** HTTP và cùng nghĩa; hai nghĩa khác nhau thì hai mã.

### 3.3 Danh mục mọi mã lỗi đang dùng

Trích **tĩnh** từ mọi lời gọi `fail(`/`refuse(`/hàm `bad(`/`{status, code}` trong `web/src/features/*/mocks.ts`, `*/state.ts`, `*/osMock.ts`, `*/sourcesMock.ts`, `*/harness-mocks.ts`, `*/emailCode.ts`, `*/logExport.ts`, `*/activity.ts` và `web/src/mocks/*.ts` (2026-11-09): **293 mã** (từ mock), cộng 5 mã chỉ backend thêm ở WP-04b phần 2 (`invalid_setup_code`, `sample_unavailable`, `invalid_from`, `invalid_to`, `misdirected_request`) và 14 mã chỉ backend thêm ở WP-07b phần 2 (lỗi của `vedette-host` và của việc core ghi snapshot: `not_appliance`, `host_unreachable`, `host_error`, `no_check_yet`, `dpkg_locked`, `dpkg_inconsistent`, `low_disk`, `rebooting`, `reboot_limit_reached`, `snapshot_rejected`, `snapshot_failed`, `apt_failed`, `health_check_failed`, `effect_not_verified`; bảng ánh xạ mã host → mã API ở `modules/core/CONTRACT.md` INV-18) và 1 mã chỉ backend thêm ở WP-13b lát 13b-9 (`ai_paused`: cổng tạm dừng của đề xuất AI; mock có từ `response/ai.ts`, tệp này nằm ngoài danh sách trích): 313. Màn hình Box network (S-CORE-8, 2026-11-10): `networkMock.ts` không nằm trong danh sách tệp trích tĩnh ở trên nên 21 mã của nó chưa có trong bảng, được thêm ở đây (`management_count`, `management_fixed`, `span_count`, `span_on_management`, `change_pending`, `confirm_required`, `nothing_pending`, `address_conflict`, `net_backend_unsupported`, `invalid_roles`, `invalid_static`, `dhcp_no_static`, `gateway_outside_subnet`, `gateway_not_host`, `invalid_span`, `no_interface`, `nothing_selected`, `bad_filter`, `bad_limit`, `default_no_servers`, `bad_ntp`), cùng 11 mã chỉ backend thêm ở lát `core` của màn hình đó (`span_has_address`, `span_not_physical`, `connectivity_check_failed`, `reverted_by_reboot`, `management_not_set`, `revert_failed`, `netplan_apply_failed`, `ntp_not_applied`, `arp_probe_failed`, `pending_invalid`, `confirm_failed`; bảng ánh xạ mã host → mã API ở `modules/core/CONTRACT.md` INV-21 và INV-25): 345; cùng 2 mã thêm theo issue #115 (`ip_not_current` 409 của `exposure` INV-13 / `POST /scans/runs`, `scanner_unavailable` 503 của `scan`, D-125): 347; cùng `provider_error` 502 của `ai` (D-129): **348**. Cột "Endpoint dùng" là handler gần nhất chứa lời gọi; với mã sinh từ hàm kiểm tra dùng chung, ghi `module <tên> (validator dùng chung)` (đó là hạn chế của cách trích tĩnh) (mục 12 đề xuất khai `errors` trong `contract.ts` để bảng này sinh tự động). Thông điệp là bản mẫu tiếng Anh trong mock.

Mã dựng bởi hàm kiểm tra có bảng riêng (`response/state.ts` `checkCatalog`: `invalid`, `read_only`; `feeds/parsers.ts`: `too_large`, `bad_config`, `bad_sample`) đã được thêm tay.

#### HTTP 400 (224 mã)

| Code | HTTP | Thông điệp mẫu (EN, từ mock) | Endpoint dùng |
|---|---|---|---|
| `allow_required` | 400 | Add at least one entry to the allow-list. Only hosts, addresses or commands on this list. | `POST /core/connections`; `PUT /core/connections/{id}` |
| `approvals_unsupported` | 400 | This channel cannot take approvals. It sends a link that opens Vedette instead. | module notify (validator dùng chung) |
| `approvers_required` | 400 | Add at least one approver, or turn off "Approve actions from this channel". | module notify (validator dùng chung) |
| `bad_action` | 400 | Choose one of: patched, mitigated, false positive, not relevant, or reopen. | `POST /findings/{id}/status` |
| `bad_active` | 400 | Active scan settings are missing. | `PUT /inventory/settings` |
| `bad_answer` | 400 | answer must be have or not_relevant. | `POST /feeds/weekly/{id}` |
| `bad_app_token` | 400 | The app-level token starts with xapp- and needs the connections:write scope. Copy it again from Basic Information. | module notify (validator dùng chung) |
| `bad_approver_address` | 400 | The approver address is not valid for this channel. | module notify (validator dùng chung) |
| `bad_body` | 400 | enabled must be true or false. | `PATCH /honeypot/decoys/{id}`; `PATCH /honeypot/traps/{service}` |
| `bad_bot_token` | 400 | The bot token starts with xoxb-. Copy it from OAuth & Permissions after installing the app. | module notify (validator dùng chung) |
| `bad_channel_id` | 400 | A Slack channel ID looks like C04ABCDEF12. Open the channel details in Slack and copy the ID at the bottom. | module notify (validator dùng chung) |
| `bad_chat_id` | 400 | Chat ID is a number (groups look like -1001234567890) or a public @channel_name. Send the bot a message, then open getUp | module notify (validator dùng chung) |
| `bad_cidr` | 400 | "${r.slice(0, 30)}" is not a valid network range. Enter something like 192.168.10.0/24. | `PUT /inventory/settings` |
| `bad_config` | 400 | Parser configuration is not valid (for example, JSONPath must start with $). | `POST /feeds/parse-test` |
| `bad_days` | 400 | Scan days must be Monday to Sunday. | `PUT /inventory/settings`; `PUT /logs/retention` |
| `bad_events` | 400 | Choose at least one event type to forward. | module logs (validator dùng chung) |
| `bad_exclusion` | 400 | Exclusion "${x.slice(0, 30)}" is not valid. Enter an IP (192.168.10.10) or a valid range (192.168.10.0/28). | `PUT /inventory/settings` |
| `bad_expiry` | 400 | Choose how long the token works: 1 to 365 days, or 0 for no expiry. | `POST /inventory/agents/tokens` |
| `bad_ext` | 400 | Choose the file type: .docx or .xlsx. | `POST /honeypot/tokens` |
| `bad_flag` | 400 | suspicious must be true or false. | `POST /inventory/devices/{id}/suspicious`; `PUT /inventory/notify-new` |
| `bad_format` | 400 | Choose a format: syslog, CEF or JSON webhook. | module logs (validator dùng chung) |
| `bad_fragile` | 400 | fragile must be true or false. | `PATCH /inventory/devices/{id}` |
| `bad_from` | 400 | The sender email is not valid, for example alerts@company.com. | module notify (validator dùng chung) |
| `bad_header` | 400 | The first row must be column headers with at least a name or product column. Download the template to see the format. | `POST /inventory/import` |
| `bad_host` | 400 | The SIEM server must be an IP address or a domain name, for example 192.168.10.50 or siem.company.com. | module logs, notify (validator dùng chung) |
| `bad_hostname` | 400 | Enter a fake hostname, for example FILESRV-OLD. Pick a name that looks like an old file server in your company. | `POST /honeypot/decoys`; `PUT /honeypot/config` |
| `bad_interface` | 400 | Network interface must be one of: ${s.interfaces.join(', ')}. Backend [ĐX]: cũng host `iface_unknown`. | `PATCH /inventory/sensors/{id}`; `PUT /core/network/span` |
| `bad_interval` | 400 | Choose how often to sync: every 5, 15, 60, 360 or 1440 minutes. | module inventory (validator dùng chung) |
| `bad_ip` | 400 | Enter a secondary IP for the decoy, for example 192.168.10.240. Pick an address no device uses. | `POST /honeypot/decoys`; `PUT /honeypot/config` |
| `bad_item` | 400 | Invalid item to apply. | `POST /findings/{id}/applied` |
| `bad_key` | 400 | The SSH private key is not valid. | `POST /scans/credentialed` |
| `bad_kind` | 400 | Device type must be one of: ${KINDS.join(', ')}. | `PATCH /inventory/devices/{id}`; `POST /inventory/agents/tokens` |
| `bad_kinds` | 400 | The list of fragile device types is not valid. | `PUT /inventory/settings` |
| `bad_label` | 400 | The channel label can be at most 80 characters. | module notify (validator dùng chung) |
| `bad_name` | 400 | The name may only contain letters without accents, digits, spaces, hyphens, dots or underscores, start with a letter or  | `POST /honeypot/tokens`; `POST /inventory/agents/tokens` |
| `bad_notes` | 400 | Notes are at most 2000 characters. | `PATCH /inventory/devices/{id}` |
| `bad_oa_id` | 400 | OA ID is a string of digits, shown in the Official Account management page. | module notify (validator dùng chung) |
| `bad_password` | 400 | The password is too long (up to 200 characters). | module inventory (validator dùng chung) |
| `bad_personality` | 400 | Choose what the decoy should look like. | `POST /honeypot/decoys` |
| `bad_plant_at` | 400 | Say where you will plant it, for example \\\\SRV-FILE\\HR or "Password manager". This reminds you where to look when it  | `POST /honeypot/tokens` |
| `bad_port` | 400 | The port must be a number from 1 to 65535. Usually 514 (UDP or TCP) or 6514 (TLS). | `POST /scans/credentialed` |
| `bad_product` | 400 | Vendor and product are at most 64 characters each and cannot contain < or >. | module inventory (validator dùng chung) |
| `bad_proto` | 400 | This device type cannot send logs with the chosen protocol. Pick another protocol from the list. | module logs (validator dùng chung) |
| `bad_quiet` | 400 | The start and end times must not be the same. | `PUT /notify/rules` |
| `bad_ranges` | 400 | The list of network ranges is missing. | `PUT /inventory/settings` |
| `bad_rate` | 400 | Scan rate is 1 to 1000 packets per second. | `PUT /inventory/settings` |
| `bad_regular_scan` | 400 | Regular scans must be: follow type setting, allow or never. | `PATCH /inventory/devices/{id}` |
| `bad_sample` | 400 | The sample text could not be read with this parser. | `POST /feeds/parse-test` |
| `bad_secret` | 400 | The signing key needs at least 16 characters. Press Generate if you want a random one. | module logs, notify (validator dùng chung) |
| `bad_security` | 400 | Choose an encryption type: STARTTLS, SSL/TLS or none. | module notify (validator dùng chung) |
| `bad_service` | 400 | Choose a service: SMB, RDP, SSH, MSSQL or HTTP. | `POST /honeypot/test-hit` |
| `bad_severity` | 400 | Choose a minimum severity: Critical, High, Medium or Low. | module notify (validator dùng chung) |
| `bad_signature` | 400 | Invalid signature. The bundle was modified or not signed by the project. The box does not install unsigned packages. | `POST /core/updates/bundle` |
| `bad_skill` | 400 | skill must be explain or mitigation-config. | `POST /findings/{id}/ai` |
| `bad_span` | 400 | span must be true or false. | `PATCH /inventory/sensors/{id}` |
| `bad_status` | 400 | Status must be new, acknowledged or resolved. | `PATCH /notify/incidents/{id}` |
| `bad_time` | 400 | Time must look like 23:00. | `PUT /inventory/settings`; `PUT /notify/rules` |
| `bad_to` | 400 | A recipient email is not valid. Separate several recipients with commas. | module notify (validator dùng chung) |
| `bad_token` | 400 | A bot token looks like 123456789:AAH… and comes from @BotFather. Copy it again without extra spaces. | module notify (validator dùng chung) |
| `bad_type` | 400 | Choose a token type: decoy file, fake credentials, URL or DNS name. | `POST /honeypot/tokens` |
| `bad_url` | 400 | Enter the Wazuh server API address starting with https://, for example https://wazuh-manager:55000. Do not put the user  | module inventory, logs, notify (validator dùng chung) |
| `bad_user_id` | 400 | The Zalo recipient ID (user_id) is the number of a person who followed or messaged the OA. | module notify (validator dùng chung) |
| `bad_username` | 400 | Enter the read-only API user name (letters, digits, dot, dash, underscore; up to 64 characters). | `POST /scans/credentialed` |
| `bad_value` | 400 | Enter only a domain name, without http://, a path, a port or spaces. Example: example.com. | `POST /exposure/targets` |
| `bad_version` | 400 | The version may only contain letters, digits, dots, hyphens and brackets, up to 40 characters. Example 7.2.5. | module inventory (validator dùng chung) |
| `bad_webhook` | 400 | A Slack Incoming Webhook URL starts with https://hooks.slack.com/services/. Copy it again from your Slack app. | module notify (validator dùng chung) |
| `bad_window` | 400 | window must be 24h or 7d. | 4 endpoint (/feeds, /inventory, /logs, /notify) |
| `code_expired` | 400 | This code has expired. Ask for a new code. | module core (validator dùng chung) |
| `code_required` | 400 | Type the 6-digit two-step code to approve a high-risk AI request. | `POST /response/actions/{id}/approve` |
| `confirm_mismatch` | 400 | The organization name does not match. Type it exactly to confirm deletion. | `POST /core/data/purge` |
| `core_module` | 400 | Core modules are always on. | `PATCH /modules/{id}` |
| `current_session` | 400 | This is the session you are using. Use "Sign out" in the account menu. | `DELETE /core/account/sessions/{id}` |
| `dangerous_locked` | 400 | Vedette has no dangerous checks: no exploitation, no denial of service. It cannot be turned on. | `PUT /scans/config` |
| `duplicate_name` | 400 | Another connection already has this name. Pick a different one. | `POST /core/connections`; `PUT /core/connections/{id}`; module feeds (validator dùng chung) |
| `duplicate_user` | 400 | The same user is listed twice as approver. | module notify (validator dùng chung) |
| `empty` | 400 | No bundle file chosen. | `POST /core/updates/bundle`; `POST /exposure/targets` |
| `empty_file` | 400 | The file is empty. Download the template, fill in your devices and choose it again. | `POST /inventory/import` |
| `empty_query` | 400 | Enter a CVE, product name, IP or domain. | `GET /feeds/search` |
| `empty_window` | 400 | The start and the end are the same, so the window is empty. Choose different times. | `PATCH /core/updates/os/settings` |
| `fallback_without_primary` | 400 | Set a primary profile for ${JOB_NAME[j.id]} before adding a fallback. | module ai (validator dùng chung) |
| `host_bits` | 400 | Range ${r} is not written correctly: the address part must be the first address of the range. Use ${cidrRange(r).network | `PUT /inventory/settings` |
| `incomplete_product` | 400 | Enter both the vendor and the product, for example vendor "Fortinet" and product "FortiGate". | module inventory (validator dùng chung) |
| `invalid` | 400 | The switch value must be on or off. | 12 endpoint (/core, /response) |
| `invalid_action` | 400 | Pick what the hook does: block, mask or require approval. | module ai (validator dùng chung) |
| `invalid_address` | 400 | Enter the head office address (5 to 200 characters). | module reports (validator dùng chung) |
| `invalid_allow` | 400 | The allow-list holds up to 30 entries of 200 characters each, one per line. Also: Each allow-list entry must be an address under ${target}, for example ${target}/api/. | `POST /core/connections`; `PUT /core/connections/{id}` |
| `invalid_auth` | 400 | Pick how the box signs in: none, token, user and password, or SSH key. | `POST /core/connections`; `PUT /core/connections/{id}`; module feeds (validator dùng chung) |
| `invalid_auto` | 400 | Automatic security updates are on or off. | `PATCH /core/updates/os/settings` |
| `invalid_base_url` | 400 | The server address is not valid. Enter it in full, for example https://api.anthropic.com or http://localhost:11434/v1. | module ai (validator dùng chung) |
| `invalid_body` | 400 | Check the values and try again. | 4 endpoint (/feeds) |
| `invalid_bundle` | 400 | Choose a module bundle: small, medium or custom. | `POST /core/setup` |
| `invalid_cap` | 400 | The profile\ | `PUT /ai/config` |
| `invalid_categories` | 400 | Unknown or empty log category in the download request. | `GET /core/logs/export` |
| `invalid_channel` | 400 | The channel is stable or beta. | `PATCH /core/updates` |
| `invalid_client` | 400 | Enter the Client ID (at most 200 characters). | `PUT /core/oidc` |
| `invalid_code` | 400 | The code is 6 digits. | `POST /auth/login`; `POST /core/account/2fa/confirm`; `POST /response/actions/{id}/approve` (từ `VerifyTwoStep`, trả nguyên, D-98) |
| `invalid_config` | 400 | The scan configuration is not valid. | `PUT /scans/config` |
| `invalid_contact` | 400 | Enter the name of the person in charge of data protection. | module reports (validator dùng chung) |
| `invalid_credentials` | 400 | Wrong email or password. | `POST /auth/login`; `POST /auth/login/resend-code` |
| `invalid_cve` | 400 | A CVE ID looks like CVE-2022-27593. | `POST /ai/cve/{id}/explain`; `POST /ai/cve/{id}/news` |
| `invalid_day` | 400 | Pick a day of the week. | module reports (validator dùng chung) |
| `invalid_email` | 400 | The email is not valid, for example name@company.com. | `POST /core/setup`; `POST /core/users` |
| `invalid_employees` | 400 | Headcount is a whole number from 0 to 1,000,000. | module reports (validator dùng chung) |
| `invalid_format` | 400 | Choose JSON or CSV. | `GET /core/logs/export`; `POST /feeds/parse-test` |
| `invalid_from` | 400 | The start of the range must be a date like 2026-11-09 or a UTC time ending in Z, like 2026-11-09T00:00:00Z. | `GET /core/audit`; `GET /core/audit/export`. Mã mới của backend [ĐX]: không dùng `bad_from` vì nó đã nghĩa là "email người gửi sai" ở notify (§3.2 mục 5). Ngày `YYYY-MM-DD` tính theo múi giờ của tổ chức; thời điểm phải tận cùng `Z` (độ lệch như `+07:00` bị từ chối) |
| `invalid_hour` | 400 | The send hour must be 0 to 23. | module reports (validator dùng chung) |
| `invalid_issuer` | 400 | The issuer must be an https address, for example https://sso.example.com/realms/main. | `PUT /core/oidc` |
| `invalid_items` | 400 | Pick at least one action of this request. | module response (validator dùng chung) |
| `invalid_jobs` | 400 | One of the chosen jobs is not an AI job. Pick from the list. | `POST /ai/knowledge`; `PUT /ai/knowledge/{id}` |
| `invalid_key` | 400 | The API key is too short or contains spaces. Copy the whole key again from the provider\ | module ai (validator dùng chung) |
| `invalid_kind` | 400 | Pick a kind: HTTP API, SSH / CLI, NETCONF / RESTCONF, automation platform or MCP server. | `POST /core/connections`; `PUT /core/connections/{id}` |
| `invalid_lan` | 400 | Enter 1 to 16 LAN ranges, for example 192.168.10.0/24. | `POST /core/setup` |
| `invalid_level` | 400 | The information system level is 1 to 5, or leave it empty if not determined yet. | module reports (validator dùng chung) |
| `invalid_location` | 400 | Say where the model runs: inside the company network or in the cloud. | module ai (validator dùng chung) |
| `invalid_match` | 400 | Enter the words (comma-separated) or the regular expression to look for, 200 characters at most. | module ai (validator dùng chung) |
| `invalid_memory` | 400 | Write what the AI should remember in 3 to 300 characters, for example "NAS-PHOTOS is reachable from the Internet". | `POST /ai/memory`; `PUT /ai/memory/{id}` |
| `invalid_message` | 400 | Write the message people will see, 3 to 200 characters. | module ai (validator dùng chung) |
| `invalid_mode` | 400 | The mode is automatic or manual. | `PATCH /core/updates`; `PUT /core/network/management`; `PUT /core/network/ntp` |
| `invalid_model` | 400 | The model name may only contain letters, digits, dots, dashes, colons and slashes (80 characters at most), for example c | module ai (validator dùng chung) |
| `invalid_module` | 400 | No module "${unknown}". | `POST /core/setup` |
| `invalid_name` | 400 | Give the connection a name of 1 to 40 characters, for example "Office FortiGate API". | 5 endpoint (/ai, /core) |
| `invalid_org` | 400 | The organization name is 2 to 80 characters. | `POST /core/setup`; `PUT /core/general` |
| `invalid_phone` | 400 | The phone number starts with 0 or +84 and has 10 to 11 digits. | module reports (validator dùng chung) |
| `invalid_question` | 400 | The question must be 3 to 500 characters. For example: "Which machines still expose RDP?" | `POST /ai/ask` |
| `invalid_range` | 400 | The start date is after the end date. / Dates are written YYYY-MM-DD, for example 2026-11-09, between 2000 and 2100. (backend, `GET /core/logs/export`: a date that is not a day, or outside 2000..2100) | `GET /core/logs/export` |
| `invalid_recipients` | 400 | The recipient list holds 20 emails at most. | module reports (validator dùng chung) |
| `invalid_retention` | 400 | Keep the AI activity log for at least ${MIN_RETENTION} days (up to 3650). | `PUT /ai/activity/settings` |
| `invalid_role` | 400 | Choose a role: view only, operator or administrator. | `PATCH /core/users/{id}`; `POST /core/users`; `PUT /core/oidc` |
| `invalid_rule` | 400 | Write the rule in 3 to 300 characters, for example "Always name devices by hostname and IP address". | module ai (validator dùng chung) |
| `invalid_scope` | 400 | Choose security updates or all updates. | `POST /core/updates/os/install` |
| `invalid_scopes` | 400 | Choose at least one read scope: devices, findings or vulnerability feeds. | `POST /core/mcp/tokens` |
| `invalid_secret` | 400 | The secret is too short. Copy the whole token, password or key again. Also: This private key is protected by a passphrase, which Vedette cannot type. Save a copy without one and paste that. Also (13b-4): This private key could not be read. Paste the whole key, including the BEGIN and END lines.; This key type is not accepted. Use an Ed25519, ECDSA or RSA key of at least 2048 bits. | `PUT /core/oidc`; `POST /core/connections`; `PUT /core/connections/{id}` |
| `invalid_sector` | 400 | Pick the field of activity. | module reports (validator dùng chung) |
| `invalid_setting` | 400 | Say whether the AI may suggest new memories: on or off. | `PUT /ai/hooks/builtin/{id}`; `PUT /ai/memory/settings`; `PUT /ai/skills/{id}` |
| `invalid_size` | 400 | The file is empty. | `POST /ai/knowledge` |
| `invalid_style` | 400 | Pick the API style the server speaks: OpenAI Chat Completions, Anthropic Messages or Gemini. | module ai (validator dùng chung) |
| `invalid_target` | 400 | Enter the SSH server as host or host:port, for example 192.168.10.30:22. Also: The address must start with https://. Vedette sends sign-in details and changes only over HTTPS.; Vedette never connects to ${why}. Enter the address of the device or service itself. (loopback, link-local, multicast, unspecified, `localhost`, non-standard numeric names, the box itself; D-94) | `POST /core/connections`; `PUT /core/connections/{id}` |
| `invalid_tax_code` | 400 | The tax code is 10 digits, or 10 digits, a dash and 3 digits for a branch. Example 0312345678. | module reports (validator dùng chung) |
| `invalid_text` | 400 | Type a sample text of up to 1,000 characters. | `POST /ai/hooks/test` |
| `invalid_tier` | 400 | Pick a tier: minimum, medium or maximum. | `PUT /ai/config` |
| `invalid_time` | 400 | Enter the start and end as hours and minutes, for example 02:00. | `PATCH /core/updates/os/settings`; `POST /core/updates/os/reboot` |
| `invalid_timezone` | 400 | The time zone is not in the list. | `PUT /core/general` |
| `invalid_to` | 400 | The end of the range must be a date like 2026-11-09 or a UTC time ending in Z, like 2026-11-09T23:59:59Z. | `GET /core/audit`; `GET /core/audit/export`. Như `invalid_from` |
| `invalid_tool_access` | 400 | Only tools of an MCP server can be marked read or write; the built-in tools of this kind are fixed. | `POST /core/connections`; `PUT /core/connections/{id}` |
| `invalid_type` | 400 | Only PDF, MD, TXT and DOCX files can be added. | `POST /ai/knowledge` |
| `invalid_url` | 400 | Use an https:// address (http:// is only allowed for internal addresses). | `PUT /feeds/sources/{id}` |
| `invalid_volume` | 400 | Pick how many people\ | module reports (validator dùng chung) |
| `invalid_when` | 400 | Pick when the hook runs: before sending to the AI, after the AI answers, or before a tool call. | `POST /ai/hooks/test`; `POST /core/updates/os/reboot` |
| `invalid_window` | 400 | The maintenance window is "any time" or "only in a window". | `PATCH /core/updates/os/settings` |
| `ip_is_box` | 400 | This is the Vedette box\ | `POST /honeypot/decoys`; `PUT /honeypot/config` |
| `ip_not_allowed` | 400 | Public IPs are not typed in. Select "Verify this box\ | `POST /exposure/targets` |
| `ip_outside_lan` | 400 | The secondary IP must be inside the box's network (${boxInfo().lan}), not the network or broadcast address. | `POST /honeypot/decoys`; `PUT /honeypot/config` |
| `key_required` | 400 | The API key is required (changing the provider type needs the key again). | module ai (validator dùng chung) |
| `kind_unsupported` | 400 | An MCP server that Vedette starts as a command is not supported. Use an MCP server that has a web address (kind "MCP server (URL)"). | `POST /core/connections`; `PUT /core/connections/{id}`; `POST /core/connections/{id}/test` (D-94) |
| `last_admin` | 400 | At least one active administrator must remain. Add another administrator first. | `PATCH /core/users/{id}` |
| `locked` | 400 | "Write tools need approval" is always on. A tool that changes something can only run through an action a person approves | `PUT /ai/hooks/builtin/{id}` |
| `missing_dependencies` | 400/409 | Module ${id} also needs: ${lacking.join(', ')}. | `PATCH /modules/{id}`; `POST /core/setup` |
| `no_code` | 400 | No code is waiting. Ask for a new code. | module core (validator dùng chung) |
| `commitment_required` | 400 | You have not confirmed that your company owns ${t.value} and you are authorized to scan it. Confirm it first. | `POST /exposure/targets/{id}/scan`; `POST /scans/runs` |
| `no_days` | 400 | Pick at least one day for the maintenance window. | `PATCH /core/updates/os/settings`; `PUT /inventory/settings` |
| `no_index_profile` | 400 | Choose which AI profile builds the index before adding documents. | `POST /ai/knowledge` |
| `no_lan` | 400 | Add your LAN range first (Devices, Scope and sensors), so Vedette knows which network the box is on. | `POST /honeypot/decoys`; `PUT /honeypot/config` |
| `no_pack` | 400 | This CVE has no confirmed recommendation yet, so there is nothing to mark as applied. | `POST /findings/{id}/applied` |
| `no_prefix` | 400 | "${r}" has no prefix length. Add it so Vedette scans the right size of network, for example ${r}/24 or ${r}/25. | `PUT /inventory/settings` |
| `no_ranges` | 400 | Active scanning needs at least one network range. | `PUT /inventory/settings` |
| `no_recipients` | 400 | Automatic sending needs at least one recipient. Add an email, then save. | `POST /reports/weekly/send` |
| `no_such_user` | 400 | One of the approvers does not exist or is disabled. | module notify (validator dùng chung) |
| `no_targets` | 400 | Choose at least one device to scan. | `POST /scans/runs` |
| `no_window` | 400 | There is no maintenance window yet. Set the days and hours first, or pick a time yourself. | `POST /core/updates/os/reboot` |
| `not_bundle` | 400 | The file is not a Vedette bundle (content cannot be read). | `POST /core/updates/bundle` |
| `not_configured` | 400 | Save the OIDC configuration before testing. | `POST /core/oidc/test`; `POST /logs/siem/test`; `POST /notify/channels/{type}/test` |
| `not_confirmed` | 400 | Tick the box to confirm that your company owns this and you are authorized to scan it. | `POST /exposure/targets/{id}/commitment` |
| `not_manual` | 400/409 | Only manually declared software can be removed. Software seen by a sensor or agent updates on the next scan. | `DELETE /inventory/devices/{id}/software/{sid}`; `POST /response/rules/{id}/manual` |
| `not_public` | 400 | The box reaches the Internet via ${ip}, which is a private, reserved or shared carrier (CGNAT) address. Scanning it coul | `POST /exposure/box-ip/verify` |
| `not_server` | 400 | The target is not a server (credentialed scan is for servers only). | `POST /scans/credentialed` |
| `note_required` | 400 | Write why this is a false positive or not relevant (at least 3 characters) so the next person understands. | `POST /findings/{id}/status` |
| `note_too_long` | 400 | The note can be at most 500 characters. Shorten it. | `PATCH /notify/incidents/{id}`; `POST /findings/{id}/status` |
| `oidc_off` | 400 | SSO sign-in is not enabled. Ask an administrator to enable it under Settings, Users. | `POST /core/sso/login` |
| `out_of_scope` | 400 | The target is outside the approved scope. | `POST /scans/credentialed`; `POST /scans/runs` |
| `outside_window` | 400 | The chosen reboot time is outside the maintenance window. | `POST /core/updates/os/reboot` |
| `overlap_range` | 400 | Range ${r} overlaps ${clash}. Keep the larger range and drop the smaller one. | `PUT /inventory/settings` |
| `password_required` | 400 | Enter the password of the read-only API user. | module inventory (validator dùng chung) |
| `phrase_mismatch` | 400 | Type ${RISK_PHRASE} exactly, in capital letters. | `POST /response/execution` |
| `port_mismatch` | 400 | Port 587 uses STARTTLS, not SSL/TLS. Choose STARTTLS, or change the port to 465 for SSL/TLS. | module notify (validator dùng chung) |
| `privacy_rule` | 400 | "${p.name}" runs in the cloud, but ${JOB_NAME[j.id]} sends internal data and the privacy rule only allows internal profi | `PUT /ai/profiles/{id}` |
| `profile_unusable` | 400 | "${p.name}" has no API key yet, so it cannot build the index. Edit the profile and add the key. | `PUT /ai/knowledge/settings` |
| `public_range` | 400 | The range is not a private range (10.x, 172.16-31.x, 192.168.x). | `POST /core/setup`; `PUT /inventory/settings` |
| `same_date` | 400 | Pick two different days to compare. | `GET /exposure/targets/{id}/diff` |
| `same_password` | 400 | The new password must differ from the current one. | `POST /core/account/password` |
| `same_profile` | 400 | The fallback for ${JOB_NAME[j.id]} must be a different profile from the primary. | module ai (validator dùng chung) |
| `sample_unavailable` | 400 | This build has no sample data. Fill in the setup form instead. | `POST /core/setup`. Mã mới của backend [ĐX] (INV-15): `sample:true` chỉ hợp lệ ở bản `data_mode=sample`; bản backend hiện chưa có dữ liệu mẫu |
| `scope_not_confirmed` | 400 | Tick the confirmation that these network ranges belong to your company and you are allowed to scan them. Vedette only sc | `PUT /inventory/settings` |
| `secret_required` | 400 | Enter the secret. It stays on this box and is encrypted; only the last 4 characters are shown afterwards. Also: Enter the secret again: the address changed, and a saved secret is only sent to the address it was saved for. | `POST /core/connections`; `PUT /core/connections/{id}`; module notify (validator dùng chung) |
| `self_disable` | 400 | You cannot disable the account you are using. Ask another administrator. | `PATCH /core/users/{id}` |
| `self_reset` | 400 | You cannot reset your own two-step sign-in here. Use My account instead. | `POST /core/users/{id}/2fa/reset` |
| `telemetry_unavailable` | 400 | This version of Vedette does not send an anonymous signal, so it cannot be turned on. | `PATCH /core/privacy` với `telemetry: true` (backend; D-154. Không có trong mock; GUI không gửi từ D-153) |
| `too_large` | 400/413 | The file is larger than 10 MB. Split it or remove pictures, then upload again. | 4 endpoint (/ai, /core, /feeds, /inventory) |
| `too_many` | 400 | A box holds up to 30 custom rules. Delete one you no longer need. Also: A box holds up to 20 connections. Delete one you no longer use. | 10 endpoint (/ai, /core, /exposure, /scans); `POST /core/connections` |
| `too_many_ranges` | 400 | At most 16 network ranges. | `PUT /inventory/settings` |
| `too_many_rows` | 400 | At most ${MAX_IMPORT_ROWS} rows per import. This file has ${data.length} rows. | `POST /inventory/import` |
| `too_many_tries` | 400 | Too many wrong codes. Ask for a new code. | module core (validator dùng chung) |
| `unknown_asset` | 400 | The device you linked is not in the inventory. | `POST /core/connections`; `PUT /core/connections/{id}` |
| `unknown_host` | 400 | Choose a server from the device list in the inventory. | `POST /scans/credentialed` |
| `unknown_product` | 400 | That product is not in the list. Pick one from the suggestions, or enter the vendor and product yourself. | module inventory (validator dùng chung) |
| `unknown_profile` | 400 | This AI profile no longer exists. Pick another. | `PUT /ai/knowledge/settings` |
| `unknown_target` | 400 | There is no target "${id.slice(0, 40)}" in the scan list. | `POST /scans/runs` |
| `username_required` | 400 | Enter the user name the box signs in with. | `POST /core/connections`; `PUT /core/connections/{id}` (SSH and Basic sign-in) |
| `viewer_not_allowed` | 400 | A viewer cannot be an approver. | module notify (validator dùng chung) |
| `weak_password` | 400 | The password needs at least ${MIN_PASSWORD} characters. A long sentence is easier to remember than random characters. | `POST /core/account/password`; `POST /core/setup` |
| `wrong_code` | 400 | Wrong code. ${left} ${left === 1 ? 'try' : 'tries'} left. | `POST /core/account/2fa/confirm`; `POST /response/actions/{id}/approve` (email, từ `VerifyTwoStep`, trả nguyên, D-98) |
| `wrong_password` | 400 | The current password is wrong. | `POST /core/account/2fa/disable`; `POST /core/account/password`; `POST /core/account/2fa/start`; `POST /core/account/2fa/email/start` (D-76: bật 2 bước cũng cần mật khẩu hiện tại, thông điệp "The password is needed to turn on two-factor authentication."; sai tính vào bộ đếm xác thực lại theo tài khoản, riêng với bộ đếm đăng nhập sai nhưng cùng mức 10 lần / 15 phút và cùng cách tăng thời gian chờ, và ghi `auth.reauth_failed`). Cũng là mã khi mật khẩu vừa chứng minh đã bị đổi giữa lúc kiểm và lúc ghi |
| `wrong_kind` | 400 | This action is an SSH command. Choose an SSH connection. | `PUT /response/catalog/{id}` |
| `dhcp_no_static` | 400 | With DHCP the address, gateway and DNS come from your DHCP server. Remove the static fields. | `PUT /core/network/management` |
| `gateway_outside_subnet` | 400 | The gateway must be inside the address range you entered. Backend [ĐX] (D-100): kiểm của `core` trước, và host `gateway_outside_subnet` (412). | `PUT /core/network/management` |
| `gateway_not_host` | 400 | The gateway cannot be the network or broadcast address of the range. Use the address of your router. | `PUT /core/network/management` |
| `invalid_static` | 400 | The IP address must be an IPv4 address like 192.168.10.250. (cùng nhóm: tiền tố 8 đến 30, địa chỉ mạng/broadcast/dành riêng/link-local 169.254, gateway trùng địa chỉ, 1 đến 3 DNS, DNS loopback/link-local/multicast hoặc trùng; luật của host `unicast4`/`hostInSubnet`/`IsGlobalUnicast`; host `invalid_args` → 400 `invalid`) | `PUT /core/network/management` |
| `invalid_roles` | 400 | Give a role (management, span or unused) for every interface. | `PUT /core/network/interfaces` |
| `invalid_span` | 400 | The SPAN settings are incomplete. (backend: giản đồ OpenAPI từ chối trước, mã chung `invalid`) | `PUT /core/network/span` |
| `no_interface` | 400 | Choose the port that receives the mirrored traffic before turning SPAN on. | `PUT /core/network/span` |
| `nothing_selected` | 400 | Choose at least one thing to read from the mirrored traffic, or turn SPAN off. | `PUT /core/network/span` |
| `bad_filter` | 400 | "${v}" is not a network range. Write it like 10.0.5.0/24, with the prefix length. (cùng nhóm: loại lọc, giá trị rỗng, dải lớn hơn /8, máy, cổng, trùng, quá 50) | `PUT /core/network/span` |
| `bad_limit` | 400 | The CPU cap must be a whole number from 5 to 50 percent. (backend: giản đồ OpenAPI từ chối trước, mã chung `invalid`) | `PUT /core/network/span` |
| `default_no_servers` | 400 | The default pool takes no server list. Choose "your own servers" to enter some. | `PUT /core/network/ntp` |
| `bad_ntp` | 400 | Give 1 to 4 NTP servers. (cùng nhóm: tên hoặc IPv4 sai, trùng; backend: tên chỉ gồm số như `1.2.3` bị từ chối, host cũng từ chối) | `PUT /core/network/ntp` |

#### HTTP 401 (3 mã)

| Code | HTTP | Thông điệp mẫu (EN, từ mock) | Endpoint dùng |
|---|---|---|---|
| `key_rejected` | 401 | The provider rejected the key (HTTP 401). Check the key has not expired and belongs to this provider. | `POST /ai/profiles/test` |
| `twofa_required` | 401/403/409 | Turn on two-step sign-in for your account first (My account), then try again. | `POST /auth/login`; `POST /response/execution`; 403 từ `core/auth.VerifyTwoStep` khi người duyệt chưa bật hai bước (D-98) |
| `unauthenticated` | 401 | Not signed in. | `GET /me`; mọi endpoint không công khai khi không có phiên, phiên hết hạn hoặc bị thu hồi; ở các thao tác ghi, phiên bị thu hồi **giữa chừng** cũng là 401 và không ghi gì: `/core/account/password`, `/core/account/2fa/{start,confirm,email/start,email/confirm,disable}`, `PATCH /core/account`, `POST /core/users`, `PATCH /core/users/{id}`, `/core/users/{id}/reset-password`, `/core/users/{id}/2fa/reset`, `PUT /core/general`, `GET /core/audit/export` |

#### HTTP 403 (10 mã)

| Code | HTTP | Thông điệp mẫu (EN, từ mock) | Endpoint dùng |
|---|---|---|---|
| `approver_not_listed` | 403 | Not counted: this ${b.channel} address is not on the approver list of that channel, or its user is not an operator or ad | `POST /response/actions/{id}/chat-decision`; `POST /response/approve/{token}` |
| `channel_not_allowed` | 403 | Approvals from ${b.channel} are not turned on for response. | `POST /response/actions/{id}/chat-decision` |
| `csrf_invalid` | 403 | The request could not be verified. Reload the page and try again. | mọi POST/PUT/PATCH/DELETE đã xác thực (`core/server`, §7.2; WP-04a) |
| `disabled` | 403 | This account has been disabled. | `POST /core/sso/login`; `POST /auth/login`; `POST /auth/login/resend-code`; mọi yêu cầu có phiên của tài khoản bị khoá; ở các thao tác ghi, tài khoản bị khoá giữa chừng cũng là 403 và không ghi gì: `/core/account/password`, `/core/account/2fa/{start,confirm,email/start,email/confirm,disable}`, `PATCH /core/account`, `POST /core/users`, `PATCH /core/users/{id}`, `/core/users/{id}/reset-password`, `/core/users/{id}/2fa/reset`, `PUT /core/general`, `GET /core/audit/export` (quản trị viên đang thực hiện bị khoá) |
| `forbidden` | 403 | Your account is not allowed to do this. | module core (validator dùng chung) |
| `in_app_required` | 403 | A high-risk AI request can only be approved in the app with your two-step code, not from chat or email. | module response (validator dùng chung) |
| `invalid_token` | 403 | This enrollment token is not valid. Create a new one in Vedette. | `POST /intake/osquery/status` |
| `invalid_setup_code` | 403 | The setup code is missing or wrong. Find it in the box's log: it is printed there each time Vedette starts while setup is open. | `POST /core/setup`. Mã mới của backend [ĐX] (D-75). Mã sai tính theo địa chỉ máy khách như đăng nhập (10 lần, rồi `rate_limited` 30 s nhân đôi tới 10 phút; IPv6 thêm bộ đếm /64 với trần 100), không có trần chung cho cả hộp (D-75, đã sửa sau hai lượt rà bảo mật: trần chung là đòn khoá chủ hộp) |
| `token_expired` | 403 | This enrollment token has expired. Create a new one in Vedette. | `POST /intake/osquery/status`; `POST /inventory/agents/tokens/{id}/sample-data` |
| `tool_not_allowed` | 403 | The action "${cat?.name ?? prop.tool}" is not enabled in the action catalog (Settings, AI response). | `POST /response/proposals/{id}/request` |

#### HTTP 404 (5 mã)

| Code | HTTP | Thông điệp mẫu (EN, từ mock) | Endpoint dùng |
|---|---|---|---|
| `no_update` | 404 | There is no new version of this component. Click "Check now". | `POST /core/updates/apply` |
| `not_found` | 404 | This ${what} no longer exists. | 51 endpoint (/ai, /core, /exposure, /feeds, /findings, /honeypot, /inventory, /logs, /modules, /notify, /reports, /response) |
| `not_in_kev` | 404 | This CVE is not on the exploited list (CISA KEV) in the current data. | `GET /feeds/cve/{id}` |
| `unknown` | 404 | This link is not valid. | `POST /response/approve/{token}` |
| `unknown_cve` | 404 | This CVE is not on the exploited list the box holds. The AI only explains CVEs the box has data for. | `POST /ai/cve/{id}/explain`; `POST /ai/cve/{id}/news` |

#### HTTP 409 (79 mã)

| Code | HTTP | Thông điệp mẫu (EN, từ mock) | Endpoint dùng |
|---|---|---|---|
| `ai_paused` | 409 | AI request: AI proposals are paused (${reason}). An admin can resume them. | cổng của đề xuất AI (13b-10 gọi `checkAIPaused`; đặt bởi cầu dao chất lượng, gỡ bởi `POST /response/ai/resume`, 13b-9) |
| `ai_unavailable` | 409 | The AI assistant module is off. Turn it on in Settings, Modules. | `POST /findings/{id}/ai`; `POST /ai/cve/{id}/explain` (cũng khi hook chặn yêu cầu hay câu trả lời sai định dạng, lý do trong thông điệp, D-148 (2)) |
| `already_on` | 409 | Two-step sign-in is already on. Turn it off first to set up the other method. | `POST /core/account/2fa/email/confirm`; `POST /core/account/2fa/email/start`; `POST /core/account/2fa/start` |
| `already_open` | 409 | This finding is already open. | `POST /findings/{id}/status` |
| `already_requested` | 409 | This action already has an open request or has already been carried out. | `POST /response/proposals/{id}/request` |
| `already_running` | 409 | A scan is already running. Wait for it to finish or press Stop now. | `POST /scans/runs` |
| `already_setup` | 409 | This box is already set up. Sign in with the administrator account. | `POST /core/setup` |
| `box_device` | 409 | This is the Vedette box itself, so it cannot be deleted. It is always the first device in the list. Its packages come fr | `DELETE /inventory/devices/{id}` |
| `circuit_open` | 409 | The circuit breaker is open: too many actions in one hour, so everything is paused. An admin can resume it in Settings, AI response. | `POST /response/actions/{id}/approve` (item refused right before it runs); `POST /response/proposals/{id}/request`; rule runs (resp_log); the emergency stop opens it too (D-88 amendment 2026-11-09) |
| `connection_changed` | 409 | The connection "…" was changed after the request was made. Nothing was changed. Ask again. (another connection, address or version than the one the request was rendered against) | `POST /response/actions/{id}/approve` (item refused right before it runs); `POST /response/actions/{id}/rollback`; `POST /core/connections/{id}/test` (the connection was edited while the test ran, so the result was not saved) |
| `builtin` | 409 | Built-in actions cannot be deleted. Disable it instead. | `DELETE /response/catalog/{id}` |
| `busy` | 409 | An update run is in progress. Wait for it to finish, then check again. | `POST /core/updates/os/check`; `POST /core/updates/os/install`; `POST /core/updates/os/reboot`; `GET /core/data/backup` (cũng khi một lần tải khác đang chạy); `GET /core/logs/export` (backend: another log download is being prepared); `GET /core/data/export` (backend: another export is being prepared) |
| `channel_not_ready` | 409 | This channel is not set up or is turned off. An administrator can turn it on in Settings, Alert channels. | `POST /notify/history/{id}/resend` |
| `check_off` | 409 | Update checks are off under Privacy. Turn them on or import an offline bundle. | `POST /core/updates/check`; `POST /core/updates/os/check` |
| `connection_off` | 409 | This connection is turned off, so nothing is sent to it. Turn it on, then test it. | `POST /core/connections/{id}/test` (PRIVACY flow 12) |
| `duplicate` | 409 | This email already has an account. | `POST /core/users`; `POST /exposure/targets`; `POST /honeypot/tokens` |
| `duplicate_ip` | 409 | IP ${ip} is already in the list (${dup.hostname ?? dup.id}). Open that device instead of adding a new one. | module inventory (validator dùng chung) |
| `duplicate_software` | 409 | This software is already on the device. | `POST /inventory/devices/{id}/software` |
| `email_channel_not_ready` | 409 | Email codes need the email alert channel. An administrator has to set it up and turn it on first. | `POST /core/account/2fa/email/confirm`; `POST /core/account/2fa/email/start` |
| `execution_off` | 409 | Execution is off (Settings, AI response). | `POST /response/actions/{id}/chat-decision`; `POST /response/proposals/{id}/request` |
| `exists` | 409 | This target already has a scan account. | `POST /scans/credentialed` |
| `expired` | 409 | Verification of ${t.value} has expired. Verify it again first. | `POST /exposure/targets/{id}/commitment`; `POST /exposure/targets/{id}/scan` |
| `feed_disabled` | 409 | Turn the feed on before fetching it. | `POST /feeds/sources/{id}/fetch` |
| `finding_closed` | 409 | The finding is no longer an open critical finding. | `POST /response/proposals/{id}/request` |
| `hostname_in_use` | 409 | The name ${hostname} belongs to device ${hostClash.ip} in the inventory. Pick another name. | `POST /honeypot/decoys`; `PUT /honeypot/config` |
| `in_use` | 409 | The rule "${user.name}" uses this action. Change or delete the rule first. / A change made through ${name} is still in force. Roll it back in Response, or wait until it expires, then delete the connection. | `DELETE /response/catalog/{id}`; `DELETE /core/connections/{id}` |
| `ip_in_use` | 409 | IP ${ip} belongs to device ${assetName(clash)} in the inventory. Pick an unused IP. | 4 endpoint (/honeypot); `PUT /core/network/management` ("… is already used by a device in the inventory or by a decoy. Pick a free address.") |
| `ip_not_current` | 409 | This box no longer reaches the Internet through ${ip}; it was last seen ${time}. Scans of it are paused until the box uses it again. | `POST /exposure/targets/{id}/scan`; `POST /scans/runs` (kiểm lúc quét của IP, `exposure` INV-13, D-79 (2)) |
| `limit` | 409 | Up to 30 rules. | `POST /response/catalog`; `POST /response/rules`; `POST /response/templates/{id}/clone`; `POST /response/actions/{id}/approve` (a `blocklist_add` item refused when the block list already holds 10 000 entries) |
| `module_off` | 409 | Turn on the MCP server before creating a token. | `POST /core/mcp/tokens` |
| `limit_reached` | 409 | The box can hold 32 decoys. Delete one before adding another. | `POST /honeypot/decoys` |
| `need_decoys` | 409 | Scan detection needs at least two decoy IPs. Add a decoy first. | `POST /honeypot/test-scan` |
| `no_devices` | 409 | No device in the inventory matches (agent sample data). | `POST /inventory/agents/tokens/{id}/sample-data`; `POST /inventory/agents/wazuh/sample-data` |
| `no_pending` | 409 | No key is waiting for confirmation. Click "Turn on two-factor authentication" to create one. | `POST /core/account/2fa/confirm` |
| `no_previous` | 409 | No previous version to go back to. | `POST /core/updates/rollback` |
| `no_secondary_ip` | 409 | Set a secondary IP for the traps before turning one on. | `PATCH /honeypot/traps/{service}` |
| `not_email_method` | 409 | This account does not use email codes. | `POST /auth/login/resend-code` |
| `maintenance` | 409 | Held: maintenance window "…" is active. Nothing was changed. | `POST /response/actions/{id}/approve` (item refused right before it runs); `POST /response/proposals/{id}/request`; rule runs (resp_log) |
| `never_touch` | 409 | … matches the never-touch list (…). Nothing was changed. Also: The never-touch list could not be read in full (the box's own addresses or the inventory are not available), so nothing was changed. | rule runs and `POST /response/proposals/{id}/request` (planning); `POST /response/actions/{id}/approve` (item refused right before it runs) |
| `not_executed` | 409 | Only an executed action can be rolled back. | module response (validator dùng chung) |
| `not_on` | 409 | Two-step sign-in is already off for this user. | `POST /core/users/{id}/2fa/reset` |
| `not_pending` | 409 | This request is already ${a.status.replace('_', ' ')}. One approval covers one request. | module response (validator dùng chung) |
| `not_running` | 409 | This scan has already ended, so there is nothing to stop. | `POST /scans/runs/{id}/stop` |
| `not_verified` | 409 | Verify ownership first; only then can you confirm the commitment for this target. | `POST /exposure/targets/{id}/commitment`; `POST /exposure/targets/{id}/scan` |
| `nothing_scheduled` | 409 | No reboot is scheduled. | `DELETE /core/updates/os/reboot` |
| `nothing_to_install` | 409 | There are no updates waiting to install. | `POST /core/updates/os/install` |
| `org_required` | 409 | Fill in and save the organisation details first, then create the report. | `POST /reports/pdpl/generate` |
| `read_only` | 409 | This connection has no write tools, so it cannot carry out actions. | `POST /response/catalog` |
| `report_required` | 409 | Create the report first; the AI needs something to comment on. | `POST /reports/pdpl/ai-summary` |
| `rule_off` | 409 | Switch the rule on first. | `POST /response/rules/{id}/manual` |
| `rule_rate_limited` | 409 | Limit of N runs per hour reached. | rule runs (resp_log only: an event is not an API call) |
| `same_approver` | 409 | You already approved this request. A second, different person must approve it. | module response (validator dùng chung) |
| `selection_differs` | 409 | The second approver must approve the same actions as the first. | module response (validator dùng chung) |
| `skill_off` | 409 | The "Ask your data" skill is turned off. Turn it on in Settings, AI assistant, Skills. | `POST /ai/ask` |
| `tool_unavailable` | 409 | The tool of the action is missing, disabled or its connection is off; or the write tool (or undo tool) of the action was changed after the request was made. | `POST /response/proposals/{id}/request`; `POST /response/actions/{id}/approve`; `POST /response/actions/{id}/rollback` |
| `trap_off` | 409 | The ${LABEL[service]} trap is off. Turn it on before testing. | `POST /honeypot/test-hit` |
| `txt_missing` | 409 | The DNS TXT record vedette-verify=${t.token} is no longer on ${t.value}, so it cannot be scanned. Add the record back, t | `POST /exposure/targets/{id}/scan` |
| `dpkg_locked` | 409 | Another package manager is running on the box (for example automatic updates). Try again in a minute. Backend [ĐX] (WP-07b phần 2): host `dpkg_locked`, kèm `retry_after`. | `POST /core/updates/os/check`; `POST /core/updates/os/install` |
| `dpkg_inconsistent` | 409 | The package database on the box is in a broken state. Run dpkg --audit on the box and repair it before updating. Backend [ĐX]: host `dpkg_inconsistent`. | `POST /core/updates/os/install` |
| `low_disk` | 409 | There is not enough free disk space for this. Free some space on the box and try again. Backend [ĐX]: host `low_disk`. | `POST /core/updates/os/install`; `GET /core/data/backup` |
| `no_check_yet` | 409 | The box has not looked for operating system updates yet. Click Check now. Backend [ĐX]: host `no_check_yet`; chưa có trong mock (mock luôn có `last_check`). | `GET /core/updates/os`; `POST /core/updates/os/install`; `PATCH /core/updates/os/settings`; `POST /core/updates/os/reboot` |
| `not_appliance` | 409 | This install has no operating system helper (container-only install), so Vedette cannot update or back up the operating system from here. Backend [ĐX] (D-55): không có socket `vedette-host`, hoặc bản phát hành OS ngoài bảng hỗ trợ của host; chưa có trong mock. | `GET /core/updates/os`; `POST /core/updates/os/check`; `POST /core/updates/os/install`; `PATCH /core/updates/os/settings`; `POST /core/updates/os/reboot`; `DELETE /core/updates/os/reboot`; `GET /core/data/backup` |
| `reboot_limit_reached` | 409 | The box has already rebooted three times in 24 hours. Wait before rebooting again. Backend [ĐX]: host `reboot_limit_reached`. | `POST /core/updates/os/reboot` |
| `rebooting` | 409 | The box is rebooting. Wait for it to come back, then try again. Backend [ĐX]: host `rebooting`. | `GET /core/updates/os`; `POST /core/updates/os/check`; `POST /core/updates/os/install`; `PATCH /core/updates/os/settings`; `POST /core/updates/os/reboot`; `DELETE /core/updates/os/reboot`; `GET /core/data/backup` |
| `pending_confirm` | 409 | A network change is waiting for confirmation. Confirm or cancel it in Settings, Box network, then try again. Backend [ĐX] (D-100): host `pending_confirm` (khoá ghi do run `awaiting_confirm` giữ) hoặc `net_pending_confirm`; id run của host không ra ngoài. | `POST /core/updates/os/check`; `POST /core/updates/os/install`; `PATCH /core/updates/os/settings`; `POST /core/updates/os/reboot`; `DELETE /core/updates/os/reboot`; `GET /core/data/backup` |
| `management_count` | 409 | Exactly one interface must be the management interface; you set ${n}. The management interface is the one you reach this page through. | `PUT /core/network/interfaces` |
| `management_fixed` | 409 | ${cur.name} is the management interface and you are using this page through it. It cannot be changed here; set the management address instead. | `PUT /core/network/interfaces` |
| `span_count` | 409 | Only one interface can capture mirrored traffic. Set the others to unused. | `PUT /core/network/interfaces` |
| `span_on_management` | 409 | ${iface.name} is the management interface. SPAN needs its own port: it listens with no IP address, and mirrored packets would reach your management network. Backend [ĐX]: cũng host `same_iface`. | `PUT /core/network/span` |
| `change_pending` | 409 | A change is waiting for confirmation. Confirm it from the new address or cancel it first. Backend [ĐX] (D-100): host `pending_confirm` khi khoá ghi do run `awaiting_confirm` giữ; id run của host không ra ngoài (các đường khác của `core` nhận cùng mã host dưới tên `pending_confirm`). | `PUT /core/network/management`; `PUT /core/network/span`; `PUT /core/network/ntp`; `PUT /core/network/interfaces` |
| `confirm_required` | 409 | This changes the address you use to reach the box. Open https://${ip}:8443 within 5 minutes and confirm, or the box returns to the old settings. You will need to sign in again at the new address. Thân có `new_ip` (null với DHCP: máy chủ DHCP chọn địa chỉ, câu nói "Find the new address your DHCP server gives the box, open it on port 8443…"). Cùng kiểu dùng cho `POST /core/updates/rollback` (D-104). | `PUT /core/network/management` |
| `nothing_pending` | 409 | No management change is waiting for confirmation. (hết giờ: "The time to confirm ran out and the box went back to the old settings. Make the change again.") Backend [ĐX]: host `not_awaiting_confirm`, `not_confirmed`. | `POST /core/network/management/confirm`; `POST /core/network/management/revert` |
| `address_conflict` | 409 | Another device already uses this address. Backend [ĐX] (D-101): host `address_conflict`, trả từ run sau ARP probe; không có gì chờ xác nhận. | `PUT /core/network/management` |
| `net_backend_unsupported` | 409 | This box's network files were not set up by the Vedette installer, so Vedette cannot change them. Reinstall with the installer or change the network on the box itself. Backend [ĐX] (D-99): host `net_backend_unsupported`. | mọi thay đổi `PUT /core/network/*` |
| `span_has_address` | 409 | That port has an IP address, and a SPAN port must have none. Remove the address from that port first, or choose another port. Chỉ backend (host `span_has_address`). | `PUT /core/network/span`; `PUT /core/network/interfaces` |
| `span_not_physical` | 409 | Only a physical network card can be the SPAN port, not a VLAN, bridge, bond or virtual interface. Chỉ backend (host `span_not_physical`). | `PUT /core/network/span`; `PUT /core/network/interfaces` |
| `connectivity_check_failed` | 409 | The box could not reach the network with the new settings, so it went back to the old ones. Check the address, prefix length and gateway, then try again. Chỉ backend (run `reverted`, D-100). | `PUT /core/network/management` |
| `reverted_by_reboot` | 409 | The box restarted before the change was confirmed, so it came back on the old address. Chỉ backend (run `reverted`). | `POST /core/network/management/confirm` |
| `management_not_set` | 409 | Vedette has not set up this box's network yet. Save the management address first, then change the other settings. Chỉ backend: host chưa ghi cấu hình nào nên không có gì để gộp. | `PUT /core/network/span`; `PUT /core/network/ntp`; `PUT /core/network/interfaces` |

#### HTTP 413 (1 mã)

| Code | HTTP | Thông điệp mẫu (EN, từ mock) | Endpoint dùng |
|---|---|---|---|
| `logs_too_large` | 413 | These logs are over 128 MB. Choose a shorter date range or fewer categories. (backend only, D-132: the mock has no size limit) | `GET /core/logs/export` |

#### HTTP 421 (1 mã)

| Code | HTTP | Thông điệp mẫu (EN, từ mock) | Endpoint dùng |
|---|---|---|---|
| `misdirected_request` | 421 | This address is not one Vedette answers to. Open it with the name or address it was set up with. | mọi yêu cầu có tiêu đề `Host` ngoài danh sách cho phép (cờ `-hosts`, mặc định tên loopback và tên trong chứng chỉ), trả **trước** khi định tuyến, kể cả đường dẫn ngoài `/api/v1`. Mã mới của backend [ĐX]: chống DNS rebinding |

#### HTTP 422 (1 mã)

| Code | HTTP | Thông điệp mẫu (EN, từ mock) | Endpoint dùng |
|---|---|---|---|
| `wazuh_auth` | 422 | Wazuh refused the user name or password. Check the read-only API user you created. | module inventory (validator dùng chung) |

#### HTTP 429 (4 mã)

| Code | HTTP | Thông điệp mẫu (EN, từ mock) | Endpoint dùng |
|---|---|---|---|
| `daily_cap` | 429 | The AI daily token cap is reached; the call is not made. | module ai (validator dùng chung) |
| `rate_limited` | 429 | Too many verification attempts (limit ${MAX_ATTEMPTS_PER_HOUR} per hour). Try again in about ${wait} minute${wait === 1  | module exposure, response (validator dùng chung) ; `POST /auth/login`; `POST /auth/login/resend-code` (kèm `retry_after` và `Retry-After`); `GET /core/data/backup` (một lần tải mỗi phút mỗi hộp, kèm `retry_after` và `Retry-After`); `POST /core/setup` (sai mã cài đặt, D-75); mật khẩu của người đã đăng nhập (`/core/account/password`, `/core/account/2fa/{start,email/start,disable}`); `GET /core/logs/export` (backend: one download a minute) |
| `resend_too_soon` | 429 | Wait ${wait} seconds before asking for a new code. | module core (validator dùng chung) |
| `too_many_codes` | 429 | Too many codes were sent in the last hour. Try again later. | module core (validator dùng chung) |

#### HTTP 502 (19 mã)

| Code | HTTP | Thông điệp mẫu (EN, từ mock) | Endpoint dùng |
|---|---|---|---|
| `provider_error` | 502 | The AI provider answered, but not in a way Vedette can use. Check the model name and the address. | `POST /ai/profiles/test` và các lời gọi AI sau (D-129 (3)); khác `unreachable` (không kết nối được) |
| `address_refused` | 502 | ${cur.target} now points to a loopback address, so Vedette did not connect. Check the name in your DNS. (the address policy of D-94 at dial time: loopback, link-local including the metadata address, multicast, unspecified, the box itself, IPv6 forms that carry an IPv4 address) | `POST /core/connections/{id}/test` |
| `device_error` | 502 | ${cur.target} was reached, but the device refused the sign-in (HTTP 401). (the device answered and said no: refused sign-in, an HTTP status, an answer over the cap, a CLI error line, an MCP error; one cleaned line, never a secret) | `POST /core/connections/{id}/test` |
| `discovery_failed` | 502 | Cannot read ${c.issuer}/.well-known/openid-configuration. Check the issuer and the network path from the box to the IdP. | `POST /core/oidc/test` |
| `pin_mismatch` | 502 | The certificate of ${cur.target} is not the one pinned at the first test. Nothing was sent. If you changed the device, edit this connection, turn on "Forget pinned key", save, then test again. | `POST /core/connections/{id}/test` (D-94) |
| `unreachable` | 502 | Could not connect to ${cur.target}. Check the address, the box's network and the firewall. | `POST /core/connections/{id}/test` (trước là `POST /ai/connections/{id}/test`, D-93); `POST /ai/profiles/test` |
| `wazuh_unreachable` | 502 | Could not reach ${u.origin}. Check the address and port (55000 by default) and that this box may connect to the Wazuh se | module inventory (validator dùng chung) |
| `apt_failed` | 502 | The package manager failed. See the update output for the reason. Backend [ĐX]: host `apt_failed`, `stale_check`. | `POST /core/updates/os/check` |
| `effect_not_verified` | 502 | The change was made but could not be confirmed on the box. Check the setting again. Backend [ĐX]: host `effect_not_verified`. | `PATCH /core/updates/os/settings` |
| `health_check_failed` | 502 | The updates were installed but a health check failed afterwards. Check the services on the box. Backend [ĐX]: host `health_check_failed`; trong lần chạy cài đặt nó hiện ở dòng cuối của `OsRun.lines`. | `POST /core/updates/os/check` |
| `host_error` | 502 | The operating system helper could not do this. The details are in the box log. Backend [ĐX]: mọi mã host còn lại (`internal`, `timeout`, `command_failed`, `backup_unknown`, ...) hoặc câu trả lời không dùng được; chi tiết chỉ ở log. | `GET /core/updates/os`; `POST /core/updates/os/check`; `POST /core/updates/os/install`; `PATCH /core/updates/os/settings`; `POST /core/updates/os/reboot`; `DELETE /core/updates/os/reboot`; `GET /core/data/backup` |
| `snapshot_rejected` | 502 | The helper could not take over a copy of the box's data. Check the box clock and the permissions of the data folder, then try again. Backend [ĐX]: host `snapshot_required`, `snapshot_invalid`, `db_unreadable`, `key_unreadable` (lỗi triển khai hoặc lệch đồng hồ, không phải lỗi người dùng). | `POST /core/updates/os/install`; `GET /core/data/backup` |
| `snapshot_failed` | 502 | Vedette could not write a copy of its data to the box's data folder. Check that the folder is writable and the disk is healthy, then try again. Backend [ĐX]: core không ghi được snapshot (thư mục `snapshots/` không ghi được, tệp khoá không đọc được, lỗi I/O); đĩa đầy hoặc ít chỗ trống hơn cỡ cơ sở dữ liệu thì là `low_disk` (409). Không bao giờ là 500. | `POST /core/updates/os/install`; `GET /core/data/backup` |
| `revert_failed` | 502 | The box could not go back to the old network settings by itself. The settings saved on the box are the old ones, so it comes back on the old address when it restarts, and it restarts by itself in about a minute. Chỉ backend (D-100 (8)); `pending.reboot_at` cho GUI. | `POST /core/network/management/revert`; `POST /core/network/management/confirm` |
| `netplan_apply_failed` | 502 | The operating system could not apply the network settings. If anything was changed it was put back; the details are in the box log. Chỉ backend. | `PUT /core/network/*` |
| `ntp_not_applied` | 502 | The time service did not take the new NTP servers. The old list was kept. Chỉ backend (D-106). | `PUT /core/network/ntp`; `PUT /core/network/management` |
| `arp_probe_failed` | 502 | The box could not check whether the new address is free, so nothing was changed. Try again. Chỉ backend (D-101). | `PUT /core/network/management` |
| `pending_invalid` | 502 | The box could not trust its record of the waiting change, so it went back to the old settings. Make the change again. Chỉ backend. | `POST /core/network/management/confirm` |
| `confirm_failed` | 502 | The box could not save the new settings, so it went back to the old ones. Make the change again. Chỉ backend. | `POST /core/network/management/confirm` |

#### HTTP 500 (1 mã)

| Code | HTTP | Thông điệp mẫu (EN) | Endpoint dùng |
|---|---|---|---|
| `internal` | 500 | Something went wrong on the box. Try again; if it keeps happening, send a bug report. | mọi endpoint, lỗi không dự kiến (`core/server`; chi tiết chỉ vào log kèm `X-Request-Id`, không vào phản hồi; WP-04a) |

#### HTTP 501 (1 mã)

| Code | HTTP | Thông điệp mẫu (EN) | Endpoint dùng |
|---|---|---|---|
| `not_implemented` | 501 | This part of the box is not built yet. | thao tác có trong hợp đồng nhưng module chưa có backend (`oas.UnimplementedHandler`; giao diện dùng mock cho module đó, WP-05) |

#### HTTP 503 (4 mã)

| Code | HTTP | Thông điệp mẫu (EN, từ mock) | Endpoint dùng |
|---|---|---|---|
| `server_busy` | 503 | The box is busy checking other sign-ins. Try again in a few seconds. | `POST /auth/login`; `POST /auth/login/resend-code`; `GET /response/blocklist/{token}.txt` (the store cannot be read: 503 with `Retry-After`, never an empty list, blocklist-format 6); mọi thao tác phải băm hoặc kiểm mật khẩu (`POST /core/users`, `/core/users/{id}/reset-password`, `/core/account/password`, `/core/account/2fa/disable`, `/core/setup`). Mã mới **[ĐX]** (WP-04b rà soát bảo mật): ít nhất một lần chờ quá 2 giây hoặc hàng đợi băm đầy. Kèm `retry_after` (giây) trong `error` và `Retry-After`. Không phải `busy` (409, cập nhật hệ điều hành). Lần thử bị từ chối vì bận **không** tính vào giới hạn đăng nhập sai |
| `twofa_email_unavailable` | 503 | The email channel cannot send two-step codes now. | `POST /auth/login`; `POST /auth/login/resend-code` |
| `host_unreachable` | 503 | The operating system helper (vedette-host) is not answering. Try again in a minute; if it keeps happening, check that the vedette-host service is running. Backend [ĐX]: socket có nhưng không trả lời, host từ chối tiến trình này, hoặc `host_shutting_down`. | `GET /core/updates/os`; `POST /core/updates/os/check`; `POST /core/updates/os/install`; `PATCH /core/updates/os/settings`; `POST /core/updates/os/reboot`; `DELETE /core/updates/os/reboot`; `GET /core/data/backup`; `PUT /notify/channels/{type}` (webhook: địa chỉ của hộp chưa biết vì vedette-host chưa từng trả lời, #157) |
| `scanner_unavailable` | 503 | The vulnerability scanner is not available: the scan container or its scanner is missing. Check the box's services, then try again. | `POST /scans/runs`; job quét lịch và quét lại KEV của `scan` (D-125: không có heartbeat của worker, hoặc heartbeat báo thiếu nuclei hay gói mẫu) |

## 4. Phân trang, lọc, sắp xếp

**Hiện trạng (mock):** hầu hết danh sách trả toàn bộ (SPA lọc/sắp xếp ở client). Có `total` ở: `GET /core/audit`, `/ai/activity`, `/inventory/catalog`, `/logs/events`. Không endpoint nào có `limit`/`cursor`. Mục tiêu 1.000 thiết bị, 50k IOC, 7 ngày log (DATA_MODEL §8) buộc phân trang ở các danh sách lớn.

**Quy ước [ĐX] (cộng thêm, không phá hợp đồng cũ):**

| Mục | Quy tắc |
|---|---|
| Tham số | `limit` (số nguyên; mặc định và tối đa theo bảng dưới), `cursor` (chuỗi mờ, lấy từ `next_cursor` của trang trước). Không dùng `offset`/`page` (lệch khi có dòng mới, chậm ở bảng log). |
| Thân phản hồi | `{ items: [...], next_cursor: string \| null, total?: integer }`. `next_cursor = null` = hết. `total` chỉ trả khi đếm rẻ (bảng nhỏ hoặc lọc theo index); không bao giờ cho `logs_event`. |
| Thứ tự mặc định | Mới nhất trước (`ts DESC, id DESC`) cho log và lịch sử. Ngoại lệ: **`GET /response/log` cũ nhất trước** (hợp đồng hiện tại, để client kiểm chuỗi hash từ đầu); phân trang bằng `cursor` tiến, client mang `hash` dòng cuối sang trang kế để kiểm tiếp. |
| `limit` ngoài khoảng | Kẹp về khoảng cho phép (không lỗi). `limit=0` hoặc không phải số → `400 bad_limit` (mã mới, ghi vào mục 3.3 khi thêm). |
| Cursor hết hạn / sai | `400 bad_cursor`. Cursor mã hoá khoá sắp xếp, không phải offset; ký bằng HMAC để không bị chỉnh. |

| Endpoint | Mặc định / tối đa | Ghi chú |
|---|---|---|
| `GET /logs/events` | 100 / 500 | khoá `events` (giữ); thêm `next_cursor` |
| `GET /core/audit`, `/ai/activity`, `/response/log`, `/honeypot/hits`, `/notify/history`, `/scans/probes`, `/scans/events`, `/ai/runs`, `/ai/asks` | 100 / 500 | |
| `GET /notify/incidents` | 500 / 500 | chưa có `cursor`: trả 500 sự cố mới nhất (mock không giới hạn) |
| `GET /findings`, `/inventory/devices`, `/inventory/catalog` | 2.000 / 2.000 | SPA hiện tải một lần và lọc ở client; giữ cho tới khi GUI chuyển phân trang (câu hỏi mở 3) |
| Bảng cấu hình nhỏ (kênh, hồ sơ AI, quy tắc, nguồn log, hook, bẫy…) | không phân trang | ≤ 30–200 dòng theo giới hạn trong hợp đồng |

**Lọc:** tham số query đặt theo tên trường, so bằng nhau; nhiều giá trị cách nhau dấu phẩy (`categories=audit,ai`, như `/core/logs/export`). `q` = tìm văn bản tự do (`/core/audit`, `/logs/events`, `/inventory/catalog`, `/feeds/search`). Khoảng thời gian: `from`, `to` (ISO UTC, **cả hai đầu gồm**, như `inRange` của mock). Tham số lạ bị bỏ qua, **trừ** giá trị sai kiểu/enum của tham số đã biết → 400. Đang dùng: `job`, `result`, `from`, `to` (`/ai/activity`); `q`, `user`, `group`, `from`, `to` (`/core/audit`); `window=24h|7d` (`/feeds/hot`); `window`, `source`, `q` (`/logs/events`); `asset` (`/findings`, `/honeypot/hits`); `finding` (`/response/plans`); `internal_only` (`/ai/assignments/suggestion`); `categories`, `from`, `to`, `format` (`/core/logs/export`).

**Sắp xếp:** mỗi endpoint có thứ tự cố định, nêu trong `summary`; chưa có tham số `sort`. Cần sắp theo cột khác thì thêm `sort=<trường>` hoặc `sort=-<trường>` (chỉ trường có index, danh sách trắng trong `contract.ts`) **[ĐX]**; sai → `400 bad_sort`.

## 5. Idempotency

Mục tiêu: bấm đúp, mạng chập chờn, hay proxy gửi lại không tạo bản sao hoặc chạy hành động hai lần.

**Hiện trạng:** mock không có khoá idempotency; một số hành động đã **idempotent tự nhiên** nhờ trạng thái: `POST /findings/{id}/applied` (mỗi item một lần), `POST /response/actions/{id}/approve` (mỗi người một lần: 409 `same_approver`/`not_pending`), `POST /response/proposals/{id}/request` (409 `already_requested`), `POST /scans/runs` (409 `already_running`), tạo thiết bị (409 `ip_in_use`/`hostname_in_use`/`duplicate_*`), `POST /response/actions/{id}/rollback` (409 `not_executed`).

**Quy ước [ĐX]:**

| Mục | Quy tắc |
|---|---|
| Header | `Idempotency-Key: <chuỗi 8–64 ký tự [A-Za-z0-9_-]>` |
| Áp dụng cho | **Mọi POST tạo tài nguyên** (trả 201) và POST hành động có tác dụng phụ ngoài DB: `POST /scans/runs`, `/response/actions/{id}/approve\|reject\|rollback`, `/response/proposals/{id}/request`, `/response/rules/{id}/manual`, `/notify/history/{id}/resend`, `/notify/channels/{type}/test`, `/inventory/import`, `/core/users`, `/core/users/{id}/reset-password`, `/core/updates/apply\|rollback\|bundle`, `/core/updates/os/install`, `/core/mcp/tokens`, `/inventory/agents/tokens`, `/ai/ask`, `/ai/cve/{id}/explain\|news`, `/reports/weekly/send`. PUT/PATCH/DELETE vốn idempotent theo ngữ nghĩa, không cần khoá. |
| Client | SPA sinh khoá mới (`crypto.randomUUID()`) cho **mỗi lần người dùng bấm**, dùng lại đúng khoá đó khi tự thử lại; nút bấm xong bị khoá tới khi có phản hồi. |
| Máy chủ | Lưu `(key, user_id, method, path, hash(thân))` và phản hồi trong **24 giờ** (bảng `core_idempotency`, DATA_MODEL §3). Cùng khoá + cùng yêu cầu → trả lại đúng phản hồi đã lưu (cùng mã HTTP), thêm `Idempotent-Replay: true`. Cùng khoá + yêu cầu khác (thân/đường dẫn khác) → `409 idempotency_key_reuse`. Yêu cầu đầu còn chạy → `409 idempotency_in_progress` kèm `Retry-After: 1`. |
| Không có header | Vẫn chạy bình thường (không bắt buộc); các ràng buộc 409 ở trên vẫn là lớp bảo vệ cuối. |
| Hành động sinh yêu cầu duyệt, token, thông báo | Gộp trùng theo khoá nghiệp vụ, không theo header: `resp_action.dedupe_key` (D-51: một yêu cầu mở mỗi (đích, hành động)), `notify_incident.dedupe_key`, `resp_rule_done` (DATA_MODEL §4.4, §4.11). |

Mã mới `idempotency_key_reuse`, `idempotency_in_progress` ghi vào mục 3.3 khi cài đặt.

## 6. Đồng thời (ETag / If-Match)

Hai người quản trị sửa cùng một cấu hình không được âm thầm đè nhau (mock không bảo vệ).

| Mục | Quy tắc [ĐX] |
|---|---|
| ETag | `GET` một tài nguyên hoặc đối tượng cấu hình trả `ETag: W/"<16 hex đầu của SHA-256 trên JSON chuẩn của thân>"`. Tính từ thân nên **không cần cột phiên bản trong DB**. |
| `If-Match` | `PUT`, `PATCH`, `DELETE` trên tài nguyên đó nhận `If-Match`. Không khớp bản hiện tại → `412 precondition_failed` thân lỗi chuẩn (mục 3.1); client gọi lại `GET` để lấy bản hiện tại. |
| Giai đoạn | M2: **tuỳ chọn** (máy chủ kiểm khi có header; thiếu header vẫn cho qua). SPA bắt đầu gửi `If-Match` ở các biểu mẫu sửa dài (quy tắc phản ứng, kênh, hồ sơ AI, nguồn feed tuỳ chỉnh, cài đặt). Sau khi SPA gửi đủ: bắt buộc cho `PUT` cấu hình (thiếu → `428 precondition_required`). |
| Không áp dụng | Bảng chỉ thêm (log, observation); hành động có máy trạng thái (approve, status) đã bảo vệ bằng kiểm tra trạng thái (`not_pending`, `already_open`, `busy`). |
| Danh sách | `If-None-Match` trên `GET` trả 304 (đặc biệt cho `GET /response/blocklist/{token}.txt`, mục 11.3). |

## 7. Xác thực và phân quyền

### 7.1 Phiên (SPA)

| Mục | Quy tắc |
|---|---|
| Cookie | `__Host-vedette_session` (khai trong `components.securitySchemes.session`): giá trị ngẫu nhiên ≥ 32 byte (base64url), `HttpOnly; Secure; SameSite=Strict; Path=/`. Máy chủ chỉ lưu SHA-256 (`core_session.token_hash`). Không có tiền tố miền, không `Domain`. Cùng lúc đặt `__Host-vedette_csrf` (§7.2). Sau một lần đăng nhập thành công còn đặt **cookie thiết bị tin cậy `__Secure-vedette_device`** (D-77): giá trị ký HMAC-SHA-256 (khoá của hộp trong `core_secret`) gồm id người dùng, `cred_version`, nonce và hạn 90 ngày; `HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth/` (chỉ các endpoint đăng nhập nhận được). Đây là cookie thứ ba và cuối cùng của Vedette, **cần thiết cho bảo mật đăng nhập** (không theo dõi, không rời hộp); đổi hoặc đặt lại mật khẩu làm mọi cookie thiết bị của tài khoản vô hiệu. |
| Đăng nhập | `POST /auth/login` `{email, password, code?}` (công khai). Sai email/mật khẩu → 400 `invalid_credentials` (cùng thông điệp cho "không có tài khoản" và "sai mật khẩu"). Tài khoản có 2 bước mà thiếu `code` → **401 `twofa_required`** kèm `method` (`app`\|`email`; với `email`: `sent_to`, `resend_after`, và máy chủ đã gửi mã). `code` sai → 400 `invalid_code` (app) / `wrong_code` / `too_many_tries` / `code_expired` (email). Tài khoản bị khoá → 403 `disabled`. Kênh email hỏng → 503 `twofa_email_unavailable` (**không bao giờ** lùi về chỉ-mật-khẩu, D-35). Đăng nhập thành công: tạo `core_session`, ghi `auth.login`, đặt `__Host-vedette_session`, `__Host-vedette_csrf` và `__Secure-vedette_device`. Yêu cầu mang `__Secure-vedette_device` hợp lệ của **đúng tài khoản đó** được đếm theo cookie (10 lần sai / 15 phút, tăng dần thời gian chờ) và **không** tính vào, cũng không bị chặn bởi, bộ đếm theo địa chỉ và /64 (D-77); cookie thiếu, sai chữ ký, hết hạn hoặc của người khác không được miễn. |
| Hết phiên | Phiên hết hạn/thu hồi → 401 `unauthenticated` ở mọi endpoint không công khai; SPA về trang đăng nhập. Hết hạn: **4 giờ không hoạt động hoặc 7 ngày kể từ lúc đăng nhập**, cái nào tới trước (D-71; `auth.IdleTimeout`, `auth.AbsoluteTimeout`); `last_seen` làm mới tối đa mỗi phút. |
| Thu hồi | `DELETE /core/account/sessions/{id}`, `POST /core/account/sessions/revoke-others`; không thu hồi chính phiên đang dùng (400 `current_session`, dùng `POST /auth/logout`). Thu hồi phiên khi đổi bảo mật (WP-04b, đã cài trong `core/auth`; quy tắc, không còn là đề xuất): đổi mật khẩu → **mọi** phiên của người đó kết thúc và phản hồi đặt lại `__Host-vedette_session` + `__Host-vedette_csrf` của một phiên mới cho đúng trình duyệt đó (người dùng vẫn đăng nhập; bản sao cookie cũ thì không: đổi định danh phiên sau thay đổi đặc quyền, OWASP); nếu yêu cầu mang cookie thiết bị `__Secure-vedette_device` còn hợp lệ trước khi đổi thì phản hồi cũng đặt cookie thiết bị mới cho mật khẩu mới (D-77: chủ vừa chứng minh mật khẩu); quản trị viên đặt lại mật khẩu hoặc đặt lại 2 bước → **mọi** phiên của người đó kết thúc trong cùng giao dịch; chính người dùng bật hoặc tắt 2 bước → mọi phiên của họ kết thúc và trình duyệt đang dùng nhận cookie của phiên mới như trên. Đổi mật khẩu, tắt 2 bước, bật 2 bước: trong giao dịch ghi, tài khoản bị khoá → 403 `disabled`, phiên đang dùng đã bị thu hồi hoặc hết hạn → 401 `unauthenticated`, mật khẩu đã bị đổi/đặt lại kể từ lúc được kiểm (`cred_version` đổi) → 400 `wrong_password` (mã đã có trong §3.3; "mật khẩu bạn vừa chứng minh không còn là mật khẩu hiện tại"). Một lần đăng nhập đang chạy mà mật khẩu (`cred_version`), trạng thái khoá hoặc kiểu 2 bước đổi trước khi nó ghi bị từ chối (400 `invalid_credentials`, hoặc 403 `disabled`), không tạo phiên. |
| Đăng xuất | `POST /auth/logout` công khai (không lỗi khi phiên đã hết), xoá cookie, 204. |
| Thiết lập lần đầu | `GET /setup` (công khai) cho biết `complete`; `POST /core/setup` chỉ chạy khi chưa thiết lập (sau đó 409 `already_setup`); tạo tổ chức, quản trị viên đầu tiên và một phiên cho họ (đặt `__Host-vedette_session` + `__Host-vedette_csrf`), bật gói module đã chọn, ghi `core_audit`, tất cả trong một giao dịch. **Mã cài đặt một lần (D-75)**: khi chưa có quản trị viên, hộp sinh một mã ngẫu nhiên (100 bit, dạng `XXXXX-XXXXX-XXXXX-XXXXX`), lưu qua `core/secrets`, in vào nhật ký của core mỗi lần khởi động còn mở cài đặt và xoá trong giao dịch tạo quản trị viên; thiếu hoặc sai mã → 403 `invalid_setup_code`, mã được xét **trước** mọi trường khác, so sánh thời gian hằng, mỗi lần đoán sai tính theo địa chỉ máy khách như đăng nhập (10 lần rồi 429 `rate_limited`; IPv6 thêm /64) và không có trần chung cho cả hộp (D-75, đã sửa sau rà bảo mật lần 2: trần chung là đòn khoá chủ hộp); sau khi cài đặt xong mọi `POST /core/setup` là 409 `already_setup` (cả `sample:true`). |
| SSO | `GET /core/auth-options` (công khai) `{oidc:boolean}`; `POST /core/sso/login` (công khai) bắt đầu OIDC. Đường gọi lại của nhà cung cấp OIDC chưa có trong hợp đồng (câu hỏi mở 5). |

### 7.2 CSRF

Mock không có CSRF. Quy ước **[ĐX]** (ARCH §5: cookie phiên + CSRF):

1. Cùng lúc đặt `__Host-vedette_session`, đặt cookie `__Host-vedette_csrf` (giá trị ngẫu nhiên, `Secure; SameSite=Strict`, **không** `HttpOnly`) và lưu SHA-256 của nó trong `core_session.csrf_hash`.
2. Mọi `POST/PUT/PATCH/DELETE` đã xác thực phải gửi header `X-CSRF-Token` bằng giá trị cookie đó (SPA đọc cookie, gắn header trong `request()` của `lib/api.ts`). Máy chủ so sánh SHA-256 của header với `csrf_hash`, so sánh thời gian hằng. Thiếu/sai → 403 `csrf_invalid` (mã mới).
3. Kiểm thêm `Origin` (hoặc `Referer`) bằng nguồn của hộp với các yêu cầu đổi trạng thái.
4. `GET` không bao giờ đổi trạng thái nên không cần CSRF (SSE `GET /events` vì thế an toàn).
5. **Miễn:** các POST công khai (`/auth/login`, `/auth/login/resend-code`, `/auth/logout`, `/core/sso/login`, `/core/setup`, `/response/approve/{token}`, `/intake/osquery/*`). Chúng được bảo vệ bằng thông tin xác thực/ token một lần trong chính yêu cầu, và `SameSite=Strict` cho trình duyệt.
6. CSP nghiêm, không script nội tuyến (ARCH §6); không CORS (SPA cùng nguồn); `Cache-Control: no-store` cho mọi phản hồi API có dữ liệu riêng.

### 7.3 Token

| Token | Dùng để | Chuyển bằng | Lưu | Phạm vi / hết hạn | Endpoint |
|---|---|---|---|---|---|
| **Token MCP** (S-MCP-1) | Máy khách MCP (Claude Desktop, v.v.) gọi công cụ **chỉ đọc** | `Authorization: Bearer <token>` tới máy chủ MCP riêng (`bind 127.0.0.1`, `port 8765`, `/mcp`; không phải REST) | `mcp_tokens.token_hash` + `last4`; hiện bản đầy đủ **đúng một lần** | `scopes` ⊂ {`assets`, `findings`, `feeds`}; công cụ: `list_assets`, `get_asset`, `list_findings`, `get_finding`, `lookup_cve`, `lookup_ioc`, `hot_vulnerabilities`; hết hạn đến khi thu hồi | `GET/PATCH /core/mcp`, `POST/DELETE /core/mcp/tokens*` (admin) |
| **Token đăng ký osquery** (D-34) | Đăng ký máy chủ osquery với hộp | `enroll_secret` lúc chạy lệnh cài (không nằm trong URL); sau đó `node_key` riêng mỗi máy | `intake_agent_tokens.token_hash` | Mặc định 7 ngày (0–365; 0 = không hết hạn), thu hồi được; chỉ để đăng ký | `POST/DELETE /inventory/agents/tokens*` (admin); `POST /intake/osquery/status\|enroll\|config\|log` (công khai, xác thực bằng token hoặc `node_key`) |
| **Token danh sách chặn** (D-44) | Firewall tự kéo danh sách | Đoạn đường dẫn `/response/blocklist/{token}.txt` | `core_secret` | Đến khi xoay (`POST /response/blocklist/token`) | `GET /response/blocklist/{token}.txt` (công khai) |
| **Token duyệt qua email** (D-46) | Một người duyệt một yêu cầu | Đoạn đường dẫn `/response/approve/{token}` (trong liên kết thư) | `resp_approval_token.token_hash` | **Một lần, 30 phút**, gắn với yêu cầu và người nhận; bấm xác nhận bằng POST (trình quét liên kết không tự duyệt) | `GET/POST /response/approve/{token}` (công khai) |
| **Token REST theo phạm vi** (ARCH §5 "API token") | Tích hợp bên ngoài gọi REST | — | — | **Chưa có story, chưa có mock, chưa xây.** Chỉ định nghĩa khi có story (rule `no-imagined-features`). Câu hỏi mở 6. | — |

Định dạng chi tiết (độ dài, tiền tố, HMAC, vòng đời) **thuộc spec riêng, không lặp ở đây**: token đăng ký osquery và `node_key`: `docs/specs/osquery-intake.md`; token duyệt (`v1.<token_id>.<mac>`): `docs/specs/approval-tokens.md`; token danh sách chặn: `docs/specs/blocklist-format.md`. Quy ước chung: ≥ 128 bit ngẫu nhiên từ `crypto/rand`; hiện bản rõ **đúng một lần** (trừ token danh sách chặn, nằm trong URL hiển thị); nhật ký truy cập và `core_audit` **che** đoạn token trong đường dẫn (`/response/blocklist/*`, `/response/approve/*`, `/approve/*`).

### 7.4 RBAC

Ba vai, theo thứ tự `viewer < operator < admin` (`rank` trong `mocks/http.ts` và `lib/session.ts`). Mỗi endpoint khai **vai tối thiểu** ở `contract.ts` trường `role: 'viewer' | 'operator' | 'admin' | 'public'`:

- `openapi.json` ghi thành `x-min-role` trên mỗi thao tác; `public` thêm `security: []` (không cần phiên). Đếm hiện tại (đo từ `core/api/routes` sinh từ `openapi.json`, 2026-11-09): **admin 133 · viewer 80 · operator 47 · public 14** (274 thao tác).
- Mock thực thi bằng `guard(min)` ở đầu handler; backend thực thi bằng **middleware sinh từ `x-min-role`**, không đặt kiểm tra tay trong từng handler. Không có `x-min-role` thì không có route: test đối chiếu hai chiều (mục 12.1).
- `viewer`: chỉ xem; thấy `*_last4` ở vài endpoint đọc (ví dụ `GET /ai/profiles`), **không bao giờ** thấy bí mật; endpoint cấu hình có bí mật đều đòi admin. `operator`: thao tác vận hành (đổi trạng thái phát hiện, quét, duyệt hành động, thêm/sửa thiết bị, gửi thử). `admin`: cấu hình hệ thống, người dùng, kênh, AI, feed, module, cập nhật.
- **401 trước 403:** không phiên → 401; đủ phiên, thiếu vai → 403 `forbidden`; tài khoản bị khoá → 403 `disabled`.
- **Cổng bổ sung ngoài vai** (kiểm ở tầng dịch vụ, mã riêng): duyệt hành động phải là người dùng có vai ≥ operator **và** có tên trong danh sách người duyệt của kênh (`approver_not_listed`, `viewer_not_allowed`); hành động rủi ro cao chỉ duyệt trong ứng dụng kèm mã 2 bước (`in_app_required`, `twofa_required`, `code_required`); hành động đổi thiết bị khác cần công tắc thực thi (`execution_off`); tự bảo vệ (`last_admin`, `self_disable`, `self_reset`, `current_session`); `POST /response/execution` cần admin + đã bật 2 bước + gõ đúng câu chấp nhận rủi ro (`twofa_required`, `phrase_mismatch`).
- Không có phạm vi dữ liệu theo người dùng/site (D-24: chưa đa site/tenant).
- Đổi vai/khoá người dùng thu hồi hiệu lực ở lần gọi kế tiếp (vai đọc từ DB mỗi yêu cầu, không nhét vào cookie).

## 8. Giới hạn tần suất

Mock chỉ có giới hạn **nghiệp vụ** (bảng dưới); chưa có giới hạn tần suất HTTP. Phần HTTP là **[ĐX]**.

| Giới hạn | Giá trị | Nguồn | Phản hồi khi vượt |
|---|---|---|---|
| Gửi lại mã 2 bước qua email | 60 s giữa hai lần; tối đa 5 mã/giờ cho đăng nhập và **5 mã/giờ riêng cho mã duyệt** (`core_email_code_send.kind`, D-98; giãn 60 s tính chung theo người); mã sống 10 phút; tối đa 5 lần nhập sai (D-35) | `core/emailCode.ts` | 429 `resend_too_soon` (kèm `retry_after`), 429 `too_many_codes` (kèm `retry_after` và `Retry-After`: giây tới khi lượt gửi cũ nhất ra khỏi cửa sổ 1 giờ); 400 `too_many_tries`, `code_expired` |
| Xác thực đích ngoài | 10 lần/giờ (`MAX_ATTEMPTS_PER_HOUR`), tối đa 20 đích (D-25) | `exposure/mocks.ts` | 429 `rate_limited`; 400 `too_many` |
| Token AI mỗi ngày | `daily_cap` theo hồ sơ và theo cấu hình chung | `ai/mocks.ts` | 429 `daily_cap` |
| Phản hồi: hành động thiết bị | `max_per_hour` (mặc định 3); cầu dao `breaker_max_per_hour` (20); `multi_target_max` (5); `max_per_hour` mỗi quy tắc (≤ 100); ngân sách AI `budget_hour` 2 / `budget_day` 5 | `response/state.ts` | 409/403 qua `refuse()` (ghi `resp_log` loại `refused`/`breaker`) |
| Đăng nhập sai | ARCH §6 "rate limit đăng nhập"; chưa có số **[ĐX]** 10 lần sai / 15 phút theo cặp (IP, email), tăng dần thời gian chờ. Lượt thử được tính ngay khi bắt đầu và trả lại khi đúng mật khẩu (các lượt song song không lọt qua nhau). IPv6 tính hai lần: theo từng địa chỉ (10, như IPv4) và theo cặp (/64, email) với trần 100, nên một máy xoay trong /64 vẫn bị chặn nhưng không khoá được cả /64 chỉ bằng 10 lần đoán; IPv4 theo địa chỉ. Hết thời gian chờ rồi gõ đúng mật khẩu không kéo dài thêm thời gian chờ. Mã 2 bước có bộ đếm riêng **theo tài khoản** (không theo IP): 10 lần sai / 15 phút → 429, tính cả mã xác nhận khi bật TOTP (khoá chờ xác nhận bị huỷ sau 5 mã sai). Mật khẩu gõ lại để đổi mật khẩu hoặc bật/tắt 2 bước có bộ đếm xác thực lại riêng theo tài khoản (cùng mức, ghi `auth.reauth_failed`). **Cookie thiết bị (D-77)**: một yêu cầu mang cookie thiết bị hợp lệ của tài khoản được đếm theo cookie (10 lần sai / 15 phút, cùng cách tăng thời gian chờ), không theo địa chỉ, nên một người cùng /64 đoán 100 lần không khoá được chủ tài khoản đã có cookie; cookie bị đánh cắp vẫn chỉ được 10 lần / 15 phút | `core/auth` | 429 `rate_limited`, `Retry-After` |
| Băm/kiểm mật khẩu (argon2, 64 MiB mỗi lần) | tối đa `min(GOMAXPROCS/2, GOMEMLIMIT/4/64 MiB)` lần cùng lúc, ít nhất 1 (`auth.Config.MaxHashing`; GOMAXPROCS theo hạn mức của container); chờ tối đa 2 s (`HashWait`), hàng đợi 4 lần số khe; quá thì từ chối | `core/auth` | 503 `server_busy`, `Retry-After: 3` |
| API đã xác thực | **[ĐX]** 600 yêu cầu/phút mỗi phiên (token bucket); SSE không tính | | 429 `rate_limited` |
| Điểm công khai | **[ĐX]** 60 yêu cầu/phút mỗi IP cho `/auth/*`, `/response/approve/*`, `/response/blocklist/*`, `/install/*`, `/intake/*` | | 429 |

Phản hồi 429 (và 503 `server_busy`) luôn có `Retry-After: <giây>`, thân chuẩn mục 3.1 (và `retry_after` trong `error` khi có), cộng `RateLimit-Limit/Remaining/Reset` trên endpoint giới hạn **[ĐX]**. Giới hạn **ra ngoài** (tốc độ quét `rate` 1–20 req/s, `inv_setting.active.rate`) là cấu hình quét, không phải giới hạn API.

## 9. Phiên bản và ngừng hỗ trợ

- **`/api/v1`** là phiên bản duy nhất hiện có (`info.version` của `openapi.json`: `0.1.0-m1`). SPA nhúng trong cùng binary nên SPA và API luôn cùng phiên bản; phiên bản chỉ bảo vệ **bên dùng ngoài**: máy khách MCP, script cài osquery trên máy chủ khách, firewall kéo danh sách chặn, trang duyệt email.
- **Thay đổi tương thích (làm trong `v1`):** thêm endpoint; thêm trường **tuỳ chọn** vào thân yêu cầu; thêm trường vào phản hồi; thêm tham số query tuỳ chọn; thêm mã lỗi mới; thêm trường mở rộng vào `error`. Client phải bỏ qua trường lạ. **Lưu ý:** thêm giá trị enum là thay đổi **có điều kiện**: SPA kiểm bằng Zod chặt, nên đổi enum buộc sửa SPA trong cùng PR; với bên dùng ngoài, thêm giá trị enum phải ghi trong ghi chú phát hành.
- **Thay đổi phá vỡ** (đổi tên/bỏ trường, đổi kiểu, siết ràng buộc, đổi nghĩa mã lỗi hay HTTP, đổi dạng canonical của log chuỗi hash): chỉ ở `v2`, chạy song song với `v1`.
- **Ngừng hỗ trợ:** endpoint/trường bị bỏ trả `Deprecation: true` và `Sunset: <HTTP-date>`, `Link: <…>; rel="successor-version"`; ghi vào `docs/UPDATES.md` và ghi chú phát hành. Tối thiểu **2 bản phát hành ổn định hoặc 90 ngày**, tuỳ cái nào dài hơn **[ĐX]**. Sau `Sunset` trả `410 gone`.
- **Hợp đồng sống lâu (đóng băng trong một major):** định dạng danh sách chặn `GET /response/blocklist/{token}.txt` (đang nằm trong cấu hình firewall khách), nội dung và tham số `GET /install/osquery.sh|.ps1`, giao thức nhận dữ liệu osquery (`/intake/*`, `docs/specs/osquery-intake.md`), trang duyệt email (`/response/approve/{token}`), giao thức MCP. Thay đổi chúng phá hộp đã triển khai, nên coi như phá vỡ.
- Mỗi release gắn `info.version` bằng phiên bản phần mềm; `api/openapi.json` đi cùng release (D-12, ký cùng bản cập nhật).

## 10. Sự kiện thời gian thực: SSE `/api/v1/events`

**Hiện trạng:** SPA **chưa dùng SSE**; nó thăm dò (polling): `scan/runs` mỗi 1 giây khi có lần quét đang chạy, `ai/knowledge` mỗi 1 giây khi có tài liệu chưa `ready`, `core/os-run` mỗi 500 ms khi đang cập nhật OS, `response/actions` mỗi 30 giây. Mọi chỗ còn lại làm mới khi người dùng thao tác (`invalidateQueries`). SSE thay các vòng thăm dò này và cho trang tự cập nhật; **REST vẫn là nguồn sự thật**: sự kiện chỉ là gợi ý "dữ liệu đã đổi, hãy tải lại".

### 10.1 Giao thức

| Mục | Quy tắc [ĐX] |
|---|---|
| Endpoint | `GET /api/v1/events` (`Content-Type: text/event-stream`), vai tối thiểu `viewer`, xác thực bằng cookie phiên (`EventSource` cùng nguồn). Không cần CSRF (GET). |
| Khung | `id: <số tăng đơn điệu>` · `event: <tên>` · `data: <JSON một dòng>`. Nhịp tim: dòng chú thích `: ping` mỗi 25 giây; `retry: 3000`. |
| Nội dung `data` | Chỉ **định danh và trạng thái**, không địa chỉ, không bí mật, không nội dung log/AI. SPA tải lại bằng REST (nơi phân quyền thật được kiểm). |
| Lọc theo vai | Máy chủ chỉ gửi sự kiện mà vai của người nghe đủ đọc (cột "Vai" dưới đây = vai của `GET` tương ứng). Vai đổi/phiên bị thu hồi → đóng luồng; SPA mở lại và nhận 401. |
| Nối lại | Trình duyệt gửi `Last-Event-ID`. Máy chủ giữ vòng đệm 1.000 sự kiện hoặc 5 phút (tuỳ cái nào nhỏ hơn) trong bộ nhớ. Quá cũ/không có → gửi `event: resync` (`data: {}`); SPA tải lại **mọi** query đang mở. Giao hàng **tối đa một lần**, không đảm bảo thứ tự giữa sự kiện khác loại. |
| Giới hạn | Tối đa 5 kết nối mỗi phiên; mỗi người dùng một kết nối cho mỗi tab. Proxy phải tắt đệm (`X-Accel-Buffering: no`). Không đưa vào `openapi.json` ở dạng JSON thường (mục 12, câu hỏi mở 7). |

### 10.2 Danh mục sự kiện

Dẫn từ các query SPA đang giữ (`queryKey`) và các chỗ đang thăm dò. "Làm mới" = `queryKey` của SPA nên được `invalidate` khi nhận sự kiện.

| Sự kiện | `data` | Phát khi | Vai | Làm mới |
|---|---|---|---|---|
| `module.changed` | `{id, enabled}` | bật/tắt module | viewer | `['modules']`, điều hướng |
| `device.changed` | `{id, change: created\|updated\|deleted\|approved}` | thiết bị thêm/sửa/xoá/duyệt; cảm biến, agent, quét cập nhật | viewer | `['inventory','devices']`, `['inventory','device',id]`, `['findings']` |
| `sensor.changed` | `{id, status}` | cảm biến online/offline, đổi giao diện/SPAN | admin | `['inventory','sensors']` |
| `agent.synced` | `{kind: osquery\|wazuh, hosts}` | agent gửi dữ liệu / Wazuh đồng bộ xong | admin | `['inventory','agents']`, `['inventory','devices']` |
| `finding.changed` | `{id, asset_id, status, change: created\|status\|applied\|rescan}` | phát hiện mới, đổi trạng thái, quét xác nhận | viewer | `['findings']`, `['findings','detail',id]`, `['inventory','device',asset_id]`, `['response','plans']` |
| `feed.updated` | `{source_id, status, records}` | một nguồn feed kéo xong hoặc lỗi | viewer | `['feeds']` (hot, status, sources, search) |
| `scan.run.changed` | `{id, status, done, total}` | lần quét tiến triển/kết thúc (thay thăm dò 1 giây) | viewer | `['scan','runs']`, `['scan','targets']`, `['findings']` |
| `scan.event.created` | `{id, cve, result}` | quét lại theo KEV mới | viewer | `['scan','events']` |
| `exposure.changed` | `{target_id, change: verified\|expired\|scanned}` | xác thực/quét đích ngoài | viewer | `['exposure']`, `['exposure','target',id]` |
| `honeypot.hit` | `{id, kind}` | bẫy bị chạm | viewer | `['honeypot']`, `['honeypot','hits',…]` |
| `incident.changed` | `{id, status, change: created\|updated}` | sự cố mới hoặc đổi trạng thái (D-52) | viewer | `['notify','incidents']`, `['notify','incident',id]` |
| `notify.sent` | `{kind, ref_id, channel, ok}` | một tin gửi xong hoặc lỗi | viewer | `['notify','history']`, `['notify','finding',id]` |
| `log.source.changed` | `{id, state: receiving\|silent\|never}` | nguồn log bắt đầu/ngừng nhận | viewer | `['logs','sources']` |
| `log.ioc_hit` | `{id}` | kết nối khớp IOC | viewer | `['logs','digest']`, `['response','events']` |
| `response.action.changed` | `{id, status}` | yêu cầu mới, được duyệt/từ chối/hết hạn/thực thi/hoàn tác (thay thăm dò 30 giây) | viewer | `['response','actions']`, `['response','metrics']` |
| `response.log.appended` | `{id, kind}` | một dòng `resp_log` mới | operator | `['response','log']` |
| `response.state` | `{execution, breaker_tripped, ai_paused}` | công tắc thực thi, cầu dao, tạm dừng AI đổi | viewer | `['response','settings']`, biểu ngữ |
| `response.blocklist.changed` | `{count}` | danh sách chặn đổi (thêm/gỡ/hết TTL) | admin | `['response','blocklist']` |
| `ai.activity.appended` | `{id, job, result}` | một lời gọi AI mới trong `ai_activity` | operator | `['ai','activity']`, `['ai','usage']`, `['ai','runs']` |
| `ai.knowledge.progress` | `{id, status, chunks}` | tài liệu RAG đổi `uploading → indexing → ready` (thay thăm dò 1 giây) | admin | `['ai']` (kho tri thức) |
| `core.os.run` | `{id, status, line_count}` | cập nhật OS đang chạy/xong (thay thăm dò 500 ms) | viewer | `['core','os-run']`, `['core','os']` |
| `core.update.changed` | `{component, action: available\|applied\|rolled_back}` | có bản mới / đã áp / quay lại | viewer | `['core','updates']`, `['core','os']` |
| `audit.appended` | `{id}` | một dòng `core_audit` mới | admin | `['core','audit',…]` |
| `user.changed` | `{id, change: created\|updated\|disabled\|twofa_reset}` | quản trị người dùng | admin | `['core','users']` |
| `session.revoked` | `{id}` | gửi **riêng** cho người dùng có phiên bị thu hồi | (chủ phiên) | `['me']` (rồi 401) |
| `report.sent` | `{id, status}` | báo cáo tuần gửi xong | viewer | `['reports','history']` |
| `resync` | `{}` | mất sự kiện (quá cũ) | (mọi) | **mọi query đang mở** |

Mỗi sự kiện sinh từ chính giao dịch nghiệp vụ **sau khi commit** (không phát khi rollback). Sự kiện được **gộp** theo `(tên, id)` trong cửa sổ 250 ms để tránh bão làm mới khi nhập hàng loạt.

## 11. Tệp: tải xuống, tải lên

### 11.1 Tải xuống

Có **11** thao tác trả tệp (`response: 'file'` trong `contract.ts`, `application/octet-stream` trong `openapi.json`). Quy ước:

| Quy tắc | Chi tiết |
|---|---|
| Xác thực | Như endpoint thường (cookie phiên); GET, không cần CSRF. Ngoại lệ công khai: `/install/osquery.sh|.ps1`, `/response/blocklist/{token}.txt`. |
| Tên tệp | `Content-Disposition: attachment; filename="…"` do máy chủ đặt (SPA `download()` hiện tự đặt tên; chuyển sang đọc header, còn tên dự phòng). Tên có ngày UTC: `vedette-<loại>-YYYYMMDD.<đuôi>`. |
| Loại nội dung | Hiện mock trả `application/octet-stream`; backend trả loại đúng: CSV `text/csv; charset=utf-8`, JSON `application/json`, script `text/x-shellscript` / `text/plain`, danh sách chặn `text/plain; charset=utf-8`, gói `application/octet-stream` **[ĐX]**. |
| Không lưu đệm | `Cache-Control: no-store` (trừ danh sách chặn và tệp cài: mục dưới). |
| Streaming | Tệp lớn (xuất log, sao lưu) trả theo luồng, không dựng cả tệp trong bộ nhớ; `GET /core/logs/export` giới hạn theo `from`/`to`/`categories` và có `head_hash`, `count` ở phần đầu (DATA_MODEL §5.3). |

| Endpoint | Vai | Nội dung |
|---|---|---|
| `GET /core/audit/export` | admin | CSV/JSON nhật ký kiểm toán đã lọc |
| `GET /core/logs/export` | admin | **mọi log của hộp** (kiểm toán, AI, phản ứng, probe quét, cảnh báo, log thiết bị), JSON hoặc CSV, theo `categories` (D-48) |
| `GET /core/data/export` | admin | xuất dữ liệu của người dùng (S-CORE-1) |
| `GET /core/data/backup` | admin | sao lưu nhất quán (`VACUUM INTO`/`pg_dump`, **không** kèm file khoá chủ: DATA_MODEL câu hỏi mở 6) |
| `GET /core/updates/bundle` | operator | gói cập nhật ngoại tuyến đã ký |
| `GET /inventory/export.csv`, `/inventory/import-template.csv` | viewer | danh sách thiết bị; mẫu nhập |
| `GET /scans/probes.csv` | viewer | nhật ký probe (SYS-7) |
| `GET /install/osquery.sh`, `GET /install/osquery.ps1` | công khai | script cài (D-34); không chứa token (token nhập lúc chạy); đi kèm SHA-256 hiển thị ở `GET /inventory/agents` |
| `GET /response/blocklist/{token}.txt` | công khai (token) | mục 11.3; `docs/specs/blocklist-format.md` |

### 11.2 Tải lên

Mock nhận **JSON có nội dung nhúng**, chưa có `multipart/form-data`: `POST /inventory/import` `{filename, size, sha256, text}`; `POST /core/updates/bundle` `{name, size, sha256, content}`; `POST /ai/knowledge` `{name, size, jobs?}` (chỉ siêu dữ liệu, chưa có nội dung).

| Mục | Quy tắc [ĐX] |
|---|---|
| Kênh | `application/json` với nội dung nhúng cho tệp ≤ 200 KB (`POST /inventory/import`: 200.000 byte, 500 dòng, `MAX_IMPORT_BYTES`/`MAX_IMPORT_ROWS`). Lớn hơn: `multipart/form-data` một phần `file` + phần `meta` JSON. |
| Trần | Nhập thiết bị 200 KB / 500 dòng (400 `too_large`/`too_many_rows`); gói cập nhật 5 MB (`MAX_UPLOAD`); tài liệu RAG 10 MB (`too_large`), chỉ PDF, MD, TXT, DOCX (`invalid_type`); khoá SSH riêng 16 KB. Quá trần → **413 `too_large`** (mục 1). Đọc thân qua `http.MaxBytesReader`, không bao giờ tải hết vào bộ nhớ trước khi kiểm. |
| Toàn vẹn | `sha256` trong thân là **kiểm tra của client**: máy chủ tính lại và từ chối nếu lệch (`invalid_bundle` cho gói; mã mới `checksum_mismatch` cho tệp khác **[ĐX]**). |
| Gói cập nhật | Máy chủ kiểm chữ ký minisign **trước** khi giải nén/áp (`bad_signature`, `not_bundle`, `invalid_bundle`); không ký hoặc ký sai → từ chối (rule `security.md`). |
| Nội dung | Tệp tải lên là dữ liệu không tin cậy (SYS-6): parser fail-closed; CSV chống công thức (`=`, `+`, `-`, `@` đầu ô khi xuất lại). Không giải nén lồng nhau không giới hạn. |
| Lưu | Tài liệu RAG: lưu **đoạn văn bản đã chỉ mục**, không giữ tệp gốc (DATA_MODEL câu hỏi mở 16). Không có thư mục tải lên công khai. |

### 11.3 Điểm công khai (không cần phiên)

Mười bốn thao tác `role: 'public'`:

| Endpoint | Mục đích | Bảo vệ |
|---|---|---|
| `POST /auth/login`, `/auth/login/resend-code`, `/auth/logout` | Đăng nhập, gửi lại mã, đăng xuất | giới hạn tần suất; `resend-code` đòi cả mật khẩu để người lạ không bắt hộp thư người khác nhận mã |
| `GET /core/auth-options`, `POST /core/sso/login` | Cho trang đăng nhập biết có SSO; bắt đầu OIDC | không lộ cấu hình, chỉ `{oidc:boolean}` |
| `GET /setup`, `GET /core/setup/modules`, `POST /core/setup` | Thiết lập lần đầu | `POST` chỉ khi chưa thiết lập (409 `already_setup` sau đó) |
| `GET /install/osquery.sh`, `/install/osquery.ps1` | Script cài osquery do hộp phục vụ (D-34) | không chứa bí mật; kèm SHA-256 (hiện ở trang Agent); `Cache-Control: no-cache` |
| `POST /intake/osquery/status` | Script cài hỏi "máy đã báo về chưa". Spec `docs/specs/osquery-intake.md` còn có `GET /intake/ca.pem` (công khai) và `POST /intake/osquery/enroll\|config\|log` (giao thức TLS của osquery): **chưa có trong `contract.ts`** (câu hỏi mở 8) | xác thực bằng token đăng ký / `node_key` trong yêu cầu; giới hạn kích thước thân |
| `GET /response/approve/{token}` | Trang duyệt qua email: chỉ **hiển thị** (`state`: `ready\|expired\|used\|decided\|unknown`, tiêu đề, thay đổi trước/sau) | token một lần, 30 phút, gắn yêu cầu + người nhận (D-46); không nói token nào tồn tại (`unknown`); `Cache-Control: no-store`; `X-Frame-Options: DENY` |
| `POST /response/approve/{token}` | Bấm **xác nhận** `{decision: approve\|reject}` | cần POST (không GET) để trình quét liên kết của hộp thư không tự duyệt; dùng một lần; kiểm danh sách người duyệt và vai; hành động rủi ro cao bị từ chối ở đây (`in_app_required`); ghi `core_audit` + `resp_log` |
| `GET /response/blocklist/{token}.txt` | Firewall kéo danh sách chặn (D-44) | xem dưới |

**Danh sách chặn:** `.txt` = `text/plain; charset=utf-8`, mỗi dòng một IP hoặc CIDR (khớp FortiGate External Block List, Palo Alto EDL, pfSense/OPNsense URL Table, MikroTik `fetch`); các biến thể (`.json`, `.domains.txt`), comment, ETag/`If-None-Match` (304) và hướng dẫn theo hãng: `docs/specs/blocklist-format.md` (nguồn chuẩn). Token sai → 404 như mọi token công khai. Mỗi lần kéo cập nhật `last_fetch {at, from}` (ghi nhận nguồn, không ghi nội dung). Không `Set-Cookie`. Đây là **hợp đồng sống lâu** (mục 9).

## 12. Đường ống hợp đồng

```
web/src/features/<m>/contract.ts  (Zod + defineEndpoints)         ← nguồn chân lý (D-18)
        │  web/src/lib/openapi.ts  (import.meta.glob '../features/*/contract.ts')
        ▼
pnpm --dir web openapi           (web/scripts/openapi.mjs)         ← sinh, KHÔNG sửa tay
        ▼
api/openapi.json  (OpenAPI 3.1, 267 thao tác)                      ← commit cùng contract
        ▼
Go codegen (M2: type + giao diện handler, strict)                   ← backend phải khớp
```

- **Nơi khai báo:** mỗi endpoint là một phần tử `defineEndpoints([...])` với `method`, `path` (không có `/api/v1`), `summary` (một câu tiếng Anh), `stories` (ID story), `role`, `params`/`query`/`body`/`response` (Zod; `null` = 204; `'file'` = tải tệp), `example` (cho test GET). Kiểu của SPA lấy bằng `z.infer` từ chính schema (`types.ts`), nên SPA, mock và backend không lệch.
- **Sinh OpenAPI:** `z.toJSONSchema(…, {target: 'draft-2020-12', io: 'output'})`; thao tác có `operationId` = `<module>_<method>_<path>`, `tags: [module]`, `x-stories`, `x-min-role`; mọi thao tác thêm `default → Error`; `securitySchemes.session` = cookie `__Host-vedette_session`.
- **Lệch đã biết** (giữa quyết định/mock và hợp đồng sinh ra): D-18 ghi `api/openapi.yaml`, thực tế `api/openapi.json` (spec này coi **`.json` là chuẩn**, câu hỏi mở 9); ~~POST tạo trả 201 nhưng khai 200~~ (đã sửa: `status` trong `Endpoint`); không có khai lỗi theo thao tác; SSE và `multipart` chưa biểu diễn được (`Endpoint` chưa có `errors`, kiểu `stream`).
- **Mở rộng `Endpoint`**: `status?: 200 | 201 | 202` **đã có** (mặc định 200; 204 khi `response === null`; WP-06). Còn đề xuất **[ĐX]**: `errors?: string[]` (mã lỗi có thể trả → `x-errors` + bảng mục 3.3 sinh tự động), `response: 'file' | 'stream'`, `contentType?` cho tệp/đa phần.

### 12.1 Kiểm tra lệch (CI)

Đã có (chạy bằng `pnpm --dir web test` / `make verify`, `web/src/lib/contract.test.ts`): (1) mọi handler mock có trong `contract.ts` **và ngược lại**, theo module; (2) mọi `GET` có `example` trả dữ liệu **khớp schema** Zod; (3) `api/openapi.json` bằng đúng bản `buildOpenApi()` hiện tại (lệch → chạy `pnpm openapi`). Repo **chưa có workflow CI** (`.github/` chỉ có `CODEOWNERS`, mẫu issue/PR); `make verify` là cổng cục bộ.

Thêm khi có Go **[ĐX]**, đều chạy trong `make verify` và workflow CI đầu tiên:

| Kiểm tra | Cách | Bắt lỗi gì |
|---|---|---|
| Sinh lại không đổi | `pnpm --dir web openapi && git diff --exit-code api/openapi.json` | quên sinh lại sau khi sửa `contract.ts` |
| Go sinh lại không đổi | chạy codegen vào thư mục tạm, `diff` với mã đã commit | sửa tay mã sinh, hoặc quên sinh lại |
| Hai chiều route ↔ spec | bảng route của router Go so với `paths` trong `openapi.json` (cùng tinh thần test mock) | route thừa/thiếu |
| Vai tối thiểu | mọi route có `x-min-role`; thử gọi với vai thấp hơn → 403, không phiên → 401 | thiếu kiểm quyền |
| Response khớp schema | với mỗi thao tác, gọi handler (`httptest`) với fixture và kiểm thân + mã HTTP theo schema | backend lệch hợp đồng |
| Mã lỗi nằm trong danh mục | mọi `code` trả về ∈ bảng mục 3.3 (hoặc `errors` của thao tác) | mã lỗi mới chưa khai |
| Mọi mutation ghi `core_audit` | test theo thao tác POST/PUT/PATCH/DELETE (SYS-3) | thiếu kiểm toán |
| Module tắt → không route | gọi endpoint của module tắt → 404 (SYS-5) | module tắt vẫn phục vụ |

### 12.2 Thêm một endpoint, từng bước

1. **Story.** Có ID trong `docs/USER_STORIES.md` (`rules/no-imagined-features.md`). Không có: dừng, đề xuất story `[chưa]` rồi hỏi kien.
2. **GUI trước** (`rules/gui-first.md`): màn hình đã qua plan → build → critique; không viết backend cho màn hình chưa duyệt.
3. **Thiết kế đường dẫn** theo mục 1 (nhóm module, danh từ, động từ là POST vào tài nguyên con) và chọn `role` tối thiểu (mục 7.4).
4. **Khai trong `web/src/features/<m>/contract.ts`**: schema Zod (dùng lại schema sẵn có, `.describe()` cho điều không hiển nhiên), rồi thêm phần tử vào `endpoints` với `stories`, `role`, `example` nếu là GET có tham số. `summary` một câu tiếng Anh.
5. **Mock** trong `features/<m>/mocks.ts`: `guard(role)` ở đầu; validate ở biên và trả lỗi qua `fail(status, code, message)` bằng **mã có trong mục 3.3** (mã mới → thêm vào bảng và kèm HTTP); mutation gọi `audit(...)`; trả đúng mã 200/201/204 theo mục 1.
6. **Kiểu và hook**: `z.infer` trong `types.ts`, hàm gọi trong `api.ts` (`useQuery`/`useMutation`; `invalidateQueries` đúng khoá; nếu endpoint đổi dữ liệu thời gian thực, thêm sự kiện SSE ở mục 10.2).
7. **Chạy**: `pnpm --dir web exec vitest run src/lib/contract.test.ts -t "<module>"` (handler ↔ contract, GET khớp schema), rồi `pnpm --dir web openapi` để sinh lại `api/openapi.json`; commit file đó **cùng** `contract.ts`. Không sửa tay `api/openapi.json`.
8. **Tài liệu**: cập nhật `CONTRACT.md` + `IMPACT.md` của module (`rules/contracts.md`); bảng/cột mới → `docs/DATA_MODEL.md`; luồng dữ liệu ra ngoài mới → `PRIVACY.md` + UI Cài đặt → Quyền riêng tư (`rules/legal.md`); dependency mới → `THIRD_PARTY_NOTICES.md`.
9. **Chạy `make verify`** (tsc + lint + vitest + build rồi dọn, `rules/build-artifacts.md`).
10. **Backend (sau khi GUI được duyệt):** sinh lại mã Go từ `api/openapi.json`; thêm migration một chiều của module (DATA_MODEL §6); cài handler **chỉ** qua giao diện sinh ra, kiểm tra vào qua schema trước dịch vụ (SYS-2), ghi `core_audit` (SYS-3), không gọi shell (SYS-1); viết test hợp đồng Go (`-run Contract`, `rules/contracts.md`); `make verify` có `go test ./...` + `golangci-lint` khi Go có mặt.
11. **PR** trên nhánh `feat/…` (`docs/…` cho tài liệu); không push `main`; AI không tạo git tag.

## 13. Câu hỏi mở

| # | Câu hỏi | Gợi ý / ảnh hưởng |
|---|---|---|
| 1 | ~~**POST tạo trả 201 nhưng hợp đồng khai 200** (16 chỗ)~~ Đã làm ở WP-06: `status` trong `Endpoint`, `openapi.json` sinh lại. Còn lại: hai endpoint trả 201/200 tuỳ trường hợp chưa biểu diễn được. | |
| 2 | **Khai mã lỗi theo thao tác** (`errors: [...]`) để bảng 3.3 sinh tự động thay vì trích tĩnh bằng regex (hạn chế: nhiều mã gắn "validator dùng chung"). Có làm không? | Giảm công bảo trì bảng 313 mã; cần sửa toàn bộ `contract.ts` |
| 3 | **Phân trang `GET /inventory/devices`, `/findings`:** SPA tải toàn bộ và lọc ở client. Chuyển sang phân trang/ lọc ở máy chủ ở M2 hay giữ tới khi vượt ngưỡng? | Mục tiêu 1.000 thiết bị vẫn chạy được không phân trang; cần xác nhận |
| 4 | **Hạn phiên** (idle, tuyệt đối), khoá đăng nhập sai, chính sách "ghi nhớ thiết bị": mock chưa có. Giá trị mặc định? | Cũng là câu hỏi mở số 7 của DATA_MODEL |
| 5 | **Đường gọi lại OIDC** (`/core/sso/callback` hoặc tương đương) và đăng xuất SSO chưa có trong `contract.ts` dù `core_oidc` có `POST /core/oidc/test` và `POST /core/sso/login`. Thêm endpoint nào, thuộc story nào? | Cần trước khi xây `auth-oidc` |
| 6 | **Token REST theo phạm vi** (ARCH §5) chưa có story. Có làm không (ai cần gọi REST bên ngoài ngoài MCP)? | Nếu có: cần story, bảng `core_api_token`, quy tắc phạm vi theo module |
| 7 | **Biểu diễn SSE và `multipart` trong `openapi.json`** (kiểu `text/event-stream`, `multipart/form-data`) để Go sinh được khung; hoặc để ngoài hợp đồng và viết tay. | Gắn với đề xuất mở rộng `Endpoint` (mục 12) |
| 8 | **Endpoint osquery TLS** (`enroll`, `config`, `log`, `GET /intake/ca.pem`) đã có trong `docs/specs/osquery-intake.md` nhưng **chưa khai trong `contract.ts`/`openapi.json`** (chỉ có `status`). Đây là giao thức của osquery (JSON, không theo lược đồ lỗi chuẩn): khai vào hợp đồng hay giữ ngoài hợp đồng với test riêng? | Là hợp đồng sống lâu (mục 9); ảnh hưởng đếm 14 điểm công khai ở mục 11.3 |
| 9 | **`api/openapi.json` hay `.yaml`:** D-18 ghi `.yaml`, mã dùng `.json`. Chốt `.json` và cập nhật D-18/ARCH §5? | Chỉ là tên tệp; ảnh hưởng đường dẫn trong script/CI |
| 10 | **Công cụ sinh Go** (`oapi-codegen`, `ogen`, khác) phải hiểu OpenAPI **3.1** (kiểu `["string","null"]`, `const`, `anyOf`). Chưa thử trên `api/openapi.json` thật; nếu không hỗ trợ, cần bước hạ 3.1→3.0 trong `scripts/openapi.mjs`. Chọn ở đầu M2 sau khi chạy thử và ghi vào `THIRD_PARTY_NOTICES.md`. | Quyết định cấu hình `go generate` |
| 11 | **Các giới hạn tần suất HTTP, CSRF, ETag, Idempotency-Key, SSE** đánh dấu **[ĐX]** là thiết kế mới (mock không có). Có duyệt nguyên khối không, hay duyệt từng phần theo mốc? Cần story ID cho từng phần không (`no-imagined-features`)? | Mỗi mục thêm mã lỗi mới (`csrf_invalid`, `precondition_failed`, `precondition_required`, `idempotency_*`, `bad_cursor`, `bad_limit`, `bad_sort`, `checksum_mismatch`, `gone`) |
| 12 | **Mã lỗi đồng nghĩa** (ví dụ `bad_name`, `invalid_name`, `duplicate_name`, `invalid_kind`/`bad_kind`; `too_large` 400 và 413) đang cùng tồn tại: giữ nguyên hay gộp trước khi backend khoá hợp đồng? | Gộp là đổi hợp đồng và FE; giữ thì thêm gánh nặng cho backend |
| 13 | **`GET /response/log` cũ nhất trước + phân trang:** client kiểm chuỗi hash qua nhiều trang bằng cách mang `hash` dòng cuối. Chấp nhận, hay thêm `GET /response/log/verify` phía máy chủ giống `/ai/activity/verify`? | Endpoint verify cần story (DATA_MODEL câu hỏi mở 4) |
