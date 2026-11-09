# Core Contract

> Tier: core · Story: S-CORE-1…7 (S-CORE-3 một phần: OIDC thuộc `auth-oidc`) · Last verified: 2026-11-09 (WP-04b phần 2: handler HTTP của đăng nhập, tài khoản, người dùng, thiết lập lần đầu, audit, general; TLS và danh sách Host; mã cài đặt D-75, mật khẩu khi bật 2 bước D-76, cookie thiết bị D-77. Phần 1: `core/auth`, `core/events`, chain head)

Nguồn hành vi: `web/src/features/core/contract.ts` + `web/src/mocks/core.ts`. Đường dẫn dưới đây không có tiền tố `/api/v1`.

## Quy ước chung (mọi module dùng)
- **Sự kiện** (chốt trong `core/events`, WP-04b): tên `<module>.<đối tượng>.<động từ>` (regex trong `events.ValidName`), phát trong process qua `core/events` **sau khi giao dịch commit** (Outbox → Flush); chỉ một tập con được đẩy ra SSE `/api/v1/events`. Sensor→server dùng lô sự kiện idempotent theo `seq` (ARCHITECTURE §3). Tên sự kiện của module nhóm B trong các CONTRACT nhóm A là tên tạm.
- **Module tắt** = `Registry.Enabled(id)==false`: route không đăng ký, job không chạy, cổng đóng, bảng giữ nguyên (SYS-5). Module khác gọi module tuỳ chọn chỉ sau khi kiểm `Enabled`; tắt = coi như vắng mặt.
- **Lỗi**: JSON `{error:{code,message}}`; 401 chưa đăng nhập, 403 thiếu vai, 409 xung đột trạng thái.

## Invariants
- **INV-1**: Module `tier: core` không tắt được (`PATCH /modules/core` → 400 `core_module`). `TestContract_INV1_CoreAlwaysOn`
- **INV-2**: Mọi handler ghi (POST/PUT/PATCH/DELETE) của mọi module đi qua `core/audit.Append` (SYS-3); harness test dựng danh sách từ bảng route (`routes.Operations`, mọi thao tác không phải GET của thẻ `core` mà module có handler): thao tác thiếu bước thử, hay bước ghi mà không để lại hàng `core_audit`, đều fail. `core_audit` chỉ thêm, không có API sửa/xoá; ngoại lệ duy nhất là `POST /core/data/purge`.
- **INV-3**: Bật module thiếu phụ thuộc → 409 `missing_dependencies` kèm `missing[]`, không bật gì; chỉ khi `with_dependencies:true` mới bật kèm. Không bao giờ bật ngầm.
- **INV-4**: Tắt module không xoá bảng, không tự tắt module phụ thuộc; phản hồi trả `affected[]` = module đang bật phụ thuộc vào nó. Module phụ thuộc chạy ở chế độ suy giảm (xem IMPACT của từng module).
- **INV-5**: Vai `viewer < operator < admin` lấy từ bảng endpoint (`role`); endpoint không khai vai thì server từ chối khởi động. `role: public` chỉ gồm `/setup`, `/core/setup*`, `/core/auth-options`, `/auth/*`, `/install/*`, `/intake/*`, và các điểm có token một lần hoặc bước SSO trong chính yêu cầu: `POST /core/sso/login`, `GET|POST /response/approve/{token}`, `GET /response/blocklist/{token}.txt`. Kiểm bằng `core/api/routes_test.go` (sinh mã thất bại nếu thao tác thiếu vai).
- **INV-6**: Bí mật (mật khẩu, khoá TOTP, secret kênh/feed/OIDC/token) chỉ qua `core/secrets` (AES-256-GCM, khoá file 0600); API chỉ trả 4 ký tự cuối; không vào log, `/core/data/export`, `/core/data/backup`, `/core/logs/export` (SYS-4).
- **INV-7**: Người dùng: không vô hiệu hoá chính mình; không bỏ quản trị viên hoạt động cuối cùng; quản trị viên không đặt lại 2FA của chính mình (400); mật khẩu tạm trả đúng một lần; đặt lại mật khẩu **và** đặt lại 2FA kết thúc mọi phiên của người đó trong cùng giao dịch; người dùng tự đổi mật khẩu, bật hoặc tắt 2FA kết thúc **mọi** phiên của họ và cùng giao dịch tạo một phiên mới cho đúng trình duyệt đó (cùng thiết bị và địa chỉ, token phiên và CSRF mới; handler đặt lại hai cookie): người dùng vẫn đăng nhập, bản sao của cookie cũ (mã độc, tiện ích, máy dùng chung) thì không (OWASP Session Management: đổi định danh phiên sau thay đổi đặc quyền / xác thực lại); tên và email không có ký tự điều khiển (Cc) hay ký tự định dạng vô hình (Cf: bidi, độ rộng bằng không, gạch nối mềm, thẻ), tên tổ chức cũng vậy; tên và email không có ký tự điều khiển; trùng email luôn là 409 `duplicate`. Một lần đăng nhập đang chạy mà mật khẩu (`core_user.cred_version`, tăng khi đổi/đặt lại mật khẩu thật, không tăng khi băm lại), trạng thái khoá hoặc kiểu 2FA đổi trước khi nó ghi không tạo phiên và không ghi đè mật khẩu mới (băm lại chỉ ghi nếu `cred_version` còn như cũ). Hành động của quản trị viên lên người khác (tạo, sửa, đặt lại mật khẩu, đặt lại 2FA, ghi cài đặt chung, xuất audit) kiểm lại **người thực hiện** trong giao dịch ghi: tài khoản bị khoá → 403 `disabled`, phiên đã thu hồi → 401 `unauthenticated`, không còn là quản trị viên → 403 `forbidden`; không ghi gì. Đổi mật khẩu của chính mình, tắt 2FA và bật 2FA kiểm lại trong giao dịch ghi: tài khoản không bị khoá, phiên đang dùng còn sống, mật khẩu đã chứng minh chưa bị đổi (không thì không ghi gì, không ghi đè mật khẩu mới hơn). Thứ tự từ chối luôn là: người gọi (khoá/phiên) trước, rồi mật khẩu cũ (`cred_version`), rồi trạng thái. Đổi mật khẩu và bật hoặc tắt 2 bước (bắt đầu TOTP, bắt đầu mã email) đòi nhập lại mật khẩu hiện tại (D-76): sai → 400 `wrong_password`, tính vào **bộ đếm xác thực lại theo tài khoản** (khoá `account`, riêng với bộ đếm đăng nhập sai theo (IP, email): cùng mức 10 lần / 15 phút và cùng cách tăng thời gian chờ, đếm trước khi kiểm, trả lại khi đúng) và ghi `auth.reauth_failed` (không có mật khẩu trong `detail`), để phiên bị đánh cắp đoán mật khẩu cũng để lại dấu vết như đăng nhập sai.
- **INV-8**: Đã bật 2FA thì đăng nhập thiếu/sai mã không tạo phiên. Kiểu `email` mà kênh email không dùng được → 503 `twofa_email_unavailable`, không bao giờ lùi về chỉ mật khẩu (D-35). Mã email: 6 số, 10 phút, dùng 1 lần, 5 lần sai huỷ mã, gửi lại sau 60 s (429 `resend_too_soon`), tối đa 5 lần gửi/giờ (`too_many_codes`). TOTP: RFC 6238 SHA1, 6 số, 30 s, ±1 bước, mã của một bước dùng được một lần (`core_user_totp.last_step`). Đăng nhập sai quá 10 lần trong 15 phút theo cặp (IP, email; IPv6 theo từng địa chỉ với trần 10 và theo /64 với trần 100) → 429 `rate_limited` với thời gian chờ tăng dần; lượt thử được đếm trước khi kiểm nên các lượt song song không vượt giới hạn; mã 2 bước còn bị giới hạn riêng theo tài khoản (10 lần sai / 15 phút, không theo IP), kể cả mã xác nhận khi bật TOTP (`POST /core/account/2fa/confirm`: đếm trước khi kiểm, trả lại khi đúng) và khoá TOTP đang chờ xác nhận bị huỷ sau 5 mã sai (400 `too_many_tries`, như mã email). **Cookie thiết bị (D-77)**: sau đăng nhập thành công hộp đặt `__Secure-vedette_device` (ký HMAC, gắn người dùng + `cred_version`, nonce **mới ở mỗi lần đăng nhập thành công**, không ký lại nonce của cookie đã gửi, nên bản sao bị đánh cắp từ trước không chung bộ đếm với cookie hiện tại của chủ); đăng nhập mang cookie hợp lệ của đúng tài khoản được đếm theo cookie (10 lần / 15 phút) và miễn khỏi bộ đếm địa chỉ và /64, nên một người cùng /64 không khoá được chủ tài khoản; cookie thiếu/sai/hết hạn/của người khác/sau đổi mật khẩu không được miễn; cookie bị đánh cắp vẫn giới hạn 10 lần / 15 phút. Email lạ và mật khẩu sai trả cùng một `invalid_credentials`, cùng công việc ở writer (cả hai ghi `auth.login_failed`). Băm/kiểm mật khẩu chạy dưới trần đồng thời (`MaxHashing`); quá trần hoặc quá thời gian chờ → 503 `server_busy` + `Retry-After`, không tính là lần đoán sai. Mã email lưu dạng HMAC-SHA-256 có khoá (`core_email_code.hmac_key` trong `core/secrets`), không phải SHA-256 trơn. `preview_code` không bao giờ có trong phản hồi thật.
- **INV-9**: Phiên hết hạn sau **4 giờ không hoạt động hoặc 7 ngày kể từ lúc đăng nhập** (D-71). Chỉ ba cookie, đều của hộp và cần cho đăng nhập: phiên `__Host-vedette_session` (HttpOnly, Secure, SameSite=Strict, Path=/), CSRF `__Host-vedette_csrf` (Secure, SameSite=Strict, SPA đọc được) và thiết bị tin cậy `__Secure-vedette_device` (HttpOnly, Secure, SameSite=Strict, `Path=/api/v1/auth/`, 90 ngày, D-77); không cookie nào khác, không analytics, không tài nguyên CDN ngoài (legal.md). Cookie `Secure` luôn được đặt; tiền tố `__Host-` (phiên, CSRF: Secure, Path=/, không Domain) và `__Secure-` (thiết bị) do trình duyệt thực thi (GitHub dùng `__Host-user_session_same_site`); trình duyệt chấp nhận cookie Secure từ `http://localhost` nên `make dev` chạy bình thường; HSTS (`max-age=31536000`) chỉ khi chủ hộp đưa chứng chỉ qua `-tls-cert`, không bao giờ với chứng chỉ tự ký (825 ngày, hộp tự làm lại cặp của chính nó khi còn dưới 30 ngày); HTTP thuần chỉ ở loopback (`-listen` khác loopback thì TLS). Tiêu đề `Host` ngoài danh sách cho phép (`-hosts`, mặc định tên loopback và tên trong chứng chỉ) → 421 `misdirected_request` trước khi định tuyến (chống DNS rebinding). `Retry-After` có trên mọi 429 và 503 `server_busy` kèm `retry_after`. `TestContract_INV9_HTTP*`.
- **INV-10**: `GET /core/privacy` trả đúng 9 luồng của `PRIVACY.md`; `telemetry.payload` là chính byte sẽ gửi giờ tới (một lần serialize, dùng cho cả hiển thị và gửi). Tắt `telemetry` ⇒ không có request nào tới máy chủ dự án; tắt `update_check` ⇒ `/core/updates/check` và `/core/updates/os/check` trả 409.
- **INV-11**: Cập nhật phần mềm/gói nội dung/bundle chỉ áp khi chữ ký `valid`; bundle sai chữ ký bị từ chối; mỗi apply/rollback ghi `core_audit` và `UpdateHistory` (trả 20 dòng mới nhất); rollback về đúng phiên bản `previous`.
- **INV-12**: Cập nhật OS (D-53, D-55): chỉ chạy danh sách lệnh apt cố định qua socket `vedette-host` (SYS-1); một lần chạy tại một thời điểm (409 khi bận); sao lưu DB trước, kiểm sức khoẻ sau, ghi `OsRunResult.backup/health`; không bao giờ tự nâng bản phát hành OS (`release_upgrade` chỉ là hướng dẫn); đặt lịch khởi động lại phải nằm trong cửa sổ bảo trì; khởi động lại khi đang cài → 409.
- **INV-13**: `/core/logs/export` chỉ nhận 8 danh mục (`audit, ai_activity, response, scan_probes, alerts, device_logs, known_bad, honeypot`), bỏ bí mật, giữ hash của log có chuỗi hash để kiểm ngoại tuyến, và bản thân lần tải được ghi `core_audit` (D-48). Mỗi module đăng ký nguồn qua `logexport.Register`.
- **INV-14**: `POST /core/data/purge` chỉ chạy khi `confirm` bằng đúng tên tổ chức; sau đó phiên kết thúc và `/setup` báo `complete:false`.
- **INV-15**: `POST /core/setup` chỉ chạy khi `setup.complete=false` (sau đó 409 `already_setup`); tạo tổ chức, quản trị viên đầu tiên, một phiên cho họ, bật gói module đã chọn và ghi `core_audit` trong **một** giao dịch. **Mã cài đặt một lần (D-75)**: khi cài đặt còn mở, hộp giữ một mã ngẫu nhiên 100 bit trong `core_secret` (purpose `core_setup_code`), in vào log mỗi lần khởi động, xoá trong giao dịch tạo quản trị viên; thiếu/sai mã → 403 `invalid_setup_code` (xét trước mọi trường khác, so sánh thời gian hằng, mỗi lần đoán sai tính **theo địa chỉ máy khách** như đăng nhập (địa chỉ; IPv6 thêm /64; 10 lần / 100 lần, rồi 429 `rate_limited` với thời gian chờ tăng dần) cộng trần chung cao 1000 lần/giờ làm lưới an toàn, nên một người lạ không giữ được cài đặt đóng với chủ hộp; mã đúng trả lại lượt đếm). Thứ tự từ chối: đã cài đặt xong (409 `already_setup`, cả khi gửi `sample:true`), bản không có dữ liệu mẫu (400 `sample_unavailable`), mã cài đặt; bên thua trong hai yêu cầu đồng thời thấy mã đã bị xoá và cài đặt đã xong thì nhận 409 `already_setup` và được trả lại lượt đoán. `sample:true` chỉ hợp lệ ở bản `data_mode=sample`: bản backend chưa có dữ liệu mẫu nên là 400 `sample_unavailable`; cài sạch (`clean`) mọi bảng rỗng ngoài thiết bị "This box" (S-INV-5). Dải LAN và cam kết quét được kiểm (`invalid_lan`, `public_range`) và giữ trong `core_setting` khoá `setup.scope` cho module kiểm kê. `TestContract_INV15_*`.
- **INV-16** (issue #17): mỗi dòng nối vào `core_audit`/`ai_activity`/`resp_log` cập nhật `core_chain_head` trong cùng giao dịch; verify đòi dòng mới nhất và số dòng khớp head, nên xoá các dòng mới nhất bị phát hiện. `TestContract_ChainHead`

- **INV-17** (WP-04b phần 2): `GET /core/audit` trả tối đa 200 dòng mới nhất, `total` đúng bộ lọc, `users` và `groups` của cả log; bộ lọc `from`/`to` nhận ngày `YYYY-MM-DD` (theo múi giờ của tổ chức) hoặc thời điểm UTC tận cùng `Z`, độ lệch → 400 `invalid_from`/`invalid_to` (không dùng `bad_from`/`bad_to`: đã là "email người gửi sai" của notify). `GET /core/audit/export` (CSV, ô bắt đầu bằng `= + - @` bị vô hiệu hoá công thức) ghi `audit.export` vào `core_audit` **trước** khi đọc và đọc theo trang (không giữ cả log trong bộ nhớ). `PUT /core/general` kiểm múi giờ IANA (`invalid_timezone`) và tên tổ chức (`invalid_org`). `TestContract_INV17_*`.

## Preconditions / Postconditions
- **PRE-1** (`PATCH /modules/{id}` enable): người gọi `admin`. **POST-1**: `core_module.enabled=true`, `enabled_at` đặt, `core_audit` có `module.enable` (cùng giao dịch); sau commit route của module trả lời (cổng module trong `core/server`) và job của nó chạy (`core/jobs`), không cần khởi động lại.
- **PRE-2** (disable): module không phải `tier:core`. **POST-2**: sau commit, route của module trả 404 như route không tồn tại, job bị huỷ, cổng đóng — không cần khởi động lại; `core_audit` có `module.disable` (kèm `affected`). `host` (`kind: component`) không có công tắc.
- **PRE-3** (`audit.Append`): có `user`, `action`, `target`. **POST-3**: hàng thêm trong cùng transaction với thay đổi; lỗi ghi audit ⇒ rollback thay đổi.
- **PRE-4** (`exec.Run`): binary ∈ allowlist, argv là mảng đã validate. **POST-4**: không qua shell; stdout/stderr bị giới hạn kích thước; timeout bắt buộc.
- **PRE-5** (`updates/apply|rollback`): `admin`, component tồn tại. **POST-5**: phiên bản mới ghi `UpdateComponent` với `signature:valid`; lỗi giữa chừng ⇒ giữ slot cũ (A/B, D-12).
- **PRE-6** (`updates/os/install`): `admin`, không có run đang chạy, `scope ∈ {security, all}`. **POST-6**: `OsRun` tạo, dòng apt hiện dần ở `GET /core/updates/os/run`, kết thúc có `result`.

## Forbidden
- **FORBID-1**: Chuỗi lệnh shell ở bất kỳ đâu (SYS-1); `eval`.
- **FORBID-2**: `core` import package của module khác (hướng phụ thuộc: module → core). Tương tác ngược (gửi mã email 2FA, kiểm kênh email) qua interface mà `notify` cài đặt.
- **FORBID-3**: Log hoặc trả về bí mật; trả `preview_code`.
- **FORBID-4**: Gửi dữ liệu ra ngoài ngoài 9 luồng của PRIVACY.md; "Báo lỗi" (S-CORE-5) không gửi gì: gói chẩn đoán dựng và tải ở trình duyệt (D-42).
- **FORBID-5**: Module khác ghi vào bảng `core_*` (qua interface của `core/*`).

## Dependencies
- **DEPENDS ON**: không (ngoài `vedette-host` ở ngoài process).
- **DEPENDED ON BY**: tất cả module. Tuỳ chọn: `notify` (mã 2FA email, `twofa_email.available` chỉ true khi `notify` bật và kênh email cấu hình + bật).

## Endpoints owned (role tối thiểu)
| Nhóm | Route | Vai |
|---|---|---|
| nền | `GET /me`; `GET /modules` | viewer |
| nền | `GET /setup`; `POST /auth/login`, `/auth/login/resend-code`, `/auth/logout` | public |
| nền | `PATCH /modules/{id}` | admin |
| cài đặt | `GET /core/setup/modules`, `POST /core/setup` (cần mã cài đặt một lần, D-75), `GET /core/auth-options` | public |
| chung | `GET /core/general` (viewer); `PUT /core/general` | admin |
| tài khoản | `GET,PATCH /core/account`; `POST /core/account/password`, `/2fa/start` và `/2fa/email/start` (đều đòi mật khẩu hiện tại, D-76), `/2fa/confirm`, `/2fa/email/confirm`, `/2fa/disable`; `DELETE /core/account/sessions/{id}`; `POST /core/account/sessions/revoke-others` | viewer |
| người dùng | `GET,POST /core/users`; `PATCH /core/users/{id}`; `POST /core/users/{id}/reset-password`, `/2fa/reset` | admin |
| audit | `GET /core/audit`, `/core/audit/export` | admin |
| cập nhật | `GET /core/updates`, `/core/updates/os`, `/core/updates/os/run` | viewer |
| cập nhật | `POST /core/updates/check`, `/core/updates/os/check`; `GET /core/updates/bundle` | operator |
| cập nhật | `PATCH /core/updates`; `POST /core/updates/apply`, `/rollback`, `/os/install`, `/os/reboot`, `/bundle`; `PATCH /core/updates/os/settings`; `DELETE /core/updates/os/reboot` | admin |
| riêng tư | `GET /core/privacy` (viewer); `PATCH /core/privacy` | admin |
| dữ liệu | `GET /core/data/backup`, `/core/data/export`, `/core/logs/export`; `POST /core/data/purge` | admin |
| chưa có trong `contract.ts` | `GET /api/v1/events` (SSE, ARCHITECTURE §5) | viewer |

Trong `core/contract.ts` nhưng thuộc module khác (nhóm B chốt, route chỉ đăng ký khi module chủ bật): `/core/oidc*`, `/core/sso/login` → `auth-oidc`; `/core/mcp*` → `mcp-server`.

## Tables owned (`core_`)
`core_module`, `core_audit`, `core_chain_anchor`, `core_chain_head`, `core_user`, `core_session`, `core_user_totp` (CONTRACT cũ ghi `core_totp`), `core_email_code`, `core_email_code_send`, `core_org`, `core_setting` (tổ chức, general, privacy, kênh cập nhật), `core_update_component`, `core_update_history`, `core_os_run`, `core_secret`, `core_job_run`.

## Events
- **Phát** (tên theo `core/events`, mẫu `<module>.<đối tượng>.<động từ>`): `core.module.enabled|disabled {id, affected[]}`, `core.update.applied|rolled_back {component, from, to}`, `core.os.install_finished {run_id, installed, reboot_required}`, `core.data.purged`.
- **Nhận**: không (lịch qua `core/jobs`).

## Behaviour khi tắt
Không áp dụng (tier core). Riêng `notify` tắt: 2FA email báo `reason:module_off`, người dùng kiểu email không đăng nhập được cho tới khi quản trị đặt lại.

## Story và quyết định
S-CORE-1, 2, 3, 4, 5, 6, 7. D-8 một binary; D-10 module; D-12 cập nhật ký, A/B; D-16/17 tín hiệu ẩn danh + pháp lý; D-18 OpenAPI từ Zod; D-24 không nhiều site; D-35 2FA; D-42 báo lỗi; D-48 xuất log; D-53/55 OS và `vedette-host`.

## Không khớp / câu hỏi mở
- ~~`contract.ts` ghi `vedette-updater`~~ Đã đổi sang `vedette-host` (D-55) trong contract/mock/UI.
- Box network (D-56) chưa có endpoint trong `contract.ts` và mock; thuộc module `host` (nhóm B), `core` chỉ cung cấp client socket.
- `core/types.ts` còn `ChannelType = telegram|zalo|email` (cũ, notify có 6 loại).
- Tắt module không tự tắt phụ thuộc (mock đúng vậy); cần chốt có muốn cascade không.
- Đã làm ở WP-06: mock có module `findings` (D-57 (6)), `mitigation` phụ thuộc `findings`, `reports` phụ thuộc `notify`, `scan-credentialed` phụ thuộc `inventory`; chuỗi hash `core_audit` có trong mock (`src/lib/chain.ts`); luồng PRIVACY thứ 11 (OIDC).
