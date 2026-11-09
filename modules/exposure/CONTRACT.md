# Exposure Contract

> Tier: optional · Story: S-EXP-1 · Last verified: 2026-11-09 (đã thêm chế độ tự phát hiện IP, 30 ngày tự gia hạn; code theo sau)

Nguồn hành vi: `web/src/features/exposure/{contract,mocks,data}.ts`, D-25, D-26, LEGAL §3.

## Invariants
- **INV-1**: Không quét mục tiêu chưa đủ cả bốn điều kiện: (a) `status=verified`, (b) IP: chưa quá 30 ngày kể từ lần hộp quan sát cuối (INV-4), (c) domain: bản ghi TXT `vedette-verify=<token>` còn đó, **kiểm lại ngay trước mỗi lần quét**, (d) đã ghi cam kết. Thiếu điều kiện → `POST …/scan` trả 409 `not_verified|expired|txt_missing` hoặc 400 `commitment_required` (D-57 (10)); `blocked_reason ∈ {unverified, expired, txt_missing, no_commitment}` là nhãn trạng thái trên `Target`. `TestContract_INV1_NoScanWithoutProof`
- **INV-2**: IP công cộng chỉ là IP mà chính hộp đang dùng để ra Internet: không API nào nhận IP; hộp tự dò bằng HTTPS tới một endpoint cố định của dự án (không do người dùng nhập, không reverse DNS, không theo redirect, phản hồi là dữ liệu không tin cậy: giới hạn kích thước và thời gian, phân tích bằng `netip`). Nhập IP vào `POST /exposure/targets` → 400 `ip_not_allowed`. Mỗi lần dò (`Detect`) gọi endpoint 3 lần, mỗi lần một kết nối riêng (không giữ kết nối), để thấy mọi IP ra Internet khi công ty có nhiều IP sau cân bằng tải; mọi IP công cộng khác nhau quan sát được đều vào kho (thêm mới hoặc gia hạn). `TestContract_INV2_OnlyObservedIPs`, `TestContract_INV2_MultiIPDetect`
- **INV-3**: Từ chối kết quả IP riêng, dành riêng, CGNAT `100.64.0.0/10` và mọi địa chỉ không phải unicast toàn cầu IPv4 (400 `not_public` khi mọi địa chỉ quan sát được đều bị từ chối; địa chỉ bị từ chối không bao giờ vào kho). Dải tài liệu RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), 198.18.0.0/15 và IPv6 cũng bị từ chối trong backend (mock cho phép dải tài liệu chỉ vì dữ liệu mẫu dùng nó); IPv6 để sau (ponytail). `TestContract_INV3_RefusesNonPublic`
- **INV-4**: IP hiệu lực 30 ngày kể từ lần thấy cuối, tự gia hạn: mỗi lần hộp quan sát một IP (tự dò, "Detect now", hoặc `POST …/verify` của chính IP đó) thì `verified_at = lần thấy`, `expires_at = verified_at + 30d`; `validity ∈ {valid, expiring (còn ≤ 5 ngày), expired}`. IP chỉ hết hạn khi **không** được quan sát suốt 30 ngày, tức khi không gia hạn được mới phải xác nhận lại; IP hết hạn mà được quan sát lại thì hợp lệ trở lại (cam kết cũ giữ nguyên). Domain không có `expires_at` (kiểm TXT trước mỗi quét). Đồng hồ tiêm được, không ngủ thật trong test. `TestContract_INV4_RenewAndExpire`
- **INV-5**: Giới hạn 10 lần xác nhận do người bấm/giờ/hộp (429 `rate_limited`): `POST /exposure/box-ip/verify` và `POST …/verify` mỗi lần tính một; lần dò của job tự phát hiện không tính (đã bị chặn bởi chu kỳ tối thiểu 15 phút) và không làm người dùng hết lượt. Mỗi lần ghi `exp_attempt` (giữ 24 giờ) và `core_audit`. Tối đa 20 mục tiêu (400 `too_many`; tự phát hiện bỏ qua IP mới khi đã đủ 20 và ghi rõ trong `last_run`); domain trùng → 409 `duplicate`. `TestContract_INV5_AttemptLimit`
- **INV-6**: Domain nhập vào chỉ là tên miền (không scheme, đường dẫn, cổng, khoảng trắng; regex tên miền); sai → 400 `bad_value`/`empty`.
- **INV-7**: Cam kết (D-26): chỉ cho mục tiêu đã xác thực (409 `not_verified|expired`), body `confirm` đúng `true` (400 `not_confirmed`), ghi `{by, at}` và câu "as is / tác giả không chịu trách nhiệm"; ai tick, khi nào được audit. Xoá mục tiêu xoá ảnh chụp và cam kết, không xoá `core_audit`.
- **INV-8**: Mỗi lần quét tạo một ảnh chụp theo ngày (`date` YYYY-MM-DD); so sánh cần hai ngày khác nhau (400 `same_date`) và cả hai tồn tại (404). `Counts.certs_expiring` đếm cert hết hạn trong 30 ngày (`CERT_WARN_DAYS`).
- **INV-9**: Dữ liệu ra ngoài chỉ gồm tên miền đã xác thực (tìm subdomain trên log CT) và yêu cầu HTTPS tới endpoint cố định của dự án (PRIVACY luồng 9: lần đầu khi cài, rồi mỗi chu kỳ tự phát hiện, mỗi lần 3 yêu cầu; không mang dữ liệu nào của khách). Tắt module ⇒ cả hai dừng. Tắt tự phát hiện ⇒ luồng 9 chỉ chạy khi người bấm.
- **INV-10**: Dữ liệu phản hồi từ host ngoài (banner, tiêu đề trang) và phản hồi của endpoint IP là không tin cậy (SYS-6): giới hạn kích thước, lưu như văn bản, phân tích fail-closed.
- **INV-11** (chế độ tự phát hiện IP, kien 2026-11-09): cài đặt `{auto, interval_min}` của hộp, mặc định `auto=true`, `interval_min=60`, chu kỳ trong **15…1440** phút (ngoài khoảng → 400 `bad_interval`); chỉ `admin` đổi (`PUT /exposure/box-ip/settings`); đổi chu kỳ hoặc tắt không xoá danh sách IP. Job `exposure/auto-detect` (5 phút một nhịp) chạy `Detect` khi `auto` bật và (chưa từng chạy, tức lần đầu khi cài hoặc khi module vừa bật, hoặc đã tới `last_run.at + interval_min`); bật `auto` từ tắt chạy `Detect` ngay trong lần PUT đó. Kết quả lần chạy cuối (`last_run {at, ok, message}`) có trong `GET /exposure/targets` → `box_ip`. `auto=false`: không có gì tự chạy, chỉ "Detect now" (`POST /exposure/box-ip/verify`). Người dùng xoá một IP (`DELETE /exposure/targets/{id}`, INV-7); nếu hộp vẫn dùng IP đó để ra Internet và `auto` còn bật thì lần dò sau thêm lại IP như mục tiêu mới (không cam kết, không ảnh chụp). Mọi lần chạy của job ghi `core_audit` với người thực hiện `system` (thêm/gia hạn/lỗi). `TestContract_INV11_AutoDetectSchedule`, `TestContract_INV11_ManualModeAndSettings`, `TestContract_INV11_RemovedIPComesBack`
- **INV-12**: Cổng quét cho `scan`: `Service.CheckScannable` là cách duy nhất `scan` hỏi được một mục tiêu ngoài có quét được không (PRE-3). `POST …/scan` của exposure kiểm INV-1 rồi giao việc quét cho `Runner` do module `scan` đăng ký; chưa có `Runner` thì trả 501 `not_implemented` sau khi qua cổng. `TestContract_INV12_ScanGate`

## Preconditions / Postconditions
- **PRE-1** (`Scan(targetID)`): `operator` và INV-1. **POST-1**: ảnh chụp mới (hosts, ports, admin_panels, certs, counts); phát `exposure.snapshot.created`.
- **PRE-2** (`Verify(targetID)`): `operator`; domain: tra TXT; IP: hộp phải đang ra Internet bằng đúng IP này (một lần dò 3 yêu cầu, thấy IP trong các kết quả là đủ). **POST-2**: `VerifyResult {verified, message, target}`; "không tìm thấy" (kể cả tra DNS lỗi hoặc không dò được) là câu trả lời bình thường (`verified:false`, không phải lỗi); `last_check` cập nhật; IP thấy được thì gia hạn (INV-4).
- **PRE-3** (`CheckScannable(ctx, targetID)`, dùng bởi `scan`; nhận cả `ext:<id>`): không. **POST-3**: trả `(ok, blocked_reason)` đã kiểm TXT/hạn tại thời điểm gọi.
- **PRE-4** (`POST …/commitment`, `POST /exposure/targets`, `DELETE`, `box-ip/verify`, `PUT box-ip/settings`): `admin`.
- **PRE-5** (`Detect`, "Detect now"): `admin`, tính một lượt (INV-5). **POST-5**: `{items, message}`: các IP vừa quan sát (đã thêm hoặc gia hạn), `last_run` cập nhật; 400 `not_public` nếu mọi địa chỉ thấy được đều bị từ chối; 502 `unreachable` nếu không lần dò nào trả lời; 501 `not_implemented` nếu bản dựng chưa có địa chỉ endpoint.

## Forbidden
- **FORBID-1**: Quét mục tiêu chưa xác thực sở hữu hoặc đã hết hạn.
- **FORBID-2**: Nhận IP công cộng do người dùng gõ (D-25). Khách chỉ được bật/tắt tự phát hiện, đổi chu kỳ và xoá IP; không thêm IP.
- **FORBID-3**: Văn bản đồng ý (đã bỏ, D-26); chỉ một ô cam kết.
- **FORBID-4**: Phụ thuộc vào cam kết của `inventory` (`scope_confirmed`) cho mục tiêu ngoài; hai cam kết độc lập.
- **FORBID-5**: Gửi dữ liệu nội bộ (kho thiết bị, log) ra các dịch vụ CT/endpoint.

## Dependencies
- **DEPENDS ON**: `core` (jobs, audit, exec), `inventory` (liên kết thiết bị biên, hiển thị).
- **DEPENDED ON BY**: `scan` (mục tiêu ngoài `ext:<id>`, chỉ `scannable`), `reports`.

## Endpoints owned (role tối thiểu)
| Route | Vai |
|---|---|
| `GET /exposure/targets` (kèm `box_ip {auto, interval_min, last_run}`), `/exposure/targets/{id}`, `/…/snapshots`, `/…/snapshots/{date}`, `/…/diff` | viewer |
| `POST /exposure/targets/{id}/verify`, `/exposure/targets/{id}/scan` | operator |
| `POST /exposure/targets`, `/exposure/box-ip/verify` ("Detect now", trả `{items, message}`), `PUT /exposure/box-ip/settings` (`{auto, interval_min}` → `BoxIpSettings`), `/exposure/targets/{id}/commitment`; `DELETE /exposure/targets/{id}` (cũng là cách xoá một IP khỏi kho) | admin |

Mới/đổi so với bản 90 ngày: `PUT /exposure/box-ip/settings` (mới), `GET /exposure/targets` (thêm `box_ip`), `POST /exposure/box-ip/verify` (trả danh sách thay vì một `Target`; luôn 200). `Target` không đổi hình dạng: với IP, `verified_at` là lần thấy cuối và `expires_at = verified_at + 30d`.

## Tables owned (`exp_`)
`exp_target` (kèm cột cam kết), `exp_snapshot` (kèm hosts/ports/admin/certs), `exp_attempt`, `exp_setting` (một dòng: `auto`, `interval_min`, kết quả lần chạy cuối).

## Events
- **Phát**: `exposure.snapshot.created {target_id, date, counts}`, `exposure.target.verified {target_id}` (IP mới, hoặc IP hết hạn được gia hạn trở lại; domain xác thực xong), `exposure.target.expired {target_id}` (hoãn: IP hết hạn tính theo thời gian, chưa có người nhận), `exposure.diff.changed` (đề xuất; chưa có trong GUI).
- **Nhận**: `core.module.disabled`.

## Behaviour khi tắt
Không route `/exposure/*`, không job, không yêu cầu HTTPS ra ngoài (luồng 9 ngừng). `scan` mất mục tiêu ngoài. Mục tiêu, ảnh chụp, cam kết, cài đặt giữ nguyên; bật lại thì job dò ngay lần đầu (IP đang dùng được gia hạn, IP không thấy quá 30 ngày vẫn `expired`).

## Story và quyết định
S-EXP-1; D-5 luật ANM; D-25 xác thực mục tiêu (90 ngày nay là 30 ngày tự gia hạn + chế độ tự phát hiện, kien 2026-11-09; ghi vào DECISIONS.md do kien); D-26 một ô cam kết.

## Không khớp / câu hỏi mở
- IP phân giải từ subdomain (có thể thuộc CDN/bên thứ ba) có được quét cổng không? D-25 chỉ xác thực domain và IP hộp; mock vẫn liệt kê cổng theo IP của host.
- ~~`scan` trả 400 `no_commitment` còn `exposure` trả 409~~ Đã thống nhất theo D-57 (10): `400 commitment_required` ở cả hai (GUI/mock đã khớp; `blocked_reason: no_commitment` giữ là nhãn trạng thái, không phải mã lỗi).
- Chu kỳ ảnh chụp tự động chưa có trong GUI (chỉ nút "Scan now").
