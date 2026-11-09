# Exposure Contract

> Tier: optional · Story: S-EXP-1 · Last verified: 2026-11-09 (docs-first, chưa có code)

Nguồn hành vi: `web/src/features/exposure/{contract,mocks,data}.ts`, D-25, D-26, LEGAL §3.

## Invariants
- **INV-1**: Không quét mục tiêu chưa đủ cả bốn điều kiện: (a) `status=verified`, (b) IP: còn ≤ 90 ngày, (c) domain: bản ghi TXT `vedette-verify=<token>` còn đó, **kiểm lại ngay trước mỗi lần quét**, (d) đã ghi cam kết. Thiếu điều kiện → `POST …/scan` trả 409 với `blocked_reason ∈ {unverified, expired, txt_missing, no_commitment}`. `TestContract_INV1_NoScanWithoutProof`
- **INV-2**: IP công cộng chỉ là IP mà chính hộp đang dùng để ra Internet: `POST /exposure/box-ip/verify` không nhận IP; hộp tự dò bằng HTTPS tới một endpoint cố định của dự án (không do người dùng nhập, không reverse DNS). Nhập IP vào `POST /exposure/targets` → 400 `ip_not_allowed`.
- **INV-3**: Từ chối kết quả IP riêng/dành riêng/CGNAT `100.64.0.0/10` (400 `not_public`).
- **INV-4**: IP hiệu lực 90 ngày: `expires_at = verified_at + 90d`; `validity ∈ {valid, expiring (≤14 ngày), expired}`; gia hạn chỉ khi hộp đang ra Internet bằng đúng IP đó. Domain không có `expires_at` (kiểm TXT trước mỗi quét).
- **INV-5**: Giới hạn 10 lần xác nhận/giờ/hộp (429 `rate_limited`); mỗi lần ghi `exp_attempt` và `core_audit`. Tối đa 20 mục tiêu (400 `too_many`); domain trùng → 409 `duplicate`.
- **INV-6**: Domain nhập vào chỉ là tên miền (không scheme, đường dẫn, cổng, khoảng trắng; regex tên miền); sai → 400 `bad_value`/`empty`.
- **INV-7**: Cam kết (D-26): chỉ cho mục tiêu đã xác thực (409 `not_verified|expired`), body `confirm` đúng `true` (400 `not_confirmed`), ghi `{by, at}` và câu "as is / tác giả không chịu trách nhiệm"; ai tick, khi nào được audit. Xoá mục tiêu xoá ảnh chụp và cam kết, không xoá `core_audit`.
- **INV-8**: Mỗi lần quét tạo một ảnh chụp theo ngày (`date` YYYY-MM-DD); so sánh cần hai ngày khác nhau (400 `same_date`) và cả hai tồn tại (404). `Counts.certs_expiring` đếm cert hết hạn trong 30 ngày (`CERT_WARN_DAYS`).
- **INV-9**: Dữ liệu ra ngoài chỉ gồm tên miền đã xác thực (tìm subdomain trên log CT) và yêu cầu HTTPS tới endpoint cố định của dự án (PRIVACY luồng 9). Tắt module ⇒ cả hai dừng.
- **INV-10**: Dữ liệu phản hồi từ host ngoài (banner, tiêu đề trang) là không tin cậy (SYS-6): giới hạn kích thước, lưu như văn bản.

## Preconditions / Postconditions
- **PRE-1** (`Scan(targetID)`): `operator` và INV-1. **POST-1**: ảnh chụp mới (hosts, ports, admin_panels, certs, counts); phát `exposure.snapshot.created`.
- **PRE-2** (`Verify(targetID)`): `operator`; domain: tra TXT; IP: hộp phải đang ra đúng IP này. **POST-2**: `VerifyResult {verified, message, target}`; "không tìm thấy" là câu trả lời bình thường (`verified:false`, không phải lỗi); `last_check` cập nhật.
- **PRE-3** (`CheckScannable(targetID)`, dùng bởi `scan`): không. **POST-3**: trả `(ok, blocked_reason)` đã kiểm TXT/hạn tại thời điểm gọi.
- **PRE-4** (`POST …/commitment`, `POST /exposure/targets`, `DELETE`, `box-ip/verify`): `admin`.

## Forbidden
- **FORBID-1**: Quét mục tiêu chưa xác thực sở hữu hoặc đã hết hạn.
- **FORBID-2**: Nhận IP công cộng do người dùng gõ (D-25).
- **FORBID-3**: Văn bản đồng ý (đã bỏ, D-26); chỉ một ô cam kết.
- **FORBID-4**: Phụ thuộc vào cam kết của `inventory` (`scope_confirmed`) cho mục tiêu ngoài; hai cam kết độc lập.
- **FORBID-5**: Gửi dữ liệu nội bộ (kho thiết bị, log) ra các dịch vụ CT/endpoint.

## Dependencies
- **DEPENDS ON**: `core` (jobs, audit, exec), `inventory` (liên kết thiết bị biên, hiển thị).
- **DEPENDED ON BY**: `scan` (mục tiêu ngoài `ext:<id>`, chỉ `scannable`), `reports`.

## Endpoints owned (role tối thiểu)
| Route | Vai |
|---|---|
| `GET /exposure/targets`, `/exposure/targets/{id}`, `/…/snapshots`, `/…/snapshots/{date}`, `/…/diff` | viewer |
| `POST /exposure/targets/{id}/verify`, `/exposure/targets/{id}/scan` | operator |
| `POST /exposure/targets`, `/exposure/box-ip/verify`, `/exposure/targets/{id}/commitment`; `DELETE /exposure/targets/{id}` | admin |

## Tables owned (`exp_`)
`exp_target`, `exp_snapshot` (kèm hosts/ports/admin/certs), `exp_commitment`, `exp_attempt`.

## Events
- **Phát**: `exposure.snapshot.created {target_id, date, counts}`, `exposure.target.verified|expired {target_id}`, `exposure.diff.changed` (đề xuất; chưa có trong GUI).
- **Nhận**: `core.module.disabled`.

## Behaviour khi tắt
Không route `/exposure/*`, không job, không yêu cầu HTTPS ra ngoài (luồng 9 ngừng). `scan` mất mục tiêu ngoài. Mục tiêu, ảnh chụp, cam kết giữ nguyên; bật lại thì IP quá 90 ngày vẫn `expired`.

## Story và quyết định
S-EXP-1; D-5 luật ANM; D-25 xác thực mục tiêu; D-26 một ô cam kết.

## Không khớp / câu hỏi mở
- IP phân giải từ subdomain (có thể thuộc CDN/bên thứ ba) có được quét cổng không? D-25 chỉ xác thực domain và IP hộp; mock vẫn liệt kê cổng theo IP của host.
- ~~`scan` trả 400 `no_commitment` còn `exposure` trả 409~~ Đã thống nhất theo D-57 (10): `400 commitment_required` ở cả hai (GUI/mock đã khớp; `blocked_reason: no_commitment` giữ là nhãn trạng thái, không phải mã lỗi).
- Chu kỳ ảnh chụp tự động chưa có trong GUI (chỉ nút "Scan now").
