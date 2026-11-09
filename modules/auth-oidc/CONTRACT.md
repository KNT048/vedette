# Auth-OIDC Contract

> Tier: tuỳ chọn (tắt mặc định) · Story: S-CORE-3 · Quyết định: D-35 (đối chiếu hai bước), D-18 · Last verified: 2026-11-09
> GUI nằm dưới `core` (`web/src/features/core/{contract,UsersSection,mocks}.ts`, mục Settings → Users). Backend là module riêng.
> Mock chỉ mô phỏng vòng chuyển hướng IdP (`POST /core/sso/login`); bản thật dùng authorization code + PKCE.

## Invariants (luôn đúng)
- **INV-1** Luồng đăng nhập là **authorization code + PKCE**; kiểm `state`, `nonce`, chữ ký ID token theo JWKS của IdP, `iss` = `issuer` đã lưu, `aud` chứa `client_id`, chưa hết hạn. Sai bất kỳ điều nào → từ chối, không tạo phiên.
- **INV-2** `issuer` bắt buộc là địa chỉ **https** (bỏ `/` cuối); `client_id` 1..200 ký tự; `client_secret` tối thiểu 8 ký tự; `default_role` ∈ {viewer, operator, admin}; `role_map` tối đa 10 dòng, mỗi dòng `{group, role}` với role hợp lệ. Sai → 400 (`invalid_issuer`, `invalid_client`, `invalid_secret`, `invalid_role`, `too_many`).
- **INV-3** `client_secret` lưu qua `core/secrets` (AES-GCM), API chỉ trả `secret_last4`; để trống khi sửa = giữ bí mật cũ (SYS-4). Không vào log/export/sao lưu.
- **INV-4** Nút SSO trên trang đăng nhập chỉ hiện khi module bật **và** đã có `issuer` (`GET /core/auth-options` → `{oidc: true}`); endpoint này công khai và không lộ gì khác (không issuer, không client).
- **INV-5** Vai của người SSO chỉ nằm trong {viewer, operator, admin}; lấy từ `role_map` theo nhóm của IdP, không khớp nhóm nào thì `default_role`. Vai không bao giờ tăng theo dữ liệu người dùng cung cấp ngoài claim đã ký. *(cách chọn khi khớp nhiều nhóm: câu hỏi mở 2)*
- **INV-6** Lần đầu đăng nhập SSO tạo người dùng (khoá theo email của IdP, kiểm `email_verified` nếu IdP cung cấp); người dùng `disabled` bị từ chối (403 `disabled`) kể cả khi IdP cho qua. Quản trị viên vô hiệu hoá/đổi vai người dùng SSO trong Users như người khác; không xoá được quản trị viên cuối cùng (luật của `core`).
- **INV-7** Mọi đăng nhập thành công/thất bại, lưu cấu hình, thử cấu hình ghi `core_audit` (SYS-3) với `auth.login` ... `SSO`, `oidc.update`, `oidc.test`.
- **INV-8** Tài khoản mật khẩu của `core` **vẫn đăng nhập được** khi bật SSO (không khoá quản trị viên ra ngoài khi IdP hỏng); hai bước của D-35 vẫn áp dụng cho đăng nhập mật khẩu. Hộp không buộc hai bước cho người SSO (IdP chịu trách nhiệm MFA). *(xác nhận: câu hỏi mở 3)*
- **INV-9** Dữ liệu từ IdP (claim, discovery, JWKS) là không tin cậy (SYS-6): kích thước giới hạn, kiểm kiểu, fail-closed.
- **INV-10** Chỉ gọi tới các endpoint lấy từ discovery của `issuer` đã khai (SYS-7); không theo chuyển hướng sang host khác không thuộc discovery.

## Preconditions (trước khi gọi)
- **PRE-1** `PUT /core/oidc`, `POST /core/oidc/test`: vai admin.
- **PRE-2** `POST /core/oidc/test`: đã lưu cấu hình (400 `not_configured`).
- **PRE-3** Đăng nhập SSO: module bật và có `issuer` (400 `oidc_off`).

## Postconditions (sau khi xong)
- **POST-1** `test` thành công trả `{ok:true, endpoints}` gồm `authorization`, `token`, `jwks` đọc từ `/.well-known/openid-configuration`; không đọc được → 502 `discovery_failed` với lý do nêu rõ đường mạng từ hộp tới IdP.
- **POST-2** Đăng nhập thành công: tạo phiên như đăng nhập mật khẩu (cookie `vedette_session`, không cookie khác, legal.md), ghi audit.
- **POST-3** Lưu cấu hình: lần đăng nhập kế tiếp dùng cấu hình mới; phiên đang có không bị ngắt.

## Forbidden (không bao giờ)
- **FORBID-1** Luồng implicit hoặc password grant; bỏ PKCE.
- **FORBID-2** Trả `client_secret` hoặc token IdP qua API/log/export.
- **FORBID-3** Cấp vai cao hơn kết quả `role_map`/`default_role`.
- **FORBID-4** Gọi IdP khi module tắt hoặc chưa có `issuer`.
- **FORBID-5** Chấp nhận `issuer` không phải https.

## Endpoints owned
| Method | Path | Vai tối thiểu | Story |
|---|---|---|---|
| GET | `/core/oidc` | admin | S-CORE-3 |
| PUT | `/core/oidc` | admin | S-CORE-3 |
| POST | `/core/oidc/test` | admin | S-CORE-3 |
| GET | `/core/auth-options` | public | S-CORE-3 |
| POST | `/core/sso/login` | public | S-CORE-3 (mock cho vòng chuyển hướng) |

Bản thật cần thêm cặp điểm vào/gọi lại (redirect + callback) của luồng code; **chưa có trong `contract.ts`** (câu hỏi mở 1).

## Tables owned
`oidc_config` (issuer, client_id, bí mật mã hoá, default_role, role_map). Mock: `core_oidc`. Người dùng và phiên thuộc `core` (`core_users`, `core_session`).

## Events
- **Phát**: không (audit qua `core`). **Nhận**: không.

## Khi tắt module (SYS-5)
Không route SSO, nút SSO biến mất khỏi trang đăng nhập (`auth-options.oidc=false`), không gọi tới IdP. Cấu hình giữ nguyên. Người dùng đã tạo qua SSO **vẫn tồn tại nhưng không có mật khẩu dùng được** (mật khẩu tạm ngẫu nhiên) nên không đăng nhập được cho tới khi quản trị viên đặt lại mật khẩu hoặc bật lại module; UI phải nêu số người bị ảnh hưởng trước khi tắt (S-CORE-1); `ToggleResponse.affected` hiện chỉ liệt kê module phụ thuộc nên cần mở rộng.

## Dependencies
- **DEPENDS ON**: `core` (người dùng, phiên, vai, audit, `core/secrets`).
- **DEPENDED ON BY**: `core` (trang đăng nhập hỏi `auth-options`). Không module khác.

## Câu hỏi mở
1. Điểm vào/gọi lại của luồng code (đường dẫn, tên cookie `state`) chưa có trong `contract.ts`; OpenAPI sẽ thiếu.
2. `role_map`: tên claim nhóm (`groups`?), và khi khớp nhiều nhóm chọn vai cao nhất hay đầu tiên. Mock không áp `role_map` (luôn `default_role`).
3. Người SSO có phải qua hai bước của hộp không (D-35 chỉ nói về đăng nhập mật khẩu)? Đề xuất: không, IdP lo.
4. Luồng dữ liệu ra mới (discovery, token, JWKS tới IdP khách khai): `legal.md` yêu cầu cập nhật `PRIVACY.md` (đang liệt 9 luồng, chưa có) và UI Cài đặt → Quyền riêng tư, cùng commit với backend.
5. Đăng xuất một phía (RP-initiated logout) có hỗ trợ không?
