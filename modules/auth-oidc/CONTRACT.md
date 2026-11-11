# Auth-OIDC Contract

> Tier: tuỳ chọn (tắt mặc định) · Story: S-CORE-3 · Quyết định: D-194 (luồng), D-195 (tài khoản, vai), D-196 (hai bước, dự phòng), D-197 (thư viện), D-35, D-71, D-77 · Last verified: 2026-11-11 (PR 2: `go test ./modules/auth-oidc/ -run Contract`, IdP giả trên httptest TLS)
> GUI nằm dưới `core` (`web/src/features/core/{contract,UsersSection,SsoCallbackPage,ssoFlow,mocks}.ts`, mục Settings → Users, trang `/sso/callback`). Backend là module riêng.
> Mock bỏ qua IdP: `authorize_url` của mock là chính trang `/sso/callback` kèm một mã, người dùng ở IdP là `MOCK_IDP_USER`.

## Invariants (luôn đúng)
- **INV-1** Luồng đăng nhập là **authorization code + PKCE S256**, luôn có `state` và `nonce` 256 bit (D-194). Kiểm ID token: chữ ký theo JWKS của issuer với **thuật toán bất đối xứng** RS256/384/512, PS256/384/512, ES256/384/512 (giao với `id_token_signing_alg_values_supported`; `none` và HS* luôn bị từ chối), `iss` = issuer đã lưu, `aud` chứa `client_id`, `azp` có mặt thì = `client_id`, nhiều `aud` thì phải có `azp`, `exp` chưa qua (lệch giờ 1 phút), `nonce` = nonce của luồng. Khoá chỉ lấy từ `jwks_uri` của discovery (bỏ qua `jku`/`x5u`/`jwk`/`x5c` của header), `kty` hợp `alg`. ID token chỉ đến từ phản hồi của điểm token qua TLS, không bao giờ từ trình duyệt, nên `kid` lạ không do người ngoài điều khiển (go-oidc tải lại bộ khoá của provider đã lưu chỉ khi gặp `kid` lạ). `SSOIdentity.Issuer` là issuer đã cấu hình (đã so khớp với `iss`). Thông báo `discovery_failed` là câu cố định theo loại lỗi, không chép nội dung phía bên kia trả về. Discovery giữ trong bộ nhớ 1 giờ; Test và lưu cấu hình làm mới. `TestContract_INV1_*`. Sai bất kỳ điều nào → 400 `sso_failed`, không tạo phiên, `auth.login_failed` chi tiết `SSO: id_token`.
- **INV-2** `issuer` bắt buộc **https** (bỏ `/` cuối); `client_id` 1..200 ký tự; `client_secret` ≥ 8 ký tự; `scopes` 1..10 từ theo RFC 6749 §3.3, phải có `openid`; `groups_claim` khớp `^[A-Za-z0-9_.:/-]{1,64}$`; `default_role` ∈ {viewer, operator, admin, null}; `role_map` ≤ 10 dòng `{group ≤ 256 ký tự, role hợp lệ}`, dòng nhóm rỗng bị bỏ. Sai → 400 (`invalid_issuer`, `invalid_client`, `invalid_secret`, `invalid_scopes`, `invalid_claim`, `invalid_role`, `too_many`).
- **INV-3** `client_secret` lưu qua `core/secrets` (AES-GCM), API chỉ trả `secret_last4`; để trống khi sửa = giữ bí mật cũ (SYS-4) **chỉ khi issuer và client_id không đổi**; đổi một trong hai mà không nhập lại bí mật → 400 `invalid_secret` (không thì bí mật thật đi tới điểm token của issuer mới). Điểm token nhận bí mật đúng một cách: `client_secret_basic` (mặc định) hoặc `client_secret_post` khi discovery chỉ khai cách đó; cách khác → `discovery_failed`. Bí mật và mọi token của IdP (code, access, ID, refresh) không vào log, export, sao lưu, audit.
- **INV-4** Nút SSO chỉ hiện khi module bật **và** đã có `issuer` (`GET /core/auth-options` → `{oidc: true}`); endpoint công khai này không lộ gì khác.
- **INV-5** **Ràng buộc trình duyệt, không cookie mới** (D-194 (4)): `POST /auth/oidc/start` lưu một luồng `oidc_flow` (SHA-256 của `state` và `binding`, nonce, PKCE verifier, `redirect_uri`, hạn 10 phút) và trả `{authorize_url, binding}`; `POST /auth/oidc/callback` cần đúng `binding`; luồng bị xoá ở lần gọi lại đầu tiên dù đúng hay sai; luồng lạ, đã dùng, quá hạn hay sai binding → 400 `sso_expired`. Tối đa 1000 luồng chưa xong (bỏ cái cũ nhất); `start` và `callback` mỗi cái theo địa chỉ 30 lần / 15 phút → 429 `rate_limited`. `state` lạ trả `sso_expired` mà **không** ghi audit (chống làm đầy nhật ký); luồng có thật thì mọi từ chối đều ghi.
- **INV-6** `redirect_uri` **ghim lúc `PUT /core/oidc`**: nguồn của yêu cầu lưu (scheme của tiến trình + `Host`) + `/sso/callback`; `GET /core/oidc` trả giá trị đã ghim (chưa lưu lần nào: giá trị sẽ được ghim từ yêu cầu này). `start` có nguồn khác → 409 `sso_wrong_address` (`address` = nguồn đúng); không bao giờ dựng `redirect_uri` từ `Host` của yêu cầu chưa đăng nhập. Luồng giữ `issuer`, `client_id`, `redirect_uri` lúc bắt đầu; ở `callback` hai giá trị đầu khác cấu hình hiện tại → 400 `sso_expired`.
- **INV-7** **Định danh là (`iss`, `sub`)** (D-195). Vai = vai cao nhất trong các dòng `role_map` có nhóm nằm trong claim `groups_claim` của ID token (khoá cấp cao nhất đúng tên, không phải đường dẫn; chuỗi hoặc mảng chuỗi; chỉ xét 200 nhóm đầu, nhóm dài quá 256 ký tự bị bỏ chứ không cắt); không dòng nào khớp → `default_role`; `null` → 403 `no_access`, không tạo tài khoản. Vai ghi lại ở **mỗi** lần đăng nhập SSO (`user.role`, chi tiết `SSO groups`) và khi vai đổi thì các phiên cũ của người đó kết thúc; `no_access` với tài khoản đã có kết thúc mọi phiên của nó.
- **INV-8** Lần đầu: tạo tài khoản `sso` (không mật khẩu dùng được, `user.create` chi tiết `SSO`). Email (claim `email`, so chữ thường; thiếu hoặc `email_verified=false` → 403 `email_unverified`) trùng tài khoản mật khẩu, hoặc tài khoản SSO cùng issuer khác `sub` → 409 `email_in_use`, không nối; trùng tài khoản SSO của issuer khác → gắn lại sang (`iss`, `sub`) mới **chỉ khi `email_verified=true`** (`user.sso_relink`), không thì 409 `email_in_use`. Email và tên không đổi theo IdP sau khi tạo. Tài khoản bị vô hiệu → 403 `disabled` dù IdP cho qua.
- **INV-9** Đăng nhập SSO thành công tạo phiên **như đăng nhập mật khẩu** (`__Host-vedette_session` + `__Host-vedette_csrf`, D-71); **không** đặt hay đọc `__Secure-vedette_device` (D-196 (2)); không qua hai bước của hộp (IdP lo MFA).
- **INV-10** Mọi đăng nhập SSO thành công/thất bại, lưu và thử cấu hình ghi `core_audit` (SYS-3): `auth.login` `SSO`, `auth.login_failed` `SSO: <state|binding|token|id_token|no_access|email_in_use|email_unverified|disabled>`, `oidc.update`, `oidc.test`, `user.create` `SSO`, `user.role` `SSO groups`, `user.sso_relink`.
- **INV-11** Dữ liệu từ IdP (discovery, JWKS, phản hồi token, claim) là không tin cậy (SYS-6): ≤ 1 MiB, 10 s, kiểm kiểu, fail-closed; `issuer` trong discovery phải trùng issuer đã lưu; điểm authorization/token/jwks phải https; không theo chuyển hướng (SYS-7).

## Preconditions (trước khi gọi)
- **PRE-1** `PUT /core/oidc`, `POST /core/oidc/test`, `GET /core/oidc`: vai admin, module bật.
- **PRE-2** `POST /core/oidc/test`: đã lưu cấu hình (400 `not_configured`).
- **PRE-3** `POST /auth/oidc/start` và `callback`: module tắt → không có route (404, SYS-5); bật mà chưa có `issuer` → 400 `oidc_off`.

## Postconditions (sau khi xong)
- **POST-1** `test` thành công trả `{ok:true, endpoints:{authorization, token, jwks}}` đọc từ `/.well-known/openid-configuration`; không đọc được → 502 `discovery_failed` nêu đường mạng từ hộp tới IdP.
- **POST-2** Đăng nhập thành công: phiên như POST-1 của đăng nhập mật khẩu, `last_login` cập nhật, audit theo INV-10; SPA tới `next` đã giữ trong sessionStorage (chỉ đường dẫn trong app).
- **POST-3** Lưu cấu hình: lần đăng nhập kế tiếp dùng cấu hình mới; phiên đang có không bị ngắt; luồng đang chờ của issuer/client cũ trả `sso_expired` (INV-6).

## Forbidden (không bao giờ)
- **FORBID-1** Luồng implicit, hybrid, password grant; bỏ PKCE; PKCE `plain`.
- **FORBID-2** Trả `client_secret` hoặc token IdP qua API/log/export.
- **FORBID-3** Cấp vai cao hơn kết quả `role_map`/`default_role`; nối vào tài khoản mật khẩu theo email.
- **FORBID-4** Gọi IdP khi module tắt hoặc chưa có `issuer`.
- **FORBID-5** Chấp nhận `issuer` hoặc điểm discovery không phải https; chấp nhận `alg` đối xứng hay `none`.
- **FORBID-6** Thêm cookie (legal.md); đặt mật khẩu cho tài khoản SSO (đặt lại, đổi mật khẩu, bật hai bước → 409 `sso_user`); đổi vai tài khoản SSO trong Users (409 `sso_user`).

## Endpoints owned
| Method | Path | Vai tối thiểu | Story |
|---|---|---|---|
| GET | `/core/oidc` | admin | S-CORE-3 |
| PUT | `/core/oidc` | admin | S-CORE-3 |
| POST | `/core/oidc/test` | admin | S-CORE-3 |
| GET | `/core/auth-options` | public | S-CORE-3 |
| POST | `/auth/oidc/start` | public | S-CORE-3 |
| POST | `/auth/oidc/callback` | public | S-CORE-3 |

Trang SPA `/sso/callback` là `redirect_uri` (D-194 (4)): IdP đưa trình duyệt về đó, trang gửi `POST /auth/oidc/callback`.

## Tables owned
`oidc_config` (issuer, client_id, bí mật mã hoá qua `core/secrets` purpose `oidc_config.client_secret`, scopes, groups_claim, default_role, role_map, redirect_uri), `oidc_flow` (luồng đang chờ, INV-5). Định danh SSO (`sso_issuer`, `sso_subject`), người dùng và phiên thuộc `core` (`core_user`, `core_session`), chỉ qua `core/auth.SSOSignIn`, `RefuseSSO`, `CountSSOUsers` (D-197).

## Events
- **Phát**: không (audit qua `core`). **Nhận**: không.

## Khi tắt module (SYS-5)
Không route SSO (`/auth/oidc/*`, `/core/oidc*`), nút SSO biến mất (`auth-options.oidc=false`), không gọi IdP. Cấu hình giữ nguyên. Tài khoản SSO vẫn tồn tại nhưng không đăng nhập được cho tới khi bật lại (không có mật khẩu); GUI nói số tài khoản này (`sso_users`) trong hộp thoại tắt. Phiên đang có giữ tới khi hết hạn.

## Dependencies
- **DEPENDS ON**: `core` (người dùng, phiên, vai, audit, `core/secrets`, giới hạn theo địa chỉ).
- **DEPENDED ON BY**: `core` (trang đăng nhập hỏi `auth-options`; luật quản trị viên cuối chỉ tính quản trị viên dùng mật khẩu, D-196 (3)).

## Câu hỏi mở
Không còn (trả lời bởi D-194..D-196). RP-initiated logout: không làm (D-194 (8)).
