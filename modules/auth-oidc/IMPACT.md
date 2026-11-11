# Auth-OIDC — Change Impact Map

> Package `modules/auth-oidc` (Go package `authoidc`), WP-27 PR 2 (D-194..D-197). Hợp đồng GUI: `web/src/features/core/contract.ts`.

## Modifying: `Service.Store(ctx, actor, origin, Save)` / `View(ctx, origin)` (PUT/GET `/core/oidc`)
- **web/features/core (UsersSection)**: form SSO; đổi trường → sinh lại `api/openapi.json` + `make generate-api` + sửa mock.
- **cmd/vedette `privacyFacts.OIDCConfigured`** đọc `Service.Configured`: luồng 11 của Privacy và `GET /core/auth-options` (nút SSO). Đổi nghĩa "đã cấu hình" → nút và trang Privacy đổi theo.
- `Store` ghim `redirect_uri` theo nguồn của người lưu (INV-6): đổi cách tính → mọi hộp phải đăng ký lại địa chỉ ở IdP.

## Modifying: `Service.Start` / `Service.Callback` (POST `/auth/oidc/start`, `/auth/oidc/callback`)
- **web/app/LoginPage**, **web/features/core/SsoCallbackPage**, **ssoFlow.ts** (sessionStorage `vedette-sso-flow`). Đổi tên trường `binding` hay đường `/sso/callback` → redirect URI đã đăng ký ở IdP của khách không còn khớp.
- **core/auth `SSOSignIn`**: Callback chuyển (`iss`, `sub`, email, `email_verified`, name, vai) sau khi đã kiểm ID token. Đổi những gì được kiểm trước khi gọi → `core/auth` tin dữ liệu chưa kiểm (INV-1).
- **modules/core codes/catalogue test**: mã lỗi mới phải có trong `docs/API_CONVENTIONS.md` (đếm theo mỗi bảng trạng thái).

## Modifying: `MapRole(groups, rows, def)` và `idClaims.groups(claim)`
- Vai của mọi tài khoản SSO ở lần đăng nhập kế tiếp; đổi quy tắc (cao nhất, khớp đúng tên, bỏ nhóm > 256 ký tự, 200 nhóm đầu) → nâng/hạ quyền hàng loạt và kết thúc phiên của người bị đổi vai.

## Modifying: `newClient` / `discover` (mọi lời gọi tới IdP)
- INV-11: https, không chuyển hướng, 1 MiB, 10 s, danh sách thuật toán. Nới bất kỳ điều nào → `TestContract_INV11_Discovery` và rà bảo mật.

## Depends on core (interface)
- `core/auth.SSOSignIn`, `RefuseSSO`, `CountSSOUsers`; `core/secrets` (purpose `oidc_config.client_secret`); `core/audit`; bảng `core_user.sso_issuer/sso_subject` (core sở hữu, migration core 0010).

## Disabling this module
- Server trả 404 cho `/auth/oidc/*`, `/core/oidc*` (SYS-5); `auth-options.oidc=false`; không gọi IdP. Tài khoản SSO không vào được tới khi bật lại (GUI nêu `sso_users` trước khi tắt). `oidc_config` giữ nguyên; `oidc_flow` hết hạn và bị dọn ở lần `start` kế tiếp.
