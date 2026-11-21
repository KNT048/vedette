# Auth-OIDC — Change Impact Map

> Package `modules/auth-oidc` (Go package `authoidc`). Hợp đồng GUI: `web/src/features/core/contract.ts`. Last verified: 2026-11-21 (mọi câu đã đối chiếu với code).

## Modifying: `Service.Store(ctx, actor, origin, Save)` / `View(ctx, origin)` (PUT/GET `/core/oidc`)
- **web/features/core (`UsersSection.tsx`)**: form SSO; đổi trường → sinh lại `api/openapi.json` + `make generate-api` + sửa mock.
- **cmd/vedette/wiring.go `privacyFacts.OIDCConfigured`** đọc `Service.Configured`; `modules/core/handlers_privacy.go` (luồng 11 của Privacy) và `modules/core/handlers_session.go` (`GET /core/auth-options`, nút SSO) gọi nó qua `privacyFacts`. Đổi nghĩa "đã cấu hình" → nút và trang Privacy đổi theo.
- `Store` ghim `redirect_uri` theo nguồn của người lưu (INV-6): đổi cách tính → mọi hộp phải đăng ký lại địa chỉ ở IdP.

## Modifying: `Service.Start` / `Service.Callback` (POST `/auth/oidc/start`, `/auth/oidc/callback`)
- **web/src/app/LoginPage.tsx**, **web/src/features/core/SsoCallbackPage.tsx**, **ssoFlow.ts** (sessionStorage `vedette-sso-flow`). Đổi tên trường `binding` hay đường `/sso/callback` → redirect URI đã đăng ký ở IdP của khách không còn khớp.
- **core/auth `SSOSignIn`**: Callback chuyển (`iss`, `sub`, email, `email_verified`, name, vai) sau khi đã kiểm ID token. Đổi những gì được kiểm trước khi gọi → `core/auth` tin dữ liệu chưa kiểm (INV-1).
- **modules/core codes/catalogue test**: mã lỗi mới phải có trong `docs/API_CONVENTIONS.md` (đếm theo mỗi bảng trạng thái).

## Modifying: `MapRole(groups, rows, def)` và `idClaims.groups(claim)`
- Vai của mọi tài khoản SSO ở lần đăng nhập kế tiếp; đổi quy tắc (cao nhất, khớp đúng tên, bỏ nhóm > 256 ký tự, 200 nhóm đầu) → nâng/hạ quyền hàng loạt và kết thúc phiên của người bị đổi vai.

## Modifying: `newClient` / `discover` / `clientFor` (mọi lời gọi tới IdP)
- INV-11: https, không chuyển hướng, 1 MiB, 10 s, danh sách thuật toán. Nới bất kỳ điều nào → `TestContract_INV11_Discovery` và rà bảo mật.
- INV-12: `clientFor(ca_pem)` cho discovery, JWKS (provider giữ client) và đổi mã lấy token (`idp.client`). Dùng `s.client` trực tiếp ở chỗ mới → IdP sau CA nội bộ hỏng ở chỗ đó. `parseCA` là cổng duy nhất vào `oidc_config.ca_pem`; nới nó → rà bảo mật.
- **web/features/core (`OidcCaField.tsx`, mock `caError`)**: thông điệp `invalid_ca` và câu "does not trust" của `publicReason` được GUI nhắc tới tên ô "Identity provider CA certificate".

## Depends on core (interface)
- `core/auth.SSOSignIn`, `RefuseSSO`, `CountSSOUsers`; `core/secrets` (purpose `oidc_config.client_secret`); `core/audit`; cột `sso_issuer`/`sso_subject` của `core_user` (core sở hữu).

## Wiring
- `cmd/vedette/modules.go` (`Deps.OIDC`, migrations), `cmd/vedette/wiring.go` (`authoidc.New`), `cmd/vedette/handler.go` (`OIDCHandlers`); `core/server/modules.go` mở/đóng route `/core/oidc`, `/auth/oidc` theo module (SYS-5); `web/src/lib/modules.ts` và `web/src/features/core/ModulesSection.tsx` (hộp thoại tắt đọc `sso_users`). Đổi đường dẫn route → sửa `core/server/modules.go`.

## Disabling this module
- Server trả 404 cho `/auth/oidc/*`, `/core/oidc*` (SYS-5); `auth-options.oidc=false`; không gọi IdP. Tài khoản SSO không vào được tới khi bật lại (GUI nêu `sso_users` trước khi tắt). `oidc_config` giữ nguyên; `oidc_flow` hết hạn và bị dọn ở lần `start` kế tiếp.
