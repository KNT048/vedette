# Auth-OIDC — Change Impact Map

> Chưa có mã Go (PR 2 của WP-27); chữ ký là kế hoạch (package `modules/authoidc`). Hợp đồng GUI đã chốt: `web/src/features/core/contract.ts` (D-194..D-196).

## Modifying: `OidcConfig` / `OidcSave` (GET/PUT `/core/oidc`)
- **web/features/core (UsersSection)**: form SSO; đổi → sinh lại `api/openapi.json` + `make generate-api` + sửa mock.
- **core (`auth-options`)**: chỉ đọc cờ "module bật và đã có issuer".

## Modifying: `POST /auth/oidc/start`, `POST /auth/oidc/callback`
- **web/app/LoginPage**, **web/features/core/SsoCallbackPage**, **ssoFlow.ts** (sessionStorage `vedette-sso-flow`). Đổi tên trường `binding` hay đường `/sso/callback` → `redirect_uri` đã đăng ký ở IdP của khách không còn khớp: mọi hộp đang chạy phải đăng ký lại.

## Modifying: `Login.Callback(ctx, code, state, binding) (userID, error)` — 1 người gọi (route callback)
- **core/session**: tạo phiên, ghi `auth.login`. Đổi lỗi/trả về → trang `/sso/callback` hiển thị sai; đổi cách lấy vai → quyền người dùng SSO đổi ở lần đăng nhập kế tiếp (test INV-7).

## Modifying: `MapRole(groups []string, cfg) (Role, ok)`
- **core/users**: vai hiển thị trong Users; đổi quy tắc chọn (cao nhất) → nâng/hạ quyền hàng loạt ở lần đăng nhập kế tiếp.

## Modifying: interface của `core` cho tài khoản SSO (`EnsureSSOUser`, cờ `core_users.sso`)
- **core/users**: luật quản trị viên cuối (chỉ tính tài khoản mật khẩu), chặn đặt lại/đổi mật khẩu, bật hai bước, đổi vai (409 `sso_user`); `AdminUser.sso`, `Account.user.sso`. Đổi khoá định danh (`iss`, `sub`) → nhân đôi người dùng hoặc gộp nhầm.

## Disabling this module
- Nút SSO biến mất; người đang đăng nhập bằng SSO giữ phiên đến hết hạn; tài khoản SSO không vào được tới khi bật lại (GUI nêu `sso_users` trước khi tắt). `oidc_config`, `oidc_identity` giữ nguyên; `oidc_flow` hết hạn tự nhiên.
