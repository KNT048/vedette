# Auth-OIDC — Change Impact Map

> Chưa có mã Go; chữ ký là kế hoạch (package `modules/authoidc`), chốt ở M7.

## Modifying: `Config.Get/Save(ctx, OidcSave)` — 2 người gọi
- **web/features/core (UsersSection)**: `OidcConfig`/`OidcSave` là hợp đồng GUI; đổi → sinh lại OpenAPI + sửa mock.
- **core (`auth-options`)**: chỉ đọc cờ "đã có issuer".

## Modifying: `Login.Callback(ctx, code, state) (Session, error)` — 1 người gọi (route callback)
- **core/session**: tạo phiên, ghi `auth.login`. Đổi lỗi/trả về → trang đăng nhập hiển thị sai; đổi cách lấy vai → quyền người dùng SSO đổi (test INV-5).

## Modifying: `MapRole(groups []string) Role`
- **core/users**: vai hiển thị trong Users; đổi quy tắc chọn → có thể nâng/hạ quyền hàng loạt ở lần đăng nhập kế tiếp.

## Modifying: `core.Users.EnsureSSOUser(email)` (interface do `core` cung cấp, `auth-oidc` gọi)
- **core**: đổi khoá định danh (email) → nhân đôi người dùng hoặc gộp nhầm.

## Disabling this module
- Nút SSO biến mất; người đang đăng nhập bằng SSO giữ phiên đến hết hạn; người chỉ có SSO (không mật khẩu dùng được) bị khoá ngoài cho tới khi quản trị viên đặt lại mật khẩu hoặc bật lại. UI phải nêu số người bị ảnh hưởng (`affected` của `PATCH /modules/{id}` chỉ liệt kê module phụ thuộc, chưa đủ cho việc này). Cấu hình `oidc_config` giữ nguyên.
