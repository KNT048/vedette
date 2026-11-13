# Scan-credentialed — Change Impact Map

## Modifying: `scancred.Service` — `Targets()`, `Add(ctx, in)`, `Remove(ctx, id)`, `Test(ctx, id)`
- **SPA** (`CredentialedTab`, ẩn trong v1 sau `CREDENTIALED_IN_UI` của `web/src/lib/credentialed.ts`, D-417: bật lại khi có backend; `ScansPage`, `ModulesSection`, `SetupPage` đọc công tắc), **core/audit**. Đổi mã lỗi (`not_server`, `exists`, `bad_key`) đổi thông báo giao diện; `scan/contract.ts` là nguồn OpenAPI.

## Modifying: lưu khoá qua `secrets.Seal` (khoá `scancred/<id>/ssh_key`)
- **core** (`/core/data/export|backup` phải loại bỏ). Đổi tên khoá làm mất khoá cũ khi nâng cấp: cần migration.

## Modifying: gọi `hostclient.StartContainer("greenbone")` và image ký
- **core/vedette-host**: danh sách lệnh cố định phải có thao tác này; thêm quyền = thay đổi bảo mật.

## Modifying: gọi `inventory.InScope` và `scan` (cửa sổ, Stop now)
- **inventory**, **scan**: nới phạm vi ở đó làm rộng phạm vi quét có tài khoản.

## Modifying: kết quả → `findings` (`basis`)
- **findings**: cần thêm giá trị `basis` nếu credentialed tạo finding; đổi enum `basis` là đổi `findings/contract.ts`.

## Disabling this module
- Tab Credentialed của Scans báo "off"; container greenbone dừng; không kết nối SSH.
- Không module nào phụ thuộc nên không module khác mất chức năng; finding từ lượt credentialed cũ giữ. Tài khoản và khoá mã hoá giữ.
