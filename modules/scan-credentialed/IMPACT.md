# Scan-credentialed — Change Impact Map

## Modifying: `scancred.Service` — `Targets()`, `Add(ctx, in)`, `Remove(ctx, id)`, `Test(ctx, id)`
- **SPA** (`CredentialedTab`, ẩn trong v1 sau `CREDENTIALED_IN_UI` của `web/src/lib/credentialed.ts`: bật lại khi có backend; module chưa có mã Go; `ScanningPage` (Settings → Scanning), `ScansMoved`, và `ModulesSection`/`SetupPage` qua `notOffered` của `web/src/lib/v1.ts` đọc công tắc), **core/audit**. Đổi mã lỗi (`not_server`, `exists`, `bad_key`) đổi thông báo giao diện; `scan/contract.ts` là nguồn OpenAPI.

## Modifying: lưu khoá qua `secrets.Seal` (purpose `scc_target.private_key`, như bảng `core_secret` ghi)
- **core** (`/core/data/export|backup` phải loại bỏ). Đổi purpose làm mất khoá cũ khi nâng cấp: cần migration.

## Modifying: chạy container `greenbone` và image ký (chưa xây; thiết kế)
- **cmd/vedette-host**, `host/client`: danh sách lệnh cố định phải có thao tác này (`exposure` đã dùng Greenbone qua `GreenboneHost` riêng của nó; thao tác đó không dùng chung cho module này); thêm quyền = thay đổi bảo mật.

## Modifying: gọi `Settings.InScope` của `inventory` và `scan` (cửa sổ, Stop now)
- **inventory**, **scan**: nới phạm vi ở đó làm rộng phạm vi quét có tài khoản.

## Modifying: kết quả → `findings` (`basis`)
- **findings**: cần thêm giá trị `basis` nếu credentialed tạo finding; đổi enum `basis` là đổi `findings/contract.ts`.

## Disabling this module
- Tab Credentialed của Scans báo "off"; container greenbone dừng; không kết nối SSH.
- Không module nào phụ thuộc nên không module khác mất chức năng; finding từ lượt credentialed cũ giữ. Tài khoản và khoá mã hoá giữ.
