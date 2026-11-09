# Kiểm tra: `make check` trên máy, bộ đầy đủ trên CI (kien, 2026-11-09, D-61 → D-62, D-63)

Repo `KNT048/vedette` là public nên GitHub Actions miễn phí (D-63). CI chạy bộ đầy đủ trên máy GitHub; máy người làm chỉ chạy phần nhanh.

- **Trước khi push / mở PR: `make check`** trên nhánh đã rebase lên `origin/main`. Chỉ kiểm phần đã đổi: Go → build, vet, `go test -race ./...` (cache chỉ chạy lại gói bị ảnh hưởng), contract, lint, kiểm mã sinh khi hợp đồng/migration/query đổi; giao diện → tsc, lint, `vitest --changed`, kiểm lệch `api/openapi.json` khi `contract.ts` đổi, spec e2e của module bị chạm (desktop); chỉ docs → không chạy gì; file dùng chung (dependency, cấu hình build, `web/src/lib`, `web/src/mocks`, Makefile, `scripts/`) → tự chạy `make verify` đầy đủ.
- **Merge khi CI xanh** (job `go`, `web`; job `e2e` tạm chưa chặn cho tới khi bộ e2e gốc được sửa). CI đỏ → sửa, không merge "vì máy mình xanh". Dán phần cuối `make check` vào mục **Local checks** của PR.
- Workflow chỉ gọi `make`; action bên thứ ba ghim theo SHA; quyền token tối thiểu. Không thêm workflow tốn phút ngoài `ci.yml` mà không ghi quyết định.
- `make audit` (govulncheck + `pnpm audit`) đầu mỗi phiên; CI cũng quét hằng ngày trên `main`.
- **Máy phát triển là Linux hoặc macOS.** Windows: chạy `make` trong WSL2 (Ubuntu), mã nằm trong hệ file của WSL (không `/mnt/c`); Makefile từ chối Windows gốc.
- **Không chạy song song nhiều việc nặng** (build web, vitest toàn bộ, Playwright, `make verify`) trên cùng máy: tối đa 2 cùng lúc; trước khi chạy Playwright kiểm không còn lượt nào (`pgrep -f playwright/test/cli.js`); lệnh hết giờ thì giết cả cây tiến trình. Máy quá tải làm test timeout giả.
- Phát hành (image, SBOM, ký cosign bằng khoá người duy trì) chạy trên máy người duy trì bằng `make` (WP-08); kien tag tay.
