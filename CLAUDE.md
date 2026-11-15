# Vedette

Phần mềm mã nguồn mở, miễn phí: cảnh báo lỗ hổng **đang bị khai thác thật** khớp với tài sản khách có, kèm cách xử lý. Không inline, không chặn traffic. Dự án cá nhân của kien (D-27); AI code, kien giám sát. Sản phẩm: `docs/PRODUCT.md`.

## Đang làm: ship v1 — đọc `SHIP.md` trước mọi việc
- v1 = 7 hành trình khách J1–J7 đạt trên hộp thật; trạng thái ở `docs/v1-journeys.json`. Phạm vi đóng băng (D-624).
- Việc v1: GitHub issue nhãn `v1`. Ý mới, việc để sau: issue nhãn `post-v1`. Không ghi việc ở nơi khác; không tạo file trong `.ai/deferred/` (D-625).
- Mỗi PR nêu nó gỡ chặn Jn hay cổng phát hành nào. Việc không thuộc v1 thì không làm trước khi tag v1.

## Lệnh
- `make dev` (giao diện + dữ liệu mẫu, http://localhost:5173), `make dev-api` (backend thật).
- Trước khi push: `git merge origin/main` rồi `make check-fast` **một lần**; CI là cổng, không ngồi chờ, không chạy lặp test.
- `make generate` sau khi sửa `api/openapi.json`, truy vấn sqlc hoặc migration. `api/openapi.json` sinh từ `web/src/features/*/contract.ts` (`pnpm --dir web openapi`). Không sửa tay `core/api/oas/`, `core/api/routes/routes_gen.go`, `core/store/coredb/`.
- Một test Go: `go test ./modules/<m>/... -run '^TestX$'`. Một test web: `pnpm --dir web vitest run <file>`.
- Công cụ Go: `go tool -modfile=tools/go.mod …`. Node ghim qua `devEngines.runtime` trong `web/package.json`.
- Build xong thì `make clean` (không để `bin/`, `web/dist/`).

## Git
Worktree riêng mỗi việc; nhánh `feat/…`, `fix/…`, `docs/…`. Không push `main`, không force-push, không tạo tag (kien hoặc supervisor tag v1 sau khi báo kien). Merge qua merge queue khi CI xanh: `gh pr merge <n> --squash`. Lượt queue đỏ: báo supervisor.

## Luật không có ngoại lệ
- **Bảo mật:** tiến trình ngoài chỉ qua `core/exec` (allowlist binary + argv), không shell string, không eval; validate ở biên; secret qua `core/secrets`, không log. → `.claude/rules/security.md`
- **Pháp lý:** dependency hoặc nguồn dữ liệu mới → `THIRD_PARTY_NOTICES.md` cùng commit, không GPL/AGPL nhúng; luồng dữ liệu rời hộp mới → `PRIVACY.md` + màn hình Quyền riêng tư cùng commit. → `.claude/rules/legal.md`
- **Ships as code:** máy mới dựng từ repo đạt cùng trạng thái; phụ thuộc cài bởi `install.sh`/package, ghim phiên bản, xác minh bằng hiệu ứng.
- **Module:** đọc `CONTRACT.md` + `IMPACT.md` trước khi sửa module. → `.claude/rules/modules.md` (tự nạp khi chạm `modules/`)
- **Agent:** mọi Bash có timeout; subagent không chạy full suite, không SSH, không deploy; tối đa 2 việc nặng cùng lúc trên một máy; chỉ dừng PID của chính mình.

## Cách quyết định
- Phân vân: xem sản phẩm hàng đầu cùng loại làm thế nào rồi tự quyết. Chỉ hỏi kien khi tốn tiền, pháp lý, dữ liệu mới rời hộp, đổi phạm vi v1 hoặc không hoàn tác được.
- File `docs/decisions/D-nnn.md` (một hàng bảng, kèm nguồn) chỉ cho: phạm vi sản phẩm, pháp lý, dữ liệu rời hộp, mô hình bảo mật, việc không hoàn tác được. Lựa chọn khác ghi trong mô tả PR.
- Màn hình hoặc hành vi mới phải truy về một story trong `docs/USER_STORIES.md`; thiếu thì thêm tiêu chí vào story sẵn có. Không thêm tuỳ chọn "để sau này cần".
- Viết đúng cái cần: không interface cho một implementation, không layer cho một caller.

## Kiểm tra
- Xong = chạy được như khách. Thay đổi giao diện: kiểm theo `docs/QA.md`. Hành trình v1: kiểm trên hộp thật, ghi chứng cứ vào `docs/v1-journeys.json`.
- Review: một lượt độc lập, đối chiếu brief/spec, bỏ qua style. Lượt hai chỉ khi lượt một có High hoặc PR chạm KEV matching, auth, secret, parser dữ liệu không tin cậy.
- Test kiểm tính đúng, không đo tốc độ máy: chờ theo trạng thái hoặc `testing/synctest`, không `time.Sleep`. Test chập chờn vào `scripts/ci/skip-tests.txt` kèm issue.

## Khi kien nói "doc"
Chạy skill `/end-of-session`.
