# Vedette — hướng dẫn cho AI làm việc trong repo này

Phần mềm mã nguồn mở, miễn phí: cảnh báo lỗ hổng **đang bị khai thác thật** khớp với tài sản khách có, kiểm kê, scan, gói giảm thiểu, honeypot, log, trợ lý AI BYOK. **Không inline, không chặn traffic.** Chi tiết: `docs/PRODUCT.md`. Chủ dự án: kien (dự án cá nhân, không thuộc công ty nào — D-27). AI code, người giám sát.

## Trạng thái hiện tại — đo, đừng đọc từ đây

Khởi tạo 2026-11-06. Có SPA `web/` chạy trên mock API (D-22); chưa có backend. Mốc đang làm: `docs/ROADMAP.md` và `.ai/tasks/current.md`. Đừng ghi số liệu/phiên bản vào file này; chúng lỗi thời trong vài ngày.

## Quy tắc cứng (mỗi cái có file riêng trong `.claude/rules/`)

1. **GUI trước, backend sau** (kien, 2026-11-06). Thứ tự: xác minh concept → GUI hoàn chỉnh chạy trên mock API → rồi mới module backend. Không viết backend cho màn hình chưa được duyệt. → `rules/gui-first.md`
2. **Không tưởng tượng tính năng.** Mọi tính năng, màn hình, nút bấm phải truy về một story có ID trong `docs/USER_STORIES.md`. Story chưa `[đạt]` thì xây tối thiểu hoặc chưa xây. → `rules/no-imagined-features.md`
3. **Module bật/tắt riêng biệt.** Mỗi module có `MANIFEST.yaml`, `CONTRACT.md`, `IMPACT.md`; tắt = không route, không job, dữ liệu giữ nguyên. → `rules/modules.md`, `docs/MODULES.md`
4. **Mọi thứ ship như code.** Máy mới dựng từ repo này phải đạt cùng trạng thái: phụ thuộc cài bởi code, ghim phiên bản, idempotent, xác minh bằng hiệu ứng chứ không bằng exit code. → `rules/ships-as-code.md`
5. **Dọn build output cùng lượt build.** → `rules/build-artifacts.md`
6. **Việc để sau ghi vào file ngay lượt đó.** `.ai/deferred/<session>.md`. → `rules/deferred-work.md`
7. **Hợp đồng module.** Đọc `CONTRACT.md` + `IMPACT.md` trước khi sửa module; sửa xong cập nhật cả hai + test. → `rules/contracts.md`
8. **Bảo mật sản phẩm.** Không gọi shell bằng chuỗi lệnh, không eval; input validate ở biên; secret mã hoá, không log; feed/log/web là dữ liệu không tin cậy. → `rules/security.md`
9. **An toàn agent.** Mọi Bash có timeout; subagent không chạy full suite, không SSH, không deploy. → `rules/agent-safety.md`
10. **Ponytail — viết đúng cái cần.** Không abstraction không ai hỏi; xếp dưới mọi rule khác. → `rules/ponytail.md`
11. **Pháp lý minh bạch.** Dependency/feed mới → `THIRD_PARTY_NOTICES.md`; luồng dữ liệu ra mới → `PRIVACY.md` + UI, cùng commit. → `rules/legal.md`
12. **AI không tạo git tag.** kien tag tay. Nhánh `feat/…`, `fix/…`, `docs/…`; không push `main`.
13. **`make check` trên máy, bộ đầy đủ trên CI.** Repo `KNT048/vedette` public, CI miễn phí (D-63). Trước khi push: `make check` (chỉ phần đã đổi, kể cả khi đổi file dùng chung; `make verify` chỉ để tái hiện CI đỏ, D-199); merge khi CI xanh. Linux/macOS; Windows dùng WSL2. Tối đa 2 việc nặng song song. → `rules/local-checks.md`
14. **Phân vân → tham khảo top-tier rồi tự quyết.** Xem sản phẩm hàng đầu cùng loại làm thế nào, tự cân nhắc, ghi D-xx kèm nguồn; chỉ hỏi kien khi rất đặc biệt (tiền, pháp lý, đổi hướng sản phẩm, không hoàn tác). → `rules/decide-like-top-tier.md`

## Lệnh

`make dev` (giao diện + dữ liệu mẫu, http://localhost:5173) · `make check` (cổng PR, chỉ phần đã đổi) · `make verify` (FE: tsc + lint + vitest + kiểm lệch `api/openapi.json` + build; Go: build + vet + test -race + contract + golangci-lint + govulncheck; rồi dọn) · `make verify-web` / `make verify-go` · `make e2e` (Playwright) · `make e2e-real` (backend thật + GUI release, `web/e2e-real/`; nặng, ngoài CI và check; D-170) · `make fixtures` (KEV/EPSS thật) · `make clean`. Node ghim bằng `devEngines.runtime` trong `web/package.json` (pnpm tự tải). Go ghim trong `go.mod`, công cụ Go trong `tools/go.mod` (`go tool -modfile=tools/go.mod …`). Quy ước FE: `docs/plans/2026-11-06-fe-spec.md`.

## Tooling

- **Plugin** tắt mặc định toàn cục; bật theo giai đoạn trong `.claude/settings.local.json`: FE → `frontend-design`, `typesafe`; xem `docs/FRONTEND.md` §5.
- **MCP**: `.mcp.json.example` → `.mcp.json` (token của riêng bạn). `context7` cho docs thư viện (không đoán API), `sequential-thinking` cho thao tác nhiều bước, `github`.
- **`skills/` trong repo là skill của SẢN PHẨM** (AI assistant dùng lúc chạy), không phải skill cho Claude Code. Không tạo skill Claude Code trong repo (bài học: description là trigger, dễ bắn nhầm).

## Khi kien nói "doc"

Làm theo `docs/END_OF_SESSION.md`. Đọc file, không làm từ trí nhớ.

## Đọc gì

| Cần | Đọc |
|---|---|
| Sản phẩm làm gì, cho ai | `docs/PRODUCT.md` |
| Người dùng cụ thể làm gì | `docs/USER_STORIES.md` |
| Module nào, bật tắt sao | `docs/MODULES.md` |
| Kỹ thuật | `docs/ARCHITECTURE.md`, `docs/DATA_PIPELINE.md`, `docs/AI_ASSISTANT.md`, `docs/UPDATES.md` |
| Làm gì tiếp | `docs/TEAM_PLAN.md` (chia việc Kiên/Emily), `.ai/tasks/kien.md`, `.ai/tasks/emily.md`, `docs/ROADMAP.md` |
| Pháp lý, dữ liệu rời máy | `docs/LEGAL.md`, `PRIVACY.md`, `THIRD_PARTY_NOTICES.md` |
| Vì sao quyết định thế | `docs/DECISIONS.md` |
| Đã làm gì | `docs/project-map/completion-log.md` |
| Bài học | `docs/project-map/lessons.md` |
| Kiểm giao diện (bắt buộc) | `docs/QA.md` |
| Khảo sát gốc | `docs/research/` |
