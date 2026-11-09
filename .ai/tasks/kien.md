# Việc của Kiên — đọc cùng docs/TEAM_PLAN.md

Cập nhật: 2026-11-09 (phiên AI lead). Sở hữu: core, host, đóng gói/phát hành, inventory, sensor-passive, sensor-active, response, honeypot, rà bảo mật.
File này là **file handoff duy nhất** của phiên AI làm việc cho Kiên: sau compact/restart đọc lại trước khi làm tiếp.

## Trạng thái WP (thứ tự TEAM_PLAN §3)
| WP | Nhánh / worktree | Trạng thái |
|---|---|---|
| WP-01 khung Go + công cụ | `feat/core-skeleton` → PR #7 | `make verify` trên máy rồi tự merge (không còn CI, D-61). PR #6 của Emily đã merge, đã gộp vào #7 |
| WP-02 sinh code OpenAPI | `feat/core-codegen` (`../vedette-wt/core-codegen`) | chọn **ogen v1.24.0** (spike: oapi-codegen v2.8.2 nhỏ hơn nhưng không validate body, `oneOf` mờ); chuẩn hoá spec 3.1 bằng bước Go lúc sinh, không đổi hợp đồng; D-60 |
| WP-03 store/secrets/audit/exec | `feat/core-store` (`../vedette-wt/core-store`), xếp chồng trên WP-02 | xong + đã sửa 12 phát hiện rà bảo mật độc lập; chờ #7 → rebase → PR WP-02 rồi WP-03 |
| WP-04a server/registry/scheduler | `feat/core-server` (`../vedette-wt/core-server`), xếp chồng trên WP-03 | đang làm (Sonnet); đặc tả: scratchpad `wp04a-brief.md` |
| e2e gốc | `fix/e2e-baseline` (`../vedette-wt/e2e-baseline`) | đang làm: 23 kịch bản × 2 đỏ sẵn trên main (chủ yếu do "This box" thành thiết bị đầu tiên) |
| WP-04b auth (phiên, CSRF, argon2id, TOTP, mã email, người dùng, tài khoản, audit API) | — | sau WP-04a |
| WP-06 giao diện khớp hợp đồng | `fix/gui-contract-align` (`../vedette-wt/gui-contract-align`) | xong phần làm (16 mục + D-57 hash/scc_/weekday); đang kiểm độc lập QA; sau đó PR nhãn `contract`, cần @kiennt049 duyệt |
| WP-05 môi trường dev | — | sau WP-02 |

## Số quyết định đã cấp (tránh trùng giữa các nhánh song song)
D-59 = WP-01 (khung Go, công cụ ghim). D-60 = WP-02 (ogen). D-61 = không GitHub Actions (đã thay bởi D-63). D-62 = `make check`. D-63 = repo KNT048 public + CI lại. Số tiếp theo cấp từ D-64.

## Bẫy kỹ thuật đã gặp
- Repo chuyển sang **`KNT048/vedette`, public** (D-63): CI GitHub Actions miễn phí chạy bộ đầy đủ; trên máy chỉ `make check` (D-62). Remote local đã đổi sang `https://github.com/KNT048/vedette.git`.
- Máy quá tải (load 100–200) do agent để lại Playwright mồ côi (shell hết giờ, runner vẫn chạy): trước khi giao việc nặng kiểm `pgrep -f playwright/test/cli.js`; tối đa 2 việc nặng song song.
- Chuỗi hash: một công thức D-57 (14) cho cả ba chuỗi, khoá sắp theo code point, NULL giữ `null`; vector chung `modules/core/testdata/chain_vectors.json`.
- Go cục bộ 1.26.2 có lỗ hổng stdlib → `go.mod` ghim `go 1.26.10` (go tự tải toolchain).
- golangci-lint mặc định chỉ báo **một lỗi mỗi dòng**: canary lint phải mỗi vi phạm một dòng.
- Máy chạy nhiều agent song song (load ~50): vitest trong `make verify-web` timeout hàng loạt (`findBy…`); chạy riêng file thì xanh. Đừng kết luận đỏ khi máy đang tải: chạy lại các file đỏ lúc máy rảnh (không còn CI làm thẩm quyền).
- GitHub Free + repo riêng tư: không bật được branch protection (API 403) → "không push main" là quy ước.
- Công cụ dev ghim trong `tools/go.mod` (`go tool -modfile=tools/go.mod …`); ogen là `tool` trong `go.mod` chính (CLI và runtime cùng một phiên bản).

## Ghi chú cho phiên AI
- Mỗi phiên một worktree + một nhánh + một WP; không sửa module của Emily.
- Đổi hợp đồng → PR nhãn `contract`, gán @kiennt049 duyệt; không merge khi chưa duyệt.
