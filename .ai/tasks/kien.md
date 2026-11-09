# Việc của Kiên — đọc cùng docs/TEAM_PLAN.md

Cập nhật: 2026-11-09 (phiên AI lead). Sở hữu: core, host, đóng gói/phát hành, inventory, sensor-passive, sensor-active, response, honeypot, rà bảo mật.
File này là **file handoff duy nhất** của phiên AI làm việc cho Kiên: sau compact/restart đọc lại trước khi làm tiếp.

## Trạng thái WP (thứ tự TEAM_PLAN §3)
| WP | Nhánh / worktree | Trạng thái |
|---|---|---|
| WP-01 khung Go + CI | `feat/core-skeleton` → PR #7 | chờ CI rồi tự merge; xong thì đóng PR #6 của Emily (PR đó tự ghi "WP-01 vào trước thì đóng") |
| WP-02 sinh code OpenAPI | `feat/core-codegen` (`../vedette-wt/core-codegen`) | chọn **ogen v1.24.0** (spike: oapi-codegen v2.8.2 nhỏ hơn nhưng không validate body, `oneOf` mờ); chuẩn hoá spec 3.1 bằng bước Go lúc sinh, không đổi hợp đồng; D-60 |
| WP-03 store/secrets/audit/exec | `feat/core-store` (`../vedette-wt/core-store`) | đang làm (người làm Sonnet) |
| WP-04 auth/registry/scheduler | — | chờ WP-03 |
| WP-06 giao diện khớp hợp đồng | `fix/gui-contract-align` (`../vedette-wt/gui-contract-align`) | đang làm; PR nhãn `contract`, cần @kiennt049 duyệt |
| WP-05 môi trường dev | — | sau WP-02 |

## Số quyết định đã cấp (tránh trùng giữa các nhánh song song)
D-59 = WP-01 (khung Go, công cụ ghim). D-60 = WP-02 (ogen). Số tiếp theo cấp từ D-61.

## Bẫy kỹ thuật đã gặp
- Go cục bộ 1.26.2 có lỗ hổng stdlib → `go.mod` ghim `go 1.26.10` (go tự tải toolchain).
- golangci-lint mặc định chỉ báo **một lỗi mỗi dòng**: canary lint phải mỗi vi phạm một dòng.
- Máy chạy nhiều agent song song (load ~50): vitest trong `make verify-web` timeout hàng loạt (`findBy…`); chạy riêng file thì xanh. Đừng kết luận đỏ khi máy đang tải; CI là thẩm quyền.
- GitHub Free + repo riêng tư: không bật được branch protection (API 403) → "không push main" là quy ước.
- Công cụ dev ghim trong `tools/go.mod` (`go tool -modfile=tools/go.mod …`); ogen là `tool` trong `go.mod` chính (CLI và runtime cùng một phiên bản).

## Ghi chú cho phiên AI
- Mỗi phiên một worktree + một nhánh + một WP; không sửa module của Emily.
- Đổi hợp đồng → PR nhãn `contract`, gán @kiennt049 duyệt; không merge khi chưa duyệt.
