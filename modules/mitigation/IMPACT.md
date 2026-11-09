# Mitigation — Change Impact Map

## Modifying: `mitigation.Provider.Guidance(ctx, findings.Row)` (phần "What to do" của `GET /findings/{id}`)
- **findings** (`FindingHandlers.SetGuidance`; bị bỏ qua khi mitigation tắt) (gộp vào `FindingDetail`), SPA trang finding. Đổi `FindingDetail.pack|compromise|recheck|ai|applied` phải sửa `findings/contract.ts` (nguồn OpenAPI).

## Modifying: các interface `Verifier`, `AI`, `Vendors` (mitigation/ports.go)
- **core/updates** (cài `Verifier`: chữ ký của bản cập nhật; thiếu = từ chối mọi gói), **ai** (cài `AI`: `Available`, `Run` qua RunJob), **inventory** (cài `Vendors.HasFirewallVendor`). Đổi chữ ký = đổi chỗ nối trong `cmd/vedette`.

## Modifying: nạp gói (`Loader.Install`) và định dạng `MitigationPack`
- **tooling `vedette-author`** (S-MIT-4) và builder phát hành: schema chung; đổi trường = đổi cả công cụ lẫn bộ nạp. **core/updates**: gói đi cùng bản cập nhật ký.

## Modifying: gọi `ai.Run(skill, input)` (`explain`, `mitigation-config`)
- **ai** (nhóm B): đổi tên skill/schema đầu ra làm `ai_available` sai và kết quả mất nhãn.

## Modifying: `POST /findings/{id}/applied`
- SPA (mục "Đã áp dụng"). Đổi bộ item (`ApplyItem`) = đổi gói và `mit_applied`.

## Disabling this module
- Mất panel "What to do" ở trang finding và Devices; nút "Ask my AI" cho finding biến mất.
- `findings`, `notify`, `scan`, `response`, `reports` không bị ảnh hưởng (không phụ thuộc `mitigation`).
- Gói đã nạp, mục "Đã áp dụng", kết quả AI giữ trong `mit_*`.
