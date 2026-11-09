# Việc để sau — nhánh feat/core-skeleton (WP-01)

- [ ] Kiểm chuỗi cung ứng trên máy (ENGINEERING §7, D-61): dựng image, `trivy fs`/`trivy image`, SBOM CycloneDX, script so `THIRD_PARTY_NOTICES.md` với lockfile/go.sum → WP-08 (chưa có image để dựng).
- [ ] Bảo vệ nhánh `main` không bật được trên GitHub Free với repo riêng tư (API trả 403); giữ quy ước "không push main" (TEAM_PLAN §5). Nâng gói GitHub là quyết định chi phí của kien.
- [ ] E2E trên `main` đỏ sẵn (lượt chạy cuối trước khi bỏ Actions: 23 kịch bản × desktop/mobile — ai, core, findings, honeypot, inventory, reports, scan, journey) → sửa ở `fix/e2e-baseline`; tới lúc đó PR chạm `web/` chạy các spec bị ảnh hưởng và ghi rõ trong PR.
