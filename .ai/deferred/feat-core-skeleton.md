# Việc để sau — nhánh feat/core-skeleton (WP-01)

- [ ] Job CI `supply-chain` (ENGINEERING §7): dựng image, `trivy fs`/`trivy image`, SBOM CycloneDX, script so `THIRD_PARTY_NOTICES.md` với lockfile/go.sum → WP-08 (chưa có image để dựng).
- [ ] Quét hằng ngày lỗi thì tự mở issue + thêm `pnpm audit` vào lịch hằng ngày (ENGINEERING §7, SECURITY.md) → WP-31.
- [ ] Bảo vệ nhánh `main` không bật được trên GitHub Free với repo riêng tư (API trả 403); giữ quy ước "không push main" (TEAM_PLAN §5). Nâng gói GitHub là quyết định chi phí của kien.
