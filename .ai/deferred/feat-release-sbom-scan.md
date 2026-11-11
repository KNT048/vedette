# Việc để sau — nhánh feat/release-sbom-scan (WP-08i)

- [ ] 2026-11-11 — WP-08k: gắn các SBOM CycloneDX trong `dist/sbom/` (mỗi image mỗi kiến trúc, `make sbom RELEASE=1` giữ lại) vào image đã ký bằng `cosign attest --type cyclonedx`, và để `make vuln-scan` chạy trước bước ký — vì sao để sau: ký và đẩy là việc của 08k, cần khoá — ở đâu: Makefile `sbom`, `docs/UPDATES.md` §4 bước 4
