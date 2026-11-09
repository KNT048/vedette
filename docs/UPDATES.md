# Cập nhật — thiết kế từ ngày đầu

kien, 2026-11-06: sản phẩm bảo mật phải cập nhật thường xuyên; chỗ cho việc đó phải có trong thiết kế ban đầu.

> **D-36 (kien, 2026-11-09):** GitHub chỉ còn phát hành **bản cập nhật phần mềm đã ký**. Kênh "1. Dữ liệu" bên dưới không còn đi qua GitHub/builder: hộp tự kéo từng feed từ nguồn (`docs/DATA_PIPELINE.md` §0). Kênh "2. Gói nội dung" (skill, gói khuyến nghị đã xác nhận, parser log…) nay **đóng gói cùng bản cập nhật phần mềm**. Rollout theo lô (§2) áp dụng cho bản cập nhật phần mềm. Bài kiểm tra an toàn feed (§5) chạy trên hộp trước khi dùng dữ liệu.

## 1. Bốn kênh

| Kênh | Nội dung | Chu kỳ | Cơ chế | Rollback |
|---|---|---|---|---|
| **1. Dữ liệu** | `feeds/*` (vuln, hot, ioc, slug) | 30–60 phút | `index.json` ký; ETag; delta | giữ bản trước; `revoked[]` rút file xấu |
| **2. Gói nội dung** | skill, mitigation pack, nuclei subset, recog DB, parser log, rule pack, template câu tiếng Việt | ngày | `content-packs/<name>-<semver>.tar.zst` ký; manifest liệt kê file + sha256 | N-1 giữ; chuyển về 1 bấm |
| **3. Phần mềm** | binary + SPA nhúng; `.deb`/`.apk`/image | theo phát hành; kênh `stable`/`beta` | tải binary ký (minisign + cosign), xác minh, cài vào slot B, đổi symlink, restart, health check; fail → về A | A/B slot; `vedette rollback` |
| **4. Advisory sản phẩm** | lỗ hổng của chính Vedette, dependency | khi có | `security.json` trong index; UI banner; mail/Telegram cho admin | — |

Mọi kênh: chữ ký bắt buộc, khoá công khai trong binary (2 khoá: `builder-vn`, `builder-gh`, + khoá phát hành phần mềm riêng), **danh sách thu hồi** trong `index.json`.

## 2. Rollout theo lô

- Mỗi hộp có `cohort = hash(install_id) mod 100`. `index.json` ghi `rollout: {content-pack X: 10}` → chỉ hộp cohort <10 nhận; tăng dần 10 → 50 → 100 sau 24 giờ không có báo lỗi (hit ẩn danh opt-in hoặc issue). Phần mềm: `beta` trước `stable` ≥ 7 ngày.
- Không bao giờ bật toàn cục một thay đổi dữ liệu/rule (bài học Cloudflare 2025-12-05).

## 3. Trang Cập nhật (S-CORE-2)

Hiện: phiên bản phần mềm/dữ liệu/gói nội dung, "cập nhật lúc", kênh, lịch sử 20 lần gần nhất, trạng thái chữ ký, nút kiểm tra ngay, nút rollback từng kênh, chế độ tự động/tay, **bundle offline** (`vedette bundle export/import` cho mạng cách ly), tình trạng advisory sản phẩm.

## 4. Quy trình phát hành (CI, GitHub Actions)

1. Test (Go, FE), lint, `govulncheck`, `trivy fs`, licence check (không GPL/AGPL vào lõi).
2. Build reproducible (`-trimpath`, `CGO_ENABLED=0`), đa kiến trúc (amd64/arm64), `.deb`/`.apk`, image.
3. SBOM CycloneDX (syft); quét SBOM (grype).
4. Ký: cosign keyless (Sigstore) **và** minisign (hộp xác minh offline bằng minisign; cosign cho người).
5. Changelog từ commit; GitHub Release; `index.json` cập nhật qua builder; `beta` trước.
6. Tag do kien tạo tay (AI không tạo tag).

## 5. Lỗ hổng của chính sản phẩm

- `SECURITY.md`: kênh báo riêng, SLA 2/14/30 ngày.
- Dependency: Renovate hàng tuần, ghim phiên bản; CVE nghiêm trọng trong dependency → phát hành vá trong 7 ngày.
- Dữ liệu feed độc hại (IOC "chặn Google", template Nuclei nguy hiểm): builder có **bài kiểm tra an toàn** trước khi ký — whitelist top-10k domain không được xuất hiện trong block list; nuclei subset chỉ tag an toàn; parser log chạy fuzz 60 giây.
- Hộp giữ log cập nhật (ai, khi nào, sha256) trong `core_audit`.

## 6. Khi hạ tầng free thay đổi

Mọi URL trong một file `channels.json` (ký) → đổi host = đổi một file. Mirror thứ hai (Releases ↔ R2) luôn tồn tại; hộp thử lần lượt.
