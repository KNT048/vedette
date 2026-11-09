# Cập nhật — thiết kế từ ngày đầu

kien, 2026-11-06: sản phẩm bảo mật phải cập nhật thường xuyên; chỗ cho việc đó phải có trong thiết kế ban đầu.

> **D-36 (kien, 2026-11-09):** GitHub chỉ còn phát hành **bản cập nhật phần mềm đã ký**. Kênh "1. Dữ liệu" bên dưới không còn đi qua GitHub/builder: hộp tự kéo từng feed từ nguồn (`docs/DATA_PIPELINE.md` §0). Kênh "2. Gói nội dung" (skill, gói khuyến nghị đã xác nhận, parser log…) nay **đóng gói cùng bản cập nhật phần mềm**. Rollout theo lô (§2) áp dụng cho bản cập nhật phần mềm. Bài kiểm tra an toàn feed (§5) chạy trên hộp trước khi dùng dữ liệu.

> **D-55 (kien, 2026-11-09):** hộp là appliance chạy container. Kênh "3. Phần mềm" nay là **image OCI ký bằng cosign** (digest ghim, phát hành theo lô, hoàn tác bằng tag cũ), **thay cơ chế A/B slot cho binary**; **cập nhật hệ điều hành** của hộp đi qua `vedette-host` (D-53, thay `vedette-updater`). Chi tiết vận hành: `docs/DEPLOYMENT.md` §9. Kiểu cài *Chỉ container* không có `vedette-host`: không tự cập nhật, GUI báo bản mới và hiện lệnh.

## 0. Cập nhật theo D-55: phần mềm và hệ điều hành

| Lớp | Cái được cập nhật | Cơ chế | Rollback |
|---|---|---|---|
| Phần mềm Vedette | image `core`, `sensor`, `honeypot`, `scan` (+ digest của `greenbone`) | `vedette-host` lấy `release.json` (ký minisign, xác minh offline được) liệt kê digest từng image, kênh, % rollout, phiên bản host tối thiểu, `revoked[]`; kéo theo digest; **cosign bắt buộc** (policy trên host, fail-closed); sao lưu DB; thay container theo thứ tự `core` → `sensor`/`scan` → `honeypot` → `greenbone`; health gate | quay về digest/tag trước (giữ 1 đời); migration chỉ expand để bản liền trước chạy được |
| Hệ điều hành | gói apt, kernel, reboot (D-53, S-CORE-7) | `vedette-host` chạy danh sách lệnh apt cố định, lịch theo cửa sổ bảo trì | sao lưu DB trước, health gate sau; nâng bản phát hành OS chỉ hướng dẫn |
| `vedette-host` | chính nó | gói/binary ký, cài bởi `vedette-host` cũ hoặc `install.sh`; chi tiết trong `specs/host-api.md` | giữ bản trước (câu hỏi mở) |

Cohort, `beta` → `stable` ≥ 7 ngày, danh sách thu hồi, bundle offline: giữ nguyên như §1–§3. Cohort chỉ chặn cập nhật **tự động** (người dùng bấm tay: xem `DEPLOYMENT.md` câu hỏi B6).

Còn lại của tài liệu này mô tả kênh dữ liệu/nội dung/advisory và phát hành CI; chỗ nào nhắc "binary", "slot A/B", "minisign + cosign cho binary" thì đọc theo bảng trên.

## 1. Bốn kênh

| Kênh | Nội dung | Chu kỳ | Cơ chế | Rollback |
|---|---|---|---|---|
| **1. Dữ liệu** | `feeds/*` (vuln, hot, ioc, slug) | 30–60 phút | `index.json` ký; ETag; delta | giữ bản trước; `revoked[]` rút file xấu |
| **2. Gói nội dung** | skill, mitigation pack, nuclei subset, recog DB, parser log, rule pack, template câu tiếng Việt | ngày | `content-packs/<name>-<semver>.tar.zst` ký; manifest liệt kê file + sha256 | N-1 giữ; chuyển về 1 bấm |
| **3. Phần mềm** (D-55) | image OCI `core`/`sensor`/`honeypot`/`scan` (SPA nhúng trong `core`); ~~binary + A/B slot~~ | theo phát hành; kênh `stable`/`beta` | `release.json` ký minisign; kéo image theo digest, cosign bắt buộc; thay container, health gate; fail → về digest trước | tag/digest cũ (giữ 1 đời); nút Rollback; xem §0 |
| **4. Advisory sản phẩm** | lỗ hổng của chính Vedette, dependency | khi có | `security.json` trong index; UI banner; mail/Telegram cho admin | — |

Mọi kênh: chữ ký bắt buộc, khoá công khai trong binary (2 khoá: `builder-vn`, `builder-gh`, + khoá phát hành phần mềm riêng), **danh sách thu hồi** trong `index.json`.

## 2. Rollout theo lô

- Mỗi hộp có `cohort = hash(install_id) mod 100`. `index.json` ghi `rollout: {content-pack X: 10}` → chỉ hộp cohort <10 nhận; tăng dần 10 → 50 → 100 sau 24 giờ không có báo lỗi (hit ẩn danh opt-in hoặc issue). Phần mềm: `beta` trước `stable` ≥ 7 ngày.
- Không bao giờ bật toàn cục một thay đổi dữ liệu/rule (bài học Cloudflare 2025-12-05).

## 3. Trang Cập nhật (S-CORE-2)

Hiện: phiên bản phần mềm/dữ liệu/gói nội dung, "cập nhật lúc", kênh, lịch sử 20 lần gần nhất, trạng thái chữ ký, nút kiểm tra ngay, nút rollback từng kênh, chế độ tự động/tay, **bundle offline** (`vedette bundle export/import` cho mạng cách ly), tình trạng advisory sản phẩm.

## 4. Quy trình phát hành (CI, GitHub Actions)

1. Test (Go, FE), lint, `govulncheck`, `trivy fs`, licence check (không GPL/AGPL vào lõi).
2. Build reproducible (`-trimpath`, `CGO_ENABLED=0`), đa kiến trúc (amd64/arm64), **image OCI** cho từng container (D-55) và gói `.deb` cho `vedette-host`.
3. SBOM CycloneDX (syft); quét SBOM (grype).
4. Ký: **cosign** cho từng image (hộp xác minh khi kéo, D-55); **minisign** cho `release.json` và gói `vedette-host` (xác minh offline). Cosign theo khoá hay keyless: câu hỏi mở A3 trong `ARCHITECTURE.md`.
5. Changelog từ commit; GitHub Release; `index.json` cập nhật qua builder; `beta` trước.
6. Tag do kien tạo tay (AI không tạo tag).

## 5. Lỗ hổng của chính sản phẩm

- `SECURITY.md`: kênh báo riêng, SLA 2/14/30 ngày.
- Dependency: Renovate hàng tuần, ghim phiên bản; CVE nghiêm trọng trong dependency → phát hành vá trong 7 ngày.
- Dữ liệu feed độc hại (IOC "chặn Google", template Nuclei nguy hiểm): builder có **bài kiểm tra an toàn** trước khi ký — whitelist top-10k domain không được xuất hiện trong block list; nuclei subset chỉ tag an toàn; parser log chạy fuzz 60 giây.
- Hộp giữ log cập nhật (ai, khi nào, sha256) trong `core_audit`.

## 6. Khi hạ tầng free thay đổi

Mọi URL trong một file `channels.json` (ký) → đổi host = đổi một file. Mirror thứ hai (Releases ↔ R2) luôn tồn tại; hộp thử lần lượt.
