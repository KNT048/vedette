# Pipeline dữ liệu — hộp tự lấy feed (D-36)

> **Mô hình hiện hành (kien, 2026-11-09, D-36):** mỗi hộp **tự kéo và tự phân tích** feed trực tiếp từ nguồn (CISA KEV, FIRST EPSS, NVD, khuyến cáo hãng, feed IOC, feed tuỳ chỉnh của khách — D-37). **Không còn builder trung tâm, không phân phối dữ liệu qua GitHub/Cloudflare.** GitHub chỉ còn **một việc: phát hành bản cập nhật phần mềm đã ký** (`docs/UPDATES.md`); gói khuyến nghị đã xác nhận (§5b) đi kèm bản cập nhật đó. Mục 1, 4, 5 bên dưới là mô hình cũ (2026-11-06), giữ để tham khảo lịch sử; mục 2 (nguồn) và 3 (chuẩn hoá, chấm điểm) nay chạy **trên hộp**.

## 0. Luồng hiện hành

```
nguồn feed (cisa.gov, api.first.org, services.nvd.nist.gov, RSS/advisory hãng, abuse.ch…, feed tuỳ chỉnh)
     │  hộp kéo theo lịch từng feed (ETag/If-Modified-Since, giới hạn kích thước + thời gian)
     ▼
parser trên hộp (fail-closed; ánh xạ trường/regex do khách chỉnh cho feed riêng — D-37)
     ▼
chuẩn hoá → lọc trùng → chấm điểm (mục 3) → feeds_* → khớp kho thiết bị → phát hiện/cảnh báo
```

- Mỗi nguồn feed là một luồng dữ liệu ra (chỉ là yêu cầu tải về, không gửi dữ liệu khách) → liệt kê trong `PRIVACY.md` và Cài đặt → Quyền riêng tư; feed tuỳ chỉnh do khách thêm hiện tên host trong cùng danh sách.
- Nguồn bị chặn theo địa lý/giới hạn tốc độ: hộp lùi thời gian và hiện lỗi ở Cài đặt → Feed; người dùng sửa địa chỉ sang mirror (D-37).

## Mô hình cũ (2026-11-06, đã thay bằng D-36)

Quyết định cũ: một VM builder (đặt tại Việt Nam) chỉ để **chuẩn bị** dữ liệu; lưu lên GitHub; phân phối qua Cloudflare; mọi thứ tĩnh; không state theo khách.

## 1. Luồng

```
feeds nguồn ──► vedette-builder (Go, VM builder; GitHub Actions dự phòng)
                 │ kéo (ETag/git pull) → chuẩn hoá → lọc trùng → chấm điểm → ký
                 ▼
            repo dữ liệu (nhánh orphan `data`, squash hàng tháng)
            Releases (snapshot ngày, file lớn)  ·  R2 (file >25 MiB)
                 ▼
            Cloudflare Pages (site tĩnh + file nhỏ) + custom domain
                 ▼
            hộp khách: GET index.json (ETag, 30–60 phút) → tải phần đổi → xác minh chữ ký → ghi feeds_*
```

Giới hạn free đo 2026-11-06: GitHub Actions không giới hạn cho repo public; Releases không giới hạn dung lượng/băng thông; repo nên <1 GB, file >100 MiB chặn; Pages 500 build/tháng, 25 MiB/file, 20k file; R2 10 GB, egress free.

## 2. Nguồn

### 2a. Lỗ hổng đang bị khai thác (trung tâm gộp, được phân phối lại)

| Nguồn | Cách kéo | Chu kỳ | Giấy phép | Tín hiệu |
|---|---|---|---|---|
| CISA KEV | JSON, ETag | 30 phút | CC0 | exploited, ransomware flag, dueDate |
| cisagov/vulnrichment | git | giờ | CC0 | SSVC, CWE, CPE bổ sung |
| CVE.org cvelistV5 | git pull | giờ | public | bản ghi nhanh nhất, `affected[]` |
| FIRST EPSS | CSV ngày | ngày | ghi nguồn | epss, Δ7 ngày |
| CIRCL Vulnerability-Lookup | API sightings + dump | giờ | AGPL (dữ liệu dùng qua API) | sightings exploited/poc/patched (Shadowserver) |
| nuclei-templates | git log | giờ | MIT | template mới = có check; subset `kev,vkev` vào content pack |
| GHSA, OSV | git/API | giờ | CC-BY / Apache | PURL cho gói |
| NVD 2.0 | API key | 2 giờ | free | CPE/CVSS bổ sung (chậm) |
| PSIRT: MSRC CSAF, Cisco openVuln, Fortinet RSS, Synology RSS, PAN CSAF, QNAP/Ivanti RSS | poll | giờ | free | "exploited in the wild" sớm hơn KEV |
| NCSC VN (alert.khonggianmang.vn), chongluadao | HTML, **cần IP VN** | tuần/ngày | — | ngữ cảnh VN |
| VulnCheck KEV Community | API key của **dự án** | giờ | ⚠ redistribution chưa xác nhận → tạm để hộp tự kéo bằng key khách | sớm hơn CISA, canary, PoC |

### 2b. IOC (trung tâm gộp, được phân phối lại)

Spamhaus DROP (⚠ hỏi về nhúng), ET Open block/compromised (BSD), IPsum level≥3 (Unlicense), hagezi TIF mini/medium (GPL-3, kèm giấy phép), Tor exit, Cymru bogons, CINS/Blocklist.de/GreenSnow (chiều vào), abuse.ch SSLBL/Feodo (CC0), Phishing.Database (MIT), whitelist Umbrella top-1M + Majestic + dải cloud AWS/Google/Azure/Cloudflare + dải ISP VN (APNIC delegated).

### 2c. Feed BYOK (hộp tự kéo bằng key khách, không qua trung tâm)

VulnCheck Community, AbuseIPDB, VirusTotal, GreyNoise, Shodan, OTX, urlscan, OpenPhish, Censys, abuse.ch ThreatFox/URLhaus (Auth-Key). Mỗi nguồn: ô key, nút thử, giới hạn request, tắt mặc định.

## 3. Chuẩn hoá và chấm điểm

- Khoá: CVE → (vendor, product, version_ranges) từ CNA `affected[]` + NVD CPE + PURL; bảng `vendor_product_slug` ánh xạ CPE vendor ↔ tên PSIRT ↔ tag Nuclei ↔ tên thương mại tiếng Việt (ví dụ "Synology DSM").
- `hot_score(vendor,product,7d) = w1·KEV mới + w2·VulnCheck/canary + w3·max ΔEPSS + w4·commit Nuclei + w5·sightings exploited + w6·PSIRT nói exploited + w7·hit từ fleet (opt-in)`, nhân hệ số phơi nhiễm VN (tồn kho fleet ẩn danh, nếu có).
- IOC: `score = Σ trọng_số_nguồn × e^(−tuổi/τ)`; τ 7 ngày scanner, 30 ngày C2/phish, ∞ DROP; `block` khi ≥2 nguồn độc lập hoặc 1 nguồn cấp DROP/CC0; `alert` khi 1 nguồn; trừ whitelist **theo domain** (không theo IP CDN); không bao giờ /24.
- Câu tiếng Việt cho S-FEED-2 sinh từ template (không cần AI): "`<Sản phẩm>` `<phiên bản>` đang bị `<nhóm/ransomware>` khai thác (KEV `<ngày>`). Nếu dùng: `<hành động ngắn>`."

## 4. Định dạng phân phối

```
index.json            { generated_at, builder_version, files: [{path, sha256, size, kind, since}], revoked: [...], signature }
feeds/vulns.json      bản ghi feeds_vuln (nén zstd, bản delta theo ngày)
feeds/hot.json        bảng nóng 7 ngày + câu tiếng Việt
feeds/ioc/block-ip.txt (≤50k), alert-ip.txt, domains-mini.txt, domains-medium.txt, ja3.txt
feeds/slug.json       vendor_product_slug
content-packs/<name>-<ver>.tar.zst   skill, mitigation pack, nuclei subset, recog DB, parser log, rule pack
```

- Ký **minisign** (khoá riêng chỉ trên VM builder, dự phòng YubiKey); khoá công khai trong mã nguồn Vedette; `revoked[]` để rút bundle xấu.
- Hộp: `If-None-Match`; tải file có sha256 đổi; xác minh chữ ký trước khi ghi; giữ bản trước để rollback.

## 5. Builder

- `cmd/vedette-builder` (Go, cùng repo mã): `fetch` → `normalize` → `score` → `render` → `sign` → `publish`. Mỗi bước idempotent, ghi `build.log` + metrics vào `status.json` (công khai: lần chạy cuối, nguồn nào lỗi).
- Chạy trên VM builder (cron 30 phút, IP VN cho nguồn geo-fence) **và** GitHub Actions (cron 60 phút, publish chỉ khi VM trễ >3 giờ) — hai nơi cùng khoá công khai, khoá riêng khác nhau (`builder-vn`, `builder-gh`), cả hai trong danh sách tin cậy của hộp.
- Web công khai = Pages tĩnh: bảng nóng, tra CVE/IP/domain, trạng thái pipeline. Không server, không tài khoản.

## 5b. Khuyến nghị giảm thiểu: dự án soạn bằng AI, người duy trì xác nhận qua GitHub (D-21, S-MIT-4) — vẫn áp dụng; từ D-36 gói đã xác nhận đi kèm **bản cập nhật phần mềm đã ký**, không qua builder

```
KEV mới (hot_score cao, chưa có gói) ─► vedette-author draft <CVE>   (CLI, key AI của dự án, skill mitigation-config)
   │  gom KEV + cvelist + advisory hãng (dữ liệu công khai) → content/mitigation/<CVE>.yaml  status: draft
   ▼
người duy trì sửa, đặt confirmed_by / confirmed_at, status: confirmed → PR → CODEOWNERS duyệt → merge
   ▼
release: chỉ nhận status: confirmed → đóng vào bản cập nhật đã ký (GitHub Releases) → hộp khách (D-36)
```

- Gói ghi `drafted_with` (model), `confirmed_by`, `confirmed_at`, `sources[]`; UI hiện "Vedette đã xác nhận, soạn với AI".
- Hộp: CVE không có gói đã xác nhận → "Chưa có khuyến nghị đã xác nhận" + thông tin gốc + "Hỏi AI của tôi" (skill `mitigation-config` chạy bằng key của khách, nhãn "AI tạo").
- Không có dữ liệu khách nào trong luồng này; `PRIVACY.md` không đổi.
- `ponytail: content/ trong repo mã + CODEOWNERS; nâng cấp: tách repo vedette-content khi PR nội dung nhiều.`

## 6. Quyết định (kien, 2026-11-06)

1. **Không** host instance Vedette dùng chung (D-15). Trung tâm chỉ là dữ liệu tĩnh; khách tự host hoặc thuê triển khai instance riêng. Xem lại khi dự án phát triển tốt.
2. **Tín hiệu fleet ẩn danh: bật mặc định** (D-16), tắt được một bấm. Hộp gửi mỗi giờ về `telemetry.vedette.<domain>` (service nhỏ của dự án, không qua GitHub) một gói **không có tên khách, không IP nội bộ, không log thô**:
   ```json
   {"install_id": "<sha256 ngẫu nhiên lúc cài>", "country": "VN", "version": "1.2.0",
    "hits": [{"kind": "honeypot/smb", "count": 1}, {"kind": "ioc/ip", "count": 3}, {"kind": "suricata/CVE-2026-109618", "count": 7}],
    "inventory_counts": {"synology:dsm:7.1": 12, "fortinet:fortios:7.2": 1}}
   ```
   Dùng để: cột "đang bị đánh ở VN" trên bảng nóng; trọng số `hot_score` theo thứ SMB VN thực dùng; phát hiện rollout dữ liệu lỗi theo cohort. Payload nguyên văn hiện trong Cài đặt → Chia sẻ tín hiệu; README và `PRIVACY.md` nêu rõ. Trung tâm giữ **tổng hợp**, xoá bản ghi thô sau 30 ngày.
3. Spamhaus DROP/CINS/ThreatView: trung tâm hay hộp tự kéo — chờ trả lời Spamhaus (`.ai/deferred`).
