# Feeds — Change Impact Map

## Modifying: `feeds.Store` — `VulnByCVE(cve)`, `VulnsByProductKey(key)`, `HasTemplate(cve)`, `IOCLookup(value)`, `KevPairs()`
- **inventory** (`catalog`, khớp sản phẩm↔KEV theo khoá `vendorproject|product` chữ thường): đổi cách chuẩn hoá khoá = mọi khớp "Do you have it?" lệch.
- **mitigation** (`KevInfo` trong `FindingRow`), **scan** (`has_template`), **mcp-server** (`lookup_cve`, `lookup_ioc`), **ai** (slot `cve.panels`), **reports**.
- **honeypot / logs / response** (nhóm B): `IOCLookup` quyết định cảnh báo và chặn; đổi `verdict` ảnh hưởng quy tắc phản ứng.

## Modifying: `feeds.Fetch(ctx, feedID)` và sự kiện `feeds.vuln.new_kev`
- **inventory** (khớp lại), **scan** (quét lại ≤ 60 phút nếu `has_template`), **mitigation** (kiểm có gói chưa). Đổi tên/ trường sự kiện = âm thầm mất tự quét lại.

## Modifying: `feeds.ParseFeed(data []byte, kind Kind, p Parser) (Result, error)` và giới hạn (5 000 000 byte, 50 000 dòng)
- **feeds** (kéo thật, `parse-test`), **SPA** (`ParserEditor`, `parsers.ts` phải cho kết quả giống Go: test chéo trên cùng mẫu `modules/feeds/testdata/samples` và `testdata/golden`).
- Lỗi: `ErrTooLarge` (→ 413 `too_large`), `ErrBadConfig`, `ErrBadSample` (→ 400); câu hiển thị cho người dùng nằm ở `(*feeds.Error).Detail`. `Result.Records` chứa mọi bản ghi nhận; `Result.Preview()` cắt 20 đầu cho `parse-test`. `CheckParser(kind, p)` kiểm cấu hình trước khi lưu.
- Đổi cách chuẩn hoá (IP qua `netip`, domain/hash chữ thường, ngày UTC) = đổi khoá khớp IOC của **honeypot/logs/response**.

## Modifying: `ParseKEV`, `ParseEPSS`, `ParseNucleiCVEs` (parser dựng sẵn)
- **feeds** job kéo (WP-20) ghi `feeds_vuln` từ `KEVCatalog.Vulns`, `has_template` từ `NucleiCVEs.CVEs`, `epss` từ `EPSSData.Scores` (`keep` lọc theo CVE đã có, DATA_MODEL câu hỏi mở 8). Đổi trường `Vuln` = đổi cột `feeds_vuln`; `Vuln.Key()` = `ProductKey` là khoá khớp của **inventory**.
- EPSS giải nén có trần `MaxEPSSDecompressed` (64 MiB) và `MaxEPSSRows`; không áp trần 50 000 dòng của INV-2.

## Modifying: `Fetcher.Fetch(ctx, Request)` (một GET tới đúng URL)
- **feeds** job kéo và `POST /feeds/sources/{id}/fetch`. Chuyển hướng: chỉ cùng host (`ErrRedirect`), không hạ https→http, tối đa 5 bước. Đổi chính sách này = đổi host nào hộp có thể liên lạc (INV-1, INV-13, `PRIVACY.md`).
- Header gửi đi cố định: `User-Agent: Vedette/<version>`, `Accept`, điều kiện `If-None-Match`/`If-Modified-Since`, xác thực của feed. Thêm header = đổi luồng dữ liệu ra (legal.md).

## Modifying: `State.NextAttempt/Due/Record`, `IsStale`, `Backoff` (lịch kéo, INV-8/9) và `Judge`, `IOCKey` (IOC verdict, INV-12)
- **feeds** job (lịch, trạng thái lỗi ở Settings → Feeds); **honeypot/logs/response** đọc `verdict`: đổi ngưỡng block/alert = đổi quy tắc phản ứng.

## Modifying: `CheckURL`, `CheckInterval`, `CheckKindFormat`, `CheckName`, `CheckAuth`, `Secret` (kiểm tra ở biên, INV-2/5/6)
- Handler `PUT /feeds/sources/{id}`, `POST/PUT /feeds/custom`; `Secret` không bao giờ in/log/JSON giá trị thật (SYS-4).

## Modifying: `GET /feeds/hot` trường `you_have`, `matched_assets`
- **SPA** `HomePage`, `YouHaveCell`; **notify** không đọc trực tiếp.

## Disabling this module
- Trang chủ Hot/Weekly/Lookup/CVE trống ("off"); Settings → Feeds mất.
- `inventory`: danh mục chỉ còn bản đã giữ; không khớp mới. `findings`: không finding mới. `scan`: không tự quét lại. `notify`: không tin lỗ hổng mới (qua `findings`).
- `honeypot`, `logs`, `response`: không IOC mới, IOC cũ giữ.
- Dữ liệu `feeds_*` và cấu hình feed riêng giữ nguyên.
