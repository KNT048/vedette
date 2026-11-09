# Feeds — Change Impact Map

## Modifying: `feeds.Store` — `VulnByCVE(cve)`, `VulnsByProductKey(key)`, `HasTemplate(cve)`, `IOCLookup(value)`, `KevPairs()`
- **inventory** (`catalog`, khớp sản phẩm↔KEV theo khoá `vendorproject|product` chữ thường): đổi cách chuẩn hoá khoá = mọi khớp "Do you have it?" lệch.
- **mitigation** (`KevInfo` trong `FindingRow`), **scan** (`has_template`), **mcp-server** (`lookup_cve`, `lookup_ioc`), **ai** (slot `cve.panels`), **reports**.
- **honeypot / logs / response** (nhóm B): `IOCLookup` quyết định cảnh báo và chặn; đổi `verdict` ảnh hưởng quy tắc phản ứng.

## Modifying: `feeds.Fetch(ctx, feedID)` và sự kiện `feeds.vuln.new_kev`
- **inventory** (khớp lại), **scan** (quét lại ≤ 60 phút nếu `has_template`), **mitigation** (kiểm có gói chưa). Đổi tên/ trường sự kiện = âm thầm mất tự quét lại.

## Modifying: `feeds.ParseFeed(text, kind, Parser)` và giới hạn (5 MB, 50 000 dòng)
- **feeds** (kéo thật, `parse-test`), **SPA** (`ParserEditor`, `parsers.ts` phải cho kết quả giống Go: test chéo trên cùng mẫu).

## Modifying: `GET /feeds/hot` trường `you_have`, `matched_assets`
- **SPA** `HomePage`, `YouHaveCell`; **notify** không đọc trực tiếp.

## Disabling this module
- Trang chủ Hot/Weekly/Lookup/CVE trống ("off"); Settings → Feeds mất.
- `inventory`: danh mục chỉ còn bản đã giữ; không khớp mới. `findings`: không finding mới. `scan`: không tự quét lại. `notify`: không tin lỗ hổng mới (qua `findings`).
- `honeypot`, `logs`, `response`: không IOC mới, IOC cũ giữ.
- Dữ liệu `feeds_*` và cấu hình feed riêng giữ nguyên.
