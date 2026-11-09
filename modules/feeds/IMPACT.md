# Feeds — Change Impact Map

## Modifying: `feeds.Store` — `VulnByCVE(cve)`, `VulnsByProductKey(key)`, `HasTemplate(cve)`, `IOCLookup(value)`, `KevPairs()`
- **inventory** (`catalog`, khớp sản phẩm↔KEV theo khoá `vendorproject|product` chữ thường): đổi cách chuẩn hoá khoá = mọi khớp "Do you have it?" lệch.
- **mitigation** (`KevInfo` trong `FindingRow`), **scan** (`has_template`), **mcp-server** (`lookup_cve`, `lookup_ioc`), **ai** (slot `cve.panels`), **reports**.
- **honeypot / logs / response** (nhóm B): `IOCLookup` quyết định cảnh báo và chặn; đổi `verdict` ảnh hưởng quy tắc phản ứng.

## Modifying: `feeds.Fetch(ctx, feedID)` và sự kiện `feeds.vuln.new_kev`
- **inventory** (khớp lại), **scan** (quét lại ≤ 60 phút nếu `has_template`), **mitigation** (kiểm có gói chưa). Đổi tên/ trường sự kiện = âm thầm mất tự quét lại.

## Modifying: `feeds.ParseFeed(ctx, data []byte, kind Kind, p Parser) (Result, error)`, `ParseSource(ctx, src Source, data)` và giới hạn (5 000 000 byte, 50 000 dòng; nguồn dựng sẵn có `Source.MaxRows` riêng)
- **feeds** (kéo thật, `parse-test`), **SPA** (`ParserEditor`, `parsers.ts` phải cho kết quả giống Go: test chéo trên cùng mẫu `modules/feeds/testdata/samples` và `testdata/golden`). Go chặt hơn TS ở IP (netip, loại địa chỉ riêng/đặc biệt), domain (suffix công cộng, tên cục bộ), ký tự điều khiển/ẩn, hash tệp rỗng: mẫu TS có IP tài liệu (198.51.100.x, 203.0.113.x) bị Go loại.
- Đổi chữ ký có `ctx`: mọi chỗ gọi (job kéo, `parse-test`) phải truyền ctx có hạn; ctx huỷ giữa chừng trả `ctx.Err()` và không trả bản ghi nào (fail-closed). Ô dài hơn 4096 byte không chạy regex (bị loại); regex biên dịch > 1000 lệnh bị `ErrBadConfig`.
- Lỗi: `ErrTooLarge` (→ 413 `too_large`), `ErrBadConfig`, `ErrBadSample` (→ 400); câu hiển thị nằm ở `(*feeds.Error).Detail`. `Result.Records` chứa mọi bản ghi nhận; `Result.Preview()` cắt 20 đầu. `CheckParser(kind, p)` kiểm cấu hình trước khi lưu.
- `reasons[]` nhóm theo mẫu thông điệp, tối đa 50 nhóm + `other`; giá trị trích dẫn bằng `%q` và cắt 40 ký tự. Giá trị feed là văn bản thuần không tin cậy: người dùng (`notify`, `reports`, `ai`, SPA) phải escape theo môi trường của mình.
- Đổi cách chuẩn hoá (IP qua `netip`, domain/hash chữ thường, ngày UTC) hoặc danh sách địa chỉ/tên bị loại = đổi khoá khớp IOC của **honeypot/logs/response**. Dòng kiểu hosts-file (`0.0.0.0 tên`) cho ra tên, không bao giờ IP đích.

## Modifying: `ParseKEV`, `EPSSBatchURLs`/`ParseEPSS`, `ParseNucleiCVEs` (parser dựng sẵn)
- **feeds** job kéo (WP-20) ghi `feeds_vuln` từ `KEVCatalog.Vulns`, `has_template` từ `NucleiCVEs.CVEs`, `epss`/`epss_7d_ago` từ `ParseEPSS` của các URL do `EPSSBatchURLs(base, cveKEV, date)` dựng (≤ 100 CVE mỗi yêu cầu, `date` = `EPSSDate(now, 7)` cho delta). Nguồn là `api.first.org` (đã có trong PRIVACY.md luồng 1). Đổi trường `Vuln` = đổi cột `feeds_vuln`; `Vuln.Key()` = `ProductKey` là khoá khớp của **inventory**.
- KEV và nuclei đọc khoá JSON đúng chữ hoa/thường, khoá lặp lấy giá trị cuối (như `JSON.parse` của SPA). nuclei `cves.json` là JSON Lines với `ID`, `Info`, `file_path`; không nhận mảng.
- Giới hạn riêng của nguồn dựng sẵn: `hagezi-tif` dùng `tif.mini.txt` với `MaxRows` 100 000; `ipsum` dùng `levels/3.txt` (IPsum mức ≥ 3, DATA_PIPELINE §2b) trong trần 50 000. Đổi URL/biến thể phải đo lại dòng và dung lượng.

## Modifying: `Fetcher.Fetch(ctx, Request)` (một GET tới đúng URL)
- **feeds** job kéo và `POST /feeds/sources/{id}/fetch`. Chuyển hướng: chỉ cùng host (`ErrRedirect`), không hạ https→http, tối đa 5 bước, bỏ `Referer`. Đổi chính sách này = đổi host nào hộp có thể liên lạc (INV-1, INV-13, `PRIVACY.md`).
- Kết nối (`NewClient`): luôn từ chối link-local (169.254/16, fe80::/10), địa chỉ metadata đám mây, unspecified và multicast; `http` chỉ tới IP riêng/loopback (tên nội bộ trỏ ra IP công cộng bị chặn); phân giải DNS một lần mỗi kết nối (chống DNS rebinding); không dùng proxy môi trường. `Fetcher.Client` tự cấp phải qua cùng bảo vệ này (chỉ dùng trong test).
- Header gửi đi cố định: `User-Agent: Vedette/<version>`, `Accept`, điều kiện `If-None-Match`/`If-Modified-Since`, xác thực của feed. Thêm header = đổi luồng dữ liệu ra (legal.md).

## Modifying: `State.NextAttempt/Due/Record`, `IsStale`, `Backoff` (lịch kéo, INV-8/9) và `Judge`, `IOCKey`, `NewWhitelist`, `SightingOf` (IOC verdict, INV-12)
- **feeds** job (lịch, trạng thái lỗi ở Settings → Feeds): mốc thời gian ở tương lai (đồng hồ sai) coi là đến hạn và cũ. **honeypot/logs/response** đọc `verdict`: đổi ngưỡng block/alert = đổi quy tắc phản ứng.
- `Judge` chuẩn hoá id nguồn (cắt khoảng trắng, chữ thường) và lấy cờ của nguồn dựng sẵn từ sổ đăng ký: nguồn gộp (`ipsum`, `hagezi-tif`) không bao giờ `block` một mình và không tính là nguồn thứ hai khi có nguồn gốc của nó; `tor-exit` chỉ thông tin, không tính vào `block`; nguồn CC0 (abuse.ch) đủ để `block`. Whitelist nhận `google.com`, `*.google.com`, `.google.com` như nhau, mục không hợp lệ là lỗi `ErrInvalidWhitelist`.
- IP riêng/đặc biệt và tên cục bộ/suffix công cộng không bao giờ có verdict (lớp bảo vệ thứ hai sau parser).

## Modifying: `CheckURL`, `CheckInterval`, `CheckKindFormat`, `CheckName`, `CheckAuth`, `Secret` (kiểm tra ở biên, INV-2/5/6)
- Handler `PUT /feeds/sources/{id}`, `POST/PUT /feeds/custom`; `Secret` bọc `core/secrets.Value` (không bao giờ in/log/JSON giá trị thật, SYS-4) cộng kiểm tra INV-6 và `Last4`.

## Modifying: `GET /feeds/hot` trường `you_have`, `matched_assets`
- **SPA** `HomePage`, `YouHaveCell`; **notify** không đọc trực tiếp.

## Modifying: `feeds.Inventory` (`MatchProducts`, `AddManualDevice`), `feeds.Deps`, `feeds.Service` (`Seed`, `Jobs`, `Fetch`, `Store`), `feeds.Handlers`
- **inventory** (Kiên) implements `Inventory`: `MatchProducts` keyed by `Product.Key()` (= `ProductKey`) gives `you_have`/`matched_assets` of the hot board and the CVE page, `how` ∈ yes|maybe; `AddManualDevice` runs inside feeds' write transaction (it must not open its own `Write`). Change a signature = the "Do you have it?" column and "I have it" stop compiling in `cmd/vedette`.
- **cmd/vedette** (`feeds.go`, `wiring.go`, `modules.go`, `handler.go`): builds `Service` once per database; `Deps.Events` is `deps.Bus` and `Deps.Inventory` is `feedsInventory{deps.Inventory}` (so `deps.Inventory` must be built before the first `feedsService` call: `buildServices` does it). `Inventory` may also implement `TxSettler`; the real one does, so its events follow the commit of feeds' transaction. `Seed` must run after the migrations, on every start.
- `Store` read methods are the API of other modules: `VulnByCVE`, `VulnsByProductKey`, `HasTemplate`, `IOCLookup`, `KevPairs` (see the first sections) and, for the wiring, `KevProducts`, `KevCVEsByKeys`, `KevVulns`, `KevVulnsByCVE` (`store_kev.go`; cisa-kev rows only). They feed `inventory.KEV` (catalog + CVE match) and `findings.Feeds` through adapters in `cmd/vedette/wiring.go`: changing what they return changes the catalog, the match events and the findings.

## Modifying: events `feeds.vuln.new_kev`, `feeds.vuln.updated`, `feeds.ioc.updated`, `feeds.fetch.failed` (`NewKEVEvent`, `VulnUpdatedEvent`, `IOCUpdatedEvent`, `FetchFailedEvent`)
- **inventory** and **scan** listen to `new_kev`/`updated`; **notify** via findings. D-78: the first pull of the CISA list into an empty table publishes one `feeds.sync.baseline {source, count}` instead of one `new_kev` per entry (about 1,200). `cmd/vedette/wiring.go` subscribes `inventory.RematchCVE` to `new_kev` and `inventory.RematchAll` to the baseline; a listener of `new_kev` that must also react to the first sync (scan) has to subscribe to the baseline too. **notify (WP-22) must send nothing for a baseline** nor for findings created by its re-match.

## Modifying: tables `feeds_*` (migration `0001_feeds_base.sql`)
- Migration `0002_feeds_review.sql` adds `feeds_source.rev` (pull vs edit race) and `feeds_weekly_answer.device_added` (one "I have it" device per product).
- `feeds_source` carries the pull state and `secret_id` (core_secret) + `secret_last4`; deleting a custom feed deletes its secret, its `feeds_vuln` rows and its `feeds_ioc_source` rows (indicators nobody else lists go too). `feeds_ioc` has no score, category or verdict column: derive them (`Judge`).

## Disabling this module
- Trang chủ Hot/Weekly/Lookup/CVE trống ("off"); Settings → Feeds mất.
- `inventory`: danh mục chỉ còn bản đã giữ; không khớp mới. `findings`: không finding mới. `scan`: không tự quét lại. `notify`: không tin lỗ hổng mới (qua `findings`).
- `honeypot`, `logs`, `response`: không IOC mới, IOC cũ giữ.
- Dữ liệu `feeds_*` và cấu hình feed riêng giữ nguyên.

## Modifying: `feeds.BodyLimits`, `Vuln.links` (contract.ts)
- `cmd/vedette/modules.go` passes `feeds.BodyLimits` (operationId → bytes) to `server.Config`; removing the entry cuts `parse-test` samples back to 1 MiB while the GUI still promises 5 MB.
- `links` of `Vuln` are strings matching `^https?://` in contract.ts (so in `api/openapi.json` and `core/api/oas`), not `format: uri`: ogen decodes that with `ParseRequestURI` and turns `#anchor` into `%23anchor`. The backend stores only http(s) links (`kevLinks`) and `CvePage` renders only http(s) hrefs.
- `conformance.test.ts` (`FEEDS_REAL_URL`) and `web/e2e/qa/feeds.spec.ts` (`FEEDS_REAL=1`) run against `make dev-api REAL=feeds`; changing a status or error code in the handlers means updating the script's `real:` overrides.
