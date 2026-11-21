# Feeds — Change Impact Map

## Modifying: `feeds.Store` — `VulnByCVE(cve)`, `VulnsByProductKey(key)`, `HasTemplate(cve)`, `IOCLookup(value)`, `IOCListed()`, `IOCSubdomainsOn()`, `KevPairs()`, `HaveSince()`
- `HaveSince`: **findings** (`ServiceConfig.HaveSince`, INV-11 của findings) khớp phần mềm không phiên bản của sản phẩm đã trả lời "I have this", trên đúng thiết bị đã khai, chỉ từ `have_since`. `feeds.Inventory.AddManualDevice` nay trả id thiết bị ("" = không biết, phạm vi tắt). Đổi `have_since`/`device_id` = đổi số finding của thiết bị đó.
- **inventory** (`catalog`, khớp sản phẩm↔KEV theo khoá `vendorproject|product` chữ thường): đổi cách chuẩn hoá khoá = mọi khớp "Do you have it?" lệch.
- **mitigation** (`KevInfo` trong `FindingRow`), **scan** (`has_template`), **mcp-server** (`lookup_cve`, `lookup_ioc`), **ai** (slot `cve.panels`), **reports**.
- **honeypot / logs / response** (nhóm B): `IOCLookup` quyết định cảnh báo và chặn; đổi `verdict` ảnh hưởng quy tắc phản ứng.

## Modifying: `feeds.Fetch(ctx, feedID)` và sự kiện `feeds.vuln.new_kev`
- **inventory** (khớp lại), **scan** (quét lại ≤ 60 phút nếu `has_template`), **mitigation** (kiểm có gói chưa). Đổi tên/ trường sự kiện = âm thầm mất tự quét lại.

## Modifying: `feeds.ParseFeed(ctx, data []byte, kind Kind, p Parser) (Result, error)`, `ParseSource(ctx, src Source, data)` và giới hạn (5 000 000 byte, 50 000 dòng; nguồn dựng sẵn có `Source.MaxRows` riêng)
- **feeds** (kéo thật, `parse-test`), **SPA** (`ParserEditor`, `parsers.ts` phải cho kết quả giống Go: test chéo trên cùng mẫu `modules/feeds/testdata/samples` và `testdata/golden`). Go chặt hơn TS ở IP (netip, loại địa chỉ riêng/đặc biệt), domain (suffix công cộng, tên cục bộ), ký tự điều khiển/ẩn, hash tệp rỗng: mẫu TS có IP tài liệu (198.51.100.x, 203.0.113.x) bị Go loại.
- Đổi chữ ký có `ctx`: mọi chỗ gọi (job kéo, `parse-test`) phải truyền ctx có hạn; ctx huỷ giữa chừng trả `ctx.Err()` và không trả bản ghi nào (fail-closed). Ô dài hơn 4096 byte không chạy regex (bị loại); regex biên dịch > 1000 lệnh bị `ErrBadConfig`.
- Lỗi: `ErrTooLarge` (→ 413 `too_large`), `ErrBadConfig`, `ErrBadSample` (→ 400); câu hiển thị nằm ở `(*feeds.Error).Detail`. `Result.Records` chứa mọi bản ghi nhận; `Result.Preview()` cắt 20 đầu. `CheckParser(kind, p)` kiểm cấu hình trước khi lưu.
- `Reason.Example` (`json:"-"`): dòng đầu của mỗi nhóm với giá trị hiện; chỉ `note`/`accepted` (câu trạng thái lần kéo, lưu ở `feeds_source.error`, gửi trong `feeds.fetch.failed`) đọc nó. Bên nhận câu đó (SPA, notify) vẽ như văn bản thuần.
- `reasons[]` nhóm theo mẫu thông điệp, tối đa 50 nhóm + `other`; giá trị trích dẫn bằng `%q` và cắt 40 ký tự. Giá trị feed là văn bản thuần không tin cậy: người dùng (`notify`, `reports`, `ai`, SPA) phải escape theo môi trường của mình.
- `rejects[]` (S-FEED-5): `row` là số dòng của mẫu với `lines` (`rawRow.line`, đếm cả chú thích và dòng trống; dòng hosts-file nhiều tên cho cùng một số dòng), số bản ghi với định dạng khác; `ParserEditor` hiện từng dòng kèm `reason` có giá trị (văn bản thuần, React escape) vì chỉ `parse-test` trả nó. Không đưa `rejects[]` vào trạng thái lần kéo hay luồng nào khác: ở đó chỉ `reasons[]` đã che. Đổi câu lý do = đổi khoá nhóm của `reasons[]` (trạng thái "Most often") và `testdata/golden`.
- Đổi cách chuẩn hoá (IP qua `netip`, domain/hash chữ thường, ngày UTC) hoặc danh sách địa chỉ/tên bị loại = đổi khoá khớp IOC của **honeypot/logs/response**. Dòng kiểu hosts-file (`0.0.0.0 tên`) cho ra tên, không bao giờ IP đích.

## Modifying: `ParseKEV`, `EPSSBatchURLs`/`ParseEPSS`, `ParseNucleiCVEs` (parser dựng sẵn)
- **feeds** job kéo (WP-20) ghi `feeds_vuln` từ `KEVCatalog.Vulns`, `has_template` từ `NucleiCVEs.CVEs`, EPSS từ `ParseEPSS` của các URL do `EPSSBatchURLs(base, cveKEV, date)` dựng (≤ 100 CVE mỗi yêu cầu, `date` = `EPSSDate(now, 7)` cho delta). Nguồn là `api.first.org` (đã có trong PRIVACY.md luồng 1). Đổi trường `Vuln` = đổi cột `feeds_vuln`; `Vuln.Key()` = `ProductKey` là khoá khớp của **inventory**.
- KEV và nuclei đọc khoá JSON đúng chữ hoa/thường, khoá lặp lấy giá trị cuối (như `JSON.parse` của SPA). nuclei `cves.json` là JSON Lines với `ID`, `Info`, `file_path`; không nhận mảng.
- Giới hạn riêng của nguồn dựng sẵn: `hagezi-tif` dùng `wildcard/tif.mini-onlydomains.txt` (kho hagezi đã bỏ thư mục `domains/`) với `MaxRows` 250 000; `ipsum` dùng `levels/3.txt` (IPsum mức ≥ 3, DATA_PIPELINE §2b) trong trần 50 000. Đổi URL/biến thể phải đo lại dòng và dung lượng.

## Modifying: `NVDPageURL`/`ParseNVD`, feed `nvd-kev`, `Store.KevAffected`, sự kiện `feeds.ranges.updated`

- `nvd_pull.go` (thử lại, tạm dừng/đi tiếp, dòng tiến độ `Service.live`), `Request.HeaderTimeout`/`slowHeaders` và `StatusError.RetryAfter` trong `fetch.go`, `lockFeed` gộp lượt kéo trùng (`busy`). Người đọc: `FeedsSettings.tsx` (feed `never` có `error` là dòng tiến độ: không kèm câu "Fetched at the next scheduled check"; Fetch now trả feed có `error` mà `status` không phải `error` ⇒ toast thông tin). Test: `nvd_pull_test.go`, `TestFeedLockIsContextAwareAndPruned`, `TestContract_INV8_*`, `feeds.test.tsx`.
- **findings** (qua `cmd/vedette` `findingsFeeds.Vulns`): mọi quyết định theo phiên bản dựa vào các mục này; đổi hình `AffectedRow` hay bỏ mục ⇒ finding đổi (`modules/findings` `TestGolden_*`).
- **cmd/vedette**: `feeds.ranges.updated` → `Inventory.RematchAll` lần đầu (trong `notify.WithBaseline`), sau đó `Inventory.RematchMany` với vendor/product của các CVE trong sự kiện (review H3); `findingsFeeds.Vulns` giữ danh sách theo `Store.MatchStamp` (đổi cách ghi `feeds_vuln`/`feeds_affected_cve` mà không đổi `last_fetch`, `updated_at` hay số hàng ⇒ findings đọc danh sách cũ).
- **PRIVACY.md** luồng 1, Settings → Privacy (`locales/en/core.json` `privacy.flow.1`), `THIRD_PARTY_NOTICES.md`, `sourcesMock.ts` (danh sách có sẵn: 14), export policy (`feeds_affected*`).

## Modifying: danh mục lỗ hổng (`feeds_cve`, `feeds_cve_metric`, `feeds_cve_range`, `feeds_kev`, `feeds_signal`, `feeds_epss_hist`, `feeds_nvd_cursor`, `ParseNVD`, `PickCVSS`, `retention`)
- **findings** (qua `cmd/vedette` `findingsFeeds`): `Vulns` (`KevVulns`, `KevAffected`, `RangesFromCVEOrg`, `KevPublished`), `KevInfo`, `CVSS`, `TierVulns`/`TierDistro` đọc các bảng mới; đổi luật chọn CVSS, luật giữ hay thứ tự nguồn khoảng làm đổi finding: chạy golden test của findings và `cmd/vedette` (`TestReachability_910_Fixture`, các test wiring dùng `catalogue_seed_test.go`).
- **inventory** (`feedsKEV`: `KevProducts`, `KevCVEsByKeys`) đọc mục chủ của `feeds_kev`.
- **core** `export_policy.go`: mọi cột mới được phân loại (`TestExport_PolicyClassifiesEveryColumn`, danh sách bảng bỏ qua trong `data_test.go`); `docs/SCHEMA.sql` bằng `make schema`.
- **PRIVACY.md** luồng 1 và `locales/en/core.json` `privacy.flow.1`: các yêu cầu NVD (cửa sổ, đi qua toàn bộ danh sách, `cveId`).
- Thêm nguồn tín hiệu mới: ghi `feeds_signal` qua `putSignal`, luật `qualifies` của loại đó; CVE có tín hiệu đạt được giữ ở mọi tuổi và được lấy bản ghi NVD (`missingSQL`).

## Modifying: `Store.Brief`, `ReadVector`, `refGroup`, `nvdTag`, `GET /feeds/cve/{id}`, `content/catalog/cwe-names.json`
- `Brief` is the read model the CVE page, the finding's summary card, the AI context, notices and reports take: a field renamed or dropped breaks `web/src/features/feeds/contract.ts` (`CveBrief`, `CveDetail`), the mock (`mocks.ts`, `briefSamples.ts`), `CvePage.tsx` and every consumer of the brief. Regenerate `api/openapi.json` and `core/api/oas` (`pnpm --dir web openapi`, `make generate`).
- `ReadVector`'s words and `Summary` are shown and given to the AI as they are: a change of wording changes what people and the AI read.
- The weakness and reference writers (BRIEF-2) are shared by `writeNVDRecords` and `writeRecords`: a change in one must keep the rule "NVD's when NVD has given them, the record's until then" in both, or the stored rows depend on which pull came first (`TestBrief_CVE2025_22225` runs both orders).
- `cwe-names.json` is MITRE's CWE List, names only (licence in `THIRD_PARTY_NOTICES.md`); refresh it from the newest `cwec_latest.xml.zip`, weaknesses and groupings.

## Modifying: `cverecord*.go` (`ParseCVERecord`, `recordRanges`, `RecordProductKey`, the archives), feed `cve-org`, `Store.RangesFromCVEOrg`, `KEVRecordRows`

- **findings** (qua `cmd/vedette` `findingsFeeds.Vulns`, `rangesFrom`): CVE danh sách không có khoảng NVD mang `Vuln.RangesFrom = findings.RangesCVEOrg`/`RangesCVEOrgPartial` từ `kevRecordView` (partial: không bao giờ đóng finding); `FixedIn.Source` "CVE.org affected versions (from the CVE record's CNA)". CPE của hàng là hãng/sản phẩm mục danh sách đã chuẩn hoá (`productid.Norm`), phiên bản đúng nằm trong CPE: đổi cách dựng ⇒ finding đổi (`TestCVEOrgRecordsThroughTheMatcher`).
- **bộ khớp sau này** (`Store.Ranges`): hàng bản ghi không có CPE mang khoá `RecordProductKey`; muốn thấy chúng phải hỏi cả khoá tên của sản phẩm bên cạnh tên CPE NVD. Đổi `RecordProductKey` ⇒ đổi khoá đã lưu (đọc lại cả danh sách).
- **nvd-kev / nvd-recent**: `writeNVDRecords` chỉ xoá hàng `origin='nvd'`; hàng bản ghi ở lại, NVD thắng khi đọc.
- **cmd/vedette**: `Deps.DataDir` (tệp làm việc); export policy `feeds_cve_ref`; allow-list cột JSON `feeds_cve_ref.tags`.
- **PRIVACY.md** luồng 1, Settings → Privacy (`locales/en/core.json` `privacy.flow.1`), `THIRD_PARTY_NOTICES.md` (điều khoản CVE Program), `sourcesMock.ts`.

## Modifying: `signal_public.go`, `signal_metasploit.go`, `signal_exploitdb.go`, `signal_pocgithub.go` (feeds `metasploit`, `exploit-db`, `poc-in-github`), `content/catalog/exploit-authors.json`

- **Danh mục** (`retention`, `keepSetSQL`): CVE có hàng `public_exploit` đạt được giữ ở mọi tuổi ⇒ thêm khoảng 25.000 CVE cũ, 153.000 khoảng phiên bản, 64 MB (đo 21/11/2026) (bản ghi NVD qua lượt đi qua toàn bộ của `nvd-recent`, `publicListedSQL`). Đổi luật `qualifies` hay danh sách tác giả ⇒ đổi số CVE giữ và số bản ghi NVD/CVE record kéo về.
- **findings** (urgency lớp 3, `Store.Signals`): `first_seen` là ngày hiện trên lý do; `qualifies = 0` không bao giờ là lớp 3.
- **PRIVACY.md** luồng 1, Settings → Privacy (`privacy.flow.1.to`), `THIRD_PARTY_NOTICES.md` (mục chỉ mục exploit công khai), `sourcesMock.ts` + `conformance.test.ts` (20 feed có sẵn), `sources_test.go` (host `gitlab.com`, `codeload.github.com`), `heldnote.go` (`poc-in-github`: bao nhiêu CVE đạt).

## Modifying: `signal_claims.go`, `signal_vendor.go`, `signal_msrc.go`, `signal_csaf.go` (feeds `msrc`, `cisco-psirt`, `fortinet-psirt`)

- **Mẫu câu của hãng** (`claimForm`, `ciscoForms`, `fortinetForms`, `claimReader`): trường có cấu trúc (CSAF `exploit_status`, cờ Exploited của Microsoft) quyết trước; nếu không có, chỉ câu khớp đúng một mẫu câu thật của hãng mới là tuyên bố; câu nói về khai thác mà không khớp mẫu nào bị đếm "unclassified" trên nhật ký feed, không bao giờ đoán. Các nguồn văn bản sau này dùng cùng cách (mẫu riêng từng nguồn). Đổi mẫu ⇒ chạy lại `TestVendorClaims_CountsOfTheFrozenFixtures` (24 Cisco, 7 Fortinet, 0 khớp nhầm, 1 câu unclassified), `TestClaimForms_*` và `TestCSAFClaims_WorkIsLinearInTheDocument`.
- **findings** (urgency lớp 2, `Store.Signals`): hàng `exploited` của ba nguồn này `qualifies = 1` ngay; `first_seen` là ngày nguồn nói, hoặc lần hộp tự thấy khi ngày nguồn cũ hơn lần kéo tốt trước quá 24 giờ. `MatchStamp` chưa có ba feed này (như các feed public-exploit).
- **Danh mục** (`keepSetSQL`, `publicListedSQL`): CVE có tuyên bố được giữ ở mọi tuổi và có thể hỏi NVD/CVE record theo ID (danh sách công khai, mọi hộp hỏi như nhau).
- **PRIVACY.md** luồng 1, Settings → Privacy (`privacy.flow.1.to`), `THIRD_PARTY_NOTICES.md` (mục tuyên bố khai thác của hãng), `sourcesMock.ts` + `conformance.test.ts` (23 feed có sẵn), `sources_test.go` (host `api.msrc.microsoft.com`, `sec.cloudapps.cisco.com`, `filestore.fortinet.com`; chu kỳ 6 giờ), `heldnote_test.go`, `store.go` (tắt/bật lại ⇒ đọc lại từ đầu).

## Modifying: `vulncheck.go`, feed `vulncheck-kev`, `isKEVSource`, the `source_id IN ('cisa-kev', 'vulncheck-kev')` reads

- **findings / inventory** (qua `cmd/vedette` `findingsFeeds`, `wiring`): `KevVulns`/`KevVulnsByCVE`/`KevCVEsByKeys`/`KevProducts`/`KevPairs` trả cả mục VulnCheck: finding mới của CVE nguồn `vulncheck-kev`, `required_action` mang câu nguồn. Bỏ nguồn thứ hai khỏi các truy vấn ⇒ finding của CVE chỉ VulnCheck có sẽ không còn khớp.
- **cve-org**: `recordDue` và `kevRecordView` đọc cả hai nguồn để chọn CVE hỏi theo ID và CVE findings thấy.
- **reports** (`cmd/vedette/reports.go` `reportsKEV.Entries`): bỏ hàng không phải `cisa-kev` (không phân phối lại dữ liệu VulnCheck). Home/weekly/announced/EPSS chỉ đọc `cisa-kev`.
- **handlers_sources.go** `PUT /feeds/sources/{id}`: `api_key` chỉ cho feed BYOK, `isBYOK`, `saveFeedKey`; `toFeedDTO` hiện `auth.secret_last4` của feed BYOK. Contract: `FeedPatch.api_key` (contract.ts, `api/openapi.json`, `core/api/oas`).
- **cmd/vedette**: `Store.MatchStamp` thêm `vulncheck-kev`; export policy không đổi (không bảng/cột mới; `feeds_vuln` vẫn xuất cả hàng `vulncheck-kev`).
- **PRIVACY.md** luồng 1, Settings → Privacy (`privacy.flow.1`), `THIRD_PARTY_NOTICES.md`, `sourcesMock.ts` (danh sách có sẵn: 11), `FeedsSettings.tsx`/`FeedDialogs.tsx` (`needsKey`, ô khoá).

## Modifying: `Fetcher.Fetch(ctx, Request)` (một GET tới đúng URL)
- **feeds** job kéo và `POST /feeds/sources/{id}/fetch`. Chuyển hướng: chỉ cùng host (`ErrRedirect`), không hạ https→http, tối đa 5 bước, bỏ `Referer`. Đổi chính sách này = đổi host nào hộp có thể liên lạc (INV-1, INV-13, `PRIVACY.md`).
- Kết nối (`NewClient`): luôn từ chối link-local (169.254/16, fe80::/10), địa chỉ metadata đám mây, unspecified và multicast; `http` chỉ tới IP riêng/loopback (tên nội bộ trỏ ra IP công cộng bị chặn); phân giải DNS một lần mỗi kết nối (chống DNS rebinding); không dùng proxy môi trường. `Fetcher.Client` tự cấp phải qua cùng bảo vệ này (chỉ dùng trong test).
- Header gửi đi cố định: `User-Agent: Vedette/<version>`, `Accept`, điều kiện `If-None-Match`/`If-Modified-Since`, xác thực của feed. Thêm header = đổi luồng dữ liệu ra (legal.md).

## Modifying: `State.NextAttempt/Due/Record`, `IsStale`, `Backoff` (lịch kéo, INV-8/9) và `Judge`, `IOCKey`, `NewWhitelist`, `SightingOf` (IOC verdict, INV-12)
- **feeds** job (lịch, trạng thái lỗi ở Settings → Feeds): mốc thời gian ở tương lai (đồng hồ sai) coi là đến hạn và cũ. **honeypot/logs/response** đọc `verdict`: đổi ngưỡng block/alert = đổi quy tắc phản ứng.
- `Judge` chuẩn hoá id nguồn (cắt khoảng trắng, chữ thường) và lấy cờ của nguồn dựng sẵn từ sổ đăng ký: nguồn gộp (`ipsum`, `hagezi-tif`) không bao giờ `block` một mình và không tính là nguồn thứ hai khi có nguồn gốc của nó; `tor-exit` chỉ thông tin, không tính vào `block`; nguồn CC0 (abuse.ch) đủ để `block`. Whitelist nhận `google.com`, `*.google.com`, `.google.com` như nhau, mục không hợp lệ là lỗi `ErrInvalidWhitelist`.
- IP riêng/đặc biệt và tên cục bộ/suffix công cộng không bao giờ có verdict (lớp bảo vệ thứ hai sau parser).
- `localName` gồm cả `testName` (`example.com|net|org` và tên dưới chúng, `*.test|example|invalid|localhost`): `Judge`/`IOCKey` không còn nhận các tên đó, nên **logs** (khớp DNS/kết nối, `cmd/vedette/logsioc.go`), **honeypot**, **response** và tìm kiếm không bao giờ khớp chúng; test của module khác dùng tên giả `*.example.*` làm IOC phải đổi sang tên khác (đã đổi `cmd/vedette/logs_test.go`).

## Modifying: `CheckURL`, `CheckInterval`, `CheckKindFormat`, `CheckName`, `CheckAuth`, `Secret` (kiểm tra ở biên, INV-2/5/6)
- Handler `PUT /feeds/sources/{id}`, `POST/PUT /feeds/custom`; `Secret` bọc `core/secrets.Value` (không bao giờ in/log/JSON giá trị thật, SYS-4) cộng kiểm tra INV-6 và `Last4`.
- `ErrOwnAddress` bọc `ErrBlockedAddress`: mọi `errors.Is(err, ErrBlockedAddress)` vẫn đúng; `userError` kiểm nó trước để nói "This address is the machine Vedette runs on…".
- `CheckDest(raw, box)` dùng `refusedAlways` và `destGuard.refused` của bộ quay số: đổi luật quay số là đổi luôn luật lúc lưu (và `blockedFeedHost` của SPA, `web/src/features/feeds/defaults.ts`, phải đổi theo). `Service.boxAddrs` đọc `Fetcher.BoxAddrs`/`Gateway` như lượt kéo. Test và e2e-real không lưu được feed trỏ 127.0.0.1: origin của test gói tên `origin.lan` (`onlyLoopback`), e2e-real dùng `e2e-loopback.lan` (`cmd/vedette/e2ebox_test.go` `e2eOffline`).
- `checkDuplicateURL` / `sameAddress` đọc `feeds_source.url` của mọi feed khác trong giao dịch ghi; mock dùng `sameFeedAddress`. Mã `blocked_host`, `duplicate_url` là hợp đồng của `FeedDialogs.tsx` (`FIELD_OF` → lỗi dưới ô Address) và `conformance.test.ts`.

## Modifying: `Service.hot` (cửa sổ, cách gom, `you_have`) và `Service.NewlyExploited`
- **reports**: `Counts.kev_new`/`kev_matched` của báo cáo tuần là `NewlyExploited`; đổi cửa sổ hay định nghĩa "products you use" là đổi cả trang chủ và báo cáo (đúng ý: hai trang phải cùng số). Chuyển `kev_matched` sang đơn vị khác phải đổi chữ `doc.weekly.stat.kevValueHome` của `web/features/reports`.

## Modifying: `GET /feeds/hot` trường `you_have`, `matched_assets`
- **SPA** `HomePage`, `YouHaveCell`; **notify** không đọc trực tiếp.

## Modifying: the way a pull applies an IOC list (`applyIOCs`, `iocChunkRows`, `Service.afterChunk`)
- **core** (`core/store` writer, one connection): every write of the box queues behind the transaction that is open. Raising `iocChunkRows` or going back to one transaction per list makes boot, login, setup and every other module's write stall for as long as the list takes (~20 s for 250 000 rows). Keep each transaction short. `iocChunkRows` is a `var` only so that the package's tests run with 200 (`TestMain`, store_test.go); the chunk tests are written in units of it.
- **logs / honeypot / response** (future `IOCLookup` readers): during a pull they see the old and the new listings together, never fewer; a pull cut off halfway leaves extra listings until the next pull (`maintain` never touches `feeds_ioc_source`). A feed switched off mid-pull keeps the committed chunks until it is pulled again (switched-off feeds' listings are kept anyway). A new reader must not assume a list is applied atomically.
- **logs** (digest `ioc_matching`): `IOCListed` says whether a switched-on feed lists at least one indicator (`feeds_ioc_source` joined with `feeds_source.enabled`); a change in what counts as listed changes when the Logs page says that nothing can be matched. Test: `TestIOCListedNeedsASwitchedOnFeedWithListings`.
- **logs**: `IOCSubdomainsOn` says whether a switched-on built-in source with `Source.Subdomains` exists (`feeds_source.enabled`, `builtin`); false makes logs skip the parent walk of unlisted names. Setting `Subdomains` on another built-in source turns the walk on with it. Test: `TestIOCSubdomainsOnFollowsTheSwitchOfHageziTIF`.
- **logs**: `IOCLookup` returns `IOCSighting.Enabled` (the feed is switched on now); the logs adapter (`cmd/vedette/logsioc.go`) ignores sightings of switched-off feeds, whose listings stay in `feeds_ioc_source` until the feed pulls again. `/feeds/search` (`iocHit`, which MCP `lookup_ioc` reads) and the AI `lookup_ioc` (`cmd/vedette/ai.go`) skip them the same way: an indicator that only switched-off feeds list is not listed (POST-4).
- **logs**: `IOCLookup` returns `IOCSighting.Subdomains`, true only for a sighting of a built-in source with `Source.Subdomains` (today `hagezi-tif`, whose list says "Domains (without subdomains)": a listed name stands for itself and all of its subdomains); a custom feed is always exact. The logs adapter puts those feeds in `Listing.SubFeeds`, and logs then matches a subdomain the device asked for through the nearest listed parent. Setting the flag on another built-in source (or a URL/variant change of `hagezi-tif` to a list of exact names) changes which subdomains logs reports as bad connections: measure what the list means first.
- **core export** (`export_policy.go`): `feeds_ioc_source.seen` stays in the export list but nothing reads or writes it now.
- Not chunked: `applyVulns`, `applyTemplates`, `applyEPSS` (a custom vulnerability list is capped at 50 000 rows, about 3 s). Raise that cap and these need the same treatment.

## Modifying: `feeds.Inventory` (`MatchProducts`, `AddManualDevice`), `feeds.Deps`, `feeds.Service` (`Seed`, `Jobs`, `Fetch`, `Store`), `feeds.Handlers`
- **inventory** implements `Inventory`: `MatchProducts` keyed by `Product.Key()` (= `ProductKey`) gives `you_have`/`matched_assets` of the hot board and the CVE page, `how` ∈ yes|maybe; `AddManualDevice` runs inside feeds' write transaction (it must not open its own `Write`). Change a signature = the "Do you have it?" column and "I have it" stop compiling in `cmd/vedette`.
- **cmd/vedette** (`feeds.go`, `wiring.go`, `modules.go`, `handler.go`): builds `Service` once per database; `Deps.Events` is `deps.Bus` and `Deps.Inventory` is `feedsInventory{deps.Inventory}` (so `deps.Inventory` must be built before the first `feedsService` call: `buildServices` does it). `Inventory` may also implement `TxSettler`; the real one does, so its events follow the commit of feeds' transaction. `Seed` must run after the migrations, on every start.
- `Store` read methods are the API of other modules: `VulnByCVE`, `VulnsByProductKey`, `HasTemplate`, `IOCLookup`, `IOCListed`, `IOCSubdomainsOn`, `KevPairs` (see the first sections) and, for the wiring, `KevProducts`, `KevCVEsByKeys`, `KevVulns`, `KevVulnsByCVE` (`store_kev.go`; cisa-kev rows only). They feed `inventory.KEV` (catalog + CVE match) and `findings.Feeds` through adapters in `cmd/vedette/wiring.go`: changing what they return changes the catalog, the match events and the findings.

## Modifying: events `feeds.vuln.new_kev`, `feeds.vuln.updated`, `feeds.ioc.updated`, `feeds.fetch.failed` (`NewKEVEvent`, `VulnUpdatedEvent`, `IOCUpdatedEvent`, `FetchFailedEvent`)
- **inventory** and **scan** listen to `new_kev`/`updated`; **notify** via findings. The first pull of the CISA list into an empty table publishes one `feeds.sync.baseline {source, count}` instead of one `new_kev` per entry (about 1,200). `cmd/vedette/wiring.go` subscribes `inventory.RematchCVE` to `new_kev` and `inventory.RematchAll` to the baseline; a listener of `new_kev` that must also react to the first sync (scan) has to subscribe to the baseline too. **notify (WP-22) must send nothing for a baseline** nor for findings created by its re-match. Every `new_kev` is also recorded in `feeds_vuln.kev_announced_at` in the pull's transaction (S4b): a change to which CVEs get `new_kev` must change `markAnnounced` with it, or **scan**'s catch-up (`Store.NewKEVSince`, through `cmd/vedette/scan.go` `scanKEV`) rescans a different set from the one the bus announced.

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
- `links` of `Vuln` are strings matching `^https?://` in contract.ts (so in `api/openapi.json` and `core/api/oas`), not `format: uri`: ogen decodes that with `ParseRequestURI` and turns `#anchor` into `%23anchor`. The backend stores only http(s) links (`kevLinks`) and `CvePage` renders only http(s) hrefs. Links are cleaned of the punctuation prose puts around them (`cleanLink`/`cleanLinks`) on write and on read: every reader (findings `KevInfo.links`, mcp `lookup_cve`, AI prompts, the CVE page) gets the cleaned form; the export of `feeds_vuln` dumps the stored JSON as it is.
- `conformance.test.ts` (`FEEDS_REAL_URL`) and `web/e2e/qa/feeds.spec.ts` (`FEEDS_REAL=1`) run against `make dev-api REAL=feeds`; changing a status or error code in the handlers means updating the script's `real:` overrides.
## Modifying: `feeds.KEVMirrorURL`, `Deps.KEVPrimary/KEVFallback`, `buildKEVBoth`, `Feed.answered_by`
- `fallbackWorthy` is gone: `buildKEVBoth` (kevcopies.go) asks both copies every check and keeps the newer (`kevKey`: plausible version, then release date; no version/date is not used; plausibility by the server's `Date` (`Response.Date`), 304 judged again from stored metadata, no count rule, #946 r1/r2; `kevguard_test.go`, `kevlevels_test.go`). `copyWhy` words each copy's failure (stored in `kev_copies`, shown on Home via `fresh.copyFailed` and in Settings as the note), the both-down sentence and the alert text (`kevhonest_test.go`, `kevfallback_test.go`, `kevFreshness.test.tsx`). `KEVCatalog.ReleasedAt` is truncated to milliseconds so a held catalog compares equal to itself after `store.FormatTS`.
- `buildKEVBoth` (kevcopies.go) is the only place both copies are asked; `raw.githubusercontent.com` for the CISA list is in `PRIVACY.md` flow 1 and Settings → Privacy (`core.json`): a new fallback host means both, in the same commit.
- `answered_by` is in `contract.ts` (`Feed`), the mock (`sourcesMock.ts`), `api/openapi.json` and `core/api/oas`, and the Settings → Feeds status cell. Migration `0003_feeds_answered_by.sql` adds the column (report the change for DATA_MODEL.md).

## Modifying: `Deps.Alert`, `ErrAlertOff`, `watchKEV`, `KEVStaleChecks` (INV-29)
- **cmd/vedette** `feeds.go` wires `Alert(ctx, id, title, text, critical)` to `newNotify(&d).Publish` (incident-kind notice, `critical` for the alert so critical-only channels get it, `high` for the recovery; no incident row; `notify.ErrModuleOff` becomes `ErrAlertOff`). Notify does not dedupe an incident-kind notice once sent, so the watch records the alert before queuing it. `RunPull` passes the CISA list as its own pull left it (`watchKEV(ctx, pulled)`): only the job's checks count toward the two in a row. A change of the rule (two both-failed checks in a row, six checks, the start of the count, enable/disable reset) is a product change. The state is on the `cisa-kev` row (migration 0016; core `export_policy.go` lists the columns).

## Modifying: `FeedStatus.kev`, the retired-built-in cleanup in `SeedBuiltins`
- `kev` is in `contract.ts` (`FeedStatus`), the mock (`kevStatus()` in `sourcesMock.ts`, read by `mocks.ts`), `api/openapi.json`, `core/api/oas` and the Home title (`HomePage.tsx`, strings `home.kev*` in `feeds.json`). Readers: the Home sentence and, when the table is empty, the hot board; both take the same sentence from `useKevNotice()` in `HomePage.tsx`, so they cannot disagree. A non-empty board keeps its rows.
- Removing a built-in id from `builtinSources` deletes its row, listings and history on the next start (INV-16): never rename an id to "retire" it, and never reuse a retired id. `PRIVACY.md` flow 1, `core.json` (Settings → Privacy), `THIRD_PARTY_NOTICES.md` and DATA_MODEL.md's id list (report) follow in the same commit (legal.md).

## Modifying: `Fetcher.BoxAddrs`, `destGuard`, `ErrBoxAddrsUnknown` (INV-17)
- **cmd/vedette** `feeds.go` sets `fd.Fetcher.BoxAddrs = notifyBoxAddrs(d.HostNet)`: the same source of the box's own addresses as notify's webhook guard (`hostNetCache.SnapshotKnown`); a change to what that returns (known/unknown, /32 entries only) changes which pulls are refused. A `Fetcher` built without it still refuses loopback and the container's own interface addresses.
- **e2e-real / `cmd/vedette/e2ebox_test.go`**: a custom feed pointed at a loopback fake server is now refused at connect; the harness needs a test seam (deferred). In-package tests set the unexported `Fetcher.allowLoopback`.
- The save check now refuses literal loopback/link-local/metadata/box addresses and `localhost` names (`blocked_host`), so what the GUI text says and what is saved agree; names are still judged only at pull.
- Pooled keep-alive connections are not re-checked on reuse: harmless, because a peer that was allowed cannot become the box. While the box addresses are unknown only global unicast addresses are dialled, and a pull refused for that reason (`ErrBoxAddrsUnknown`) is not recorded as a failure: no back-off, the feed stays due.
- `Fetcher.Gateway` (wired to `procGateway` in `cmd/vedette/feeds.go`) adds the container default gateway to the box set, as core/conn does.
- The rule of Vedette itself is now one rule in feeds, notify, logs and ai (`ownAddrs`: loopback and the container's own interfaces on every port, the machine's addresses — `Fetcher.BoxAddrs`, `Fetcher.Gateway` — only on `vedettePorts` 8443, 8444, 8765, 514, 6514), with one sentence (`ownText`, the same text as `channel.OwnText`, logs `ownText`, `provider.OwnText` and the SPA's `OWN_TEXT` copies). `CheckDest` takes an `ownAddrs`. Changing the port list or the sentence means changing every copy; the GUI's `blockedFeedHost` returns `'own'` or `'blocked'`.
- `Fetcher.Self` (cmd/vedette `vedetteSelf`: the honeypot's decoys, read at every check) is Vedette itself on every port; `cmd/vedette/ownaddr.go` `machineAddrs` is the one source of the machine's addresses for feeds, notify, logs and ai (it includes the gateway, so `Fetcher.Gateway` is no longer wired).

## Modifying: `PlatformChecker`
- Cài bởi `cmd/vedette/wiring.go` `feedsInventory.NotAffected` (inventory + `findings.PlatformRuledOut`); SPA trang CVE (`CvePage.tsx`) chỉ thấy danh sách ngắn hơn, không đổi hợp đồng.

## Modifying: feeds `epss-all`, `nvd-recent`, `ParseEPSSCSV`, `RecentPageURL`/`ParseNVDRecent`, bảng `feeds_epss`, `feeds_recent_*`
- **findings** (slice 2): tầng 2 đọc `feeds_epss` (EPSS ≥ `EPSSLikely`, CVE công bố trong 12 tháng theo `feeds_recent_cve.published`), tầng 3 đọc `feeds_recent_cve` + `feeds_recent_affected`; khi đó thêm hai feed vào `Store.MatchStamp` và phát `feeds.ranges.updated` (hoặc sự kiện riêng) sau lượt kéo. Hiện chưa module nào đọc chúng.
- **nvd-kev**: dùng chung `nvdPage` (thêm tham số `maxBytes`, `nvd-kev` truyền 0 = `MaxBodyBytes`) và cổng `nvdSlot` (mọi request NVD của hai feed cách nhau ≥ `nvdPause`; với `nvd-kev` một mình cổng không thêm chờ vì `nvdPages` đã nghỉ `nvdPause`); `nvd-recent` dừng khi `nvd-kev` đang kéo (`Service.busy`) hoặc đang chờ NVD (`nvdResumeAt`).
- **core** (`modules/core/export_policy.go`): bốn bảng mới `skipAll` (dữ liệu công khai, kéo lại được); `cmd/vedette` `TestExport_PolicyClassifiesEveryColumn` ghim danh sách đó.
- **PRIVACY.md** luồng 1 + Settings → Privacy (`locales/en/core.json` `privacy.flow.1`), `THIRD_PARTY_NOTICES.md` (hàng FIRST EPSS, NVD), `sourcesMock.ts` + `conformance.test.ts` (danh sách feed có sẵn), `sources_test.go` (host `epss.empiricalsecurity.com`, 16 feed).
- **TERMS.md**: đoạn mô tả ba tầng và luật tuổi vào ở slice 2 cùng hành vi (slice 1 không đổi TERMS.md).
- **Mặc định tắt** (`Source.Off`): slice 2 bỏ `Off` và phải bật hai feed trên hộp đã seed (hàng có sẵn giữ `enabled = 0`), như lần đổi lịch CISA trước.

## Modifying: ngày công bố KEV và dữ liệu tầng cho trang (INV-25)
- **findings** (qua `cmd/vedette/wiring.go` `findingsFeeds`): `Store.KevPublished` → `Vuln.Published` (luật tuổi: KEV công bố hơn 12 tháng không thành finding khi chỉ khớp tên sản phẩm; finding mở loại đó đóng) và `KevInfo.published`; `Store.TierStatus` → `findings.Feeds.TierStatus` cho `GET /findings/plan`. Đổi ý nghĩa ngày (ví dụ dùng `dateAdded`) là đổi finding của mọi hộp; thiếu ngày luôn phải nghĩa là "gần đây".
- **nvd-kev**: bảng `feeds_published` trống (và đã có khoảng) ⇒ lần kéo kế là kéo đầy đủ (`buildNVD`; ~18 trang). Giới hạn: trong lúc NVD trả 503 lượt kéo đầy đủ tạm dừng và đi tiếp ở lượt sau (chỉ trong bộ nhớ: khởi động lại thì bắt đầu lại), và trong lúc đó không có lượt cập nhật, nên khoảng của mục KEV mới chờ tới khi lượt đầy đủ xong (như lần nạp đầu tiên của nvd-kev); một câu trả lời NVD không có `published` đọc được để bảng trống và mọi lượt kéo sau lại đầy đủ (NVD luôn có trường này). Test fixture NVD phải mang `published` để kiểm lượt kéo cập nhật. Đo lượt kéo một lần này trên hộp thật (deferred).
- **exposure** (`cmd/vedette/exposurematch.go`): CVE KEV cũ chỉ khớp tên sản phẩm thành dòng "ruled out" kèm lý do thay vì dòng CVE.
- **core export** (`export_policy.go`): `feeds_published` được xuất.
- **`Store.PublishedOf(ctx, cves)`** (#825): một truy vấn mỗi `publishedChunk` = 500 CVE (`json_each`, như `CVSSOf`), không một truy vấn mỗi CVE; `GET /findings` và `GET /findings/summary` hỏi mọi CVE mở qua `findingsFeeds.KevInfo` (đo trên i5-7400, 2 000 CVE: lần tính Home 52–68 ms → 30–35 ms, `GET /findings` p50 146 → 74 ms). Kết quả không đổi (`TestPublishedOfReadsEveryAskedCVEAcrossChunks`).
- **SPA**: `CveDetail.published`, `TierCve` (`web/src/features/feeds/contract.ts`, `CvePage.tsx`, `TierCvePage.tsx`, mock `web/src/mocks/tiers.ts`).

## Modifying: CVE tiers slice 3a
- **findings** đọc `Store.TierRecords` qua `cmd/vedette` `findingsFeeds.TierVulns` (trả rỗng khi module feeds tắt) và `Store.MatchStamp` qua `findingsFeeds.MatchStamp`; `MatchStamp` thêm `epss-all`, `nvd-recent` (một lượt kéo của chúng cũng làm mới bộ nhớ đệm danh sách KEV của findings/exposure: một lần đọc lại, không đổi kết quả).
- **Feed tầng bật mặc định** (`Source.Off` bỏ; migration 0012 bật trên hộp cũ khi `rev = 0`): hộp mới và hộp nâng cấp gọi `epss.empiricalsecurity.com` mỗi ngày và nạp 12 tháng NVD (~105 request lần đầu, hơn một giờ khi NVD trả 503 như đo trên hộp thử); `PRIVACY.md` luồng 1 và Settings → Privacy (`web/src/locales/en/core.json`) nói "on by default"; mock `web/src/features/feeds/sourcesMock.ts`.
- **`feeds_published.source`**: export policy `modules/core/export_policy.go`; `publishedCount` chỉ đếm `nvd`.
- **Migration 0013** (`feeds_recent_affected.platforms`, xoá `feeds_recent_cursor`): hộp nâng cấp nạp lại 12 tháng NVD một lần; export policy liệt kê cột mới (bảng vẫn không xuất). `Store.TierStamp` cho findings.
- **nvd-recent**: `Service.recent` là `*recentProgress` (dòng tiến độ viết lúc `live`), `recentAt` chặn `RunPull`; `nvdPage` nhận `start` (log); `nvdSlot` giữ `nvdBookedAt`.

## Modifying: lịch và dòng feed của `nvd-recent` khi dữ liệu chưa đầy đủ (fix/n55-feeds)
- `RunPull` đọc `feeds_recent_cursor` mỗi lần kiểm khi `nvd-recent` bật (một hàng); con trỏ chưa `done` cho địa chỉ của feed ⇒ đến hạn ngay (chỉ back-off sau lỗi giữ lại). Mọi lần xoá con trỏ sau này (migration, sửa tay) nạp lại ở lần kiểm kế, không cần migration đổi lịch.
- `Service.live` nhận `ctx` (đọc con trỏ và số CVE của `nvd-recent` khi không có lượt nào đang chạy, cả khi trạng thái là lỗi); người gọi: `GET /feeds/sources`, `POST /feeds/sources/{id}/fetch`, `pull`. Không đổi API hay GUI: dòng tiến độ đi trong `error` như lượt nạp đầu.

## Modifying: điểm CVSS (`cvssOf`, `metricsOf`, `NVDPage.CVSS`/`Seen`, `applyCVSS`, `Store.CVSSOf`, `fullDue`, bảng `feeds_cvss`, cột `feeds_recent_cve.cvss_*`, `feeds_source.full_due`; INV-28, #825)
- **findings** (qua `cmd/vedette/wiring.go` `findingsFeeds.CVSS`): `FindingRow.cvss` trên `GET /findings`, `GET /findings/{id}` và các câu trả lời `FindingDetail` của `mitigation` (findings INV-22); đổi luật chọn (phiên bản, Primary/Secondary, vector bắt buộc, làm tròn) = đổi điểm khách thấy trên mọi finding và trên trang chủ (phần dashboard của #825 đọc cùng trường).
- **nvd-kev / nvd-recent** (INV-19, INV-24): `metrics` là `json.RawMessage` trong `nvdAnswer` và `recentRecord`, giải mã riêng (`metricsOf`): một `metrics` hỏng không bao giờ làm hỏng trang hay bản ghi (như với khoảng phiên bản và ngày). `severityOf` (tầng 3) giữ luật và cột cũ (`severity`, `score`); `cvssOf` là luật riêng của điểm finding (cột `cvss_*`).
- **nvd-kev** (`buildNVD`, `RunPull`): khi `feeds_source.full_due = 1` (migration 0015) feed đến hạn ở lần kiểm 5 phút kế (trừ back-off sau lỗi) và kéo đầy đủ; lượt đầy đủ được lưu xoá dấu (`pull.go`); không còn đếm `feeds_cvss`. Test giả NVD (`nvdBody`, `nvdOrigin`) có `metrics` kèm vector.
- **nvd-recent**: không nạp lại (con trỏ giữ nguyên, "Updates to plan" không gián đoạn); hàng cũ có `cvss_*` khi NVD sửa bản ghi. Bản ghi có `metrics` hỏng nay được nhận không mức/điểm (trước bị từ chối cả bản ghi): tầng 3 có thể liệt kê nó.
- **core** (`modules/core/export_policy.go`): `feeds_cvss` và `feeds_source.full_due` xuất; các cột `cvss_*` của `feeds_recent_cve` bỏ; `cmd/vedette` `TestExport_PolicyClassifiesEveryColumn`.
- **THIRD_PARTY_NOTICES.md** hàng NVD (điểm CVSS, vector) và hàng FIRST CVSS (mọi điểm kèm vector; ghi công "CVSS is owned by FIRST and used by permission", cũng trong ⓘ của điểm). Không đổi PRIVACY.md: không luồng ra mới.
- **Ngày giờ hiển thị (`core/orgtime`)**: `Deps.Zone` (múi giờ tổ chức) cho giờ trong cảnh báo danh sách CISA (`kevStaleNotice`, `kevFreshNotice`, `orgtime.StampZone`: kèm tên viết tắt của múi giờ, "UTC" khi không đọc được). `feeds_epss_baseline.score_date` (migration 0022, `DecoderEPSSAll` lên 2) giữ ngày FIRST của điểm; `TierStatus.EPSSDate` đọc nó, nên findings (`epss_date` của trang kế hoạch) và ghi chú feed nói cùng ngày.

## Modifying: câu "feed giữ gì" (`heldNotes`, `heldFrom`, `Service.heldNow`, `Service.live`, migration 0023; POST-1)
- **Hàng feed của API** (`GET /feeds/sources`, Fetch now, `PUT /feeds/sources/{id}`): câu giữ gì đếm lúc đọc, trước ghi chú của lượt cuối; `feeds_source.error` và `feeds_fetch_log.error` của lượt tốt chỉ còn ghi chú của chính lượt. `pullOne` trả hàng như đã lưu; handler áp `live` một lần. Web (`FeedsSettings.tsx`, `NeedsInput.tsx`, `PrivacySection.tsx`) đọc cùng trường `error`, không đổi.
- **Chi phí đọc**: một feed bản phân phối đếm mọi hàng của nó (~0,1 s mỗi 100 000 hàng, Linux x86 dev box); đếm lại chỉ khi `last_fetch`/`rev` của một feed trong `heldFrom` đổi. Thêm nguồn ghi vào các bảng đó (ngoài lượt kéo hay sửa feed) thì phải thêm feed ấy vào `heldFrom` hoặc đổi khoá đệm (`TestHeldNotes_FollowTheData`).

## Modifying: hàng `open`, hàng tầng Alpine, `TierDistroRecords`/`TierDistro` (INV-27, migration 0024)

- **findings** (cmd/vedette `findingsFeeds.TierDistro` → `Feeds.TierDistro`, `plandistro.go`): `Records` có hàng fixed, not affected, open; `Known` (gói có dữ liệu) và `Loading` quyết định ba câu của mục bản phân phối (bản vá / "No fix from … yet" / "Check …'s security updates"); đổi chữ ký hay ý nghĩa `TierDistro` hay `DistroOpen` ⇒ sửa `distroWords`/`distroItems`, `cmd/vedette/distro_test.go` và các cài đặt giả `findings.Feeds.TierDistro` (`modules/findings/service_test.go`, `modules/mitigation/mitigation_test.go`). Bộ khớp KEV không đọc `open`: `Store.DistroFixes` lọc `fixed|not_affected`.
- **Bảng và nội dung**: migration 0024 dựng lại `feeds_distro_fix` (CHECK `status`, `fixed_version`); tăng phiên bản nội dung decoder (`contentversion.go`, INV-32) làm hộp đang chạy đọc lại `ubuntu-osv`, `debian-tracker`, `alpine-osv` một lần: kiểm `contentversion_test.go`.
- **`TierStamp`** thêm `alpine-osv`: lượt kéo của nó chạy lại lượt so đầy đủ của job `plan`.
- **Bộ nhớ/thời gian của lượt kéo Alpine** tăng vì giữ hàng tầng; đo lại bằng log `feeds: distribution pull parsed` khi đổi tập gói giữ.

## Modifying: `DeviceMerged`, `DeviceDeleted` (`devicelifecycle.go`, INV-33)
- **inventory** calls them inside its merge or delete transaction (core/lifecycle, registered in `cmd/vedette/devicelifecycle.go`): write only through `tx`; an error rolls the inventory's write back. `HaveSince` (findings) reads `device_id`: a change of what it holds after a merge or delete changes which device an answer scopes.

## Modifying: vendor-notation rows (`statedRows`, `exceptRows`, `Range.Generic`, `genericRowSQL`, `RangeScheme`), `core/versionscheme`, the catalogue's `scheme`/`record` (VN-1…3, BRIEF-3)
- **Every reader that matches** must read generic rows only (`Range.Generic`, `genericRowSQL`): a new query on `feeds_cve_range` for matching that forgets it compares "8.0" with "ESXi80U3d-24585383" and changes findings. `TestRecordRanges_ExploitedListView` and the findings golden tests hold the line.
- **findings (the one match pass)**: to use a vendor row, resolve the software's product (`productid`), take its `Scheme`, read the rows with `feeds.RangeScheme` and decide with `versionscheme.Judge` on `Scheme.Installed(version, build)`. ESXi needs the host's build (sensor-active states it in the OS line; the software row keeps the version and the update CPE only).
- **core/productid**: `scheme` must be a `versionscheme` name (the catalogue refuses to load otherwise); `record` names only feed `ByRangeName`, never inventory identity; `kev_shared` keeps a combined exploited-list name ("ESXi and Workstation") in a product's match keys without `ByKEV` resolving it to that product.
- **A change of `recordRanges`/`statedRows` output** must bump `recordReader`: records are not stored whole, so only a new whole-list read brings the new rows to boxes that read the records already.
- **sensor-active**: reads the ESXi build table through `versionscheme.ESXiBuild`; a new release is a row of `esxi-builds.json`.
- **web**: `CveRange.train`, `CveRange.fixed_release`, `CveBrief.fixes` (`contract.ts`, `briefSamples.ts`); the `vendor:` version types never count.
- **Storage**: about 0.6 extra rows per record read (650 rows for the 1 092 records of the count sample): a few MB on a full catalogue.

## Modifying: `ReadUrgencyFacts` / `feeds_signal` columns (urgency of findings)
- findings rates every finding from these facts each hour (cmd/vedette `urgencyFacts`); the selfcheck `findings.urgency_recomputed`
  reads them on its read-only handle. `FirstLoad` = the row was stored in its source's first pull (`stored_at` = the source's earliest)
  and is not dated after it: a source that rewrites `stored_at` on every pull would make every signal look new and send alerts.
- An exploited list's entry without its signal row is added as one (kind exploited, the list's source, its date added).

