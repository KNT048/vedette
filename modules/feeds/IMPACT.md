# Feeds — Change Impact Map

> Last verified: 2026-11-21 (mọi câu đã đối chiếu với code)

## Modifying: `feeds.Store` — `VulnByCVE(cve)`, `VulnsByProductKey(key)`, `HasTemplate(cve)`, `IOCLookup(value)`, `IOCListed()`, `IOCSubdomainsOn()`, `KevPairs()`, `HaveSince()`
- `HaveSince`: **findings** (`ServiceConfig.HaveSince`, INV-11 của findings) khớp phần mềm không phiên bản của sản phẩm đã trả lời "I have this", trên đúng thiết bị đã khai, chỉ từ `have_since`. `feeds.Inventory.AddManualDevice` trả id thiết bị ("" = không biết, phạm vi tắt). Đổi `have_since`/`device_id` = đổi số finding của thiết bị đó.
- **inventory** (`catalog`, khớp sản phẩm↔KEV theo khoá `vendorproject|product` chữ thường): đổi cách chuẩn hoá khoá = mọi khớp "Do you have it?" lệch.
- **mitigation** (`KevInfo` trong `FindingRow`, qua `findings`), **scan** (`has_template`), **mcp-server** (`lookup_cve`, `lookup_ioc`), **ai** (slot `cve.panels`, `lookup_ioc`), **reports** (`NewlyExploited`, mục KEV), **notify** (sự kiện `new_kev`), **logs** (`IOC*`).
- **logs** (`cmd/vedette/logsioc.go`) và **ai** (`lookup_ioc`, `cmd/vedette/ai.go`): `IOCLookup` quyết định điều chúng báo về một chỉ báo. `honeypot` và `response` không đọc feeds trực tiếp.

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

## Modifying: `ParseKEV`, `ParseEPSSCSV`, `ParseNucleiCVEs` (parser dựng sẵn)
- **feeds** job kéo ghi `feeds_kev` từ `KEVCatalog.Vulns`, `has_template` (hàng `feeds_signal` `public_exploit` của `nuclei-templates`) từ `NucleiCVEs.CVEs`, điểm EPSS từ `ParseEPSSCSV` của tệp hằng ngày của FIRST (`epss-all`: một GET, không gửi CVE nào; nguồn `epss.empiricalsecurity.com`, đã có trong PRIVACY.md luồng 1). Đổi trường `Vuln` = đổi cột `feeds_kev`; `Vuln.Key()` = `productid.Key` là khoá khớp của **inventory**.
- KEV và nuclei đọc khoá JSON đúng chữ hoa/thường, khoá lặp lấy giá trị cuối (như `JSON.parse` của SPA). nuclei `cves.json` là JSON Lines với `ID`, `Info`, `file_path`; không nhận mảng.
- Giới hạn riêng của nguồn dựng sẵn: `hagezi-tif` dùng `wildcard/tif.mini-onlydomains.txt` (kho hagezi đã bỏ thư mục `domains/`) với `MaxRows` 250 000; `ipsum` dùng `levels/3.txt` (IPsum mức ≥ 3, DATA_PIPELINE §2b) trong trần 50 000. Đổi URL/biến thể phải đo lại dòng và dung lượng.

## Modifying: `NVDPageURL`/`ParseNVD`, feed `nvd-kev`, `Store.KevAffected`, sự kiện `feeds.ranges.updated`

- `nvd_pull.go` (thử lại, tạm dừng/đi tiếp, dòng tiến độ `Service.live`), `Request.HeaderTimeout`/`slowHeaders` và `StatusError.RetryAfter` trong `fetch.go`, `lockFeed` gộp lượt kéo trùng (`busy`). Người đọc: `FeedsSettings.tsx` (feed `never` có `error` là dòng tiến độ: không kèm câu "Fetched at the next scheduled check"; Fetch now trả feed có `error` mà `status` không phải `error` ⇒ toast thông tin). Test: `nvd_pull_test.go`, `TestFeedLockIsContextAwareAndPruned`, `TestContract_INV8_*`, `feeds.test.tsx`.
- **findings** (qua `cmd/vedette` `findingsFeeds.Vulns`): mọi quyết định theo phiên bản dựa vào các mục này; đổi hình `AffectedRow` hay bỏ mục ⇒ finding đổi (`modules/findings` `TestGolden_*`).
- **cmd/vedette**: `feeds.ranges.updated` → `Inventory.RematchAll` lần đầu (trong `notify.WithBaseline`), sau đó `Inventory.RematchMany` với vendor/product của các CVE trong sự kiện (review H3); `findingsFeeds.Vulns` giữ danh sách theo `Store.MatchStamp` (đổi cách ghi `feeds_kev`/`feeds_cve_range` mà không đổi `last_fetch`, `updated_at` hay số hàng ⇒ findings đọc danh sách cũ).
- **PRIVACY.md** luồng 1, Settings → Privacy (`locales/en/core.json` `privacy.flow.1`), `THIRD_PARTY_NOTICES.md`, `sourcesMock.ts` (danh sách có sẵn: 27), export policy (`feeds_cve_range`, không xuất).

## Modifying: danh mục lỗ hổng (`feeds_cve`, `feeds_cve_metric`, `feeds_cve_range`, `feeds_kev`, `feeds_signal`, `feeds_epss_hist`, `feeds_nvd_cursor`, `ParseNVD`, `PickCVSS`, `retention`)
- **findings** (qua `cmd/vedette` `findingsFeeds`): `Vulns` (`KevVulns`, `KevAffected`, `RangesFromCVEOrg`, `KevPublished`), `KevInfo`, `CVSS`, `TierVulns`/`TierDistro` đọc các bảng này; đổi luật chọn CVSS, luật giữ hay thứ tự nguồn khoảng làm đổi finding: chạy golden test của findings và `cmd/vedette` (`TestReachability_910_Fixture`, các test wiring dùng `catalogue_seed_test.go`).
- **inventory** (`feedsKEV`: `KevProducts`, `KevCVEsByKeys`) đọc mục chủ của `feeds_kev`.
- **core** `export_policy.go`: mọi cột được phân loại (`TestExport_PolicyClassifiesEveryColumn`, danh sách bảng bỏ qua trong `data_test.go`); `docs/SCHEMA.sql` bằng `make schema`.
- **PRIVACY.md** luồng 1 và `locales/en/core.json` `privacy.flow.1`: các yêu cầu NVD (cửa sổ, đi qua toàn bộ danh sách, `cveId`).
- Thêm nguồn tín hiệu mới: ghi `feeds_signal` qua `putSignal`, luật `qualifies` của loại đó; CVE có tín hiệu đạt được giữ ở mọi tuổi và được lấy bản ghi NVD (`publicListedSQL`).

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
- **PRIVACY.md** luồng 1, Settings → Privacy (`privacy.flow.1.to`), `THIRD_PARTY_NOTICES.md` (mục chỉ mục exploit công khai), `sourcesMock.ts` + `conformance.test.ts` (27 feed có sẵn), `sources_test.go` (host `gitlab.com`, `codeload.github.com`), `heldnote.go` (`poc-in-github`: bao nhiêu CVE đạt).

## Modifying: `signal_claims.go`, `signal_vendor.go`, `signal_msrc.go`, `signal_csaf.go` (feeds `msrc`, `cisco-psirt`, `fortinet-psirt`)

- **Mẫu câu của hãng** (`claimForm`, `ciscoForms`, `fortinetForms`, `claimReader`): trường có cấu trúc (CSAF `exploit_status`, cờ Exploited của Microsoft) quyết trước; nếu không có, chỉ câu khớp đúng một mẫu câu thật của hãng mới là tuyên bố; câu nói về khai thác mà không khớp mẫu nào bị đếm "unclassified" trên nhật ký feed, không bao giờ đoán. Các nguồn văn bản sau này dùng cùng cách (mẫu riêng từng nguồn). Đổi mẫu ⇒ chạy lại `TestVendorClaims_CountsOfTheFrozenFixtures` (24 Cisco, 7 Fortinet, 0 khớp nhầm, 1 câu unclassified), `TestClaimForms_*` và `TestCSAFClaims_WorkIsLinearInTheDocument`.
- **findings** (urgency lớp 2, `Store.Signals`): hàng `exploited` của ba nguồn này `qualifies = 1` ngay; `first_seen` là ngày nguồn nói, hoặc lần hộp tự thấy khi ngày nguồn cũ hơn lần kéo tốt trước quá 24 giờ. `MatchStamp` chưa có ba feed này (như các feed public-exploit).
- **Danh mục** (`keepSetSQL`, `publicListedSQL`): CVE có tuyên bố được giữ ở mọi tuổi và có thể hỏi NVD/CVE record theo ID (danh sách công khai, mọi hộp hỏi như nhau).
- **PRIVACY.md** luồng 1, Settings → Privacy (`privacy.flow.1.to`), `THIRD_PARTY_NOTICES.md` (mục tuyên bố khai thác của hãng), `sourcesMock.ts` + `conformance.test.ts` (27 feed có sẵn), `sources_test.go` (host `api.msrc.microsoft.com`, `sec.cloudapps.cisco.com`, `filestore.fortinet.com`; chu kỳ 6 giờ), `heldnote_test.go`, `store.go` (tắt/bật lại ⇒ đọc lại từ đầu).

## Modifying: `signal_text.go`, `signal_apple.go`, `signal_seed.go`, `content/signals/seed.json`, `scripts/release/signalseed.go` (feeds `chrome-releases`, `android-bulletin`, `rapid7-blog`, `gti-blog`, nguồn `apple`)

- **Mẫu câu văn xuôi** (`proseForms`, `chromeForms`, `androidForms`, `appleForms`; `claimForm.subject`/`open`, `claimHedgeRE` trong `signal_claims.go`): đổi mẫu ⇒ chạy lại `TestTextClaims_CountsOfTheFrozenFixtures` (Rapid7 5, GTI 5, Chrome 10, Android 6, Apple 5; CVE-2026-123890 ngày 19/11), `TestProseForms_*`, `TestVendorClaims_CountsOfTheFrozenFixtures` (mẫu Cisco/Fortinet dùng chung bộ đọc).
- **Apple** đọc từ `feeds_cve.description` sau mỗi `writeRecords` và `writeNVDRecords`: đổi cột mô tả hay hai hàm này ⇒ `TestApple_ClaimsComeFromTheCatalogueDescriptions`.
- **Hạt giống**: định dạng do `ParseSeed` kiểm (hộp panic khi file hỏng, `TestSeed_TheReleaseSeedAndTheMerge` bắt trước); `scripts/release signal-seed` dùng `SeedFromFeed`, `SeedFromAndroidPage`, `SeedFromCSAF`, `MergeSeed` (đổi chữ ký ⇒ `scripts/release/signalseed_test.go`). Lần kéo đầu của `cisco-psirt`/`fortinet-psirt` cũng đọc hạt giống.
- **PRIVACY.md** luồng 1, `privacy.flow.1.to`, `THIRD_PARTY_NOTICES.md` (mục tuyên bố văn xuôi), `sourcesMock.ts` + `conformance.test.ts`, `sources_test.go` (host `chromereleases.googleblog.com`, `source.android.com`, `www.rapid7.com`, `cloudblog.withgoogle.com`; chu kỳ 6 giờ), `heldnote_test.go`, `brief.go` (`sourceNames`: tên của nguồn `apple`), `pull.go` (một dòng `case` gọi `buildTextClaims`).

## Modifying: `vulncheck.go`, feed `vulncheck-kev`, `isKEVSource`, the `source_id IN ('cisa-kev', 'vulncheck-kev')` reads

- **findings / inventory** (qua `cmd/vedette` `findingsFeeds`, `wiring`): `KevVulns`/`KevVulnsByCVE`/`KevCVEsByKeys`/`KevProducts`/`KevPairs` trả cả mục VulnCheck: finding mới của CVE nguồn `vulncheck-kev`, `required_action` mang câu nguồn. Bỏ nguồn thứ hai khỏi các truy vấn ⇒ finding của CVE chỉ VulnCheck có sẽ không còn khớp.
- **cve-org**: `recordDue` (qua `publicListedSQL`) và `kevRecordView` đọc cả hai nguồn để chọn CVE hỏi theo ID và CVE findings thấy.
- **reports** (`cmd/vedette/reports.go` `reportsKEV.Entries`): bỏ hàng không phải `cisa-kev` (không phân phối lại dữ liệu VulnCheck). Home/weekly/announced/EPSS chỉ đọc `cisa-kev`.
- **handlers_sources.go** `PUT /feeds/sources/{id}`: `api_key` chỉ cho feed BYOK, `isBYOK`, `saveFeedKey`; `toFeedDTO` hiện `auth.secret_last4` của feed BYOK. Contract: `FeedPatch.api_key` (contract.ts, `api/openapi.json`, `core/api/oas`).
- **cmd/vedette**: `Store.MatchStamp` thêm `vulncheck-kev`; export policy: `feeds_kev` xuất cả hàng `vulncheck-kev`.
- **PRIVACY.md** luồng 1, Settings → Privacy (`privacy.flow.1`), `THIRD_PARTY_NOTICES.md`, `sourcesMock.ts` (danh sách có sẵn: 27), `FeedsSettings.tsx`/`FeedDialogs.tsx` (`needsKey`, ô khoá).

## Modifying: `Fetcher.Fetch(ctx, Request)` (một GET tới đúng URL)
- **feeds** job kéo và `POST /feeds/sources/{id}/fetch`. Chuyển hướng: chỉ cùng host (`ErrRedirect`), không hạ https→http, tối đa 5 bước, bỏ `Referer`. Đổi chính sách này = đổi host nào hộp có thể liên lạc (INV-1, INV-13, `PRIVACY.md`).
- Kết nối (`NewClient`): luôn từ chối link-local (169.254/16, fe80::/10), địa chỉ metadata đám mây, unspecified và multicast; `http` chỉ tới IP riêng/loopback (tên nội bộ trỏ ra IP công cộng bị chặn); phân giải DNS một lần mỗi kết nối (chống DNS rebinding); không dùng proxy môi trường. `Fetcher.Client` tự cấp phải qua cùng bảo vệ này (chỉ dùng trong test).
- Header gửi đi cố định: `User-Agent: Vedette/<version>`, `Accept`, điều kiện `If-None-Match`/`If-Modified-Since`, xác thực của feed. Thêm header = đổi luồng dữ liệu ra (legal.md).

## Modifying: `State.RetryAt/Due/Record`, `IsStale`, `Backoff`, `Service.ScheduleOwner` (lịch kéo, INV-5/8/9) và `Judge`, `IOCKey`, `NewWhitelist`, `SightingOf` (IOC verdict, INV-12)
- Lịch của mỗi nguồn là hàng `core_schedule` `feeds.source:<id>` (`feedschedule.go`: owner `feeds.source` của `core/schedule`, chỉ khoảng, giới hạn `scheduleLimits` 1…168 giờ; `interval_hours` của API đọc từ đó, không lưu trong `feeds_source`). Khi đến hạn lịch không tự kéo: job `pull` (`PullEvery` 5 phút) so `State.Due` với lúc lịch đến hạn lần cuối (`scheduledDue`). Seed và `POST /feeds/custom` tạo lịch qua `ensureSchedule`; xoá feed riêng xoá lịch. Đổi giới hạn khoảng = đổi cả trình sửa lịch và hộp thoại feed.
- **feeds** job (lịch, trạng thái lỗi ở Settings → Feeds): mốc thời gian ở tương lai (đồng hồ sai) coi là đến hạn và cũ. **honeypot/logs/response** đọc `verdict`: đổi ngưỡng block/alert = đổi quy tắc phản ứng.
- `Judge` chuẩn hoá id nguồn (cắt khoảng trắng, chữ thường) và lấy cờ của nguồn dựng sẵn từ sổ đăng ký: nguồn gộp (`ipsum`, `hagezi-tif`) không bao giờ `block` một mình và không tính là nguồn thứ hai khi có nguồn gốc của nó; `tor-exit` chỉ thông tin, không tính vào `block`; nguồn CC0 (abuse.ch) đủ để `block`. Whitelist nhận `google.com`, `*.google.com`, `.google.com` như nhau, mục không hợp lệ là lỗi `ErrInvalidWhitelist`.
- IP riêng/đặc biệt và tên cục bộ/suffix công cộng không bao giờ có verdict (lớp bảo vệ thứ hai sau parser).
- `localName` gồm cả `testName` (`example.com|net|org` và tên dưới chúng, `*.test|example|invalid|localhost`): `Judge`/`IOCKey` không còn nhận các tên đó, nên **logs** (khớp DNS/kết nối, `cmd/vedette/logsioc.go`), **honeypot**, **response** và tìm kiếm không bao giờ khớp chúng; test của module khác dùng tên giả `*.example.*` làm IOC phải đổi sang tên khác (đã đổi `cmd/vedette/logs_test.go`).

## Modifying: `CheckURL`, `CheckKindFormat`, `CheckName`, `CheckAuth`, `Secret` (kiểm tra ở biên, INV-2/5/6)
- Handler `PUT /feeds/sources/{id}`, `POST/PUT /feeds/custom`; `Secret` bọc `core/secrets.Value` (không bao giờ in/log/JSON giá trị thật, SYS-4) cộng kiểm tra INV-6 và `Last4`.
- `ErrOwnAddress` bọc `ErrBlockedAddress`: mọi `errors.Is(err, ErrBlockedAddress)` vẫn đúng; `userError` kiểm nó trước để nói câu `ownText` ("That address is Vedette itself: …").
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
- `Store` read methods are the API of other modules: `VulnByCVE`, `VulnsByProductKey`, `HasTemplate`, `IOCLookup`, `IOCListed`, `IOCSubdomainsOn`, `KevPairs` (see the first sections) and, for the wiring, `KevProducts`, `KevCVEsByKeys`, `KevVulns`, `KevVulnsByCVE` (`kev_store.go`, `store_kev.go`; the CISA and VulnCheck lists). They feed `inventory.KEV` (catalog + CVE match) and `findings.Feeds` through adapters in `cmd/vedette/wiring.go`: changing what they return changes the catalog, the match events and the findings.

## Modifying: events `feeds.vuln.new_kev`, `feeds.vuln.updated`, `feeds.ioc.updated`, `feeds.fetch.failed`, `feeds.sync.baseline`, `feeds.ranges.updated` (`NewKEVEvent`, `VulnUpdatedEvent`, `IOCUpdatedEvent`, `FetchFailedEvent`, `SyncBaselineEvent`, `RangesUpdatedEvent`)
- **inventory** and **scan** listen to `new_kev`/`updated`; **notify** subscribes to `new_kev` and the baseline itself (`modules/notify/events.go`, `baseline.go`). The first pull of the CISA list (or of VulnCheck KEV) into an empty table publishes one `feeds.sync.baseline {source, count}` instead of one `new_kev` per entry (about 1,200 for the CISA list). `cmd/vedette/wiring.go` subscribes `inventory.RematchCVE` to `new_kev` and `inventory.RematchAll` to the baseline; a listener of `new_kev` that must also react to the first sync (scan) has to subscribe to the baseline too. **notify must send nothing for a baseline** nor for findings created by its re-match. Every `new_kev` of a CISA entry is also recorded in `feeds_kev.announced_at` in the pull's transaction: a change to which CVEs get `new_kev` must change `markAnnounced` with it, or **scan**'s catch-up (`Store.NewKEVSince`, through `cmd/vedette/scan.go` `scanKEV`) rescans a different set from the one the bus announced.

## Modifying: tables `feeds_*` (`migrations/sqlite/0001_feeds.sql`)
- `feeds_source.rev` is the pull-versus-edit race guard (every edit, switch on or off bumps it; a pull whose row changed in between writes nothing); `feeds_weekly_answer.device_added` keeps one "I have it" device per product.
- `feeds_source` carries the pull state and `secret_id` (core_secret) + `secret_last4`; deleting a custom feed deletes its secret, its `feeds_kev`, `feeds_signal` and `feeds_ioc_source` rows (indicators nobody else lists go too) and its `core_schedule` row (`purgeLoaded`, `deleteCustom`). `feeds_ioc` has no score, category or verdict column: derive them (`Judge`).

## Modifying: `winrel.go` (feed `windows-releases`, `winRelReleases`, `parseWinRelUpdates`, `LearnWindowsReleases`, tables `feeds_winrel`, `feeds_winrel_update`; INV-30)
- **core/winrel**: `Service.LearnWindowsReleases` hands the stored releases and monthly updates to `winrel.Learn` and `winrel.LearnUpdates` at start (`cmd/vedette/main.go` through `cmd/vedette/feeds.go` `learnWindowsReleases`, before agent-intake writes a device's OS row), when the service is ready, and after every good pull. Anything that reads `winrel` (agent-intake's OS row, the Windows rules of **findings** in `modules/findings/windows.go`: `winrel.ByBuild`, `winrel.Baseline`, `winrel.Learned`) sees a changed table at once: a change in what the feed derives (names, GA, line, target build) changes Windows findings on every box.
- **findings**: a change of the table publishes `feeds.ranges.updated` with every CVE that has a Windows row in `feeds_cve_range`, so the devices are matched again.
- **core** `export_policy.go`: `feeds_winrel` and `feeds_winrel_update` are exported (a restore names the same releases); **PRIVACY.md** flow 1 and `THIRD_PARTY_NOTICES.md` (Microsoft's release information pages: `learn.microsoft.com`), `sourcesMock.ts`, `winrel_test.go`.

## Disabling this module
- Trang chủ Hot/Weekly/Lookup/CVE trống ("off"); Settings → Feeds mất.
- `inventory`: danh mục chỉ còn bản đã giữ; không khớp mới. `findings`: không finding mới. `scan`: không tự quét lại. `notify`: không tin lỗ hổng mới (qua `findings`).
- `honeypot`, `logs`, `response`: không IOC mới, IOC cũ giữ.
- Dữ liệu `feeds_*` và cấu hình feed riêng giữ nguyên.

## Modifying: `feeds.BodyLimits`, `Vuln.links` (contract.ts)
- `cmd/vedette/modules.go` passes `feeds.BodyLimits` (operationId → bytes) to `server.Config`; removing the entry cuts `parse-test` samples back to 1 MiB while the GUI still promises 5 MB.
- `links` of `Vuln` are strings matching `^https?://` in contract.ts (so in `api/openapi.json` and `core/api/oas`), not `format: uri`: ogen decodes that with `ParseRequestURI` and turns `#anchor` into `%23anchor`. The backend stores only http(s) links (`kevLinks`) and `CvePage` renders only http(s) hrefs. Links are cleaned of the punctuation prose puts around them (`cleanLink`/`cleanLinks`) on write and on read: every reader (findings `KevInfo.links`, mcp `lookup_cve`, AI prompts, the CVE page) gets the cleaned form; the export of `feeds_vuln` dumps the stored JSON as it is.
- `conformance.test.ts` (`VITE_FEEDS_REAL_URL`) and `web/e2e/qa/feeds.spec.ts` (`FEEDS_REAL=1`) run against `make dev-api REAL=feeds`; changing a status or error code in the handlers means updating the script's `real:` overrides.
## Modifying: `feeds.KEVMirrorURL`, `Deps.KEVPrimary/KEVFallback`, `buildKEVBoth`, `Feed.answered_by`
- `buildKEVBoth` (kevcopies.go) asks both copies every check and keeps the newer (`kevKey`: plausible version, then release date; no version/date is not used; plausibility by the server's `Date` (`Response.Date`), 304 judged again from stored metadata, no count rule; `kevguard_test.go`, `kevlevels_test.go`). `copyWhy` words each copy's failure (stored in `feeds_source.kev_copies`, shown on Home via `fresh.copyFailed` and in Settings as the note), the both-down sentence and the alert text (`kevhonest_test.go`, `kevfallback_test.go`, `kevFreshness.test.tsx`). `KEVCatalog.ReleasedAt` is truncated to milliseconds so a held catalog compares equal to itself after `store.FormatTS`.
- `buildKEVBoth` is the only place both copies are asked; `raw.githubusercontent.com` for the CISA list is in `PRIVACY.md` flow 1 and Settings → Privacy (`core.json`): a new fallback host means both, in the same commit.
- `answered_by` (column of `feeds_source`) is in `contract.ts` (`Feed`), the mock (`sourcesMock.ts`), `api/openapi.json` and `core/api/oas`, and the Settings → Feeds status cell.

## Modifying: `Deps.Alert`, `ErrAlertOff`, `watchKEV`, `KEVStaleChecks` (INV-29)
- **cmd/vedette** `feeds.go` wires `Alert(ctx, id, title, text, critical)` to `newNotify(&d).Publish` (incident-kind notice, `critical` for the alert so critical-only channels get it, `high` for the recovery; no incident row; `notify.ErrModuleOff` becomes `ErrAlertOff`). Notify does not dedupe an incident-kind notice once sent, so the watch records the alert before queuing it. `RunPull` passes the CISA list as its own pull left it (`watchKEV(ctx, pulled)`): only the job's checks count toward the two in a row. A change of the rule (two both-failed checks in a row, six checks, the start of the count, enable/disable reset) is a product change. The state is the `stale_*` columns of the `cisa-kev` row of `feeds_source` (core `export_policy.go` lists them).

## Modifying: `FeedStatus.kev`, the retired-built-in cleanup in `SeedBuiltins`
- `kev` is in `contract.ts` (`FeedStatus`), the mock (`kevStatus()` in `sourcesMock.ts`, read by `mocks.ts`), `api/openapi.json`, `core/api/oas` and the Home title (`HomePage.tsx`, strings `home.kev*` in `feeds.json`). Readers: the Home sentence and, when the table is empty, the hot board; both take the same sentence from `useKevNotice()` in `HomePage.tsx`, so they cannot disagree. A non-empty board keeps its rows.
- Removing a built-in id from `builtinSources` deletes its row, listings and history on the next start (INV-16): never rename an id to "retire" it, and never reuse a retired id. `PRIVACY.md` flow 1, `core.json` (Settings → Privacy), `THIRD_PARTY_NOTICES.md` and DATA_MODEL.md's id list (report) follow in the same commit (legal.md).

## Modifying: `Fetcher.BoxAddrs`, `destGuard`, `ErrBoxAddrsUnknown` (INV-17)
- **cmd/vedette** `feeds.go` sets `fd.Fetcher.BoxAddrs = machineAddrs(&d)` and `fd.Fetcher.Self = vedetteSelf(&d)`; `cmd/vedette/ownaddr.go` `machineAddrs` is the one source of the machine's addresses for feeds, notify, logs and ai: what vedette-host reports (`notifyBoxAddrs`, `hostNetCache.SnapshotKnown`), the container's default gateways (`procGateways`), the `-hosts` literals, `VEDETTE_BIND_IP` and the host-alias names. A change to what it returns (known/unknown, /32 entries only) changes which pulls are refused. A `Fetcher` built without it still refuses loopback and the container's own interface addresses. `Fetcher.Gateway` is a hook that wiring does not set (the gateways are in `machineAddrs`).
- In-package tests set the unexported `Fetcher.allowLoopback`; a custom feed pointed at a loopback fake server is refused at connect.
- The save check refuses literal loopback/link-local/metadata/box addresses and `localhost` names (`blocked_host`), so what the GUI text says and what is saved agree; names are still judged only at pull.
- Pooled keep-alive connections are not re-checked on reuse: harmless, because a peer that was allowed cannot become the box. While the box addresses are unknown only global unicast addresses are dialled, and a pull refused for that reason (`ErrBoxAddrsUnknown`) is not recorded as a failure: no back-off, the feed stays due.
- The rule of Vedette itself is one rule in feeds, notify, logs and ai (`ownAddrs`: loopback and the container's own interfaces on every port, the machine's addresses on `vedettePorts` 8443, 8444, 8765, 514, 6514 only), with one sentence (`ownText`, the same text as `channel.OwnText`, logs `ownText`, `provider.OwnText` and the SPA's `OWN_TEXT` copies). `CheckDest` takes an `ownAddrs`. Changing the port list or the sentence means changing every copy; the GUI's `blockedFeedHost` returns `'own'` or `'blocked'`.
- `Fetcher.Self` (cmd/vedette `vedetteSelf`: the honeypot's decoys, read at every check) is Vedette itself on every port.

## Modifying: `PlatformChecker`
- Cài bởi `cmd/vedette/wiring.go` `feedsInventory.NotAffected` (inventory + `findings.PlatformRuledOut`); SPA trang CVE (`CvePage.tsx`) chỉ thấy danh sách ngắn hơn, không đổi hợp đồng.

## Modifying: feeds `epss-all`, `nvd-recent`, `ParseEPSSCSV`, `RecentPageURL`, `ParseNVD`, tables `feeds_epss`, `feeds_epss_baseline`, `feeds_nvd_cursor`
- **findings**: the plan's tiers read `feeds_epss` (EPSS at or above `EPSSLikely`, CVEs published in the last 12 months by `feeds_cve.published`) and the NVD entries of `feeds_cve_range` (origin `nvd`); both feeds are in `Store.MatchStamp` and `Store.TierStamp`, and a pull that changes exploited-list ranges publishes `feeds.ranges.updated`.
- **nvd-kev**: shares `nvdPage` and the gate `nvdSlot` (every NVD request of the two feeds is spaced by at least `nvdPause`); `nvd-recent` stops while `nvd-kev` is pulling (`Service.busy`) or waiting out NVD (`nvdResumeAt`).
- **core** (`modules/core/export_policy.go`): `feeds_epss`, `feeds_epss_baseline`, `feeds_nvd_cursor` are `skipAll` (public data, pulled again); `cmd/vedette` `TestExport_PolicyClassifiesEveryColumn` pins the list.
- **PRIVACY.md** flow 1 + Settings → Privacy (`locales/en/core.json` `privacy.flow.1`), `THIRD_PARTY_NOTICES.md` (FIRST EPSS, NVD rows), `sourcesMock.ts` + `conformance.test.ts`, `sources_test.go` (host `epss.empiricalsecurity.com`): both feeds are on by default, so every box calls them and fills 12 months of NVD on first start (about 105 requests; more than an hour when NVD answers 503).
- **TERMS.md**: the paragraph on the three tiers and the age rule.
- **nvd-recent state**: `RunPull` reads the `recent` row of `feeds_nvd_cursor` on every check while the feed is on; a cursor that is not `done` for the feed's address makes it due at the next check (only the back-off after a failure holds it back), so deleting the cursor refills at the next check. `Service.recent` (`*recentProgress`) is the progress line written by `live`, `recentAt` holds `RunPull` back, `nvdSlot` keeps `nvdBookedAt`. `Service.live` takes the `ctx` (it reads the cursor and the CVE count when no pull is running, also when the status is an error); callers: `GET /feeds/sources`, `POST /feeds/sources/{id}/fetch`, `pull`. The progress line travels in `error`, as for the first fill.
- `Deps.Zone` (the organization's time zone, `core/orgtime`) writes the times of the CISA list alerts (`kevStaleNotice`, `kevFreshNotice`, `orgtime.StampZone`: with the zone's abbreviation, "UTC" when it cannot be read). `feeds_epss_baseline.score_date` holds FIRST's day of the scores; `TierStatus.EPSSDate` reads it, so findings (`epss_date` of the plan page) and the feed note name the same day.

## Modifying: ngày công bố KEV và dữ liệu tầng cho trang (INV-25)
- **findings** (qua `cmd/vedette/wiring.go` `findingsFeeds`): `Store.KevPublished` → `Vuln.Published` (luật tuổi: KEV công bố hơn 12 tháng không thành finding khi chỉ khớp tên sản phẩm; finding mở loại đó đóng) và `KevInfo.published`; `Store.TierStatus` → `findings.Feeds.TierStatus` cho `GET /findings/plan`. Đổi ý nghĩa ngày (ví dụ dùng `dateAdded`) là đổi finding của mọi hộp; thiếu ngày luôn phải nghĩa là "gần đây". Ngày là `feeds_cve.published` (bản ghi NVD trước, CVE.org khi NVD chưa cho ngày).
- **nvd-kev**: lượt kéo đầy đủ (`buildNVD`, ~18 trang) chạy khi chưa có CVE nào của danh sách khai thác mà NVD đã trả lời (`kevNVDCount`) hoặc lần tốt cuối cũ hơn `nvdIncrementalDays`. Trong lúc NVD trả 503 lượt kéo đầy đủ tạm dừng và đi tiếp ở lượt sau (chỉ trong bộ nhớ: khởi động lại thì bắt đầu lại), và trong lúc đó không có lượt cập nhật, nên khoảng của mục KEV mới chờ tới khi lượt đầy đủ xong. Test fixture NVD phải mang `published`.
- **exposure** (`cmd/vedette/exposurematch.go`): CVE KEV cũ chỉ khớp tên sản phẩm thành dòng "ruled out" kèm lý do thay vì dòng CVE.
- **core export** (`export_policy.go`): `feeds_cve` là `skipAll` (dữ liệu công khai kéo lại được).
- **`Store.PublishedOf(ctx, cves)`**: một truy vấn mỗi `publishedChunk` = 500 CVE (`json_each`, như `CVSSOf`), không một truy vấn mỗi CVE; `GET /findings` và `GET /findings/summary` hỏi mọi CVE mở qua `findingsFeeds.KevInfo`. Kết quả không đổi (`TestPublishedOfReadsEveryAskedCVEAcrossChunks`).
- **SPA**: `CveDetail.published`, `TierCve` (`web/src/features/feeds/contract.ts`, `CvePage.tsx`, `TierCvePage.tsx`, mock `web/src/mocks/tiers.ts`).

## Modifying: dữ liệu tầng (`Store.TierRecords`, `Store.TierStamp`, `Store.MatchStamp`)
- **findings** đọc `Store.TierRecords` qua `cmd/vedette` `findingsFeeds.TierVulns` (trả rỗng khi module feeds tắt) và `Store.MatchStamp` qua `findingsFeeds.MatchStamp`; `MatchStamp` gồm `epss-all` và `nvd-recent` (một lượt kéo của chúng cũng làm mới bộ nhớ đệm danh sách KEV của findings/exposure: một lần đọc lại, không đổi kết quả). `Store.TierStamp` cho job `plan` của findings.
- **Feed tầng bật mặc định**: hộp mới gọi `epss.empiricalsecurity.com` mỗi ngày và nạp 12 tháng NVD; `PRIVACY.md` luồng 1 và Settings → Privacy (`web/src/locales/en/core.json`) nói "on by default"; mock `web/src/features/feeds/sourcesMock.ts`.


## Modifying: điểm CVSS (`metricsOf`, `NVDRecord.Metrics`, `PickCVSS`, `Severity`, `Store.CVSSOf`, bảng `feeds_cve_metric`; INV-28)
- **findings** (qua `cmd/vedette/wiring.go` `findingsFeeds.CVSS`): `FindingRow.cvss` trên `GET /findings`, `GET /findings/{id}` và các câu trả lời `FindingDetail` của `mitigation` (findings INV-22); đổi luật chọn (phiên bản, Primary/Secondary, vector bắt buộc, làm tròn) = đổi điểm khách thấy trên mọi finding và trên trang chủ (phần dashboard đọc cùng trường).
- **nvd-kev / nvd-recent / cve-org** (INV-19, INV-24, INV-20): `metrics` là `json.RawMessage`, giải mã riêng (`metricsOf`): một `metrics` hỏng không bao giờ làm hỏng trang hay bản ghi (như với khoảng phiên bản và ngày). Mức và điểm của tầng 3 (`withSeverity`) và của finding cùng đọc `PickCVSS`.
- **core** (`modules/core/export_policy.go`): `feeds_cve_metric` là `skipAll`; `cmd/vedette` `TestExport_PolicyClassifiesEveryColumn`.
- **THIRD_PARTY_NOTICES.md** hàng NVD (điểm CVSS, vector) và hàng FIRST CVSS (mọi điểm kèm vector; ghi công "CVSS is owned by FIRST and used by permission", cũng trong ⓘ của điểm). Không đổi PRIVACY.md: không luồng ra mới.

## Modifying: câu "feed giữ gì" (`heldNotes`, `heldFrom`, `Service.heldNow`, `Service.live`; POST-1)
- **Hàng feed của API** (`GET /feeds/sources`, Fetch now, `PUT /feeds/sources/{id}`): câu giữ gì đếm lúc đọc, trước ghi chú của lượt cuối; `feeds_source.error` và `feeds_fetch_log.error` của lượt tốt chỉ còn ghi chú của chính lượt. `pullOne` trả hàng như đã lưu; handler áp `live` một lần. Web (`FeedsSettings.tsx`, `PrivacySection.tsx`) đọc cùng trường `error`, không đổi.
- **Chi phí đọc**: một feed bản phân phối đếm mọi hàng của nó (~0,1 s mỗi 100 000 hàng); đếm lại chỉ khi `last_fetch`/`rev` của một feed trong `heldFrom` đổi. Thêm nguồn ghi vào các bảng đó (ngoài lượt kéo hay sửa feed) thì phải thêm feed ấy vào `heldFrom` hoặc đổi khoá đệm (`TestHeldNotes_FollowTheData`).

## Modifying: hàng `open`, hàng tầng Alpine, `TierDistroRecords`/`TierDistro` (INV-27)
- **findings** (cmd/vedette `findingsFeeds.TierDistro` → `Feeds.TierDistro`, `plandistro.go`): `Records` có hàng fixed, not affected, open; `Known` (gói có dữ liệu) và `Loading` quyết định ba câu của mục bản phân phối (bản vá / "No fix from … yet" / "Check …'s security updates"); đổi chữ ký hay ý nghĩa `TierDistro` hay `DistroOpen` ⇒ sửa `distroWords`/`distroItems`, `cmd/vedette/distro_test.go` và các cài đặt giả `findings.Feeds.TierDistro` (`modules/findings/service_test.go`, `modules/mitigation/mitigation_test.go`). Bộ khớp KEV không đọc `open`: `Store.DistroFixes` lọc `fixed|not_affected`.
- **Bảng**: `feeds_distro_fix` (CHECK `status`, `fixed_version`).
- **`TierStamp`** gồm `alpine-osv`: lượt kéo của nó chạy lại lượt so đầy đủ của job `plan`.
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
  reads them on its read-only handle. `FirstLoad` = the row was stored in its source's first good pull (by `feeds_fetch_log`, else the source's earliest `stored_at`)
  and is not dated after it: a source that rewrites `stored_at` on every pull would make every signal look new and send alerts.
- An exploited list's entry without its signal row is added as one (kind exploited, the list's source, its date added). A feed that is
  off (other than an exploited list) contributes no signal; its rows stay for when it is on again.
- The first load ends at the source's first good pull in `feeds_fetch_log` (else its earliest row); `UrgencyReader` caches it until
  `feeds_source` changes (a pull or a switch), so a device's match write does not scan every signal row.

