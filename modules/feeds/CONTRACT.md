# Feeds Contract

> Tier: standard · Story: S-FEED-1…5 · Last verified: 2026-11-09 (WP-20 + nối module: `inventory`, bus sự kiện, đường cơ sở D-78, đọc cho `inventory`/`findings`)

Nguồn hành vi: `web/src/features/feeds/{contract,defaults,parsers,sourcesMock}.ts`. Nguồn dữ liệu: `PRIVACY.md` luồng 1, `docs/DATA_PIPELINE.md` §0, §3.

## Invariants
- **INV-1**: Hộp chỉ kéo từ nguồn đã khai báo: feed có sẵn (bật) và feed riêng (bật); mỗi lần kéo là HTTPS GET tới đúng `Feed.url`, không gửi dữ liệu khách (D-36, SYS-7). Không có request dữ liệu feed nào tới GitHub của dự án. `TestContract_INV1_OnlyDeclaredSources`
- **INV-2**: URL feed: `https`; `http` chỉ cho host nội bộ (10/8, 172.16/12, 192.168/16, 127/8, `localhost`, `.local`, `.lan`, `.internal`, `.localhost`); còn lại 400 `invalid_url`. Trần mặc định cho mọi lần kéo và mọi feed riêng: 5 000 000 byte (vượt → 413 `too_large` ở `parse-test`), 50 000 dòng (`truncated:true`) và trần thời gian (60 s). Ngoại lệ duy nhất là trần dòng riêng của nguồn dựng sẵn (`Source.MaxRows`): `hagezi-tif` (biến thể `tif.mini`) 100 000 dòng; mọi nguồn dựng sẵn khác giữ 50 000 dòng (`ipsum` dùng `levels/3.txt`). Trần 5 000 000 byte áp cho tất cả. EPSS không tải một tệp lớn: lấy từ `api.first.org` theo lô ≤ 100 CVE (mỗi câu trả lời ≤ 50 000 dòng). Ô dài hơn 4096 byte không chạy regex của khách; regex biên dịch quá 1000 lệnh bị từ chối khi lưu. Chuyển hướng chỉ theo cùng host (khác host bị từ chối), không hạ https→http, tối đa 5 bước. Lúc kết nối: luôn từ chối link-local (169.254/16, fe80::/10) và địa chỉ metadata đám mây; `http` chỉ tới IP riêng/loopback (chống DNS rebinding).
- **INV-3**: Parser fail-closed (SYS-6): dòng không hợp lệ bị loại, đếm theo lý do (`rejected`, `reasons[]`, `rejects[]` 20 dòng đầu); không dòng nào lọt vào `feeds_*` khi bị loại; nội dung feed không bao giờ được diễn giải thành lệnh/HTML. Fuzz parser 60 s trong CI. `rejects[]` giữ 20 dòng đầu (SPA phải theo); `reasons[]` nhóm theo mẫu thông điệp, tối đa 50 nhóm + `other`. Văn bản feed là văn bản thuần không tin cậy: ký tự điều khiển, C1 và ký tự định dạng Unicode (bidi, zero-width) bị loại khỏi định danh/khoá và bị bỏ khỏi văn bản tự do; bên dùng (notify, reports, ai, SPA) phải escape theo môi trường của mình.
- **INV-4**: Feed có sẵn không xoá được (chỉ bật/tắt, `interval_hours`, `url` mirror; `url:""` đặt lại mặc định). Feed riêng: thêm/sửa/bật/tắt/xoá; xoá feed riêng xoá luôn bản ghi nó đã nạp.
- **INV-5**: `interval_hours ∈ [1,168]`; tên feed duy nhất không phân biệt hoa thường; định dạng phải hợp loại: `vulnerabilities ⊂ {json,csv,rss}`, `ioc ⊂ {json,csv,rss,stix,lines}`.
- **INV-6**: Bí mật xác thực feed (`bearer|header|basic`) qua `core/secrets`, API chỉ trả `secret_last4`; secret ≥ 8 ký tự, không khoảng trắng; sửa feed mà bỏ trống secret thì giữ secret cũ (SYS-4).
- **INV-7**: `POST /feeds/parse-test` không ghi `feeds_*` và không gọi mạng (dùng `sample` của người gọi hoặc mẫu dựng sẵn theo định dạng).
- **INV-8**: `POST /feeds/sources/{id}/fetch` trên feed tắt → 409 `feed_disabled`. Kéo lỗi: ghi `status:error`, `error`, lùi thời gian thử lại, không làm sập job; hiện ở Settings → Feeds (D-37).
- **INV-9**: Dữ liệu không quá hạn kéo quá 60 phút (tuổi ≤ `interval_hours` + 60 phút) khi nguồn bật và truy cập được; `FeedStatus.generated_at` và `sources[].fetched_at` luôn hiển thị (S-FEED-1). Test bằng đồng hồ giả. Cũ nghĩa là quá `interval_hours` + 60 phút; mốc thời gian ở tương lai (đồng hồ sai) coi là đến hạn và cũ.
- **INV-10**: Hoạt động không cần module khác: `inventory` tắt ⇒ `HotRow.you_have=null`, `matched_assets=[]`, `FeedStatus.inventory_on=false`; không lỗi.
- **INV-11**: `you_have`: `yes` nếu có tài sản khớp chắc (`how=yes`); `maybe` nếu chỉ khớp theo hãng cho sản phẩm "Multiple products"; còn lại `no`.
- **INV-12**: IOC: `verdict=block` khi ≥ 2 nguồn độc lập hoặc 1 nguồn loại DROP/CC0; `alert` khi 1 nguồn; trừ whitelist theo domain (không theo IP CDN); không bao giờ mở rộng IP thành /24 (DATA_PIPELINE §3). IP riêng/loopback/link-local/multicast/CGNAT/tài liệu/dành riêng (kể cả dạng IPv4-mapped) và tên cục bộ (`.local`, `.lan`, `.internal`, `.arpa`, `.test`, `.example`…), tên một nhãn, suffix công cộng thường gặp không bao giờ thành IOC (parser và `Judge` đều kiểm). Nguồn gộp (IPsum, hagezi) không `block` một mình và không tính là nguồn thứ hai cùng nguồn gốc của nó; Tor exit chỉ mang tính thông tin, không tính vào `block`.
- **INV-13**: Mỗi host nguồn (có sẵn và feed riêng) xuất hiện trong Settings → Privacy và `PRIVACY.md` luồng 1 (legal.md).
- **INV-14**: Câu "This week, in short" sinh từ template trên hộp, không cần AI của khách, nhãn nguồn từng dòng; `answer=have` tạo đúng một thiết bị khai tay qua `inventory`; `not_relevant` chỉ lưu câu trả lời.

## Preconditions / Postconditions
- **PRE-1** (`Fetch(feedID)`): feed bật, URL qua INV-2. **POST-1**: `feeds_source.last_fetch/records/status/error` cập nhật; sự kiện `feeds.vuln.new_kev` chỉ phát cho CVE chưa từng có.
- **PRE-2** (`GET /feeds/hot`): `window ∈ {24h,7d}` (400 `bad_window`). **POST-2**: hàng xếp theo `you_have=yes` trước, rồi số CVE, rồi `max_epss`.
- **PRE-3** (`GET /feeds/cve/{id}`): CVE nằm trong dữ liệu; nếu không → 404 `not_in_kev`. **POST-3**: kèm `matched` (null khi `inventory` tắt).
- **PRE-4** (`GET /feeds/search`): `q` 1…200 ký tự (400 `empty_query`). **POST-4**: một trong `cve|ioc|text`; trả từ DB cục bộ, không gọi mạng.
- **PRE-5** (`POST /feeds/custom`, `PUT /feeds/custom/{id}`): `admin`, qua INV-2/5/6. **POST-5**: feed lưu cùng `parser`; `core_audit` ghi (không ghi secret).

## Forbidden
- **FORBID-1**: Phân phối dữ liệu qua GitHub/Cloudflare, builder trung tâm (D-36).
- **FORBID-2**: Gửi dữ liệu khách (tài sản, log) tới nguồn feed. Chỉ IP của hộp lộ trong log nguồn.
- **FORBID-3**: Kéo nguồn không khai báo hoặc nguồn bị tắt.
- **FORBID-4**: Đọc/ghi bảng `inv_*` trực tiếp; so khớp tài sản qua interface của `inventory`.

## Dependencies
- **DEPENDS ON**: `core` (jobs, secrets, audit). Tuỳ chọn: `inventory` (`you_have`, "I have it").
- **DEPENDED ON BY**: `inventory` (danh mục KEV, khớp), `findings` (KevInfo), `mitigation` (gói theo CVE), `scan` (`has_template`, KEV mới), `notify` (qua `findings`), `reports`, `ai` (slot `cve.panels`), `mcp-server` (`lookup_cve`, `lookup_ioc`), `honeypot`/`logs`/`response` (IOC, nhóm B).

## Endpoints owned (role tối thiểu)
| Route | Vai |
|---|---|
| `GET /feeds/status`, `/feeds/hot`, `/feeds/weekly`, `/feeds/cve/{id}`, `/feeds/search`, `/feeds/sources` | viewer |
| `POST /feeds/weekly/{id}` | operator |
| `PUT /feeds/sources/{id}`, `POST /feeds/sources/{id}/fetch`, `POST /feeds/custom`, `PUT,DELETE /feeds/custom/{id}`, `POST /feeds/parse-test` | admin |

## Tables owned (`feeds_`)
`feeds_source` (cấu hình feed có sẵn + feed riêng, parser JSON, `secret_id` + `secret_last4`, trạng thái kéo: `last_fetch`, `last_success`, `failures`, `records`, `status`, `error`, `etag`, `last_modified`, `catalog_version`), `feeds_vuln`, `feeds_template` (CVE có mẫu nuclei), `feeds_ioc`, `feeds_ioc_source` (feed nào đang liệt kê chỉ báo nào, kèm `confidence`), `feeds_fetch_log`, `feeds_weekly_answer`.

## Triển khai (WP-20)
- **Một chủ cho mỗi CVE**: `feeds_vuln.cve` là PK; `cisa-kev` thắng feed riêng (feed riêng không đè hàng của feed khác); CVE rời KEV vẫn giữ. Feed riêng loại `vulnerabilities` thay hàng của mình ở mỗi lần kéo (CVE không còn trong danh sách thì xoá); thiếu hãng/sản phẩm thì ghi `Unknown`, thiếu ngày thì lấy ngày thấy lần đầu.
- **IOC**: `verdict`, `score` (= độ tin cậy cao nhất mà một feed đưa ra; feed không đưa thì 0,5) và `category` (theo nguồn, tối đa 2, "Custom feed" cho feed riêng) tính khi đọc từ `feeds_ioc_source` qua `Judge`; không lưu. Chỉ báo không còn feed nào liệt kê bị xoá sau 30 ngày. Mỗi lần kéo feed IOC là bản chụp đầy đủ: mục biến mất khỏi feed thì mất khỏi `feeds_ioc_source`; bản kéo không có dòng nào hợp lệ là lỗi và không xoá gì. Whitelist domain chưa có nguồn cấu hình (không có thao tác, không có story): `Judge` nhận danh sách rỗng.
- **Kéo**: job `pull` chạy mỗi 5 phút, mỗi feed bật và đến hạn theo `State.Due` (khoảng riêng + lùi sau lỗi) được kéo lần lượt, KEV trước, EPSS sau. KEV có CVE mới thì EPSS được kéo ngay trong lượt đó. Kết quả mỗi lần kéo ghi trong **một** giao dịch (dữ liệu + trạng thái + `feeds_fetch_log`); lỗi hoặc dữ liệu hỏng chỉ ghi trạng thái, dữ liệu cũ giữ nguyên. EPSS: hai lượt theo lô 100 CVE (hôm nay và 7 ngày trước), một lô lỗi là cả lần kéo lỗi. Kéo có điều kiện (`If-None-Match`/`If-Modified-Since`) chỉ sau một lần kéo thành công và chỉ cho địa chỉ hiện tại. Chỉ lần kéo tay (`POST …/fetch`) ghi `core_audit` (`feeds.fetch`).
- **Sự kiện** (qua `feeds.Publisher`, nil = bỏ): `feeds.vuln.new_kev` cho mỗi CVE chưa từng có, **trừ lần kéo đầu của danh sách CISA vào bảng rỗng: đó là đường cơ sở, chỉ phát một `feeds.sync.baseline {source, count}` (D-78)**; "rỗng" là chưa có hàng `cisa-kev` nào, nên feed riêng có trước không làm mất đường cơ sở; kéo lỗi rồi kéo lại vẫn là đường cơ sở; `feeds.vuln.updated` khi trường KEV đổi hoặc `has_template` đổi, `feeds.ioc.updated`, `feeds.fetch.failed`. Kiểu payload: `NewKEVEvent`, `SyncBaselineEvent`, `VulnUpdatedEvent`, `IOCUpdatedEvent`, `FetchFailedEvent`.
- **Đọc cho module khác** (`Store`, chỉ hàng `cisa-kev`): `KevProducts` (cặp hãng/sản phẩm + số CVE + version của tập hàng, cho `inventory.KEV.Products`), `KevCVEsByKeys` (khoá `vendor|product`; mục "Multiple products" của hãng khớp mọi khoá của hãng đó, cho `inventory.KEV.CVEs`), `KevVulns` và `KevVulnsByCVE` (cho `findings.Feeds`). `cmd/vedette/wiring.go` đổi sang kiểu của từng cổng. Danh sách CISA chưa có khoảng bị ảnh hưởng NVD nên `findings` chỉ khớp theo sản phẩm.
- **Inventory**: `feeds.Inventory` (`MatchProducts`, `AddManualDevice(ctx, tx, …)`) do `inventory` cài qua `cmd/vedette/wiring.go` (`feedsInventory`); `nil` hoặc module tắt ⇒ INV-10. `answer=have` gọi `AddManualDevice` trong giao dịch của feeds, đúng một lần cho mỗi sản phẩm (bấm lần hai không tạo thêm). `Inventory` có thể cài thêm `TxSettler.Settle(ctx, tx, committed)`: feeds gọi nó sau khi giao dịch kết thúc (commit hay rollback) để `inventory` phát sự kiện của thiết bị chỉ khi đã commit (`writeDeclaring`).
- **Khác `contract.ts`/mock** (có chủ đích): secret rỗng khi sửa = giữ secret cũ (mock báo lỗi); `window`, `answer`, thân sai dạng và CVE id viết thường bị máy chủ sinh từ OpenAPI chặn trước handler nên trả `400 invalid` thay vì `bad_window`/`bad_answer`/`invalid_body` (handler vẫn giữ kiểm tra riêng); "This week" không loại riêng `CVE-2022-27593` (đó là chi tiết của mock); ngày trong câu dùng `2 Jan` (mock dùng `toLocaleDateString('en-GB')`, có thể ra `Sept`).
- **Feed riêng không phải KEV (sửa sau rà soát)**: `feeds.vuln.new_kev` và `feeds.vuln.updated` chỉ phát cho hàng của `cisa-kev` (kể cả khi `cisa-kev` lần đầu liệt kê một CVE mà feed riêng có trước: đó là lần thấy KEV đầu tiên); feed riêng không phát sự kiện nào. EPSS, `KevPairs` và câu "This week" chỉ dùng hàng `cisa-kev` (CVE của feed riêng không bao giờ gửi tới `api.first.org`, không bao giờ được mô tả là "added to the CISA list"); hot, search, CVE vẫn hiện cả hàng của feed riêng.
- **Chống chạy đua**: `feeds_source.rev` tăng mỗi lần sửa/bật/tắt; trong giao dịch ghi của một lần kéo, hàng được đọc lại: xoá giữa chừng → `ErrNotFound` (404 ở `POST …/fetch`), sửa hoặc tắt giữa chừng → bỏ kết quả, không ghi gì. Bật lại một feed xoá back-off. Khoá kéo theo feed nhận ctx và được dọn khi không còn ai giữ/chờ.
- **Lỗi lưu**: nếu giao dịch ghi kết quả lỗi (không phải ctx), một giao dịch nhỏ thứ hai ghi `status:error` + câu "The result could not be stored…" để có back-off và hiện ở Settings.
- **Giao dịch**: mỗi kết quả kéo một giao dịch (toàn có hoặc toàn không); khoá ghi giữ trong lúc áp dụng (trần INV-2: 50 000 dòng, hagezi 100 000 dòng, cỡ 1-2 giây), ctx được kiểm mỗi 256 dòng, dữ liệu cũ đọc một lần trước vòng lặp.
- **Ingest**: vendor/product dài quá 200 ký tự (hoặc khoá quá 500) bị loại hàng kèm lý do; ngày ở tương lai của feed vulnerability thành hôm nay (như `first_seen` của IOC). `answer=have` ghi `device_added` (một thiết bị cho mỗi sản phẩm, mọi lần trả lời sau không tạo thêm); trả lời `have` lúc `inventory` tắt thì job kéo tạo thiết bị khi `inventory` bật lại (người thực hiện ghi `system`). Lỗi của `Inventory.MatchProducts` thành `you_have:null` (INV-10). `GET /feeds/status` chưa kéo lần nào trả `generated_at` = 1970-01-01 (không giả làm mới); `parse-test` với `sample:""` cho 0 bản ghi; tìm văn bản trả tối đa 200 hàng, so khớp chữ thường ASCII.
- **Giới hạn**: thân yêu cầu tối đa 1 MiB (`core/server`), nên `parse-test` thực tế nhận mẫu < 1 MiB dù contract cho 5 MB (handler vẫn trả 413 `too_large` quá 5 MB). Danh sách `GET /feeds/sources` và `/feeds/status` trả nguyên `url` cho vai viewer: feed riêng không nên đặt token trong chuỗi truy vấn (dùng `auth`).

## Events
- **Phát**: `feeds.sync.baseline {source, count}` (một lần, lần kéo đầu vào bảng rỗng, D-78; thay cho từng `new_kev` của lần đó), `feeds.vuln.new_kev {cve, vendor, product, has_template, date_added}`, `feeds.vuln.updated {cves[]}`, `feeds.ioc.updated {feed_id, added, removed}`, `feeds.fetch.failed {feed_id, error}`.
- **Nhận**: không (chạy theo `core/jobs`).

## Behaviour khi tắt (SYS-5)
Không route `/feeds/*`, không job kéo, dữ liệu giữ. Trang chủ "Hot" hiện "Feeds is off". `inventory` ngừng khớp mới; `scan` ngừng tự quét lại; `honeypot`/`logs` mất IOC mới.

## Story và quyết định
S-FEED-1…5. D-2 BYOK feed cấm thương mại; D-30 danh mục KEV; D-36 hộp tự kéo; D-37 feed riêng + parser.

## Không khớp / câu hỏi mở
- S-FEED-2 và DATA_PIPELINE §3 ghi câu tiếng Việt; D-28 chỉ tiếng Anh, GUI dùng tiếng Anh. Hợp đồng theo D-28.
- D-37 nói nút Thử "kéo mẫu"; `contract.ts` chỉ dùng mẫu của người gọi/mẫu dựng sẵn (INV-7).
- Feed BYOK (VulnCheck, AbuseIPDB…) chưa có trong GUI (`DEFS`) và `contract.ts`.
- `MODULES.md` chưa liệt kê S-FEED-4/5.
