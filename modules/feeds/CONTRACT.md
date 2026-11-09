# Feeds Contract

> Tier: standard · Story: S-FEED-1…5 · Last verified: 2026-11-09 (docs-first, chưa có code)

Nguồn hành vi: `web/src/features/feeds/{contract,defaults,parsers,sourcesMock}.ts`. Nguồn dữ liệu: `PRIVACY.md` luồng 1, `docs/DATA_PIPELINE.md` §0, §3.

## Invariants
- **INV-1**: Hộp chỉ kéo từ nguồn đã khai báo: feed có sẵn (bật) và feed riêng (bật); mỗi lần kéo là HTTPS GET tới đúng `Feed.url`, không gửi dữ liệu khách (D-36, SYS-7). Không có request dữ liệu feed nào tới GitHub của dự án. `TestContract_INV1_OnlyDeclaredSources`
- **INV-2**: URL feed: `https`; `http` chỉ cho host nội bộ (10/8, 172.16/12, 192.168/16, 127/8, `localhost`, `.local`, `.lan`, `.internal`, `.localhost`); còn lại 400 `invalid_url`. Mỗi lần kéo có trần kích thước 5 000 000 byte (vượt → 413 `too_large` ở `parse-test`), trần 50 000 dòng (`truncated:true`) và trần thời gian.
- **INV-3**: Parser fail-closed (SYS-6): dòng không hợp lệ bị loại, đếm theo lý do (`rejected`, `reasons[]`, `rejects[]` 20 dòng đầu); không dòng nào lọt vào `feeds_*` khi bị loại; nội dung feed không bao giờ được diễn giải thành lệnh/HTML. Fuzz parser 60 s trong CI.
- **INV-4**: Feed có sẵn không xoá được (chỉ bật/tắt, `interval_hours`, `url` mirror; `url:""` đặt lại mặc định). Feed riêng: thêm/sửa/bật/tắt/xoá; xoá feed riêng xoá luôn bản ghi nó đã nạp.
- **INV-5**: `interval_hours ∈ [1,168]`; tên feed duy nhất không phân biệt hoa thường; định dạng phải hợp loại: `vulnerabilities ⊂ {json,csv,rss}`, `ioc ⊂ {json,csv,rss,stix,lines}`.
- **INV-6**: Bí mật xác thực feed (`bearer|header|basic`) qua `core/secrets`, API chỉ trả `secret_last4`; secret ≥ 8 ký tự, không khoảng trắng; sửa feed mà bỏ trống secret thì giữ secret cũ (SYS-4).
- **INV-7**: `POST /feeds/parse-test` không ghi `feeds_*` và không gọi mạng (dùng `sample` của người gọi hoặc mẫu dựng sẵn theo định dạng).
- **INV-8**: `POST /feeds/sources/{id}/fetch` trên feed tắt → 409 `feed_disabled`. Kéo lỗi: ghi `status:error`, `error`, lùi thời gian thử lại, không làm sập job; hiện ở Settings → Feeds (D-37).
- **INV-9**: Dữ liệu ≤ 60 phút tuổi khi nguồn bật và truy cập được; `FeedStatus.generated_at` và `sources[].fetched_at` luôn hiển thị (S-FEED-1). Test bằng đồng hồ giả.
- **INV-10**: Hoạt động không cần module khác: `inventory` tắt ⇒ `HotRow.you_have=null`, `matched_assets=[]`, `FeedStatus.inventory_on=false`; không lỗi.
- **INV-11**: `you_have`: `yes` nếu có tài sản khớp chắc (`how=yes`); `maybe` nếu chỉ khớp theo hãng cho sản phẩm "Multiple products"; còn lại `no`.
- **INV-12**: IOC: `verdict=block` khi ≥ 2 nguồn độc lập hoặc 1 nguồn loại DROP/CC0; `alert` khi 1 nguồn; trừ whitelist theo domain (không theo IP CDN); không bao giờ mở rộng IP thành /24 (DATA_PIPELINE §3).
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
`feeds_source` (cấu hình feed có sẵn + feed riêng, parser JSON), `feeds_vuln`, `feeds_ioc`, `feeds_fetch_log`, `feeds_weekly_answer`.

## Events
- **Phát**: `feeds.vuln.new_kev {cve, vendor, product, has_template, date_added}`, `feeds.vuln.updated {cves[]}`, `feeds.ioc.updated {feed_id, added, removed}`, `feeds.fetch.failed {feed_id, error}`.
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
