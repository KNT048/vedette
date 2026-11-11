# Trợ lý AI — BYOK, skill, RAG, 3 mức

Nguyên tắc (kien): sản phẩm không bán AI. Khách cắm key/model của họ; phần mềm cung cấp **việc cụ thể, có ích**. Khách trả tiền token cho provider của họ. Không bàn giá token trong sản phẩm ngoài đồng hồ đo.

## 1. Provider

| Loại | Cách nối | Năng lực khai báo |
|---|---|---|
| Anthropic | API native (Messages), tool use, structured output | `tools`, `structured`, `web_search` (nếu bật) |
| OpenAI-compatible | `base_url` + key: OpenAI, Ollama, vLLM, LM Studio, OpenRouter, gateway nội bộ | `tools` (nếu model hỗ trợ), `structured` (json schema) |
| Gemini | API native | `tools`, `structured` |

- Cấu hình: provider, `base_url`, key (mã hoá, chỉ hiện 4 ký tự cuối), model, giới hạn context, cờ năng lực (tự dò bằng lệnh thử). Nhiều hồ sơ: ví dụ "Haiku cho log, Opus cho giải thích".
- **Key không bao giờ rời hộp** ngoài request tới provider. Không qua trung tâm.
- Đồng hồ: token vào/ra theo skill/ngày/tháng; trần token/ngày theo mức; vượt trần → hạ mức → thông báo.

## 2. Skill — gói việc cụ thể, cập nhật được

Mỗi skill là một thư mục trong `skills/<tên>/`, định dạng tương thích Agent Skills (`SKILL.md` + file phụ) để khách dùng lại với công cụ khác:

```
skills/explain-finding/
  SKILL.md         # frontmatter: name, version, description, trigger (sự kiện/nút), tier_budget {min,med,max}, tools_allowed[], inputs schema, output schema
  prompt.vi.md     # system/instructions tiếng Việt (en tuỳ chọn)
  output.schema.json
  fixtures/        # input mẫu + output kỳ vọng (test hồi quy, chạy với model rẻ trong CI nếu có key)
  README.md        # việc này làm gì, không làm gì
```

Skill được ship qua **content pack** (ký) → cập nhật prompt/schema mà không cần phát hành binary. Hộp giữ bản trước để rollback. Skill do khách tự viết đặt ở `data/skills/` (ưu tiên thấp hơn, không bị ghi đè).

### Danh sách skill ban đầu (mỗi cái truy về story)

| Skill | Story | Input (hộp chuẩn bị, không để AI tự tìm) | Output (schema) | Tier |
|---|---|---|---|---|
| `explain-finding` | S-AI-2 | bản ghi CVE (cvelist JSON rút gọn), tín hiệu feed (KEV/EPSS/PoC/sightings), asset + software + version + vendor firewall đã khai, 24h log liên quan (gộp), mitigation pack nếu có | `{affected: yes/no/unknown, why, patch_steps[], temp_mitigations[], config_snippets{vendor: text}, detection_hints[], citations[]}` | 1 lần/CVE/asset, cache theo hash |
| `cve-news` | S-AI-3 | văn bản hộp đã fetch (D-280): bản ghi NVD, một advisory của hãng trong danh sách host, tìm kiếm kho GitHub `CVE-…` (PoC?), 6 feed watchTowr/GreyNoise/SANS ISC/Rapid7/Unit 42/Project Zero; làm sạch, có giới hạn, trong khối có rào | `{exploited, public_exploit, workaround, other[]}` → `lines` có nhãn do hộp gắn; `sources`, `citations` do hộp dựng | theo yêu cầu; không web search của nhà cung cấp ở mức nào (FORBID-6) |
| `log-digest` | S-AI-4 | bảng gộp (signature, src, dst, count, Δ so baseline), hit IOC, asset liên quan | `{items: [{severity, evidence_lines[], recommendation}], summary}` | min: 1/ngày · med: 1/giờ · max: theo alert mới |
| `log-investigate` | S-AI-4 (max) | như trên + **tool chỉ-đọc**: `search_assets`, `events_around(ip, window)`, `lookup_ioc`, `lookup_cve` | như trên + `tool_calls[]` ghi lại | max |
| `mitigation-config` | S-MIT-1 | CVE + vendor firewall + model/phiên bản + topology ngắn (WAN/LAN) | `{snippets{vendor: text}, side_effects[], verify_steps[]}` | theo yêu cầu |
| `fingerprint-fallback` | S-INV-1 | banner/sysDescr/HTTP title mà nmap/Recog không gán được | `{vendor, product, version?, confidence}` | lô, model rẻ |
| `translate-advisory` | S-FEED-2 | advisory tiếng Anh | tiếng Việt, giữ số/phiên bản | lô |
| `weekly-report` | S-REP-1 | số liệu tuần (phát hiện mới/đã xử lý/còn, honeypot, log bất thường) | markdown 1 trang | 1/tuần |
| `pdpl-assessment` | S-REP-2 | kiểm kê + scan + cấu hình | báo cáo theo mục luật (template cố định, AI chỉ điền) | theo yêu cầu |
| `ask-my-data` | S-AI-5 | câu hỏi + tool chỉ-đọc | trả lời + bảng | theo yêu cầu |

`mitigation-config` chạy ở hai nơi (D-21): **trung tâm**, bằng key của dự án, soạn nháp gói giảm thiểu cho người duy trì xác nhận qua PR (S-MIT-4, `DATA_PIPELINE.md` §5b); **hộp**, bằng key của khách, chỉ khi CVE chưa có gói đã xác nhận (S-MIT-1). Kết quả trên hộp không bao giờ hiện như khuyến nghị đã xác nhận.

## 3. RAG — tìm đúng ngữ cảnh trước khi hỏi

- **Kho**: tài sản/phát hiện (từ DB, render thành văn bản ngắn), mitigation pack, advisory đã fetch, bản dịch, skill README, tài liệu sản phẩm, log gộp 7 ngày.
- **Chỉ mục**: SQLite **FTS5 (BM25)** ngay từ đầu — không phụ thuộc embedding; tuỳ chọn vector (`sqlite-vec`) với embedding từ provider của khách hoặc Ollama (bge-m3 tốt tiếng Việt). Lai (BM25 + vector) khi có vector.
- **Chunk**: theo thực thể (1 asset = 1 doc; 1 CVE = 1 doc; advisory chia ~800 token có tiêu đề). Cập nhật tăng dần khi DB đổi.
- **Truy xuất**: theo skill, top-k nhỏ (5–12), lọc theo site/tenant và quyền người hỏi; mỗi chunk mang `source` để AI trích dẫn; câu trả lời không có citation → UI gắn nhãn "không có nguồn".
- **Tài liệu của khách (S-AI-7, lát 4c, D-209)**: MD/TXT/DOCX ≤ 10 MB (PDF chưa hỗ trợ: cần đọc trong tiến trình con có giới hạn, D-209) do quản trị viên tải lên, hộp đọc và cắt đoạn ~3200 byte, chỉ mục FTS5 (BM25) trên hộp, không embedding; mỗi lần gọi một việc mang dữ liệu nội bộ lấy tối đa 4 đoạn khớp câu hỏi, từng đoạn qua hook, thành khối dữ liệu có rào (không vào system prompt).
- **Không RAG** cho dữ liệu mà hộp có thể đưa chính xác bằng truy vấn (asset theo IP…): dùng tool chỉ-đọc.

## 4. Ba mức token (S-AI-4)

| Mức | Gửi gì | Khi nào | Trần mặc định |
|---|---|---|---|
| Tối thiểu | 1 digest/ngày: top-N bất thường đã gộp + hit IOC; `explain-finding` chỉ khi bấm | model đắt hoặc local nhỏ | ~10k token/ngày |
| Trung bình | mỗi giờ: lô sự kiện **mới** + cửa sổ bất thường, kèm asset; `explain-finding` tự chạy cho phát hiện mới mức cao | mặc định | ~60k/ngày |
| Tối đa | theo từng alert mới; `log-investigate` với tool; `cve-news` tự chạy (chưa làm) | khách có SOC/IT | khách đặt |

Vượt trần → hạ mức → ghi thông báo. Mọi lần gọi ghi `ai_run` (skill, token, model, hash input) để tra và cache.

## 5. Guardrail

- Log, feed, web, agent là **dữ liệu không tin cậy**: đặt trong khối dữ liệu có nhãn, system prompt chốt vai trò; lọc injection (regex + danh sách mẫu "ignore previous…", và bộ phân loại nhỏ khi có) trước khi đưa; văn bản fetch giới hạn kích thước.
- **AI không hành động**: không tool ghi; mọi output là đề xuất, có nhãn "AI tạo, cần người xác nhận" (S-AI-6); nút áp dụng cấu hình là của người, ghi audit.
- Output theo **schema cứng**; không parse được → hiển thị thô với cảnh báo, không suy diễn.
- Redact trước khi gửi: secret, token, mật khẩu trong log, và tuỳ chọn PII (email, số điện thoại) theo cài đặt.
- Khách không gửi được dữ liệu ra ngoài → cùng giao diện với Ollama/vLLM nội bộ.
- Test: fixtures/skill chạy trong CI với model rẻ khi có key của dự án; đo tỉ lệ đúng schema, tỉ lệ có citation.

## 6. MCP

- Module `mcp-server`: Vedette **cung cấp** tool chỉ-đọc cho agent ngoài (Claude Desktop/Code, SIEM có MCP): `search_assets`, `get_finding`, `lookup_cve`, `lookup_ioc`, `recent_events`, `hot_board`. Bind localhost mặc định; token scoped.
- Vedette **không** tiêu thụ MCP server ngoài ở M6 (ponytail); để sau nếu có story.
