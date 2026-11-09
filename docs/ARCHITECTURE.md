# Kiến trúc kỹ thuật

Trạng thái: thiết kế ban đầu 2026-11-06. Mọi lựa chọn có lý do trong `DECISIONS.md`.

## 1. Tổng quan

```
                 ┌──────────────── Trung tâm (free, tĩnh) ────────────────┐
                 │ VM builder (IP VN) + GitHub Actions dự phòng → ký →    │
                 │ GitHub repo dữ liệu / Releases / R2 → Cloudflare CDN    │
                 │ index.json (ký), feeds/*.json, content-packs/*.tar.zst  │
                 └──────────────────────────┬──────────────────────────────┘
                                            │ HTTPS, ETag, 30–60 phút
┌──────────── Tại khách ─────────────────────▼──────────────────────────────┐
│  vedette (1 binary Go, SPA nhúng)                                          │
│  ┌ server ─────────────────────────────┐  ┌ sensor (cùng process ở SMB) ┐ │
│  │ core · feeds · inventory · notify   │  │ sensor-passive · sensor-    │ │
│  │ mitigation · exposure · scan · ai   │◄─┤ active · honeypot · logs    │ │
│  │ reports · fleet · mcp-server        │  │ (mTLS ra server khi tách)   │ │
│  └───────────┬─────────────────────────┘  └─────────────────────────────┘ │
│   SQLite (mặc định) / PostgreSQL                                           │
│   Tiến trình ngoài: nmap (repo OS), zeek/suricata (tuỳ chọn), opencanary, │
│   greenbone (container), nuclei/httpx/subfinder (thư viện Go, nhúng)      │
└───────────────────────────────────────────────────────────────────────────┘
          │ chỉ khi khách bật                         │ chỉ khi khách bật
          ▼                                           ▼
   Provider AI của khách (BYOK)               Feed cần key của khách (BYOK)
```

Hộp **không** nằm trên đường mạng. Nó là một host trong LAN (hoặc VM), tuỳ chọn nhận SPAN/TAP và syslog.

## 2. Stack và lý do

| Lớp | Chọn | Lý do |
|---|---|---|
| Backend | **Go 1.26** (ghim trong `go.mod`), một binary tĩnh, `net/http` + router nhẹ (chi/stdlib), `embed` SPA | Nuclei/httpx/naabu/subfinder/dnsx là **thư viện Go** → nhúng được, không spawn; Vuls/go-kev tham khảo; cross-compile x86/ARM; không runtime |
| DB | **SQLite** (`modernc.org/sqlite`, không cgo, WAL) mặc định; **PostgreSQL 16** tuỳ chọn qua cùng một lớp `store` (sqlc) | SMB: một file, backup = copy; Mid/Enterprise: Postgres. FTS5 cho RAG BM25 |
| Frontend | **React 19 + TypeScript + Vite + Tailwind v4 + shadcn/ui + TanStack Query/Table + React Router**, pnpm, i18n vi/en | Stack tác giả đã dùng; chi tiết `FRONTEND.md` |
| Job/scheduler | Trong process (`core/jobs`), cron-like, có khoá, có lịch sử; không message queue | Ponytail; đủ cho ≤ vài trăm asset/site. `ponytail: 1 process; nâng cấp: river/postgres queue khi fleet >50 sensor` |
| Discovery | nmap (binary từ repo OS, XML → parser), Recog (`recog-go`, BSD-2), listener DHCP/mDNS/SSDP/ARP/LLDP tự viết (gopacket), SNMP (`gosnmp`), Zeek/Suricata EVE reader, Fingerbank API tuỳ chọn | Xem `research` §3: nmap mạnh nhất về version đa giao thức; naabu/httpx cho ngoài |
| Scan | Nuclei lib (`nuclei/v3/lib`), template subset `kev,vkev` + safe tags, từ content pack đã ký | Xác nhận thay vì đoán |
| Honeypot | OpenCanary (Python, BSD-3) tiến trình riêng, cấu hình sinh từ DB, log JSON → `logs` | Không viết lại honeypot |
| Log | Thu syslog (RFC3164/5424, TLS), parser theo vendor (bảng regex/grok trong content pack), gộp theo cửa sổ, baseline 7 ngày | Tiền xử lý không AI |
| AI | Adapter: Anthropic native, OpenAI-compatible (OpenAI/Ollama/vLLM/OpenRouter), Gemini; skill runner; RAG FTS5 (+ vector tuỳ chọn) | `AI_ASSISTANT.md` |
| Cập nhật | Client kéo `index.json` ký minisign; A/B dir cho binary; content pack tar.zst ký | `UPDATES.md` |
| Đóng gói | Binary + `.deb`/`.apk` + Docker image + ISO/VM image sau; systemd/OpenRC unit; installer `install.sh` idempotent | Ships-as-code |

## 3. Sensor / Server tách được từ ngày đầu

- Cùng binary: `vedette serve` (server), `vedette sensor --server https://… --token …` (sensor), mặc định SMB chạy cả hai trong một process (`vedette all`).
- Sensor **chỉ gọi ra** server (mTLS, cert do server cấp khi enroll bằng token một lần). Không có cổng vào trên sensor trừ honeypot/syslog.
- Giao thức sensor→server: HTTPS JSON, lô sự kiện (`inventory.observation`, `honeypot.hit`, `logs.batch`), idempotent theo `seq`. Định nghĩa trong `modules/core/CONTRACT.md` (SYS-*).
- Server không bao giờ gọi vào sensor; lệnh (quét ngay, đổi cửa sổ) là hàng đợi sensor poll.

## 4. Data model lõi (bảng, tiền tố theo module)

| Thực thể | Trường chính | Ghi chú |
|---|---|---|
| `inv_asset` | id, site_id, ip[], mac, hostname, kind (router/nas/printer/camera/pc/server/iot/unknown), vendor, model, os, first_seen, last_seen, approved(bool), fragile(bool) | Hợp nhất từ nhiều observation |
| `inv_observation` | asset_id, source (passive/nmap/snmp/agent/manual), field, value, confidence (0–1), seen_at, evidence | **Không ghi đè**; asset là view hợp nhất theo ưu tiên nguồn (manual > agent > snmp > nmap > passive) |
| `inv_service` | asset_id, port, proto, product, version, cpe, banner_hash, confidence, source | |
| `inv_software` | asset_id, vendor, product, version, cpe, purl, confidence, source | Khớp với feeds |
| `feeds_vuln` | cve, vendor, product, version_ranges, kev_date, vulncheck_date, epss, epss_delta7, poc(bool), sightings, ransomware(bool), hot_score | Từ index.json |
| `feeds_ioc` | type (ip/cidr/domain/url/hash/ja3), value, sources[], score, first_seen, last_seen, ttl | |
| `inv_finding` | id, asset_id, cve, status (suspected/confirmed/mitigated/patched/false_positive), confidence, evidence, first_seen, last_seen, resolved_by | "Phát hiện" = CVE × asset |
| `mit_pack` | cve, vendor_firewall, steps[], config_snippets{vendor→text}, rules{suricata,crs,crowdsec,nft}, detection_hints[] | Từ content pack (Vedette đã xác nhận, D-21) hoặc AI của khách (nhãn "AI tạo", không trộn với gói đã xác nhận) |
| `notify_event` | kind, severity, finding_ids[], channel, sent_at, status | |
| `logs_event` | ts, source_asset, vendor, signature, src, dst, proto, count, window, raw_hash | Gộp, không lưu thô dài hạn (retention cấu hình) |
| `hp_hit` | ts, service, src_ip, src_asset, session_excerpt | |
| `ai_run` | skill, tier, provider, model, tokens_in/out, cost_est, inputs_hash, output, citations[], status | Cache theo inputs_hash |
| `core_audit` | ts, user, action, target, before/after hash | Mọi thay đổi |
| `core_module` | id, enabled, enabled_at, config_json, version | Trạng thái bật/tắt |

## 5. API

- REST JSON `/api/v1/…`, OpenAPI 3.1 **spec-first** (D-18): `api/openapi.yaml` sinh từ schema Zod của mock ở M1 là nguồn chân lý, Go sinh type/handler từ file đó; versioned; SSE `/api/v1/events` cho live.
- Auth: session cookie httpOnly + CSRF cho SPA; token API (scoped) cho tích hợp; OIDC tuỳ chọn.
- RBAC 3 vai: viewer / operator / admin. Mọi mutation ghi `core_audit`.
- MCP server (module `mcp-server`): tool chỉ-đọc `search_assets`, `get_finding`, `lookup_cve`, `lookup_ioc`, `recent_events` — cùng lớp service với REST.

## 6. Bảo mật của chính sản phẩm (sản phẩm bảo mật phải sạch hơn mức trung bình)

- Không `exec` shell; mọi tiến trình ngoài qua `core/exec` với allowlist binary + argv, không string shell. Ký tự nguy hiểm bị từ chối ở validator (bài học thực tế: input lọt vào file cấu hình).
- Validate mọi input ở biên (JSON schema → struct tag); IP qua `netip`, tên qua regex `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`.
- Secret (key AI, key feed, token Zalo, SSH key) mã hoá AES-256-GCM với khoá trong file 0600 do installer tạo; không log; không vào JSON export; UI chỉ hiện 4 ký tự cuối.
- Dữ liệu từ feed, log, web, agent là **không tin cậy**: parser fail-closed, giới hạn kích thước, AI nhận chúng như dữ liệu (`AI_ASSISTANT.md` §Guardrail).
- Bundle cập nhật và content pack **ký**; client từ chối không ký/sai ký; revocation list.
- Tín hiệu fleet ẩn danh **bật mặc định** (D-16): payload cố định, hiện nguyên văn trong UI, tắt một bấm; không có telemetry nào khác (`PRIVACY.md`).
- Headers: CSP nghiêm, no inline script; cookie Secure/HttpOnly/SameSite; rate limit đăng nhập; 2FA TOTP ở M7.
- SBOM CycloneDX mỗi release; `govulncheck` + `trivy fs` trong CI; dependency ghim; Renovate.
- Chạy không root: capabilities `CAP_NET_RAW` cho sensor; systemd hardening (ProtectSystem, NoNewPrivileges); honeypot cổng thấp qua socket activation hoặc `CAP_NET_BIND_SERVICE`.

## 7. Giấy phép thành phần

| Thành phần | Giấy phép | Cách dùng |
|---|---|---|
| Mã Vedette | Apache-2.0 | |
| nuclei, httpx, naabu, subfinder, dnsx, nuclei-templates | MIT | thư viện Go nhúng |
| recog (DB) / recog-go | BSD-2 | nhúng |
| nmap | NPSL 0.95 | **không ship**; installer cài từ repo OS; gọi binary riêng; module `sensor-active` là plugin tách riêng để nếu cần tách giấy phép |
| OpenCanary | BSD-3 | tiến trình riêng, cài bởi installer |
| Zeek (BSD), Suricata (GPL-2) | — | tiến trình riêng, tuỳ chọn |
| Greenbone CE | GPL-2/AGPL-3 | container riêng, không sửa |
| Wazuh / osquery | GPL-2 / Apache-2.0+GPL-2 | không ship; osquery gửi dữ liệu về hộp, Wazuh được hộp đọc qua API (D-33) |
| hagezi (GPL-3), ET Open (BSD), IPsum (Unlicense), KEV (CC0), cvelistV5 (public), EPSS (ghi nguồn), GHSA (CC-BY) | dữ liệu | phân phối lại qua trung tâm, kèm giấy phép |
| OTX, AbuseIPDB free, VirusTotal public, Shodan InternetDB, OpenPhish community, GreyNoise community, VulnCheck community | non-commercial / theo tài khoản | **hộp tự kéo bằng key của khách**, không qua trung tâm |
| OpenCVE | BSL 1.1 | không dùng trong lõi; tham khảo |

## 8. Hiệu năng mục tiêu (đo lại khi có code)

- Hộp 4 nhân/8 GB: 1.000 asset, 50k IOC, 7 ngày log gộp ≤ 2 GB SQLite; UI <300 ms p95 cho trang chính.
- Sensor thụ động ≤ 5% CPU một nhân ở 100 Mbps SPAN.
- Kéo feed: ≤ 5 MB/giờ nhờ ETag + delta.
