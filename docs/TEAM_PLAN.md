# Kế hoạch làm việc nhóm — M2 (backend)

Lập 2026-11-09. Nhóm: **Kiên** (`@kiennt048`, người duy trì) và **Emily / Mlee** (`@kiennt049`). Mỗi người điều phối nhiều phiên AI (Claude Code), mỗi phiên dùng subagent. Mục tiêu: ship nhanh nhất mà không giẫm chân nhau.

## 1. Nguyên tắc chia việc

1. **Chia theo module, không chia theo lớp.** Mỗi người sở hữu trọn module: backend Go + test hợp đồng + chuyển giao diện module đó từ mock sang API thật. Ranh giới là `modules/<id>/CONTRACT.md`; hai người gần như không sửa chung file.
2. **Hợp đồng trước, code sau.** Đổi `contract.ts`, `api/openapi.json`, `modules/*/CONTRACT.md`, `docs/DATA_MODEL.md` → PR nhãn `contract`, **người kia duyệt**. Mọi thứ khác: chủ module tự quyết.
3. **Không ai chờ ai.** Trong lúc nền tảng (core) chưa xong, Emily viết các **thư viện lá** không cần core (parser feed, bộ khớp lỗ hổng, adapter kênh, adapter AI, bộ chạy hook) với test riêng; cắm vào core khi registry sẵn.
4. **Một module — một phiên AI đang ghi.** Không bao giờ hai phiên cùng sửa một module. Phiên nhận việc bằng cách tự gán issue của gói việc (WP) và ghi tên phiên vào issue.
5. **Lõi không gắn hãng thiết bị (D-58).** Không nhánh code riêng cho hãng nào.
6. **QA theo `docs/QA.md`** cho mọi màn hình chạm tới; người làm ≠ người kiểm.

## 2. Ai sở hữu gì

| Kiên | Emily |
|---|---|
| `core` (nền tảng), `host` (`vedette-host`), đóng gói + phát hành | `feeds`, `mitigation` + khớp lỗ hổng/phát hiện |
| `inventory`, `sensor-passive`, `sensor-active` | `notify` (kênh, Incidents, vận chuyển lời duyệt) |
| `response` (quy tắc, duyệt, thực thi, vỏ an toàn) | `exposure`, `scan`, `scan-credentialed` |
| `honeypot` | `logs`, `agent-intake` |
| Rà bảo mật, chuẩn bị kiểm thử xâm nhập | `ai` (harness), `reports`, `mcp-server`, `auth-oidc` |

Kiên giữ phần nhạy cảm bảo mật (core, host, response, cảm biến); Emily giữ các luồng dữ liệu và tích hợp. Khối lượng xấp xỉ cân bằng (mỗi bên ~3 gói lớn).

## 3. Gói việc (WP) và thứ tự

Kích cỡ: S ≈ 1–2 phiên-ngày, M ≈ 3–5, L ≈ 6–10 (ước lượng thô, đo lại sau 2 tuần).

### Giai đoạn 0 — nền tảng (chạy song song ngay)
| WP | Việc | Chủ | Cỡ | Phụ thuộc | Nhánh |
|---|---|---|---|---|---|
| WP-01 | Khung Go (`go.mod` ghim 1.26, layout `cmd/` `core/` `modules/`), Makefile, golangci-lint (kiểm tra trên máy, D-61) | Kiên | S | — | `feat/core-skeleton` |
| WP-02 | Sinh code từ `api/openapi.json` + kiểm lệch (`make generate-check`). **Rủi ro cần thử ngày đầu:** file là OpenAPI 3.1 — chọn công cụ hỗ trợ (thử ogen, oapi-codegen), không được thì xuất 3.0 từ Zod | Kiên | M | WP-01 | `feat/core-codegen` |
| WP-03 | `core/store` (SQLite WAL, goose + sqlc), `core/secrets`, `core/audit` (chuỗi hash D-57), `core/exec` (allowlist) | Kiên | M | WP-01 | `feat/core-store` |
| WP-04 | `core/auth` (phiên, CSRF, argon2id, TOTP, mã email, RBAC, token API), module registry, job scheduler | Kiên | L | WP-03 | `feat/core-auth` |
| WP-05 | Môi trường dev (docker compose), giao diện bật API thật **theo từng module** (mock cho module chưa có backend) | Kiên | S | WP-02 | `feat/dev-env` |
| WP-06 | Chỉnh giao diện khớp hợp đồng + D-57/D-58 (danh sách lệch ở mục 6) | Kiên (phiên AI) | M | — | `fix/gui-contract-align` |
| WP-20a | Thư viện feed: lịch kéo, nguồn có sẵn, parser 5 định dạng + fuzz, kiểm tra an toàn | Emily | M | — | `feat/feeds-lib` |
| WP-21a | Thư viện khớp lỗ hổng: KEV × phần mềm/phiên bản (CPE), basis/status | Emily | M | — | `feat/matching-lib` |
| WP-22a | Thư viện adapter kênh: Slack, Telegram, email (SMTP), Zalo OA, Zalo cá nhân, webhook + bộ giả lập | Emily | M | — | `feat/notify-adapters` |
| WP-25a | Thư viện AI: adapter nhà cung cấp, định tuyến + dự phòng, bộ chạy hook, đồng hồ token | Emily | M | — | `feat/ai-lib` |

### Giai đoạn 1 — module cắm vào core (khi WP-04 xong)
| WP | Việc | Chủ | Cỡ |
|---|---|---|---|
| WP-10 | `inventory`: tài sản, hợp nhất quan sát, phạm vi, hộp là thiết bị đầu tiên, CSV | Kiên | M |
| WP-11 | `sensor-passive`: ARP/DHCP/mDNS, SPAN metadata (DNS/SNI/HTTP host/luồng, gopacket) | Kiên | M |
| WP-12 | `sensor-active`: nmap qua `core/exec`, parser XML + fuzz, cửa sổ giờ, quét một lần cho thiết bị mong manh | Kiên | S |
| WP-07 | `host`: socket API, cập nhật OS, cấu hình mạng tự hoàn tác, vòng đời container (Podman/Quadlet) | Kiên | L |
| WP-20 | `feeds` module: endpoint, feed tuỳ chỉnh, trạng thái | Emily | S |
| WP-21 | Module `findings` (D-57: tách hợp đồng khỏi `mitigation`, bảng `fnd_*`) + `mitigation`: endpoint, gói khuyến nghị đã xác nhận, "What to do" | Emily | M |
| WP-22 | `notify`: kênh, giờ im lặng, gộp, Incidents, lịch sử gửi, token duyệt email | Emily | M |
| WP-23 | `exposure` (TXT, IP ra của hộp, CT, httpx) + `scan` (nuclei lib, nhật ký probe) | Emily | M |

### Giai đoạn 2 — module phụ thuộc
| WP | Việc | Chủ | Cỡ |
|---|---|---|---|
| WP-13 | `response`: quy tắc KHI/NẾU/THÌ, tham số có kiểu + escape, bộ thực thi chung (HTTP, SSH, NETCONF/RESTCONF, tự động hoá, MCP, danh sách chặn), duyệt, vỏ an toàn, `resp_log` | Kiên | L |
| WP-14 | `honeypot`: sinh cấu hình OpenCanary, vai giả, honey token, phát hiện quét | Kiên | M |
| WP-24 | `logs`: nhận syslog UDP/TCP/TLS, parser, gộp, baseline, khớp IOC, chuyển SIEM | Emily | L |
| WP-25 | `ai` module: harness (rules, memory, skills, RAG FTS5, kết nối, hook), nhật ký hoạt động | Emily | L |
| WP-26 | `agent-intake`: máy chủ TLS cho osquery, token đăng ký, kéo Wazuh | Emily | M |
| WP-27 | `reports`, `mcp-server`, `auth-oidc` | Emily | M |

### Giai đoạn 3 — hoàn thiện
| WP | Việc | Chủ |
|---|---|---|
| WP-08 | Đóng gói: image, Quadlet, script cài, cosign, phát hành theo lô | Kiên |
| WP-30 | E2E trên backend thật cho từng module (mỗi chủ module) | Cả hai |
| WP-31 | Rà bảo mật SYS-1…8 + D-41, chuẩn bị kiểm thử xâm nhập | Kiên (+ AI kiểm độc lập) |
| WP-32 | Điền RUNBOOK, hướng dẫn cài đặt và quản trị | Cả hai |

**Đường găng:** WP-01 → WP-03 → WP-04 → (WP-10, WP-22) → WP-13. Kiên ưu tiên tuyệt đối WP-01…WP-04 trong tuần đầu; Emily không phụ thuộc đường găng cho tới giai đoạn 1.

## 4. Cách mỗi người chạy nhiều phiên AI

- **2–4 phiên song song mỗi người**, mỗi phiên **một git worktree + một nhánh + một WP**. Ví dụ Kiên: phiên A `feat/core-store`, phiên B `fix/gui-contract-align`, phiên C rà PR của Emily. Emily: phiên A `feat/feeds-lib`, phiên B `feat/matching-lib`, phiên C `feat/notify-adapters`.
- Mỗi phiên dùng subagent theo vai: **người làm** (viết code + test), **người kiểm độc lập** (theo `docs/QA.md`, không đọc lời giải thích của người làm), **người cập nhật tài liệu** (CONTRACT, IMPACT, DATA_MODEL khi đổi).
- Đầu phiên AI đọc: `CLAUDE.md` → `docs/TEAM_PLAN.md` → `.ai/tasks/<người>.md` → `modules/<id>/CONTRACT.md` của WP. Cuối phiên: cập nhật `.ai/tasks/<người>.md`, ghi việc để sau vào `.ai/deferred/<nhánh>.md`.
- Phiên không bao giờ sửa module của người kia; cần đổi → mở issue hoặc PR nhãn `contract` gán người kia.

## 5. Nhịp phối hợp

- **PR nhỏ** (≤ ~400 dòng), một WP có thể nhiều PR. Người kia duyệt PR chạm hợp đồng; PR trong module của mình: tự merge khi `make verify` trên máy xanh (dán kết quả vào PR). **Không dùng GitHub Actions** (D-61, `rules/local-checks.md`): mọi kiểm tra chạy trên máy của người làm.
- **Mỗi ngày 15 phút** (hoặc ghi chú trong GitHub Discussions): đang làm WP nào, bị chặn gì, hợp đồng nào sắp đổi.
- **Thứ tự merge** theo phụ thuộc ở mục 3; `main` luôn xanh. GitHub Free không khoá được nhánh riêng tư → quy ước, không phải cơ chế.
- **Issue** mỗi WP, nhãn `module:<id>`, `owner:kien` / `owner:emily`, `wp:<số>`; GitHub Projects một bảng Kanban.

## 6. Việc đầu tiên của từng người (ngày 1)

**Kiên:** phiên A — WP-01 khung Go; phiên B — WP-06 chỉnh giao diện khớp hợp đồng: ngày trong tuần 1–7, `400 commitment_required`, chữ về khoá SSH, `vedette-updater` → `vedette-host`, Findings phụ thuộc `inventory`, tiền tố bảng, `confidence` 0–1, một công thức hash, `reports` phụ thuộc `notify`, kiểu kết nối chung + NETCONF/RESTCONF + nền tảng tự động hoá, mẫu hành động là dữ liệu (D-58), 11 điểm lệch trong `docs/specs/action-templates.md` §12, Privacy bỏ chữ IDS và thêm luồng OIDC, API tạo mới trả `201`, mock hợp nhất quan sát theo ưu tiên nguồn (ARCHITECTURE), Findings phụ thuộc module `findings`; phiên C — duyệt PR.

**Emily:** đọc `docs/ARCHITECTURE.md`, `docs/DATA_MODEL.md`, `docs/API_CONVENTIONS.md`, `modules/{feeds,mitigation,notify,ai}/CONTRACT.md`; phiên A — WP-20a, phiên B — WP-21a, phiên C — WP-22a (WP-25a khi một phiên rảnh).

## 7. Khi nào xem lại kế hoạch
Sau 2 tuần hoặc khi WP-04 xong: đo tốc độ thật (WP đã merge), chỉnh cỡ ước lượng và cân lại khối lượng.
