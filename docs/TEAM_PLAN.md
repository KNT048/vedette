# Kế hoạch làm việc nhóm — M2 (backend)

Lập 2026-11-09. Nhóm: **Kiên** (`@kiennt048`, người duy trì) và **Emily / Mlee** (`@kiennt049`). Mỗi người điều phối nhiều phiên AI (Claude Code), mỗi phiên dùng subagent. Mục tiêu: ship nhanh nhất mà không giẫm chân nhau.

## 1. Nguyên tắc chia việc

1. **Chia theo module, không chia theo lớp.** Mỗi người sở hữu trọn module: backend Go + test hợp đồng + chuyển giao diện module đó từ mock sang API thật. Ranh giới là `modules/<id>/CONTRACT.md`; hai người gần như không sửa chung file.
2. **Hợp đồng trước, code sau — không chờ nhau duyệt (D-65).** Đổi `contract.ts`, `api/openapi.json`, `modules/*/CONTRACT.md`, `docs/DATA_MODEL.md`, `docs/API_CONVENTIONS.md` → PR nhãn `contract` và nhắc người kia (@) **để thông báo**, không chờ duyệt: CI xanh thì merge.
3. **Không ai chờ ai.** Trong lúc nền tảng (core) chưa xong, Emily viết các **thư viện lá** không cần core (parser feed, bộ khớp lỗ hổng, adapter kênh, adapter AI, bộ chạy hook) với test riêng; cắm vào core khi registry sẵn.
4. **Một module — một phiên AI đang ghi.** Không bao giờ hai phiên cùng sửa một module. Phiên nhận việc bằng cách tự gán issue của gói việc (WP) và ghi tên phiên vào issue.
5. **Chồng lấn thì Kiên làm hết, Emily chỉ thông báo (kien, D-65).** Việc nào đụng phần của Kiên hoặc phần dùng chung (`core/`, `cmd/`, Makefile, `go.mod`, `tools/`, `scripts/`, `.github/`, `web/src/lib`, `web/src/mocks`, `docs/DECISIONS.md`, hợp đồng chung `DATA_MODEL`/`API_CONVENTIONS`/`MODULE_CONTRACTS`), hoặc đang có phiên khác sửa cùng chỗ: Emily **dừng phần đó** và mở issue nhãn `owner:kien` (nhánh, đã làm gì, còn gì, cần gì) rồi làm việc khác; phiên AI của Kiên nhận và làm. Không bàn qua lại. PR của Kiên chạm module Emily cũng chỉ thông báo, không chờ duyệt.
5. **Lõi không gắn hãng thiết bị (D-58).** Không nhánh code riêng cho hãng nào.
6. **QA theo `docs/QA.md`** cho mọi màn hình chạm tới; người làm ≠ người kiểm.

## 2. Ai sở hữu gì

| Kiên | Emily |
|---|---|
| `core` (nền tảng), `host` (`vedette-host`), đóng gói + phát hành | `feeds`, `mitigation` + khớp lỗ hổng/phát hiện |
| `inventory`, `sensor-passive`, `sensor-active` | `notify` (kênh, Incidents, vận chuyển lời duyệt) |
| `response` (quy tắc, duyệt, thực thi, vỏ an toàn) | `exposure`, `scan`, `scan-credentialed` |
| `honeypot` | `logs` |
| Rà bảo mật, chuẩn bị kiểm thử xâm nhập | `ai` (harness), `reports`, `mcp-server` |
| `agent-intake`, `auth-oidc` (chuyển từ Emily 2026-11-11, D-190) | |

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
| WP-23 | `exposure` (TXT, IP ra của hộp, CT, httpx) + `scan` (nuclei lib, nhật ký probe). **Thêm (kien 2026-11-09):** tự phát hiện IP công cộng của hộp (chế độ tự động/thủ công, chạy lần đầu khi cài, kiểm lại theo chu kỳ khách chọn 1 phút–24 giờ (mặc định 60 phút), khách sửa và xoá được IP đã lấy, hiệu lực 30 ngày gia hạn mỗi lần thấy lại); yêu cầu và danh mục kiểm ở `.ai/tasks/kien.md` §"Giám sát WP-23" | Emily | M |

### Giai đoạn 2 — module phụ thuộc
| WP | Việc | Chủ | Cỡ |
|---|---|---|---|
| WP-13 | `response`: quy tắc KHI/NẾU/THÌ, tham số có kiểu + escape, bộ thực thi chung (HTTP, SSH, NETCONF/RESTCONF, tự động hoá, MCP, danh sách chặn), duyệt, vỏ an toàn, `resp_log` | Kiên | L |
| WP-14 | `honeypot`: sinh cấu hình OpenCanary, vai giả, honey token, phát hiện quét | Kiên | M |
| WP-24 | `logs`: nhận syslog UDP/TCP/TLS, parser, gộp, baseline, khớp IOC, chuyển SIEM | Emily | L |
| WP-25 | `ai` module: harness (rules, memory, skills, RAG FTS5, kết nối, hook), nhật ký hoạt động | Emily | L |
| WP-26 | `agent-intake`: máy chủ TLS cho osquery, token đăng ký, kéo Wazuh | Kiên (AI-Trưởng; D-190) | M |
| WP-27 | `reports`, `mcp-server` (Emily) · `auth-oidc` (Kiên, phiên Mac; đụng `core/auth`; D-190) | Emily + Kiên | M |

### Giai đoạn 3 — hoàn thiện
| WP | Việc | Chủ |
|---|---|---|
| WP-08 | Đóng gói: image, Quadlet, script cài, cosign, phát hành theo lô | Kiên |
| WP-30 | E2E trên backend thật cho từng module (mỗi chủ module) | Cả hai |
| WP-31 | Rà bảo mật SYS-1…8 + D-41, chuẩn bị kiểm thử xâm nhập | Kiên (+ AI kiểm độc lập) |
| WP-32 | Điền RUNBOOK, hướng dẫn cài đặt và quản trị | Cả hai |

**Đường găng:** WP-01 → WP-03 → WP-04 → (WP-10, WP-22) → WP-13. Kiên ưu tiên tuyệt đối WP-01…WP-04 trong tuần đầu; Emily không phụ thuộc đường găng cho tới giai đoạn 1.

## 4. Cách các phiên AI chạy (cập nhật 2026-11-11, D-190)

- **AI-Supervisor (máy Mac của Kiên)** điều phối cả ba phía. Nó không viết code trực tiếp. Trạng thái của nó nằm ở `vedette-wt/LEAD-STATE.md` trên máy Mac, ngoài git.
  - **Mỗi lát việc (một nhánh, một PR) của phía Mac chạy thành một session phụ của Claude Desktop** (`start_session`), dùng worktree riêng. Session phụ tự chạy trọn gate: test, rà độc lập, sửa, `make check`, PR, merge khi CI xanh. Trạng thái của mỗi session phụ ghi vào `vedette-wt/sessions/<tên>.md`. Supervisor bị thay hay compact thì các session phụ vẫn chạy tiếp.
  - Mỗi 30 phút supervisor kiểm hai box, các session phụ, PR và CI.
- **AI-Trưởng** (box Ubuntu của Kiên, user `byn`, tmux `claude`): WP-08, `honeypot`, `host`, WP-30 các lát qua `vedette-host`, WP-32 phần Kiên, WP-26.
- **AI-Mlee** (box Ubuntu của Emily, user `byn2`, tmux `claude`): các module của Emily, WP-30 và WP-32 phần Emily, `reports`, `mcp-server`. Supervisor nhắn qua tmux; không dùng GitHub Discussions nữa.
- **Mỗi phiên, mỗi session phụ:** một git worktree, một nhánh, một WP hoặc một lát. Subagent dùng cho việc nhỏ bên trong: người làm, người kiểm độc lập (theo `docs/QA.md`, Opus cho phần nhạy cảm bảo mật), người cập nhật tài liệu.
- **Việc nặng** (`make check`/`verify`, Playwright, `go test` nhiều gói, lint) chạy qua khoá `~/vedette-wt/heavy` trên box. Mỗi máy tối đa 2 việc nặng một lúc.
- **Dải số quyết định** để các phiên không tranh số: Trưởng D-157…D-169, Mac D-170…D-199, Mlee D-200…D-229.
- **Đầu phiên** đọc: `CLAUDE.md` → `.ai/tasks/current.md` → `docs/TEAM_PLAN.md` → `.ai/tasks/<người>.md` → `modules/<id>/CONTRACT.md` của WP. **Cuối phiên:** cập nhật `.ai/tasks/<người>.md` và ghi việc để sau vào `.ai/deferred/<nhánh>.md`.
- Phiên không sửa module của phía kia. Cần đổi thì mở issue `owner:kien` hoặc `owner:emily`, kèm một dòng `[→ AI-Supervisor]` khi việc đó chặn mình.

## 5. Nhịp phối hợp

- **PR nhỏ** (≤ ~400 dòng), một WP có thể nhiều PR. Mọi PR (kể cả nhãn `contract`): tự merge khi CI xanh, sau `make check` trên máy (dán kết quả vào PR; `rules/local-checks.md`, D-62, D-63); PR chạm phần người kia thì @ họ để thông báo, không chờ (D-65).
- **Nhịp:** AI-Supervisor kiểm mỗi 30 phút: các phiên, PR và CI, chồng lấn file, câu hỏi đang chờ. Từ 2026-11-11 không dùng GitHub Discussions (#145) nữa.
- **Thứ tự merge** theo phụ thuộc ở mục 3; `main` luôn xanh. GitHub Free không khoá được nhánh riêng tư → quy ước, không phải cơ chế.
- **Issue** mỗi WP, nhãn `module:<id>`, `owner:kien` / `owner:emily`, `wp:<số>`; GitHub Projects một bảng Kanban.

## 6. Việc đầu tiên của từng người (ngày 1)

**Kiên:** phiên A — WP-01 khung Go; phiên B — WP-06 chỉnh giao diện khớp hợp đồng: ngày trong tuần 1–7, `400 commitment_required`, chữ về khoá SSH, `vedette-updater` → `vedette-host`, Findings phụ thuộc `inventory`, tiền tố bảng, `confidence` 0–1, một công thức hash, `reports` phụ thuộc `notify`, kiểu kết nối chung + NETCONF/RESTCONF + nền tảng tự động hoá, mẫu hành động là dữ liệu (D-58), 11 điểm lệch trong `docs/specs/action-templates.md` §12, Privacy bỏ chữ IDS và thêm luồng OIDC, API tạo mới trả `201`, mock hợp nhất quan sát theo ưu tiên nguồn (ARCHITECTURE), Findings phụ thuộc module `findings`; phiên C — duyệt PR.

**Emily:** đọc `docs/ARCHITECTURE.md`, `docs/DATA_MODEL.md`, `docs/API_CONVENTIONS.md`, `modules/{feeds,mitigation,notify,ai}/CONTRACT.md`; phiên A — WP-20a, phiên B — WP-21a, phiên C — WP-22a (WP-25a khi một phiên rảnh).

## 7. Khi nào xem lại kế hoạch
Sau 2 tuần hoặc khi WP-04 xong: đo tốc độ thật (WP đã merge), chỉnh cỡ ước lượng và cân lại khối lượng.
