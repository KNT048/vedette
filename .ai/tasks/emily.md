# Việc của Emily (Mlee) — đọc cùng docs/TEAM_PLAN.md

Cập nhật: 2026-11-10 (phiên AI lead của Emily). Repo: **`KNT048/vedette`** (public, D-63). Module Go: `github.com/knt048/vedette`.
Emily sở hữu (TEAM_PLAN §2) các module: feeds, findings (D-57 (6)), mitigation, notify, exposure, scan, scan-credentialed, logs, agent-intake, ai, reports, mcp-server, auth-oidc.
File này là **file handoff duy nhất** của các phiên AI làm cho Emily. Sau compact hay khởi động lại, đọc lại file này trước khi làm tiếp.

## Quy trình (D-61 → D-65)
- **Kiểm trên máy, trong WSL2 Ubuntu.** Mã nằm ở hệ file của WSL (`~/src/vedette`, worktree `~/src/vedette-wt/<nhánh>`), không đặt ở `/mnt/c`. Makefile từ chối chạy trên Windows gốc.
  - Trước khi push hay mở PR: rebase lên `origin/main`, chạy `heavy make check` (ghi lại mã thoát), rồi dán phần cuối log kèm SHA vào mục "Local checks".
  - Rebase lên main mà main chỉ đổi file không liên quan (tài liệu, module của Kiên) thì không chạy lại gate. Ghi rõ những file main đã đổi vào "Local checks"; CI trên GitHub vẫn kiểm toàn bộ.
  - Chỉ merge khi CI (GitHub Actions: `go`, `web`) xanh. CI đỏ vì test chập chờn của module khác: chạy lại job hỏng, rồi báo chủ module.
  - Chạy `make audit` đầu mỗi phiên.
- **E2E**: chỉ chạy spec của module vừa chạm, cộng kịch bản kiểm độc lập theo QA.md (D-64).
- **Cổng kiểm mỗi lát**:
  1. Người làm (Sonnet, hoặc Opus cho phần thiết kế nặng) viết test đỏ trước, lưu bằng chứng (log của lần chạy đỏ, hoặc tắt từng hành vi xem test bắt được).
  2. Người kiểm độc lập, không đọc lời giải thích của người làm. Dùng Opus cho phần nhận dữ liệu không tin cậy, khoá bí mật, quyền đồng ý quét.
  3. Sửa theo kết quả kiểm, rồi chạy gate.
  4. Màn hình giao diện cần thêm QA độc lập theo QA.md, chạy cả trên hộp thật.
- **Chồng lấn → Kiên làm (D-65).** Việc đụng module của Kiên hoặc phần dùng chung: mở issue `owner:kien`.
  - Phần dùng chung: `core/`, `cmd/` (trừ dòng nối dây chỉ thêm vào), `Makefile`, `go.mod`, `tools/`, `scripts/`, `.github/`, `web/src/lib`, `web/src/mocks`, `docs/DECISIONS.md`, `DATA_MODEL`, `API_CONVENTIONS`, `MODULE_CONTRACTS`.
  - File API sinh tự động (`api/openapi.json`, `core/api/oas`) thì sinh lại từ `contract.ts` của module mình; không sửa tay.
- **PR không chờ duyệt.** PR chạm file của Kiên thì @kiennt048 để báo. **Không tự đánh số D-xx**: ghi vào mục "Quyết định cần ghi" của PR, phiên của Kiên chép vào DECISIONS (ví dụ D-128, D-129, D-131, D-134, D-136).

## Đã merge (theo WP)
- **Giai đoạn 0 (thư viện):** #8, #10 findings · #15 notify · #16 ai · #28 feeds (D-67..D-70).
- **WP-20 feeds:**
  - #46 backend;
  - #80 giao diện chạy trên backend thật, đã sửa theo QA độc lập, EPSS kéo sau mỗi lần nạp KEV;
  - #93 KEV dự phòng qua kho GitHub của CISA khi cisa.gov chặn (D-91);
  - #135 bỏ SSLBL, Home không còn ghi "0" khi chưa từng nạp KEV (D-92, D-134).
- **WP-21 findings + mitigation:** #44 backend. Nối với inventory/feeds qua cổng và bus ở #56 (của Kiên, D-78).
- **WP-22 notify:**
  - #42 Zalo cá nhân;
  - #60 module: kênh, giao tin, link duyệt, chặn SSRF webhook. Lượt kéo KEV đầu tiên không gửi tin, đánh dấu bằng context (D-78, D-86);
  - #120 tin lỗ hổng gửi thật (danh mục finding), bỏ tin xếp hàng cũ hơn 24 giờ khi bật lại (D-86 (7), D-128).
  - Kiên nối Users/Mailer/BaseURL/Zone ở #69 và thêm đường duyệt ở #110, #128.
- **WP-23 exposure:**
  - #91: tự dò IP public, quét chỉ khi hộp còn thấy IP (INV-13), danh sách Ignored, 3 dịch vụ của 3 nhà vận hành (D-79, D-81).
  - Kiên sửa test chập chờn ở #90, #122.
- **WP-23 scan:** #127 S0 giao diện/mock theo D-125/D-126 (D-131) · #131 S1 cấu hình, lớp trừu tượng scanner.
- **Khác:** #59 sửa test ai chập chờn (#50) · #55, #30 handoff.

## Đang làm (mỗi việc một worktree, một agent)
- **WP-25 ai**, lát 1 (PR #123, `feat/ai-module`), D-129: hồ sơ, khoá, phân việc.
  - Đang sửa theo rà bảo mật: chỉ dùng lại khoá đã lưu khi cùng origin; ghi audit kể cả khi client ngắt; chặn link-local và metadata; truyền ctx vào `buildServices`; đổi sang `provider_error`.
  - Lát 2 (giải thích CVE, `feat/ai-explain`) đã viết xong.
  - Kế hoạch 7 lát nằm ở `.ai/deferred/feat-ai-module.md`. Thứ tự: 1, 2, 3, 4a, 4b, 4c, 6, 5, 7.
- **WP-23 scan** S2 (PR #138, đang giữ): đang sửa theo rà bảo mật.
  - Worker chỉ nhận IPv4 nội bộ.
  - Cờ nuclei dạng allow-list (`-pt`, `-dr`, `-nh`).
  - Mã băm gói ràng buộc với template thật sự chạy.
  - S3 (mục tiêu, Scan now/Stop, nhật ký probe, kết quả thành finding) đã qua chạy đỏ. S4 (lịch, quét lại khi có KEV) đang viết. S5 chờ #115.
- **WP-21 giao diện findings/mitigation trên API thật** (`feat/findings-gui-real`):
  - Đối chiếu API thật với mock không thấy lệch.
  - Đang sửa 3 spec cũ đỏ sẵn trên main, và cho gói mẫu khớp với mock (`packs.ts` là chuẩn).
  - Sau đó: QA độc lập rồi mới mở PR.

## Chờ từ Kiên
- **#115 scan S5:**
  - proto 2 (job nuclei);
  - dispatcher tách khe nuclei;
  - worker chạy nuclei với môi trường sạch;
  - image scan có nuclei và gói template;
  - cờ `Careful` trên `ScanDecision`.
- **#114:** phần đọc của core/conn đã xong ở #126 (D-127). Phần xuất `ai_activity` đang ở #137.
- **#62 notify:** `Tokens` (response), `BoxAddrs` (podman).
- **#79:** câu chữ bảng nóng khi chưa có KEV (#136, D-134); `answered_by` trong DATA_MODEL.

## Kế tiếp
1. Merge ai lát 1 → lát 2 → 3 (dùng nguồn export của #137) → 4a/4b/4c → 6 → 5 (`core/conn/read`) → 7 (`Propose`, D-97/D-119).
2. scan S2 → S3 → S4. S5 làm sau #115.
3. Findings/mitigation: QA độc lập, rồi PR.
4. Feeds: dòng trống của bảng nóng theo tiêu chí mới (#136).
5. Notify, việc tiếp theo:
   - Zalo listener, Slack Socket Mode, Telegram (D-96: notify lo đường truyền);
   - giao diện notify chuyển sang API thật;
   - mã hoá URL webhook (SYS-4).
6. Giai đoạn 2: WP-24 logs, WP-26 agent-intake, WP-27 reports/mcp-server/auth-oidc.

## Bẫy kỹ thuật
- **Mọi lệnh nặng đi qua `heavy`**: `go build/vet/test/generate`, `make generate-*`, `make dev-api`, `pnpm tsc/build/vitest/playwright`. Chỉ git, cat, grep, ls, gofmt được chạy ngoài.
  - Riêng việc biên dịch `core/api/oas` đã tốn ~2,3 GB. Ngày 2026-11-10, vài agent `go build ./...` ngoài khoá làm WSL hết RAM.
  - WSL có 5 GB / 3 CPU (máy 4 CPU / 12 GB).
- **Script để dưới `~/`, không để ở `/tmp`:** WSL tự khởi động lại thì `/tmp` bị xoá.
- **`wsl.exe` tự thay `$VAR`, `$?` và `$(...)`** trước khi bash chạy, nên đặt lệnh trong file script.
- **Health script 10 phút** (`C:/Users/BYN/.vedette-tools/health.sh`), chạy từ lịch của phiên:
  - tiến trình treo, mồ côi, chạy trùng;
  - tiến trình Go chạy ngoài `heavy`;
  - WSL treo, đồng hồ lệch;
  - thay đổi trên GitHub.
  
  Lớp bọc (`heavy`, `timeout`, script gate) đang chờ khoá thì không tính là treo. Trạng thái phiên chi tiết nằm ở `C:/Users/BYN/.vedette-tools/SESSION-STATE.md`.
- **Playwright trong WSL:** Chromium tải bằng `pnpm --dir web e2e:install`, cộng các thư viện apt `libnss3 libnspr4 libasound2t64 fonts-liberation fonts-noto-color-emoji`.
- **`gh` không có trong WSL:** gọi `gh` từ Git Bash bên Windows, đưa file nội dung PR qua đường dẫn `//wsl.localhost/...`.
- **Test có giới hạn thời gian thật dễ chập chờn trên CI bận** (#50, #89, #122). Chỉ dùng trần rộng để bắt bùng nổ; kiểm tính đúng bằng điều kiện tất định.
- **Giá trị test giống secret thật** (webhook Slack, token Telegram…) bị GitHub push protection chặn. Ghép lúc chạy hoặc dùng giá trị rõ là giả.
- **Struct handler nhúng phải mang tên riêng** (`FeedHandlers`, `NotifyHandlers`, `ExposureHandlers`, `AIHandlers`…).
- **Migration chưa merge được sửa tại chỗ**; DB dev tạo từ bản cũ của nhánh thì xoá `.dev/vedette.db`.
- **Máy Ubuntu thứ hai làm máy chạy gate** (Emily cho phép 2026-11-10): khoá SSH `~/.ssh/vedette_runner` trong WSL, chỉ phiên lead dùng. Agent con không SSH.
