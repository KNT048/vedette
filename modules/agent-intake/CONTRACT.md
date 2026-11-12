# Agent-intake Contract

> Tier: tuỳ chọn (tắt mặc định) · Story: S-INV-4 · Quyết định: D-33, D-34, D-55, D-169, D-265, D-305..D-309 · Last verified: 2026-11-12 (WP-26 lát 2: osquery `enroll`/`config`/`log`/`status`, token ở mức dịch vụ, bảng, ánh xạ gói; lát 4: kéo Wazuh — test/save/delete, job `wazuh-pull`; chưa có đường admin của token, script: lát 3)
> GUI nằm dưới `inventory` (`web/src/features/inventory/{contract,AgentsSection,installScripts,agentConfig}.ts*`). Backend là module riêng.

## Invariants (luôn đúng)
- **INV-1** Chỉ hai nguồn: osquery (Vedette là máy chủ TLS cho osquery) và Wazuh (hộp kéo qua Wazuh server API). Không Trivy, không macOS, không ship agent (D-33). `AgentKind = ['osquery']`; Wazuh không có token.
- **INV-2** Hệ điều hành hỗ trợ chỉ là máy chủ: Linux (Debian, Ubuntu, RHEL, Rocky, AlmaLinux) và Windows Server. Script cài khác theo OS: Linux dùng curl + kiểm SHA-256 + bash; Windows dùng PowerShell 5.1 + `Get-FileHash` (D-34).
- **INV-3** Token osquery: chỉ dùng để đăng ký osquery và hỏi trạng thái; **không đọc được gì khác**. Hiện đầy đủ đúng một lần lúc tạo (`CreateTokenResult.secret`); sau đó chỉ `last4`; lưu dạng băm. Hết hạn mặc định 7 ngày (`expires_in_days` 0..365, 0 = không hết hạn); thu hồi được và có hiệu lực ngay. Token 160 bit, lưu SHA-256; sau `enroll` mỗi máy có `node_key` riêng 256 bit (lưu SHA-256, bảng `intake_osquery_nodes`, D-169 (2)): hết hạn chỉ chặn đăng ký mới, thu hồi xoá luôn các máy của token đó.
- **INV-4** Token không bao giờ nằm trong URL: chỉ header `Authorization: Bearer` (`POST /intake/osquery/status`). Token không vào log, audit, export (SYS-4).
- **INV-5** Script cài (`/install/osquery.sh`, `/install/osquery.ps1`) phục vụ công khai, **không chứa bí mật**; token truyền bằng tham số. Mỗi script có SHA-256 hiển thị trong GUI để người dùng so trước khi chạy. Gói osquery chính thức do hộp phục vụ nên máy chủ không cần Internet (D-34): ba tệp (`.deb`, `.rpm`, `.msi`) + `SHA256SUMS` **đóng sẵn trong image**, phiên bản và hash ghim trong repo, kiểm lúc dựng; không tải lúc chạy, không luồng ra mới (D-169 (10)). Có lệnh gỡ một dòng. Script và `ca.pem` nhúng/trả cùng một chứng chỉ ghim (INV-11).
- **INV-6** Wazuh: tài khoản chỉ đọc (`agent:read`, `syscollector:read`); `url` phải là https; mật khẩu lưu mã hoá qua `core/secrets`, API chỉ trả `password_last4`; `interval_minutes` ∈ {5, 15, 60, 360, 1440}; `status` ∈ {never, connected, error}. Xoá kết nối xoá luôn mật khẩu.
- **INV-7** Dữ liệu từ agent/Wazuh là không tin cậy (SYS-6): parser fail-closed, giới hạn kích thước (đăng ký 64 KiB, config 4 KiB, log 4 MiB, status 1 KiB), chỉ đọc cột trong danh sách cho phép của truy vấn đã biết; khoá thừa ở lớp ngoài của osquery (`decorations`, `epoch`, …) được **bỏ qua và không lưu** (từ chối chúng sẽ hỏng mỗi lần nâng osquery, D-169 (8)); dòng sai kiểu hoặc sai chữ bị bỏ riêng, phần còn lại giữ; gói/phiên bản chỉ vào kho qua `inventory` với `source = agent`, `confidence` cố định (mock dùng 0.95; hộp tự khai gói dpkg của chính nó là 1.0, D-53).
- **INV-8** Phần mềm nguồn `agent` được thay ở lần báo kế tiếp; phần mềm khai tay (`source=manual`) không bị đụng.
- **INV-9** Mọi mutation (tạo/thu hồi token, lưu/xoá Wazuh) ghi `core_audit` (SYS-3).
- **INV-10** Điểm cuối `.../sample-data` là **chỉ bản xem trước (mock)**; trong bản dựng thật chúng vẫn nằm trong hợp đồng và bảng route (sinh từ OpenAPI) nhưng handler trả 404 `not_found` như đường không tồn tại, và nút trong GUI không hiện (`MOCK_BUILD`).
- **INV-11** (D-169 (9)) Chứng chỉ osquery ghim là một **CA riêng của hộp** (khoá riêng, `CA:TRUE`, `pathlen 0`, sống lâu) ký chứng chỉ lá 8443 tự tạo; D-139 chỉ cấp lại lá bằng cùng CA nên gia hạn hay đổi địa chỉ không làm máy đã đăng ký mất kết nối. Lá **không** được là CA (trình duyệt từ chối). `GET /intake/ca.pem` và script nhúng đúng chứng chỉ CA đó. Chứng chỉ chủ hộp đưa vào (`-tls-cert`) không bị đụng: `ca.pem` là chuỗi chủ hộp đưa vào (lá nếu tệp chỉ có lá; chủ hộp tự chạy lại lệnh cài khi đổi chứng chỉ của mình); từng kiểu (lá tự ký, CA riêng, CA công cộng) có test `openssl verify` ở lát 1. **Đã làm (WP-26 lát 1, D-262; D-351)**: CA của hộp ở `cmd/vedette/boxca.go` (hàng `core_secret` purpose `core_box_ca`, core INV-30: vào bản chụp cùng `vedette.db`, khôi phục với khoá chủ giữ nguyên CA nên máy đã đăng ký không phải cài lại; không vào bản xuất JSON), lá ở `tls.go` (`selfSignedPEM`), test `cmd/vedette/tls_ca_test.go` (`x509.Verify` chỉ với CA sau khi cấp mới, gia hạn, đổi địa chỉ, nâng cấp từ lá tự ký cũ, khôi phục sang thư mục mới; `openssl verify` nếu có). **`GET /intake/ca.pem`** (`handlers.go` `InventoryGetIntakeCaPem`, D-351 (5)): công khai, `application/x-pem-file`, lấy `Config.TrustAnchor` (cmd/vedette `intakeTrustAnchor`: chứng chỉ CA của hộp, hoặc tệp `-tls-cert` đọc lại mỗi lần) và **chỉ chép khối `CERTIFICATE`** (bỏ header PEM; khoá cùng tệp không bao giờ ra, `TestContract_INV11_CaPemServesTheCertificateOnly`); `TrustAnchor` nil (hộp HTTP trên loopback) → 404; module tắt → 404 (SYS-5). Còn lại: script cài nhúng cùng chứng chỉ (lát script); kiểu chủ hộp có chuỗi CA công cộng/riêng chưa có test `openssl verify`/osquery thật (`.ai/deferred/feat-agent-intake.md`).
- **INV-12** (D-169 (5), D-265 (3)) Hộp chỉ ghi gói và quan sát của một máy khi địa chỉ TCP của kết nối (`r.RemoteAddr`, không đọc header chuyển tiếp) nằm trong các IPv4 máy khai ở truy vấn `interfaces` (của chính yêu cầu `log` đó, hoặc cặp đã gắn lần trước nếu yêu cầu không có `interfaces` và địa chỉ vẫn đúng); MAC dùng là của đúng card đó. Không khớp (địa chỉ giả, NAT, IPv6, loopback/link-local) = không ghi gì, cặp gắn bị xoá (`bound_ip`/`bound_mac` NULL), có một dòng log mỗi giờ cho mỗi máy (đóng kín). Chỉ IPv4 (kho chỉ có IPv4). Gợi ý thiết bị cho kho **chỉ là IP** của kết nối, không kèm MAC (kho tìm thiết bị theo MAC trước, nên MAC do máy tự khai sẽ cho nó ghi lên máy khác); MAC của card chỉ vào như một quan sát `mac` độ tin cậy 0.9, kho từ chối nếu MAC đó là của thiết bị khác (D-265 (4), test `TestContract_INV12_MACClaimCannotWriteOnAnotherDevice`). Hệ quả chấp nhận: thiết bị đổi IP chưa được cảm biến gắn lại có thể có một bản ghi trùng cho tới khi cảm biến đối chiếu.
- **INV-13** (D-169 (8)) Giao thức osquery: mọi lỗi thông tin xác thực (token lạ/thu hồi/hết hạn, `node_key` sai hoặc sai dạng, `host_identifier` rỗng/không sạch) = HTTP 200 + `{"node_invalid": true}`, không phân biệt lý do; thân quá lớn, không phải JSON, sai dạng, quá tần suất = 413/400/429 với envelope chuẩn (`Retry-After` ở 429). Ngoại lệ của riêng `status` (D-265 (1)): 403 `invalid_token` / `token_expired` như mock đã duyệt, vì kiểu trả lời không có `node_invalid`. Không có `distributed` (không chạy truy vấn từ xa): đường đó không tồn tại.
- **INV-14** (D-265 (2)) Hạn mức công khai: > 10 lần sai thông tin xác thực/phút từ một nguồn (IPv6 gộp /64) → chặn 30 giây rồi nhân đôi tới 10 phút (429 `rate_limited`, kể cả cuộc gọi đúng của nguồn đó); mỗi máy 6 `config` + 12 `log` mỗi phút; đăng ký lại cùng (token, `host_identifier`) trong 60 giây = 429; 500 máy mỗi token, 5.000 máy cả hộp = 429 `too_many_nodes`; 50 token = 409 `too_many_tokens`.
- **INV-16** (lát 4, D-305..D-309) **Kéo Wazuh.** Client chỉ đọc: đúng một POST (`/security/user/authenticate?raw=true`, Basic), còn lại GET trên danh sách cho phép `/`, `/agents`, `/syscollector/{id}/{netaddr,netiface,packages}` với `id` khớp `^[0-9]{3,10}$` (kiểm trước khi gửi, `allowedCall`; FORBID-4, `TestWazuh_FORBID4_ReadOnlyCalls`). Đi qua facade `core/conn` (`Service.NewHTTPS`, D-305): chính sách địa chỉ D-94 lúc quay số, TLS ≥ 1.2, không chuyển hướng/proxy, yêu cầu ≤ 64 KiB, trả lời ≤ 1 MiB, 15 s mỗi lời gọi; trang 250 dòng; ≤ 4 lời gọi/giây; 429 chờ `Retry-After` (≤ 60 s, 2 lần mỗi lời gọi); 401 giữa chừng đăng nhập lại một lần; lượt kéo 10 phút, lượt dài đi tiếp ở nhịp sau từ agent sau `resume_after`. **Ghim** (D-308): Save (mật khẩu gõ) quyết định một lần — chứng chỉ được gốc công cộng bảo chứng → `tls_pin=system` (từ đó bắt buộc gốc công cộng), còn lại ghim SHA-256 khoá công khai (TOFU); lượt kéo và Test với mật khẩu đã lưu chỉ gửi tới đúng ghim; chứng chỉ đổi → kéo dừng `status=error` trước khi gửi mật khẩu, Test 502 `wazuh_tls`, Save để trống mật khẩu 400 `password_required` — **mật khẩu đã lưu không bao giờ tới khoá khác ghim**, chỉ gõ lại mật khẩu mới tin chứng chỉ mới. Mật khẩu đã lưu cũng không đi tới host:port khác (`password_required`). **Gắn thiết bị** (D-307): gợi ý chỉ là IP của agent (`ip`, nơi manager thấy agent) khi đó là IPv4 unicast nằm trong `netaddr` của chính agent (NAT → bỏ qua, đóng kín); MAC của card đó chỉ là quan sát 0.9 (`TestWazuh_MACClaimCannotWriteOnAnotherDevice`); bỏ agent loopback (manager `000`), agent `disconnected` im quá 7 ngày, agent trùng IP (giữ cái nghe gần nhất); gói `deb`/`rpm`/`win` qua cùng mapper với osquery, định dạng khác bỏ. Danh sách gói rỗng không xoá gì. Mỗi agent ghi qua `inventory` trong giao dịch riêng; không giao dịch nào mở qua mạng. Save/Delete trong lúc kéo: `generation` đổi, lượt kéo dừng ở agent kế và không ghi kết quả. Nguồn `agent` dùng chung với osquery: **bên ghi sau thắng** (giới hạn đã biết, D-169 (6); nâng cấp: giá trị nguồn `wazuh`).
- **INV-15** Danh sách gói rỗng (hoặc mọi dòng bị bỏ) không bao giờ thay danh sách cũ; chỉ truy vấn trong lịch (`schedule.go`, bằng đúng chữ GUI, có test so khớp) với cột trong danh sách cho phép được đọc; kết quả `status` của osquery bị bỏ; kết quả vi sai (`added`/`removed`) bị bỏ.

## Preconditions (trước khi gọi)
- **PRE-1** Tạo token / cấu hình Wazuh: vai admin (`/inventory/agents*`).
- **PRE-2** `PUT /inventory/agents/wazuh`: đăng nhập API thử thành công **trước** khi lưu (`/test` kiểm mà không lưu).
- **PRE-3** `server_url` = `https://<IP hộp>:8443`; chưa biết IP → `https://<VEDETTE_BOX_IP>:8443` (placeholder hiện rõ, không đoán).

## Postconditions (sau khi xong)
- **POST-1** Máy chủ chạy một dòng cài + token hợp lệ → `POST /intake/osquery/status` trả `{enrolled: true, hosts ≥ 1}` và thiết bị xuất hiện trong kho với danh sách gói, nguồn `agent`.
- **POST-2** Wazuh kết nối → mỗi chu kỳ `interval_minutes` cập nhật `last_sync`, `agents`, `packages`; lỗi → `status=error` và `error` có nội dung; không xoá dữ liệu cũ.
- **POST-3** Thu hồi token → máy dùng token đó bị từ chối ở lần báo kế tiếp; dữ liệu đã nhận giữ nguyên.
- **POST-4** Hết hạn token không làm máy đã đăng ký ngừng báo (token chỉ để đăng ký; quyết ở D-169 (3), câu hỏi mở 3 đã đóng). Token hết hạn chỉ bị xoá khi không còn máy nào dùng nó; máy im quá 90 ngày **khi module bật** bị dọn (job `node-prune`, job thường: không chạy khi module tắt, và chuỗi 90 ngày bắt đầu lại sau mỗi khoảng tắt hoặc khởi động lại; D-265 (8)).

## Forbidden (không bao giờ)
- **FORBID-1** Cài/chạy bất cứ thứ gì lên máy agent từ hộp (chỉ phục vụ script để người dùng tự chạy; D-33).
- **FORBID-2** Token hoặc mật khẩu Wazuh trong URL, log, export, sao lưu.
- **FORBID-3** Ghi trực tiếp bảng `inv_*`: chỉ qua interface của `inventory` (modules.md).
- **FORBID-4** Gọi Wazuh API bằng phương thức ghi (chỉ đọc: `agent:read`, `syscollector:read`, D-33).

## Endpoints owned
| Method | Path | Vai tối thiểu | Ghi chú |
|---|---|---|---|
| GET | `/inventory/agents` | admin | token, Wazuh, script cài, `server_url` |
| POST | `/inventory/agents/tokens` | admin | trả token đầy đủ một lần |
| DELETE | `/inventory/agents/tokens/{id}` | admin | thu hồi |
| POST | `/inventory/agents/tokens/{id}/sample-data` | admin | chỉ xem trước (INV-10) |
| PUT | `/inventory/agents/wazuh` | admin | xác minh rồi lưu |
| POST | `/inventory/agents/wazuh/test` | admin | không lưu |
| DELETE | `/inventory/agents/wazuh` | admin | xoá luôn mật khẩu |
| POST | `/inventory/agents/wazuh/sample-data` | admin | chỉ xem trước |
| GET | `/install/osquery.sh` | public | không bí mật |
| GET | `/install/osquery.ps1` | public | không bí mật |
| POST | `/intake/osquery/status` | public (Bearer token) | token trong header |
| POST | `/intake/osquery/enroll` | public (token trong thân, `enroll_secret`) | máy-với-máy; trả `node_key` một lần; INV-13 |
| POST | `/intake/osquery/config` | public (`node_key`) | lịch truy vấn chỉ đọc, snapshot |
| POST | `/intake/osquery/log` | public (`node_key`) | kết quả truy vấn → `inventory` (INV-7, INV-12) |
| GET | `/intake/ca.pem` | public | chứng chỉ ghim, không bí mật (INV-11); `application/x-pem-file`, 404 khi hộp không chạy TLS (D-351) |
| GET | `/install/osquery/{file}` | public | `SHA256SUMS` + 3 tệp gói (danh sách cố định, tra bảng, không ghép đường dẫn từ input); tên khác 404 |

Giao thức osquery TLS: `enroll`, `config`, `log` có trong `contract.ts` từ WP-26 lát 0 (câu hỏi mở 2 đã đóng); `distributed` không có (INV-13). Đường dẫn osquery nằm trong cờ `*_tls_endpoint` của script (`/api/v1/intake/osquery/{enroll,config,log}`).

## Tables owned
`intake_agent_tokens` (băm token, tên, hết hạn, `last_received`, số host), `intake_osquery_nodes` (băm `node_key`, token FK CASCADE, `host_identifier` duy nhất theo token, hostname, nền tảng, phiên bản osquery, `enrolled_at`, `last_seen`, `last_result_at`, `bound_ip`/`bound_mac`; D-169 (2), lát 2; số máy mỗi token tính lúc đọc, không có cột `hosts`), `intake_wazuh` (url, user, `secret_id` → `core_secret` purpose `intake_wazuh.password`, `password_last4`, chu kỳ, trạng thái, `tls_pin` = `system` hoặc SHA-256 khoá công khai, `generation`, `next_pull`, `resume_after`/`pass_packages`; lát 4, `0002_wazuh.sql`). Thiết bị/gói/quan sát thuộc `inventory` (`inv_*`).

## Dịch vụ (Go, `modules/agent-intake`, lát 2)
`IssueToken(ctx, actor, name, ttlDays) (Token, secret, error)` · `RevokeToken(ctx, actor, id)` · `ListTokens(ctx)` (các đường admin HTTP là lát 3) · `Enroll`/`Config`/`Log`/`Status` (qua `IntakeHandlers`) · `Prune` (job `node-prune`, job thường, D-265 (8): máy im 90 ngày, token hết hạn quá 30 ngày không còn máy) · `BodyLimits` (đăng ký 64 KiB, config 4 KiB, log 4 MiB, status 1 KiB). Ghi vào kho chỉ qua `core/observe` (`Sink.Record`, `SoftwareSink.ReplaceSoftware`, nguồn `agent`, độ tin cậy 0.95; MAC của card 0.9). Ánh xạ gói → khoá KEV: `pkgmap.json`, test đối chiếu catalog. Nguồn `agent` dùng chung với Wazuh: bên ghi sau thắng (D-169 (6)). **Wazuh (lát 4)**: `TestWazuh`/`SaveWazuh`/`DeleteWazuh` (qua `WazuhHandlers`; lỗi 400 `bad_url`, `bad_username`, `password_required`, `bad_password`, `bad_interval`; 422 `wazuh_auth`, `wazuh_forbidden`; 502 `wazuh_unreachable`, `wazuh_tls`, `wazuh_bad_reply`; 409 `wazuh_changed`; 404 `not_found` khi xoá mà chưa nối; `sample-data` 404, INV-10) · `Wazuh(ctx)` (kết nối không mật khẩu, cho `GET /inventory/agents` ở lát 3) · `WazuhConnected(ctx)` (luồng 14 của Settings → Privacy) · `WazuhPull` (job `wazuh-pull`, nhịp 1 phút, job thường). Cần `Config.Secrets` và `Config.Conn`; thiếu thì các route Wazuh 501 và job không làm gì.

## Events
- **Phát**: `inventory.observation` (tên có trong ARCHITECTURE) với `source=agent`.
- **Nhận**: không.

## Khi tắt module (SYS-5)
Không route `/install/*`, `/intake/*`, `/inventory/agents*`; không kéo Wazuh (job `wazuh-pull` là job thường: context bị huỷ ngay, không ghi gì thêm; `TestWazuh_SYS5_ModuleOffIs404`); osquery không đăng ký/báo được (mất kết nối). Token, cấu hình Wazuh và dữ liệu đã nhận giữ nguyên. Thiết bị nguồn `agent` ngừng cập nhật và hiển thị tuổi dữ liệu thật, không giả vờ mới.

## Dependencies
- **DEPENDS ON**: `core` (auth, `core/secrets`, TLS 8443, `core/conn` facade HTTPS cho Wazuh, D-305), `inventory` (nhận quan sát), `core/updates` (gói osquery chính thức nằm trong `managed` của Cập nhật).
- **DEPENDED ON BY**: `inventory` (cột nguồn `agent`, độ tin cậy cao), `exposure/scan` (không bắt buộc), `reports` (nguồn kiểm kê trong PDPL `inventory.sources`).

## Câu hỏi mở
1. ~~Tên bảng `inv_*` vs `intake_*`~~ Mock đã đổi sang `intake_agent_tokens`/`intake_wazuh` (WP-06).
2. ~~Đường dẫn osquery TLS API và `node_key`~~ Đóng (D-169 (1), (2), (8)): `contract.ts` có `enroll`/`config`/`log`.
3. ~~Token hết hạn có làm máy đã đăng ký ngừng báo không?~~ Đóng: không (D-169 (3)).
4. ~~Gói osquery lấy từ đâu~~ Đóng: đóng sẵn trong image, hash ghim, không luồng ra mới (D-169 (10)); dòng `THIRD_PARTY_NOTICES.md` cùng commit với bước dựng (lát 3).
5. ~~Chứng chỉ nhúng trong script~~ Đóng: là chứng chỉ CA công khai của hộp (không phải khoá); `MOCK_CA` chỉ là mẫu (D-169 (9), INV-11). Việc đổi hộp sang CA riêng làm ở lát 1 (core TLS).
6. [verify] Truy vấn `interfaces` (JOIN `interface_details` với `interface_addresses`) trên Windows Server thật và cầu nối Linux; script PowerShell dùng `curl.exe --cacert` (Windows Server 2019 có thể ship curl 7.55, chưa hỗ trợ `--cacert` với Schannel). Chờ máy Windows Server (D-169 (16)); trước đó chỉ test tĩnh, dòng `.ai/deferred` có ngày.
