# MCP-server Contract

> Tier: tuỳ chọn (tắt mặc định) · Story: S-MCP-1 · Quyết định: D-18, D-39, D-230..D-234, D-395 (đối chiếu: đây là MCP **do Vedette phục vụ**; MCP/kết nối **ra ngoài** của AI thuộc `core/conn`, D-93) · Last verified: 2026-11-13
> GUI nằm dưới `core` (`web/src/features/core/{contract,McpSection,mocks}.ts`, mục `/core/mcp`). Backend: `modules/mcp-server` (package `mcpserver`), nối ở `cmd/vedette/mcpserver.go`.

## Invariants (luôn đúng)
- **INV-1** **Chỉ đọc**: bảy công cụ cố định, theo thứ tự `tools/list` — `list_assets`, `get_asset` (scope `assets`); `list_findings`, `get_finding` (scope `findings`); `lookup_cve`, `lookup_ioc`, `hot_vulnerabilities` (scope `feeds`). Mỗi công cụ có `inputSchema` (`additionalProperties: false`), `outputSchema`, chú thích `readOnlyHint: true`, `destructiveHint: false`. Không công cụ ghi, không công cụ chạy lệnh, không đường vào `response` (SYS-8, D-41).
- **INV-2** Phạm vi token ∈ {`assets`, `findings`, `feeds`}; tạo token cần ≥ 1 phạm vi hợp lệ (400 `invalid_scopes`). `tools/list` chỉ liệt kê công cụ thuộc phạm vi của token; gọi công cụ ngoài phạm vi → lỗi JSON-RPC `-32602`, không đọc nguồn, không trả một phần. Một phạm vi chỉ trả dữ liệu của module sở hữu nó (token `feeds` không thấy thiết bị khớp một CVE, D-233).
- **INV-3** Token dạng `vmcp_` + 32 ký tự hex (128 bit); **trả đầy đủ đúng một lần** lúc tạo; sau đó chỉ `last4`; lưu SHA-256 hex (SYS-4, D-231); không log, không export. Bản sao lưu chỉ có bản băm, không dựng lại được token.
- **INV-4** Thu hồi (xoá dòng) có hiệu lực ở yêu cầu kế tiếp; token bị thu hồi, sai dạng hoặc không có → 401 với `WWW-Authenticate: Bearer`. `last_used` ghi ở mỗi lời gọi công cụ, các yêu cầu khác tối đa mỗi phút một lần.
- **INV-5** Máy chủ **chỉ tới được từ loopback của máy**: cờ `-mcp-listen` (mặc định `127.0.0.1:8765`, endpoint `http://127.0.0.1:8765/mcp`); địa chỉ không phải loopback → không khởi động. Ngoại lệ duy nhất (D-395): **trong container** (`Config.InContainer`, cmd/vedette thấy `/run/.containerenv` hoặc `/.dockerenv`) được nhận **địa chỉ unspecified** `0.0.0.0`/`[::]` — namespace mạng riêng của container, không phải LAN — vì runtime chuyển publish tới địa chỉ của container chứ không tới loopback của nó; đơn vị Quadlet `core` và `compose.yaml` chỉ-container chỉ publish `127.0.0.1:8765:8765` (test golden của host/ops, `deploy/compose/compose_test.go`), và `GET /core/mcp` vẫn báo `127.0.0.1:<port>`. Địa chỉ cụ thể khác (LAN, IP của container) luôn bị từ chối. Mở ra ngoài host là đường hầm/proxy khách tự dựng (D-234).
- **INV-6** Đầu vào công cụ validate ở biên (SYS-2): chỉ tên đối số trong schema, đúng kiểu, độ dài; CVE theo `CVE-YYYY-NNNN+`, id theo `^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$`, IOC là IP hoặc tên miền theo đúng quy tắc `validDomain` của feeds (nhận cả TLD IDN dạng ASCII như `discord.xn--q9jyb4c`, `TestContract_INV7_AnswersFitTheirOutputSchema`). Sai → kết quả `isError: true` với lời giải thích để agent sửa.
- **INV-7** Dữ liệu trả về chỉ gồm tài sản, phát hiện, tra cứu feed, theo danh sách cho phép từng trường (D-233). **Không** trả: bí mật, khoá API, token, người dùng, audit, nhật ký AI/phản ứng, cấu hình kênh, nội dung log thô, kết nối ngoài, MAC, ghi chú, người đổi trạng thái và ghi chú của họ, tóm tắt/request/response của lần quét (tóm tắt nêu thiết bị: dữ liệu inventory). Trả theo `outputSchema`; trang ≤ 100 mục, câu trả lời ≤ 512 KiB, chuỗi bị cắt (SYS-6, D-232).
- **INV-8** Thao tác quản trị (tạo/thu hồi token; bật/tắt là của `core` qua `PATCH /modules/mcp-server`) ghi `core_audit` (SYS-3), vai admin. **Mỗi `tools/call` một dòng `core_audit`** `mcp.call` (tên token, công cụ, kết quả, số mục), ghi trước khi trả lời; **không ghi đối số** — đó là điều agent hỏi (D-232).
- **INV-9** Giao thức (D-230): Streamable HTTP, chỉ `POST`; dual-era — `_meta` của 2026-07-28 (header `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name` bắt buộc và phải khớp thân, sai → 400 `-32020`; thời cũ có gửi thì cũng phải khớp) hoặc `initialize` của 2025-03-26..2025-11-25; không cấp `Mcp-Session-Id`, không SSE, không batch; có header `Origin` → 403.
- **INV-10** Giới hạn (D-232): mỗi token 30 yêu cầu dồn, nạp 30/phút, mọi yêu cầu đã xác thực đều tính; 2.000 lời gọi công cụ/ngày; chỗ trả lời 4 cả máy chủ, 2 mỗi token, giữ sau khi đọc xong thân, chờ ≤ 2 s; tối đa 10 token (400 `too_many`). Vượt → 429 + `Retry-After`, không ghi audit.
- **INV-11** `GET /core/mcp` nói cổng có mở không (`listening`, `listen_error`); cổng bị chương trình khác giữ thì màn hình cảnh báo, hộp thử lại mỗi 15 giây (D-230).

## Preconditions (trước khi gọi)
- **PRE-1** `/core/mcp*`: vai admin; module `mcp-server` bật (tắt → 404, SYS-5). Bật/tắt bằng `PATCH /modules/mcp-server` (vai admin, `core`).
- **PRE-2** Gọi công cụ: module bật, `Authorization: Bearer <token>` hợp lệ có phạm vi của công cụ.

## Postconditions (sau khi xong)
- **POST-1** Bật → cổng mở trên loopback (trong container: listener trong namespace của nó; publish `127.0.0.1:8765` của runtime giữ cổng phía máy suốt lúc container chạy, module tắt thì kết nối tới đó bị từ chối/cắt, D-395); tắt → cổng đóng, kết nối đang mở bị cắt, mọi token không dùng được nhưng **không bị xoá** (S-CORE-1).
- **POST-2** `POST /core/mcp/tokens` trả `{token, item}` (201); danh sách sau đó chỉ có `item` (có `last4`).
- **POST-3** `GET /core/mcp` trả trạng thái, `bind`/`port`/`endpoint` của listener đang chạy, token (không bí mật), danh sách công cụ + phạm vi.

## Forbidden (không bao giờ)
- **FORBID-1** Công cụ ghi, kể cả "tạm thời" hoặc theo token đặc quyền.
- **FORBID-2** Trả bí mật/khoá/token của người dùng, audit, hoặc dữ liệu ngoài ba phạm vi.
- **FORBID-3** Lưu token ở dạng đọc được; trả lại token đầy đủ lần thứ hai.
- **FORBID-4** Nghe ngoài loopback, trừ địa chỉ unspecified trong container mà đơn vị chỉ publish trên `127.0.0.1` (INV-5, D-395); không bao giờ publish trên địa chỉ LAN.
- **FORBID-5** Dùng đường MCP này để AI của chính Vedette gọi (AI dùng công cụ nội bộ, `ai` INV-14); hai thứ tách nhau.

## Endpoints owned
| Method | Path | Vai tối thiểu | Story |
|---|---|---|---|
| GET | `/core/mcp` | admin | S-MCP-1 |
| POST | `/core/mcp/tokens` | admin | S-MCP-1 |
| DELETE | `/core/mcp/tokens/{id}` | admin | S-MCP-1 |
| (MCP, HTTP) | `POST http://127.0.0.1:8765/mcp` | Bearer token theo phạm vi | S-MCP-1 |

Các `/core/mcp*` nằm dưới tiền tố `core` trong `contract.ts` của GUI nhưng thuộc module này (`core/server/modules.go`). Công cụ MCP không có trong `contract.ts`; danh sách và schema ở `modules/mcp-server/tools.go` là hợp đồng.

## Tables owned
`mcp_tokens` (id, name, scopes, token_hash, last4, created_at, last_used).

## Events
- **Phát**: không. **Nhận**: không. Đọc inventory, findings, feeds qua cổng `mcpserver.Source` (`cmd/vedette/mcpserver.go`: dịch vụ inventory/findings, handler feeds), không đọc bảng của module khác.

## Khi tắt module (SYS-5)
Cổng đóng, không route `/core/mcp*` (404), không job. Token giữ nguyên nhưng vô dụng. Agent/SIEM ngoài mất kết nối (lỗi kết nối, không phải 401). UI nói "MCP server is off" và chỉ còn công tắc. Module nguồn (inventory, findings, feeds) tắt → công cụ của phạm vi đó trả lỗi công cụ nói rõ module nào tắt.

## Dependencies
- **DEPENDS ON**: `core` (auth admin, audit), mềm: `inventory`, `findings`, `feeds`.
- **DEPENDED ON BY**: không module nào (người dùng ngoài: agent/SIEM). `core` đọc công tắc cho luồng quyền riêng tư 13.

## Câu hỏi mở
1. ~~Loopback trong container `core`~~ D-395 (thay D-234 (3)): trong container nghe `0.0.0.0:8765`, đơn vị Quadlet và `compose.yaml` publish `127.0.0.1:8765` của máy. Máy khác: đường hầm SSH/proxy của khách.
2. ~~Giới hạn trang và tốc độ~~ D-232.
3. ~~Bằng chứng quét trong `get_finding`~~ D-233: chỉ tóm tắt, mẫu và lúc kiểm; request/response thô ở lại hộp.
4. ~~Tên bảng~~ `mcp_tokens` (WP-06).
