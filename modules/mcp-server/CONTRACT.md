# MCP-server Contract

> Tier: tuỳ chọn (tắt mặc định) · Story: S-MCP-1 · Quyết định: D-18, D-39 (đối chiếu: đây là MCP **do Vedette phục vụ**; MCP/kết nối **ra ngoài** của AI thuộc module `ai`) · Last verified: 2026-11-09
> GUI nằm dưới `core` (`web/src/features/core/{contract,McpSection,mocks}.ts`, mục `/core/mcp`). Backend là module riêng.

## Invariants (luôn đúng)
- **INV-1** **Chỉ đọc**: bảy công cụ cố định — `list_assets`, `get_asset` (scope `assets`); `list_findings`, `get_finding` (scope `findings`); `lookup_cve`, `lookup_ioc`, `hot_vulnerabilities` (scope `feeds`). Không công cụ ghi, không công cụ chạy lệnh, không đường vào `response` (SYS-8, D-41).
- **INV-2** Phạm vi token ∈ {`assets`, `findings`, `feeds`}; tạo token cần ≥ 1 phạm vi hợp lệ (400 `invalid_scopes`). Một lời gọi công cụ chỉ thành công khi token có đúng phạm vi của công cụ đó; thiếu → từ chối, không trả một phần.
- **INV-3** Token dạng `vmcp_` + 32 ký tự hex; **trả đầy đủ đúng một lần** lúc tạo; sau đó chỉ `last4`; lưu dạng băm (SYS-4); không log, không export, không vào sao lưu.
- **INV-4** Thu hồi có hiệu lực ngay; token bị thu hồi hoặc sai → 401. `last_used` cập nhật mỗi lần dùng.
- **INV-5** Máy chủ **chỉ bind `127.0.0.1`** (`bind`, `port` 8765, `endpoint .../mcp`); không bao giờ bind 0.0.0.0 từ công tắc này. Mở ra ngoài host (nếu cần) là cấu hình mạng khác, có trong IMPACT/câu hỏi mở.
- **INV-7** Dữ liệu trả về chỉ gồm tài sản, phát hiện, tra cứu feed. **Không** trả: bí mật, khoá API, token, người dùng, audit, nhật ký AI/phản ứng, cấu hình kênh, nội dung log thô, kết nối ngoài. Trả về theo schema, có giới hạn kích thước trang (SYS-6, trị số chốt khi viết).
- **INV-8** Mọi thao tác quản trị (bật/tắt, tạo/thu hồi token) ghi `core_audit` (SYS-3), vai admin; không ghi nội dung truy vấn của agent ngoài (chỉ số lần dùng, `last_used`).
- **INV-6** Đầu vào của công cụ (mã CVE, IOC, id) validate theo schema ở biên (SYS-2); từ chối dạng không hợp lệ.

## Preconditions (trước khi gọi)
- **PRE-1** `PATCH /core/mcp {enabled:true}`: vai admin; module `mcp-server` bật.
- **PRE-2** Gọi công cụ: máy chủ đang bật và có `Authorization: Bearer <token>` hợp lệ có phạm vi phù hợp.

## Postconditions (sau khi xong)
- **POST-1** Bật → cổng 8765 mở trên loopback; tắt → cổng đóng, mọi token không dùng được nhưng **không bị xoá** (S-CORE-1).
- **POST-2** `POST /core/mcp/tokens` trả `{token, item}` (201); danh sách sau đó chỉ có `item` (có `last4`).
- **POST-3** `GET /core/mcp` trả trạng thái, token (không bí mật), danh sách công cụ + phạm vi.

## Forbidden (không bao giờ)
- **FORBID-1** Công cụ ghi, kể cả "tạm thời" hoặc theo token đặc quyền.
- **FORBID-2** Trả bí mật/khoá/token của người dùng, audit, hoặc dữ liệu ngoài ba phạm vi.
- **FORBID-3** Lưu token ở dạng đọc được; trả lại token đầy đủ lần thứ hai.
- **FORBID-4** Bind ngoài loopback bằng công tắc `enabled`.
- **FORBID-5** Dùng đường MCP này để AI của chính Vedette gọi (AI dùng công cụ nội bộ, `ai` INV-14); hai thứ tách nhau.

## Endpoints owned
| Method | Path | Vai tối thiểu | Story |
|---|---|---|---|
| GET | `/core/mcp` | admin | S-MCP-1 |
| PATCH | `/core/mcp` | admin | S-MCP-1 |
| POST | `/core/mcp/tokens` | admin | S-MCP-1 |
| DELETE | `/core/mcp/tokens/{id}` | admin | S-MCP-1 |
| (MCP, HTTP) | `http://127.0.0.1:8765/mcp` | Bearer token theo phạm vi | S-MCP-1 |

Các `/core/mcp*` nằm dưới tiền tố `core` trong `contract.ts` của GUI nhưng thuộc module này. Công cụ MCP (7 công cụ) không có trong `contract.ts`; danh sách ở trên là hợp đồng.

## Tables owned
`mcp_tokens` (id, tên, phạm vi, băm token, `last4`, `created_at`, `last_used`). Mock: `core_mcp_tokens`.

## Events
- **Phát**: không. **Nhận**: không. Đọc `inventory`, findings, `feeds` qua interface chỉ-đọc.

## Khi tắt module (SYS-5)
Cổng 8765 đóng, không route `/core/mcp*`, không job. Token giữ nguyên nhưng vô dụng. Agent/SIEM ngoài đang dùng mất kết nối (client nhận lỗi kết nối, không phải 401). UI nói "MCP đang tắt".

## Dependencies
- **DEPENDS ON**: `core` (auth admin, audit, `core/secrets` băm), mềm: `inventory`, `feeds`, findings.
- **DEPENDED ON BY**: không module nào (người dùng ngoài: agent/SIEM).

## Câu hỏi mở
1. Loopback trong container `core` (D-55): agent/SIEM **ở máy khác** không với tới được. Cách mở (publish cổng trên loopback của host + SSH tunnel, hay reverse proxy có TLS)? Nếu mở ra LAN thì cần TLS và có thể thêm luồng/cổng → PRIVACY, MANIFEST `ports`.
2. Giới hạn kích thước trang và tốc độ gọi cho từng công cụ (SYS-6).
3. Có cần phạm vi riêng cho `findings` chứa bằng chứng quét (request/response rút gọn) không, hay `get_finding` trả bản đã lọc?
4. Tên bảng: mock `core_mcp_tokens` vs tiền tố module `mcp_`.
