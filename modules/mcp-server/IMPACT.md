# MCP-server — Change Impact Map

> Package `modules/mcp-server` (`mcpserver`); nối ở `cmd/vedette/mcpserver.go`. Test: `go test ./modules/mcp-server/... -run Contract`, `go test ./cmd/vedette -run 'MCP'`.

## Modifying: `Tools` (tập công cụ, schema, phạm vi) — 2 người gọi
- **Agent/SIEM của khách** (ngoài hệ thống): đổi tên công cụ/schema trả về → agent đã cấu hình hỏng không báo lỗi rõ. Thêm công cụ = đổi bề mặt dữ liệu rời hộp theo tay người dùng: đặt vào một phạm vi sẵn có, ghi vào CONTRACT INV-1 và PRIVACY luồng 13. `TestContract_INV7_AnswersFitTheirOutputSchema` bắt câu trả lời lệch schema.
- **web/features/core/McpSection**: hiển thị `tools[]`/`scopes[]` từ `GET /core/mcp` và nhãn `mcp.tools.<tên>` trong `core.json`; thêm công cụ → thêm nhãn, mock `MCP_TOOLS`.

## Modifying: `Source` (cổng dữ liệu) và `mcpSource` (cmd/vedette)
- Là **người tiêu thụ** `inventory.Service.Devices/Device`, `findings.Service.List/Get`, `feeds.FeedHandlers.FeedsGetFeedsCveID/Search/Hot`: đổi trường ở đó không tự lọt ra (danh sách cho phép từng trường, D-233) nhưng có thể làm mất trường ở đây. Lọc bí mật nằm ở `mcpSource`, không dựa vào module nguồn; `TestMCPServerOnTheRealWiring` kiểm MAC, ghi chú, request/response quét và người duyệt không tới agent.

## Modifying: `authenticate`, `CleanScopes`, `hashToken`
- Đổi so khớp phạm vi hoặc cách băm → token cũ có thể thành vô hiệu hoặc quá quyền; test INV-2/INV-3/INV-4 bắt buộc.

## Modifying: `rpc.go` (giao thức)
- Đổi phiên bản hỗ trợ, header bắt buộc hoặc mã lỗi → khách MCP thật (Claude Code, v.v.) có thể không kết nối; `TestContract_Transport`, `TestContract_BothEras`.

## Modifying: bind/port (`-mcp-listen`, `DefaultListen`)
- Đổi từ loopback sang giao diện khác = thay đổi bảo mật + PRIVACY (INV-5, FORBID-4); `New` và `parseMCPListen` từ chối, test `TestContract_INV5_LoopbackOnly`, `TestParseMCPListen`. Cờ nằm trong `newFlags`: đơn vị Quadlet của `core` (host/ops) đọc cùng bộ cờ.

## Modifying: `recordCall` / giới hạn
- Bỏ dòng audit mỗi lời gọi vi phạm INV-8 (`TestContract_INV6_INV8_…`); nới giới hạn làm tăng trần dòng audit (D-232).

## Disabling this module
- Cổng đóng; agent/SIEM ngoài mất truy cập. Không module nào của Vedette phụ thuộc. Token và cấu hình giữ nguyên. Settings → Privacy luồng 13 thành `off`.
