# MCP-server — Change Impact Map

> Chưa có mã Go; chữ ký là kế hoạch (package `modules/mcpserver`), chốt ở M6.

## Modifying: `Tools()` (tập công cụ) và scope map — 2 người gọi
- **Agent/SIEM của khách** (ngoài hệ thống): đổi tên công cụ/schema trả về → agent đã cấu hình hỏng không báo lỗi rõ. Thêm công cụ = đổi bề mặt dữ liệu rời hộp (theo tay người dùng), phải đặt vào một phạm vi sẵn có hoặc thêm phạm vi mới và ghi vào CONTRACT.
- **web/features/core/McpSection**: hiển thị `tools[]`/`scopes[]` từ `GET /core/mcp`; đổi → sinh lại OpenAPI.

## Modifying: `Authorize(token, scope) error` — mọi lời gọi công cụ
- Đổi so khớp phạm vi hoặc cách băm → token cũ có thể thành vô hiệu hoặc quá quyền; test INV-2/INV-3 bắt buộc.

## Modifying: `inventory.ListAssets`, `findings.List`, `feeds.Lookup*` (interface nguồn)
- Là **người tiêu thụ**: đổi trường → trả về MCP đổi theo, agent ngoài thấy khác. Lọc bí mật phải nằm ở lớp MCP, không dựa vào module nguồn.

## Modifying: bind/port
- Đổi từ loopback sang giao diện khác = thay đổi bảo mật + PRIVACY (INV-5).

## Disabling this module
- Cổng 8765 đóng; agent/SIEM ngoài mất truy cập. Không module nào của Vedette phụ thuộc. Token và cấu hình giữ nguyên.
