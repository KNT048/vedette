# AI — Change Impact Map

> Chưa có mã Go; chữ ký là kế hoạch (package `modules/ai`), chốt ở M6.

## Modifying: `RunJob(ctx, job AiJob, in JobInput) (JobResult, error)` — 6 người gọi
- **core UI handlers** (`/ai/cve/{id}/explain|news`, `/ai/ask`, `/ai/logs/digest`): đổi lỗi `ai_unavailable` → toàn bộ nút AI hiển thị sai trạng thái.
- **reports** (`weekly-report`, `pdpl-assessment`): đổi `JobResult` → nhận xét AI trong báo cáo vỡ.
- **response** (`response-plan`): đổi cấu trúc kế hoạch → `/response/plans` và bước đề xuất hành động vỡ.
- **mitigation** (`mitigation-config`, "Hỏi AI của tôi"), **logs** (`log-digest`): đổi nhãn "AI tạo" → vi phạm S-AI-6.
- Thêm việc mới: thêm vào `AiJob`, bảng phân việc, ghi `data: internal|public` (quyết định INV-3), cập nhật GUI.

## Modifying: `Profiles.Resolve(job) ([]Profile, error)` (chọn chính/dự phòng, INV-3)
- Mọi `RunJob`. Đổi logic loại hồ sơ cloud → có thể rò dữ liệu nội bộ; test INV-3 bắt buộc xanh.

## Modifying: `Tools.ForModel(job) []Tool` (INV-14)
- **mcp-server**: không dùng. **ask-my-data / log-investigate**: thêm công cụ chỉ-đọc mới = đổi bề mặt dữ liệu AI thấy; công cụ `write` không bao giờ vào danh sách.

## Modifying: `Connections` (`Get`, `ToolsWrite`) — nhà cung cấp cho response
- **response**: danh mục hành động chọn `connection_id`, chỉ được dùng kết nối có công cụ ghi bật; đổi `ConnectorTool.access` hoặc `Connector.status` → hành động `tool_unavailable`/`tool_not_allowed`.

## Modifying: `Activity.Append(entry)` / `Activity.Verify()` (D-48)
- **core/logs export** (`ai_activity`), **GUI Activity panel**: đổi công thức hash → chuỗi cũ không kiểm lại được; phải có bước di trú (ghi `version` vào entry).

## Modifying: `Hooks.Run(when, text)`
- Mọi `RunJob`, `Ask`. Đổi thứ tự (block trước mask) hoặc thêm hook dựng sẵn → thay đổi dữ liệu rời hộp (PRIVACY luồng 3).

## Disabling this module
- Hết nút AI (Findings/CVE, Logs digest, báo cáo, Assistant); `response` mất kế hoạch AI và **mất cả kết nối để thực thi** (chỉ còn quy tắc cảnh báo/danh sách chặn/webhook); `mitigation` chỉ hiện "Chưa có khuyến nghị đã xác nhận" + KEV requiredAction.
- Không cuộc gọi nào ra provider. `ai_*` và chuỗi nhật ký giữ nguyên.
