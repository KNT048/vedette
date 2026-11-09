# features/ai

Story: S-AI-1 (nhiều hồ sơ AI, thử kết nối, công bố luồng dữ liệu), S-AI-3 (tin mới về CVE, nguồn do hộp tải), S-AI-4 (mức, trần chung và trần từng hồ sơ, hạ mức, đồng hồ, nhật ký, phân việc chính/dự phòng, luật "dữ liệu nội bộ chỉ gửi hồ sơ nội bộ"), S-AI-5 (hỏi dữ liệu bằng tool chỉ-đọc), S-AI-6 (mọi output trong `AiBlock`, không nút hành động).
Slot cung cấp: `cve.panels` (props `{ cve }`), `logs.panels`. Cài đặt: `ai` (order 40, admin). UI và mọi chữ do mock sinh ra chỉ có tiếng Anh (D-28).

- **Hồ sơ AI** (`AiProfile`): Anthropic, OpenAI, Gemini, OpenAI-compatible (Ollama, vLLM) hoặc tuỳ chỉnh (tên, địa chỉ, kiểu API OpenAI/Anthropic/Gemini, model, khoá tuỳ chọn với máy chủ nội bộ, nội bộ hay đám mây, trần token riêng). Khoá không lưu và không trả lại; chỉ 4 ký tự cuối (SYS-4).
- **Phân việc**: 9 việc (giải thích phát hiện, viết cấu hình giảm thiểu, hỏi dữ liệu, tóm tắt log, điều tra log, nhận xét báo cáo tuần, nhận xét báo cáo đánh giá, tin CVE, dịch khuyến cáo), mỗi việc một hồ sơ chính và một dự phòng. `runJob` (mocks.ts) chuyển sang dự phòng khi hồ sơ chính không trả lời, hết trần riêng hoặc bị luật riêng tư loại; ghi tên hồ sơ vào nhật ký chạy và vào `AiBlock` (model + tên hồ sơ).
- **Gợi ý một cú bấm**: model nhanh cho việc hàng loạt, model mạnh cho việc cần suy luận; việc dữ liệu nội bộ ưu tiên hồ sơ nội bộ, việc dữ liệu công khai ưu tiên đám mây (`suggest` trong mocks.ts).
- Địa chỉ/model mặc định từng nhà cung cấp đã đối chiếu tài liệu chính thức 2026-11-06 (nguồn trong `AiSettings.tsx`).
- Dùng chung (mocks/stores.ts, thêm ở cuối): `aiProfilesStore`, `aiAssignStore`, `aiCandidates(job)`, `aiAvailable(job?)`, `recordAiRun(skill, in, out, target, profile?, fallback?)`; `aiConfigStore.configured` = có ít nhất một hồ sơ dùng được (module ai cập nhật).
- Bảng riêng: `ai_sample_runs`, `ai_downgrades`, `ai_explains`, `ai_news`, `ai_asks`, `ai_log_digests`. Cài sạch: không lần chạy mẫu, không digest mẫu.
- Không hiện tiền (D-6). Câu trả lời "Hỏi dữ liệu" soạn sẵn, nhưng bảng/số tính từ `assetsStore`/`findingsStore`.

## Harness (S-AI-7, D-39)
Settings → AI assistant has tabs (`?tab=`): profiles, rules, memory, skills, knowledge, connections, hooks. UI in `harness/`, endpoints in `harness-mocks.ts`, tables and the hook engine in `harness.ts` (tables `ai_rules`, `ai_memory`, `ai_memory_suggestions`, `ai_memory_settings`, `ai_skills`, `ai_knowledge`, `ai_knowledge_settings`, `ai_hooks`, `ai_hooks_builtin`; connections live in `mocks/connectors.ts`). "Ask your data" runs hooks before the AI, on each tool call and on the answer; `AskResult.hooks` names what acted. "Write tools need approval" is locked on. Knowledge status is computed from upload time (uploading, indexing, ready).
