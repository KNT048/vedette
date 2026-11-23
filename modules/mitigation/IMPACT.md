# Mitigation — Change Impact Map

## Modifying: `mitigation.Provider.Guidance(ctx, findings.Row)` (phần "What to do" của `GET /findings/{id}`)
- **findings** (`FindingHandlers.SetGuidance`; bị bỏ qua khi mitigation tắt) (gộp vào `FindingDetail`), SPA trang finding (`FindingPage.tsx`, `Recommendation.tsx`). Các kiểu `findings.Guide`/`MitigationPack`/`AIResult` (`findings/guide.go`) là hợp đồng của phần này. Đổi `FindingDetail.pack|compromise|recheck|ai|applied` phải sửa `findings/contract.ts` (nguồn OpenAPI).

## Modifying: `{IP}`/`{HOST}` (deviceReplacer)
- Khi không có thiết bị hoặc IP không hợp lệ, văn bản có `<IP>`/`<HOST>` (mock dùng `<IP-NAS>`/IP). Dán nhầm vào shell thì vô hại: `<` là chuyển hướng nhập từ một tệp không tồn tại nên lệnh lỗi, không chạy gì. Khi tên máy không an toàn hoặc vắng thì `{HOST}` là IP thiết bị, đúng như mock (`hostname ?? ip`).

## Modifying: các interface `Verifier`, `AI`, `Vendors` (mitigation/ports.go)
- **`cmd/vedette` `packVerifier`** (cài `Verifier` trên `internal/release.VerifyContent` và khoá phát hành nhúng; thiếu = từ chối mọi gói): đổi `Statement` phải đổi cùng lúc công cụ ký `release packs` (`scripts/release`) và mọi chữ ký đã phát hành không còn khớp, **ai** (cài `AI`: `Available`, `Run` qua `ai.Service.Brief`), **inventory** (cài `Vendors.HasFirewallVendor`: `cmd/vedette/wiring.go` hỏi `inventory.HasDevice` với loại `firewall` hoặc `router`, so hãng không phân biệt hoa thường, kể cả hãng của phần mềm trên thiết bị, mọi loại thiết bị hoạt động như firewall hoặc router). Đổi chữ ký = đổi chỗ nối trong `cmd/vedette`. `AI` là cửa của module `ai` (`aiMitigation`); `Loader` được dựng trong `buildServices` với `packVerifier` và chạy qua job `load-packs`.

## Modifying: `Provider.SetAgents` (kiểm "agent còn báo thiết bị", INV-7)
- **cmd/vedette** `agentReports` (wiring.go) là kiểm duy nhất, dùng chung với `findings.FindingHandlers.SetAgents` (Updates to plan) và cùng luật với `web/src/features/findings/agentNow.ts` (tiêu đề, bước, dòng "I updated it"). Đổi luật ở một chỗ phải đổi cả ba, nếu không trang finding và "How to check" lại nói khác nhau.

## Modifying: gia cố chung (`hardening.go`, INV-8)
- SPA `web/src/features/findings/Hardening.tsx` (`GeneralChecks`) và mock `hardeningMock.ts`; đổi `findings.Hardening` (`{software, family, checks}`) phải sửa `findings/contract.ts` (`GeneralHardening`). Không còn cấu hình firewall nào do code viết: đừng thêm lại khi chưa có quyết định sản phẩm mới.

## Modifying: nạp gói (`Loader.Install`) và định dạng `MitigationPack`
- **`scripts/release`** (`packs.go`, lệnh `release packs`): ký thư mục gói bằng `Statement`, đọc lại bằng `ReadPackDir` và kiểm từng gói bằng `CheckPack` (bộ phân tích của chính hộp) trước khi ký; đổi trường hay luật của gói = đổi cả công cụ lẫn bộ nạp. Gói đi cùng image `core` đã ký: đổi thư mục `/opt/vedette/content/mitigation` hay bố cục `ReadPackDir` phải đổi cùng `deploy/containers/core/Containerfile` và job `load-packs`.

## Modifying: gọi `AI.Run(AIRequest)` (skill `explain`, `mitigation-config`)
- Lỗi `*apierr.Error` từ `AI.Run` được handler trả nguyên: `cmd/vedette` `aiMitigation.Run` không bọc lại; đổi điều đó thì trang finding lại hiện sai lý do.
- `AIRequest.FixedIn` và dữ liệu `aiFindingData` (thiết bị, cổng, firewall trong inventory qua `inventory.DevicesOfKind`/`Device`) là điều AI biết; bỏ một mục thì câu trả lời lại hỏi điều trang đã có. `AIOutput.Configs`/`Shortened` → `findings.AIResult.configs/shortened` (contract.ts `AiResult`) → `AiOutput` trong `Recommendation.tsx`.
- **ai** (nhóm B): đổi tên skill/schema đầu ra làm `ai_available` sai và kết quả mất nhãn. Cửa là `cmd/vedette/ai.go` (`aiMitigation`, `aiFindingData`, `aiVulnPorts`, `aiSafeApply`) và `cmd/vedette/aipath.go` (`aiPickWalls`, `aiNetworkBlock`, đường đi của thiết bị qua firewall); đổi `inventory.Device`/`DevicesOfKind` phải xem lại các hàm này.

## Modifying: `POST /findings/{id}/applied`
- SPA (mục "Đã áp dụng"). Đổi bộ item (`ApplyItem`) = đổi gói và `mit_applied` (cột `item` có CHECK).
- **cmd/vedette** `mitigationApplied` (wiring.go) đọc `mit_applied` để `findings` giữ finding đã có mục áp dụng khi gộp thiết bị (`ServiceConfig.Applied`): đổi tên bảng hoặc cột `finding_id` phải sửa cả hàm này.

## Disabling this module
- Mất panel "What to do" ở trang finding (`RequireModule module="mitigation"`); nút "Ask my AI" cho finding biến mất. `core/server/modules.go` (`/findings/{id}/applied`, `/ai`) và `web/src/lib/apiModules.ts` gắn hai route này với module; `modules/core/handlers_setup.go` (`bundleSMB`) và `web/src/features/core/bundles.ts` đặt nó trong gói mặc định.
- `findings`, `notify`, `scan`, `response`, `reports` không bị ảnh hưởng (không phụ thuộc `mitigation`).
- Gói đã nạp, mục "Đã áp dụng", kết quả AI giữ trong `mit_*`.

## Modifying: `FindingFolded(ctx, tx, lifecycle.FindingFold)` (INV-9)
- **findings** calls it through `core/lifecycle` (registered in `cmd/vedette/devicelifecycle.go`) inside the inventory's merge transaction, right before it deletes the folded finding: a new table keyed by finding id must be moved here too, or the FK cascade drops its rows on a merge. Write only through `tx`; an error rolls the merge back.

## Modifying: `AIRequest` (finding id, skill, pack flag, user), `AIOutput.Answers`
- `AIRequest` no longer carries the finding row or `FixedIn`: the AI door (`cmd/vedette` `aiMitigation`) reads the view of the finding and the brief of its CVE by id, the same sources every other reader uses, so the fixed release the AI names is the stored fix the page shows. `sanitizeAI` keeps at most four answers (text 1200 characters, eight http(s) links each) in `findings.AIResult.Answers`.
- Left as it was: `Provider.Guidance` still reads `findings.Row` (the finding page's "What to do" text); it moves with the finding page.
