# Mitigation Contract

> Tier: standard · Story: S-MIT-1 (phần "What to do"), S-MIT-3, S-MIT-4, S-AI-2 · Last verified: 2026-11-12 (gói ký trong image, D-345..D-349; WP-21: bộ nạp gói, nhà cung cấp "What to do", `applied|ai`, migration `mit_*`, có test; đã nối vào `cmd/vedette`: `Vendors` từ inventory, `Provider` đăng ký vào findings, `ActionHandlers`; `AI` là bản giả luôn "không có" (409 `ai_unavailable`) tới khi nối `ai` (WP-25); `Loader` nạp gói ký trong image qua job `load-packs`, D-345..D-349)

Mitigation là phần **"What to do"** của một finding: gói giảm thiểu đã xác nhận, "Đã áp dụng", dấu hiệu "Tôi đã bị chưa?", giải thích AI. Finding (khớp, trạng thái, vòng đời) thuộc module `findings` (D-57(6)); `mitigation` phụ thuộc `findings`, tắt `mitigation` không mất phát hiện hay cảnh báo. GUI: `web/src/features/findings/{Recommendation.tsx,packs.ts}` và phần `pack`/`ai`/`applied` của trang finding. Nguồn hành vi: `findings/{contract,mocks,packs}.ts`.

## Invariants
- **INV-1**: "Đã áp dụng" chỉ ghi nhận cho CVE có gói đã xác nhận (400 `no_pack`), thêm `AppliedEntry {item, ts, user}` (mỗi item một lần), **không** đổi `status` của finding. (test ở WP-21, cần DB)
- **INV-2**: Gói đáng tin (D-21): chỉ hiện "Vedette confirmed" khi gói có `status: confirmed`, `confirmed_by`, `confirmed_at`, `drafted_with`, `sources[]` và chữ ký hợp lệ của bản cập nhật; bộ nạp từ chối gói `draft` hoặc không ký. CVE không có gói ⇒ `pack:null` và UI hiện "no confirmed recommendation yet" + thông tin gốc KEV + nút "Ask my AI" chỉ khi AI dùng được.
- **INV-3**: Kết quả AI luôn mang nhãn "AI generated", ghi `model`, `profile`, `tokens`, `citations`; không bao giờ hiện như khuyến nghị đã xác nhận (S-AI-6). `POST /findings/{id}/ai` khi chưa gán hồ sơ AI cho việc đó hoặc `ai` tắt → 409 `ai_unavailable`; lỗi của chính lời gọi AI (`ai_cut_off`, `ai_bad_format`, `blocked_by_hook`, `provider_error`, `unreachable`, `ai_timeout`, `budget_reached`) được trả nguyên như module `ai` nói (D-481; trước đó mọi lỗi thành "No AI profile is assigned", beta 0.1.0-beta.1). `mitigation` không có công cụ ghi cho AI (SYS-8).
- **INV-4**: Mỗi `CodeStep` có `side_effect` phải hiện trước khi người dùng sao chép lệnh; `{IP}`/`{HOST}` thay bằng giá trị thiết bị, đã escape (giá trị thiết bị là dữ liệu không tin cậy).
- **INV-5**: `firewall[].detected=true` khi `inventory` có thiết bị của hãng đó.
- **INV-6**: Dấu hiệu "Tôi đã bị chưa?" và lệnh kiểm tra chỉ là văn bản từ nội dung ký; Vedette không bao giờ chạy chúng.

## Preconditions / Postconditions
- **PRE-1** (`Guidance(finding)`, nguồn của phần "What to do" trong `GET /findings/{id}`): finding tồn tại (do `findings` kiểm). **POST-1**: trả `pack`, `compromise`, `recheck`, `ai`, `ai_available {explain, config}`, `applied`; thiết bị thay vào `{IP}`/`{HOST}` theo INV-4. `recheck` chung (gói không có) gọi thiết bị bằng `AssetView.Name` (không bao giờ id), không giả định trang quản trị, và chỉ nhắc "Rescan this device" khi thiết bị có IP (D-484, W1-32).
- **PRE-2** (`POST /findings/{id}/applied`, `…/ai`): `operator`. **POST-2**: trả `FindingDetail` mới; thất bại không đổi gì.

## Forbidden
- **FORBID-1**: Chạy lệnh hoặc ghi cấu hình lên thiết bị/firewall của khách: chỉ hiện văn bản (lệnh, cấu hình) để người dùng tự dán (D-3). Thực thi hành động thuộc `response`. (Giữ ở cả `findings` vì hai module cùng chạm thiết bị theo hai cách: phát hiện và nội dung hướng dẫn.)
- **FORBID-2**: Hiện nội dung AI như "Vedette confirmed" hoặc gộp vào gói đã xác nhận.
- **FORBID-3**: Nạp gói chưa `confirmed` hoặc chưa ký.
- **FORBID-4**: Gói rule "vá ảo" Suricata/CRS/CrowdSec/nftables (S-MIT-2, D-31).
- **FORBID-5**: Tự đổi `status` của finding (việc của `findings`); chỉ `findings` ghi `fnd_*`.

## Dependencies
- **DEPENDS ON**: `core`, `findings` (finding, KevInfo), `inventory` (`firewall[].detected`). Tuỳ chọn: `ai` (giải thích).
- **DEPENDED ON BY**: SPA trang finding (panel "What to do"), `ai` (hỏi AI khi chưa có khuyến nghị đã xác nhận). `findings` không phụ thuộc `mitigation`.

## Endpoints owned (role tối thiểu)
| Route | Vai |
|---|---|
| `POST /findings/{id}/applied`, `/findings/{id}/ai` | operator |

`GET /findings/{id}` do `findings` phục vụ; phần "What to do" của nó do `mitigation` cấp (PRE-1) bằng cách đăng ký một nhà cung cấp "What to do" (interface trong `core`) qua module registry của `core`; `findings` không phụ thuộc `mitigation`. `POST /findings/{id}/applied|ai` do `mitigation` định tuyến dưới tiền tố `/findings` và mất khi `mitigation` tắt (nhà cung cấp vắng, các trường "What to do" là `null`/rỗng).

## Tables owned (`mit_`)
`mit_applied`, `mit_ai_output`, `mit_pack` (chỉ mục gói đã nạp từ bản cập nhật; nội dung là tệp ký, không phải dữ liệu khách). FK tới `fnd_finding` (cascade).

## Events
- **Phát**: không.
- **Nhận**: `core.update.applied` (nạp lại gói).

## Behaviour khi tắt
Không route `POST /findings/{id}/applied|ai`; trang finding mất panel "What to do" (`pack`, `compromise`, `recheck`, `ai`, `applied` rỗng). Finding, trạng thái và cảnh báo `notify` vẫn chạy bình thường. Bảng giữ nguyên.

## Story và quyết định
S-MIT-1 (phần "What to do"), S-MIT-3, S-MIT-4, S-AI-2. D-3 không chặn; D-21 gói xác nhận qua PR; D-29 hồ sơ AI theo việc; D-31 bỏ vá ảo; D-57(6) tách `findings`.

## Cài đặt (WP-21)
- Định dạng tệp gói: JSON (`status`, `cve`, `confirmed_by`, `confirmed_at`, `drafted_with`, `sources[]`, `patch`, `workaround`, `firewall[]`, `checklist`, tuỳ chọn `recheck{steps,code}` và `compromise`), trường lạ bị từ chối. `recheck` theo gói thay cho nhánh riêng CVE-2022-27593 trong mock; thiếu thì dùng văn bản chung. `firewall[].detected` trong tệp bị bỏ qua.
- **Gói ký trong image (D-345..D-349):** gói đã xác nhận nằm trong image `core` đã ký, thư mục `/opt/vedette/content/mitigation` (từ `content/mitigation/packs/`): các tệp `*.json`, `VERSION`, `packs.minisig` (chữ ký minisign của khoá phát hành trên `Statement`), `packs.list` (bản sao để người kiểm tay). `Statement(version, docs)` = `vedette mitigation packs v1`, `version <v>`, rồi `<sha256> <tên>` mỗi tệp, xếp theo tên: buộc `Update.Version`, mọi byte của mọi `Docs[].Data` và tập tài liệu; tên phải là tên tệp `*.json` thường, không trùng (`ErrBadPackSet`). `ReadPackDir(dir)` đọc có trần (chỉ tệp thường, không link, ≤ 1000 gói, 256 KiB mỗi gói, 32 MiB tổng; tệp lạ ⇒ từ chối cả thư mục; không có thư mục hoặc chỉ có README ⇒ `ErrNoPackDir`). `Verifier` của hộp do `cmd/vedette` dựng (`packVerifier`: `Statement` + `internal/release.VerifyContent` với khoá nhúng, khoá đang dùng hoặc dự phòng; chưa đọc danh sách thu hồi khoá, D-346). Job `mitigation/load-packs` (lúc khởi động, khi bật module, mỗi ngày) gọi `Install`; `ErrReplay` (cùng hoặc cũ hơn) im lặng, chữ ký sai làm lượt chạy lỗi và không đổi gì. Test: `packsig_test.go`, `cmd/vedette/mitigation_packs_test.go`.
- `Loader.Install(ctx, Update)`: `Verifier` vắng hoặc chữ ký sai ⇒ từ chối cả bản cập nhật, không đổi gì (fail closed). Từng tệp không đạt INV-2 bị loại riêng và liệt kê; gói vắng trong bản mới bị rút. Thay toàn bộ `mit_pack` trong một giao dịch + `core_audit`.
- INV-4: `{IP}`/`{HOST}` chỉ nhận IP phân tích được (không zone) và tên máy khớp `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`; giá trị khác thay bằng `<IP>`/`<HOST>`, không escape vào văn bản, thay một lượt.
- Bản cập nhật: không có gói hợp lệ nào (không tài liệu, hoặc tất cả bị loại) ⇒ `ErrNoValidPack`, không xoá gói đang nạp, kết quả vẫn trả lý do từng tài liệu; phiên bản không mới hơn phiên bản đã cài, hoặc không so sánh được ⇒ `ErrReplay` (bảng `mit_pack_state`, một hàng). Bản bị từ chối không dùng hết phiên bản của nó. `Verifier` phải ký ràng buộc `Version` và byte của mọi `Docs[].Data`.
- Kết quả AI: cắt độ dài, giới hạn số mục, chỉ giữ link `http(s)`; lưu trong `mit_ai_output` (nhãn "AI generated").

## Không khớp / câu hỏi mở
- S-MIT-1 liệt kê 8 hãng firewall; GUI/gói mẫu chỉ có `fortigate`, `mikrotik`, `generic`.
- Khi `mitigation` tắt, `pack:null` không phân biệt được với "chưa có khuyến nghị đã xác nhận" (xem câu hỏi mở của `findings`).
