# Approval tokens: duyệt hành động từ email, Slack, Telegram, Zalo

Trạng thái: bản nháp M2-0 (docs-first), 2026-11-09. Văn xuôi tiếng Việt; tên trường, thông điệp, đường dẫn bằng tiếng Anh.
Truy vết: D-41 (người duyệt, hết hạn, một hành động mỗi lần duyệt), D-46 (duyệt trong từng kênh), D-38 (Slack Socket Mode, Telegram long polling), D-51 (mọi hành động cần duyệt, 2 người cho rủi ro cao, rủi ro cao AI phải duyệt trong app có mã hai bước), D-35 (hai bước), D-48 (nhật ký hash); story S-RESP-2, S-NOT-2; GUI mock `web/src/features/response` (`ApprovePage.tsx`, `state.ts`, `mocks.ts`) và `web/src/features/notify` (`Approver`, `ChannelInput`).

## 1. Mục đích

Một yêu cầu hành động (`ActionRequest`) của module `response` chỉ chạy khi đủ số người duyệt hợp lệ. Spec này định nghĩa **cách người duyệt xác nhận** qua từng kênh sao cho:

- một cú nhấp của trình quét liên kết trong hộp thư **không** duyệt thay người;
- token bị chuyển tiếp hoặc phát lại **không** cho người khác duyệt;
- danh tính của người duyệt trên kênh được ánh xạ về **một người dùng Vedette** vai operator trở lên (D-41);
- mọi quyết định vào nhật ký hash-chain (D-48).

Ngoài phạm vi: nội dung/cơ chế của hành động (`action-packs.md`), thuật toán quyết định có cần duyệt không (engine phản ứng, D-51).

## 2. Actors

| Actor | Vai trò |
|---|---|
| Người duyệt | người dùng Vedette vai `operator`/`admin`, có địa chỉ trên kênh (`Approver {user_id, address}` trong cấu hình kênh) |
| `core` (module `response`, `notify`) | tạo yêu cầu, phát token, kiểm tra, thực thi sau đủ duyệt |
| Kênh | Email (SMTP của khách), Slack (Socket Mode), Telegram (bot, long polling), Zalo OA (liên kết), Zalo cá nhân (mã trả lời, không chính thức) |
| Trình quét liên kết | phần mềm của hộp thư/gateway tự `GET` mọi URL trong thư: coi là kẻ **tự động nhấp** |

## 3. Quy tắc chung (mọi kênh)

1. **Một yêu cầu = một gói** hành động (D-51, một yêu cầu gộp mỗi lần chạy). Người duyệt duyệt/từ chối **cả gói**; thay đổi trước/sau (`change`) luôn hiện đủ trước khi nhận quyết định.
2. **Hết hạn**: yêu cầu hết hạn sau 15 phút (D-41) tới 30 phút (D-51 cho quy tắc; mặc định trong `response_settings.expiry_min = 15`). **Token email/Zalo OA sống 30 phút (D-46)** nhưng **không bao giờ sống lâu hơn yêu cầu**: `token.expires_at = min(now + 30 phút, request.expires_at)`.
3. **Số người duyệt**: 1, hoặc 2 người **khác nhau** cho rủi ro cao (D-51). Hai lần duyệt của cùng một người dùng chỉ tính một. Người **tạo** quy tắc/yêu cầu thủ công không được tính là người duyệt thứ hai của chính nó (câu hỏi mở §13).
4. **Rủi ro cao do AI gửi** chỉ duyệt **trong app bằng mã hai bước** (D-51); kênh chat/email với yêu cầu này nhận tin "mở Vedette để duyệt", không có nút duyệt (khớp `in_app_required` trong mock).
5. **Kiểm lại lúc duyệt**: dù token/nút hợp lệ, core kiểm tại thời điểm POST/callback: người duyệt vẫn trong danh sách của kênh, vẫn là người dùng đang hoạt động vai ≥ operator, kênh vẫn bật "Approve actions from this channel", yêu cầu vẫn `pending`, module `response` còn bật và `execution` còn bật. Sai → từ chối `403 approver_not_listed` (khớp mock).
6. Duyệt xong core đặt trạng thái; thực thi sau khi đủ số người; **dừng khẩn cấp và cầu dao** (D-51) có thể chặn ngay cả yêu cầu đã duyệt đủ, không do token quyết định.
7. Mọi bước (`request`, `approved`, `rejected`, `expired`, `refused`, `executed`…) ghi vào nhật ký `resp_log` với `hash = SHA-256(prev_hash "\n" canon(entry không có hash))` (một công thức cho mọi chuỗi, D-57 (14)) và `core_audit` (SYS-3). `actor` ghi **kênh và danh tính** (ví dụ `Lan Pham via email lan@…`).

## 4. Email: liên kết xác nhận

### 4.1 Định dạng token

Token đi trong **đường dẫn** của trang xác nhận công khai: `https://<IP hộp>:8443/approve/<token>`.

```
<token> = "v1." base64url(token_id) "." base64url(mac)
token_id = 16 byte ngẫu nhiên (CSPRNG)
mac      = HMAC-SHA256(K_approval, "vedette-approval-v1\n" token_id "\n" request_id "\n" approver_user_id "\n" channel "\n" expires_at_unix)
          cắt còn 16 byte đầu (128 bit)
```

- `K_approval`: khoá HMAC 256 bit riêng cho mục đích này, sinh lúc cài, lưu trong `core/secrets` (AES-256-GCM, SYS-4), tách khỏi khoá mã hoá dữ liệu. Có cơ chế xoay (`key_id` ghi trong bản ghi token; token cũ chỉ còn hiệu lực tới `expires_at`).
- **Vì sao HMAC chứ không phải Ed25519:** người ký và người kiểm là **cùng một hộp**; không bên thứ ba nào cần kiểm token, nên khoá đối xứng đủ và đơn giản hơn (ponytail: HMAC-SHA256; nâng cấp: Ed25519 nếu sau này có dịch vụ ngoài cần kiểm token mà không giữ khoá ký).
- **HMAC không phải thứ duy nhất bảo vệ.** Bản ghi `response_tokens` (DB) là nguồn chân lý: `{token_id (băm), request_id, user_id, address, channel, key_id, expires_at, used_at}`. HMAC chỉ để từ chối nhanh token làm giả mà **không cần truy DB** và để chống dò token_id. Trạng thái dùng/hết hạn lấy từ DB, không từ token.
- Độ dài token ~ 3 + 22 + 1 + 22 = ~48 ký tự, ASCII URL-safe, so sánh bằng hằng thời gian.

Mock hiện dùng token ngẫu nhiên 32 hex không ký (`TOKEN_RE = /^[a-f0-9]{32}$/`). **Định dạng ở trên thay thế regex đó**; đổi `TOKEN_RE` ở FE và route `approve/:token` là việc của M2 (câu hỏi mở §13).

### 4.2 Gắn với hành động và người nhận

Token gắn với đúng bộ bốn: **yêu cầu** (`request_id`), **người duyệt** (`user_id` + địa chỉ email đã gửi tới), **kênh** (`email`), **hạn**. Core kiểm lúc xem và lúc POST rằng bản ghi khớp bộ bốn đó. Không thể dùng token của A để duyệt yêu cầu B, hay giả danh người khác. Mỗi người duyệt trong danh sách nhận **token riêng** (nên "ai duyệt" là biết chắc).

### 4.3 Dùng một lần

- Chỉ **POST quyết định** mới đốt token: `used_at` đặt trong cùng giao dịch DB với việc ghi quyết định (cập nhật có điều kiện `WHERE used_at IS NULL`). Hai POST đồng thời: một thắng, một nhận `409 used`.
- Xem trang (GET) **không** đốt token và **không** thay đổi gì (khớp mock: "opening the link never approves").
- Từ chối (`reject`) cũng đốt token.
- Khi yêu cầu đã được quyết định bằng đường khác (người khác duyệt trong Slack, huỷ trong app) token còn lại thành `decided`, GET/POST đều không đổi gì.

### 4.4 Trang xác nhận: chỉ POST mới duyệt

| Method | Path | Auth | Hành vi |
|---|---|---|---|
| GET | `/api/v1/response/approve/{token}` | token | **chỉ đọc**; trả `ApprovalView`; không đốt token, không ghi quyết định |
| POST | `/api/v1/response/approve/{token}` | token + body | thực hiện quyết định |

SPA route công khai `/approve/:token` hiển thị `ApprovalView` rồi hai nút **Approve** / **Reject** gửi POST. Thiết kế dành cho trình quét liên kết: các scanner (Safe Links, Mimecast, v.v.) thường `GET` (và có thể chạy JS trong sandbox) nhưng không bấm nút và không gửi POST; vì vậy **không có quyết định nào trên đường GET**, không có "một cú nhấp" (`?action=approve`), không dùng redirect tự duyệt.

`ApprovalView` (response của GET): `{ "state": "ready"|"expired"|"used"|"decided"|"unknown", "title": string|null, "items": [ { "title", "risk": "low"|"medium"|"high", "change": { before, after, cli } } ], "approver": string|null, "expires_at": datetime|null, "status": string|null, "requires_approvals": int|null, "approved_so_far": int|null }`. Khi `state != "ready"`, `title`/`items`/`approver`/`expires_at` là rỗng/`null` (không lộ nội dung cho token sai/hết hạn/đã dùng).

Body POST: `{ "decision": "approve" | "reject" }` (không thêm trường). Response `200`: `ActionRequest` đã cập nhật, trong đó `status` có thể là `pending` (cần người duyệt thứ hai), `approved`/`executed`, hoặc `rejected`.

Thêm cho chống tự động hoá: phản hồi trang có `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY` (chặn clickjacking nút duyệt), CSP nghiêm. POST yêu cầu `Content-Type: application/json` (loại gửi từ form chéo-site) và header `X-Requested-With`/Origin trùng host hộp; không dùng cookie phiên (token là credential duy nhất), nên CSRF cổ điển không áp dụng nhưng **Origin/Fetch-Metadata phải kiểm** để chống trang khác ép trình duyệt người duyệt POST.

### 4.5 Phát lại và chuyển tiếp

| Rủi ro | Biện pháp | Rủi ro còn lại |
|---|---|---|
| Thư bị chuyển tiếp, ai có link đều duyệt được | token gắn người duyệt nhưng **người cầm token vẫn duyệt được** nếu không có yếu tố thứ hai; giảm bằng hạn 30 phút, một lần, gộp một gói, rủi ro cao cần 2 người, rủi ro cao AI không duyệt bằng email | **Chấp nhận**: email là kênh yếu; GUI nêu rõ. Có thể thêm bước nhập mã hai bước (câu hỏi mở §13) |
| Phát lại sau khi dùng | `used_at` + `409 used` | không |
| Phát lại sau hạn | `expires_at` + `409 expired` | không |
| Thư trong hộp thư bị chiếm | như chuyển tiếp | cần bảo vệ hộp thư |
| Dò token | HMAC 128 bit + token_id 128 bit, rate limit 20 lần sai/phút/IP, trả `404 unknown` đồng nhất | không |
| Trình quét tự nhấp | GET không đổi gì (§4.4) | không |
| Lộ trong lịch sử trình duyệt / Referer | `Referrer-Policy: no-referrer`; token sống ngắn và một lần | thấp |
| Trả lời thư để duyệt | **không hỗ trợ**: hộp không đọc hộp thư đến (D-46: dễ giả mạo) | không |

### 4.6 Nội dung thư

Thư chứa: tiêu đề yêu cầu, bảng thay đổi (lấy từ `change`, **văn bản thuần**, escape HTML, giới hạn 4 KiB), mức rủi ro, hạn, một nút/link tới `…/approve/<token>`. Không chèn nội dung tác nhân (do kẻ tấn công kiểm soát, D-51) không escape. Gửi qua **SMTP của khách** (PRIVACY luồng 5), không bên thứ ba.

## 5. Slack (Socket Mode)

- Hộp mở kết nối WebSocket **ra** tới Slack bằng `app_token` (`xapp-…`, Socket Mode) và dùng `bot_token` (`xoxb-…`) để gửi tin; **không có cổng vào** (D-38). Cả hai token lưu mã hoá (SYS-4), UI chỉ 4 ký tự cuối.
- Tin yêu cầu: Block Kit gồm tiêu đề, `change`, rủi ro, hạn; nút **Approve** / **Reject**. Nút mang `action_id` và `value = request_id` (không chứa bí mật; không có token).
- **Ánh xạ danh tính**: sự kiện `block_actions` đến kèm `user.id` (Slack member ID) và `channel.id`. Core tìm `Approver` trong cấu hình kênh Slack có `address == user.id` → `user_id` Vedette. Không tìm thấy hoặc người dùng không còn operator/admin → từ chối, tin phản hồi riêng (ephemeral) "You are not an approver".
- Chỉ nhận từ `channel_id` đã khai báo trong cấu hình (mock có `channel_id` "approvals only"); nút bấm trong kênh khác bị bỏ qua.
- Chống giả mạo: kết nối Socket Mode được Slack xác thực bằng `app_token`, nên không cần kiểm chữ ký request như webhook; vẫn kiểm `request_id` còn `pending` và `payload.team.id` trùng team đã cấu hình.
- Sau khi quyết định: cập nhật tin gốc (chat.update) để bỏ nút, ghi ai quyết định.
- Kết nối đứt: kết nối lại có lùi dần; trong lúc đứt, yêu cầu vẫn mở trong app và các kênh khác. Quá hạn thì yêu cầu hết hạn bình thường.

## 6. Telegram (bot, long polling)

- Hộp gọi `getUpdates` (long polling) tới Telegram bằng bot token (mã hoá): kết nối **ra**. Không đặt webhook (không cổng vào).
- Tin yêu cầu: văn bản thuần + `inline_keyboard` hai nút; `callback_data = "a:<request_id>:<nonce>"` (≤ 64 byte theo giới hạn Telegram), `nonce` ngẫu nhiên 8 byte lưu kèm yêu cầu để callback lạ không đoán được.
- **Ánh xạ danh tính**: `callback_query.from.id` (Telegram user ID) khớp `Approver.address` (loại `Telegram user ID`). Với nhóm, **chỉ** `from.id` quyết định, không phải tên hiển thị hay `chat.id`; chỉ chấp nhận callback từ `chat_id` đã cấu hình.
- Sau quyết định: `answerCallbackQuery` và sửa tin để bỏ nút.

## 7. Zalo

| Loại | Cơ chế duyệt | Ghi chú |
|---|---|---|
| **Zalo OA** (chính thức) | gửi **liên kết** (như email, mục 4) | chỉ tin có link; không nhận quyết định qua chat |
| **Zalo cá nhân** (không chính thức, như node cộng đồng n8n Zalo, D-46) | **trả lời mã** | GUI cảnh báo: không chính thức, có thể bị khoá tài khoản, nên dùng tài khoản riêng |

Duyệt bằng mã trả lời (Zalo cá nhân):

- Hộp gửi tin với mã duyệt riêng cho **từng người duyệt**: `A-<6 ký tự>` (duyệt) và `R-<6 ký tự>` (từ chối), bảng chữ không gây nhầm (không `0/O/1/I`), tạo bằng CSPRNG; lưu băm, gắn `request_id`, `user_id`, hạn bằng hạn yêu cầu (tối đa 30 phút), **một lần**.
- Người duyệt trả lời đúng mã. Hộp (qua phiên Zalo cá nhân của kênh) nhận tin vào, so với bản ghi mã: **gửi từ `Approver.address`** (Zalo user ID) mới được chấp nhận; mã đúng nhưng người gửi khác → bỏ và ghi `refused`.
- Mã trả lời đã dùng/hết hạn → hộp trả lời "expired/used".
- Vì kênh không chính thức, độ tin cậy danh tính thấp hơn Slack/Telegram: **mặc định không dùng cho rủi ro cao** (câu hỏi mở §13), và rủi ro cao AI vẫn chỉ duyệt trong app.
- Phiên Zalo cá nhân là bí mật (quét QR một lần); xoá kênh xoá phiên (PRIVACY luồng 5).

## 8. Ánh xạ danh tính tổng hợp

| Kênh | Định danh trên kênh | Khoá ánh xạ | Xác minh |
|---|---|---|---|
| Email | địa chỉ email của người duyệt | `Approver.address` = email đăng nhập | token riêng gắn người nhận |
| Slack | Slack member ID (`U…`) | `address` | Socket Mode `user.id` + `channel_id` |
| Telegram | Telegram user ID (số) | `address` | `callback_query.from.id` + `chat_id` |
| Zalo OA | Zalo user ID / số điện thoại | `address` | token trong link |
| Zalo cá nhân | Zalo user ID | `address` | mã trả lời + ID người gửi |

Một `Approver` là cặp `(user_id Vedette, address trên kênh)`. Lập cặp **do admin** làm trong Cài đặt → Kênh cảnh báo; hộp không tự suy ra từ tên. Một địa chỉ chỉ thuộc **một** người dùng trên cùng kênh (ràng buộc duy nhất), nếu không một ID chat đại diện hai người. Khi người dùng bị vô hiệu hoá/hạ vai, mọi lần duyệt đang chờ của người đó bị từ chối (§3.5) và token chưa dùng coi như vô hiệu.

## 9. Sequence

```mermaid
sequenceDiagram
    participant R as Engine / AI
    participant C as core
    participant M as Hộp thư người duyệt
    participant S as Trình quét liên kết
    actor U as Người duyệt (trình duyệt)
    R->>C: tạo ActionRequest (pending, hết hạn T)
    C->>C: tạo token riêng mỗi người duyệt (v1.id.mac)
    C->>M: email: link /approve/<token> (qua SMTP khách)
    S->>C: GET /approve/<token> (quét link)
    C-->>S: ApprovalView (không đổi gì, không đốt token)
    U->>C: GET /approve/<token>
    C-->>U: trang xem thay đổi + nút Approve/Reject
    U->>C: POST /approve/<token> {decision: approve}
    C->>C: kiểm lại: người duyệt, kênh, trạng thái; đốt token (điều kiện)
    alt đủ số người duyệt
        C->>C: thực thi (action-packs), kiểm lại, ghi nhật ký
    else cần thêm người
        C-->>U: status pending (đợi người thứ hai)
    end
```

## 10. Xử lý lỗi

| HTTP | `code` | Khi nào |
|---|---|---|
| 400 | `invalid` | `decision` không phải `approve`/`reject` |
| 404 | `unknown` | token sai định dạng, sai HMAC, không có bản ghi (thông điệp đồng nhất, không phân biệt) |
| 409 | `used` | token đã dùng |
| 409 | `expired` | quá hạn token hoặc yêu cầu |
| 409 | `decided` | yêu cầu đã được quyết định bằng cách khác |
| 403 | `approver_not_listed` | người duyệt không còn hợp lệ trên kênh (§3.5) |
| 403 | `in_app_required` | rủi ro cao do AI: chỉ duyệt trong app có mã hai bước |
| 403 | `twofa_required` / `code_required` / `invalid_code` | trong app: thiếu/sai mã hai bước |
| 409 | `execution_off`, `emergency_stop` | module/tính năng tắt hoặc đã dừng khẩn cấp |
| 429 | `rate_limited` | quá giới hạn thử |

Thông điệp tiếng Anh, ngắn (D-28); lỗi `409` trả kèm `ActionRequest.id` để trang nói rõ. Lỗi không bao giờ chứa nội dung `change` cho token không hợp lệ.

## 11. Giới hạn

| Mục | Giới hạn |
|---|---|
| Hạn token email / Zalo OA | 30 phút, không quá hạn yêu cầu (D-46) |
| Hạn yêu cầu | 15–30 phút (D-41/D-51) |
| Người duyệt mỗi kênh | tối đa 10 (mặc định, chưa đo) |
| Kích thước nội dung thay đổi trong thư/tin | 4 KiB, cắt và thêm "…open Vedette for the full change" |
| Mã Zalo | 6 ký tự, một lần, hạn theo yêu cầu |
| POST `approve` | 10 request/phút/IP; 20 token sai/phút/IP |
| Số token chưa dùng cho một yêu cầu | = số người duyệt × số kênh link |

## 12. Cân nhắc bảo mật (ánh xạ SYS)

| SYS | Áp dụng |
|---|---|
| SYS-1 | Duyệt chỉ đổi trạng thái; hành động chạy qua `core/exec`/kết nối được kiểm; tên/giá trị trong thư không bao giờ vào shell |
| SYS-2 | `decision` theo enum, token theo cấu trúc; callback Slack/Telegram theo schema |
| SYS-3 | Mọi quyết định ghi `core_audit` + chuỗi hash `resp_log` (D-48) |
| SYS-4 | `K_approval`, token Slack/Telegram, phiên Zalo qua `core/secrets`; không log token/URL; GUI chỉ 4 ký tự cuối |
| SYS-5 | Module `response` hoặc kênh tắt → route `/approve/*` trả `404`, bot dừng polling/ngắt Socket Mode |
| SYS-6 | Nội dung yêu cầu có dữ liệu tác nhân (không tin cậy): chỉ hiển thị văn bản thuần, escape, cắt kích thước |
| SYS-7 | Slack/Telegram/Zalo là luồng ra đã liệt kê trong PRIVACY luồng 5; trang `/approve` chỉ tới được từ LAN trừ khi người dùng tự mở cổng (nêu rõ ở GUI) |
| SYS-8 | AI **không** có công cụ duyệt hay tạo token; chỉ gửi yêu cầu (D-51), người duyệt là con người ngoài AI |

## 13. Versioning

- Token mang tiền tố phiên bản (`v1.`); phiên bản mới (đổi dữ liệu ký) chạy song song tới hết hạn token cũ (≤ 30 phút), nên đổi định dạng không cần cửa sổ chuyển đổi dài.
- API `/api/v1/response/approve/{token}`; thêm trường `ApprovalView` là tương thích tiến.
- Quy tắc kênh (Slack action_id, tiền tố mã Zalo) đổi → ghi trong CONTRACT của `response`.

## 14. Câu hỏi mở

1. **Email quá yếu cho rủi ro cao?** Hiện tại link + một lần bấm là đủ cho rủi ro thấp/trung bình. Có nên bắt nhập mã hai bước trên trang `/approve` (như duyệt trong app) khi chọn duyệt bằng email cho rủi ro cao, hay cấm email với rủi ro cao? D-46/D-51 chưa nói rõ phần này.
2. **Tạo yêu cầu và duyệt cùng một người**: có cho người tạo thủ công tự duyệt không (D-51 "người duyệt thứ hai" cho rủi ro cao)? Cần quyết.
3. **Đổi `TOKEN_RE` và route FE** từ `^[a-f0-9]{32}$` sang định dạng ký `v1.…`: đây là thay đổi hợp đồng ở M2, kéo theo đổi `ApprovePage` và test.
4. Zalo cá nhân có được duyệt hành động rủi ro trung bình hay chỉ thấp (hiện suy ra: không dùng cho rủi ro cao; D-46 không nêu)?
5. Link duyệt chỉ tới được trong LAN: người duyệt đang ngoài văn phòng (qua email trên điện thoại) không mở được. Hướng dẫn VPN hay reverse proxy tự dựng do khách; Vedette không cung cấp tunnel (D-15).
6. Hạn yêu cầu mặc định 15 hay 30 phút khi quy tắc không đặt (D-41 nói 15, D-51 nói 15–30).
7. Mức độ giới hạn: số người duyệt mỗi kênh, rate limit (chưa đo).
