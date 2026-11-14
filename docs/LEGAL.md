# Pháp lý và tuân thủ — rõ ràng, minh bạch

kien, 2026-11-06: mọi thứ liên quan luật pháp, giấy phép, cookie phải rõ ràng, minh bạch và tuân thủ. File này là nơi duy nhất tổng hợp; chi tiết dữ liệu ở `PRIVACY.md`, giấy phép thành phần ở `THIRD_PARTY_NOTICES.md`.

## 1. Giấy phép

- Mã Vedette: **Apache-2.0** (`LICENSE`). `NOTICE` ghi tên dự án và bản quyền; người phân phối lại phải giữ `LICENSE` + `NOTICE`.
- Thành phần bên thứ ba: liệt kê trong `THIRD_PARTY_NOTICES.md` (tên, phiên bản, giấy phép, cách dùng: nhúng / tiến trình riêng / dữ liệu). CI chạy kiểm tra giấy phép (`go-licenses`, `license-checker` cho npm); GPL/AGPL không được nhúng vào binary — chỉ tiến trình/container riêng.
- Dữ liệu phân phối lại từ trung tâm: mỗi file feed mang `license` và `attribution` trong `index.json`; UI hiện nguồn ở mọi dòng dữ liệu. Nguồn cấm phân phối lại không bao giờ vào trung tâm (D-2).
- nmap: không phân phối; không nằm trong image nào của dự án; cài từ kho gói OS vào image `scan` mà `vedette-host` dựng trên hộp (`deploy/containers/scan/Containerfile.onbox`, mã ở `host/ops/scanbuild.go`, D-146, D-147); không dùng tên/logo nmap trong marketing. Spamhaus: không dùng tên trong marketing; chờ xác nhận điều khoản nhúng.
- Nhãn hiệu: "Vedette" là tên dự án; không dùng tên/logo hãng khác (Fortinet, Synology, CISA…) ngoài mục đích chỉ sản phẩm tương thích.

## 2. Dữ liệu cá nhân (Luật BVDLCN 91/2025, NĐ 356/2025, NĐ 330/2026)

- Vedette chạy **tại khách**; khách là bên kiểm soát dữ liệu. Vedette xử lý: địa chỉ IP/MAC/hostname thiết bị, log mạng (có thể chứa tên người dùng, email trong log). Tất cả ở trên hộp của khách.
- Dự án Vedette chỉ nhận **tín hiệu ẩn danh** (`PRIVACY.md` §2) — không định danh được cá nhân hay tổ chức. Giữ tổng hợp; xoá bản thô sau 30 ngày.
- Khách có thể: tắt tín hiệu; đặt retention log; bật redact PII trước khi gửi AI; xuất/xoá toàn bộ dữ liệu (`vedette data export|purge`).
- Khi khách bật AI BYOK: dữ liệu đi tới provider **của khách** theo hợp đồng của họ với provider; Vedette hiện rõ điều này ở bước cấu hình và cho chọn redact.
- Báo cáo PDPL mà Vedette sinh (S-REP-2) là **hỗ trợ đánh giá**, không phải tư vấn pháp lý; ghi rõ trên báo cáo. Giấy phép Apache-2.0 §7–8: không bảo hành, tác giả không chịu trách nhiệm.

## 3. Quét và kiểm kê (Luật An ninh mạng 116/2025, BLHS Điều 289)

- Quét chủ động chỉ trên tài sản **đã xác thực**: dải LAN người dùng khai + tick cam kết; domain qua DNS TXT (kiểm lại trước mỗi lần quét); IP công cộng chỉ là IP chính hộp đang ra Internet, hộp tự phát hiện và tự gia hạn, hiệu lực 30 ngày kể từ lần thấy cuối (D-25, sửa theo kien 2026-11-09). Không có văn bản đồng ý; thay bằng cam kết + câu "Vedette được cung cấp nguyên trạng theo Apache-2.0; tác giả (Kiên) không chịu trách nhiệm về cách bạn sử dụng" (D-26). Từ D-544 có thêm điều khoản sử dụng chung (`TERMS.md`, §5) chấp nhận một lần khi cài hay khôi phục lần đầu; cam kết theo dải và theo mục tiêu ở đây giữ nguyên. **Domain và IP ngoài (D-473, kien 2026-11-13):** không còn bước xác nhận riêng; lần Scan now đầu tiên của admin có đăng nhập hai bước ghi cam kết D-26 (ai, khi nào, mục tiêu, đúng câu hiện cạnh nút và phiên bản của nó) vào `exp_target` và `core_audit` cùng một giao dịch. Operator không quét được mục tiêu chưa cam kết. Sửa D-26, giữ bản ghi của D-5. **D-559 (kien 2026-11-14):** câu hiện hành nêu cả phạm vi ("…including identifying its services and versions, safe checks for known exploited vulnerabilities and a passive web scan"); cam kết ghi theo câu cũ được hỏi lại một lần, ở Scan now đầu tiên của admin sau khi nâng cấp.
- Nhật ký mọi probe (đích, thời điểm, template) giữ ≥90 ngày để chứng minh phạm vi. Quét web thụ động bằng ZAP (D-562, D-521): đơn vị ghi là một dòng mỗi trang với phạm vi (`ip:port`, URL, công cụ và tuỳ chọn, thời điểm), ghi trước khi chạy; request của spider không ghi từng cái mà bị rào mạng của host giữ trong đúng phạm vi đó.
- Không có chế độ quét IP ngoài scope; không có template khai thác (`-exclude-tags dos,intrusive,fuzz`).
- Honeypot chỉ nghe, không phản công, không tương tác với hệ thống bên ngoài.

## 4. Cookie và web

- SPA của Vedette dùng **ba cookie, đều của chính hộp và cần cho đăng nhập**: cookie phiên (`__Host-vedette_session`, HttpOnly, Secure, SameSite=Strict), cookie CSRF (`__Host-vedette_csrf`, đọc được bởi SPA) và cookie thiết bị tin cậy (`__Secure-vedette_device`, HttpOnly, chỉ gửi tới các endpoint đăng nhập, D-77), và và `localStorage` cho tuỳ chọn giao diện (ngôn ngữ, theme). Không cookie theo dõi, không analytics bên thứ ba, không font/CDN ngoài (font nhúng). Vì chỉ có cookie cần thiết, không cần banner; vẫn ghi rõ ở `PRIVACY.md` §4 và trang Cài đặt → Quyền riêng tư.
- ~~Site tĩnh công khai (bảng nóng trên Cloudflare Pages)~~: đã bỏ (D-36, D-81): dự án không chạy máy chủ nào ngoài GitHub.

## 5. Minh bạch với khách (bắt buộc trong UI)

- **Điều khoản sử dụng (D-544, kien 2026-11-14):** `TERMS.md` ở gốc repo là văn bản duy nhất (Apache-2.0 nguyên trạng, không bảo hành; người vận hành chịu trách nhiệm mọi lần quét, chỉ quét thứ mình sở hữu hoặc được phép; quét sâu có thể làm gián đoạn dịch vụ; quét tên/IP đằng sau hosting, CDN, proxy chạm cả máy của nhà cung cấp đó và người vận hành phải có phép của họ, Vedette không kiểm ai sở hữu IP; dữ liệu ở lại hộp trừ các luồng của `PRIVACY.md`; điều khoản thử nghiệm của từng mục tiêu chấp nhận riêng trước lần quét sâu đầu tiên). Bước đầu của trình hướng dẫn cài đặt lần đầu hiện văn bản và ô "I have read, understood and agree to the terms of use"; không tick thì không đi tiếp, và `POST /core/setup`, `POST /core/setup/restore` từ chối (400 `terms_not_accepted`), nên khôi phục từ bản sao lưu trên hộp mới cũng cần. Hộp lưu ai chấp nhận, khi nào, phiên bản nào (ngày + SHA-256 của `TERMS.md`) và một dòng audit; Settings → General hiện lại cả văn bản. Bổ sung, không thay cam kết phạm vi quét của §3.
- Trang Cài đặt → Quyền riêng tư: mọi luồng dữ liệu ra khỏi hộp, mỗi luồng một công tắc hoặc lý do không tắt được (kéo feed), lần gửi gần nhất, payload mẫu.
- Mọi kết quả AI có nhãn "AI tạo, cần người xác nhận".
- Mọi dòng dữ liệu có nguồn và thời điểm.
- `CHANGELOG` công khai; advisory bảo mật của chính sản phẩm công khai (`SECURITY.md`).

## 6. Xuất khẩu / mã hoá

Vedette dùng TLS và AES-GCM chuẩn (Go stdlib). Không có khoá/thuật toán riêng. Phân phối toàn cầu qua GitHub theo điều khoản GitHub.

## 7. Quy tắc cho người đóng góp (`.claude/rules/legal.md`)

Thêm dependency/feed/luồng dữ liệu ra ngoài = cập nhật `THIRD_PARTY_NOTICES.md` hoặc `PRIVACY.md` trong **cùng commit**; CI chặn dependency không có giấy phép được phép.
