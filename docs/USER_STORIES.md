# User stories — cụ thể, không tưởng tượng

Quy ước: `S-<MODULE>-<n>` · Persona P1–P4 (`PRODUCT.md` §3) · **Trạng thái xác minh**: `[đạt]` / `[đạt]` / `[rớt]` theo `CONCEPT_VERIFICATION.md`. Story `[đạt]` chỉ được xây ở mức tối thiểu để xác minh; story `[rớt]` không xây. Mỗi story có **Kích hoạt → Thấy → Bấm → Nhận** và **Tiêu chí chấp nhận**. Không có story → không có tính năng (`.claude/rules/no-imagined-features.md`).

## FEED — Bảng nóng và tra cứu

**S-FEED-1** (P2) `[đạt]` — Mỗi sáng tôi mở Vedette và thấy lỗ hổng nào **mới bị khai thác thật trong 24h/7 ngày**, theo hãng/sản phẩm.
- Kích hoạt: mở trang chủ. Thấy: bảng "Đang nóng" 7 ngày: hãng → sản phẩm → số CVE mới trong KEV/VulnCheck, ΔEPSS, có PoC, có sightings; cột "Anh có?" (✓/–/?) nếu module kiểm kê bật. Bấm: một dòng → chi tiết CVE (mô tả tiếng Việt nếu AI bật, link nguồn, ngày KEV, due date, ransomware flag). Nhận: biết hôm nay có gì mới trong ≤2 phút.
- Chấp nhận: dữ liệu ≤60 phút tuổi (hiển thị "cập nhật lúc"); nguồn ghi rõ từng dòng; hoạt động không cần module khác.
- Chấp nhận (issue #79): trang chủ không bao giờ nói "0" khi thực ra là "chưa biết". Khi danh sách KEV **chưa từng tải được** (`cisa-kev` chưa có lần kéo `ok` nào), chỗ câu đếm "Today: 0 vulnerabilities newly exploited…" hiện "The CISA list could not be fetched yet: <reason>. See Settings → Feeds." (`<reason>` là lỗi lần kéo cuối, một dòng, đã làm sạch; liên kết tới Cài đặt → Feed); khi admin **tắt** `cisa-kev`, hiện "The CISA list is turned off. See Settings → Feeds.". Đã tải ít nhất một lần thì vẫn hiện số đếm kèm "cập nhật lúc" như cũ, kể cả khi lần kéo sau lỗi. Tham khảo: Grafana hiện biểu tượng lỗi trên panel thay vì một giá trị khi truy vấn hỏng; Dependabot ghi rõ lần cập nhật cuối thất bại thay vì báo "không có cảnh báo".

**S-FEED-2** (P1, P3) `[đạt]` — Tôi muốn xem "tuần này thế giới/VN đang bị đánh gì" như đọc báo, không cần hiểu CVE.
- Thấy: 5–10 dòng ngôn ngữ thường: "Synology NAS cũ đang bị ransomware C3RB3R — nếu dùng DSM 6.x/7.1 hãy cập nhật". Bấm: "Tôi có" → thêm vào tồn kho khai tay. Nhận: biết có liên quan hay không.
- Chấp nhận: câu tiếng Việt do pipeline sinh từ dữ liệu (không cần AI của khách); mỗi dòng có nút "Tôi có"/"Không liên quan".

**S-FEED-3** (P2, P4) `[đạt]` — Tra một CVE/sản phẩm/IP/domain và biết ngay: bị khai thác chưa, PoC chưa, IOC nào liên quan.

**S-FEED-4** (P2, P4) `[đạt]` (D-36, D-37) — Trong Cài đặt → Feed, tôi thấy các feed có sẵn (bật/tắt, sửa lịch và địa chỉ) và thêm feed riêng của công ty (lỗ hổng hoặc IOC), bật/tắt/sửa/xoá; mỗi feed hiện lần kéo gần nhất, số bản ghi, lỗi.
**S-FEED-5** (P4) `[đạt]` (D-37) — Tôi chỉnh cách Vedette đọc feed của tôi (định dạng, ánh xạ trường, biểu thức chính quy), bấm Thử để xem trước bản ghi đã chuẩn hoá trước khi lưu.
- Chấp nhận: kết quả <1 giây từ DB cục bộ; nêu nguồn và thời điểm.

## ALERT — Cảnh báo

**S-ALERT-1** (P1, P2) `[đạt]` — Khi có KEV mới **khớp thứ tôi có** (khai tay hoặc kiểm kê tự động), tôi nhận Zalo/Telegram/email trong ≤60 phút với: cái gì, mức khẩn, làm gì trước.
**S-ALERT-3** (P2) `[đạt]` (D-52) — Trang Incidents cho tôi thấy điều đang xảy ra (chạm bẫy, kết nối độc hại, log bất thường, thiết bị lạ), xác nhận/đóng từng mục và bấm Respond; lỗ hổng nằm ở Findings, không lặp lại ở đây.
- Chấp nhận: không gửi CVE không khớp; gộp nhiều CVE cùng sản phẩm vào một tin; có link mở gói giảm thiểu; có nút "đã xử lý/không liên quan" trong UI; nhật ký gửi.

**S-ALERT-2** (P3) `[rớt]` (hoãn, D-24) — Là MSP, tôi nhận một tin gộp "KEV X khớp 7/40 khách: A, B, C…".

## INV — Kiểm kê

**S-INV-1** (P2) `[đạt]` — Cắm hộp vào LAN, 1 giờ sau tôi có danh sách thiết bị: IP, MAC, hãng (OUI), tên, loại (router/NAS/máy in/camera/PC/server), OS, dịch vụ mở, sản phẩm+phiên bản khi đọc được, **độ tin cậy** từng trường và nguồn (thụ động/nmap/SNMP/agent).
- Chấp nhận: thụ động chạy liên tục không cần cấu hình; quét chủ động chỉ trong cửa sổ giờ tôi đặt; thiết bị "mỏng manh" (máy in, camera, PLC, NAS cũ) mặc định chỉ thụ động.
- Chấp nhận (D-84, D-74, WP-12): lần quét chủ động đầu tiên của một thiết bị **chưa rõ loại hoặc thuộc loại mong manh** là **một lần quét nhẹ** (tốc độ thấp nhất, không nhận dạng dịch vụ/OS), trong cửa sổ giờ; sau đó chỉ thụ động cho tới khi thiết bị được phân loại (dữ liệu thụ động hoặc người đặt loại) hoặc người cho phép quét thường (loại trong "regular scan kinds" hoặc "Allow regular scans").
- Chấp nhận (D-74): "Never" nghĩa là **không bao giờ** quét chủ động sau lần quét nhẹ đầu, **với mọi loại thiết bị** (kể cả máy chủ không mong manh); chọn "Never" trên thiết bị đang được quét thì lượt quét dừng ngay. Chính hộp Vedette không bao giờ bị quét.
- Chấp nhận (D-112, D-114, giao thức sensor): sensor hiện `offline` trong vòng 90 giây sau khi nó dừng; bắt gói chỉ chạy trong container `sensor` (không bao giờ trong `core`).

**S-INV-2** (P1, P2) `[đạt]` — Không có hộp, tôi vẫn khai tay: chọn hãng/sản phẩm/phiên bản từ danh sách gợi ý (CPE) để nhận cảnh báo.
- Chấp nhận: ≤3 bấm cho một sản phẩm; gợi ý tên thương mại, không chỉ CPE; danh mục đủ mọi sản phẩm từng có trong KEV + sản phẩm phổ biến SMB + khai tự do (D-30).

**S-INV-3** (P2) `[đạt]` — Thiết bị mới xuất hiện trong LAN → tôi được báo (tuỳ chọn) và nó vào danh sách "chưa duyệt".

**S-INV-4** (P4) `[đạt]` — Tôi cài osquery trên máy chủ Linux/Windows (mặc định), hoặc nối Wazuh có sẵn qua API chỉ đọc, để Vedette biết đúng gói/phiên bản và bớt "nghi" (D-33).
**S-INV-5** (P2) `[đạt]` (D-53) — Chính hộp Vedette là thiết bị đầu tiên trong danh sách, có danh sách gói thật, được khớp lỗ hổng như thiết bị khác và không xoá được.

## EXP — Bề mặt ngoài

**S-EXP-1** (P2) `[đạt]` — Tôi nhập domain của công ty và xác thực bằng DNS TXT; IP công cộng chỉ là IP chính hộp đang ra Internet, hộp tự dò (D-25, D-79); trước khi quét tôi tick một ô cam kết (D-26); Vedette liệt kê subdomain, IP, cổng mở, giao diện quản trị lộ ra Internet, cert sắp hết hạn.
- Chấp nhận: không quét thứ chưa xác thực sở hữu; có "ảnh chụp" theo ngày để so sánh thay đổi.
- Chấp nhận (D-79, kien 2026-11-09): chế độ tự dò (mặc định, dò lần đầu lúc cài) và thủ công ("Detect now"); chu kỳ 1 phút–24 giờ, mặc định 60 phút, admin sửa được; IP hiệu lực 30 ngày từ lần thấy cuối, gia hạn mỗi lần thấy lại, `expiring` ≤ 5 ngày; admin gỡ được IP; không có ô nhập IP.
- Chấp nhận (D-79): trước khi quét một IP, lượt dò gần nhất hoặc một lượt dò kỹ phải còn thấy nó; không thấy → quét IP đó tạm dừng với lý do rõ, IP vẫn trong danh sách.
- Chấp nhận (D-79): gỡ IP hỏi "Don't add it again if detected" (mặc định bật); IP bị bỏ qua nằm trong mục Ignored, có Restore; không bao giờ được quét hay tự thêm lại; mọi thay đổi ghi kiểm toán.

## SCAN — Quét lỗ hổng

**S-SCAN-1** (P2) `[đạt]` — Quét tài sản ngoài/trong bằng template xác nhận (Nuclei tag kev/vkev, an toàn), kết quả "xác nhận có" tách khỏi "nghi theo phiên bản".
**S-SCAN-2** (P2, P3) `[đạt]` — Có KEV mới có template → tự quét lại đúng tài sản liên quan trong ≤60 phút, báo nếu dính.
**S-SCAN-3** (P2) `[đạt]` — Mỗi phát hiện ghi rõ: bằng chứng (request/response rút gọn), độ tin cậy, cách tự kiểm tra lại.
**S-SCAN-4** (P1, P2) `[đạt]` — Tôi đặt cửa sổ giờ, tốc độ, danh sách loại trừ; quét dừng khi thấy thiết bị không phản hồi bất thường. Có nút "Dừng ngay".
**S-SCAN-5** (P4) `[đạt]` — Bật tier credentialed (Greenbone container riêng, SSH key) cho server quan trọng.

## MIT — Gói giảm thiểu

**S-MIT-1** (P2) `[đạt]` — Với CVE khớp, tôi mở "Làm gì": (a) phiên bản vá + link; (b) vá tạm; (c) **đoạn cấu hình** cho đúng vendor firewall tôi đã khai (FortiGate CLI, MikroTik script, pfSense/OPNsense, Sophos, Cisco IOS/ASA, Windows Firewall, Synology/QNAP); (d) checklist xác nhận.
- Chấp nhận: đoạn cấu hình có cảnh báo tác dụng phụ; nút "Đã áp dụng" ghi nhật ký; không có vendor nào → hướng dẫn chung.
- Chấp nhận (D-21): nguồn khuyến nghị luôn hiện rõ: **Vedette đã xác nhận** (người xác nhận, ngày, "soạn với AI") hoặc **Chưa có khuyến nghị đã xác nhận**. Khi chưa có: vẫn hiện thông tin gốc (KEV `requiredAction`, link advisory hãng) và nút "Hỏi AI của tôi" nếu module `ai` bật (S-AI-2); kết quả từ AI của khách mang nhãn "AI tạo" và không bao giờ hiện như khuyến nghị đã xác nhận.
**S-MIT-2** (P2, P4) `[rớt]` (D-31) — Tải gói rule (Suricata/CRS/CrowdSec/nftables set) cho CVE để nạp vào IPS/WAF sẵn có.
**S-MIT-3** (P2) `[đạt]` — "Tôi đã bị chưa?": dấu hiệu khai thác (log pattern, file, process) + câu lệnh kiểm tra.
**S-MIT-4** (người duy trì dự án) `[đạt]` (D-21) — Có KEV mới ảnh hưởng thiết bị phổ biến ở SMB VN, tôi muốn có gói giảm thiểu đáng tin cho mọi hộp mà không viết tay từ đầu.
- Kích hoạt: danh sách CVE chưa có gói, xếp theo `hot_score`. Thấy: công cụ soạn (`vedette-author`) dùng AI với key của dự án, chỉ trên dữ liệu công khai (KEV, cvelist, advisory hãng), ra bản nháp theo schema gói giảm thiểu, mỗi ý có nguồn. Bấm: sửa, ghi tên người xác nhận, mở PR lên GitHub. Nhận: sau khi merge, gói vào content pack ký và hiện "Vedette đã xác nhận" trên hộp khách trong chu kỳ content pack kế tiếp.
- Chấp nhận: không có PR được CODEOWNERS duyệt → không vào content pack; builder từ chối gói `status` khác `confirmed`; mỗi gói ghi `drafted_with` (model), `confirmed_by`, `confirmed_at`, nguồn; đoạn cấu hình có tác dụng phụ và bước kiểm tra; công cụ không đọc dữ liệu khách nào.

## HP — Honeypot nội bộ

**S-HP-1** (P2, P4) `[đạt]` — Bật bẫy SMB/RDP/SSH/MSSQL/HTTP trên hộp; bất kỳ kết nối nào vào bẫy → cảnh báo ngay, kèm IP nguồn, thiết bị nguồn (từ kiểm kê), 1 giờ sự kiện quanh đó.
**S-HP-2** (P2) `[đạt]` (D-50) — Tôi rải honey token (tệp mồi, tài khoản mồi, URL/DNS token), chọn vai giả giống thiết bị thật, được báo khi có quét cổng tới bẫy; chạm bẫy có thể kích hoạt phản ứng.
- Chấp nhận: loại trừ scanner của chính Vedette; không FP từ broadcast; bẫy không chạy dịch vụ thật.
- Chấp nhận (D-102): mỗi IP bẫy có **MAC riêng** (32 IP không bao giờ chung một MAC); mặc định là MAC local-administered ổn định theo IP; bẫy không mở được kết nối mới ra mạng (chỉ trả lời). Tuỳ chọn, có thể làm sau: danh sách decoy hiện MAC của từng IP (`mac` từ `GET /v1/state/net` của host), và vai giả có thể mang tiền tố MAC của hãng (`oui`, lấy từ bảng OUI của D-83).

## LOG — Log và bất thường

**S-LOG-1** (P2) `[đạt]` — Trỏ syslog của FortiGate/MikroTik/pfSense/Windows về hộp; Vedette gộp theo (signature, nguồn, đích) và so với 7 ngày trước; tôi thấy "cái mới" và "cái tăng đột biến", không phải log thô.
**S-LOG-2** (P2) `[đạt]` — Kết nối từ LAN ra IP/domain trong danh sách độc hại → cảnh báo, kèm thiết bị nguồn.
**S-LOG-3** (P4) `[đạt]` — Chuyển tiếp sự kiện Vedette sang SIEM (syslog/CEF/JSON webhook).
**S-LOG-4** (P2) `[đạt]` (D-43) — Có SPAN thì hộp đọc metadata DNS/SNI/luồng để thấy máy nào trong LAN liên lạc IP/domain độc hại, không cần cài IDS.

## AI — Trợ lý BYOK

**S-AI-1** (P2) `[đạt]` — Tôi thêm một hoặc nhiều hồ sơ AI (nhà cung cấp có sẵn hoặc tuỳ chỉnh: base URL, kiểu API) + key + model, rồi phân việc cho từng hồ sơ với dự phòng (D-29); Vedette thử một lệnh nhỏ, báo chi phí ước tính/ngày theo mức tôi chọn; key lưu mã hoá trên hộp.
**S-AI-2** (P1, P2) `[đạt]` — Trên một CVE khớp, bấm "Giải thích": AI viết tiếng Việt: có dính không và vì sao, bước vá cho đúng phiên bản, vá tạm, cấu hình cho vendor của tôi, dấu hiệu bị khai thác. Có nguồn, có token đã dùng.
**S-AI-3** (P2) `[đạt]` — Bấm "Tin mới về CVE này": Vedette tự fetch advisory/GitHub PoC/RSS (không để AI tự duyệt), AI tóm tắt: khai thác chưa, PoC chưa, workaround.
**S-AI-4** (P2, P4) `[đạt]` — Chọn mức tối thiểu/trung bình/tối đa cho đọc log; mức tối đa cho AI dùng tool chỉ-đọc để tự điều tra; trần token/ngày; vượt trần tự hạ mức.
**S-AI-5** (P2) `[đạt]` — Hỏi tự do trên dữ liệu của tôi ("máy nào còn RDP ra WAN?") — AI trả lời bằng tool chỉ-đọc, có bảng kết quả.
**S-AI-6** (P1, P3) `[đạt]` — Mọi câu AI trả lời đều có ghi "AI tạo, cần người xác nhận" và không có nút hành động trực tiếp.
**S-AI-7** (P4) `[đạt]` (D-39) — Tôi quản lý harness AI trong hộp: quy tắc, memory, skills, kho tri thức RAG, kết nối MCP ra ngoài (SSH/HTTP/API, danh sách cho phép, đọc/ghi) và hook chặn (dữ liệu cá nhân, việc ngoài phạm vi bảo mật, công cụ ghi phải duyệt).
- Chấp nhận (D-93, D-94): kết nối ra thiết bị và máy chủ MCP được quản lý ở **Settings → Connections** (thuộc `core`; tab AI chỉ còn một liên kết tới đó) và vẫn dùng được khi module `ai` tắt; công cụ ghi luôn tắt khi tạo, AI chỉ thấy công cụ đọc; loại `mcp-stdio` hiện "not supported" và lưu bị từ chối (400 `kind_unsupported`); kết nối HTTPS có chứng chỉ không được hệ thống tin cậy và kết nối SSH được ghim ở lần Test đầu (hiện dấu vân tay chỉ đọc, admin xoá ghim được), ghim lệch hoặc khoá máy chủ đổi → từ chối, không gửi thông tin xác thực; bí mật chỉ hiện 4 ký tự cuối; xoá kết nối còn thay đổi đang hiệu lực → 409 `in_use`.
**S-AI-8** (P2, P4) `[đạt]` (D-48) — Tôi xem và tải về mọi việc AI đã làm (lần gọi, công cụ, hook, đề xuất, hành động) với chuỗi hash chống sửa.

## RESP — Phản ứng

**S-RESP-1** (P2) `[đạt]` (D-40) — Thiết bị của tôi dính phát hiện Critical → AI đề xuất kế hoạch phản ứng theo đúng hạ tầng của tôi (ví dụ tắt NAT cổng NAS trên FortiGate), hiện ở trang phát hiện và gửi kênh báo cáo.
**S-RESP-2** (P2) `[đạt]` (D-41, rủi ro cao, tắt mặc định) — Tôi bật cho phép AI thực thi hành động đã được duyệt; AI gửi yêu cầu (thay đổi chính xác trước/sau, hoàn tác) lên kênh báo cáo; người có quyền bấm Duyệt hoặc Từ chối; hết hạn sau 15 phút; mọi bước ghi kiểm toán; có nút dừng khẩn cấp.
- Chấp nhận (D-96, D-97, D-98) — ai duyệt được ở đâu: **trong app**: rủi ro thấp/trung bình 1 người; cao 2 người khác nhau; cao do AI đề xuất 2 người khác nhau và mỗi người nhập mã hai bước của mình (không có cửa sổ "đã xác thực": mỗi lần duyệt một mã). **Nút Slack/Telegram**: thấp/trung bình; cao 2 người; cao do AI → 403 `in_app_required` (tin chỉ có "Open Vedette"). **Liên kết email**: chỉ thấp/trung bình (mở liên kết không bao giờ duyệt, phải bấm Approve/Reject; dùng một lần); cao → 403 `in_app_required`, thư không có liên kết duyệt. **Mã trả lời Zalo cá nhân**: thấp/trung bình; cao → 403 `channel_not_allowed`. **Tự động** chỉ cho quy tắc duyệt sẵn (thấp, hoàn tác được, TTL ≤ 24 giờ, một người duyệt). Người duyệt không có trong danh sách của kênh hay kênh không bật cho duyệt → từ chối và ghi log; yêu cầu chỉ gửi tới kênh nằm trong `approval_channels` của Response; mỗi lần gửi ghi vào `sent_to`.
- Chấp nhận (13b-6, D-117) — hoàn tác và kết quả chưa rõ: khi một bước đã gửi đi mà không biết kết quả (hết giờ sau khi gửi, HTTP 3xx/5xx, công cụ MCP báo lỗi, một dòng SSH bị từ chối, lỗi nửa chừng), mục hiện **failed** kèm nhãn "The result of this change is unknown. Undo it to be sure it is not in force." và nút **Roll back** (cùng nút hoàn tác của mục đã chạy); bấm sẽ gửi bước hoàn tác rồi đọc lại, và chỉ khi đọc lại cho thấy thay đổi không còn thì mục thành `rolled_back`. Nếu hành động có chữ đọc lại (`expect`), hộp tự đọc lại ngay và ở mỗi lượt sweep: có chữ → mục thành `executed` (đang có hiệu lực, có giờ tự hoàn tác); thiết bị trả lời mà không có chữ → không có hiệu lực; không rõ → vẫn chưa rõ. Hoàn tác không bị chặn bởi công tắc thực thi hay cầu dao, nhưng bị chặn bởi dừng khẩn cấp tới khi admin tiếp tục; đổi token, ghim hay công cụ ghi của kết nối không làm kẹt hoàn tác (chỉ địa chỉ/loại/id đổi thì từ chối, kèm lời giải thích). Yêu cầu hiện **cả tiêu đề (header) kèm giá trị đã điền** và `{expiry_s}` thành số giây sẽ được gửi.
**S-RESP-3** (P2) `[đạt]` (D-44) — Tôi bật quy tắc phản ứng không cần AI (IOC khớp → chặn đích; chạm bẫy → chặn nguồn), chọn chỉ cảnh báo / hỏi duyệt / tự động; firewall của tôi kéo danh sách chặn từ hộp hoặc hộp đẩy qua API/SSH; có danh sách không bao giờ chặn và tự gỡ sau TTL.
**S-RESP-4** (P2, P4) `[đạt]` (D-47) — Tôi mô tả loại hành động bằng lời và thêm/sửa/xoá loại tuỳ chỉnh với mẫu lệnh có tham số được kiểm và mẫu hoàn tác.
- Chấp nhận (D-93): hành động lên thiết bị chọn kết nối từ Settings → Connections; hành động thiết bị chạy được khi module `ai` tắt.
- Chấp nhận (D-95): mẫu có **Check before** (lệnh/API chỉ đọc chạy trước khi ghi, tối đa 5 chuỗi từ chối) và **Expect** ở bước đọc lại; đầu ra kiểm trước chứa chuỗi từ chối → không gửi gì để ghi, lý do hiện trên yêu cầu; có Expect → kết quả "verified"/"not as expected" (sau hoàn tác: chuỗi phải biến mất), không có → "not checked"; hành động có `{interface}` không có Check before với ít nhất một chuỗi từ chối thì "không khả dụng"; hành động cần giá trị đọc từ thiết bị lúc chạy (`{seq}`, VLAN cũ...) hiện "không khả dụng" kèm lý do.

## REP — Báo cáo

**S-REP-1** (P1, P3) `[đạt]` — Báo cáo tuần 1 trang tiếng Việt: có gì mới, đã xử lý gì, còn gì, gửi tự động.
**S-REP-2** (P1, P2) `[đạt]` — Báo cáo tự đánh giá bảo vệ dữ liệu cá nhân theo Luật 91/2025/QH15 + Nghị định 356/2025/NĐ-CP (áp dụng theo quy mô tổ chức; cấp độ hệ thống thông tin là chế độ riêng, tuỳ chọn) từ kiểm kê + scan, xuất PDF để lưu; có câu miễn trừ và nguồn pháp lý.

## NOTIFY / CORE / FLEET

**S-NOT-1** (P1, P2) `[đạt]` — Cấu hình kênh Zalo OA/Telegram/email/webhook, thử gửi, lịch im lặng.
**S-NOT-2** (P1, P2) `[đạt]` (D-38) — Thêm kênh Slack (Incoming Webhook; Socket Mode nếu muốn duyệt hành động trong Slack), thử gửi.
**S-CORE-1** (P2) `[đạt]` — Bật/tắt từng module trong Cài đặt; tắt giữ dữ liệu; màn hình nói rõ module nào đang tắt và vì sao thiếu dữ liệu.
**S-CORE-2** (P2) `[đạt]` — Trang Cập nhật: phiên bản phần mềm, dữ liệu, gói nội dung; cập nhật tự động hay tay; rollback 1 bấm; bundle offline.
- Chấp nhận (D-104): khi bản đang chạy khai `rollback.safe=false`, hộp thoại Rollback cảnh báo "Data written since the update is lost." và nút xác nhận chỉ gửi khi người dùng đồng ý: `POST /core/updates/rollback` thiếu `confirm_data_loss: true` thì trả `409 confirm_required` (cùng kiểu với xác nhận đổi mạng); `UpdateComponent` có `rollback_restores_data` để GUI biết khi nào cảnh báo. Rollback bị từ chối hiện lý do bằng lời thường cho `rollback_not_allowed` (bản trước thấp hơn mức cho phép), `previous_revoked` (bản trước đã bị thu hồi), `rollback_backup_missing` (không còn bản sao lưu trước cập nhật). Không có đường hạ bản ngoài Rollback về bản trước đã xác minh.
**S-CORE-7** (P2) `[đạt]` (D-53) — Trong Settings → Updates tôi thấy hệ điều hành của chính hộp có bao nhiêu bản vá bảo mật chờ, có cần khởi động lại không, bấm cài ngay hoặc đặt lịch trong cửa sổ bảo trì, bật tự cập nhật bảo mật; cùng trang có gói phụ thuộc và phần mềm Vedette.
**S-CORE-8** (P2) `[đạt]` (D-56) — Trong Settings → Box network tôi chọn card quản trị (DHCP/tĩnh, đổi IP có xác nhận trong 2 phút hoặc tự quay lại) và card nhận SPAN, thấy lưu lượng nhân bản có tới thật không kèm lời khuyên, chọn trích xuất gì, đặt bộ lọc, xem hướng dẫn bật port mirroring theo loại switch, IP phụ cho bẫy và NTP.
- Chấp nhận (D-100): phần trợ giúp cạnh nút lưu đổi địa chỉ nói "If the box restarts before you confirm, it comes back on the old address."; chỉ đổi DNS, NTP hay card SPAN thì áp ngay, không đếm ngược. Thông báo lỗi bằng lời thường cho: `address_conflict` ("Another device already uses this address."), `gateway_outside_subnet` ("The gateway must be inside the address range you entered."), `net_backend_unsupported` ("This box's network files were not set up by the Vedette installer, so Vedette cannot change them. Reinstall with the installer or change the network on the box itself."). Hết giờ hay bấm Cancel thì hiện cấu hình cũ đã quay lại; xác nhận khi không còn thay đổi chờ thì báo đã hết hạn.
- Chấp nhận (D-118): với DHCP hộp chưa biết địa chỉ mới nên hộp thoại xác nhận chỉ chỗ tìm (máy chủ DHCP hoặc danh sách thiết bị của router) chứ không hiện địa chỉ; nếu hộp không tự quay về được (hoàn tác hỏng) thì trang nói hộp sẽ khởi động lại và quay về địa chỉ cũ, và bỏ nút Confirm/Cancel; hộp mà host chưa ghi cấu hình nào thì chỉ cho lưu địa chỉ quản trị trước (409 `management_not_set`: "Vedette has not set up this box's network yet. Save the management address first, then change the other settings.").
**S-CORE-4** (P1, P2) `[đạt]` — Trong Cài đặt → Chia sẻ tín hiệu, tôi thấy **nguyên văn** gói dữ liệu ẩn danh sắp gửi, lần gửi gần nhất, và một công tắc tắt; tắt xong không còn gì rời hộp ngoài kéo feed và gọi provider AI tôi cấu hình.
**S-CORE-3** (P4) `[đạt]` — Đăng nhập OIDC, 3 vai (xem/vận hành/quản trị), audit log mọi thay đổi. Đăng nhập hai bước: ứng dụng xác thực (QR hoặc khoá tay) hoặc mã qua email (cần kênh email); quản trị viên đặt lại được (D-35).
- Tiêu chí bổ sung (D-75, D-76): màn hình Setup lần đầu đòi **mã cài đặt một lần** in trên console/log của hộp; sai mã → từ chối, mã hết hiệu lực khi admin đầu tiên được tạo. Bật đăng nhập hai bước (ứng dụng hoặc email) đòi **nhập lại mật khẩu hiện tại**, như khi tắt.
**S-FLEET-1** (P3) `[rớt]` (hoãn, D-24) — Bảng tổng nhiều khách/site: khách nào có KEV mới khớp, bao nhiêu chưa xử lý, hộp nào mất liên lạc.
**S-MCP-1** (P4) `[đạt]` — Bật MCP server chỉ-đọc để agent/SIEM bên ngoài tra tài sản, phát hiện, feed.
**S-CORE-5** (tất cả) `[đạt]` (D-42) — Gặp lỗi, tôi bấm Báo lỗi: mô tả, xem trước gói chẩn đoán đã lọc, tải về và mở GitHub issue điền sẵn.
**S-CORE-6** (tất cả) `[đạt]` (D-48) — Tôi tải toàn bộ log của hộp (kiểm toán, AI, phản ứng, probe quét, cảnh báo, log thiết bị) dạng JSON/CSV.

## Nhật ký xác minh

| Story | Ngày | Phương pháp | Kết quả | Ghi chú |
|---|---|---|---|---|
| S-CORE-1 | 2026-11-06 | quyết định D-10 (nhóm A, D-20) | đạt | nền, không cần phỏng vấn |
| S-CORE-2 | 2026-11-06 | quyết định D-12 (nhóm A, D-20) | đạt | nền |
| S-CORE-4 | 2026-11-06 | quyết định D-16, D-17 (nhóm A, D-20) | đạt | nền, pháp lý |
| S-AI-6 | 2026-11-06 | quyết định D-11 (nhóm A, D-20) | đạt | guardrail AI |
| S-MIT-4 | 2026-11-06 | quyết định D-21 (kien) | đạt | quy trình của người duy trì |
| Mọi story còn lại | 2026-11-06 | quyết định D-23 (kien: không phỏng vấn) | đạt | xác minh bằng QA người dùng thật do AI làm |
