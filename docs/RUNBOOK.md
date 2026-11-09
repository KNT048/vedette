# Runbook vận hành Vedette (khung)

Lập 2026-11-09. Đây là **khung**: chỗ nào phụ thuộc backend ghi "sẽ điền ở M2". Kiến trúc hộp theo D-55 (appliance Debian 12 / Ubuntu 24.04, `vedette-host` + container Podman/Quadlet) và D-56 (mạng/SPAN). Mọi lệnh sau khi điền phải chạy được trên máy mới dựng từ repo và có bước xác minh bằng hiệu ứng (`rules/ships-as-code.md`).

Quy ước: **Triệu chứng → Kiểm tra → Sửa → Xác minh**. Không SSH sửa tay cấu hình rồi bỏ đó: cấu hình sinh từ DB/repo, sửa tay sẽ bị ghi đè.

## 1. Cài đặt

### 1.1 Appliance (đủ tính năng)
- Yêu cầu: máy x86-64/arm64, Debian 12 hoặc Ubuntu 24.04 mới cài, 2 card mạng (quản trị + SPAN/TAP), đĩa và RAM tối thiểu: sẽ điền ở M2.
- Cài bằng script: sẽ điền ở M2 (lệnh, ghim phiên bản, idempotent; chạy lại không phá).
- Xác minh cài xong: `vedette-host` chạy (systemd), các container `core`, `sensor`, `honeypot` lên, cổng HTTPS 8443 mở, image đúng chữ ký cosign: sẽ điền ở M2.
- Hệ điều hành không hỗ trợ: script dừng và nói rõ lý do, không cài dở.
- ISO/VM image: chưa có (D-55: làm sau).

### 1.2 Chỉ container (Docker/Podman sẵn có)
- Không quản lý OS, không cấu hình card mạng; tính năng mạng sâu (SPAN, IP phụ cho bẫy) có hạn chế ghi rõ trong UI: sẽ điền ở M2.
- Compose file, volume, biến môi trường, tài khoản chạy: sẽ điền ở M2.

## 2. Khởi động lần đầu
Cài đặt ban đầu làm hoàn toàn trong GUI (D-22): tạo admin, bật 2FA, tên tổ chức, múi giờ, bật module, khai thiết bị, kênh cảnh báo.
- Lấy địa chỉ và mã thiết lập lần đầu từ console: sẽ điền ở M2.
- Thứ tự màn hình, giá trị mặc định an toàn (module tuỳ chọn tắt, hành động phản ứng tắt): sẽ điền ở M2.
- Cấu hình card quản trị / SPAN (Settings → Box network, D-56): sẽ điền ở M2.
- Xác minh: đăng nhập được bằng 2FA, trang Home hiện dữ liệu feed có thời điểm, `feeds` kéo `index.json` đã ký thành công: sẽ điền ở M2.

## 3. Nâng cấp
- Nâng cấp từ giao diện (Settings → Updates), qua kênh `stable` hoặc `beta`, theo cohort (`docs/ENGINEERING.md` §6, D-12).
- Trước khi nâng: sao lưu tự động (xem §5), kiểm cửa sổ bảo trì: sẽ điền ở M2.
- Quy trình: `vedette-host` kéo image, kiểm chữ ký cosign, khởi động container mới, kiểm sức khoẻ, chuyển: sẽ điền ở M2.
- Từ chối khi chữ ký sai hoặc bị thu hồi; hiện lý do trong UI: sẽ điền ở M2.
- Xác minh: phiên bản mới ở Settings → Updates, các module trước đó bật vẫn bật, dữ liệu còn nguyên: sẽ điền ở M2.

## 4. Hoàn tác
- Hoàn tác bằng tag image cũ (D-55); migration DB chỉ tiến nên hoàn tác = image cũ + khôi phục sao lưu trước nâng cấp: sẽ điền ở M2.
- Hộp tự hoàn tác khi kiểm sức khoẻ thất bại sau nâng cấp: sẽ điền ở M2.
- Hoàn tác thủ công từ console: sẽ điền ở M2.
- Xác minh: phiên bản cũ chạy, đăng nhập được, dữ liệu khớp bản sao lưu: sẽ điền ở M2.

## 5. Sao lưu và khôi phục
- Có gì trong bản sao lưu: SQLite trên volume, khoá `core/secrets` (mã hoá, tách khỏi bản sao lưu dữ liệu hay không: sẽ điền ở M2), cấu hình sinh ra, content pack: sẽ điền ở M2.
- Sao lưu hằng ngày + trước nâng cấp, nơi lưu, số bản giữ, mã hoá: sẽ điền ở M2. Lưu ý IP egress 90 ngày (D-25) khi khôi phục sang máy khác: phải xác nhận lại.
- Xuất/xoá dữ liệu từ GUI (Settings → Data): sẽ điền ở M2.
- Khôi phục: sẽ điền ở M2. Xác minh bằng tra cứu một bản ghi đã biết và chạy thử gửi cảnh báo.
- **Diễn tập khôi phục** trên máy sạch mỗi quý: sẽ điền ở M2 (ghi kết quả vào `docs/project-map/completion-log.md`).

## 6. Cập nhật hệ điều hành
- Hộp kiểm hệ điều hành trước tiên (D-53): bản phát hành, kernel, gói có vá bảo mật, cần khởi động lại, unattended-upgrades, hạn hỗ trợ.
- `vedette-host` thực thi qua danh sách lệnh cố định; không cho giao diện chạy lệnh tuỳ ý: sẽ điền ở M2.
- Cửa sổ bảo trì và lịch khởi động lại (Settings → Updates): sẽ điền ở M2.
- Sau khởi động lại: container tự lên (Quadlet), SPAN nhận lại lưu lượng, bẫy lên lại trên IP phụ: sẽ điền ở M2.
- Nâng bản phát hành OS (Debian 12 → 13…): sẽ điền ở M2.

## 7. Đặt lại 2FA của admin từ console
Dùng khi admin mất thiết bị 2FA. Phải có quyền vật lý hoặc SSH quản trị vào hộp (đã được chủ hộp cho phép); thao tác được ghi audit.
- Lệnh trên console, tham số, xác nhận danh tính: sẽ điền ở M2.
- Hiệu ứng mong đợi: đăng nhập lại chỉ bằng mật khẩu một lần, buộc đăng ký 2FA mới, phiên cũ bị huỷ: sẽ điền ở M2.
- Không có cửa sau trong giao diện web; không đặt lại qua email: sẽ điền ở M2 (xác nhận với kien).

## 8. Xử lý sự cố

### 8.1 SPAN không thấy lưu lượng
Kiểm theo thứ tự, từ rẻ đến đắt:
1. Settings → Box network: trạng thái lưu lượng (gói/giây, số MAC khác hộp, lần nhận gói cuối). Chỉ thấy MAC của hộp = mirror chưa bật hoặc sai cổng (D-56).
2. Card SPAN còn link, không có IP, đang ở chế độ nghe: sẽ điền ở M2 (lệnh kiểm).
3. Cấu hình port mirroring trên switch (theo hướng dẫn từng hãng trong UI); mirror cả hai chiều; cổng đích đúng.
4. Bộ lọc loại trừ không che hết; giới hạn tài nguyên không làm rơi gói: sẽ điền ở M2.
5. Container `sensor` chạy với `CAP_NET_RAW`, đúng card: sẽ điền ở M2.
- Xác minh: số gói/giây > 0, thấy MAC thiết bị khác, DNS/SNI mới xuất hiện: sẽ điền ở M2.

### 8.2 Feed lỗi
- Trang feeds: nguồn nào lỗi, từ khi nào, lỗi gì.
- Kiểm: ra Internet (HTTPS), DNS, giờ hệ thống (chữ ký có hạn), proxy, key BYOK hết hạn/hết quota, chữ ký `index.json` sai (fail-closed: giữ dữ liệu cũ và báo): sẽ điền ở M2.
- Xác minh: lần kéo gần nhất thành công, thời điểm cập nhật mới: sẽ điền ở M2.

### 8.3 Phê duyệt không tới
"Phê duyệt" = thông báo duyệt thiết bị/hành động phản ứng đến kênh cảnh báo.
- Kiểm: kênh bật chưa, "Gửi thử" từ Settings → Alert channels, lịch im lặng, gộp thông báo, token Telegram/Slack/Zalo hết hạn, mạng bị chặn tới nhà cung cấp kênh (đổi kênh nếu bị chặn, D-19), hàng đợi gửi: sẽ điền ở M2.
- Thông báo duyệt không bao giờ chạy hành động khi chưa có thao tác trong GUI: sẽ điền ở M2 (khớp S-NOT / module `response`).
- Xác minh: "Gửi thử" nhận được; duyệt thật đi đến log audit: sẽ điền ở M2.

### 8.4 CPU cao
1. Container nào: `podman stats`: sẽ điền ở M2.
2. `scan` (nuclei/nmap) đang chạy: dừng ngay từ GUI, giảm throttle, dời vào cửa sổ giờ.
3. `sensor` trên SPAN lưu lượng lớn: thêm bộ lọc loại trừ, giảm trích xuất, giới hạn tài nguyên.
4. `logs` parser/gộp: giới hạn tốc độ nhận, kiểm vòng lặp nguồn log.
5. `ai` job lô, SQLite khoá/VACUUM: sẽ điền ở M2.
- Tắt module không cần (tắt = không route, không job, dữ liệu giữ nguyên) là cách giảm tải an toàn nhất.
- Xác minh: CPU xuống dưới ngưỡng, không còn job treo: sẽ điền ở M2.

## 9. Ứng phó sự cố: lỗ hổng trong chính Vedette
Vedette là sản phẩm bảo mật nên lỗ hổng của nó là sự cố (`SECURITY.md`). Cam kết hiện có: xác nhận trong 2 ngày làm việc; sửa hoặc giảm thiểu trong 14 ngày (critical) / 30 ngày (high); mọi bản vá bảo mật có advisory (GHSA, CVE nếu phù hợp), đi qua kênh product-advisory và hiện trong ứng dụng.

| Bước | Việc | Ai |
|---|---|---|
| 1. Tiếp nhận | Báo cáo riêng qua GitHub Security Advisories; không thảo luận ở issue/PR công khai. Ghi giờ nhận. | người duy trì |
| 2. Xác nhận và phân loại | Tái hiện trên bản mới nhất và bản đã phát hành; chấm CVSS, ghi phiên bản và module bị ảnh hưởng; có đang bị khai thác không. | người duy trì + owner module |
| 3. Giảm thiểu tạm | Nếu chưa có vá: hướng dẫn tắt module bị ảnh hưởng, đổi cấu hình, chặn cổng. | người duy trì |
| 4. Sửa | Làm trên nhánh riêng tư (advisory private fork); thêm test lặp lại lỗi; review bởi người thứ hai; không lộ chi tiết trong tên nhánh/commit công khai trước khi phát hành. | owner module |
| 5. Phát hành | Đi qua `docs/ENGINEERING.md` §6 với cohort rút gọn, ký cosign, kênh product-advisory; **kien tag tay**. | người duy trì |
| 6. Thông báo | Công bố GHSA (+ CVE), changelog mục Security, banner trong ứng dụng cho người dùng đang chạy bản bị ảnh hưởng: sẽ điền ở M2 (cơ chế banner). | người duy trì |
| 7. Thu hồi | Nếu một bản phát hành bị lỗi nặng: thu hồi (revocation) để hộp không cài và cảnh báo hộp đã cài (D-12): sẽ điền ở M2. | người duy trì |
| 8. Sau sự cố | Ghi nguyên nhân gốc vào `docs/project-map/lessons.md`, thêm test/quy tắc chặn tái diễn, đóng advisory. | người duy trì |

- Lộ khoá ký (cosign/minisign): thu hồi khoá, phát hành khoá mới qua kênh đã biết, đính chính công khai: sẽ điền ở M2.
- Lộ secret của người dùng do lỗi Vedette: thông báo để họ đổi khoá API/token đã cấu hình; Vedette không giữ khoá ở dạng rõ (AES-256-GCM).
