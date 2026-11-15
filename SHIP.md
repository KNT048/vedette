# SHIP.md: phạm vi v1 (đóng băng, kien 2026-11-15, D-624)

v1 dành cho **P2, người làm IT một mình**: biết trong 1 giờ thứ mình đang dùng có bị khai thác thật không, mình có gì, phải làm gì (`docs/PRODUCT.md` §1).

**v1 xong khi 7 hành trình dưới đây đạt trên hộp thật (N100 Ubuntu và máy Debian), kiểm như khách, và bản phát hành ký được.** Không phải khi mọi module xong. Trạng thái từng hành trình nằm ở `docs/v1-journeys.json`; chỉ đổi `passes` sau một lượt kiểm như khách có ghi chứng cứ.

## 7 hành trình

| # | Hành trình | Story |
|---|---|---|
| J1 | Cài sạch từ bản phát hành có ký, đăng nhập, bật 2 bước | S-CORE-2, S-CORE-3 (đăng nhập cục bộ) |
| J2 | Quét LAN, thấy thiết bị kèm hãng và phiên bản | S-INV-1, S-INV-5 |
| J3 | KEV mới khớp một thiết bị → finding và cảnh báo tới Email hoặc Telegram trong 1 giờ | S-FEED-1, S-ALERT-1, S-NOT-1 |
| J4 | Mở finding → hướng dẫn vá và cấu hình giảm thiểu cho firewall | S-MIT-1, S-MIT-3 |
| J5 | Trang Plan nói cần cập nhật gì | S-TIER-1, S-TIER-2, S-TIER-4 |
| J6 | IP công khai: cổng đang lộ và phiên bản dịch vụ | S-EXP-1, S-EXP-2 |
| J7 | Cập nhật lên bản mới; sao lưu rồi khôi phục | S-CORE-2 |

Cổng phát hành đi kèm: job release (bake `install.sh`, đẩy ghcr, ký image), `make vuln-scan` xanh, không còn phát hiện bảo mật mức High.

## Module

| Nhóm | Module | Nghĩa |
|---|---|---|
| **v1** | core, host, feeds, inventory, sensor-active, sensor-passive, agent-intake, findings, mitigation, notify (Email, Telegram), exposure (cổng và phiên bản trên IP công khai) | Lỗi làm hỏng J1–J7 chặn v1 |
| **Preview** | scan, honeypot, logs, ai, reports | Ship, tắt mặc định, gắn nhãn Preview. Chỉ chặn v1 khi lỗi bảo mật, mất dữ liệu, hoặc làm hỏng J1–J7 |
| **Sau v1** | response, mcp-server, auth-oidc, scan-credentialed | Ẩn khỏi giao diện ở v1; mã giữ nguyên |

Tính năng sau v1 (không làm trước khi tag v1): OpenVAS đăng nhập, ZAP full/active, FULL-5 (dò bề mặt tấn công của domain), trợ lý cấu hình firewall, AI soạn hồ sơ phản ứng, CVE tiers 3c, Zalo, mail M365/Workspace, VulnCheck.

## Luật đóng băng
- Ý mới, kể cả của kien, vào GitHub issue nhãn `post-v1`. Chỉ vào v1 khi kien nói rõ "đưa vào v1" và cập nhật file này.
- Việc chặn v1 nằm trong issue nhãn `v1`. Không có nơi nào khác ghi việc v1.
- Mỗi PR trước v1 phải nêu nó gỡ chặn hành trình nào (Jn) hoặc cổng phát hành nào.
