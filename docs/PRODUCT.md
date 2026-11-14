# Vedette — Mô tả sản phẩm

Phiên bản tài liệu: 2026-11-06 · Chủ: kien · Nguồn số liệu: `docs/research/2026-11-06-proposal.md`

## 1. Một câu

Phần mềm mã nguồn mở, miễn phí, cho doanh nghiệp biết **trong vòng 1 giờ** nếu thiết bị/phần mềm mình đang dùng nằm trong danh sách **đang bị hacker khai thác thật**, biết mình **có gì** và **hở ở đâu**, và nhận sẵn **cách xử lý** — mà không chen vào đường mạng.

## 2. Vấn đề (đo được)

| Sự thật | Nguồn |
|---|---|
| Khai thác lỗ hổng là vector xâm nhập số 1 (31%), lần đầu vượt credential | Verizon DBIR 2026 |
| Chỉ 26% lỗ hổng trong CISA KEV được vá hết; median 43 ngày | DBIR 2026 |
| 29% khai thác xảy ra trước/đúng ngày công bố CVE; 36% nhắm CVE đã >1 năm | VulnCheck 2026 |
| Lớp bị nhắm nhiều nhất: thiết bị biên mạng (firewall/VPN/NAS), rồi CMS | VulnCheck 2026, DBIR 2025 |
| Công ty 100–250 người chỉ chặn được 34% vụ ransomware trước khi bị mã hoá | Sophos 2026 |
| Thời gian từ xâm nhập đến bàn giao cho nhóm ransomware: 22 giây | Mandiant M-Trends 2026 |
| VN: 52,3% tổ chức bị thiệt hại; 47,7% không có nhân sự bảo mật; >50% không có anti-malware tập trung | NCA 2025 (5.300 tổ chức) |
| VN: Luật BVDLCN 91/2025 (1/1/2026) phạt tới 5% doanh thu; NĐ 330/2026, 363/2026 có biểu phạt cụ thể | thuvienphapluat, PwC |

Tóm lại: thiết bị biên không cài được EDR, bị khai thác nhanh hơn tốc độ vá, và SMB không có ai đọc cảnh báo. Khoảng trống: **"cái gì đang bị khai thác" × "tôi có cái đó không" × "làm gì ngay"** — chưa có sản phẩm miễn phí nào nối ba vế (khảo sát đối thủ: `docs/research/` §12).

## 3. Đối tượng

| Persona | Hoàn cảnh | Điều họ cần | Điều họ **không** làm |
|---|---|---|---|
| **P1 — Chủ/quản lý SMB không có IT** (10–100 người) | Có 1 firewall gia đình/SMB, 1 NAS Synology/QNAP, vài máy chủ cũ, website WordPress. IT là người bên ngoài hoặc nhân viên kiêm nhiệm | Biết "có nguy hiểm không, gọi ai, bảo họ làm gì", bằng tiếng Việt, qua Zalo | Không đọc dashboard, không cấu hình scan, không hiểu CVE |
| **P2 — IT một người** (100–500 người) | Quản mọi thứ: mạng, server, user. Có FortiGate/MikroTik/pfSense, AD, vài web app, có thể có Wazuh/Zabbix | Danh sách ngắn "sáng nay phải làm gì", copy-dán cấu hình, bằng chứng để xin ngân sách | Không có thời gian đọc advisory tiếng Anh, không viết rule IPS |
| **P3 — Đội triển khai / MSP** (hoãn: chưa hỗ trợ nhiều site, D-24) | Quản 10–200 khách | Một chỗ nhìn nhiều khách, biết khách nào dính KEV mới, gói giảm thiểu để gửi khách, báo cáo tháng | Không muốn đăng nhập từng hộp |
| **P4 — SOC/IT enterprise** (500+ người, có SOC hoặc thuê SOC) | Đã có SIEM/EDR/VM thương mại | Tín hiệu bổ sung "KEV × inventory" rẻ, honeypot nội bộ, API/MCP để kéo vào SIEM, SSO/RBAC | Không thay thế SIEM; không chấp nhận hộp inline |

Ưu tiên xây: P2 → P1 → P3 → P4. P2 là người sẽ **cài và giữ** sản phẩm; P1 là người sẽ **trả tiền triển khai**; P3/P4 mở rộng.

## 4. Lời hứa (được phép quảng cáo — mỗi dòng truy về story trong `USER_STORIES.md`)

**Biết sớm**
- Theo dõi 24/7 các nguồn lỗ hổng đang bị khai thác thật (CISA KEV, VulnCheck KEV, CVE.org, EPSS, PSIRT Microsoft/Fortinet/Synology/Cisco…), cập nhật mỗi giờ. (S-FEED-1)
- Bảng "đang nóng tuần này": hãng/thiết bị nào đang bị đánh nhiều nhất, thế giới và Việt Nam. (S-FEED-2)
- Cảnh báo Zalo/Telegram/email chỉ cho thiết bị anh có. (S-ALERT-1)

**Biết mình có gì**
- Tự kiểm kê mạng: thiết bị, hãng, model, OS, phiên bản, dịch vụ mở — không cài gì lên máy nhân viên. (S-INV-1)
- Liệt kê những gì đang lộ ra Internet: domain, subdomain, IP, cổng, giao diện quản trị. (S-EXP-1)
- Báo thiết bị lạ mới xuất hiện. (S-INV-3)

**Biết mình hở ở đâu**
- Quét lỗ hổng cho tài sản đã khai (chỉ cần IP/domain) hoặc hộp tự tìm; **mỗi khi có lỗ hổng mới bị khai thác, tự quét lại**. (S-SCAN-1, S-SCAN-2)
- Chỉ báo "có lỗ hổng" khi đã xác nhận được; phân biệt rõ "xác nhận" và "nghi ngờ theo phiên bản". (S-SCAN-3)
- Quét an toàn: giới hạn tốc độ, bỏ phép thử nguy hiểm, trong cửa sổ giờ cho phép. (S-SCAN-4)

**Biết phải làm gì**
- Mỗi lỗ hổng khớp: hướng dẫn vá đúng phiên bản, vá tạm, **đoạn cấu hình sẵn** cho firewall đang có (FortiGate, MikroTik, pfSense/OPNsense, Sophos, Cisco, Windows Firewall, Synology/QNAP). (S-MIT-1)
- Dấu hiệu để biết lỗ hổng đó đã bị khai thác trên máy anh chưa. (S-MIT-3)

**Biết khi bị vào**
- Bẫy nội bộ giả máy chủ file/RDP/SSH/SQL: chạm vào là báo ngay, gần như không báo nhầm. (S-HP-1)
- Nhận log từ firewall/máy chủ hiện có, so với 7 ngày trước để chỉ ra cái mới, đối chiếu IP/domain độc hại cập nhật hàng giờ. (S-LOG-1, S-LOG-2)

**Trợ lý AI của riêng anh**
- Cắm API key AI anh chọn (Anthropic, OpenAI, Gemini, hoặc model nội bộ qua Ollama/vLLM). Key ở trên thiết bị anh. (S-AI-1)
- Giải thích tiếng Việt lỗ hổng ảnh hưởng gì đến đúng thiết bị anh, viết sẵn cấu hình giảm thiểu, tóm tắt tin tức/PoC. (S-AI-2, S-AI-3)
- Đọc log giúp ở 3 mức chi phí; đồng hồ token và trần ngày. (S-AI-4)
- Báo cáo tuần một trang; báo cáo đánh giá an toàn theo Luật BVDLCN. (S-REP-1, S-REP-2)

**Mô hình**
- Mã nguồn mở, miễn phí vĩnh viễn (Apache-2.0). Tự cài hoặc thuê triển khai/vận hành.
- Dữ liệu của anh ở chỗ anh: kiểm kê, log, key AI không rời thiết bị. Thứ duy nhất gửi ra là **tín hiệu ẩn danh** (số lần bẫy bị chạm, số kết nối tới IOC, số lượng theo loại thiết bị) để bảng nóng có cột Việt Nam; nêu rõ trong `PRIVACY.md`, tắt một bấm. (S-CORE-4)
- Máy x86 bất kỳ (4 nhân, 8 GB), không chen vào đường mạng, tháo ra lúc nào cũng được.

## 5. Không làm (nói rõ với khách)

- Không thay firewall, **không tự chặn traffic** (bỏ ý tưởng inline IPS/WAF 2026-11-06, decision D-3).
- Không phải antivirus/EDR; không sao lưu dữ liệu.
- Không tự hành động từ AI: AI là cố vấn, người bấm.
- Không bán feed, không bán AI, không thu phí phần mềm.
- Không chống phishing Zalo/email (thị trường đã có).

## 6. Hình thái phát hành (edition = cùng một binary, khác cấu hình)

| | SMB | Mid | Enterprise/MSP |
|---|---|---|---|
| Triển khai | 1 hộp = server + sensor | 1 server + 1–5 sensor (mỗi site/VLAN) | 1 server trung tâm + nhiều sensor; hoặc 1 server mỗi khách + bảng tổng MSP |
| DB | SQLite | SQLite hoặc PostgreSQL | PostgreSQL |
| Đăng nhập | Local user | Local + RBAC 3 vai | OIDC/SSO + RBAC + audit |
| Tích hợp | Zalo/Telegram/email | + webhook, syslog out | + API/MCP, SIEM forward, multi-tenant |
| AI | BYOK | BYOK | BYOK hoặc gateway nội bộ |

Tất cả từ **một** codebase, module bật/tắt, không nhánh riêng. Sensor/server tách được từ ngày đầu (`ARCHITECTURE.md` §Sensor/Server) để Mid/Enterprise dùng được sớm.

## 7. Khác biệt thật (so với khảo sát đối thủ)

1. Nối kiểm kê LAN với bảng nóng 7 ngày → chỉ cảnh báo cái anh có. Chưa ai miễn phí làm.
2. Gói giảm thiểu copy-dán theo vendor firewall. Không ai có, kể cả thương mại.
3. AI BYOK tiếng Việt, 3 mức token, báo cáo PDPL. Chưa có OSS nào.
4. Tự quét lại theo sự kiện KEV (không theo lịch).
5. Honeypot + syslog + kiểm kê cùng một hộp.

Không nói: "feed khai thác đầu tiên", "AI EASM đầu tiên".

## 8. Tên

**Vedette** (chọn 2026-11-06). Đã kiểm tra: không có sản phẩm bảo mật/repo cùng tên. Tránh: Exploit Shield, KEV Watch, PatchWatch, chữ "Shield" (CyRadar Internet Shield ở VN). Tagline tiếng Việt: *Biết sớm. Biết rõ. Biết phải làm gì.*
