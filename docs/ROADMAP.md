# Lộ trình — xác minh concept → GUI → module

Ràng buộc (kien, 2026-11-06): ship nhanh nhưng đúng concept; SMB/Mid/Enterprise dùng được sớm; **GUI tốt rồi mới làm backend** để không chệch hướng; không tưởng tượng tính năng. Thời lượng là ước lượng cho 1–2 người + AI; đo lại sau mỗi mốc.

| Mốc | Thời lượng | Giao gì | "Xong" khi | Không làm |
|---|---|---|---|---|
| ~~M0 Xác minh concept~~ (bỏ, D-23) | — | Prototype bấm được (dữ liệu KEV thật, tồn kho giả), 8–10 phỏng vấn P1/P2/P3, bảng kết quả theo story, quyết định go/no-go từng module | Mỗi story trong M0 có `[đạt]`/`[rớt]` kèm bằng chứng; `DECISIONS.md` ghi module nào vào M1 | Backend, DB, auth |
| **M1 GUI** | 4–6 tuần | SPA hoàn chỉnh cho mọi module `[đạt]`, chạy trên **mock API** (MSW + fixture từ KEV/Nuclei thật); bật/tắt module trong Cài đặt; i18n vi/en; dark/light; a11y; usability test 5 người; design review theo `FRONTEND.md` | `pnpm test` + `pnpm build` xanh; mọi màn hình truy về story; không màn hình nào không có story; 5/5 người test hoàn thành 3 việc chính không cần hướng dẫn | Backend thật |
| **M2 Lõi + Feed + Thông báo** | 4 tuần | Binary Go: core (auth local, cấu hình, module registry, job, audit, update client), `feeds` (kéo index.json ký), `inventory` khai tay, `notify` Zalo/Telegram/email; **builder** + repo dữ liệu + Pages; service tín hiệu ẩn danh **không ghi IP nguồn** (cam kết vào `PRIVACY.md` cùng commit, D-20) | Máy mới: `install.sh` → 10 phút sau nhận alert thật cho sản phẩm khai tay; cập nhật dữ liệu ký chạy 24h không lỗi | Sensor, scan, AI |
| **M3 Kiểm kê + Giảm thiểu** | 6 tuần | `sensor-passive`, `sensor-active` (nmap từ repo OS, Recog), hợp nhất observation, cột "Anh có?" thật; `mitigation` với pack cho ≥5 vendor firewall; `vedette-author` + xác nhận qua PR (S-MIT-4, D-21); sensor/server tách được | Cắm hộp vào LAN thử: ≥80% thiết bị có vendor đúng, ≥50% có product/version; KEV mới khớp → alert + gói giảm thiểu ≤60 phút | AI, scan |
| **M4 Bề mặt ngoài + Quét** | 4 tuần | `exposure` (xác thực sở hữu, subfinder/httpx), `scan` (Nuclei kev/vkev safe), quét lại theo sự kiện KEV, bằng chứng | Nuclei xác nhận đúng trên lab có lỗ hổng; không quét thứ chưa xác thực; "Dừng ngay" dừng trong 5 giây | Credentialed |
| **M5 Honeypot + Log** | 4 tuần | `honeypot` (OpenCanary), `logs` (syslog FortiGate/MikroTik/pfSense/Windows, baseline 7 ngày, IOC) | Chạm bẫy → alert ≤30 giây kèm thiết bị nguồn; log 7 ngày gộp ≤ 1/100 dòng thô | SIEM forward |
| **M6 AI BYOK** | 4 tuần | `ai`: provider adapter, skill runner, RAG FTS5, 3 mức, `explain-finding`, `cve-news`, `log-digest`, `mcp-server` | Fixtures skill đạt ≥95% đúng schema; đồng hồ token đúng ±5%; không có nút hành động từ AI | Vector RAG, log-investigate (max) nếu chưa có story đạt |
| **M7 Mid/Enterprise/MSP** | 6 tuần | `reports`, `fleet`, `auth-oidc` + RBAC + 2FA, `agent-intake`, `scan-credentialed`, SIEM forward, PostgreSQL | 1 server + 3 sensor + 2 tenant chạy ổn 7 ngày; OIDC với Keycloak/Entra | — |

Sau M2 đã **dùng được** cho P1/P2 (alert theo khai tay). Sau M3 là sản phẩm SMB đầy đủ. Sau M7 là Mid/Enterprise.

## Nguyên tắc chuyển mốc
- Mỗi mốc kết thúc bằng: completion-log entry, decisions, deferred file dọn sạch, demo ghi hình.
- Không kéo việc mốc sau vào mốc trước "tiện tay". Ponytail.
- Mốc M1 có thể chạy song song với builder (M2) vì builder không có GUI.

## Rủi ro đã biết
| Rủi ro | Giảm thiểu |
|---|---|
| Thiết bị giấu version (Synology, Fortinet, MikroTik v7) → "Anh có?" sai | 3 mức tin cậy, hiển thị "nghi" rõ, Nuclei xác nhận, agent tuỳ chọn |
| Free tier thay đổi | `channels.json` ký, mirror kép |
| FP IOC chặn nhầm | Vedette không chặn; chỉ cảnh báo; whitelist theo domain |
| Prompt injection qua log/web | guardrail §5 `AI_ASSISTANT.md`; AI không hành động |
| Dự án mở bị fork thương mại | chấp nhận (Apache-2.0); lợi thế là triển khai + dữ liệu VN |
| Khó tuyển đủ 10 người phỏng vấn cuối năm | mời 12–14; thiếu P4 thì story P4 sang nhóm D (D-20) |
| Giải thích AI soạn tay trong prototype tốt hơn AI thật → H15 lạc quan | ghi chú khi chấm; xác minh lại ở M6 bằng fixtures skill |
| Người test tin tồn kho giả như thật | nói rõ đầu buổi; nhãn "Dữ liệu mẫu" trên prototype |
| M2 trùng Tết Nguyên đán (6/2/2027) | đệm 1 tuần |
