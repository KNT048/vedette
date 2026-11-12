# fix/g13-mlee — việc để sau

- [x] Moved → #380 (post-v1): 2026-11-12 — Connections (Settings → AI → Connections): đổi Sign-in type xoá bí mật đã gõ (mac-walk3 G13 mục 4, phần Connections) — vì sao để sau: vùng của Kiên (connections), ngoài phạm vi G13 — ở đâu: web/src/features/ai/harness (Connections) / module connections
- [ ] 2026-11-12 — Webhook/SMTP của notify chưa chặn các địa chỉ metadata đám mây không thuộc link-local (100.100.100.200, 192.0.0.192, fd00:ec2::254) mà feeds/logs/ai đã chặn — vì sao để sau: G13 chỉ sửa câu báo; các host này không phục vụ https và http tới chúng đã bị `insecure_url`, nên chỉ còn https — ở đâu: modules/notify/channel/webhook.go forbiddenAddr (dùng chung với smtp.go), mocks.ts/types.ts forbiddenHost
