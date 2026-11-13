# features/findings

Module `mitigation`. Story: S-MIT-1 (Làm gì: bản vá, vá tạm, cấu hình firewall FortiGate/MikroTik/chung, danh sách kiểm tra, "Đã áp dụng"), S-MIT-3 ("Tôi đã bị chưa?"), S-SCAN-3 (bằng chứng + cách tự kiểm tra lại), S-AI-2 ("Giải thích" và "Hỏi AI của tôi" trong `AiBlock origin="customer"`), D-21.

- Phát hiện nằm ở `findingsStore` dùng chung (seed: `src/mocks/seed/findings.ts`). Gói đã xác nhận và dấu hiệu khai thác là nội dung ký của dự án (packs.ts, không lưu); bảng riêng: `mit_ai_outputs`.
- Gói Vedette đã xác nhận (D-21: soạn với AI, người duy trì xác nhận qua PR GitHub) chỉ có cho CVE-2022-27593; mọi CVE khác hiện "Chưa có khuyến nghị đã xác nhận" + thông tin gốc KEV + "Hỏi AI của tôi". Nội dung gói là dữ liệu máy chủ (tiếng Anh, D-28); `{IP}`/`{HOST}` thay bằng thiết bị thật.
- Slot cung cấp: `device.panels` (props `{ assetId }`). Slot tiêu thụ: không.
- D-484 (lượt đi khách 1): tên thiết bị từ `asset.name` (không bao giờ id), "No IP address" và không "Rescan" khi không có IP; xếp theo độ chắc chắn rồi mức nghiêm trọng (`basis.ts` `riskRank`), `RiskChip` làm mờ mức nghiêm trọng của phát hiện chỉ khớp sản phẩm; chọn nhiều + `POST /findings/status` (tối đa 500); lọc `?device=`, `?product=`.
- Đường dẫn: `/findings`, `/findings/:id`; liên kết ra `/scans?target=<assetId>`, `/devices/:id`, `/cve/:id`, `/settings/ai`.
