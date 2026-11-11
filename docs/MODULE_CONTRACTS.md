# Hợp đồng module

Dự án AI-code 100%; AI không có trí nhớ giữa session. Hợp đồng đặt **phát biểu kiểm thử được** ở biên mỗi module để session sau đọc trước khi sửa.

## Vị trí
```
modules/<tên>/CONTRACT.md     INV-* / PRE-* / POST-* / FORBID-* + DEPENDS ON / DEPENDED ON BY
modules/<tên>/IMPACT.md       mỗi hàm public: ai gọi (file:dòng), hậu quả khi đổi; tắt module này ảnh hưởng ai
modules/<tên>/*_contract_test.go   mỗi INV/POST một test
```

## Quy tắc
1. Trước khi sửa module: đọc CONTRACT + IMPACT. Sau khi sửa: mọi INV/POST còn đúng; `go test ./modules/<tên>/... -run Contract`.
2. Cố ý phá hợp đồng → sửa **cả** CONTRACT và test, nói rõ trong commit. Không phá ngầm.
3. Phát biểu phải đo được. Sai: "an toàn". Đúng: "`sensor-active` không bao giờ quét IP ngoài `inv_scope` đã duyệt (INV-3)".
4. Module mới: CONTRACT + IMPACT + MANIFEST trước khi merge.

## Bất biến hệ thống (SYS-*, mọi module)
- SYS-1: Tiến trình ngoài chỉ qua `core/exec` với allowlist binary + argv; không gọi shell bằng chuỗi lệnh.
- SYS-2: Input ở biên validate theo schema trước service.
- SYS-3: Mọi mutation ghi `core_audit`.
- SYS-4: Secret chỉ qua `core/secrets` (AES-GCM), không log, không export.
- SYS-5: Module tắt: không route, không job, không cổng; dữ liệu giữ, trừ việc xoá dữ liệu quá thời hạn lưu khách đã đặt hoặc sản phẩm đã công bố (CONTRACT và GUI), hoặc vượt trần lưu trữ đã ghi trong tài liệu, kèm dòng audit của việc xoá đó (job `Housekeeping` của `core/jobs`, D-160, D-201, D-202).
- SYS-6: Dữ liệu từ feed/log/web/agent là không tin cậy: parser fail-closed, giới hạn kích thước.
- SYS-7: Mọi hành động mạng ra ngoài LAN (scan, fetch) phải nằm trong scope đã xác thực sở hữu hoặc nguồn feed khai báo.
- SYS-8: AI không có tool ghi.

Mẫu: `modules/_template/`.
