# Hợp đồng module

Trước khi sửa `modules/<tên>/`: đọc `CONTRACT.md` và `IMPACT.md`. Sau khi sửa: mọi INV/POST còn đúng, `go test ./modules/<tên>/... -run Contract` xanh; cập nhật CONTRACT/IMPACT khi đổi hàm public, bất biến, phụ thuộc. Bất biến hệ thống SYS-1…8 trong `docs/MODULE_CONTRACTS.md` áp dụng mọi nơi.
