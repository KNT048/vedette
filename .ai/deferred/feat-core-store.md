# Việc để sau — nhánh feat/core-store (WP-03)

- [ ] Prune retention của `core_audit` (xoá dòng cũ + ghi `core_chain_anchor`, cần bỏ/tạo lại trigger `core_audit_no_update/no_delete` trong cùng giao dịch) → cần scheduler `core/jobs`, WP sau.
