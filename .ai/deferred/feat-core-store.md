# Việc để sau — nhánh feat/core-store (WP-03)

- [x] (#654, D-416: job `core/audit-prune`, anchor dời trước, trigger 0011 thay vì bỏ/tạo lại) Prune retention của `core_audit` (xoá dòng cũ + ghi `core_chain_anchor`, cần bỏ/tạo lại trigger `core_audit_no_update/no_delete` trong cùng giao dịch) → cần scheduler `core/jobs`, WP sau.
