# Việc để sau — nhánh feat/core-store (WP-03)

- [ ] Prune retention của `core_audit` (xoá dòng cũ + ghi `core_chain_anchor`, cần bỏ/tạo lại trigger `core_audit_no_update/no_delete` trong cùng giao dịch) → cần scheduler `core/jobs`, WP sau.
- [ ] Xoay khoá `core_secret` (`key_version` > 1, mã hoá lại từng hàng, `rotated_at`) → khi có lệnh `vedette-host`/CLI xoay khoá; hiện chỉ `key_version=1`.
- [ ] `LoadKeyFile` chưa kiểm chủ sở hữu file (uid) và đường dẫn nằm ngoài volume DB (DATA_MODEL câu hỏi mở 6) → khi installer quyết đường dẫn khoá.
- [ ] Test "đồng dạng lược đồ" SQLite/Postgres (DATA_MODEL §6 rule 4) và thư mục `migrations/postgres` → khi làm backend Postgres.
- [ ] Sửa `docs/DATA_MODEL.md` §5.3 theo D-57 (14) (một công thức, `prev_hash` trong entry, `\n`, thứ tự khoá theo code point, NULL = `null`, bỏ `HashPositional`/dạng vị trí của resp_log) → PR riêng của chủ hợp đồng; mock TS `web/src/features/*` cũng phải khớp.
- [ ] Ràng buộc trigger/migration của module khác (`ai_activity`, `resp_log`) cần cùng bộ `BEFORE INSERT/UPDATE/DELETE` như `core_audit` → khi viết migration của module ai/response.
- [ ] exec: tiến trình con gọi `setsid` thoát khỏi nhóm bị kill → cgroup / systemd transient scope do `vedette-host` quản lý (ponytail trong `core/exec/isolate_unix.go`).
- [ ] Trình bao `core/exec` chưa hỗ trợ không-Unix (`ErrUnsupportedOS`) → chỉ cần nếu có bản Windows của core (hiện chỉ Linux/macOS).
