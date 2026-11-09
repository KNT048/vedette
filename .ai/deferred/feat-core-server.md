# Việc để sau — nhánh feat/core-server (WP-04a)

- [ ] `core_module.version` chỉ ghi lúc chèn hàng (`Config.Version`), chưa cập nhật khi module được migrate lên bản mới → làm cùng cơ chế migrate theo module (WP-04b/WP-08).
- [ ] `Authenticator` thật (phiên, CSRF, `Origin`/`Referer`, 429 giới hạn tần suất HTTP của API_CONVENTIONS §8) → WP-04b; hiện `cmd/vedette` dùng `noSessions` (mọi route cần phiên trả 401).
- [ ] TLS và SPA nhúng (`-listen` mặc định `127.0.0.1:8080` HTTP thường) → WP-04b/WP-08.
- [ ] Mã lỗi mới `csrf_invalid`, `not_implemented`, `internal` và `too_large` → 413 (§3.3 ghi 400/413) chưa có trong `docs/API_CONVENTIONS.md` §3.3 → PR của chủ hợp đồng.
- [ ] `docs/DATA_MODEL.md` §3/§5.6: thêm bảng `core_job_run`, cột `core_module.disabled_at`/`version` đã có, ghi `enabled_at` = NULL khi tắt → PR của chủ hợp đồng.
- [ ] `modules/core/CONTRACT.md`: PRE/POST-1 nhắc `Init`+`Routes`+`Jobs`; thực tế là cổng module ở `core/server` + `jobs.ModuleChanged` (interface `module.Module` chưa có) → cập nhật khi viết `module.Module`.
- [ ] Cổng module của `findings`: `Enabled("findings")` = false tới khi WP-21 thêm `modules/findings/MANIFEST.yaml` (`/findings/*` trả 404 trong lúc đó).
- [ ] Mỗi module còn lại chưa có `Migrations`; `cmd/vedette` chỉ migrate core → thêm vào vòng lặp khi module có migration.
