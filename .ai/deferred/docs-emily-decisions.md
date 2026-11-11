# Deferred: docs/emily-decisions

- [ ] 2026-11-11 — WP-08 (owner: AI-Trưởng, công cụ phát hành): công cụ dựng manifest từ chối `rollback.safe=true` khi có migration DB của core từ bản phát hành trước mà không chỉ-thêm (hoặc `db_schema` đổi không theo kiểu thêm) — vì sao để sau: công cụ phát hành chưa có; D-183 chuyển việc bảo vệ quay lui sang bản phát hành — ở đâu: `internal/release/manifest.go` (D-138, D-183)
