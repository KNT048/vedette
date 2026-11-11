# Deferred — feat/auth-oidc (WP-27 auth-oidc, session wp27-oidc)

- [ ] PR 2: backend `modules/authoidc` + `core/auth` khớp hợp đồng GUI (D-194..D-196), IdP giả trong test cho mọi đường từ chối. Hiện `/auth/oidc/*` và `/core/oidc*` trả 501 trên backend thật.
- [ ] Sau PR 2: dòng `'/settings/users': GET /api/v1/core/oidc` trong `web/e2e-real/gaps.spec.ts` hết đúng; thuộc wp30 (không sửa ở nhánh này) — báo session WP-30 khi PR 2 merge.
