# Việc để sau — nhánh feat/auth-stepup (WP-13b-3)

- [ ] **13b-9: `notify` cài `SendStepUpCode(ctx, to, code, summary string) error`** (`core/auth.StepUpMailer`): tiêu đề "Approve a Vedette action", hiện `summary`, ghi "if you did not ask to approve this, someone may have your session — sign out everywhere", không có liên kết /login. Đến khi có, email duyệt trả 503 `twofa_email_unavailable` (lý do `mailer`). Emily hoặc lead, theo D-65.
