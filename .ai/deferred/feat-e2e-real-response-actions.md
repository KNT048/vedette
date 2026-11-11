# Deferred — feat/e2e-real-response-actions (WP-30 slice 9a)
- Issue #302: GET /response/settings answers 500 after an emergency stop (unknown field stopped_at). `response-exec.global.spec.ts` keeps a `test.fail`; remove it when fixed.
- Issue #308: GET /response/log serves ts without milliseconds, so the served chain cannot be re-verified and the Log tab cannot show "Chain verified". `test.fail` in the same file; remove when fixed.
- Not covered in 9a (kept for 9b or later): pre-approved rules, 2 approvers (INV-2), the TTL sweep undo, SSH and MCP device actions on the real box, `msg_send`/`webhook_call` box actions, AI-proposed requests (S-RESP-1/2, Emily's `ai`).
- Dry-run log entry kind `failed` is not written when a check before refuses (the item fails, the log has no "failed" line): look at whether INV-19 wants one.
