# Deferred — fix/wp31-approver-identity (WP-31 R3, L7, D-191)

- [ ] NEEDS-MLEE (notify, Emily): optional port `notify.Config.ApproverLinks{Linked(ctx, userID, ch, address) (bool, error)}`; `approverProblem` skips an unlinked approver ("the approver has not linked this address in My account"). Until then notify still mails the request (title + summary, dead link) to an unlinked email approver. D-191 (6).
- [ ] Optional, notify: Telegram `/start <code>` deep link as a nicer first link (D-191 Không chọn (b)).
