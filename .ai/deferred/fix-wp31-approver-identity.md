# Deferred — fix/wp31-approver-identity (WP-31 R3, L7, D-191)

- [x] Done (#234 + this PR: cmd/vedette notifyApproverLinks): optional port `notify.Config.ApproverLinks{Linked(ctx, userID, ch, address) (bool, error)}`; `approverProblem` skips an unlinked approver ("the approver has not linked this address in My account"). Until then notify still mails the request (title + summary, dead link) to an unlinked email approver. D-191 (6).
- [ ] Optional, notify: Telegram `/start <code>` deep link as a nicer first link (D-191 Không chọn (b)).
- [ ] notify (Emily), with the Slack (lát 3) and Zalo personal (lát 4) listeners: answer `DecisionResult.Message` only to the presser (Slack ephemeral / Zalo 1:1). Then Kiên side adds the channel to `response.privateAnswer` so its approvers can link (D-191, CONTRACT INV-24).
