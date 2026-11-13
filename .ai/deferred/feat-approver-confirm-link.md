# Deferred: feat/approver-confirm-link (D-414)

- [ ] Try the Telegram confirm link on a real bot (N100 walk): private message to an approver who pressed Start, fallback into the approval chat for one who did not; open the link on a phone, sign in with 2FA, Confirm; then press Approve. (Agents do not touch the box; supervisor walk.)
- [ ] Opus review LOW 5: each other_account refusal of a confirm link writes an audit row; an operator posting well-formed tokens in a loop can grow core_audit. Rate-limit the row (one per user per minute) in response.ConfirmLink.
- [ ] Opus review LOW 6: a Send again refused by response (resend_too_soon from a concurrent press) overwrites the approver state "waiting" with an error though the earlier link still works (Telegram and Zalo). Keep the previous record on a 429 refusal.
