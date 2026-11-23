# Approval tokens: approving actions from email, Slack, Telegram, Zalo

Status: draft (docs-first), 2026-11-09; updated: §7.1 reply-code hashing and test vectors, §14 open questions answered. Field names, messages and paths are in English.
Traceability: design requirements (approver, expiry, one action per approval; approval inside each channel; Slack Socket Mode, Telegram long polling; every action needs approval, 2 people for high risk, high-risk AI actions must be approved in the app with a two-step code; two-step verification; hash log); stories S-RESP-2, S-NOT-2; GUI mock `web/src/features/response` (`ApprovePage.tsx`, `state.ts`, `mocks.ts`) and `web/src/features/notify` (`Approver`, `ChannelInput`).

## 1. Purpose

An action request (`ActionRequest`) of the `response` module runs only when it has enough valid approvers. This spec defines **how the approver confirms** through each channel so that:

- a click by a link scanner in a mailbox does **not** approve in a person's place;
- a forwarded or replayed token does **not** let someone else approve;
- the approver's identity on the channel is mapped to **one Vedette user** with the operator role or higher;
- every decision goes into the hash-chain log.

Out of scope: the content/mechanism of the action (`action-packs.md`), and the algorithm that decides whether approval is needed (the response engine).

## 2. Actors

| Actor | Role |
|---|---|
| Approver | a Vedette user with role `operator`/`admin` who has an address on the channel (`Approver {user_id, address}` in the channel configuration) |
| `core` (modules `response`, `notify`) | creates the request, issues the token, checks it, and executes once enough approvals exist |
| Channel | Email (the customer's SMTP), Slack (Socket Mode), Telegram (bot, long polling), Zalo OA (link), personal Zalo (reply code, unofficial) |
| Link scanner | mailbox/gateway software that automatically `GET`s every URL in a message: treated as an **automatic clicker** |

## 3. General rules (every channel)

1. **One request = one bundle** of actions (one request merges each run). The approver approves/rejects **the whole bundle**; the before/after change (`change`) is always shown in full before a decision is accepted.
2. **Expiry**: a request expires after 15 to 30 minutes (per rule; the default in `response_settings.expiry_min = 15`). **An email/Zalo OA token lives 30 minutes** but **never lives longer than the request**: `token.expires_at = min(now + 30 minutes, request.expires_at)`.
3. **Number of approvers**: 1, or 2 **different** people for high risk. Two approvals by the same user count as one. The person who **created** the rule/manual request is not counted as the second approver of their own request (open question §14).
4. **High risk submitted by the AI** is approved **only in the app with a two-step code**; a chat/email channel for this request receives the message "open Vedette to approve" and has no approve button (matches `in_app_required` in the mock).
5. **Re-check at approval time**: even if the token/button is valid, core checks at the moment of the POST/callback: the approver is still in the channel's list, is still an active user with role ≥ operator, the channel still has "Approve actions from this channel" on, the request is still `pending`, and the `response` module and `execution` are still on. Otherwise → rejected with `403 approver_not_listed` (matches the mock).
6. After approval core sets the status; execution happens once enough people have approved; the **emergency stop and the circuit breaker** can block even a fully approved request, and the token does not decide that.
7. Every step (`request`, `approved`, `rejected`, `expired`, `refused`, `executed`…) is written to the `resp_log` log with `hash = SHA-256(prev_hash "\n" canon(entry without hash))` (one formula for every chain) and to `core_audit` (SYS-3). `actor` records the **channel and identity** (for example `Lan Pham via email lan@…`).

## 4. Email: confirmation link

### 4.1 Token format

The token travels in the **path** of the public confirmation page: `https://<box IP>:8443/approve/<token>`.

```
<token> = "v1." base64url(token_id) "." base64url(mac)
token_id = 16 random bytes (CSPRNG)
mac      = HMAC-SHA256(K_approval, "vedette-approval-v1\n" token_id "\n" request_id "\n" approver_user_id "\n" channel "\n" expires_at_unix)
          cut to the first 16 bytes (128 bits)
```

- `K_approval`: a 256-bit HMAC key reserved for this purpose, generated at install and stored in `core/secrets` (AES-256-GCM, SYS-4), separate from the data-encryption key. There is a rotation mechanism (`key_id` is recorded in the token record; an old token stays valid only until `expires_at`).
- **Why HMAC and not Ed25519:** the signer and the verifier are **the same box**; no third party needs to verify a token, so a symmetric key is enough and simpler (simplest option: HMAC-SHA256; upgrade: Ed25519 if an external service later needs to verify tokens without holding the signing key).
- **HMAC is not the only protection.** The `response_tokens` record (DB) is the source of truth: `{token_id (hashed), request_id, user_id, address, channel, key_id, expires_at, used_at}`. HMAC exists only to reject a forged token quickly **without a DB lookup** and to prevent probing of token_id. Used/expired state comes from the DB, not from the token.
- Token length ~ 3 + 22 + 1 + 22 = ~48 characters, URL-safe ASCII, compared in constant time.

The mock currently uses a random unsigned 32-hex token (`TOKEN_RE = /^[a-f0-9]{32}$/`). **The format above replaces that regex**; changing `TOKEN_RE` in the frontend and the `approve/:token` route is backend-phase work (open question §14).

### 4.2 Binding to an action and a recipient

A token is bound to exactly four things: the **request** (`request_id`), the **approver** (`user_id` + the email address it was sent to), the **channel** (`email`), and the **expiry**. Core checks, when the page is viewed and at the POST, that the record matches those four. A token of A cannot be used to approve request B or to impersonate someone else. Each approver in the list receives a **separate token** (so "who approved" is certain).

### 4.3 Single use

- Only **the decision POST** burns the token: `used_at` is set in the same DB transaction as recording the decision (a conditional update `WHERE used_at IS NULL`). Two concurrent POSTs: one wins, the other gets `409 used`.
- Viewing the page (GET) does **not** burn the token and changes **nothing** (matches the mock: "opening the link never approves").
- Rejecting (`reject`) also burns the token.
- **A decision refused by a gate does not burn the token**: `403 approver_not_listed`, `403 in_app_required`, `409 execution_off`… leave `used_at` as it is; only a decision that was recorded burns it.
- When the request has been decided by another path (someone else approved in Slack, cancelled in the app) the remaining tokens become `decided`, and neither GET nor POST changes anything.

### 4.4 Confirmation page: only POST approves

| Method | Path | Auth | Behaviour |
|---|---|---|---|
| GET | `/api/v1/response/approve/{token}` | token | **read only**; returns `ApprovalView`; does not burn the token and records no decision |
| POST | `/api/v1/response/approve/{token}` | token + body | performs the decision |

The public SPA route `/approve/:token` shows the `ApprovalView` and then two buttons, **Approve** / **Reject**, which send the POST. The design is for link scanners: scanners (Safe Links, Mimecast, etc.) usually `GET` (and may run JS in a sandbox) but do not press buttons and do not send a POST; so **no decision exists on the GET path**, there is no "one click" (`?action=approve`), and no self-approving redirect is used.

`ApprovalView` (the GET response): `{ "state": "ready"|"expired"|"used"|"decided"|"unknown", "title": string|null, "items": [ { "title", "risk": "low"|"medium"|"high", "change": { before, after, cli } } ], "approver": string|null, "expires_at": datetime|null, "status": string|null, "requires_approvals": int|null, "approved_so_far": int|null }`. When `state != "ready"`, `title`/`items`/`approver`/`expires_at` are empty/`null` (no content is revealed for a wrong/expired/used token).

POST body: `{ "decision": "approve" | "reject" }` (no extra fields). `200` response: the updated `ActionRequest`, in which `status` may be `pending` (a second approver is needed), `approved`/`executed`, or `rejected`.

Additional anti-automation measures: the page response carries `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY` (blocks clickjacking of the approve button), and a strict CSP. The POST requires `Content-Type: application/json` (a type that a cross-site form cannot send) and an `X-Requested-With`/Origin header matching the box's host; no session cookie is used (the token is the only credential), so classic CSRF does not apply, but **Origin/Fetch-Metadata must be checked** to prevent another page from forcing the approver's browser to POST.

### 4.5 Replay and forwarding

| Risk | Mitigation | Residual risk |
|---|---|---|
| The message is forwarded, and anyone with the link can approve | the token is bound to the approver but **whoever holds the token can still approve** when there is no second factor; reduced by a 30-minute expiry, single use, one bundle, 2 people for high risk, and no email approval for high-risk AI actions | **Accepted**: email is a weak channel; the GUI says so plainly. A two-step code entry step could be added (open question §14) |
| Replay after use | `used_at` + `409 used` | none |
| Replay after expiry | `expires_at` + `409 expired` | none |
| The message in a compromised mailbox | same as forwarding | the mailbox needs protection |
| Token probing | 128-bit HMAC + 128-bit token_id, rate limit of 20 wrong tries/minute/IP, a uniform `404 unknown` | none |
| A scanner that clicks by itself | GET changes nothing (§4.4) | none |
| Exposure in browser history / Referer | `Referrer-Policy: no-referrer`; the token is short-lived and single-use | low |
| Replying to the message to approve | **not supported**: the box does not read incoming mail (easy to forge) | none |

### 4.6 Message content

The message contains: the request title, the change table (taken from `change`, **plain text**, HTML-escaped, limited to 4 KiB), the risk level, the expiry, and one button/link to `…/approve/<token>`. Content from the agent (controlled by an attacker) is never inserted unescaped. Sent through **the customer's SMTP** (PRIVACY flow 5), with no third party.

## 5. Slack (Socket Mode)

- The box opens an **outbound** WebSocket connection to Slack with `app_token` (`xapp-…`, Socket Mode) and uses `bot_token` (`xoxb-…`) to send messages; **there is no inbound port**. Both tokens are stored encrypted (SYS-4), and the UI shows only the last 4 characters.
- Request message: Block Kit with the title, `change`, risk, expiry; **Approve** / **Reject** buttons. A button carries `action_id` and `value = request_id` (it contains no secret; there is no token).
- **Identity mapping**: a `block_actions` event arrives with `user.id` (the Slack member ID) and `channel.id`. Core looks for an `Approver` in the Slack channel configuration with `address == user.id` → the Vedette `user_id`. Not found, or the user is no longer operator/admin → rejected, with a private (ephemeral) reply "You are not an approver".
- Accepted only from the `channel_id` declared in the configuration (the mock has `channel_id` "approvals only"); a button pressed in another channel is ignored.
- Forgery protection: the Socket Mode connection is authenticated by Slack with `app_token`, so there is no need to check the request signature as with a webhook; it still checks that `request_id` is still `pending` and that `payload.team.id` equals the configured team.
- After the decision (or expiry): update the original message (chat.update) to remove the buttons, keep the text, and add one fixed line stating the result (Approved / Rejected / Expired / Cancelled / ended). The name or email of the person who decided is not written into the Slack channel; Vedette's audit log has it.
- Connection dropped: reconnect with backoff; while it is down, the request stays open in the app and the other channels. If it passes the expiry the request expires normally.

## 6. Telegram (bot, long polling)

- The box calls `getUpdates` (long polling) to Telegram with the bot token (encrypted): an **outbound** connection. No webhook is set (no inbound port).
- Request message: plain text + an `inline_keyboard` with two buttons; `callback_data = "a:<request_id>:<nonce>"` (≤ 64 bytes per the Telegram limit), with `nonce` being 8 random bytes stored with the request so that an unknown callback cannot be guessed.
- **Identity mapping**: `callback_query.from.id` (the Telegram user ID) matches `Approver.address` (kind `Telegram user ID`). In a group, **only** `from.id` decides, not the display name or `chat.id`; only callbacks from the configured `chat_id` are accepted.
- After the decision: `answerCallbackQuery` and edit the message to remove the buttons.

## 7. Zalo

| Kind | Approval mechanism | Notes |
|---|---|---|
| **Zalo OA** (official) | sends a **link** (like email, section 4) | only a message with a link; decisions are not received through chat |
| **Personal Zalo** (unofficial, like the community n8n Zalo node) | **reply code** | the GUI warns: unofficial, the account may be locked, a dedicated account should be used |

Approval by reply code (personal Zalo):

- The box sends a message with its own approval code for **each approver**: `A-<6 characters>` (approve) and `R-<6 characters>` (reject), from an alphabet that avoids confusion (no `0/O/1/I`), generated with a CSPRNG; stored hashed, bound to `request_id`, `user_id`, expiring at the request's expiry (at most 30 minutes), **single use**.
- The approver replies with the exact code. The box (through the channel's personal Zalo session) receives the incoming message and compares it with the code record: only a message **sent from `Approver.address`** (the Zalo user ID) is accepted; a correct code from a different sender → dropped and recorded as `refused`.
- A reply code that is used/expired → the box replies "expired/used".
- Because the channel is unofficial, the reliability of the identity is lower than Slack/Telegram: **not used for high risk by default** (open question §14), and high-risk AI actions are still approved only in the app.
- The personal Zalo session is a secret (scan a QR code once); deleting the channel deletes the session (PRIVACY flow 5).

### 7.1 Reply-code hashing (`notify` creates it, `response` stores and checks it)

- **Alphabet** `23456789ABCDEFGHJKLMNPQRSTUVWXYZ` (32 characters, no `0 1 I O`). A code = the prefix `A-` (approve) or `R-` (reject) + 6 characters, each character taking one CSPRNG byte `& 31` (256 is divisible by 32 so there is no bias): 30 bits. Each approver receives two separate codes per request.
- **Normalisation** (at creation and at receipt): strip ASCII whitespace at both ends, and turn ASCII lowercase letters to uppercase; afterwards it must match `^[AR]-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{6}$`, otherwise the message is not a code and is ignored. `decision` = `approve` with prefix `A`, `reject` with `R`.
- **Formula**: `code_hash = lowercase hex of SHA-256("vedette-reply-code-v1" LF request_id LF user_id LF decision LF code)`; LF is the byte `0x0A`; the fields are UTF-8 bytes exactly as stored; no trailing LF, no other byte.
- **Storage**: `notify` computes `code_hash` and then calls `TokenRecorder.RecordReplyCode(ctx, ReplyCode{RequestID, UserID, Address, Approve, CodeHash, ExpiresAt})` **before** sending the message; `response` writes `resp_tokens` (`kind=code`, `channel=zalo-personal`, `address` = the approver's Zalo ID, `decision`, `expires_at` = the request's expiry, at most 30 minutes). The plain code is not stored or logged anywhere.
- **Check**: the listener calls `Decide(Decision{Channel: zalo-personal, ExternalID: <sender ID>, RequestID: "", Approve, Code})`; `response` takes the unused, unexpired `kind=code` records of **exactly** `(channel, address = ExternalID)`, computes the hash with the `request_id`, `user_id`, `decision` of each record, and compares in constant time. On a match → the gates of INV-3 (`response`) → burn in the decision transaction (`used_at IS NULL`), at the same time burning the person's remaining code for that request. A correct code sent from another account matches no record of that sender: dropped and recorded as `refused`.
- **Why unkeyed SHA-256**: a code only works when sent from the approver's own Zalo ID, lives ≤ 30 minutes, and is single use; the hash is bound to `request_id` + `user_id` so there is no shared lookup table; HMAC would need a key to be shared between `notify` and `response` (simplest option). The 2-step code over email uses HMAC because that code alone (10^6 values) is the proof.
- **Test vectors** (the tests of `notify` and `response` both pin them):
  - `request_id` = `req-20261109-0001`, `user_id` = `u-lan`, `decision` = `approve`, `code` = `A-7KQ2MX`.
  - Input bytes (62 bytes, hex): `766564657474652d7265706c792d636f64652d76310a7265712d32303236313130392d303030310a752d6c616e0a617070726f76650a412d374b51324d58`.
  - `code_hash` = `1f16413d45bce5c596496fc0a4d169a0c09ade7bb044335507f4020e15060fa0`.
  - Received ` a-7kq2mx ` → normalised to `A-7KQ2MX` → the same `code_hash`.
  - Reject code `R-7KQ2MX`, the same `request_id`/`user_id`, `decision` = `reject` → `560dd02a99d9bc0e022a7b7c50a9d6834cc2c8ab8587c50089bda4ce7077b671`.

## 8. Combined identity mapping

| Channel | Identifier on the channel | Mapping key | Verification |
|---|---|---|---|
| Email | the approver's email address | `Approver.address` = the login email | a separate token bound to the recipient |
| Slack | Slack member ID (`U…`) | `address` | Socket Mode `user.id` + `channel_id` |
| Telegram | Telegram user ID (a number) | `address` | `callback_query.from.id` + `chat_id` |
| Zalo OA | Zalo user ID / phone number | `address` | the token in the link |
| Personal Zalo | Zalo user ID | `address` | reply code + the sender's ID |

An `Approver` is a pair `(Vedette user_id, address on the channel)`. The pairing is **made by an admin** in Settings → Alert channels; the box does not infer it from a name. An address belongs to **only one** user on the same channel (a uniqueness constraint), otherwise one chat ID would represent two people. When a user is disabled/demoted, every pending approval by that person is rejected (§3.5) and unused tokens are treated as void.

## 9. Sequence

```mermaid
sequenceDiagram
    participant R as Engine / AI
    participant C as core
    participant M as Approver's mailbox
    participant S as Link scanner
    actor U as Approver (browser)
    R->>C: create ActionRequest (pending, expires at T)
    C->>C: create a separate token for each approver (v1.id.mac)
    C->>M: email: link /approve/<token> (through the customer's SMTP)
    S->>C: GET /approve/<token> (link scan)
    C-->>S: ApprovalView (changes nothing, does not burn the token)
    U->>C: GET /approve/<token>
    C-->>U: page showing the change + Approve/Reject buttons
    U->>C: POST /approve/<token> {decision: approve}
    C->>C: re-check: approver, channel, status; burn the token (conditional)
    alt enough approvers
        C->>C: execute (action-packs), re-check, write the log
    else more people needed
        C-->>U: status pending (waiting for the second person)
    end
```

## 10. Error handling

| HTTP | `code` | When |
|---|---|---|
| 400 | `invalid` | `decision` is not `approve`/`reject` |
| 404 | `unknown` | a token with a wrong format, a wrong HMAC, or no record (a uniform message, with no distinction) |
| 409 | `used` | the token has already been used |
| 409 | `expired` | the token or the request has expired |
| 409 | `decided` | the request has already been decided another way |
| 403 | `approver_not_listed` | the approver is no longer valid on the channel (§3.5) |
| 403 | `in_app_required` | high risk submitted by the AI: approval only in the app with a two-step code |
| 403 | `twofa_required` / `code_required` / `invalid_code` | in the app: the two-step code is missing/wrong |
| 409 | `execution_off`, `emergency_stop` | the module/feature is off or an emergency stop is active |
| 429 | `rate_limited` | the attempt limit was exceeded |

Messages are in English and short; a `409` error returns the `ActionRequest.id` so the page can say it clearly. An error never contains the `change` content for an invalid token.

## 11. Limits

| Item | Limit |
|---|---|
| Email / Zalo OA token expiry | 30 minutes, not beyond the request's expiry |
| Request expiry | 15–30 minutes |
| Approvers per channel | at most 10 (default, not measured) |
| Size of the change content in a message | 4 KiB, cut with "…open Vedette for the full change" appended |
| Zalo code | 6 characters, single use, expiry follows the request |
| POST `approve` | 10 requests/minute/IP; 20 wrong tokens/minute/IP |
| Number of unused tokens for one request | = the number of approvers × the number of link channels |

## 12. Security considerations (mapping to SYS)

| SYS | Applies |
|---|---|
| SYS-1 | Approval only changes status; the action runs through `core/exec`/checked connections; names/values in a message never reach a shell |
| SYS-2 | `decision` follows an enum, the token follows its structure; Slack/Telegram callbacks follow a schema |
| SYS-3 | Every decision writes `core_audit` + the `resp_log` hash chain |
| SYS-4 | `K_approval`, the Slack/Telegram tokens and the Zalo session go through `core/secrets`; tokens/URLs are not logged; the GUI shows only the last 4 characters |
| SYS-5 | When the `response` module or the channel is off → the `/approve/*` routes return `404`, and the bot stops polling/disconnects Socket Mode |
| SYS-6 | The request content contains agent data (untrusted): shown only as plain text, escaped, size-limited |
| SYS-7 | Slack/Telegram/Zalo are the outbound flows already listed in PRIVACY flow 5; the `/approve` page is reachable only from the LAN unless the user opens a port themselves (stated clearly in the GUI) |
| SYS-8 | The AI has **no** tool to approve or to create a token; it only submits requests, and the approver is a human outside the AI |

## 13. Versioning

- Tokens carry a version prefix (`v1.`); a new version (changing the signed data) runs in parallel until the old tokens expire (≤ 30 minutes), so changing the format needs no long transition window.
- API `/api/v1/response/approve/{token}`; adding `ApprovalView` fields is forward compatible.
- Changing a channel rule (Slack action_id, the Zalo code prefix) → record it in the CONTRACT of `response`.

## 14. Open questions (answered, 2026-11-09)

1. ~~Is email too weak for high risk?~~ **Forbidden**: a link is for low/medium risk only; a high-risk request → the message has no approval link, and a POST on an old link → `403 in_app_required`. No two-step code entry step is added on the `/approve` page.
2. ~~A manual creator approving their own request~~ **Per INV-2 of `response`**: high risk needs two different `user_id`s, so the person who started a manual run is at most one of the two; for low/medium risk that person may approve it themselves (one person is enough). No new rule is added.
3. ~~Change `TOKEN_RE` and the frontend route~~ **Done**: `TOKEN_RE` follows the format `v1.<22 base64url>.<22 base64url>` (`web/src/features/response/logic.ts`), and the token in the mock was changed to a signed token (the tag part is random: the mock holds no HMAC key, and the mock's store is the source of truth); the `/approve/:token` route is unchanged.
4. ~~May personal Zalo approve medium risk?~~ **Yes**: low and medium; high → `403 channel_not_allowed`; an `in_app_only` request → `403 in_app_required`.
5. The approval link is reachable only inside the LAN: **unchanged** (Vedette provides no tunnel; customers use their own VPN/reverse proxy). Nothing to do yet.
6. ~~Default request expiry~~ **15 minutes** (`resp_settings.expiry_min` defaults to 15, range 15–30, INV-6 of `response`); a token lives `min(30 minutes, the request's expiry)`.
7. ~~The limit levels~~ **POST `approve`: 10 times/minute/IP and 20 wrong tokens/minute/IP** (429 `rate_limited`, as in §11). Approvers per channel: `notify` applies no cap; none is added until there is a story (simplest option), and the "at most 10" in §11 is only an old suggestion.
8. (added) Preventing another page from forcing the browser to POST: the handler rejects `Sec-Fetch-Site` other than `same-origin`/`none` (403), plus `Content-Type: application/json` as in §4.4.
