# API conventions

The conventions below (naming, errors, pagination, concurrency, authentication, rate limits, events, files) are the rules every
endpoint follows. The source of truth for each operation is its Zod contract in `web/src/features/*/contract.ts`, from which
`api/openapi.json` is generated (393 operations, 14 tags on 2026-11-24) and the Go handlers are generated in turn; the system
invariants are in `docs/MODULE_CONTRACTS.md` (SYS-1…8). The tables of error codes and minimum roles were measured from the code on
2026-11-09 and may lag behind it: when a table and a contract differ, the contract wins. A choice that is a proposal is marked
**[PROPOSED]**; gaps are listed in section 13 ("Open questions"). For data types and DB tables see `docs/DATA_MODEL.md`.
Endpoint names, error codes and field names are kept exactly as they appear in the contracts.

## 1. Resources: naming, methods, status codes

**Root:** `/api/v1` (`servers: [{url: '/api/v1'}]`). Body is `application/json; charset=utf-8`, except file downloads (section 11).

| Rule | Details (measured from `openapi.json`) |
|---|---|
| Grouping by module | The first path segment is the module's group: `/ai`, `/core`, `/exposure`, `/feeds`, `/findings`, `/honeypot`, `/inventory`, `/logs`, `/notify`, `/reports`, `/response`, `/scans`. Deliberate exceptions, all owned by `core` or `inventory`: `/auth/*`, `/me`, `/modules`, `/setup`, `/scanning` (Settings › Scanning, answers when every scanner module is off), `/detection` (intrusion-detection overview, answers when every detection module is off; `/detection/alerts` goes to the `ids` module when it is present) (core); `/install/*`, `/intake/*` (inventory: install files and agent data intake). `/findings` belongs to the `mitigation` module (README `features/findings`); `/scans` (plural) belongs to the `scan` module. |
| Operations per group | core 57 · ai 52 · response 39 · inventory 29 · honeypot 14 · feeds 13 · scan 13 · notify 12 · exposure 11 · reports 11 · logs 10 · findings 5 (GET 103, POST 97, PUT 33, DELETE 22, PATCH 12). |
| Nouns, kebab-case | Paths are plural nouns for collections (`/core/users`, `/inventory/devices`, `/honeypot/trap-ips`), singular for single-instance configuration objects (`/core/general`, `/core/privacy`, `/scans/config`, `/logs/siem`). Path segments are kebab-case (`box-ip`, `chat-decision`, `sample-data`, `auth-options`). Path parameter is `{id}`, except for natural keys: `{type}` (channel), `{service}` (trap), `{date}`, `{token}`. |
| Field and parameter names | JSON and query: `snake_case`. The identifier **of a kind of thing** (module id, channel, AI job, type): kebab-case (`explain-finding`, `zalo-personal`, `sensor-passive`, `netconf-restconf`). **Status / status enums**: snake_case (`false_positive`, `auto_stopped`, `blocked_by_hook`). |
| Action = POST to a sub-resource | `POST /{resource}/{id}/{verb}`: `verify`, `scan`, `stop`, `approve`, `reject`, `rollback`, `test`, `resend`, `commitment`, `status`, `applied`, `suspicious`, `reset-password`, `2fa/reset`. Actions on a whole collection: `POST /scans/runs`, `/response/rules/run`, `/response/rules/simulate`, `/feeds/parse-test`, `/ai/hooks/test`, `/ai/profiles/test`, `/ai/profiles/models`. No verbs in GET/PUT/DELETE paths. |
| GET | Read, no side effects (including `GET /response/approve/{token}`: it only shows the state). File downloads are also GET (section 11). |
| POST | Create (returns 201), or an action with side effects (returns 200/202/204). |
| PUT | **Replaces the whole object** (configuration, profile, rule, channel). Returns 200 + the saved object. A blank secret = keep the stored secret (SYS-4). |
| PATCH | **Partial update** (`/modules/{id}`, `/core/users/{id}`, `/core/account`, `/core/updates`, `/inventory/devices/{id}`, `/honeypot/*`, `/notify/incidents/{id}`). |
| Existing PUT-as-PATCH exceptions | `PUT /feeds/sources/{id}`, `PUT /ai/memory/{id}`, `PUT /scans/config`, `PUT /ai/knowledge/{id}` accept a body whose fields are all optional. Kept as is (already part of the contract); **new endpoints** follow the rule PUT = complete, PATCH = partial. |
| DELETE | Delete. 204 with no body; exception with a body: `DELETE /ai/profiles/{id}` returns `{cleared_jobs}` (200) because deleting a profile empties the job assignments. |

### Status codes (measured in the mock)

| Code | Used for | Notes |
|---|---|---|
| 200 | Read, update, an action that returns the new resource | Most `POST …/approve\|reject\|status\|verify` return the updated resource |
| 201 | Create (16 places in the mock) | Declared with `status: 201` in `contract.ts` and present in `openapi.json` (the `contract.test.ts` test checks the mock against it). Two endpoints return 201 or 200 depending on the case (`POST /exposure/box-ip/verify`, `POST /response/ai/proposals`); they keep the default 200 and say so in `summary`. With a `Location` header **[PROPOSED]** |
| 202 | Long job running in the background (`POST /core/updates/os/install`, declares `status: 202`) | Body = a "run" resource (`id`, `status`); follow it with `GET …/run` or SSE (section 11) |
| 204 | Delete, an action with no result | No body |
| 400 | Invalid input at the boundary (SYS-2) | Almost all validation errors (237 codes, section 3). `invalid_credentials` on a wrong login is also 400, **not** 401 |
| 401 | Not signed in / session expired (`unauthenticated`), or a two-step code is needed (`twofa_required` on `POST /auth/login`, with `method`) | |
| 403 | Valid session but not enough permission, or forbidden by state (`forbidden`, `disabled`, `tool_not_allowed`, `token_expired`, `approver_not_listed`…) | |
| 404 | No such object (`not_found`, 51 endpoints) or a bad link (`unknown`) | For public tokens, "does not exist" and "not allowed to view" are not distinguished |
| 409 | The current state does not allow it (64 codes: `already_*`, `busy`, `expired`, `not_pending`, `ip_in_use`…) | The operation may succeed after the user fixes the state |
| 413 | File/body too large (`too_large` on `POST /feeds/parse-test`) | The mock still returns 400 `too_large` on 3 file-upload endpoints: unify on 413 **[PROPOSED]** |
| 422 | An external service rejects information that is well-formed (`wazuh_auth`, `wazuh_forbidden`) | Currently exactly 1 place; used for "well-formed but the other side refuses" |
| 429 | Rate limit / cap (`rate_limited`, `resend_too_soon`, `too_many_codes`, `budget_reached`) | With `Retry-After` (section 8) |
| 504 | An external system did not answer in time (`ai_timeout`) | |
| 502 / 503 | An external system is unreachable / a required channel is broken (`unreachable`, `address_refused`, `device_error`, `pin_mismatch`, `discovery_failed`, `wazuh_unreachable`, `wazuh_tls`, `wazuh_bad_reply`, `twofa_email_unavailable`, `server_busy`) | `server_busy` comes with `Retry-After` (section 8) |

**Invariants:** (1) every mutation writes `core_audit` (SYS-3); (2) the response body of PUT/PATCH/POST-actions is the **resource after the change**, so the client does not have to call GET again (existing exceptions: `PATCH /core/account` and a few POSTs return `{ok:true}`; kept as is); (3) `GET` never writes, except `last_fetch` of the blocklist (section 11.3) and the data-export GETs (`…/export*`), which write one `core_audit` row containing no data.

### Lists wrapped in a body

A list returns an object, not a bare array (so `total` and `next_cursor` can be added later without breaking). The wrapping key **currently differs** and is part of each endpoint's contract: `items` (most), `channels` (`/notify/channels`), `incidents`, `sensors`, `modules`, `events` (`/logs/events`), `sources` (`/logs/sources`, also `box`), `sends`. **New endpoints use `items`.** The key of an old endpoint is not changed (that would break the contract).

## 2. Data formats, time, IDs

| Type | Rule |
|---|---|
| Timestamp | ISO-8601 UTC with a trailing `Z` (`2026-11-09T04:12:30.123Z`), matching `z.iso.datetime()`. The server **rejects** a timestamp with an offset (`+07:00`) in the body and in the query (`bad_from`, `bad_to`). Responses always have 3 millisecond digits. |
| Date | `YYYY-MM-DD` (`date_added`, snapshot `{date}`). |
| Time of day | `HH:MM` 24-hour (`/^([01]\d|2[0-3]):[0-5]\d$/`), interpreted in `core_org.timezone` (IANA, default `Asia/Ho_Chi_Minh`). A window that crosses midnight is valid (`from=23:00`, `to=05:00`); `from == to` is rejected (`empty_window`, `bad_quiet`). |
| Duration | An integer, with the unit in the field name: `*_min`, `*_hours`, `*_days`, `*_ms`, `resend_after` (seconds). Strings such as `"15m"` are not used. |
| Confidence | A real number 0–1 (`confidence`, `score`). |
| ID | String `^[\w.-]{1,96}$`, issued by the server, **with no structure to infer** (clients treat it as opaque). |
| IP, CIDR | IPv4 dotted decimal; a network range **must have a prefix length** (`no_prefix`, `host_bits`). Checked with `netip` at the boundary (SYS-2). IPv6 is not in the contract yet. |
| Secret strings | Never in a response: only `*_last4`. Sent up in the `secret`/`api_key`/`password`/`private_key` field; blank = keep unchanged. |
| User strings | Trimmed at both ends; the length limit is written in `contract.ts`; control characters are rejected. Data from a feed/log/agent is never interpolated into a command (SYS-1, SYS-6). |
| Names in configuration | `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$` when the name is used as an identifier (SYS-2); display names for people (profile, rule) allow accented letters and spaces within each field's limit. |

## 3. Errors

### 3.1 Format

```json
{ "error": { "code": "ip_in_use", "message": "IP 192.168.10.21 belongs to device NAS-PHOTOS in the inventory. Pick an unused address." } }
```

- `code`: `snake_case`, stable, **for machines** (the client branches on `code`, not on `message`). `message`: English, says **what went wrong and how to fix it**, safe to show verbatim to the user; contains no secrets and leaks no internal information (paths, SQL, stack).
- **Extension fields** sit next to `code`/`message` inside `error` (the client reads them into `ApiError.details`): `missing: string[]` (`missing_dependencies`, modules that must be enabled first); `method: 'app'|'email'`, `sent_to`, `resend_after` (`twofa_required`); `retry_after: number` (seconds; `resend_too_soon`). **Only add, never remove.** `preview_code` in the mock's `twofa_required` is **mock-only**: the backend never returns a code in an error.
- Proposed extension field for validation errors: `field: string` (name of the offending field) **[PROPOSED]**; added gradually, not mandatory. An error produced by the auto-generated schema validator (`400 invalid`) always carries `field` as the full path (`active.days[0]`); a request body of the wrong type or with an unknown key (`400 invalid`) also carries `field` (without the array element index, because the generated decoder does not report it; an invalid unknown key must not be echoed back).
- Errors are created through a single function (`fail(status, code, message)` in the mock, the equivalent in Go); handlers do not build error JSON themselves.
- The OpenAPI contract declares `default` → `Error` for every operation (`components.schemas.Error`); it does **not yet** declare each error code per operation (section 13, open question 2).

### 3.2 Rules for creating a new code

1. Look in section 3.3 first; reuse a code with the same meaning.
2. A new code is `snake_case` and names the **condition**, not the fix; for a new field validation error prefer `invalid_<field>` (with `field`).
3. Choose the HTTP status from the table in section 1 (validation → 400; state → 409; permission → 403; absent → 404).
4. Add it to table 3.3 in the **same commit**; the contract test (section 12.1) compares the codes returned against this table.
5. One code may appear on several endpoints with the **same** HTTP status and the same meaning; two different meanings need two codes.

### 3.3 Catalogue of every error code in use

Extracted **statically** from every call of `fail(`/`refuse(`/the `bad(` function/`{status, code}` in `web/src/features/*/mocks.ts`, `*/state.ts`, `*/osMock.ts`, `*/sourcesMock.ts`, `*/harness-mocks.ts`, `*/emailCode.ts`, `*/logExport.ts`, `*/activity.ts` and `web/src/mocks/*.ts` (2026-11-09): **293 codes** (from the mock), plus 5 codes added only by the backend for setup (`invalid_setup_code`, `sample_unavailable`, `invalid_from`, `invalid_to`, `misdirected_request`) and 14 codes added only by the backend for the host service (errors of `vedette-host` and of core writing the snapshot: `not_appliance`, `host_unreachable`, `host_error`, `no_check_yet`, `dpkg_locked`, `dpkg_inconsistent`, `low_disk`, `rebooting`, `reboot_limit_reached`, `snapshot_rejected`, `snapshot_failed`, `apt_failed`, `health_check_failed`, `effect_not_verified`; the table mapping host codes to API codes is in `modules/core/CONTRACT.md` INV-18) and 1 code added only by the backend for the AI proposal gate (`ai_paused`: the pause gate of AI proposals; the mock has it from `response/ai.ts`, a file outside the extraction list): 313. Box network screen (S-CORE-8, 2026-11-10): `networkMock.ts` is not in the static extraction list above, so its 21 codes were not yet in the table and are added here (`management_count`, `management_fixed`, `span_count`, `span_on_management`, `change_pending`, `confirm_required`, `nothing_pending`, `address_conflict`, `net_backend_unsupported`, `invalid_roles`, `invalid_static`, `dhcp_no_static`, `gateway_outside_subnet`, `gateway_not_host`, `invalid_span`, `no_interface`, `nothing_selected`, `bad_filter`, `bad_limit`, `default_no_servers`, `bad_ntp`), together with 11 codes added only by the backend in the `core` part of that screen (`span_has_address`, `span_not_physical`, `connectivity_check_failed`, `reverted_by_reboot`, `management_not_set`, `revert_failed`, `netplan_apply_failed`, `ntp_not_applied`, `arp_probe_failed`, `pending_invalid`, `confirm_failed`; the table mapping host codes to API codes is in `modules/core/CONTRACT.md` INV-21 and INV-25): 345; plus 2 codes added per issue #115 (`ip_not_current` 409 of `exposure` INV-13 / `POST /scans/runs`, `scanner_unavailable` 503 of `scan`): 347; plus `provider_error` 502 of `ai`: 348; plus 4 codes of the AI job call (`blocked_by_hook`, `ai_cut_off`, `ai_bad_format`, `ai_timeout`): **352**. The "Endpoint" column is the nearest handler that contains the call; for codes produced by a shared validation function it reads `module <name> (shared validator)` (a limitation of static extraction) (open question 2 in section 13 proposes declaring `errors` in `contract.ts` so that this table is generated automatically). Messages are the English templates in the mock.

Codes built by a validation function with its own table (`response/state.ts` `checkCatalog`: `invalid`, `read_only`; `feeds/parsers.ts`: `too_large`, `bad_config`, `bad_sample`) were added by hand.

#### HTTP 400 (259 codes)

| Code | HTTP | Sample message (EN, from the mock) | Endpoint |
|---|---|---|---|
| `allow_required` | 400 | Add at least one entry to the allow-list. Only hosts, addresses or commands on this list. | `POST /core/connections`; `PUT /core/connections/{id}` |
| `approvals_unsupported` | 400 | This channel cannot take approvals. It sends a link that opens Vedette instead. | module notify (shared validator) |
| `approvers_required` | 400 | Add at least one approver, or turn off "Approve actions from this channel". | module notify (shared validator) |
| `bad_active` | 400 | Active scan settings are missing. | `PUT /inventory/settings` |
| `bad_answer` | 400 | answer must be have or not_relevant. | `POST /feeds/weekly/{id}` |
| `bad_app_id` | 400 | App ID is the number of your Zalo app, shown in Zalo Developers next to the app name. | module notify (Zalo OA) |
| `bad_app_token` | 400 | The app-level token starts with xapp- and needs the connections:write scope. Copy it again from Basic Information. | module notify (shared validator) |
| `bad_approver_address` | 400 | The approver address is not valid for this channel. | module notify (shared validator) |
| `bad_body` | 400 | enabled must be true or false. | `PATCH /honeypot/trap-ips/{id}`; `PUT /exposure/greenbone` (mock) |
| `bad_bot_token` | 400 | The bot token starts with xoxb-. Copy it from OAuth & Permissions after installing the app. | module notify (shared validator) |
| `bad_channel_id` | 400 | A Slack channel ID looks like C04ABCDEF12. Open the channel details in Slack and copy the ID at the bottom. | module notify (shared validator) |
| `bad_chat_id` | 400 | Chat ID is a number (groups look like -1001234567890) or a public @channel_name. Send the bot a message, then open getUp | module notify (shared validator) |
| `bad_cidr` | 400 | "${r.slice(0, 30)}" is not a valid network range. Enter something like 192.168.10.0/24. | `PUT /inventory/settings` |
| `bad_client_cert` | 400 | Only a TLS source can have a client certificate, given as its SHA-256 fingerprint: 64 hexadecimal characters. | module logs (shared validator) |
| `bad_client_id` | 400 | The client ID is the Application (client) ID of the app registration, for example 0a1b2c3d-4e5f-6789-abcd-ef0123456789. | `PUT /notify/channels/email` (Microsoft 365) |
| `bad_config` | 400 | Parser configuration is not valid (for example, JSONPath must start with $). | `POST /feeds/parse-test` |
| `bad_cursor` | 400 | That search position is not valid. Search again from the start. | `GET /logs/events` (module logs): `cursor` not in the form of a `next_cursor`, or sent without `q`; GUI searches again from the start |
| `bad_address` | 400 | Give one IPv4 address or MAC address of this device. | `POST /inventory/devices/{id}/split` |
| `bad_choice` | 400 | Pick the name of one of the devices being merged. (the field's words: name, type, operating system) | `POST /inventory/devices/{id}/merge` (`fields`) |
| `bad_days` | 400 | Scan days must be Monday to Sunday. | `PUT /inventory/settings`; `PUT /logs/retention` |
| `bad_events` | 400 | Choose at least one event type to forward. | module logs (shared validator) |
| `bad_exclusion` | 400 | Exclusion "${x.slice(0, 30)}" is not valid. Enter an IP (192.168.10.10) or a valid range (192.168.10.0/28). | `PUT /inventory/settings` |
| `bad_expiry` | 400 | Choose how long the token works: 1 to 365 days, or 0 for no expiry. | `POST /inventory/agents/tokens` |
| `bad_ext` | 400 | Choose the file type: .docx or .xlsx. | `POST /honeypot/tokens` |
| `bad_flag` | 400 | suspicious must be true or false. | `POST /inventory/devices/{id}/suspicious`; `PUT /inventory/notify-new` |
| `bad_format` | 400 | Choose a format: syslog, CEF or JSON webhook. | module logs (shared validator) |
| `bad_fragile` | 400 | fragile must be true or false. | `PATCH /inventory/devices/{id}` |
| `bad_from` | 400 | The sender email is not valid, for example alerts@company.com. | module notify (shared validator); `GET /findings/handled` (`from` not a UTC time) |
| `bad_header` | 400 | The first row must be column headers with at least a name or product column. Download the template to see the format. | `POST /inventory/import` |
| `bad_host` | 400 | The SIEM server must be an IP address or a domain name, for example 192.168.10.50 or siem.company.com. | module logs, notify (shared validator) |
| `bad_interface` | 400 | Network interface must be one of: ${s.interfaces.join(', ')}. Backend [PROPOSED]: also the host's `iface_unknown`. | `PATCH /inventory/sensors/{id}`; `PUT /core/network/span` |
| `bad_interval` | 400 | Choose how often to sync: every 5, 15, 60, 360 or 1440 minutes. | module inventory (shared validator) |
| `bad_ip` | 400 | Enter an address for the Trap IP, for example 192.168.10.240. Pick an address no device uses. | `POST /honeypot/trap-ips`; `PUT /honeypot/trap-ips/{id}` |
| `bad_item` | 400 | Invalid item to apply. | `POST /findings/{id}/applied` |
| `bad_key` | 400 | The SSH private key is not valid. | `POST /scans/credentialed` |
| `bad_kind` | 400 | Device type must be one of: ${KINDS.join(', ')}. | `PATCH /inventory/devices/{id}`; `POST /inventory/agents/tokens` |
| `bad_kinds` | 400 | The list of fragile device types is not valid. | `PUT /inventory/settings` |
| `bad_label` | 400 | The channel label can be at most 80 characters. | module notify (shared validator) |
| `bad_name` | 400 | The name may only contain letters without accents, digits, spaces, hyphens, dots or underscores, start with a letter or  | `POST /honeypot/tokens`; `POST /inventory/agents/tokens`; `POST /honeypot/trap-ips`, `PUT /honeypot/trap-ips/{id}` ("Enter a name for the Trap IP, for example FILESRV-OLD." / NetBIOS rule) |
| `bad_notes` | 400 | Notes are at most 2000 characters. | `PATCH /inventory/devices/{id}` |
| `bad_oa_id` | 400 | OA ID is a string of digits, shown in the Official Account management page. | module notify (shared validator) |
| `bad_password` | 400 | The password is too long (up to 200 characters). | module inventory (shared validator) |
| `bad_preset` | 400 | Choose what the Trap IP looks like. | `POST /honeypot/trap-ips`; `PUT /honeypot/trap-ips/{id}` |
| `bad_plant_at` | 400 | Say where you will plant it, for example \\\\SRV-FILE\\HR or "Password manager". This reminds you where to look when it  | `POST /honeypot/tokens` |
| `bad_port` | 400 | The port must be a number from 1 to 65535. Usually 514 (UDP or TCP) or 6514 (TLS). | `POST /scans/credentialed` |
| `bad_product` | 400 | Vendor and product are at most 64 characters each and cannot contain < or >. | module inventory (shared validator) |
| `bad_proto` | 400 | This device type cannot send logs with the chosen protocol. Pick another protocol from the list. | module logs (shared validator) |
| `bad_provider` | 400 | Choose an email provider from the list, or Custom SMTP. | `PUT /notify/channels/email` |
| `bad_quiet` | 400 | The start and end times must not be the same. | `PUT /notify/rules` |
| `bad_ranges` | 400 | The list of network ranges is missing. | `PUT /inventory/settings` |
| `bad_rate` | 400 | Scan rate is 1 to 1000 packets per second. | `PUT /inventory/settings` |
| `bad_refresh_token` | 400 | Enter the refresh token of the OA (Zalo Developers, API Explorer, OA access token). It lasts about 3 months. | module notify (Zalo OA) |
| `bad_regular_scan` | 400 | Regular scans must be: follow type setting, allow or never. | `PATCH /inventory/devices/{id}` |
| `bad_sample` | 400 | The sample text could not be read with this parser. | `POST /feeds/parse-test` |
| `bad_secret` | 400 | The signing key needs at least 16 characters. Press Generate random if you want a random one. Also (email): a Google service account key file, a Microsoft 365 client secret or a Postmark server token of the wrong shape. | module logs, notify (shared validator) |
| `bad_secret_key` | 400 | Enter the Secret key of the Zalo app (Zalo Developers, your app, Settings). | module notify (Zalo OA) |
| `bad_security` | 400 | Choose an encryption type: STARTTLS, SSL/TLS or none. | module notify (shared validator) |
| `bad_service` | 400 | Choose a service: SMB, RDP, SSH, MSSQL or HTTP. | `POST /honeypot/test-hit` |
| `bad_services` | 400 | Pick at least one service for the Trap IP to answer on. | `POST /honeypot/trap-ips`; `PUT /honeypot/trap-ips/{id}` |
| `bad_severity` | 400 | Choose a minimum severity: Critical, High, Medium or Low. | module notify (shared validator) |
| `bad_signature` | 400 | Invalid signature. The bundle was modified or not signed by the project. The box does not install unsigned packages. | `POST /core/updates/bundle` |
| `bad_skill` | 400 | skill must be explain or mitigation-config. | `POST /findings/{id}/ai` |
| `bad_span` | 400 | span must be true or false. | `PATCH /inventory/sensors/{id}` |
| `bad_state` | 400 | This address belongs to another sign-in. Press Sign in with Google again and paste the address of that sign-in. | `POST /notify/email-signin/{id}` |
| `bad_status` | 400 | Status must be new, acknowledged or resolved. | `PATCH /notify/incidents/{id}` |
| `bad_tenant_id` | 400 | The tenant ID is the Directory (tenant) ID of the app registration, for example 72f988bf-86f1-41af-91ab-2d7cd011db47, or your domain such as company.onmicrosoft.com. | `PUT /notify/channels/email` (Microsoft 365) |
| `bad_time` | 400 | Time must look like 23:00. | `PUT /inventory/settings`; `PUT /notify/rules` |
| `bad_to` | 400 | not-an-email is not a valid email address. Separate several recipients with commas. | module notify (shared validator); `GET /findings/handled` (`to` not a UTC time) |
| `bad_token` | 400 | A bot token looks like 123456789:AAH… and comes from @BotFather. Copy it again without extra spaces. | module notify (shared validator) |
| `bad_type` | 400 | Choose a token type: decoy file, fake credentials or URL. | `POST /honeypot/tokens` |
| `bad_until` | 400 | Accept the risk until a date from tomorrow up to one year from today. | `POST /findings/handle` |
| `bad_target` | 400 | Choose the findings: up to 500 ids, or a device and one of its fixes. | `POST /findings/handle` |
| `many_devices` | 400 | Mark findings of one device at a time. | `POST /findings/handle` |
| `bad_url` | 400 | Enter the Wazuh server API address starting with https://, for example https://wazuh-manager:55000. Do not put the user  Also: the address pasted after a Google sign-in is not this sign-in's loopback address, or has no code (`POST /notify/email-signin/{id}`). | module inventory, logs, notify (shared validator) |
| `bad_user_id` | 400 | The Zalo recipient ID (user_id) is the number of a person who followed or messaged the OA. | module notify (shared validator) |
| `bad_username` | 400 | Enter the read-only API user name (letters, digits, dot, dash, underscore; up to 64 characters). | `POST /scans/credentialed` |
| `bad_value` | 400 | Enter only a domain name, without http://, a path, a port or spaces. Example: example.com. | `POST /exposure/targets` |
| `bad_version` | 400 | The version may only contain letters, digits, dots, hyphens and brackets, up to 40 characters. Example 7.2.5. | module inventory (shared validator) |
| `bad_vendor` | 400 | Choose a vendor from the list, or none. | `POST /honeypot/trap-ips`; `PUT /honeypot/trap-ips/{id}` |
| `bad_webhook` | 400 | A Slack Incoming Webhook URL starts with https://hooks.slack.com/services/. Copy it again from your Slack app. | module notify (shared validator) |
| `bad_window` | 400 | window must be 24h or 7d. / The time range must be 24h, 7d or 30d. | 4 endpoints with 24h/7d (/feeds, /inventory, /logs, /notify); `GET /detection/alerts` (24h, 7d or 30d) |
| `code_expired` | 400 | This code has expired. Ask for a new code. | module core (shared validator) |
| `code_required` | 400 | Type the 6-digit two-step code to approve a high-risk AI request. | `POST /response/actions/{id}/approve` |
| `confirm_mismatch` | 400 | The organization name does not match. Type it exactly to confirm deletion. | `POST /core/data/purge` |
| `core_module` | 400 | Core modules are always on. | `PATCH /modules/{id}` |
| `current_session` | 400 | This is the session you are using. Use "Sign out" in the account menu. | `DELETE /core/account/sessions/{id}` |
| `dangerous_locked` | 400 | Vedette has no dangerous checks: no exploitation, no denial of service. It cannot be turned on. | `PUT /scans/config` |
| `duplicate_name` | 400 | Another connection already has this name. Pick a different one. | `POST /core/connections`; `PUT /core/connections/{id}`; module feeds (shared validator) |
| `duplicate_user` | 400 | The same user is listed twice as approver. | module notify (shared validator) |
| `empty` | 400 | No bundle file chosen. | `POST /core/updates/bundle`; `POST /exposure/targets` |
| `empty_file` | 400 | The file is empty. Download the template, fill in your devices and choose it again. | `POST /inventory/import` |
| `empty_query` | 400 | Enter a CVE, product name, IP or domain. | `GET /feeds/search` |
| `empty_window` | 400 | The start and the end are the same, so the window is empty. Choose different times. | `PATCH /core/updates/os/settings` |
| `fallback_without_primary` | 400 | Set a primary profile for ${JOB_NAME[j.id]} before adding a fallback. | module ai (shared validator) |
| `host_bits` | 400 | Range ${r} is not written correctly: the address part must be the first address of the range. Use ${cidrRange(r).network | `PUT /inventory/settings` |
| `incomplete_product` | 400 | Enter both the vendor and the product, for example vendor "Fortinet" and product "FortiGate". | module inventory (shared validator) |
| `invalid` | 400 | The switch value must be on or off. | 12 endpoint (/core, /response) |
| `invalid_action` | 400 | Pick what the hook does: block, mask or require approval. | module ai (shared validator) |
| `invalid_address` | 400 | Enter the head office address (5 to 200 characters). | module reports (shared validator) |
| `invalid_allow` | 400 | The allow-list holds up to 30 entries of 200 characters each, one per line. Also: Each allow-list entry must be an address under ${target}, for example ${target}/api/. | `POST /core/connections`; `PUT /core/connections/{id}` |
| `invalid_auth` | 400 | Pick how the box signs in: none, token, user and password, or SSH key. | `POST /core/connections`; `PUT /core/connections/{id}`; module feeds (shared validator) |
| `invalid_auto` | 400 | Automatic security updates are on or off. | `PATCH /core/updates/os/settings` |
| `invalid_base_url` | 400 | The server address is not valid. Enter it in full, for example https://api.anthropic.com or http://192.168.1.20:11434/v1. | module ai (shared validator) |
| `invalid_body` | 400 | Check the values and try again. | 4 endpoint (/feeds) |
| `invalid_bundle` | 400 | Choose a module bundle: smb, mid or custom. | `POST /core/setup` |
| `invalid_cap` | 400 | The profile\ | `PUT /ai/config` |
| `invalid_categories` | 400 | Unknown or empty log category in the download request. | `GET /core/logs/export` |
| `invalid_channel` | 400 | The channel is stable or beta. | `PATCH /core/updates` |
| `invalid_claim` | 400 | Enter the name of the groups claim, for example groups (letters, digits and _ . : / -, at most 64). | `PUT /core/oidc` |
| `invalid_ca` | 400 | The CA certificate <why>. Paste the PEM of the CA that signed the identity provider's certificate (-----BEGIN CERTIFICATE-----). | `PUT /core/oidc` |
| `invalid_client` | 400 | Enter the Client ID (at most 200 characters). | `PUT /core/oidc` |
| `invalid_code` | 400 | The code is 6 digits. | `POST /auth/login`; `POST /core/account/2fa/confirm`; `POST /response/actions/{id}/approve` (from `VerifyTwoStep`, returned as is) |
| `invalid_config` | 400 | The scan configuration is not valid. | `PUT /scans/config` |
| `invalid_contact` | 400 | Enter the name of the person in charge of data protection. | module reports (shared validator) |
| `invalid_credentials` | 400 | Wrong email or password. | `POST /auth/login`; `POST /auth/login/resend-code` |
| `invalid_content` | 400 | This is not a Word (DOCX) file. Only PDF, MD, TXT and DOCX files can be added. (also: this is not a PDF file; not UTF-8 text) | `POST /ai/knowledge` |
| `invalid_cve` | 400 | A CVE ID looks like CVE-2022-27593. | `POST /ai/cve/{id}/explain`; `POST /ai/cve/{id}/news` |
| `invalid_email` | 400 | The email is not valid, for example name@company.com. | `POST /core/setup`; `POST /core/users` |
| `invalid_employees` | 400 | Headcount is a whole number from 0 to 1,000,000. | module reports (shared validator) |
| `invalid_format` | 400 | Choose JSON or CSV. | `GET /core/logs/export`; `POST /feeds/parse-test` |
| `invalid_from` | 400 | The start of the range must be a date like 2026-11-09 or a UTC time ending in Z, like 2026-11-09T00:00:00Z. | `GET /core/audit`; `GET /core/audit/export`. New backend code [PROPOSED]: `bad_from` is not used because it already means "wrong sender email" in notify (§3.2 rule 5). A `YYYY-MM-DD` date is interpreted in the organisation's timezone; a timestamp must end in `Z` (an offset such as `+07:00` is rejected) |
| `invalid_grouping` | 400 | Group the open findings by device or by CVE. | `PUT /reports/definition` |
| `invalid_issuer` | 400 | The issuer must be an https address, for example https://sso.example.com/realms/main. | `PUT /core/oidc` |
| `invalid_items` | 400 | Pick at least one action of this request. | module response (shared validator) |
| `invalid_jobs` | 400 | One of the chosen jobs is not an AI job. Pick from the list. | `POST /ai/knowledge`; `PUT /ai/knowledge/{id}` |
| `invalid_key` | 400 | The API key is too short or contains spaces. Copy the whole key again from the provider\ | module ai (shared validator) |
| `invalid_kind` | 400 | Pick a kind: HTTP API, SSH / CLI, NETCONF / RESTCONF, automation platform or MCP server. | `POST /core/connections`; `PUT /core/connections/{id}` |
| `invalid_lan` | 400 | Enter 1 to 16 LAN ranges, for example 192.168.10.0/24. | `POST /core/setup` |
| `invalid_level` | 400 | The information system level is 1 to 5, or leave it empty if not determined yet. | module reports (shared validator) |
| `invalid_location` | 400 | Say where the model runs: inside the company network or in the cloud. | module ai (shared validator) |
| `invalid_match` | 400 | Enter the words (comma-separated) or the regular expression to look for, 200 characters at most. | module ai (shared validator) |
| `invalid_memory` | 400 | Write what the AI should remember in 3 to 300 characters, for example "NAS-PHOTOS is reachable from the Internet". | `POST /ai/memory`; `PUT /ai/memory/{id}` |
| `invalid_message` | 400 | Write the message people will see, 3 to 200 characters. | module ai (shared validator) |
| `invalid_mode` | 400 | The mode is automatic or manual. | `PATCH /core/updates`; `PUT /core/network/management`; `PUT /core/network/ntp` |
| `invalid_model` | 400 | The model name may only contain letters, digits, dots, dashes, colons and slashes (80 characters at most), for example c | module ai (shared validator) |
| `invalid_module` | 400 | No module "${unknown}". | `POST /core/setup` |
| `invalid_name` | 400 | Give the connection a name of 1 to 40 characters, for example "Office FortiGate API". | 5 endpoint (/ai, /core); `PUT /reports/definition` ("The report name must be 1 to 80 characters.") |
| `invalid_org` | 400 | The organization name is 2 to 80 characters. | `POST /core/setup`; `PUT /core/general` |
| `invalid_period` | 400 | Pick the period: the last 7 days, the last 30 days or the last calendar month. | `PUT /reports/definition` |
| `invalid_phone` | 400 | The phone number starts with 0 or +84 and has 10 to 11 digits. | module reports (shared validator) |
| `invalid_question` | 400 | The question must be 3 to 500 characters. For example: "Which machines still expose RDP?" | `POST /ai/ask` |
| `invalid_range` | 400 | The start date is after the end date. / Dates are written YYYY-MM-DD, for example 2026-11-09, between 2000 and 2100. (backend, `GET /core/logs/export`: a date that is not a day, or outside 2000..2100) | `GET /core/logs/export` |
| `invalid_recipients` | 400 | The recipient list holds 20 emails at most. | module reports (shared validator) |
| `invalid_retention` | 400 | Keep the AI activity log for at least ${MIN_RETENTION} days (up to 3650). | `PUT /ai/activity/settings` |
| `invalid_role` | 400 | Choose a role: view only, operator or administrator. | `PATCH /core/users/{id}`; `POST /core/users`; `PUT /core/oidc` |
| `invalid_rule` | 400 | Write the rule in 3 to 300 characters, for example "Always name devices by hostname and IP address". | module ai (shared validator) |
| `invalid_scope` | 400 | Choose security updates or all updates. | `POST /core/updates/os/install` |
| `invalid_scopes` | 400 | Choose at least one read scope: devices, findings or vulnerability feeds. | `POST /core/mcp/tokens`; `PUT /core/oidc` with its own message: "Scopes are words separated by spaces, at most 10, and must include openid." |
| `invalid_secret` | 400 | The secret is too short. Copy the whole token, password or key again. Also: This private key is protected by a passphrase, which Vedette cannot type. Save a copy without one and paste that. Also (13b-4): This private key could not be read. Paste the whole key, including the BEGIN and END lines.; This key type is not accepted. Use an Ed25519, ECDSA or RSA key of at least 2048 bits. | `PUT /core/oidc`; `POST /core/connections`; `PUT /core/connections/{id}` |
| `invalid_sector` | 400 | Pick the field of activity. | module reports (shared validator) |
| `invalid_setting` | 400 | Say whether the AI may suggest new memories: on or off. | `PUT /ai/hooks/builtin/{id}`; `PUT /ai/memory/settings`; `PUT /ai/skills/{id}` |
| `invalid_size` | 400 | The file is empty. (also: The file arrived damaged or cut short. Pick it again.) | `POST /ai/knowledge` |
| `invalid_style` | 400 | Pick the API style the server speaks: OpenAI Chat Completions, Anthropic Messages or Gemini. | module ai (shared validator) |
| `invalid_target` | 400 | Enter the SSH server as host or host:port, for example 192.168.10.30:22. Also: The address must start with https://. Vedette sends sign-in details and changes only over HTTPS.; Vedette never connects to ${why}. Enter the address of the device or service itself. (loopback, link-local, multicast, unspecified, `localhost`, non-standard numeric names, the box itself) | `POST /core/connections`; `PUT /core/connections/{id}` |
| `invalid_tax_code` | 400 | The tax code is 10 digits, or 10 digits, a dash and 3 digits for a branch. Example 0312345678. | module reports (shared validator) |
| `invalid_text` | 400 | Type a sample text of up to 1,000 characters. | `POST /ai/hooks/test` |
| `invalid_tier` | 400 | Pick a tier: minimum, medium or maximum. | `PUT /ai/config` |
| `invalid_time` | 400 | Enter the start and end as hours and minutes, for example 02:00. | `PATCH /core/updates/os/settings`; `POST /core/updates/os/reboot` |
| `invalid_timezone` | 400 | The time zone is not in the list. | `PUT /core/general` |
| `invalid_to` | 400 | The end of the range must be a date like 2026-11-09 or a UTC time ending in Z, like 2026-11-09T23:59:59Z. | `GET /core/audit`; `GET /core/audit/export`. Same as `invalid_from` |
| `invalid_tool_access` | 400 | Only tools of an MCP server can be marked read or write; the built-in tools of this kind are fixed. | `POST /core/connections`; `PUT /core/connections/{id}` |
| `invalid_type` | 400 | Only PDF, MD, TXT and DOCX files can be added. | `POST /ai/knowledge` |
| `invalid_url` | 400 | Use an https:// address (http:// is only allowed for internal addresses). | `PUT /feeds/sources/{id}` |
| `invalid_volume` | 400 | Pick how many people\ | module reports (shared validator) |
| `invalid_when` | 400 | Pick when the hook runs: before sending to the AI, after the AI answers, or before a tool call. | `POST /ai/hooks/test`; `POST /core/updates/os/reboot` |
| `invalid_window` | 400 | The maintenance window is "any time" or "only in a window". | `PATCH /core/updates/os/settings` |
| `ip_is_box` | 400 | This is the Vedette box\ | `POST /honeypot/trap-ips`; `PUT /honeypot/trap-ips/{id}` |
| `ip_is_gateway` | 400 | This is the address of your router (the box's default gateway). Pick an unused IP. | `POST /honeypot/trap-ips`; `PUT /honeypot/trap-ips/{id}`; `PATCH /honeypot/trap-ips/{id}` (the gateway as the host reports it, B2) |
| `ip_not_allowed` | 400 | Public IPs are not typed in. Select "Verify this box\ | `POST /exposure/targets` |
| `ip_outside_lan` | 400 | The Trap IP must be inside the box's network (${boxInfo().lan}), not the network or broadcast address. | `POST /honeypot/trap-ips`; `PUT /honeypot/trap-ips/{id}` |
| `key_required` | 400 | The API key is required (changing the provider type needs the key again). | module ai (shared validator) |
| `kind_unsupported` | 400 | An MCP server that Vedette starts as a command is not supported. Use an MCP server that has a web address (kind "MCP server (URL)"). | `POST /core/connections`; `PUT /core/connections/{id}`; `POST /core/connections/{id}/test` |
| `last_admin` | 400 | At least one active administrator who signs in with a password must remain, so the box stays reachable when the identity provider is down. Add another administrator first. | `PATCH /core/users/{id}` (only password accounts count) |
| `locked` | 400 | "Write tools need approval" is always on. A tool that changes something can only run through an action a person approves | `PUT /ai/hooks/builtin/{id}` |
| `missing_dependencies` | 400/409 | Module ${id} also needs: ${lacking.join(', ')}. | `PATCH /modules/{id}`; `POST /core/setup`; `PATCH /scanning/engines/{id}` |
| `no_code` | 400 | No code is waiting. Ask for a new code. | module core (shared validator) |
| `commitment_required` | 400 | (operator) ${t.value} has not been confirmed yet. An administrator must run the first scan: it records that your company owns ${t.value} and that the scan is authorized. (administrator, no `notice_version`) The first scan of ${t.value} records a confirmation, so the request must carry notice_version of the sentence shown next to Scan now. (`POST /scans/runs`: Vedette does not scan until the scope commitment is ticked. Do it under Settings › Scanning › Safety.) | `POST /exposure/targets/{id}/scan`; `POST /scans/runs` |
| `no_days` | 400 | Pick at least one day for the maintenance window. | `PATCH /core/updates/os/settings`; `PUT /inventory/settings` |
| `no_index_profile` | 400 | Choose an AI profile for the index before adding documents. | `POST /ai/knowledge` |
| `no_lan` | 400 | Add your LAN range first (Settings › Scanning › Safety), so Vedette knows which network the Trap IPs go on. | `POST /honeypot/trap-ips`; `PUT /honeypot/trap-ips/{id}` |
| `no_pack` | 400 | This CVE has no confirmed recommendation yet, so there is nothing to mark as applied. | `POST /findings/{id}/applied` |
| `no_prefix` | 400 | "${r}" has no prefix length. Add it so Vedette scans the right size of network, for example ${r}/24 or ${r}/25. | `PUT /inventory/settings` |
| `no_ranges` | 400 | Active scanning needs at least one network range. | `PUT /inventory/settings` |
| `no_recipients` | 400 | Automatic sending needs at least one recipient. Add an email, then save. | `POST /reports/weekly/send`; `POST /reports/send` |
| `no_rows` | 400 | No device rows were found below the column headers. Add at least one row and choose the file again. | `POST /inventory/import` |
| `no_sections` | 400 | Turn on at least one section; a report with no section would be empty. | `PUT /reports/definition` |
| `no_such_user` | 400 | One of the approvers does not exist or is disabled. | module notify (shared validator) |
| `no_targets` | 400 | Choose at least one device to scan. | `POST /scans/runs` |
| `no_window` | 400 | There is no maintenance window yet. Set the days and hours first, or pick a time yourself. | `POST /core/updates/os/reboot` |
| `not_bundle` | 400 | The file is not a Vedette bundle (content cannot be read). | `POST /core/updates/bundle` |
| `not_configured` | 400 | Save the OIDC configuration before testing. | `POST /core/oidc/test`; `POST /logs/siem/test`; `POST /notify/channels/{type}/test` |
| `not_scannable` | 400 | ${target} may not be scanned: it is set to never be scanned / it was added by hand / it has no IP address. (`reason` names the inventory's rule) | `POST /scanning/engines/nmap-discovery/run` |
| `notice_changed` | 409 | The confirmation text changed since this page loaded. Read it again, then press Scan now again. | `POST /exposure/targets/{id}/scan` (an administrator's first scan sent an old `notice_version`; nothing is recorded) |
| `not_manual` | 400/409 | Only manually declared software can be removed. Software seen by a sensor or agent updates on the next scan. | `DELETE /inventory/devices/{id}/software/{sid}`; `POST /response/rules/{id}/manual` |
| `not_public` | 400 | The box reaches the Internet via ${ip}, which is a private, reserved or shared carrier (CGNAT) address. Scanning it coul | `POST /exposure/box-ip/verify` |
| `not_server` | 400 | The target is not a server (credentialed scan is for servers only). | `POST /scans/credentialed` |
| `note_required` | 400 | Write why this is a false positive, not relevant or an accepted risk (at least 3 characters) so the next person understands. | `POST /findings/handle`; `POST /findings/questions/{id}/answer` (not affected) |
| `confirm_note_required` | 400 | Write what makes you sure (at least 3 characters) so the next person understands. | `POST /findings/{id}/verify` |
| `note_too_long` | 400 | The note can be at most 500 characters. Shorten it. | `PATCH /notify/incidents/{id}` |
| `oidc_off` | 400 | SSO sign-in is not set up. Sign in with your email and password, or ask an administrator. | `POST /auth/oidc/start`; `POST /auth/oidc/callback` |
| `out_of_scope` | 400 | The target is outside the approved scope. | `POST /scans/credentialed`; `POST /scans/runs`; `POST /scanning/engines/nmap-discovery/run`; `POST /exposure/targets/{id}/scan` (on the exclusion list of the shared safety block, exposure INV-31) |
| `outside_window` | 400 | The chosen reboot time is outside the maintenance window. | `POST /core/updates/os/reboot` |
| `overlap_range` | 400 | Range ${r} overlaps ${clash}. Keep the larger range and drop the smaller one. | `PUT /inventory/settings` |
| `password_required` | 400 | Enter the password of the read-only API user. | module inventory (shared validator) |
| `phrase_mismatch` | 400 | Type ${RISK_PHRASE} exactly, in capital letters. | `POST /response/execution` |
| `port_mismatch` | 400 | Port 587 uses STARTTLS, not SSL/TLS. Choose STARTTLS, or change the port to 465 for SSL/TLS. | module notify (shared validator) |
| `privacy_rule` | 400 | "${p.name}" runs in the cloud, but ${JOB_NAME[j.id]} sends internal data and the privacy rule only allows internal profi | `PUT /ai/profiles/{id}` |
| `profile_unusable` | 400 | "${p.name}" has no API key yet, so it cannot build the index. Edit the profile and add the key. | `PUT /ai/knowledge/settings` |
| `public_range` | 400 | The range is not a private range (10.x, 172.16-31.x, 192.168.x, 100.64-127.x). | `POST /core/setup`; `PUT /inventory/settings` |
| `same_date` | 400 | Pick two different days to compare. | `GET /exposure/targets/{id}/diff` |
| `same_password` | 400 | The new password must differ from the current one. | `POST /core/account/password` |
| `same_profile` | 400 | The fallback for ${JOB_NAME[j.id]} must be a different profile from the primary. | module ai (shared validator) |
| `sample_unavailable` | 400 | This build has no sample data. Fill in the setup form instead. | `POST /core/setup`. New backend code [PROPOSED] (INV-15): `sample:true` is valid only in a `data_mode=sample` build; the current backend build has no sample data |
| `scope_not_confirmed` | 400 | Tick the confirmation that these network ranges belong to your company and you are allowed to scan them. Vedette only sc | `PUT /inventory/settings`; `PUT /scanning/safety`; `PATCH /scanning/engines/{id}`; `POST /scanning/engines/nmap-discovery/run` |
| `secret_required` | 400 | Enter the secret. It stays on this box and is encrypted; only the last 4 characters are shown afterwards. Also: Enter the secret again: the address changed, and a saved secret is only sent to the address it was saved for. | `POST /core/connections`; `PUT /core/connections/{id}`; module notify (shared validator) |
| `self_disable` | 400 | You cannot disable the account you are using. Ask another administrator. | `PATCH /core/users/{id}` |
| `self_reset` | 400 | You cannot reset your own two-step sign-in here. Use My account instead. | `POST /core/users/{id}/2fa/reset` |
| `signin_refused` | 400 | Microsoft refused the app registration. Check the client ID and the tenant ID, and turn on Allow public client flows under Authentication of the app registration. (Each refusal of Microsoft or Google has its own fixed sentence; never the provider's text.) | `POST /notify/email-signin`, `POST /notify/email-signin/{id}` |
| `sso_expired` | 400 | This sign-in has expired or was already used. Start again from the sign-in page. / This sign-in was started in another tab or browser. Start again from the sign-in page. | `POST /auth/oidc/callback`: state unknown, used or older than 10 minutes, or the binding is wrong; the flow is spent either way |
| `sso_failed` | 400 | The identity provider's answer could not be verified. Ask an administrator to check the SSO settings; the audit log has the reason. | `POST /auth/oidc/callback`: code exchange refused, or the ID token fails a check (signature, alg, iss, aud/azp, exp, nonce); `auth.login_failed` says which |
| `temp_password_expired` | 400 | This temporary password has expired. Ask an administrator for a new one. | `POST /auth/login` |
| `telemetry_unavailable` | 400 | This version of Vedette does not send an anonymous signal, so it cannot be turned on. | `PATCH /core/privacy` with `telemetry: true` (backend only. Not in the mock; the GUI does not send it) |
| `terms_not_accepted` | 400 | Read the terms of use and tick that you agree to them before you go on. | `POST /core/setup`; `POST /core/setup/restore`. Checked immediately after the setup code |
| `tls_unavailable` | 400 | Syslog over TLS needs the box's HTTPS certificate; this box serves plain HTTP. Choose UDP or TCP. | module logs: only on a box with no TLS configuration (loopback/dev) |
| `too_large` | 400/413 | The file is larger than 10 MB. Split it or remove pictures, then upload again. | 4 endpoint (/ai, /core, /feeds, /inventory) |
| `too_many` | 400 | The certificate-transparency logs list more than 300 names under ${domain}, more than one scan reads, so nothing was scanned. … (`POST /exposure/targets/{id}/scan`) / A box holds up to 30 custom rules. Delete one you no longer need. Also: A box holds up to 20 connections. Delete one you no longer use. | 10 endpoint (/ai, /core, /exposure, /scans); `POST /core/connections`; `POST /core/mcp/tokens`: "A box holds up to 10 MCP tokens. Revoke one you no longer use." |
| `too_many_exclusions` | 400 | The exclusion list can have at most 200 lines. | `PUT /scanning/safety`; `PUT /scans/config` (write-through) |
| `too_many_ranges` | 400 | At most 16 network ranges. | `PUT /inventory/settings` |
| `too_many_rows` | 400 | At most ${MAX_IMPORT_ROWS} rows per import. This file has ${data.length} rows. | `POST /inventory/import` |
| `too_many_tries` | 400 | Too many wrong codes. Ask for a new code. | module core (shared validator) |
| `unknown_asset` | 400 | The device you linked is not in the inventory. | `POST /core/connections`; `PUT /core/connections/{id}` |
| `unknown_device` | 400 | No device has the address or id ${target}. Let discovery find it first, or add it under Devices. | `POST /scanning/engines/nmap-discovery/run` |
| `unknown_host` | 400 | Choose a server from the device list in the inventory. | `POST /scans/credentialed` |
| `unknown_product` | 400 | That product is not in the list. Pick one from the suggestions, or enter the vendor and product yourself. | module inventory (shared validator) |
| `unknown_profile` | 400 | This AI profile no longer exists. Pick another. | `PUT /ai/knowledge/settings` |
| `unknown_target` | 400 | There is no target "${id.slice(0, 40)}" in the scan list. | `POST /scans/runs` |
| `url_unreadable` | 400 | The saved webhook URL cannot be read. Enter it again and save. | `PUT /notify/channels/webhook` (backend only: a sealed URL cannot be opened, for example after the key changed; the mock has no sealed state, so it does not return this code). A separate code because the webhook's `secret_required` is about the signing key; the GUI shows it under the URL field |
| `username_required` | 400 | Enter the user name the box signs in with. | `POST /core/connections`; `PUT /core/connections/{id}` (SSH and Basic sign-in) |
| `viewer_not_allowed` | 400 | A viewer cannot be an approver. | module notify (shared validator) |
| `weak_password` | 400 | The password needs at least ${MIN_PASSWORD} characters. A long sentence is easier to remember than random characters. | `POST /core/account/password`; `POST /core/setup`; `POST /core/data/backup` (the backup password: "The backup password needs at least …") |
| `wrong_code` | 400 | Wrong code. ${left} ${left === 1 ? 'try' : 'tries'} left. | `POST /core/account/2fa/confirm`; `POST /response/actions/{id}/approve` (email, from `VerifyTwoStep`, returned as is) |
| `wrong_password` | 400 | The current password is wrong. | `POST /core/data/purge` ("Wrong password. The password is needed to delete all data."); `POST /core/account/2fa/disable`; `POST /core/account/password`; `POST /core/account/2fa/start`; `POST /core/account/2fa/email/start` (turning on two-step also needs the current password, message "The password is needed to turn on two-factor authentication."; a wrong one counts against the per-account re-authentication counter, separate from the failed-login counter but with the same limit of 10 per 15 minutes and the same back-off growth, and writes `auth.reauth_failed`). Also the code when the password just proven was changed between the check and the write |
| `wrong_backup_password` | 400 | The backup password is wrong. Enter the password that was set when the backup was downloaded. | `POST /core/setup/restore/upload`, `POST /core/data/restore/upload` (counted like a wrong setup code: 429 `rate_limited` after ten) |
| `wrong_kind` | 400 | This action is an SSH command. Choose an SSH connection. | `PUT /response/catalog/{id}` |
| `dhcp_no_static` | 400 | With DHCP the address, gateway and DNS come from your DHCP server. Remove the static fields. | `PUT /core/network/management` |
| `gateway_outside_subnet` | 400 | The gateway must be inside the address range you entered. Backend [PROPOSED]: checked by `core` first, and the host's `gateway_outside_subnet` (412). | `PUT /core/network/management` |
| `gateway_not_host` | 400 | The gateway cannot be the network or broadcast address of the range. Use the address of your router. | `PUT /core/network/management` |
| `invalid_static` | 400 | The IP address must be an IPv4 address like 192.168.10.250. (same group: prefix 8 to 30, network/broadcast/reserved/link-local 169.254 addresses, gateway equal to the address, 1 to 3 DNS servers, loopback/link-local/multicast or duplicate DNS; rules of the host's `unicast4`/`hostInSubnet`/`IsGlobalUnicast`; host `invalid_args` → 400 `invalid`) | `PUT /core/network/management` |
| `invalid_roles` | 400 | Give a role (management, span or unused) for every interface. | `PUT /core/network/interfaces` |
| `invalid_span` | 400 | The SPAN settings are incomplete. (backend: the OpenAPI schema rejects it first, generic code `invalid`) | `PUT /core/network/span` |
| `no_interface` | 400 | Choose the port that receives the mirrored traffic before turning SPAN on. | `PUT /core/network/span` |
| `nothing_selected` | 400 | Choose at least one thing to read from the mirrored traffic, or turn SPAN off. | `PUT /core/network/span` |
| `bad_filter` | 400 | "${v}" is not a network range. Write it like 10.0.5.0/24, with the prefix length. (same group: filter type, empty value, range larger than /8, host, port, duplicate, more than 50) | `PUT /core/network/span`; `GET /findings/devices`, `GET /findings/fixes` (`status`), `GET /findings/handled` (`resolution`) |
| `bad_limit` | 400 | The CPU cap must be a whole number from 5 to 50 percent. (backend: the OpenAPI schema rejects it first, generic code `invalid`) | `PUT /core/network/span` |
| `default_no_servers` | 400 | The default pool takes no server list. Choose "your own servers" to enter some. | `PUT /core/network/ntp` |
| `bad_ntp` | 400 | Give 1 to 4 NTP servers. (same group: wrong or duplicate name or IPv4; backend: a name made only of digits such as `1.2.3` is rejected, the host also rejects it) | `PUT /core/network/ntp` |
| `bad_box_address` | 400 | Enter a host name like vedette.office.lan or an IPv4 address like 192.168.1.10, without https:// and without a port. (URL, port, path, spaces, IPv6, loopback, `localhost`/`*.localhost`, names made only of digits; a body missing `address` is the schema's `invalid`) | `PUT /core/network/box-address` |
| `blocked_host` | 400 | Vedette does not pull feeds from link-local, multicast, unspecified or cloud metadata addresses. Also, for Vedette itself in every module: That address is Vedette itself: loopback, Vedette's own container, or one of its ports (8443, 8444, 8765, 514, 6514) on the machine that runs it. For another program on that machine, enter the machine's LAN address and that program's port. | `POST /feeds/custom`; `PUT /feeds/custom/{id}`; `PUT /feeds/sources/{id}`; `PUT /logs/siem` |
| `duplicate_url` | 400 | The feed "Tor exit list" already uses this address. | `POST /feeds/custom`; `PUT /feeds/custom/{id}` |

#### HTTP 401 (3 codes)

| Code | HTTP | Sample message (EN, from the mock) | Endpoint |
|---|---|---|---|
| `key_rejected` | 502 | The provider rejected the key (HTTP 401). Check the key has not expired and belongs to this provider. | `POST /ai/profiles/test` |
| `twofa_required` | 401/403/409 | Turn on two-step sign-in for your account first (My account), then try again. | `POST /auth/login`; `POST /response/execution`; 403 from `core/auth.VerifyTwoStep` when the approver has not turned on two-step; `POST /exposure/targets/{id}/scan`: an administrator's first scan of a target without two-step sign-in on the account: Turn on two-step sign-in for your account first (My account), then run the first scan again. The first scan records your confirmation that your company owns the target and that you are authorized to scan it. |
| `unauthenticated` | 401 | Not signed in. | `GET /me`; every non-public endpoint when there is no session, or the session expired or was revoked; on write operations, a session revoked **midway** is also 401 and nothing is written: `/core/account/password`, `/core/account/2fa/{start,confirm,email/start,email/confirm,disable}`, `PATCH /core/account`, `POST /core/users`, `PATCH /core/users/{id}`, `/core/users/{id}/reset-password`, `/core/users/{id}/2fa/reset`, `PUT /core/general`, `GET /core/audit/export` |

#### HTTP 403 (14 codes)

| Code | HTTP | Sample message (EN, from the mock) | Endpoint |
|---|---|---|---|
| `approver_not_listed` | 403 | Not counted: this ${b.channel} address is not on the approver list of that channel, or its user is not an operator or ad | `POST /response/actions/{id}/chat-decision`; `POST /response/approve/{token}` |
| `channel_not_allowed` | 403 | Approvals from ${b.channel} are not turned on for response. | `POST /response/actions/{id}/chat-decision` |
| `csrf_invalid` | 403 | The request could not be verified. Reload the page and try again. | every authenticated POST/PUT/PATCH/DELETE (`core/server`, §7.2) |
| `disabled` | 403 | This account has been disabled. | `POST /auth/oidc/callback` (even when the identity provider lets the person in); `POST /auth/login`; `POST /auth/login/resend-code`; every request with a session of a disabled account; on write operations, an account disabled midway is also 403 and nothing is written: `/core/account/password`, `/core/account/2fa/{start,confirm,email/start,email/confirm,disable}`, `PATCH /core/account`, `POST /core/users`, `PATCH /core/users/{id}`, `/core/users/{id}/reset-password`, `/core/users/{id}/2fa/reset`, `PUT /core/general`, `GET /core/audit/export` (the acting administrator is disabled) |
| `email_unverified` | 403 | Your identity provider says this email address is not verified. Verify it there, or ask an administrator. | `POST /auth/oidc/callback`, new account: `email_verified` is false, or the ID token has no email |
| `forbidden` | 403 | Your account is not allowed to do this. | module core (shared validator) |
| `in_app_required` | 403 | A high-risk AI request can only be approved in the app with your two-step code, not from chat or email. | module response (shared validator) |
| `invalid_token` | 403 | This enrollment token is not valid. Create a new one in Vedette. | `POST /intake/osquery/status` |
| `invalid_setup_code` | 403 | The setup code is missing or wrong. Find it in the box's log: it is printed there each time Vedette starts while setup is open. | `POST /core/setup`. New backend code [PROPOSED]. A wrong code counts per client address like sign-in (10 tries, then `rate_limited` 30 s doubling up to 10 minutes; IPv6 adds a /64 counter capped at 100), with no global cap for the whole box (fixed after two security reviews: a global cap is a way to lock the box owner out) |
| `no_access` | 403 | Your company account is not in a group that may use Vedette. Ask an administrator. | `POST /auth/oidc/callback`: no mapped group and the default role is No access |
| `password_change_required` | 403 | Choose a new password before you continue. | every request with a session of a user who has a temporary password, except `GET /me`, `POST /core/account/password` |
| `token_expired` | 403 | This enrollment token has expired. Create a new one in Vedette. | `POST /intake/osquery/status`; `POST /inventory/agents/tokens/{id}/sample-data` |
| `tool_not_allowed` | 403 | The action "${cat?.name ?? prop.tool}" is not enabled in the action catalog (Settings, AI response). | `POST /response/proposals/{id}/request`; `POST /response/incidents/{id}/request` |
| `twofa_reset_required` | 403 | Your two-step sign-in key could not be read on this box (it was restored without the decryption key, or the box key changed). Ask an administrator to reset your two-step sign-in in Settings, Users, then sign in and set it up again. | `POST /auth/login` (correct password, with or without `code`) and the second step of every operation that needs re-confirmation with an app code: the authenticator key was sealed with a different master key (restored without the decryption key, `confirm_without_key`). It never falls back to password-only; an administrator resets two-step (`POST /core/users/{id}/2fa/reset`) |

#### HTTP 404 (9 codes)

| Code | HTTP | Sample message (EN, from the mock) | Endpoint |
|---|---|---|---|
| `mirror_missing` | 404 | This box has no copy of the osquery packages (a development build, or an install without them). Update Vedette to the release. | `GET /install/osquery/{file}` when the package directory (`-osquery-dir`, default `/usr/share/vedette/osquery`) is missing or does not contain that file; with a WARN log line (agent-intake). A name outside the list of 4 files is `not_found` |
| `no_box_address` | 404 | This box knows no address that other machines can reach, so an install script would point nowhere. Open Vedette at its network address; on a container-only install first set VEDETTE_BIND_IP to this machine's LAN address and VEDETTE_HOSTS to that address or a name for it. Then copy the command again. | `GET /install/osquery.sh`, `GET /install/osquery.ps1` when the box address in the script would be the placeholder `<VEDETTE_BOX_IP>` (opened via localhost, no configured address); `GET /inventory/agents` still returns the placeholder `server_url` (agent-intake INV-17 (c)). **409**: The box does not know an address other machines can reach yet. Set the Box address in Settings → Box network, then try again. — `POST /honeypot/tokens` of type `url` when the box has no Box address and the store has no IP of the box |
| `no_certificate` | 404 | This box serves plain HTTP on loopback, so it has no certificate for osquery to trust. Open Vedette at its network address. | `GET /intake/ca.pem`, `GET /install/osquery.sh`, `GET /install/osquery.ps1` when the box serves HTTP on loopback (no certificate to pin); `GET /inventory/agents` still returns the script with the CA gap spelled out (agent-intake) |
| `no_update` | 404 | There is no new version of this component. Click "Check now". | `POST /core/updates/apply` |
| `not_found` | 404 | This ${what} no longer exists. | 52 endpoint (/ai, /core, /exposure, /feeds, /findings, /honeypot, /inventory, /logs, /modules, /notify, /reports, /response) |
| `not_in_data` | 404 | The vulnerability data on this box does not hold this CVE. | `GET /feeds/cve/{id}` (and, with its own sentence, `GET /feeds/cve/{id}/tier`) |
| `address_not_found` | 404 | This address is not one of this device's addresses. Reload the device page. | `POST /inventory/devices/{id}/split` |
| `unknown` | 404 | This link is not valid. | `POST /response/approve/{token}` |
| `unknown_cve` | 404 | This CVE is not on the exploited list the box holds. The AI only explains CVEs the box has data for. | `POST /ai/cve/{id}/explain`; `POST /ai/cve/{id}/news` |

#### HTTP 409 (119 codes)

| Code | HTTP | Sample message (EN, from the mock) | Endpoint |
|---|---|---|---|
| `ai_paused` | 409 | AI request: AI proposals are paused (${reason}). An admin can resume them. | the AI proposal gate (calls `checkAIPaused`; set by the quality circuit breaker, cleared by `POST /response/ai/resume`) |
| `ai_unavailable` | 409 | The AI assistant module is off. Turn it on in Settings, Modules. | `POST /findings/{id}/ai`; `POST /ai/cve/{id}/explain` and every AI job call: only when AI is **not usable yet** (module off, no profile, not assigned, privacy rule, skill off, profile does not accept tools). A blocking hook, a truncated answer, a bad format and a provider error have their own codes |
| `blocked_by_hook` | 409 | The AI was not asked: a hook stopped the question. The text contains an ID number. It was not sent to the AI. Remove the number and ask again. Rephrase and try again; an administrator can adjust the hooks in Settings, AI assistant, Hooks. | `POST /findings/{id}/ai`, `POST /ai/cve/{id}/explain`, `POST /ai/cve/{id}/news`, `POST /ai/ask`, `POST /ai/logs/digest`, `POST /reports/weekly/ai-summary`, `POST /reports/pdpl/ai-summary`: a `before_ai` hook blocks the question or the data that goes with it (the message says which part) or an `after_ai` hook blocks the answer; `POST /ai/ask` returns 200 with the hook in `hooks[].step` instead of this code |
| `already_on` | 409 | Two-step sign-in is already on. Turn it off first to set up the other method. | `POST /core/account/2fa/email/confirm`; `POST /core/account/2fa/email/start`; `POST /core/account/2fa/start` |
| `already_open` | 409 | This finding is already open. | `POST /findings/{id}/reopen` |
| `already_verified` | 409 | This finding is already confirmed. | `POST /findings/{id}/verify` |
| `not_one_cve` | 409 | This question decides several CVEs: correct the software on the device (its version) instead. | `POST /findings/questions/{id}/answer` |
| `not_suspected` | 409 | Only a suspected finding can be confirmed. | `POST /findings/{id}/verify` |
| `not_confirmed_by_person` | 409 | Only a finding a person confirmed can be returned to suspected; a scan confirmed this one. | `POST /findings/{id}/unverify` |
| `already_requested` | 409 | This action already has an open request or has already been carried out. | `POST /response/proposals/{id}/request`; `POST /response/incidents/{id}/request` |
| `already_running` | 409 | A scan is already running. Wait for it to finish or press Stop now. | `POST /scans/runs` |
| `already_setup` | 409 | This box is already set up. Sign in with the administrator account. | `POST /core/setup` |
| `key_unreadable` | 409 | The decryption key file cannot be read on this box. The details are in the box log. | `POST /core/data/key`; `POST /core/data/backup` with a password ("…so a password-protected backup cannot carry it. Download the backup without a password, or see the box log.", before anything is made) |
| `backup_password_required` | 409 | This backup is protected with a password. Enter the password that was set when it was downloaded. | `POST /core/setup/restore/upload`, `POST /core/data/restore/upload` (an age file sent without `X-Backup-Password`) |
| `box_device` | 409 | This is the Vedette box itself, so it cannot be deleted. It is always the first device in the list. Its packages come fr | `DELETE /inventory/devices/{id}`; `POST /inventory/devices/{id}/merge`, `POST /inventory/devices/{id}/keep-separate` ("…so it cannot be merged with another device / compared with another device. It is always its own device.") |
| `circuit_open` | 409 | The circuit breaker is open: too many actions in one hour, so everything is paused. An admin can resume it in Settings, AI response. | `POST /response/actions/{id}/approve` (item refused right before it runs); `POST /response/proposals/{id}/request`; rule runs (resp_log); the emergency stop opens it too; `POST /response/incidents/{id}/request` |
| `connection_changed` | 409 | The connection "…" was changed after the request was made. Nothing was changed. Ask again. (another connection, address or version than the one the request was rendered against) | `POST /response/actions/{id}/approve` (item refused right before it runs); `POST /response/actions/{id}/rollback`; `POST /core/connections/{id}/test` (the connection was edited while the test ran, so the result was not saved) |
| `builtin` | 409 | Built-in actions cannot be deleted. Disable it instead. | `DELETE /response/catalog/{id}` |
| `busy` | 409 | An update run is in progress. Wait for it to finish, then check again. / Another external scan is running on this box. Wait for it to finish, then try again. (`POST /exposure/targets/{id}/scan` of the target whose scan runs now; another target's scan waits in the queue, exposure INV-36) | `POST /core/updates/os/check`; `POST /core/updates/os/install`; `POST /core/updates/os/reboot`; `GET /core/data/backup` (also when another download is running; the host is busy with another write command for over 2 minutes: "The box is busy with another task, for example starting a module. Wait a minute, then try again."); every write command through the host when the host returns `busy` (same sentence) or `install_in_progress` ("An operating system update is being installed. Wait for it to finish, then try again."); `GET /core/logs/export` (backend: another log download is being prepared); `GET /core/data/export` (backend: another export is being prepared); `POST /ai/knowledge` (documents still being read); `POST /core/updates/apply`, `POST /core/updates/rollback` ("An update or rollback of the software is already running. Wait for it to finish."; while an OS install runs: "An operating system update is running. Wait for it to finish, then try again."). Backend: a software run counts as busy for the OS endpoints too; `POST /scanning/engines/nmap-discovery/run` (a LAN sweep is already going on: "A LAN sweep is already going on: it is the answer. Follow it on the Runs tab."; any other run in the way queues the person's run instead); `POST /schedules/{owner_key}/run` ("The run this schedule last started has not ended. Open it to follow it or stop it, then try again.") |
| `channel_not_ready` | 409 | This channel is not set up or is turned off. An administrator can turn it on in Settings, Alert channels. | `POST /notify/history/{id}/resend` |
| `check_off` | 409 | Update checks are off under Privacy. Turn them on to look for Vedette releases. | `POST /core/updates/check`; `POST /core/updates/os/check` |
| `connection_off` | 409 | This connection is turned off, so nothing is sent to it. Turn it on, then test it. | `POST /core/connections/{id}/test` (PRIVACY flow 12) |
| `dns_unavailable` | 409 | A DNS token cannot alert: the box runs no DNS server, so nothing would record a lookup of its name. Use a URL token or fake credentials instead. | `POST /honeypot/tokens` |
| `duplicate` | 409 | This email already has an account. | `POST /core/users`; `POST /exposure/targets`; `POST /honeypot/tokens` |
| `duplicate_ip` | 409 | IP ${ip} is already in the list (${dup.hostname ?? dup.id}). Open that device instead of adding a new one. | module inventory (shared validator) |
| `duplicate_software` | 409 | This software is already on the device. | `POST /inventory/devices/{id}/software` |
| `email_channel_not_ready` | 409 | Email codes need a working email alert channel. An administrator has to set it up, turn it on and send a test message that succeeds. | `POST /core/account/2fa/email/confirm`; `POST /core/account/2fa/email/start` |
| `email_in_use` | 409 | A Vedette account already uses ${email} and does not belong to this SSO identity. Use another email at the identity provider, or ask an administrator. | `POST /auth/oidc/callback` |
| `engine_off` | 409 | Network discovery is off. Turn it on in Settings, Scanning first. (active discovery's own switch, not a module) | `POST /scanning/engines/nmap-discovery/run` |
| `execution_off` | 409 | Execution is off (Settings, AI response). | `POST /response/actions/{id}/chat-decision`; `POST /response/proposals/{id}/request`; `POST /response/incidents/{id}/request` |
| `exists` | 409 | This target already has a scan account. | `POST /scans/credentialed` |
| `expired` | 409 | Verification of ${t.value} has expired. Verify it again first. | `POST /exposure/targets/{id}/scan` |
| `feed_disabled` | 409 | Turn the feed on before fetching it. | `POST /feeds/sources/{id}/fetch` |
| `finding_closed` | 409 | The finding is no longer an open critical finding. | `POST /response/proposals/{id}/request` |
| `name_in_use` | 409 | The name ${name} is already used by a device or another Trap IP. Pick another name. | `POST /honeypot/trap-ips`; `PUT /honeypot/trap-ips/{id}` |
| `in_use` | 409 | The rule "${user.name}" uses this action. Change or delete the rule first. / A change made through ${name} is still in force. Roll it back in Response, or wait until it expires, then delete the connection. | `DELETE /response/catalog/{id}`; `DELETE /core/connections/{id}` |
| `ip_in_use` | 409 | IP ${ip} belongs to device ${assetName(clash)} in the inventory. Pick an unused IP. | 4 endpoint (/honeypot); `PUT /core/network/management` ("… is already used by a device in the inventory or by a decoy. Pick a free address.") |
| `ip_not_current` | 409 | This box no longer reaches the Internet through ${ip}; it was last seen ${time}. Scans of it are paused until the box uses it again. | `POST /exposure/targets/{id}/scan`; `POST /scans/runs` (check at scan time of the IP, `exposure` INV-13); `PUT /exposure/targets/{id}/terms` (a paused IP cannot accept the testing terms) |
| `limit` | 409 | Up to 30 rules. | `POST /response/catalog`; `POST /response/rules`; `POST /response/templates/{id}/clone`; `POST /response/actions/{id}/approve` (a `blocklist_add` item refused when the block list already holds 10 000 entries) |
| `limit_reached` | 409 | The box can hold 32 Trap IPs. Delete one before adding another. | `POST /honeypot/trap-ips` |
| `module_off` | 409 | The module for this role is off. / The External exposure module is off, so the box cannot scan. An admin can turn it on in Settings, Modules. | `POST /exposure/targets/{id}/scan` while the exposure module is off or was switched off while the gate or the scan ran (the scan module's runner follows exposure's switch); sensor link 8444 (`core/sensorlink`); `POST /response/me/identities/{channel}/code` on a chat channel while notify is off. `/core/mcp*` no longer uses it: off, they are 404 |
| `need_decoys` | 409 | Scan detection needs at least two Trap IPs that are on. Add a Trap IP first. | `POST /honeypot/test-scan` |
| `no_devices` | 409 | No device in the inventory matches (agent sample data). | `POST /inventory/agents/tokens/{id}/sample-data`; `POST /inventory/agents/wazuh/sample-data` |
| `no_source` | 409 | This incident names no single address Vedette can act on. Nothing was requested. | `POST /response/incidents/{id}/request`: not a trap incident, a test hit, or the hit is gone |
| `incident_resolved` | 409 | This incident is resolved, so nothing is offered. Reopen it in Incidents to act on it. | `POST /response/incidents/{id}/request` |
| `not_same_device` | 409 | These are two machines: an agent reports from each of them. Keep them separate; delete a device only when its machine is gone. | `POST /inventory/devices/{id}/merge`; `refusal` of `GET /inventory/devices/{id}/merge-preview` |
| `only_address` | 409 | This is the device's only address, so there is nothing to split off. Delete the device when it is not there. | `POST /inventory/devices/{id}/split` |
| `agent_address` | 409 | This device's agent reports from this address, so it stays with the agent's machine. Split off the device's other addresses instead. | `POST /inventory/devices/{id}/split`: the interface an osquery node bound to the device last reported from, or an address or MAC a Wazuh agent was delivered at (`addresses[].agent`) |
| `not_toggleable` | 409 | This engine has no switch of its own: it follows nmap-discovery / it runs as a step of another scan. | `PATCH /scanning/engines/{id}` (nmap-versions, snmp, zap) |
| `source_unconfirmed` | 409 | The source of a scan or of a UDP request can be forged: it completed no connection, so this address may belong to someone innocent. Confirm on the device first. Nothing is offered for it. | `POST /response/incidents/{id}/request` (honeypot): a scan hit, or a UDP trap hit (TFTP, NTP, SIP), whose source has no TCP service hit within the hour around it |
| `no_pending` | 409 | No key is waiting for confirmation. Click "Turn on two-factor authentication" to create one. | `POST /core/account/2fa/confirm` |
| `no_previous` | 409 | No previous version to go back to. | `POST /core/updates/rollback` |
| `not_email_method` | 409 | This account does not use email codes. | `POST /auth/login/resend-code` |
| `maintenance` | 409 | Held: maintenance window "…" is active. Nothing was changed. | `POST /response/actions/{id}/approve` (item refused right before it runs); `POST /response/proposals/{id}/request`; rule runs (resp_log); `POST /response/incidents/{id}/request` |
| `never_touch` | 409 | … matches the never-touch list (…). Nothing was changed. Also: The never-touch list could not be read in full (the box's own addresses or the inventory are not available), so nothing was changed. | rule runs and `POST /response/proposals/{id}/request` (planning); `POST /response/actions/{id}/approve` (item refused right before it runs); `POST /response/incidents/{id}/request` |
| `not_publishable` | 409/400 | 192.168.1.5 is not a public address (private, loopback, link-local, carrier-grade NAT 100.64.0.0/10, multicast or reserved). The block list only carries public addresses, so your firewall never blocks your own network. … Nothing was changed. (not `not_public`, which is exposure's 400 for the box's own address) | 409: rule runs and manual runs (resp_log; only that action is dropped, the rule's others go ahead); `POST /response/proposals/{id}/request`; AI proposals; `POST /response/actions/{id}/approve` (a `blocklist_add` item made before the check is refused right before it runs). 400: `POST /response/rules`, `PUT /response/rules/{id}`, `POST /response/rules/simulate` (a fixed address in a block list action) |
| `not_executed` | 409 | Only an executed action can be rolled back. | module response (shared validator) |
| `not_on` | 409 | Two-step sign-in is already off for this user. | `POST /core/users/{id}/2fa/reset` |
| `not_pending` | 409 | This request is already ${a.status.replace('_', ' ')}. This decision changed nothing. | module response (shared validator); `decided` with the same message from a chat button, Zalo reply code or email link |
| `withdrawn` | 409 | This request was withdrawn without a decision: the finding moved to … after a device split. Nothing was changed. A new request for it is waiting for a decision: … (`new_request_id`) / A new plan is written for the finding on its new device; ask again from that plan in Vedette. | `POST /response/actions/{id}/approve`, `POST /response/actions/{id}/reject`, `POST /response/approve/{token}`, chat decisions (response INV-25) |
| `nothing_to_rerun` | 409 | The newest scan of this target has no OpenVAS step that was stopped or did not finish, so there is nothing to run again. Run a deep scan instead. | `POST /exposure/targets/{id}/openvas` |
| `not_running` | 409 | This scan has already ended, so there is nothing to stop. Also: No scan is running now. | `POST /scans/runs/{id}/stop`; `POST /runs/{id}/stop` ("This run has already ended, so there is nothing to stop."); `POST /exposure/scan/stop` |
| `not_resumable` | 409 | This run cannot be resumed: it has no work left, or its engine cannot go on from where it stopped. | `POST /runs/{id}/resume` |
| `not_started` | 409 | Its module is off. (the schedule's owner gives the reason it does not start now) | `POST /schedules/{owner_key}/run` |
| `not_queued` | 409 | ${value} is not waiting in the scan queue. | `DELETE /exposure/targets/{id}/queue` (exposure INV-36) |
| `not_verified` | 409 | Verify ownership first; only then can this target be scanned. | `POST /exposure/targets/{id}/scan` |
| `nothing_scheduled` | 409 | No reboot is scheduled. | `DELETE /core/updates/os/reboot` |
| `nothing_to_install` | 409 | There are no updates waiting to install. | `POST /core/updates/os/install` |
| `org_required` | 409 | Fill in and save the organisation details first, then create the report. | `POST /reports/pdpl/generate` |
| `read_only` | 409 | This connection has no write tools, so it cannot carry out actions. | `POST /response/catalog` |
| `report_required` | 409 | Create the report first; the AI needs something to comment on. | `POST /reports/pdpl/ai-summary` |
| `rule_off` | 409 | Switch the rule on first. | `POST /response/rules/{id}/manual` |
| `rule_rate_limited` | 409 | Limit of N runs per hour reached. | rule runs (resp_log only: an event is not an API call) |
| `same_approver` | 409 | You already approved this request. A second, different person must approve it. | module response (shared validator) |
| `secret_lost` | 409 | A saved secret was not restored (the backup was restored without its decryption key, or the box key changed). Enter it again. (Each endpoint has its own sentence, see the adjacent column.) | A saved secret sealed with a different master key (`secrets.IsWrongKey`: the right key version and purpose; a row of another key version does not count). `POST /core/connections/{id}/test`: "The saved password, token or key of this connection was not restored (…). Open Edit, enter it again and save, then test the connection. Nothing was sent." (nothing is sent, saves `status=error`, audit `connection.test` "failed: secret_lost"). `POST /inventory/agents/wazuh/test`, `PUT /inventory/agents/wazuh` when the password is left blank: "The saved Wazuh password was not restored (…). Open Edit, enter the password again and press Save. Nothing is pulled until then."; typing the password again clears it. `GET /response/blocklist`: "The block list address could not be read on this box (…). Your firewall keeps using its current address. Press Regenerate token to make a new one, then paste it into the firewall." (the token is not replaced on read; the firewall keeps pulling the old address because only the hash is compared; `POST /response/blocklist/token` replaces it, adds a WARN and the administrator's `box-key.replace` audit). `POST /logs/siem/test`, `PUT /logs/siem` when the signing key is left blank while the webhook is enabled (only the `json` format and `enabled`, the webhook is signed with the key; turning it off, switching or changing the URL still saves): "The saved signing key of the SIEM webhook was not restored (…). Enter the signing key again (…) and press Save. Nothing is sent to the SIEM until then." (nothing is sent; `GET /logs/siem` returns `secret_lost: true`; the forwarder stops sending, one WARN, no retry; saving a new key resumes sending). `POST /ai/profiles/test`, `POST /ai/profiles/models`, `PUT /ai/profiles/{id}` when the key is left blank: "The saved API key of the AI profile "X" was not restored (…). Open Edit, enter the key again and save, then test it. Nothing was sent." (`GET /ai/profiles` returns `key_lost: true`, `usable: false`; delete still works); an AI job (`POST /ai/cve/{id}/explain`, `POST /ai/ask`, …) when no other profile accepts it: "The saved API key of the AI profile "X" was not restored (…), so <job> did not run and nothing was sent. …" (if there is a fallback the job runs on the fallback); `PUT /ai/assignments` assigning a profile that lost its key to a new job, `PUT /ai/knowledge/settings` choosing it as the index profile: "… so it cannot take <job> (the knowledge index). Open Edit on the profile and enter the key again first. Nothing was saved." |
| `selection_differs` | 409 | The second approver must approve the same actions as the first. | module response (shared validator) |
| `set_in_box_network` | 409 | On this box the card the sensor listens on is chosen in Settings → Box network. Backend [PROPOSED]: when `vedette-host` is present (an appliance, or a configured host that cannot supply the card list), the host applies the SPAN card; nothing changes. | `PATCH /inventory/sensors/{id}` |
| `skill_off` | 409 | The "Ask your data" skill is turned off. Turn it on in Settings, AI assistant, Skills. | `POST /ai/ask` |
| `sso_user` | 409 | This account signs in through SSO. Its password, two-step sign-in and role come from the identity provider. | `PATCH /core/users/{id}` (role), `POST /core/users/{id}/reset-password`, `POST /core/account/password`, `POST /core/account/2fa/start`, `POST /core/account/2fa/email/start` ((5)) |
| `sso_wrong_address` | 409 | SSO sign-in works at ${address}. Open Vedette there to sign in with SSO. | `POST /auth/oidc/start` from an address other than the redirect URI saved in Settings, Users; `address` in the body |
| `sso_secret_lost` | 409 | SSO sign-in cannot be used: the SSO client secret could not be read on this box (it was restored without the decryption key, or the box key changed). An administrator signs in with a password and enters the client secret again in Settings, Users, SSO sign-in. | `POST /auth/oidc/start`, `POST /auth/oidc/callback`: the client secret was sealed with a different master key; the user is not redirected to the IdP |
| `too_soon` | 409 | The network was swept a moment ago. Start another sweep in ${n} minutes. (at least 10 minutes between two sweeps; `retry_after` in seconds) | `POST /scanning/engines/nmap-discovery/run` |
| `tool_unavailable` | 409 | The tool of the action is missing, disabled or its connection is off; or the write tool (or undo tool) of the action was changed after the request was made. | `POST /response/proposals/{id}/request`; `POST /response/actions/{id}/approve`; `POST /response/actions/{id}/rollback` |
| `trap_off` | 409 | No Trap IP that is on has ${LABEL[service]}. Add ${LABEL[service]} to a Trap IP, or turn one on, before testing. | `POST /honeypot/test-hit` |
| `proof_missing` | 409 | The proof of ${t.value} is not found now, so it cannot be scanned. Put the token file back (or set the reverse DNS name), then check again. Also: the same sentence for a typed IP that is not sent to Shodan | `POST /exposure/targets/{id}/scan`; `POST /exposure/targets/{id}/outside` |
| `txt_missing` | 409 | The DNS TXT record vedette-verify=${t.token} is no longer on ${t.value}, so it cannot be scanned. Add the record back, t | `POST /exposure/targets/{id}/scan` |
| `dpkg_locked` | 409 | Another package manager is running on the box (for example automatic updates). Try again in a minute. Backend [PROPOSED]: host `dpkg_locked`, with `retry_after`. | `POST /core/updates/os/check`; `POST /core/updates/os/install` |
| `dpkg_inconsistent` | 409 | The package database on the box is in a broken state. Run dpkg --audit on the box and repair it before updating. Backend [PROPOSED]: host `dpkg_inconsistent`. | `POST /core/updates/os/install` |
| `low_disk` | 409 | There is not enough free disk space for this. Free some space on the box and try again. Backend [PROPOSED]: host `low_disk`. | `POST /core/updates/os/install`; `GET /core/data/backup`; `PUT /exposure/greenbone` (enabling Greenbone with less than 60 GB free, with the measured number: "This box has 41.3 GB of free disk space; Greenbone needs at least 60.0 GB free.") |
| `low_memory` | 409 | This box has 5.9 GB of memory; OpenVAS needs at least 6.0 GB. Or, under 8 GB: This box has 7.1 GB of memory and 0.0 GB of swap; with less than 8.0 GB of memory OpenVAS needs at least 2.0 GB of swap for its first feed load. (the measured MemTotal and SwapTotal, decimal GB rounded down) | `PUT /exposure/greenbone` |
| `shared_address` | 409 | This box reaches the Internet through carrier-grade NAT (its gateway 100.64.0.1 is in 100.64.0.0/10), so 203.0.113.10 is probably shared with your provider's other customers and its open ports are the provider's. The disruptive checks cannot be accepted for it; accept the deep scan only if your provider confirms the address is yours alone. | `PUT /exposure/targets/{id}/terms` |
| `no_check_yet` | 409 | The box has not looked for operating system updates yet. Click Check now. Backend [PROPOSED]: host `no_check_yet`. `GET /core/updates/os` no longer returns this code: a box that has not checked yet returns 200 with `os` null; settings and reboot also return the state with `os` null. | `POST /core/updates/os/install` |
| `not_appliance` | 409 | This install has no operating system helper (container-only install), so Vedette cannot update or back up the operating system from here. Backend [PROPOSED]: there is no `vedette-host` socket, or the OS release is outside the host's support table. Also the answer when enabling a module that needs the host (`needs_host`) on a container-only install: "Module {id} needs vedette-host, which only the appliance install has. This is a container-only install, so it cannot run here." (the mock has this branch). | `GET /core/updates/os`; `POST /core/updates/os/check`; `POST /core/updates/os/install`; `PATCH /core/updates/os/settings`; `POST /core/updates/os/reboot`; `DELETE /core/updates/os/reboot`; `GET /core/data/backup`; `POST /core/updates/apply`, `POST /core/updates/rollback` (no `vedette-host`, or core does not run from a pinned container: "Vedette itself does not run from a pinned container on this box, so it cannot update itself from here."); `PATCH /modules/{id}`, `POST /core/setup` (module `needs_host` on a container-only install); `PATCH /scanning/engines/{id}` |
| `reboot_limit_reached` | 409 | The box has already rebooted three times in 24 hours. Wait before rebooting again. Backend [PROPOSED]: host `reboot_limit_reached`. | `POST /core/updates/os/reboot` |
| `rebooting` | 409 | The box is rebooting. Wait for it to come back, then try again. Backend [PROPOSED]: host `rebooting`. | `GET /core/updates/os`; `POST /core/updates/os/check`; `POST /core/updates/os/install`; `PATCH /core/updates/os/settings`; `POST /core/updates/os/reboot`; `DELETE /core/updates/os/reboot`; `GET /core/data/backup` |
| `pending_confirm` | 409 | A network change is waiting for confirmation. Confirm or cancel it in Settings, Box network, then try again. Backend [PROPOSED]: host `pending_confirm` (the write lock is held by a run in `awaiting_confirm`) or `net_pending_confirm`; the host's run id is not exposed. | `POST /core/updates/os/check`; `POST /core/updates/os/install`; `PATCH /core/updates/os/settings`; `POST /core/updates/os/reboot`; `DELETE /core/updates/os/reboot`; `GET /core/data/backup` |
| `management_count` | 409 | Exactly one interface must be the management interface; you set ${n}. The management interface is the one you reach this page through. | `PUT /core/network/interfaces` |
| `management_fixed` | 409 | ${cur.name} is the management interface and you are using this page through it. It cannot be changed here; set the management address instead. | `PUT /core/network/interfaces` |
| `span_count` | 409 | Only one interface can capture mirrored traffic. Set the others to unused. | `PUT /core/network/interfaces` |
| `span_on_management` | 409 | ${iface.name} is the management interface. SPAN needs its own port: it listens with no IP address, and mirrored packets would reach your management network. Backend [PROPOSED]: also the host's `same_iface`. | `PUT /core/network/span` |
| `change_pending` | 409 | A change is waiting for confirmation. Confirm it from the new address or cancel it first. Backend [PROPOSED]: host `pending_confirm` when the write lock is held by a run in `awaiting_confirm`; the host's run id is not exposed (the other `core` paths receive the same host code under the name `pending_confirm`). | `PUT /core/network/management`; `PUT /core/network/span`; `PUT /core/network/ntp`; `PUT /core/network/interfaces` |
| `confirm_required` | 409 | This changes the address you use to reach the box. Open https://${ip}:8443 within 5 minutes and confirm, or the box returns to the old settings. You will need to sign in again at the new address. The body has `new_ip` (null with DHCP: the DHCP server picks the address, and the message says "Find the new address your DHCP server gives the box, open it on port 8443…"). The same pattern is used for `POST /core/updates/rollback`. | `PUT /core/network/management` |
| `nothing_pending` | 409 | No management change is waiting for confirmation. (timed out: "The time to confirm ran out and the box went back to the old settings. Make the change again.") Backend [PROPOSED]: host `not_awaiting_confirm`, `not_confirmed`. | `POST /core/network/management/confirm`; `POST /core/network/management/revert` |
| `address_conflict` | 409 | Another device already uses this address. Backend [PROPOSED]: host `address_conflict`, returned from the run after the ARP probe; nothing is left waiting for confirmation. | `PUT /core/network/management` |
| `net_backend_unsupported` | 409 | This box's network files were not set up by the Vedette installer, so Vedette cannot change them. Reinstall with the installer or change the network on the box itself. Backend [PROPOSED]: host `net_backend_unsupported`. | every `PUT /core/network/*` change |
| `span_has_address` | 409 | That port has an IP address, and a SPAN port must have none. Remove the address from that port first, or choose another port. Backend only (host `span_has_address`). | `PUT /core/network/span`; `PUT /core/network/interfaces` |
| `span_not_physical` | 409 | Only a physical network card can be the SPAN port, not a VLAN, bridge, bond or virtual interface. Backend only (host `span_not_physical`). | `PUT /core/network/span`; `PUT /core/network/interfaces` |
| `connectivity_check_failed` | 409 | The box could not reach the network with the new settings, so it went back to the old ones. Check the address, prefix length and gateway, then try again. Backend only (run `reverted`). | `PUT /core/network/management` |
| `reverted_by_reboot` | 409 | The box restarted before the change was confirmed, so it came back on the old address. Backend only (run `reverted`). | `POST /core/network/management/confirm` |
| `management_not_set` | 409 | Vedette has not set up this box's network yet. Save the management address first, then change the other settings. Backend only: the host has not written any configuration yet, so there is nothing to merge into. | `PUT /core/network/span`; `PUT /core/network/ntp`; `PUT /core/network/interfaces` |
| `too_many_tokens` | 409 | There are already 500 enrollment tokens, the most there can be. Use Remove unused tokens (every token with no machine, made over an hour ago) or revoke a token you no longer need, then create the install command again. | `POST /inventory/agents/tokens` (agent-intake INV-14) |
| `wazuh_changed` | 409 | The Wazuh connection was changed or removed while this was checked. Enter the password and save again. | `PUT /inventory/agents/wazuh` with a blank password while another Save or Delete ran (agent-intake) |
| `previous_revoked` | 409 | The previous version has been withdrawn by the project, so the box will not go back to it. Backend only: host `previous_revoked`; also `run.error` when the host refuses at run time. | `POST /core/updates/rollback` (`run.error`) |
| `rollback_not_allowed` | 409 | The running version cannot go back that far: its database is not readable by the previous version. Check the release notes. Backend only: host `rollback_not_allowed`. | `POST /core/updates/rollback` (`run.error`) |
| `rollback_backup_missing` | 409 | The copy of the database from before the update is no longer on the box, so the rollback cannot put it back. Backend only: host `rollback_backup_missing`. | `POST /core/updates/rollback` (`run.error`) |
| `rollback_is_upgrade` | 409 | The previous version is newer than the running one. Install it as an update instead. Backend only: `core.previous` is higher than the running version (after a rollback), checked before any host call. | `POST /core/updates/rollback` |
| `current_version_unknown` | 409 | The box has no record of which version it runs, so it cannot switch versions yet. See the RUNBOOK (first version record). Backend only: the host has not recorded the running version (bootstrap). | `POST /core/updates/apply`, `POST /core/updates/rollback` |
| `approver_not_ready` | 409 | This message went to one approver, who can no longer approve (why). It was not sent again. | `POST /notify/history/{id}/resend` (module notify INV-11) |
| `telegram_busy` | 409 | Another program is already reading this bot's messages (a webhook is set, or other software uses the same token). Type the Chat ID by hand, or stop the other reader and try again. Also: Approval buttons are on for this bot, so Vedette is already reading its messages. Switch approvals off and save, press Find my chat, then switch them on again; or type the Chat ID by hand. | `POST /notify/telegram/chats` |

#### HTTP 412 (1 code)

| Code | HTTP | Sample message (EN, from the mock) | Endpoint |
|---|---|---|---|
| `transition_pending` | 412 | An update of Vedette is waiting to be completed or could not be recovered, so the box cannot be wiped now. Nothing was deleted. See the RUNBOOK (update journal) and finish or roll back the update first. (backend only: the host answers it to `backup.purge`) | `POST /core/data/purge`; as 409 with "An earlier version change on the box has not been completed yet. Wait a few minutes; if it stays, see the RUNBOOK (update journal, or "vedette-host self-update stopped half way")." in `run.error` of `POST /core/updates/apply` and `/rollback` and for the other host calls (also every helper action after a system helper update that stopped half way) |

#### HTTP 413 (1 code)

| Code | HTTP | Sample message (EN, from the mock) | Endpoint |
|---|---|---|---|
| `logs_too_large` | 413 | These logs are over 128 MB. Choose a shorter date range or fewer categories. (backend only: the mock has no size limit) | `GET /core/logs/export` |

#### HTTP 421 (1 code)

| Code | HTTP | Sample message (EN, from the mock) | Endpoint |
|---|---|---|---|
| `misdirected_request` | 421 | This address is not one Vedette answers to. Open it with the name or address it was set up with. | every request whose `Host` header is outside the allow list (flag `-hosts`; by default the loopback names and the names in the certificate; with a self-signed certificate only addresses, single-label names and names ending in `.local`/`.lan`/`.home.arpa`/`.internal`), returned **before** routing, including paths outside `/api/v1`. New backend code [PROPOSED]: protection against DNS rebinding. A browser opening a page (GET/HEAD with `text/html` in `Accept`, path outside `/api/`) gets the same 421 as a short HTML page instead of JSON |

#### HTTP 422 (2 codes)

| Code | HTTP | Sample message (EN, from the mock) | Endpoint |
|---|---|---|---|
| `wazuh_auth` | 422 | Wazuh refused the user name or password. Check the read-only API user you created. | module inventory (shared validator) |
| `wazuh_forbidden` | 422 | Wazuh signed the user in, but it may not read the agents or their inventory. Give its role the agent:read and syscollector:read actions on agent:id:* (the steps above). | `POST /inventory/agents/wazuh/test`, `PUT /inventory/agents/wazuh` (agent-intake) |

#### HTTP 429 (5 codes)

| Code | HTTP | Sample message (EN, from the mock) | Endpoint |
|---|---|---|---|
| `budget_reached` | 429 | This month's AI token budget (the box's or a profile's) is used up; the call is not made, or a question whose own turns used it up stops partway and says so. Also a scheduled AI job (response plans) from 80 % of the month's budget spent. With `retry_after` (seconds until the new budget day) and `Retry-After`. | module ai (shared validator) |
| `rate_limited` | 429 | ${value} was scanned at ${time}. Scan it again after ${time}: at most one scan of a target every 10 minutes. (`POST /exposure/targets/{id}/scan`, backend only) / Too many verification attempts (limit ${MAX_ATTEMPTS_PER_HOUR} per hour). Try again in about ${wait} minute${wait === 1  Also: more than 10 model lists a minute by one admin (`POST /ai/profiles/models`). Also: more than 8 email sign-ins open at once (`POST /notify/email-signin`). | module exposure, response (shared validator) ; `POST /auth/login`; `POST /auth/login/resend-code` (with `retry_after` and `Retry-After`); `GET /core/data/backup` (one download per minute per box, with `retry_after` and `Retry-After`); `POST /core/setup` (wrong setup code); the password of a signed-in user (`/core/account/password`, `/core/account/2fa/{start,email/start,disable}`); `GET /core/logs/export` (backend: one download a minute); agent-intake (with `retry_after` and `Retry-After`): `POST /intake/osquery/{enroll,config,log,status}` when one source fails authentication more than 10 times a minute, or one machine sends more than 6 `config` / 12 `log` a minute, or re-enrols the same (token, `host_identifier`) within 60 seconds; `GET /install/osquery/{file}` when 4 package downloads are already running at once (`Retry-After: 5`); module ai: loop circuit breaker, an AI job called more than 30 times in one minute; the rest of the month's AI budget is currently reserved by another call, not yet used up (with `retry_after` 15) |
| `resend_too_soon` | 429 | Wait ${wait} seconds before asking for a new code. | module core (shared validator) |
| `too_many_codes` | 429 | Too many codes were sent in the last hour. Try again later. | module core (shared validator) |
| `too_many_nodes` | 429 | This enrollment token already has the most machines it can have. Revoke it and make a new one. | `POST /intake/osquery/enroll` when the token already has 500 machines or the box already has 5,000 machines (agent-intake INV-14; with `retry_after` 3600 and `Retry-After`); machine to machine, osquery only logs and retries |

#### HTTP 502 (27 codes)

| Code | HTTP | Sample message (EN, from the mock) | Endpoint |
|---|---|---|---|
| `idp_unreachable` | 502 | Vedette cannot reach the identity provider at ${issuer}. Try again; if it keeps failing, sign in with your email and password or ask an administrator. | `POST /auth/oidc/start` (discovery), `POST /auth/oidc/callback` (token endpoint, keys) |
| `provider_error` | 502 | The AI provider answered, but not in a way Vedette can use. Check the model name and the address. / The AI provider returned an error for explaining findings (Claude: provider refused the request (HTTP 400): …). | `POST /ai/profiles/test` and later AI calls; different from `unreachable` (could not connect). AI job calls (`POST /findings/{id}/ai`, `POST /ai/cve/{id}/explain`, `POST /ai/cve/{id}/news`, `POST /ai/ask`, `POST /ai/logs/digest`, `POST /reports/weekly/ai-summary`, `POST /reports/pdpl/ai-summary`): name the profile, the error kind, the HTTP status and the provider's own words with keys filtered out (≤ 200 characters) |
| `ai_cut_off` | 502 | The AI's answer was cut off at the output limit (12,000 tokens), so it was not used. Try again; if it keeps happening, use a model for explaining findings that writes shorter answers. | `POST /findings/{id}/ai`, `POST /ai/cve/{id}/explain`, `POST /ai/cve/{id}/news`, `POST /ai/ask`, `POST /ai/logs/digest`, `POST /reports/weekly/ai-summary`, `POST /reports/pdpl/ai-summary`: the provider stopped at the output token cap (`stop` = `max_tokens`) even after a retry with a doubled cap |
| `ai_bad_format` | 502 | The AI answered, but not in the format Vedette needs, so the answer was discarded. Try again, or use a stronger model for this job. | `POST /findings/{id}/ai`, `POST /ai/cve/{id}/explain`, `POST /ai/cve/{id}/news`, `POST /ai/ask`, `POST /ai/logs/digest`, `POST /reports/weekly/ai-summary`, `POST /reports/pdpl/ai-summary`: the answer is complete but does not pass the job's parser; also when Ask's tool loop runs out of turns without an answer |
| `address_refused` | 502 | ${cur.target} now points to a loopback address, so Vedette did not connect. Check the name in your DNS. (the outbound address policy at dial time: loopback, link-local including the metadata address, multicast, unspecified, the box itself, IPv6 forms that carry an IPv4 address) | `POST /core/connections/{id}/test` |
| `device_error` | 502 | ${cur.target} was reached, but the device refused the sign-in (HTTP 401). (the device answered and said no: refused sign-in, an HTTP status, an answer over the cap, a CLI error line, an MCP error; one cleaned line, never a secret) | `POST /core/connections/{id}/test` |
| `discovery_failed` | 502 | Cannot read ${c.issuer}/.well-known/openid-configuration. Check the issuer and the network path from the box to the IdP. | `POST /core/oidc/test` |
| `pin_mismatch` | 502 | The certificate of ${cur.target} is not the one pinned at the first test. Nothing was sent. If you changed the device, edit this connection, turn on "Forget pinned key", save, then test again. | `POST /core/connections/{id}/test` |
| `unreachable` | 502 | Could not connect to ${cur.target}. Check the address, the box's network and the firewall. / The certificate-transparency search (crt.sh) did not answer, so the scan stopped and nothing was saved. Try again in a few minutes. / The scan did not finish within 5 minutes, so nothing was saved. Try again later. | `POST /exposure/targets/{id}/scan`; `POST /exposure/box-ip/verify` (the public IP services); `POST /core/connections/{id}/test` (formerly `POST /ai/connections/{id}/test`); `POST /ai/profiles/test`; AI job calls when every request sent could not reach the provider (`POST /findings/{id}/ai`, `POST /ai/cve/{id}/explain`, `POST /ai/cve/{id}/news`, `POST /ai/ask`, `POST /ai/logs/digest`, `POST /reports/weekly/ai-summary`, `POST /reports/pdpl/ai-summary`) |
| `wazuh_tls` | 502 | The Wazuh certificate changed since it was saved, so the saved password was not sent. Open Edit and press Save to trust the new one, or check what answers at that address. | `POST /inventory/agents/wazuh/test` with the saved password (agent-intake); the pull shows the same as the card's error |
| `wazuh_bad_reply` | 502 | The Wazuh server answered in a way Vedette does not understand (${what}). Check that the address is the Wazuh server API, port 55000 by default. | `POST /inventory/agents/wazuh/test`, `PUT /inventory/agents/wazuh` (agent-intake; never the server's own text) |
| `wazuh_unreachable` | 502 | Could not reach ${u.origin}. Check the address and port (55000 by default) and that this box may connect to the Wazuh se | module inventory (shared validator) |
| `apt_failed` | 502 | The package manager failed. See the update output for the reason. Backend [PROPOSED]: host `apt_failed`, `stale_check`. | `POST /core/updates/os/check` |
| `effect_not_verified` | 502 | The change was made but could not be confirmed on the box. Check the setting again. Backend [PROPOSED]: host `effect_not_verified`. | `PATCH /core/updates/os/settings` |
| `health_check_failed` | 502 | The updates were installed but a health check failed afterwards. Check the services on the box. Backend [PROPOSED]: host `health_check_failed`; in an install run it appears on the last line of `OsRun.lines`. | `POST /core/updates/os/check` |
| `host_error` | 502 | The operating system helper could not do this. The details are in the box log. Backend [PROPOSED]: every remaining host code (`internal`, `timeout`, `command_failed`, `backup_unknown`, ...) or an unusable answer; the details are only in the log. | `GET /core/updates/os`; `POST /core/updates/os/check`; `POST /core/updates/os/install`; `PATCH /core/updates/os/settings`; `POST /core/updates/os/reboot`; `DELETE /core/updates/os/reboot`; `GET /core/data/backup`; `PUT /exposure/greenbone` (turning Greenbone off when its containers did not stop: "Greenbone is off for scans, but its containers did not stop: <reason>.") |
| `snapshot_rejected` | 502 | The helper could not take over a copy of the box's data. Check the box clock and the permissions of the data folder, then try again. Backend [PROPOSED]: host `snapshot_required`, `snapshot_invalid`, `db_unreadable`, `key_unreadable` (a deployment error or clock skew, not a user error). | `POST /core/updates/os/install`; `GET /core/data/backup` |
| `snapshot_failed` | 502 | Vedette could not write a copy of its data to the box's data folder. Check that the folder is writable and the disk is healthy, then try again. Backend [PROPOSED]: core could not write the snapshot (the `snapshots/` folder is not writable, the key file is unreadable, an I/O error); a full disk or less free space than the database size is `low_disk` (409). Never 500. | `POST /core/updates/os/install`; `GET /core/data/backup` |
| `update_check_failed` | 502 | The update information did not pass Vedette's signature checks, so nothing new is offered and nothing was installed. The details are in the box log. Backend only: the index or manifest has a bad signature, a bad shape, is over 256 KiB, has a `sequence` that goes backwards, a different `manifest_sha256`, a manifest URL outside the project's release store, or a revoked key. Other messages with the same code: the stored index no longer verifies ("The update information this box stored earlier no longer verifies…"), a newer `schema` ("…cannot read the newer update information. Reinstall it with the installer of a newer release."), a build with no keys ("…has no release signing keys…"). Text from the external server is never repeated. | `POST /core/updates/check` |
| `update_not_published` | 502 | No release found yet: the release source answered, but no update information is published there. This is not a network problem and nothing needs fixing on the box. **No longer sent** (a 404 for the index when the box has never stored an index is now a good check, 200, with nothing offered); it remains only in a `last_check_error` stored by an older version, and the next good check clears it. Earlier behaviour, backend only: the release source returned 404 for the index (or its signature): no release has been published at the source yet, as when running a `-test.N` build; a 404 for the manifest of a version that the index names is still `update_source_unreachable`; it is not a network error, so it does not suggest checking github.com. | `POST /core/updates/check` |
| `revert_failed` | 502 | The box could not go back to the old network settings by itself. The settings saved on the box are the old ones, so it comes back on the old address when it restarts, and it restarts by itself in about a minute. Backend only; `pending.reboot_at` is for the GUI. | `POST /core/network/management/revert`; `POST /core/network/management/confirm` |
| `netplan_apply_failed` | 502 | The operating system could not apply the network settings. If anything was changed it was put back; the details are in the box log. Backend only. | `PUT /core/network/*` |
| `ntp_not_applied` | 502 | The time service did not take the new NTP servers. The old list was kept. Backend only. | `PUT /core/network/ntp`; `PUT /core/network/management` |
| `arp_probe_failed` | 502 | The box could not check whether the new address is free, so nothing was changed. Try again. Backend only. | `PUT /core/network/management` |
| `pending_invalid` | 502 | The box could not trust its record of the waiting change, so it went back to the old settings. Make the change again. Backend only. | `POST /core/network/management/confirm` |
| `confirm_failed` | 502 | The box could not save the new settings, so it went back to the old ones. Make the change again. Backend only. | `POST /core/network/management/confirm` |
| `telegram_failed` | 502 | Telegram did not answer: ${reason} | `POST /notify/telegram/chats` |

#### HTTP 500 (2 codes)

| Code | HTTP | Sample message (EN) | Endpoint |
|---|---|---|---|
| `internal` | 500 | Something went wrong on the box. Try again; if it keeps happening, send a bug report. | every endpoint, unexpected error (`core/server`; the details go only to the log together with `X-Request-Id`, not into the response) |
| `backups_already_deleted` | 500 | The backups held by the operating system helper were already deleted, but the data on this box could not be deleted. The data on this box is still there. Fix the problem described in the box log and delete all data again. (backend only: the purge failed after the helper step) | `POST /core/data/purge` |

#### HTTP 501 (1 code)

| Code | HTTP | Sample message (EN) | Endpoint |
|---|---|---|---|
| `not_implemented` | 501 | This part of the box is not built yet. | an operation that is in the contract but whose module has no backend yet (`oas.UnimplementedHandler`; the UI uses the mock for that module); `PUT /exposure/greenbone` when the box has no Greenbone ("Greenbone is not available on this box.") |

#### HTTP 504 (1 code)

| Code | HTTP | Sample message (EN) | Endpoint |
|---|---|---|---|
| `ai_timeout` | 504 | The AI did not finish in time. Ask a narrower question, or use a faster profile for this job. | `POST /findings/{id}/ai`, `POST /ai/cve/{id}/explain`, `POST /ai/cve/{id}/news`, `POST /ai/ask`, `POST /ai/logs/digest`, `POST /reports/weekly/ai-summary`, `POST /reports/pdpl/ai-summary`: every request sent timed out (90 s each), or the Ask question ran out of its 2 minutes |

#### HTTP 503 (7 codes)

| Code | HTTP | Sample message (EN, from the mock) | Endpoint |
|---|---|---|---|
| `risk_unavailable` | 503 | Vedette could not read the risk marks just now, so it cannot filter by risk. Try again in a moment, or remove the risk filter. (`retry_after` 5 and `Retry-After`; inventory INV-40: the findings module did not answer. Only a request **with** a `risk` filter gets it, never the unfiltered list; without the filter the list is served without markers and `risk_unavailable: true`.) | `GET /inventory/devices`; `GET /inventory/export.csv` |
| `server_busy` | 503 | The box is busy checking other sign-ins. Try again in a few seconds. | **Any operation that writes** when the database writer stays taken by another transaction for 5 s (`store.RequestWriteWait`, INV-29 of core: "The box is busy saving other changes. Try again in a few seconds.", `Retry-After: 5`, `retry_after: 5`; nothing was written); `POST /auth/login`; `POST /auth/login/resend-code`; `GET /response/blocklist/{token}.txt` (the store cannot be read: 503 with `Retry-After`, never an empty list, blocklist-format 6); `GET /intake/ca.pem` (agent-intake: the box CA was replaced and the leaf signed by the new one is not served yet; "The box certificate is being renewed. Try again in a minute.", `retry_after: 30` and `Retry-After`); `POST /ai/hooks/test` (module ai: 503 when another hook test is running and this one does not get a slot within the hook deadline, 5 seconds; message: "The box is busy testing another hook. Try again in a moment."; **no** `Retry-After`, as with logs; `modules/ai/CONTRACT.md` INV-12); `GET /logs/events` (module logs: 503 when 2 searches are already running at once and a third does not get a slot within 5 seconds, or when a search cannot finish its first stage (20,000 lines) within 5 seconds; a keyword search that runs longer than 5 seconds after the first stage is **no longer** a 503: it returns 200 with `searched_back_to` and `next_cursor`; message: "The box is busy searching the logs. Choose a shorter time range or a more specific keyword, then try again."; **no** `Retry-After` or `retry_after`: the GUI shows the error and a retry button; `modules/logs/CONTRACT.md`); every operation that must hash or check a password (`POST /core/users`, `/core/users/{id}/reset-password`, `/core/account/password`, `/core/account/2fa/disable`, `/core/setup`). New code **[PROPOSED]** (from a security review): at least one wait longer than 2 seconds, or the hashing queue is full. With `retry_after` (seconds) in `error` and `Retry-After`. Not `busy` (409, operating system update). An attempt refused because of load does **not** count towards the failed-sign-in limit |
| `twofa_email_unavailable` | 503 | The email channel cannot send two-step codes now. | `POST /auth/login`; `POST /auth/login/resend-code` |
| `host_unreachable` | 503 | The operating system helper (vedette-host) is not answering. (`POST /core/data/purge` answers it with status 502: a configured helper that holds the backups does not answer, its socket file missing included, and nothing is deleted.) Try again in a minute; if it keeps happening, check that the vedette-host service is running. Backend [PROPOSED]: the socket exists but does not answer, the host refuses this process, or `host_shutting_down`. | `GET /core/updates/os`; `POST /core/updates/os/check`; `POST /core/updates/os/install`; `PATCH /core/updates/os/settings`; `POST /core/updates/os/reboot`; `DELETE /core/updates/os/reboot`; `GET /core/data/backup`; `PUT /notify/channels/{type}` (webhook: the box address is not known yet because vedette-host has never answered) |
| `approver_check_unavailable` | 503 | Vedette could not check the approver just now. Try again in a moment. (`retry_after` seconds, `Retry-After` header, §8; the user directory or the link store did not answer.) | `POST /notify/history/{id}/resend` |
| `update_source_unreachable` | 503 | Could not reach the update source (<host>): <reason>. Try again later; if it keeps happening, check that the box can reach <host> over HTTPS. Backend only: a network error, a timeout (30 s per file), a redirect outside the GitHub hosts of PRIVACY flow 6, a refused redirect, an answer other than 200, a 404 for the index signature, a 404 for the index when the box has already stored an index, or a 404 for the manifest that the index names (a 404 for the index when the box has never stored an index is a good check). `<host>` is the configured source host; `<reason>` is fixed text per error kind (`unreachableReason`), and no text or status code from the network is copied. | `POST /core/updates/check` |
| `scanner_unavailable` | 503 | The vulnerability scanner is not available: the scan container or its scanner is missing. Check the box's services, then try again. | `POST /scans/runs`; the scheduled-scan and KEV re-scan jobs of `scan` (no worker heartbeat, or the heartbeat reports that nuclei or the template pack is missing); `POST /scanning/engines/nmap-discovery/run` (nmap); `POST /exposure/targets/{id}/scan` (the shared safety settings cannot be read, exposure INV-31); `POST /exposure/targets/{id}/openvas` ("OpenVAS cannot run now: …": off, starting, loading its feed, testing terms not accepted) |

## 4. Pagination, filtering, sorting

**Current state (mock):** most lists return everything (the SPA filters/sorts on the client). `total` exists on: `GET /core/audit`, `/ai/activity`, `/inventory/catalog`, `/logs/events`. No endpoint has `limit`/`cursor`. The targets of 1,000 devices, 50k IOCs and 7 days of logs (DATA_MODEL §8) force pagination on large lists.

**Convention [PROPOSED] (additive, does not break the existing contract):**

| Item | Rule |
|---|---|
| Parameters | `limit` (integer; default and maximum per the table below), `cursor` (opaque string, taken from the previous page's `next_cursor`). `offset`/`page` are not used (they drift when new rows arrive and are slow on the log table). |
| Response body | `{ items: [...], next_cursor: string \| null, total?: integer }`. `next_cursor = null` = end. `total` is returned only when counting is cheap (a small table or a filter on an index); never for `logs_event`. |
| Default order | Newest first (`ts DESC, id DESC`) for logs and history. Exception: **`GET /response/log` is oldest first** (the current contract, so the client can verify the hash chain from the start); paging uses a forward `cursor`, and the client carries the `hash` of the last row to the next page to continue the check. |
| `limit` out of range | Clamped to the allowed range (no error). `limit=0` or not a number → `400 bad_limit` (new code, add it to section 3.3 when implemented). |
| Expired / wrong cursor | `400 bad_cursor`. The cursor encodes the sort key, not an offset; it is signed with HMAC so it cannot be altered. **Unsigned exception:** `GET /logs/events`: the viewer can already read every row, so a forged cursor only moves the search to another place within the rows they may see; it is only an SQL parameter. |

| Endpoint | Default / maximum | Notes |
|---|---|---|
| `GET /logs/events` | 100 / 500 | key `events` (kept); adds `next_cursor` |
| `GET /core/audit`, `/ai/activity`, `/response/log`, `/honeypot/hits`, `/notify/history`, `/scans/probes`, `/scans/events`, `/ai/runs`, `/ai/asks` | 100 / 500 | |
| `GET /notify/incidents` | 500 / 500 | no `cursor` yet: returns the 500 newest incidents (the mock has no limit) |
| `GET /findings`, `/inventory/devices`, `/inventory/catalog` | 2,000 / 2,000 | the SPA currently loads once and filters on the client; kept until the GUI moves to pagination (open question 3) |
| Small configuration tables (channels, AI profiles, rules, log sources, hooks, traps…) | not paginated | ≤ 30–200 rows by the limits in the contract |

**Filtering:** query parameters are named after the field and compared for equality; several values are separated by commas (`categories=audit,ai`, as in `/core/logs/export`). `q` = free-text search (`/core/audit`, `/logs/events`, `/inventory/catalog`, `/feeds/search`). Time range: `from`, `to` (ISO UTC, **both ends inclusive**, like the mock's `inRange`). Unknown parameters are ignored, **except** a value of the wrong type/enum for a known parameter → 400. In use: `job`, `result`, `from`, `to` (`/ai/activity`); `q`, `user`, `group`, `from`, `to` (`/core/audit`); `window=24h|7d` (`/feeds/hot`); `window`, `source`, `q` (`/logs/events`); `asset` (`/findings`, `/honeypot/hits`); `finding` (`/response/plans`); `internal_only` (`/ai/assignments/suggestion`); `categories`, `from`, `to`, `format` (`/core/logs/export`).

**Sorting:** each endpoint has a fixed order, stated in its `summary`; there is no `sort` parameter yet. To sort by another column, add `sort=<field>` or `sort=-<field>` (indexed fields only, an allow list in `contract.ts`) **[PROPOSED]**; a wrong value → `400 bad_sort`.

## 5. Idempotency

Goal: a double click, a flaky network or a proxy resend must not create a copy or run an action twice.

**Current state:** the mock has no idempotency key; some actions are already **naturally idempotent** thanks to state: `POST /findings/{id}/applied` (once per item), `POST /response/actions/{id}/approve` (once per person: 409 `same_approver`/`not_pending`), `POST /response/proposals/{id}/request` (409 `already_requested`), `POST /scans/runs` (409 `already_running`), creating a device (409 `ip_in_use`/`hostname_in_use`/`duplicate_*`), `POST /response/actions/{id}/rollback` (409 `not_executed`).

**Convention [PROPOSED]:**

| Item | Rule |
|---|---|
| Header | `Idempotency-Key: <string of 8–64 characters [A-Za-z0-9_-]>` |
| Applies to | **Every POST that creates a resource** (returns 201) and POST actions with side effects outside the DB: `POST /scans/runs`, `/response/actions/{id}/approve\|reject\|rollback`, `/response/proposals/{id}/request`, `/response/rules/{id}/manual`, `/notify/history/{id}/resend`, `/notify/channels/{type}/test`, `/inventory/import`, `/core/users`, `/core/users/{id}/reset-password`, `/core/updates/apply\|rollback\|bundle`, `/core/updates/os/install`, `/core/mcp/tokens`, `/inventory/agents/tokens`, `/ai/ask`, `/ai/cve/{id}/explain\|news`, `/reports/weekly/send`. PUT/PATCH/DELETE are idempotent by semantics and need no key. |
| Client | The SPA generates a new key (`crypto.randomUUID()`) for **each user click** and reuses exactly that key when it retries by itself; the button stays locked after the click until a response arrives. |
| Server | Stores `(key, user_id, method, path, hash(body))` and the response for **24 hours** (a `core` table; not in `docs/SCHEMA.sql` yet, because the header is only proposed). Same key + same request → returns the stored response unchanged (same HTTP status), adding `Idempotent-Replay: true`. Same key + a different request (different body/path) → `409 idempotency_key_reuse`. The first request is still running → `409 idempotency_in_progress` with `Retry-After: 1`. |
| No header | Runs normally (not mandatory); the 409 constraints above remain the last line of defence. |
| Actions that produce approval requests, tokens, notifications | De-duplicated by business key, not by header: `resp_action.dedupe_key` (one open request per (target, action)), `notify_incident.dedupe_key`, `resp_rule_done` (DATA_MODEL sections 4.4 and 4.11). |

The new codes `idempotency_key_reuse` and `idempotency_in_progress` are added to section 3.3 when implemented.

## 6. Concurrency (ETag / If-Match)

Two administrators editing the same configuration must not silently overwrite each other (the mock does not protect against this).

| Item | Rule [PROPOSED] |
|---|---|
| ETag | `GET` of a resource or configuration object returns `ETag: W/"<first 16 hex of the SHA-256 of the canonical JSON of the body>"`. It is computed from the body, so **no version column is needed in the DB**. |
| `If-Match` | `PUT`, `PATCH`, `DELETE` on that resource accept `If-Match`. If it does not match the current version → `412 precondition_failed` with the standard error body (section 3.1); the client calls `GET` again to get the current version. |
| Phase | M2: **optional** (the server checks when the header is present; a missing header still passes). The SPA starts sending `If-Match` on the long edit forms (reaction rules, channels, AI profiles, custom feed sources, settings). Once the SPA sends it everywhere: mandatory for configuration `PUT` (missing → `428 precondition_required`). |
| Not applicable | Append-only tables (logs, observations); actions with a state machine (approve, status) are already protected by state checks (`not_pending`, `already_open`, `busy`). |
| Lists | `If-None-Match` on `GET` returns 304 (notably for `GET /response/blocklist/{token}.txt`, section 11.3). |

## 7. Authentication and authorization

### 7.1 Session (SPA)

| Item | Rule |
|---|---|
| Cookie | `__Host-vedette_session` (declared in `components.securitySchemes.session`): a random value of ≥ 32 bytes (base64url), `HttpOnly; Secure; SameSite=Strict; Path=/`. The server stores only the SHA-256 (`core_session.token_hash`). No domain prefix, no `Domain`. `__Host-vedette_csrf` is set at the same time (§7.2). After a successful sign-in a **trusted-device cookie `__Secure-vedette_device`** is also set: an HMAC-SHA-256-signed value (the box's key in `core_secret`) containing the user id, `cred_version`, a nonce and a 90-day expiry; `HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth/` (only the sign-in endpoints receive it). This is the third and last cookie of Vedette, **needed for sign-in security** (no tracking, it never leaves the box); changing or resetting the password invalidates every device cookie of the account. |
| Sign-in | `POST /auth/login` `{email, password, code?}` (public). Wrong email/password → 400 `invalid_credentials` (the same message for "no such account" and "wrong password"). An account with two-step but a missing `code` → **401 `twofa_required`** with `method` (`app`\|`email`; for `email`: `sent_to`, `resend_after`, and the server has sent the code). A wrong `code` → 400 `invalid_code` (app) / `wrong_code` / `too_many_tries` / `code_expired` (email). A disabled account → 403 `disabled`. A password set by an administrator that is over 72 hours old (and correct) → 400 `temp_password_expired`; while still valid the user can sign in but the session is restricted: every request except `GET /me`, `POST /core/account/password`, `POST /auth/logout` returns 403 `password_change_required` until the password is changed. A broken email channel → 503 `twofa_email_unavailable` (**never** falls back to password-only). An authenticator key that cannot be opened with the box's master key (restored without the decryption key) → 403 `twofa_reset_required` right after the correct password, with no code prompt, until an administrator resets two-step. A successful sign-in: creates a `core_session`, writes `auth.login`, sets `__Host-vedette_session`, `__Host-vedette_csrf` and `__Secure-vedette_device`. A request carrying a valid `__Secure-vedette_device` of **that same account** is counted per cookie (10 wrong tries / 15 minutes, with growing wait) and does **not** count towards, nor is blocked by, the per-address and /64 counters; a missing cookie, a bad signature, an expired one or one belonging to someone else gets no exemption. |
| Session end | An expired/revoked session → 401 `unauthenticated` on every non-public endpoint; the SPA returns to the sign-in page. Expiry: **4 hours of inactivity or 7 days from sign-in**, whichever comes first (`auth.IdleTimeout`, `auth.AbsoluteTimeout`); `last_seen` is refreshed at most once a minute. |
| Revocation | `DELETE /core/account/sessions/{id}`, `POST /core/account/sessions/revoke-others`; the session in use cannot be revoked (400 `current_session`, use `POST /auth/logout`). Session revocation on a security change (implemented in `core/auth`; a rule, no longer a proposal): changing the password → **every** session of that person ends and the response sets `__Host-vedette_session` + `__Host-vedette_csrf` of a new session for exactly that browser (the user stays signed in; a copy of the old cookie does not: the session identifier changes after a privilege change, OWASP); if the request carried a still-valid device cookie `__Secure-vedette_device` before the change, the response also sets a new device cookie for the new password (the owner has just proven the password); an administrator resetting a password or resetting two-step → **every** session of that person ends in the same transaction; the user themself turning two-step on or off → all of their sessions end and the browser in use receives the cookie of a new session as above. Change password, turn two-step off, turn two-step on: inside the write transaction, a disabled account → 403 `disabled`, a session in use that was revoked or expired → 401 `unauthenticated`, a password that was changed/reset since it was checked (`cred_version` changed) → 400 `wrong_password` (a code already in §3.3; "the password you just proved is no longer the current password"). A sign-in in progress whose password (`cred_version`), disabled state or two-step type changes before it writes is refused (400 `invalid_credentials`, or 403 `disabled`), and no session is created. |
| Sign-out | `POST /auth/logout` is public (no error when the session has already ended), clears the cookies, 204. |
| First-time setup | `GET /setup` (public) tells whether it is `complete`; `POST /core/setup` runs only when not yet set up (afterwards 409 `already_setup`); it creates the organisation, the first administrator and a session for them (sets `__Host-vedette_session` + `__Host-vedette_csrf`), enables the chosen module bundle and writes `core_audit`, all in one transaction. **One-time setup code**: while there is no administrator, the box generates a random code (100 bits, of the form `XXXXX-XXXXX-XXXXX-XXXXX`), stores it through `core/secrets`, prints it to the core log each time it starts while setup is still open and deletes it in the transaction that creates the administrator; a missing or wrong code → 403 `invalid_setup_code`; the code is checked **before** every other field, with a constant-time comparison; each wrong guess counts per client address like sign-in (10 tries, then 429 `rate_limited`; IPv6 adds a /64 counter) and there is no global cap for the whole box (fixed after a second security review: a global cap is a way to lock the box owner out); once setup is done every `POST /core/setup` is 409 `already_setup` (including `sample:true`). |
| SSO | `GET /core/auth-options` (public) `{oidc:boolean}`; `POST /auth/oidc/start` (public) returns `{authorize_url, binding}`; the IdP brings the browser back to the SPA page `/sso/callback`, which sends `POST /auth/oidc/callback` `{code, state, binding}` (public) and receives the session cookie as in a password sign-in. |

### 7.2 CSRF

The mock has no CSRF. Convention **[PROPOSED]** (ARCH §5: session cookie + CSRF):

1. At the same time as `__Host-vedette_session`, set the cookie `__Host-vedette_csrf` (a random value, `Secure; SameSite=Strict`, **not** `HttpOnly`) and store its SHA-256 in `core_session.csrf_hash`.
2. Every authenticated `POST/PUT/PATCH/DELETE` must send the header `X-CSRF-Token` with the value of that cookie (the SPA reads the cookie and attaches the header in `request()` of `lib/api.ts`). The server compares the SHA-256 of the header with `csrf_hash`, in constant time. Missing/wrong → 403 `csrf_invalid` (new code).
3. Also check `Origin` (or `Referer`) against the box's own origin for state-changing requests.
4. `GET` never changes state, so it needs no CSRF (SSE `GET /events` is therefore safe).
5. **Exempt:** the public POSTs (`/auth/login`, `/auth/login/resend-code`, `/auth/logout`, `/auth/oidc/start`, `/auth/oidc/callback`, `/core/setup`, `/response/approve/{token}`, `/intake/osquery/*`). They are protected by the credentials/one-time token in the request itself, and by `SameSite=Strict` for browsers.
6. A strict CSP with no inline scripts (ARCH §6); no CORS (the SPA is same-origin); `Cache-Control: no-store` for every API response with private data.

### 7.3 Token

| Token | Used to | Carried by | Stored | Scope / expiry | Endpoint |
|---|---|---|---|---|---|
| **MCP token** (S-MCP-1) | An MCP client (Claude Desktop, etc.) calling **read-only** tools | `Authorization: Bearer <token>` to the separate MCP server (`bind 127.0.0.1`, `port 8765`, `/mcp`; not REST) | `mcp_tokens.token_hash` + `last4`; the full value is shown **exactly once** | `scopes` ⊂ {`assets`, `findings`, `feeds`}; tools: `list_assets`, `get_asset`, `list_findings`, `get_finding`, `lookup_cve`, `lookup_ioc`, `hot_vulnerabilities`; valid until revoked | `GET /core/mcp`, `POST/DELETE /core/mcp/tokens*` (admin); the switch is `PATCH /modules/mcp-server` |
| **osquery enrollment token** | Enrolling an osquery host with the box | `enroll_secret` when the install command runs (not in the URL); afterwards a separate `node_key` per machine | `intake_agent_tokens.token_hash` | 7 days by default (0–365; 0 = no expiry), revocable; for enrollment only | `POST/DELETE /inventory/agents/tokens*` (admin); `POST /intake/osquery/status\|enroll\|config\|log` (public, authenticated by the token or `node_key`) |
| **Blocklist token** | A firewall pulling the list by itself | Path segment `/response/blocklist/{token}.txt` | `core_secret` | Until rotated (`POST /response/blocklist/token`) | `GET /response/blocklist/{token}.txt` (public) |
| **Email approval token** | One person approving one request | Path segment `/response/approve/{token}` (in the email link) | `resp_approval_token.token_hash` | **One time, 30 minutes**, bound to the request and the recipient; confirmation is by POST (link scanners do not approve by themselves) | `GET/POST /response/approve/{token}` (public) |
| **Honey token URL** (S-HP-2) | Catching whoever opens a planted bait link | Path segment `/t/{id}` (10 characters `a-z0-9`), **outside** `/api/v1` | tail of `hp_tokens.value` | Until the token is deleted; no session, no CSRF; every `/t/<x>` returns the same `404 page not found` text/plain (never the SPA, no distinction between a real and an unknown id); the first open of each token/source/10 minutes is always recorded, repeats at most 10 per address per minute | `/t/{id}`, `/t/{id}/…` any method (public) |
| **Scoped REST token** (ARCH §5 "API token") | An external integration calling REST | — | — | **No story, no mock, not built.** To be defined only when there is a story. Open question 6. | — |

The detailed formats (length, prefix, HMAC, lifecycle) **belong to separate specs and are not repeated here**: osquery enrollment tokens and `node_key`: `docs/specs/osquery-intake.md`; approval tokens (`v1.<token_id>.<mac>`): `docs/specs/approval-tokens.md`; blocklist token: `docs/specs/blocklist-format.md`. General convention: ≥ 128 random bits from `crypto/rand`; the plaintext is shown **exactly once** (except the blocklist token, which is in the displayed URL); the access log and `core_audit` **mask** the token segment of the path (`/response/blocklist/*`, `/response/approve/*`, `/approve/*`).

### 7.4 RBAC

Three roles, in the order `viewer < operator < admin` (`rank` in `mocks/http.ts` and `lib/session.ts`). Each endpoint declares its **minimum role** in `contract.ts`, field `role: 'viewer' | 'operator' | 'admin' | 'public'`:

- `openapi.json` records it as `x-min-role` on each operation; `public` adds `security: []` (no session needed). Current count (measured from `core/api/routes` generated from `openapi.json`, 2026-11-09): **admin 133 · viewer 80 · operator 47 · public 14** (274 operations).
- The mock enforces it with `guard(min)` at the top of the handler; the backend enforces it with **middleware generated from `x-min-role`**, with no hand-written check in each handler. No `x-min-role` means no route: a test compares both directions (section 12.1).
- `viewer`: read-only; sees `*_last4` on a few read endpoints (for example `GET /ai/profiles`), **never** a secret; configuration endpoints that hold secrets all require admin. `operator`: operational actions (change a finding's state, scan, approve an action, add/edit a device, send a test). `admin`: system configuration, users, channels, AI, feeds, modules, updates.
- **401 before 403:** no session → 401; a session without the role → 403 `forbidden`; a disabled account → 403 `disabled`.
- **Extra gates beyond the role** (checked in the service layer, with their own codes): approving an action requires a user with role ≥ operator **and** listed among the channel's approvers (`approver_not_listed`, `viewer_not_allowed`); a high-risk action can only be approved in the application with a two-step code (`in_app_required`, `twofa_required`, `code_required`); an action that changes another device needs the execution switch (`execution_off`); self-protection (`last_admin`, `self_disable`, `self_reset`, `current_session`); `POST /response/execution` needs admin + two-step turned on + typing the exact risk-acceptance phrase (`twofa_required`, `phrase_mismatch`).
- There is no per-user/per-site data scope (no multi-site/tenant yet).
- Changing a user's role or disabling them takes effect on the next call (the role is read from the DB on every request, not put in the cookie).

## 8. Rate limits

The mock has only **business** limits (table below); there is no HTTP rate limit yet. The HTTP part is **[PROPOSED]**.

| Limit | Value | Source | Response when exceeded |
|---|---|---|---|
| Resending a two-step code by email | 60 s between two sends; at most 5 codes/hour for sign-in and **a separate 5 codes/hour for approval codes** (`core_email_code_send.kind`; the 60 s spacing is counted per person across both); a code lives 10 minutes; at most 5 wrong entries | `core/emailCode.ts` | 429 `resend_too_soon` (with `retry_after`), 429 `too_many_codes` (with `retry_after` and `Retry-After`: seconds until the oldest send leaves the 1-hour window); 400 `too_many_tries`, `code_expired` |
| Verifying an external target | 10 times/hour (`MAX_ATTEMPTS_PER_HOUR`), at most 20 targets | `exposure/mocks.ts` | 429 `rate_limited`; 400 `too_many` |
| AI tokens per month | `monthly_budget` per profile and in the shared configuration | `ai/mocks.ts` | 429 `budget_reached` |
| Response: device actions | `max_per_hour` (default 3); circuit breaker `breaker_max_per_hour` (20); `multi_target_max` (5); `max_per_hour` per rule (≤ 100); AI budget `budget_hour` 2 / `budget_day` 5 | `response/state.ts` | 409/403 through `refuse()` (writes `resp_log` of kind `refused`/`breaker`) |
| Failed sign-in | ARCH §6 "sign-in rate limit"; no number yet **[PROPOSED]** 10 failures / 15 minutes per (IP, email) pair, with growing wait. An attempt is counted as soon as it starts and given back when the password is right (parallel attempts cannot slip past each other). IPv6 is counted twice: per address (10, like IPv4) and per (/64, email) pair with a cap of 100, so one machine rotating inside a /64 is still blocked but the whole /64 cannot be locked out with just 10 guesses; IPv4 is per address. Waiting out the delay and then typing the right password does not extend the delay. The two-step code has its own counter **per account** (not per IP): 10 wrong / 15 minutes → 429, including the confirmation code when turning on TOTP (a pending-confirmation key is discarded after 5 wrong codes). A password retyped to change the password or turn two-step on/off has its own re-authentication counter per account (same level, writes `auth.reauth_failed`). **Device cookie**: a request carrying a valid device cookie of the account is counted per cookie (10 wrong / 15 minutes, with the same growing wait), not per address, so someone in the same /64 guessing 100 times cannot lock out an account owner who has the cookie; a stolen cookie still gets only 10 tries / 15 minutes | `core/auth` | 429 `rate_limited`, `Retry-After` |
| Password hashing/checking (argon2, 64 MiB each) | at most `min(GOMAXPROCS/2, GOMEMLIMIT/4/64 MiB)` at once, at least 1 (`auth.Config.MaxHashing`; GOMAXPROCS follows the container's limit); waits at most 2 s (`HashWait`), queue of 4 times the number of slots; beyond that it refuses | `core/auth` | 503 `server_busy`, `Retry-After: 3` |
| Waiting for the DB write connection (single writer) | each request waits at most 5 s (`store.RequestWriteWait`); background jobs are unlimited and wait on their own context | `core/store` | 503 `server_busy`, `Retry-After: 5` |
| Authenticated API | **[PROPOSED]** 600 requests/minute per session (token bucket); SSE not counted | | 429 `rate_limited` |
| Public requests with no session (only on an appliance with `vedette-host`) | 60 requests / minute per client address (IPv6 per /64): public operations (`/setup`, `/auth/*`, `/core/setup*`, `/core/auth-options`, `/response/approve/*`, `/response/blocklist/*`) sent without a valid session; not counted: requests with a session (even to public routes), the 401 of a route that needs sign-in (the GUI needs the 401 to return to the sign-in page), the routes of the osquery agent (`/intake/*`, `/install/*`: a whole fleet behind one NAT, with its own enrollment secret) and loopback (the box itself: health checks, the `vedette` command) | `core/server` (`publimit.go`, `Config.PublicPerMinute`) | 429 `rate_limited`, "Too many requests from this address. Try again in N seconds.", `retry_after` + `Retry-After` |

A 429 response (and 503 `server_busy`) always carries `Retry-After: <seconds>`, the standard body of section 3.1 (and `retry_after` inside `error` when applicable), plus `RateLimit-Limit/Remaining/Reset` on rate-limited endpoints **[PROPOSED]**. **Outbound** limits (the scan rate `rate` 1–20 req/s, `inv_setting.active.rate`) are scan configuration, not an API limit.

## 9. Versioning and deprecation

- **`/api/v1`** is the only version that exists (`info.version` of `openapi.json`: `0.1.0-m1`). The SPA is embedded in the same binary, so the SPA and the API always have the same version; the version only protects **outside consumers**: MCP clients, the osquery install script on customer hosts, firewalls pulling the blocklist, the email approval page.
- **Compatible changes (made within `v1`):** adding an endpoint; adding an **optional** field to a request body; adding a field to a response; adding an optional query parameter; adding a new error code; adding an extension field to `error`. Clients must ignore unknown fields. **Note:** adding an enum value is a **conditional** change: the SPA validates with strict Zod, so changing an enum forces a SPA change in the same PR; for outside consumers, adding an enum value must be recorded in the release notes.
- **Breaking changes** (renaming/removing a field, changing a type, tightening a constraint, changing the meaning of an error code or HTTP status, changing the canonical form of the hash-chained log): only in `v2`, running in parallel with `v1`.
- **Deprecation:** a removed endpoint/field returns `Deprecation: true` and `Sunset: <HTTP-date>`, `Link: <…>; rel="successor-version"`; recorded in `docs/UPDATES.md` and in the release notes. At least **2 stable releases or 90 days**, whichever is longer **[PROPOSED]**. After `Sunset` it returns `410 gone`.
- **Long-lived contracts (frozen within a major version):** the blocklist format `GET /response/blocklist/{token}.txt` (already in customers' firewall configuration), the content and parameters of `GET /install/osquery.sh|.ps1`, the osquery data-intake protocol (`/intake/*`, `docs/specs/osquery-intake.md`), the email approval page (`/response/approve/{token}`), the MCP protocol. Changing them breaks deployed boxes, so treat it as breaking.
- Each release sets `info.version` to the software version; `api/openapi.json` ships with the release (signed together with the update).

## 10. Real-time events: SSE `/api/v1/events`

**Current state:** the SPA **does not use SSE yet**; it polls: `scan/runs` every 1 second while a scan is running, `ai/knowledge` every 1 second while a document is not `ready`, `core/os-run` every 500 ms during an OS update, `response/actions` every 30 seconds. Everywhere else refreshes when the user acts (`invalidateQueries`). SSE replaces these polling loops and lets pages update by themselves; **REST remains the source of truth**: an event is only a hint "data changed, reload".

### 10.1 Protocol

| Item | Rule [PROPOSED] |
|---|---|
| Endpoint | `GET /api/v1/events` (`Content-Type: text/event-stream`), minimum role `viewer`, authenticated by the session cookie (same-origin `EventSource`). No CSRF needed (GET). |
| Framing | `id: <monotonically increasing number>` · `event: <name>` · `data: <one-line JSON>`. Heartbeat: a comment line `: ping` every 25 seconds; `retry: 3000`. |
| `data` content | Only **identifiers and state**, no addresses, no secrets, no log/AI content. The SPA reloads through REST (where real authorization is checked). |
| Filtering by role | The server sends only events that the listener's role may read (the "Role" column below = the role of the corresponding `GET`). Role changed/session revoked → the stream is closed; the SPA reopens it and receives 401. |
| Reconnection | The browser sends `Last-Event-ID`. The server keeps a ring buffer of 1,000 events or 5 minutes (whichever is smaller) in memory. Too old/absent → it sends `event: resync` (`data: {}`); the SPA reloads **every** open query. Delivery is **at most once**, with no ordering guarantee between events of different kinds. |
| Limits | At most 5 connections per session; one connection per user per tab. Proxies must turn off buffering (`X-Accel-Buffering: no`). Not included in `openapi.json` as plain JSON (section 13, open question 7). |

### 10.2 Event catalogue

Derived from the queries the SPA holds (`queryKey`) and from the places that poll. "Refresh" = the SPA `queryKey` that should be invalidated on receiving the event.

| Event | `data` | Emitted when | Role | Refresh |
|---|---|---|---|---|
| `module.changed` | `{id, enabled}` | a module is turned on/off | viewer | `['modules']`, navigation |
| `device.changed` | `{id, change: created\|updated\|deleted\|approved}` | a device is added/edited/deleted/approved; sensor, agent, update scan | viewer | `['inventory','devices']`, `['inventory','device',id]`, `['findings']` |
| `sensor.changed` | `{id, status}` | a sensor goes online/offline, interface/SPAN changes | admin | `['inventory','sensors']` |
| `agent.synced` | `{kind: osquery\|wazuh, hosts}` | an agent sends data / Wazuh sync finishes | admin | `['inventory','agents']`, `['inventory','devices']` |
| `finding.changed` | `{id, asset_id, status, change: created\|status\|applied\|rescan}` | a new finding, a status change, a confirming scan | viewer | `['findings']`, `['findings','detail',id]`, `['inventory','device',asset_id]`, `['response','plans']` |
| `feed.updated` | `{source_id, status, records}` | a feed source finishes pulling or fails | viewer | `['feeds']` (hot, status, sources, search) |
| `scan.run.changed` | `{id, status, done, total}` | a scan makes progress/finishes (replaces the 1-second polling) | viewer | `['scan','runs']`, `['scan','targets']`, `['findings']` |
| `scan.event.created` | `{id, cve, result}` | a re-scan triggered by a new KEV entry | viewer | `['scan','events']` |
| `exposure.changed` | `{target_id, change: verified\|expired\|scanned}` | an external target is verified/scanned | viewer | `['exposure']`, `['exposure','target',id]` |
| `honeypot.hit` | `{id, kind}` | a trap is touched | viewer | `['honeypot']`, `['honeypot','hits',…]` |
| `incident.changed` | `{id, status, change: created\|updated}` | a new incident or a status change | viewer | `['notify','incidents']`, `['notify','incident',id]` |
| `notify.sent` | `{kind, ref_id, channel, ok}` | a message is sent or fails | viewer | `['notify','history']`, `['notify','finding',id]` |
| `log.source.changed` | `{id, state: receiving\|silent\|never}` | a log source starts/stops receiving | viewer | `['logs','sources']` |
| `log.ioc_hit` | `{id}` | a connection matches an IOC | viewer | `['logs','digest']`, `['response','events']` |
| `response.action.changed` | `{id, status}` | a new request, approved/rejected/expired/executed/rolled back (replaces the 30-second polling) | viewer | `['response','actions']`, `['response','metrics']` |
| `response.log.appended` | `{id, kind}` | a new `resp_log` row | operator | `['response','log']` |
| `response.state` | `{execution, breaker_tripped, ai_paused}` | the execution switch, the circuit breaker or the AI pause changes | viewer | `['response','settings']`, banner |
| `response.blocklist.changed` | `{count}` | the blocklist changes (add/remove/TTL expiry) | admin | `['response','blocklist']` |
| `ai.activity.appended` | `{id, job, result}` | a new AI call in `ai_activity` | operator | `['ai','activity']`, `['ai','usage']`, `['ai','runs']` |
| `ai.knowledge.progress` | `{id, status, chunks}` | a RAG document changes `uploading → indexing → ready` (replaces the 1-second polling) | admin | `['ai']` (knowledge base) |
| `core.os.run` | `{id, status, line_count}` | an OS update is running/done (replaces the 500 ms polling) | viewer | `['core','os-run']`, `['core','os']` |
| `core.update.changed` | `{component, action: available\|applied\|rolled_back}` | a new version is available / applied / rolled back | viewer | `['core','updates']`, `['core','os']` |
| `audit.appended` | `{id}` | a new `core_audit` row | admin | `['core','audit',…]` |
| `user.changed` | `{id, change: created\|updated\|disabled\|twofa_reset}` | user administration | admin | `['core','users']` |
| `session.revoked` | `{id}` | sent **only** to the user whose session was revoked | (session owner) | `['me']` (then 401) |
| `report.sent` | `{id, status}` | a weekly report has been sent | viewer | `['reports','history']` |
| `resync` | `{}` | events were lost (too old) | (all) | **every open query** |

Each event is produced from the business transaction itself **after commit** (it is not emitted on rollback). Events are **coalesced** by `(name, id)` within a 250 ms window to avoid a refresh storm during bulk imports.

## 11. Files: download, upload

### 11.1 Download

There are **11** operations that return a file (`response: 'file'` in `contract.ts`, `application/octet-stream` in `openapi.json`). Conventions:

| Rule | Details |
|---|---|
| Authentication | Like a normal endpoint (session cookie); GET, no CSRF needed. Public exceptions: `/install/osquery.sh|.ps1`, `/response/blocklist/{token}.txt`. |
| File name | `Content-Disposition: attachment; filename="…"` set by the server (the SPA `download()` currently picks the name itself; it will move to reading the header, keeping a fallback name). The name carries the UTC date: `vedette-<kind>-YYYYMMDD.<extension>`. |
| Content type | The mock currently returns `application/octet-stream`; the backend returns the right type: CSV `text/csv; charset=utf-8`, JSON `application/json`, script `text/x-shellscript` / `text/plain`, blocklist `text/plain; charset=utf-8`, bundle `application/octet-stream` **[PROPOSED]**. |
| No caching | `Cache-Control: no-store` (except the blocklist and install files: see below). |
| Streaming | Large files (log export, backup) are streamed and the whole file is not built in memory; `GET /core/logs/export` is limited by `from`/`to`/`categories` and carries `head_hash`, `count` at the start (DATA_MODEL §5.3). |

| Endpoint | Role | Content |
|---|---|---|
| `GET /core/audit/export` | admin | the filtered audit log as CSV/JSON |
| `GET /core/logs/export` | admin | **every log of the box** (audit, AI, response, scan probes, alerts, device logs), JSON or CSV, by `categories` |
| `GET /core/data/export` | admin | an export of the user's data (S-CORE-1) |
| `GET /core/data/backup` | admin | a consistent backup (`VACUUM INTO`, **without** the master key file; `POST` with a password encrypts it and carries the key inside the encryption; `docs/DATA_MODEL.md` section 7) |
| `GET /core/updates/bundle` | operator | the signed offline update bundle |
| `GET /inventory/export.csv`, `/inventory/import-template.csv` | viewer | the device list; the import template |
| `GET /scans/probes.csv` | viewer | the probe log (SYS-7) |
| `GET /install/osquery.sh`, `GET /install/osquery.ps1` | public | the install script; contains no token (the token is entered when it runs); accompanied by a SHA-256 shown at `GET /inventory/agents` |
| `GET /response/blocklist/{token}.txt` | public (token) | section 11.3; `docs/specs/blocklist-format.md` |

### 11.2 Upload

The mock accepts **JSON with embedded content** and has no `multipart/form-data` yet: `POST /inventory/import` `{filename, size, sha256, text}`; `POST /core/updates/bundle` `{name, size, sha256, content}`; `POST /ai/knowledge` `{name, size, content, jobs?}` (`content` is the file as base64, decoded to exactly `size` bytes; the box keeps only the text extracted from the file).

| Item | Rule [PROPOSED] |
|---|---|
| Channel | `application/json` with embedded content for files ≤ 200 KB (`POST /inventory/import`: 200,000 bytes, 500 rows, `MAX_IMPORT_BYTES`/`MAX_IMPORT_ROWS`). Larger: `multipart/form-data` with one `file` part + a JSON `meta` part. |
| Caps | Device import 200 KB / 500 rows (400 `too_large`/`too_many_rows`); update bundle 5 MB (`MAX_UPLOAD`); RAG document 10 MB (`too_large`), PDF, MD, TXT, DOCX only (`invalid_type`); private SSH key 16 KB. Over the cap → **413 `too_large`** (section 1). The body is read through `http.MaxBytesReader` and is never loaded fully into memory before it is checked. |
| Integrity | The `sha256` in the body is the **client's check**: the server recomputes it and refuses on a mismatch (`invalid_bundle` for a bundle; the new code `checksum_mismatch` for other files **[PROPOSED]**). |
| Update bundle | The server verifies the minisign signature **before** unpacking/applying (`bad_signature`, `not_bundle`, `invalid_bundle`); unsigned or wrongly signed → refused. |
| Content | An uploaded file is untrusted data (SYS-6): parsers fail closed; CSV is formula-safe (`=`, `+`, `-`, `@` at the start of a cell when exported again). No unbounded nested extraction. |
| Storage | RAG document: the **indexed text chunks** are stored, not the original file (`ai_knowledge_chunk`, `docs/DATA_MODEL.md` section 4.9). There is no public upload folder. |

### 11.3 Public endpoints (no session needed)

Fourteen operations with `role: 'public'`:

| Endpoint | Purpose | Protection |
|---|---|---|
| `POST /auth/login`, `/auth/login/resend-code`, `/auth/logout` | Sign in, resend the code, sign out | rate limited; `resend-code` also requires the password so that a stranger cannot make another person's mailbox receive codes |
| `GET /core/auth-options`, `POST /auth/oidc/start`, `POST /auth/oidc/callback` | Tell the sign-in page whether SSO exists; start and finish OIDC | exposes no configuration, only `{oidc:boolean}` |
| `GET /setup`, `GET /core/setup/modules`, `POST /core/setup` | First-time setup | `POST` only when not yet set up (409 `already_setup` afterwards) |
| `GET /install/osquery.sh`, `/install/osquery.ps1` | The osquery install script served by the box | contains no secret; accompanied by a SHA-256 (shown on the Agent page); `Cache-Control: no-cache` |
| `POST /intake/osquery/status` | The install script asks "has the machine reported yet". The spec `docs/specs/osquery-intake.md` also has `GET /intake/ca.pem` (public) and `POST /intake/osquery/enroll\|config\|log` (osquery's TLS protocol): **not in `contract.ts` yet** (open question 8) | authenticated by the enrollment token / `node_key` in the request; body size limit |
| `GET /response/approve/{token}` | The email approval page: **display only** (`state`: `ready\|expired\|used\|decided\|unknown`, title, before/after change) | one-time token, 30 minutes, bound to the request + recipient; does not reveal which tokens exist (`unknown`); `Cache-Control: no-store`; `X-Frame-Options: DENY` |
| `POST /response/approve/{token}` | Clicking **confirm** `{decision: approve\|reject}` | needs POST (not GET) so that the mailbox's link scanner does not approve by itself; single use; checks the approver list and the role; a high-risk action is refused here (`in_app_required`); writes `core_audit` + `resp_log` |
| `GET /response/blocklist/{token}.txt` | A firewall pulling the blocklist | see below |

**Blocklist:** `.txt` = `text/plain; charset=utf-8`, one IP or CIDR per line (matches FortiGate External Block List, Palo Alto EDL, pfSense/OPNsense URL Table, MikroTik `fetch`); the variants (`.json`, `.domains.txt`), comments, ETag/`If-None-Match` (304) and per-vendor instructions: `docs/specs/blocklist-format.md` (the authoritative source). A wrong token → 404 like every public token. Each pull updates `last_fetch {at, from}` (records the source, not the content). No `Set-Cookie`. This is a **long-lived contract** (section 9).

## 12. The contract pipeline

```
web/src/features/<m>/contract.ts  (Zod + defineEndpoints)         ← source of truth
        │  web/src/lib/openapi.ts  (import.meta.glob '../features/*/contract.ts')
        ▼
pnpm --dir web openapi           (web/scripts/openapi.mjs)         ← generated, NEVER edited by hand
        ▼
api/openapi.json  (OpenAPI 3.1, 267 operations)                    ← committed together with the contract
        ▼
Go codegen (M2: types + handler interface, strict)                  ← the backend must match
```

- **Where it is declared:** each endpoint is an element of `defineEndpoints([...])` with `method`, `path` (without `/api/v1`), `summary` (one English sentence), `stories` (story IDs), `role`, `params`/`query`/`body`/`response` (Zod; `null` = 204; `'file'` = file download), `example` (for GET tests). The SPA's types come from `z.infer` over the schemas themselves (`types.ts`), so the SPA, the mock and the backend do not drift.
- **OpenAPI generation:** `z.toJSONSchema(…, {target: 'draft-2020-12', io: 'output'})`; an operation has `operationId` = `<module>_<method>_<path>`, `tags: [module]`, `x-stories`, `x-min-role`; every operation gets `default → Error`; `securitySchemes.session` = the cookie `__Host-vedette_session`.
- **Known drift** (between decisions/mock and the generated contract): the old design documents say `api/openapi.yaml`, in reality `api/openapi.json` (this spec treats **`.json` as the standard**, open question 9); ~~a creating POST returns 201 but declares 200~~ (fixed: `status` in `Endpoint`); no per-operation error declaration; SSE and `multipart` cannot be expressed yet (`Endpoint` has no `errors`, no `stream` type).
- **Extending `Endpoint`**: `status?: 200 | 201 | 202` **already exists** (default 200; 204 when `response === null`). Still proposed **[PROPOSED]**: `errors?: string[]` (the possible error codes → `x-errors` + the section 3.3 table generated automatically), `response: 'file' | 'stream'`, `contentType?` for files/multipart.

### 12.1 Drift checks (CI)

Already present (run by `pnpm --dir web test` / `make verify`, `web/src/lib/contract.test.ts`): (1) every mock handler is in `contract.ts` **and vice versa**, per module; (2) every `GET` with an `example` returns data that **matches the Zod schema**; (3) `api/openapi.json` equals exactly the current `buildOpenApi()` output (drift → run `pnpm openapi`). The repo has **no CI workflow yet** (`.github/` has only `CODEOWNERS` and issue/PR templates); `make verify` is the local gate.

To be added once there is Go **[PROPOSED]**, all running in `make verify` and the first CI workflow:

| Check | How | What it catches |
|---|---|---|
| Regeneration changes nothing | `pnpm --dir web openapi && git diff --exit-code api/openapi.json` | forgetting to regenerate after editing `contract.ts` |
| Go regeneration changes nothing | run codegen into a temporary folder and `diff` against the committed code | hand-editing generated code, or forgetting to regenerate |
| Route ↔ spec in both directions | the Go router's route table against `paths` in `openapi.json` (same idea as the mock test) | extra/missing routes |
| Minimum role | every route has `x-min-role`; calling with a lower role → 403, no session → 401 | a missing permission check |
| Response matches the schema | for each operation, call the handler (`httptest`) with a fixture and check the body + HTTP status against the schema | the backend drifting from the contract |
| Error codes are in the catalogue | every returned `code` ∈ the section 3.3 table (or the operation's `errors`) | a new error code that was not declared |
| Every mutation writes `core_audit` | a test per POST/PUT/PATCH/DELETE operation (SYS-3) | missing audit |
| Module off → no route | calling an endpoint of a disabled module → 404 (SYS-5) | a disabled module still serving |

### 12.2 Adding an endpoint, step by step

1. **Story.** Have a story ID. If there is none: stop, propose a story marked `[not yet]` and ask the maintainer.
2. **GUI first**: the screen has been planned, built and reviewed; no backend is written for a screen that is not approved.
3. **Design the path** by section 1 (module group, nouns, a verb is a POST to a sub-resource) and choose the minimum `role` (section 7.4).
4. **Declare in `web/src/features/<m>/contract.ts`**: the Zod schema (reuse an existing schema, `.describe()` for what is not obvious), then add an element to `endpoints` with `stories`, `role`, and `example` if it is a GET with parameters. `summary` is one English sentence.
5. **Mock** in `features/<m>/mocks.ts`: `guard(role)` first; validate at the boundary and return errors through `fail(status, code, message)` with a **code from section 3.3** (a new code → add it to the table with its HTTP status); a mutation calls `audit(...)`; return exactly 200/201/204 per section 1.
6. **Types and hook**: `z.infer` in `types.ts`, the calling function in `api.ts` (`useQuery`/`useMutation`; `invalidateQueries` with the right key; if the endpoint changes real-time data, add an SSE event in section 10.2).
7. **Run**: `pnpm --dir web exec vitest run src/lib/contract.test.ts -t "<module>"` (handler ↔ contract, GET matches schema), then `pnpm --dir web openapi` to regenerate `api/openapi.json`; commit that file **together with** `contract.ts`. Never edit `api/openapi.json` by hand.
8. **Documentation**: update the module's `CONTRACT.md` + `IMPACT.md`; a new table/column → `docs/DATA_MODEL.md`; a new outbound data flow → `PRIVACY.md` + the Settings → Privacy UI; a new dependency → `THIRD_PARTY_NOTICES.md`.
9. **Run `make verify`** (tsc + lint + vitest + build, then clean up).
10. **Backend (after the GUI is approved):** regenerate the Go code from `api/openapi.json`; add the module's one-way migration (DATA_MODEL §6); implement handlers **only** through the generated interface, validate input through the schema before the service (SYS-2), write `core_audit` (SYS-3), call no shell (SYS-1); write Go contract tests (`-run Contract`); `make verify` includes `go test ./...` + `golangci-lint` when Go is present.
11. **PR** on a `feat/…` branch (`docs/…` for documentation); do not push `main`; git tags are created by the maintainer.

## 13. Open questions

| # | Question | Hint / impact |
|---|---|---|
| 1 | ~~**A creating POST returns 201 but the contract declares 200** (16 places)~~ Done: `status` in `Endpoint`, `openapi.json` regenerated. Remaining: two endpoints that return 201/200 depending on the case cannot be expressed yet. | |
| 2 | **Declare error codes per operation** (`errors: [...]`) so that table 3.3 is generated automatically instead of statically extracted with a regex (limitation: many codes are tagged "shared validator"). Do it? | Reduces the effort of maintaining the 313-code table; requires editing every `contract.ts` |
| 3 | **Pagination of `GET /inventory/devices`, `/findings`:** the SPA loads everything and filters on the client. Move to server-side pagination/filtering in M2 or keep until a threshold is exceeded? | The target of 1,000 devices still works without pagination; needs confirmation |
| 4 | **Session lifetime** (idle, absolute), failed-sign-in lockout, "remember this device" policy: the mock has none. Default values? | Sessions: `core_session`, `docs/DATA_MODEL.md` section 3 |
| 5 | ~~OIDC callback path and SSO sign-out~~ — answered: `POST /auth/oidc/start`, the `/sso/callback` page, `POST /auth/oidc/callback`; no sign-out on the IdP side | Done |
| 6 | **Scoped REST token** (ARCH §5) has no story. Do it (who needs to call REST from outside besides MCP)? | If yes: needs a story, a new token table, a per-module scope rule |
| 7 | **Representing SSE and `multipart` in `openapi.json`** (types `text/event-stream`, `multipart/form-data`) so that Go can generate the skeleton; or leave them outside the contract and write them by hand. | Tied to the proposed `Endpoint` extension (section 12, "The contract pipeline") |
| 8 | **The osquery TLS endpoints** (`enroll`, `config`, `log`, `GET /intake/ca.pem`) are in `docs/specs/osquery-intake.md` but **not declared in `contract.ts`/`openapi.json`** (only `status` is). This is osquery's protocol (JSON, not following the standard error schema): declare it in the contract or keep it outside the contract with its own tests? | A long-lived contract (section 9); affects the count of 14 public points in section 11.3 |
| 9 | **`api/openapi.json` or `.yaml`:** the old design documents say `.yaml`, the code uses `.json`. Settle on `.json` and update ARCH §5? | Only a file name; affects paths in scripts/CI |
| 10 | **The Go generator** (`oapi-codegen`, `ogen`, other) must understand OpenAPI **3.1** (type `["string","null"]`, `const`, `anyOf`). Not yet tried on the real `api/openapi.json`; if it is not supported, a 3.1→3.0 downgrade step is needed in `scripts/openapi.mjs`. Choose at the start of M2 after a trial run and record it in `THIRD_PARTY_NOTICES.md`. | Decides the `go generate` configuration |
| 11 | **The HTTP rate limits, CSRF, ETag, Idempotency-Key, SSE** marked **[PROPOSED]** are new design (the mock has none). Approve as a whole, or part by part by milestone? Is a story ID needed for each part (features need a story)? | Each adds new error codes (`csrf_invalid`, `precondition_failed`, `precondition_required`, `idempotency_*`, `bad_cursor`, `bad_limit`, `bad_sort`, `checksum_mismatch`, `gone`) |
| 12 | **Synonymous error codes** (for example `bad_name`, `invalid_name`, `duplicate_name`, `invalid_kind`/`bad_kind`; `too_large` 400 and 413) currently coexist: keep them or merge them before the backend freezes the contract? | Merging changes the contract and the frontend; keeping them adds burden to the backend |
| 13 | **`GET /response/log` oldest first + pagination:** the client verifies the hash chain across pages by carrying the `hash` of the last row. Accept, or add a server-side `GET /response/log/verify` like `/ai/activity/verify`? | A verify endpoint needs a story (not decided yet) |
