# Block list: a block list that the firewall pulls by itself

Status: implemented in `response` (written 2026-11-09 before the code). Where this spec and the code or `modules/response/CONTRACT.md` differ, those win. Field names, formats and paths are in English.
Traceability: design requirements (pull preferred; the `blocklist_add` action, TTL, undo); story S-RESP-3; GUI mock `web/src/features/response` (`BlocklistTab.tsx`, `guides.ts`, `mocks.ts`, `contract.ts`).

## 1. Purpose

The box **publishes** a list of addresses to block at an internal URL with a token; the customer's firewall/DNS filter **pulls it** periodically. Vedette needs no write access to the device and does not sit on the network path. Each entry in the list is the result of an approved action (every action needs approval; the exception is "pre-approved" by rule), has a TTL after which it is removed automatically, and can be undone.

The list serves only the **destination direction** (blocking outbound connections to malicious addresses). Isolating a machine on the LAN (touches a trap → block the source) is an action pushed through an API/SSH and does not go through this list.

## 2. Actors

| Actor | Role |
|---|---|
| `core` (module `response`) | keeps the list, publishes it, rotates the token |
| Firewall / DNS filter | a client that pulls the list (FortiGate, Palo Alto, pfSense, OPNsense, MikroTik, Pi-hole, AdGuard Home) |
| Administrator | copies the URL, sets up the firewall side following the instructions in the GUI, rotates the token |
| Response engine | adds/removes entries through the `blocklist_add` / `blocklist remove` actions |

## 3. Transport and authentication

- `GET` over HTTPS to `https://<box IP>:8443/api/v1/response/blocklist/<token>.<ext>`; the certificate is signed by the box's internal CA (self-signed from the firewall's point of view; the GUI instructions ask to import the CA into the firewall, except for the MikroTik script, which uses `check-certificate=no`; see §8 and §12).
- **No authentication header.** The token in the path is the only credential; the reason: firewall pull mechanisms usually accept only a URL (the GUI instructions turn off HTTP basic auth for FortiGate). Consequence: the URL must be treated as a secret, reachable only from the LAN, and **never** shown in an access log, a referrer, or an error report.
- Token: 128 random bits from a CSPRNG, 32 lowercase hex characters (`^[a-f0-9]{32}$`, like `TOKEN_RE` in the mock). Stored hashed (SHA-256) on the core side; the GUI shows the full URL only to an admin and the last 4 characters elsewhere. A wrong token → `404 Not found` (indistinguishable from a wrong path).
- Rate limit: 60 requests/minute per source IP; 20 wrong tokens/minute per IP before `429`. Each successful request records `last_fetch {at, from}` (shown in the GUI: "from a device on the LAN").
- Not served on the public listener: this listener binds only to the management card and rejects sources outside the RFC1918/ULA range of the management network (mirrors SYS-7: not opened to the Internet).

## 4. Variants and formats

| URL | `Content-Type` | Content | Used for |
|---|---|---|---|
| `<token>.txt` | `text/plain; charset=utf-8` | IPs and CIDRs, one entry per line | FortiGate, Palo Alto, pfSense, OPNsense, MikroTik |
| `<token>.json` | `application/json` | the same content with all fields | custom integrations, checks, the GUI |
| `<token>.domains.txt` | `text/plain; charset=utf-8` | domains, one name per line | Pi-hole, AdGuard Home (domain block lists) |

`.txt` and `.json` already exist in the mock (only `.txt` actually appears in the GUI). `.domains.txt` is derived from the Pi-hole/AdGuard requirement and is **not yet in the mock**; see §12.

### 4.1 Fields of an entry

| Field | Type | Rule |
|---|---|---|
| `value` | string | a single IPv4 (`netip.ParseAddr`), a CIDR (`netip.ParsePrefix`, the prefix length is mandatory), or an ASCII domain (IDNA converted to punycode, ≤ 253 characters, each label ≤ 63, lowercase) |
| `kind` | enum | `ip` \| `cidr` \| `domain` (derived from `value`, not chosen by the caller) |
| `source` | string | the label of the rule/action that created the entry, ≤ 120 characters (for example `Rule: Known-bad IP`) |
| `reason` | string | ≤ 200 characters (for example `IPsum, confidence 85`) |
| `added` | datetime | RFC 3339 UTC (the mock calls it `added_at`) |
| `expires` | datetime \| null | `null` = never expires (allowed only when the action has **no** TTL; TTL ≤ 24 hours for pre-approved) (mock: `expires_at`) |

The JSON field names are consistent with `BlockEntry` in `contract.ts`: `added_at`, `expires_at`. The table above uses the short names of the requirement; **the official on-the-wire names are `added_at`/`expires_at`** to match the mock.

`kind` is **not yet** in the mock's `BlockEntry` (only `value, source, reason, added_at, expires_at`); add it to the contract when the backend is written (see §12).

### 4.2 The `.txt` variant

```
# vedette blocklist
# generated 2026-11-09T07:12:41.000Z
# entries 2
203.0.113.77
198.51.100.9
```

- The first three comment lines (from a security review, replacing the old form that had `# <source> | <reason> | expires …` before each entry): the list name, the server time, the number of entries. **No device name, rule, event summary or reason** appears in the public file (§12 (a)); `source`, `reason`, `expires_at` are on the admin screen and in `.json`. After that, one value per line.
- Lines end in `\n` (LF), encoding is UTF-8 without BOM; there are no blank lines.
- An empty list: still `200` with only the three comment lines (`# entries 0`; not `404`, not an empty body).
- **Line-injection protection.** (This now matters only for `.json`/the admin screen: `.txt` no longer prints `source`/`reason`.) `source` and `reason` can contain data controlled by an attacker. Before publishing, every control character (`\r`, `\n`, `\t`, NUL, U+0085, U+2028/2029…) is replaced with a space, `|` is replaced with `/`, and the text is cut to its limit. As a result a `reason` containing a newline **never** creates a fake `value` line. This is an invariant that must have a test (§12).
- Only `ip` and `cidr` in `.txt`; a `domain` entry never appears in `.txt` (a firewall that does not understand domains would skip it or fail on the whole list).

### 4.3 The `.json` variant

```json
{
  "generated_at": "2026-11-09T07:12:41Z",
  "version": "9f2c4a1e03b7d5a8",
  "entries": [
    {
      "value": "203.0.113.77",
      "kind": "ip",
      "source": "Rule: Known-bad IP: add to the block list",
      "reason": "IPsum, confidence 85",
      "added_at": "2026-11-09T07:10:02Z",
      "expires_at": "2026-11-10T07:10:02Z"
    }
  ]
}
```

`version` = the first 16 hex characters of the SHA-256 of the normalised `entries` content (also the basis of `ETag`).

### 4.4 The `.domains.txt` variant

One domain per line, with `#` comments like `.txt`. Pi-hole accepts a one-name-per-line domain list; AdGuard Home accepts the DNS block-list syntax. The plain domain form is used so that both can read it; AdGuard's `||example.org^` syntax is an open question (§12).

## 5. TTL, removal, and consistency

- **Expiry is applied at serving time**, not only at cleanup: when building the response, core filters entries with `expires_at <= now`. A firewall that pulls at 00:00:01 does not receive an entry that expired at 00:00:00 even if the cleanup job has not run.
- The cleanup job (`ttl_removed` in the response log) deletes the entry from the store and writes a line into the hash chain.
- Active removal (undo): the action `blocklist remove {ip}` deletes the entry at once; every source that produces the same `value`: the entry is removed only when **no** action still in effect holds it (reference counting by `value`; the entry takes the latest `expires_at`).
- Adding a duplicate `value`: merge (no second line is created), and update `expires_at` to the larger value.
- The never-block list: **checked again at publication**, in addition to the check at add time. An entry that matches the list (gateway, DNS, authentication server, the box itself, the management IP, services the customer declared) is **removed from the response**; every loopback, link-local, multicast, `0.0.0.0/8`, and the RFC1918/CGNAT `100.64.0.0/10` ranges are also removed (to avoid locking out the LAN itself because of a poisoned IOC set).
- **Rejected at the point of adding, not silently.** A `blocklist_add` with a non-public address (the `notPublishable` table, INV-17) is rejected as `not_publishable` **at planning time** on every path (rule, manual run, AI proposal, AI plan; a fixed value at the moment the rule is saved) and again at run time for an item created earlier; each rejection writes one `refused` line into the log. In a rule only that block action is dropped and the other actions still run (it has no effect, it is not dangerous). Such an old entry still in the store is deleted once at startup, with a line stating the number of entries. A match against the never-block list is also rejected as `never_touch` at add time and at run time (INV-10). Filtering at publication is the last layer and **does not write a line on every pull** (a firewall pulls every 5 minutes; an append-only log would fill with repeated lines).
- The per-hour entry limit per rule and the shared circuit breaker: these belong to the response engine and are outside this spec.

## 6. Response headers and caching

| Header | Value | Reason |
|---|---|---|
| `ETag` | `"<version>"` (the first 16 hex of the content's SHA-256) | a smart firewall asks again with `If-None-Match` → `304` |
| `Last-Modified` | the most recent time the entry set changed | |
| `Cache-Control` | `no-store` (the URL contains the token, store it nowhere) | the URL contains the token; shared proxies must not store it; always revalidate |
| `Content-Type` | as in §4 | |
| `X-Content-Type-Options` | `nosniff` | |
| `Referrer-Policy` | `no-referrer` | |
| `Content-Length` | always present | some embedded firewalls do not understand chunked encoding |

`Content-Encoding` is not used (many embedded clients do not decompress). Many firewalls ignore the condition and always download again: the server always returns a full `200` when there is no `If-None-Match`.

**Fail-static (important).** When core cannot read the store (a DB error), it serves `503 Service Unavailable` with `Retry-After: 60` and **never** returns an empty list: many firewalls treat an empty list as "remove everything" but keep the old copy when they receive an error. When the `response` module is off: `404` (SYS-5; the data is kept, and the firewall keeps its old copy in its own way).

## 7. Limits

| Item | Default limit |
|---|---|
| Maximum number of entries | 10,000 (at the limit: new entries are refused, `refused` is recorded and reported through a channel; nothing is silently cut) |
| Response size | ≤ 1 MiB (entries fit because a comment line is at most ~400 bytes) |
| `source` / `reason` | 120 / 200 characters |
| Maximum TTL of an entry | per rule: pre-approved ≤ 24 hours; manual ≤ 30 days; `null` (never expires) only when the approver chooses it explicitly |
| Adding entries | ≤ 100/hour for the whole box (the shared circuit breaker blocks earlier) |

Limits of each platform differ by model and version (FortiGate, Palo Alto EDL, pfSense alias, MikroTik address-list). The figure of 10,000 is Vedette's safe ceiling and **has not been checked** against each vendor's documentation: this step must be done when building (verify against official sources) and recorded in `guides.ts`.

## 8. How each device pulls

Step-by-step instructions already exist in the GUI (`guides.ts`); this table summarises the spec's conditions.

| Device | Mechanism | Variant | Interval (GUI instructions) | Notes |
|---|---|---|---|---|
| FortiGate | Security Fabric → External Connectors → Threat Feeds → IP Address | `.txt` | 5 minutes | turn off HTTP basic auth (the token is the credential); create a `DENY` policy whose destination is the feed; import the box CA to avoid certificate errors |
| Palo Alto | Objects → External Dynamic Lists, type IP List | `.txt` | Every Five Minutes | a Certificate Profile containing the box CA; Commit after creating the rule |
| pfSense | Firewall → Aliases → URLs, `URL Table (IPs)` | `.txt` | 1 day (the lowest pfSense allows) | import the box CA; a floating `Block` rule, direction out |
| OPNsense | Firewall → Aliases, `URL Table (IPs)` | `.txt` | ≥ 1 hour (OPNsense accepts days+hours) | a `Block` rule on LAN |
| MikroTik | a `/tool fetch` script + scheduler, loaded into `address-list` | `.txt` | 5 minutes | the script drops lines starting with `#`; `check-certificate=no` because the certificate is self-signed (risk: someone in the middle on the LAN gets the token **and** injects a list); importing the CA and turning on certificate verification is recommended |
| Pi-hole | Adlists, add the URL | `.domains.txt` | per the Pi-hole schedule (gravity) | needs the box CA to be trusted in Pi-hole |
| AdGuard Home | DNS blocklists, add the URL | `.domains.txt` | AdGuard's cycle (≥ 1 hour) | |

pfSense/OPNsense: a long interval (1 day/1 hour) means a **blocking delay** of hours/days; an entry with a TTL shorter than the pull interval may not take effect in time. The GUI should say this. A device with no API/SSH that does not pull a URL (an ISP modem) is not covered.

For commands that create an alias through an API (pfSense `Vedette_Blocklist`, OPNsense), the push action pack is used, not this spec (see `action-packs.md`).

## 9. Rotating the token

- `POST /response/blocklist/token` (admin, writes `core_audit` + the response log `blocklist_token`): generates a new token and **invalidates the old token at once** (mock: `blockMeta` replaces the token, `last_fetch` goes back to `null`), and returns the new URL.
- Because every firewall must change its URL, the GUI shows a warning before rotating (`regenerateBody`). **There is no transition period** in which two tokens are alive (to keep the spec simple; open question §12).
- Signs that rotation is needed: a suspected URL leak, staff leaving, a firewall replaced.
- After rotation, every request with the old token gets `404` and raises a "pulled with old token" counter so the administrator can see which device has not been updated (a counter per source IP; the old token is not stored verbatim).
- Rotating also resets `last_fetch`, so the GUI shows "never fetched" until the firewall pulls.

## 10. Sequence

```mermaid
sequenceDiagram
    participant E as Response engine
    participant C as core (response)
    participant F as Firewall
    E->>C: blocklist_add {ip, ttl} (approved)
    C->>C: check never-block, validate netip, merge duplicates
    C-->>E: executed (entry + expires_at)
    loop every firewall cycle
        F->>C: GET /response/blocklist/<token>.txt (If-None-Match)
        alt unchanged
            C-->>F: 304
        else changed
            C-->>F: 200 text/plain + ETag
        end
        F->>F: load the addresses, apply the DENY rule
    end
    Note over C: TTL expires: the cleanup job deletes the entry;<br/>the next pull no longer has it
```

## 11. Error handling

| Condition | Response |
|---|---|
| Wrong / rotated token | `404 Not found` (text/plain) |
| `response` module off | `404` |
| Store cannot be read | `503` + `Retry-After: 60` (never an empty list) |
| Rate limit exceeded | `429` + `Retry-After` |
| Any method other than `GET`/`HEAD` | `405` |
| A value added with the wrong type (not a valid IP/CIDR/domain) | rejected at the **add** step (the action fails), never enters the list |

## 12. Security considerations (mapping to SYS)

| SYS | Applies |
|---|---|
| SYS-1 | There is no execution path; the list is plain data |
| SYS-2 | `value` is validated with `netip`/IDNA before it is stored; `source`/`reason` are sanitised; the token follows a regex |
| SYS-3 | Adding/removing/rotating the token writes `core_audit` + the response hash-chain log |
| SYS-4 | The token is stored hashed, the URL is not logged, and is not exported in an export/error report (the GUI shows only the last 4 characters) |
| SYS-5 | Module off → no route |
| SYS-6 | IOCs/hits are untrusted data (they can be poisoned to block Google, a lesson from UPDATES §5): never-touch + the private/CGNAT exclusion list + a top-10k domain check before a feed is used + the engine needs approval |
| SYS-7 | Pulls are reachable only from the LAN; it is not an outbound Internet flow, so nothing is added to PRIVACY |
| SYS-8 | The AI only **proposes** actions (the "AI proposed" flag); an entry enters the list only after a person approves |

Known risks: (a) a leaked URL lets someone in the LAN read the list (they cannot write it); the list reveals only the malicious addresses that were blocked, not customer data; (b) the token in the URL easily ends up in the firewall's history/logs: accepted because it is the only mechanism these devices support; (c) a poisoned list leading to self-DoS: the protection layer is in §5; (d) someone in the middle on the LAN: TLS + a pinned CA, except the MikroTik script if it keeps `check-certificate=no`.

**Contract tests (the `contracts.md` rule) that must exist:** an entry whose `reason` contains `\n198.51.100.1` does not create a new value line; an expired entry is not in the response; `503` when the store fails instead of an empty list; an old token gets `404` right after rotation; an entry that equals never-touch does not appear.

## 13. Versioning

- The path is prefixed with `/api/v1`. The `.txt` format is a **hard contract** because customers' firewalls do not update along with Vedette: the line syntax does not change; only `#` comment lines may be added.
- `.json` may gain fields (forward compatible); changing the meaning of or removing a field = `/api/v2/…` running in parallel for a while.
- Changing the token does not change the format.

## 14. Open questions

1. **`kind` and `.domains.txt` are not yet in the mock** (the mock is IP only; `ipOnly` in the locale says plainly "IP addresses only"). The design requirement says "block destination IPs/domains" and mentions Pi-hole/AdGuard. A decision is needed: add `kind` + a domain variant in the backend phase (a small frontend change), or stay IP-only and let Pi-hole/AdGuard go through the push action pack.
2. The list syntax of AdGuard Home (`||domain^` or a plain domain) and Pi-hole: check against the official documentation when building.
3. Are two overlapping tokens needed during the transition (grace) when rotating, or cut immediately (this spec: cut immediately)?
4. The ceiling of 10,000 entries, and the limits of each vendor, have not been checked (§7).
5. Is a separate list in the **source** direction (isolating LAN machines) needed (this spec: no, use push).
6. Is a 128-bit token enough compared with 256 bits; the mock uses 16 hex bytes.
7. MikroTik: recommend importing the CA instead of `check-certificate=no` in the GUI instructions.
8. The real pull interval of pfSense/OPNsense is too long compared with a short TTL; should the GUI warn when TTL < the interval.
