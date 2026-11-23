# Vendor action packs

> **This is a library of action TEMPLATES in the form of data, not code.** The Vedette core has only generic connection kinds (HTTP API, SSH/CLI, NETCONF/RESTCONF, automation platforms such as Ansible AWX/n8n, MCP, block lists). Each entry below is an example template shipped with an update; customers can edit/add them, and the AI can draft one for another device for a person to approve. Vendor names are only examples.


Status: draft, written 2026-11-09. Basis: the current GUI catalogue in `web/src/features/response/data.ts`, `logic.ts`, `CatalogEditor.tsx`. Block lists that a firewall pulls: `docs/specs/blocklist-format.md` (a separate spec).

This document is the backend's contract for the `response` module: each action has an exact command/API, typed parameters, rollback, re-check, minimum permission and risk. GUI changes listed in section 12 need the maintainer's approval (the GUI-first rule) and are not made on their own.

## 0. How to read the verification labels

Every command, API path and JSON field belongs to one of two kinds:

- **[verified]**: read in the vendor's official documentation (the URL is given right under the entry). If it was seen only on an unofficial vendor page (the Fortinet community, a wrapper) it is labelled "community source".
- **unverified**: written from general knowledge or an unofficial source, not found in the official documentation when drafted. **Do not put it into production code** before running it on a real device/lab and changing the label to [verified] with a URL or "tried on <model, version> on <date>".

Two Fortinet documentation pages are very long (hundreds of thousands of characters) so the page-fetching tool returned only the menu; points taken from them are sourced to search results leading to the page on `docs.fortinet.com`. The full FortiOS REST API reference is behind a Fortinet Developer Network login, so FortiGate `cmdb`/`monitor` paths are unverified by default until tried on a device.

## 1. Common conventions for every pack

### 1.1 The record of an action (logical schema)

| Field | Meaning |
|---|---|
| `id` | a stable identifier, lowercase, for example `fgt_addrgrp_add` |
| `pack`, `name`, `description` | the pack, the name and a description in plain words |
| `connection` | the kind of connection needed (fortigate-rest, mikrotik-rest, ssh-cisco...) |
| `params` | a list of typed parameters, see 1.2 |
| `run`, `rollback`, `verify` | command/API templates for each step |
| `precheck` | a step that reads the state before writing (to decide idempotency and to save the old value for rollback) |
| `ttl` | the deadline for automatic removal, see 1.4 |
| `risk` | `low`, `medium`, `high` (1.5) |
| `ai_may_propose` | a flag that lets the AI propose it |
| `min_version` | the supported version range |

### 1.2 Typed parameters and escaping

Agent data (source IP, domain, device name, SNI, log content) is controlled by an attacker. Two mandatory layers: (1) type checking, rejecting if wrong; (2) escaping for the transport when it is put into a template. A value that does not pass layer 1 never reaches layer 2.

| Type | Check (layer 1) | Notes by transport (layer 2) |
|---|---|---|
| `ip` | `netip.ParseAddr`, drop the zone, `Unmap()`, the canonical form Go prints; reject unspecified, loopback, multicast, link-local, and every IP in the never-touch list | already normalised so it contains only `[0-9a-f.:]`; still escaped per JSON/URL/CLI below |
| `cidr` | `netip.ParsePrefix` then `Masked()`; block a prefix wider than the configured cap (default IPv4 `/16`, IPv6 `/48`) and every range that intersects the never-touch list | the mask form is set per vendor (FortiGate `a.b.c.d m.m.m.m`, Cisco wildcard); the backend converts it, the user does not type it |
| `domain` | lowercase, convert to punycode, RFC 1123 label regex (`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`), at most 253 characters, no wildcard, no IP | if the action uses a regex (Pi-hole `regex`): insert `regexp.QuoteMeta` and only then compose; **the first version does not support regex**, only `exact` |
| `port` | an integer 1 to 65535 | a number, no escaping |
| `mac` | 6 bytes, normalised `aa:bb:cc:dd:ee:ff` | the format is converted per vendor in the backend (Cisco `aabb.ccdd.eeff`) |
| `vlan` | an integer 1 to 4094, excluding the management VLAN and VLANs declared in the never-touch list | a number, no escaping |
| `interface` | a per-vendor regex (see each pack) **and** it must be in the snapshot of the port list read from the device (`precheck`), **and** not in the never-touch list (uplinks, the port connecting the Vedette box) | only characters `[A-Za-z0-9/.:-]` |
| `name` | `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$` (security.md) | safe inside double quotes of the FortiOS and RouterOS CLI |
| `id` (new proposal) | an integer 1 to 2^31-1; used for FortiGate's `policyid` | a number, no escaping. The GUI does not have this type yet, see section 12 |

Escaping by transport (matches `escapeFor` in `logic.ts`, stricter where stated):

- **JSON**: never concatenate strings into JSON text. Parse the template into a JSON tree, assign values to string nodes or arrays, and then serialise (Go `encoding/json`). The structure cannot change and no field can be added.
- **URL path**: `url.PathEscape` for each segment; a parameter that makes up a whole segment containing `/` is forbidden. No parameter goes into the scheme, host, port or userinfo.
- **Query**: `url.Values.Encode`.
- **Header**: no parameter goes into a header name; a header value rejects `\r`, `\n`.
- **CLI over SSH**: each command line is sent separately; a parameter that has passed layer 1 contains no whitespace, `"`, `\`, `;`, `|`, `?`, `$`, `[`, `]`, or control characters (`?` opens help in the FortiOS/Cisco CLI; `[` `]` `$` have meaning in RouterOS scripts). The final value must match line by line the stored template: after substitution, the number of lines equals the number of lines of the template.

### 1.3 Ownership mark (protecting against removing an administrator's object by mistake)

Every object Vedette creates on a device must carry a mark: a name prefix `vedette-` or `comment`/`description` = `vedette:<request_id>`. Rollback removes only an object that has this mark **and** matches the request. If the same IP already exists because an administrator created it (no mark): the action reports "already exists, not Vedette's", writes nothing and does not roll back.

### 1.4 TTL

- Prefer the **device's own** TTL (it keeps running while the Vedette box is off): MikroTik `timeout=`, FortiGate banned `expiry`, a pulled block list (entries come in/out by `expires_at`).
- A device with no native TTL (FortiGate address group, pfSense/OPNsense alias through the API, Cisco/Aruba ACL, Pi-hole, AdGuard): Vedette stores `expires_at` and runs the rollback when it is due. If the box is off at the due time: run it late on restart and show "overdue" on the Response screen. An automatic rollback at expiry also writes an audit entry and still requires the block entry to be on the "reversible without approval" list (a rollback adds no further harm).
- Maximum TTL by risk: low 30 days, medium 7 days, high 24 hours. No TTL only for an action with the `permanent` flag set by an administrator by hand.

### 1.5 Risk levels

- **low**: adding an entry to a block list outside the LAN (a destination IP/domain), a notification; removing it again affects nothing else.
- **medium**: blocking a **source** IP inside the LAN or on an inbound port; turning a switch port off/on; adding an ACL line on a switch.
- **high**: moving to a quarantine VLAN; disabling a VIP/policy that serves real users; anything that cuts a service. Needs 2 approvers.

Risk also rises one step with many targets (the rule's risk) or when the target is a device in the same service group.

### 1.6 Re-reading after running (verify)

Each action has a read-only `verify`, run after `run` and after `rollback`, compared with a specific expectation (for example "the entry is in the list", "the state is disable"). On a mismatch: mark the action `uncertain`, do not retry on its own more than once, notify the approver, and stop the chain. An HTTP 2xx return code or a command line without an error is **not** treated as verification (ships-as-code).

### 1.7 The preferred pull path

Blocking a destination IP/domain: prefer the `blocklist_add` action and let the firewall pull it, because it needs no write permission on the firewall. The packs below are the push path, used when (a) an immediate block is needed (the pull cycle is slow), (b) the device cannot pull, (c) an action that is not a list is needed (VIP, port, VLAN). Pull cycles differ markedly: FortiGate 1 to 43200 minutes [verified], OPNsense has "Refresh frequency" [verified but the unit is unclear], pfSense URL Table is unverified (may be counted in days), and MikroTik writes its own `fetch` schedule.

---

## 2. FortiGate (FortiOS REST API)

**Versions**: the target is FortiOS 7.2 to 7.6; 7.0 is best effort only. The CLI command `diagnose user banned-ip` exists from 7.2; versions 6.0/7.0 use `diagnose user quarantine list` [verified, Fortinet community source]. Administration guides 7.2.7, 7.4.6, 7.6.5 have been seen for the REST API page.

**Sources**:
- Using the API, the Bearer token, the REST API administrator: https://docs.fortinet.com/document/fortigate/7.4.6/administration-guide/940602 and https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/399023
- Threat feed (External Block List): https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/891236/external-blocklist-threat-feed
- CLI `config system external-resource`: https://docs.fortinet.com/document/fortigate/7.4.0/cli-reference/72620
- The banned IP list: https://community.fortinet.com/fortigate-3/technical-tip-how-to-list-or-remove-a-banned-ip-from-the-list-on-a-fortigate-92714 (the Fortinet community, not official documentation)
- The full REST API reference: Fortinet Developer Network, needs a login (could not be read)

### 2.1 Connection and minimum permissions

- Authentication: an API token sent in the header `Authorization: Bearer <token>` [verified]. The token is **shown only once** at creation and FortiGate does not provide it again [verified]. A token in a URL is not used (from 7.6 a new global setting must be turned on to allow it) [verified]. Only an administrator with the `super_admin` profile can create a REST API administrator [verified].
- Trusted hosts: required, only the Vedette box's IP; `0.0.0.0/0` is not allowed [verified]. FortiGate checks the trusted hosts of an ordinary administrator first and then the api-user's trusted hosts (community source).
- The administration profile (`accprofile`) grants only what is needed. Proposed minimum (field names unverified; confirm in the CLI of the exact version):

```
config system accprofile
    edit "vedette-response"
        set fwgrp custom
        config fwgrp-permission
            set address read-write
            set policy read-write
        end
        set authgrp read-write
    next
end
config system api-user
    edit "vedette"
        set accprofile "vedette-response"
        config trusted-hosts
            edit 1
                set ipv4-trusted-host <vedette-box-ip>/32
            next
        end
    next
end
execute api-user generate-key vedette
```

  Note: `authgrp` is needed only for `user/banned`; drop it if the ban action is not used. `policy` is needed only for disabling/enabling policies and VIPs. The Vedette box requests exactly the permissions of the actions the customer turned on (the interface shows the "permissions to grant" per enabled action). Never use the `super_admin` profile and never grant `sysgrp` (system configuration) to Vedette.
- Repeated wrong keys can lock out an API administrator for a while (the title of a community post "administrative lockout durations for FortiGate API users", content not read): the box does not retry a wrong token and reports the authentication error at once.
- VDOM: every REST command adds `?vdom=<name>` when VDOMs are used (unverified). Store `vdom` in the connection.
- There is no commit step: REST `cmdb` takes effect at once. The CLI over SSH also takes effect at `next` or `end` (unverified). HA: a change on the primary is synchronised to the secondary (unverified); a FortiGate managed by FortiManager may have local objects overwritten when the policy is reinstalled (unverified), so a lab is needed if the customer uses FortiManager.

### 2.2 `fgt_addrgrp_add` / `fgt_addrgrp_remove`: add/remove an address in an address group

- Description: "Add an IP or range to the address group `Vedette-Blocked`; an existing block policy that uses that group will cut that IP". The customer creates the block policy once (the box may print the CLI snippet as guidance, and does not create it itself).
- Parameters: `ip` or `cidr` (one of the two, the type fixed by the template); the group's `name` defaults to `Vedette-Blocked`, configured on the connection, not taken from the agent.
- Address object name: `vedette-<ip>` for IPv4 (the `.` is valid); CIDR: `vedette-<ip>_<len>`. The maximum name length is unverified (believed to be 79 characters). The name is generated by the backend from a checked value, not from the agent.
- REST transport (paths unverified, following FortiOS's `cmdb` convention):
  1. `precheck`: `GET /api/v2/cmdb/firewall/address/vedette-{ip}` and `GET /api/v2/cmdb/firewall/addrgrp/Vedette-Blocked`. If the address is already a member: `already exists`, no write.
  2. `POST /api/v2/cmdb/firewall/address` body `{"name":"vedette-{ip}","type":"ipmask","subnet":"{ip} 255.255.255.255","comment":"vedette:<request_id>"}`
  3. `POST /api/v2/cmdb/firewall/addrgrp/Vedette-Blocked/member` body `{"name":"vedette-{ip}"}`
- Equivalent CLI (unverified):

```
config firewall address
    edit "vedette-{ip}"
        set subnet {ip} 255.255.255.255
        set comment "vedette:<request_id>"
    next
end
config firewall addrgrp
    edit "Vedette-Blocked"
        append member "vedette-{ip}"
    next
end
```

- Rollback (in the right order: remove from the group first, delete the object afterwards, because an object that a group references cannot be deleted):
  1. `DELETE /api/v2/cmdb/firewall/addrgrp/Vedette-Blocked/member/vedette-{ip}`
  2. `DELETE /api/v2/cmdb/firewall/address/vedette-{ip}`
  CLI: `config firewall addrgrp` / `edit "Vedette-Blocked"` / `unselect member "vedette-{ip}"` / `next` / `end`, then `config firewall address` / `delete "vedette-{ip}"` / `end`.
- Re-check: `GET /api/v2/cmdb/firewall/addrgrp/Vedette-Blocked`; expect `member[]` to contain/not contain `vedette-{ip}`. CLI: `show firewall addrgrp Vedette-Blocked`.
- Risk: `medium` if `ip` is a source inside the LAN; `low` if it is an outside IP. Classified by the trigger's "source/destination" flag.
- Pitfalls:
  - **A FortiOS address group needs at least one member** (unverified in the documentation, but common behaviour): removing the last member gives an error. Solution: the group always has an anchor member `vedette-anchor` = `192.0.2.1/32` (TEST-NET-1, a documentation address, never routed). The box builds the anchor in a one-time guidance step and never removes it.
  - The block policy must be **above** the allow policies; the box only checks at the end (`GET /api/v2/cmdb/firewall/policy`, unverified) and warns if the order is wrong, and does not change it itself.
  - An address object has a count cap that depends on the model; the box sets a low `max_per_hour` and counts group members, refusing when above 80% of the configured cap.
  - No native TTL: Vedette rolls back by itself (1.4).
  - Idempotent: two `run`s for the same IP do not create a copy thanks to `precheck`; a POST with a duplicate name returns an error so it must not be treated as a silent success.
- Version: the REST API token from FortiOS 5.6 and above (unverified); target 7.2 to 7.6.

### 2.3 `fgt_ban_ip` / `fgt_unban_ip`: ban an IP

- Description: "Put the IP on FortiGate's banned list: every session of the IP is cut and new sessions are refused until it expires or is removed". It needs no separate policy and has a native TTL, so it is the tidiest way to block a source inside the LAN.
- Parameters: `ip`; `ttl` in seconds (converted to seconds by the backend, not typed by the user); `ttl` should match the action's TTL.
- REST (path and fields unverified):
  - `POST /api/v2/monitor/user/banned/add_users` body `{"ip_addresses":["{ip}"],"expiry":<seconds>}`
  - Basis: the Ansible module `fortios_monitor` lists the actions `add_users.user.banned`, `clear_users.user.banned`, `clear_all.user.banned`, and `add_users` takes an array of IPs and supports IPv4 and IPv6 [verified through Ansible documentation, not Fortinet documentation]: https://docs.ansible.com/ansible/latest/collections/fortinet/fortios/fortios_monitor_module.html . The `expiry` field is inferred from a third-party wrapper (hfortix) and is **unverified**.
- CLI (a Fortinet community source for `list`, `stat`, `clear`, `delete`; **the `add` command is unverified**, the post says plainly that it does not mention a manual add command):
  - View: `diagnose user banned-ip list`; count: `diagnose user banned-ip stat`
  - Remove one entry: `diagnose user banned-ip delete src4 {ip}` (IPv6: `src6`) [verified, community]
  - Add: `diagnose user banned-ip add src4 {ip}` is the command the GUI currently uses, **unverified**; ask `diagnose user banned-ip ?` on a real device to get the syntax that has `expiry`.
- Rollback: `POST /api/v2/monitor/user/banned/clear_users` body `{"ip_addresses":["{ip}"]}` (unverified), CLI `diagnose user banned-ip delete src4 {ip}`.
- Re-check: `GET /api/v2/monitor/user/banned` (unverified) expecting the IP to be/not be in `results`; CLI `diagnose user banned-ip list`.
- Risk: `medium` (completely cuts off a machine inside the LAN); a destination outside the LAN cannot use this method.
- Pitfall: the banned list may **not survive a restart** unless `config firewall global` / `set banned-ip-persistency {disabled|permanent-only|all}` [verified, community]. With a `ban` of short TTL, losing it on restart is acceptable; the box must read again and treat a lost entry as "already removed", not report an error. A ban cannot replace "never touch": the box itself refuses an IP in the never-touch list before calling.
- Version: the CLI command from 7.2 and above; 6.0/7.0 use `diagnose user quarantine` (different syntax, not supported in the first backend phase).

### 2.4 `fgt_vip_disable` / `fgt_vip_enable`: turn a VIP (port forwarding/NAT) off/on

- Description: "Turn off the VIP mapping that exposes a service to the Internet; outside users lose access until it is turned back on; the office network is unchanged".
- Parameters: `name` (the VIP name, which must be in the VIP list read in `precheck`).
- **Warning**: the `status` field on `firewall vip` is **unverified**; the GUI currently assumes `set status disable`. If it does not exist on a real device, use the alternative below (disable the policy, 2.5).
- REST (unverified): `PUT /api/v2/cmdb/firewall/vip/{name}` body `{"status":"disable"}`; rollback `{"status":"enable"}`. Save the old state in `precheck` (`GET /api/v2/cmdb/firewall/vip/{name}`); if the VIP was already `disable` beforehand, the action does not roll back to `enable`.
- CLI (unverified): `config firewall vip` / `edit "{name}"` / `set status disable` / `next` / `end`.
- Re-check: `GET /api/v2/cmdb/firewall/vip/{name}` expecting `status`.
- Risk: `high`. Pitfall: the VIP is referenced by a policy; turning the VIP off does not delete open sessions (a manual `diagnose sys session clear` may be needed, which the box does not do).
- Version: target 7.2 to 7.6, pending lab confirmation.

### 2.5 `fgt_policy_disable` / `fgt_policy_enable`: turn a firewall policy off/on

- Description: "Fully turn off a firewall policy by its policy number; traffic that matched that policy falls to the next policy".
- Parameters: `id` (policyid, the new integer type), a list of allowed policyids declared by an administrator for the action (the box does not allow choosing a policyid outside that list).
- REST (unverified): `PUT /api/v2/cmdb/firewall/policy/{id}` body `{"status":"disable"}`; rollback `{"status":"enable"}`.
- CLI (unverified): `config firewall policy` / `edit {id}` / `set status disable` / `next` / `end`.
- Re-check: `GET /api/v2/cmdb/firewall/policy/{id}` expecting `status`.
- Risk: `high` (turning off an "allow" policy loses a service; turning off a "deny" policy lets more traffic through). The box refuses if the policy has `action` = `deny` (read in `precheck`): turning off a block policy is never a safe action.
- Pitfall: `policyid` is a number, not a name; the number can change if an administrator deletes and recreates the policy; save the policy's `name` too in `precheck` and compare it before rolling back.

### 2.6 `fgt_ebl_setup`: connect an External Block List (Threat Feed)

- Description: "Create an external block list connection on the FortiGate that points to the block list URL of the Vedette box; the FortiGate pulls it by itself on a cycle". This is the preferred path: the firewall pulls by itself.
- Unlike the actions above: this is a **one-time setup**, not tied to an event. The configuration `system external-resource` belongs to the system permission group (unverified); Vedette does **not** ask for that permission. By default the box **shows the CLI snippet for the administrator to paste** and does not call the API.
- Syntax [verified] (the FortiOS CLI page and a Fortinet community post):

```
config system external-resource
    edit "Vedette-Blocklist"
        set type address
        set resource "https://<box-ip>:<port>/blocklist/<token>/ip.txt"
        set refresh-rate 5
    next
end
```

  `refresh-rate` 1 to 43200 minutes, default 5 [verified]. Feed types on FortiOS 7.4: IP address, domain name, MAC address (new), malware hash, FortiGuard category [verified, from the documentation's table of contents]. The file format (one entry per line) and the URL path are defined by `docs/specs/blocklist-format.md` and are not repeated here.
- Use in a policy: a feed of type `address` goes into a policy as an address object (unverified); use in a DNS filter through `set external-ip-blocklist "<name>"` [verified, community post].
- An optional REST path if an administrator issues a temporary token themselves: `POST /api/v2/cmdb/system/external-resource` (unverified). Recommended not to.
- Rollback: `config system external-resource` / `delete "Vedette-Blocklist"` / `end`.
- Re-check: the check is on the box side: the box sees the **first download request** from the firewall IP to the URL with the token (written in the access log) within 2 `refresh-rate` cycles. If it does not, it reports "the firewall has not pulled yet". The pull status on the firewall: `diagnose sys external-resource` (a command form that is unverified).
- Risk: `low` for the box (nothing is written to the firewall); `medium` for the firewall (a feed-based block policy). For the token in the URL see `blocklist-format.md` on rotation; HTTPS with the box's certificate must be trusted by the FortiGate (FortiGate verifies certificates, depending on version, unverified).
- Pitfall: a device that cannot reach the box's address (NAT, a management VLAN) gets an empty feed; the pull cycle is the minimum blocking delay.

---

## 3. MikroTik RouterOS (REST API v7 and CLI)

**Versions**: REST exists from RouterOS v7.1beta4 [verified]; HTTP access (no TLS) from v7.9 [verified] (not used). The target is RouterOS 7.9 and above; v6 has no REST, so only SSH/the old API (outside the scope of the first backend phase).

**Sources**:
- REST API: https://help.mikrotik.com/docs/spaces/ROS/pages/47579162/REST+API
- Address lists: https://help.mikrotik.com/docs/spaces/ROS/pages/130220135/Address-lists (the page points to https://manual.mikrotik.com/docs/ , a frozen copy)
- Firewall matchers/actions: https://help.mikrotik.com/docs/spaces/ROS/pages/250708064/Common+Firewall+Matchers+and+Actions

### 3.1 Connection and minimum permissions

- Authentication: HTTP Basic with a RouterOS user [verified]; the path root is `https://<router>/rest` through the `www-ssl` service [verified]. Mapping: `GET`=print, `PUT`=add (one record per request), `PATCH`=set, `DELETE`=remove by ID, `POST`=any console command [verified].
- Certificate: use the certificate an administrator imports into Vedette (a CA or a pinned fingerprint); no `-k`.
- A dedicated user `vedette` in a dedicated group, with only the permissions needed (policy names unverified; confirm with `/user group print` of the exact version):

```
/user group add name=vedette-response policy=read,write,rest-api,api comment="Vedette response"
/user add name=vedette group=vedette-response address=<vedette-box-ip>/32 password=<strong> comment="Vedette response"
/ip service set www-ssl disabled=no address=<vedette-box-ip>/32
```

  Do not grant `policy`, `ftp`, `sniff`, `sensitive`, `password`, `reboot`, `test`. Limit `address=` on the user and the services to the box's IP. The hypotheses that `rest-api` is a separate policy name and that `write` is enough for `address-list add` are both **unverified**.
- A firewall rule is required first, created once by the customer: a `drop` rule (input/forward, or `raw` prerouting to save CPU) that matches `src-address-list=vedette-block` and/or `dst-address-list=vedette-block`. Vedette does not create this rule with REST (it needs wider `policy`/`write` permission).

### 3.2 `mt_addrlist_add`: add an address to an address-list with a timeout

- Description: "Add an IP/range to the router's address list `vedette-block`; the router removes it by itself after the deadline".
- Parameters: `ip` or `cidr` (RouterOS accepts `1.2.3.0/24` in the `address` field); `ttl` converted to the RouterOS form (`1d`, `1h30m`, `00:30:00`); the list name `vedette-block` is fixed on the connection. `domain` is not used in the first version (RouterOS resolves the name and attaches several IPs to the entry, and a name's TTL may be removed at the same time, unverified).
- REST: `PUT /rest/ip/firewall/address-list` body `{"list":"vedette-block","address":"{ip}","timeout":"<ttl>","comment":"vedette:<request_id>"}` [verified method/path; the fields are taken from the documentation's example `PUT /rest/ip/address`; the field names `list`, `address`, `timeout`, `comment` are unverified on the REST page but coincide with the CLI properties]. It returns the object just created with `.id`, **store `.id` as the evidence for rollback** [verified: PUT returns the object with `.id`].
- CLI: `/ip firewall address-list add list=vedette-block address={ip} timeout=<ttl> comment="vedette:<request_id>"`
- `precheck`: `GET /rest/ip/firewall/address-list?list=vedette-block&address={ip}` [verified: filtering with query parameters, for example `GET /rest/ip/address?network=...&dynamic=true` in the documentation]. If it is already there, skip and record "already exists".
- Rollback: `DELETE /rest/ip/firewall/address-list/<id>` [verified: `DELETE` by ID; repeating returns `{"error":404,"message":"Not Found"}`, and rollback treats 404 as already removed]. If `id` is not known (the box restarted): first `GET` with a filter like `precheck` to find `id`, removing only an entry whose `comment` starts with `vedette:`. CLI: `/ip firewall address-list remove [find list=vedette-block address={ip} comment~"^vedette:"]` (the `~` operator is unverified).
- Re-check: `GET /rest/ip/firewall/address-list?list=vedette-block&address={ip}` expecting the entry to be present/absent.
- Risk: `low` if the IP is outside the LAN and the rule uses only `dst-address-list`; `medium` if the IP is a source inside the LAN and the rule uses `src-address-list`.
- Pitfalls:
  - **An entry with `timeout` lives in RAM and is lost when the router restarts**; without `timeout` it is stored permanently [verified, MikroTik wiki: https://wiki.mikrotik.com/Address_list]. For a temporary block this is desirable; do not drop `timeout`.
  - A duplicate add (the same `list`+`address`) on RouterOS usually reports the error "already have such entry" (unverified): `precheck` avoids the collision, and this error still goes through the re-read step rather than being ignored.
  - One `PUT` request creates only one record [verified]; a chain of several IPs is several requests, subject to the rule's entries/hour limit.
  - A firewall rule's `address-list-timeout` behaves differently (a dynamic entry created by the rule); Vedette does not touch it.
- Permissions: see 3.1. Version: 7.9 and above.

### 3.3 `mt_addrlist_remove`: remove an address

- This is the rollback of 3.2, and also a standalone action for "unblock". The REST/CLI template is like the rollback in 3.2; `precheck` must read `comment` (an administrator's entry is not removed); `verify` as in 3.2. Risk `low`.

---

## 4. pfSense and OPNsense

Both have an official **pull** path (URL Table). The push paths differ greatly: OPNsense has an official REST API; pfSense has **no** official REST API from Netgate.

### 4.1 OPNsense (official REST API)

**Sources**:
- API firewall (alias, alias_util): https://docs.opnsense.org/development/api/core/firewall.html
- Using the API, key/secret: https://docs.opnsense.org/development/how-tos/api.html
- Aliases and the External type: https://docs.opnsense.org/manual/aliases.html

**Connection and permissions**
- Authentication: HTTP Basic, the key is the user name and the secret is the password; created in user management, and the secret is **downloaded once** [verified]. The key's permissions = the permissions of the user that owns it (the documentation does not describe the detailed computation) [partly verified].
- A dedicated user `vedette-api` belonging only to a group that has the page permissions needed for aliases (the exact permission names are unverified; try by granting the minimum and checking for a 403 error). Do not grant full administration rights.
- A valid HTTPS certificate for a real environment; do not skip certificate verification [verified: a recommendation in the documentation].
- The customer first creates an alias of type **External (advanced)** named `Vedette_Blocklist` and a block rule on that alias. Only aliases of type Host, Network, External accept `alias_util/add` [verified]; the External type is the type created for an outside program to push entries [verified]. Vedette does not create aliases with REST (it needs `alias/add_item` and `reconfigure`, wider permissions).

**`opn_alias_add` / `opn_alias_remove`**
- Description: "Add/remove an IP in OPNsense's alias `Vedette_Blocklist`; the block rule on the alias does the rest".
- Parameters: `ip` or `cidr`; the alias name `name` is fixed on the connection.
- REST [verified method/path from the documentation and the alias page]:
  - Add: `POST /api/firewall/alias_util/add/Vedette_Blocklist` body `{"address":"{ip}"}`
  - Remove: `POST /api/firewall/alias_util/delete/Vedette_Blocklist` body `{"address":"{ip}"}`
  - List: `GET /api/firewall/alias_util/list/Vedette_Blocklist`
  - Empty: `POST /api/firewall/alias_util/flush/Vedette_Blocklist` (not used; outside the allowlist because it deletes other people's entries too)
  - Unverified: the field name of the `address` array when adding several IPs, and the response form.
- `precheck`/`verify`: `GET /api/firewall/alias_util/list/Vedette_Blocklist` expecting the IP to be/not be in the response array.
- Risk: `low` (outside IP) / `medium` (a source inside the LAN).
- Pitfalls:
  - **Entries added through the API are not kept across a restart; `flush` is not durable either** [verified, the aliases page]. Acceptable for a temporary block; the box re-synchronises the list from the table of open requests after it detects that OPNsense restarted (keeping `connection.last_seen_boot`, how to read it is unverified).
  - Existing states need to be cleared if the rule uses state tracking, otherwise open connections stay alive [verified, the aliases page]. The box does **not** clear states by itself in the first version; the result records "open connections may remain".
  - A forum report about an old version (19.1): adding a third entry loses the old entries (a search result, a forum source); it must be checked again on the target version with a "add 3 entries and read back" trial before it is turned on.
  - No native TTL: Vedette rolls back by itself.
- Version: the first version that has `alias_util` is unverified; the target is OPNsense 24.x and above, confirmed in a lab.

**`opn_urltable_setup`** (a one-time setup, the pull path): create an alias of type **URL Table (IPs)** pointing at the box's block list URL, and set "Refresh frequency" [verified that the type and option exist; the unit is unclear]. The box prints the instructions and the administrator does it in the interface. Re-check on the box side: it sees the first download request from the firewall IP. Risk `low`.

### 4.2 pfSense

**The actual situation, said plainly**: Netgate does not publish an official REST API for pfSense. The REST API package (`pfsense-pkg-restapi`, documentation pfrest.org, maintainer Jared Hendrickson) is **unofficial**, "not affiliated with or supported by Netgate or the pfSense team" [verified: https://pfrest.org/]. Netgate keeps an OpenAPI specification at https://netgate.github.io/pfsense-api/ (scope and level of support unverified). FauxAPI is another third-party package, not used. No `docs.netgate.com` page was found that talks about a REST API.

So Vedette ranks three options by level of trust:

1. **Pull (official)**: an alias of type URL Table (IPs) pointing at the box's block list. The description of the alias type is at https://docs.netgate.com/pfsense/en/latest/firewall/aliases.html (the page only mentions that URL Table exists, with details on the "Alias Types" page, which could not be read). **The minimum update cycle of the pfSense URL Table is unverified** (it may be in days, which is too slow for an immediate block): check before presenting it to customers as the main method.
2. **Push through the unofficial REST package**: used when the customer has installed the package themselves. Label it "unofficial" in the interface (like the way personal Zalo is labelled). The v2 package: the paths `/api/v2/firewall/alias` (update the alias's `address` array) and `/api/v2/firewall/apply` (apply) are **unverified** (the pfrest.org page does not list endpoints in the part that could be read; Swagger is self-served at System > REST API > Documentation after installation [verified]). The GUI currently uses `/api/v1/firewall/alias/entry`, the old v1 branch, which is **not** used in this spec.
3. **Push through SSH + `pfctl`** (unverified in Netgate documentation; `pfctl` is a FreeBSD tool): `pfctl -t Vedette_Blocklist -T add {ip}`, `pfctl -t Vedette_Blocklist -T delete {ip}`, `pfctl -t Vedette_Blocklist -T show`. Pitfall: running `pfctl` needs root, so the SSH account has very high privilege (no smaller minimum permission exists), and entries added with `pfctl` are usually lost when the filter is reloaded (unverified). Only for the "custom template" list with a warning, and not in the built-in templates.

**`pf_alias_add` / `pf_alias_remove` (option 2, unofficial)**
- Description: "Add/remove an IP in pfSense's alias `Vedette_Blocklist` through the unofficial REST package".
- Parameters: `ip`; the alias name is fixed on the connection.
- Run/rollback: read the alias, then `PATCH` the `address` array (add/remove exactly one element), then `POST /api/v2/firewall/apply`. All **unverified**; write code only after reading the package's own Swagger on a lab machine.
- Permissions: the package uses a pfSense user; grant the minimum page permission `Firewall: Aliases` (permission name unverified). Do not use `admin`.
- Risk: `low` (outside IP) / `medium` (a source inside the LAN). Pitfall: `apply` must be called after each change, apply reloads the filter and may drop connections briefly; merge changes and use `max_per_hour`.
- Rollback and re-check: remove the element and then `apply`; read the alias again.

---

## 5. Cisco IOS / IOS-XE (SSH)

**Sources**:
- ACL sequence numbers (named standard/extended): https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/sec-vpn/b-security-vpn/m_sec-acl-seq-num.html and https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_data_acl/configuration/xe-3s/sec-data-acl-xe-3s-book/sec-acl-seq-num.html
- ACL configuration on Catalyst: https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960xr/software/15-2_4_e/configuration_guide/b_1524e_consolidated_2960xr_cg/b_1524e_consolidated_2960xr_cg_chapter_01100000.html

**Versions**: IOS 15.x, IOS-XE 16.x/17.x (usable for Catalyst 9000, 2960-XR and above). The commands below are written per design; each command is labelled explicitly.

### 5.1 Connection, minimum permissions

- SSH v2 through a Go library (not through the box's shell), the host key pinned the first time and **stopping if the key changes** (never ignored), public-key authentication preferred, and no `enable` password sent in a template. One session at a time per connection (a queue per device). Startup: `terminal length 0`, `terminal width 511` (`width` is unverified on every platform).
- Read the output by the command prompt with a timeout; every line beginning with `%` (an IOS error such as `% Invalid input detected`) is a **failure**: stop the chain and run `end`.
- Minimum permissions: create a local user with its own privilege level that has only the commands needed. The template is based on `privilege` (**unverified**, the name of the ACL sub-mode differs by version; try on a lab machine):

```
username vedette privilege 7 secret <strong>
privilege exec level 7 configure terminal
privilege exec level 7 show ip access-lists
privilege exec level 7 show interfaces
privilege exec level 7 show running-config
privilege exec level 7 write memory
privilege configure level 7 ip access-list extended
privilege configure level 7 interface
privilege interface level 7 shutdown
privilege interface level 7 switchport access vlan
```

  A stronger way: AAA with TACACS+/ISE authorising each command (`aaa authorization commands`), or `parser view`; both are unverified in detail. If the customer uses level 15 for convenience: the interface warns and it is written to the audit.
- Protecting the never-touch port list: uplinks, Port-channel, the port connecting the Vedette box and important APs/cameras the customer declares.
- The list of **forbidden** commands in every Cisco template (the box refuses to save them): `reload`, `erase`, `write erase`, `delete`, `format`, `copy` (except `copy running-config startup-config` in the save action), `no ip access-list`, `no interface`, `crypto`, `username`, `enable`, `aaa`.

### 5.2 `cisco_acl_deny` / `cisco_acl_remove`: block an IP with an ACL (a named extended ACL, inserted at the top)

- Description: "Add a `deny` line for the IP to the ACL `VEDETTE-BLOCK` before every other line; the ACL has been attached by the customer to the uplink port (once)". The box does **not** attach the ACL to a port; the customer does that once.
- ACL design (the customer creates it once, the box prints a template):

```
ip access-list extended VEDETTE-BLOCK
 2147483000 permit ip any any
!
interface <uplink>
 ip access-group VEDETTE-BLOCK in
```

  An important point: an ACL ends with an implicit `deny ip any any`; an ACL with only `deny` lines would block **all** traffic. A `permit ip any any` line at a very large sequence number is mandatory, and Vedette inserts only at a number **smaller** than it. The maximum IOS sequence number is unverified in the sources read (expected 2147483647).
- Parameters: `ip` (source) or `cidr` (converted to `wildcard`); the ACL name is fixed on the connection (`name`).
- Inserting at the top: the sequence number convention in the design: Vedette lines use a number in the range `1`-`1000000`, assigned as "the smallest number in use minus 1" (`precheck`: `show ip access-lists VEDETTE-BLOCK` and then compute). If the smallest number is already `1`, run `ip access-list resequence VEDETTE-BLOCK 100 10` (it creates a gap, and does **not** change the order; old lines keep their order) [verified: resequence only creates/widens the spacing and does not reorder; for example `ip access-list resequence 150 1 2`, a Cisco community source]. Because Vedette's ACL contains only separate `deny host` lines, the order among them has no effect.
- Run (command lines, each sent separately):

```
configure terminal
ip access-list extended VEDETTE-BLOCK
{seq} deny ip host {ip} any log
end
```

  The form with a sequence number in a named ACL [verified: the feature applies to named standard/extended ACLs, the default numbers 10 apart]. The `log` keyword is unverified on every platform, drop it if the device reports an error. With `cidr`: `{seq} deny ip <network> <wildcard> any`.
- Rollback (by the **stored sequence number**, not by content, so that nothing is removed by mistake): `configure terminal` / `ip access-list extended VEDETTE-BLOCK` / `no {seq}` / `end`. Sequence numbers are **not kept across a restart** (they are renumbered from the start) [verified], so after the device restarts the box reads the ACL again and searches by the content `deny ip host {ip} any` to recover the number.
- Re-check: `show ip access-lists VEDETTE-BLOCK`; expecting the line `{seq} deny ip host {ip} any` to be present/absent. The match count (`(N matches)`) is extra information and is not used as a criterion yet.
- Risk: `medium`. The risk rises if `ip` is a needed internal source (gateway, DNS), so the never-touch list applies strongly.
- Pitfalls:
  - **A configuration that is not saved is lost on restart**: by default the box does not save (see 5.5). For a block with a TTL, losing it on reload is safe behaviour.
  - IOS accepts duplicate content under a different sequence number (unverified); `precheck` reads the ACL to avoid that.
  - A large ACL costs TCAM on the switch; set `max_per_hour` and a cap on the number of entries (for example 200) on the connection.
  - It takes effect only in the direction/interface where the ACL is attached; the box cannot know that in advance, so `verify` only confirms that the line is in the ACL and does **not** confirm that traffic has been blocked.
  - No native TTL: Vedette rolls back by itself (`time-range absolute end` could be used, unverified, costing one time object per entry: not used yet).

### 5.3 `cisco_port_shut` / `cisco_port_noshut`: turn a port off/on

- Description: "Turn off a switch port; whatever is plugged in loses its network until it is turned back on".
- Parameters: `interface` (regex `^(Fa|Gi|Te|Twe|Fo|Hu|Eth)[A-Za-z]*\d+(/\d+){0,3}$`, no Port-channel and no port in the never-touch list in the first version); it must be in the snapshot of `show interfaces status` in `precheck`.
- Run: `configure terminal` / `interface {interface}` / `shutdown` / `end`. Rollback: `no shutdown`. Both [standard IOS commands, unverified on the pages read].
- `precheck`: `show interfaces {interface} status` records the old state; if it is already `disabled`, the action records "already off beforehand" and the rollback does **not** turn it back on (it was not turned off by Vedette).
- Re-check: `show interfaces {interface} status`, expecting the Status column `disabled` after turning off, `connected`/`notconnect` after turning on.
- Risk: `medium` (turning off); a PoE device (camera, phone, AP) loses power as well. Risk `high` if the port has several devices behind it (the snapshot shows several MACs: `show mac address-table interface {interface}`, command form unverified); the box raises the level itself.
- Pitfall: turning off a port through which the Vedette box/customer is connected by SSH would cut the control session itself: the port that connects the box is in the never-touch list.

### 5.4 `cisco_port_vlan_quarantine` / `cisco_port_vlan_restore`: move an access port to a quarantine VLAN

- Description: "Move an access port to a quarantine VLAN (with no path to the servers); the device keeps its link but loses everything else".
- Parameters: `interface`, `vlan` (the quarantine VLAN chosen by the customer on the connection, not taken from the agent).
- A mandatory `precheck` (without it, it does not run):
  1. `show interfaces {interface} switchport`: it must be in static **access** mode (`Administrative Mode: static access`); trunk or dynamic is refused.
  2. Record the current access VLAN (`Access Mode VLAN: <n>`) as the rollback value.
  3. `show vlan id {vlan}`: the quarantine VLAN must **already exist** (on some switches `switchport access vlan` to a VLAN that does not exist creates a new VLAN, so check it yourself; unverified in the Cisco sources read).
- Run: `configure terminal` / `interface {interface}` / `switchport access vlan {vlan}` / `end`.
- Rollback: `switchport access vlan <the stored old value>` (when the old one was the default 1: `no switchport access vlan`).
- Re-check: `show interfaces {interface} switchport`, expecting `Access Mode VLAN: {vlan}`; after rollback expecting the old VLAN.
- Risk: `high` (2 approvers). Labelled `ai_may_propose` (the GUI currently has `true` for this action).
- Pitfalls:
  - The device keeps the DHCP address of the old VLAN until the link flaps; the quarantine VLAN may therefore need its own DHCP. It does not `shutdown`/`no shutdown` by itself within the same action.
  - 802.1X/MAB dynamic VLAN assignment may override the static value (unverified), and `verify` also re-reads the `Operational Mode`/the actual VLAN.
  - A port with a voice VLAN or `port-security` needs a separate check (unverified).

### 5.5 `cisco_save_config`: save the configuration

- Description: "Write the running configuration to startup memory so that it remains after a restart".
- Run: `write memory` or `copy running-config startup-config` (unverified in the sources read; standard IOS). Re-check: the result `[OK]`, plus reading `show startup-config | include VEDETTE` (unverified).
- **By default the box does NOT save** after the actions in 5.2 to 5.4. Reason: saving also writes every unsaved change of other administrators, and a temporary block should disappear on restart. Only a `permanent` action or an approver who chooses "save" calls this action.
- Risk: `medium` (a permanent consequence if the configuration has an error). Rollback: there is no automatic rollback (a configuration backup is needed); the box writes `show running-config | include <Vedette's objects>` to the audit before saving.

---

## 6. Aruba CX and ArubaOS-Switch / HPE

Two **completely different** platforms: AOS-CX (CX 6000/6100/6200/6300/8xxx, has REST) and ArubaOS-Switch (ProVision, 2530/2920/2930F/5400R, mostly CLI). Both in the first version: SSH CLI; the AOS-CX REST is a secondary path.

**Sources**:
- AOS-CX REST API (v10.04 to v10.16 have a reference page): https://developer.arubanetworks.com/aoscx/v10.13/reference/get_system
- POST ACL: https://developer.arubanetworks.com/aoscx/v10.13/reference/post_system-acls
- ACL entry: https://developer.arubanetworks.com/aoscx/v10.13/reference/acl_entry
- ArubaOS-Switch: no official page was found when drafting

### 6.1 Aruba AOS-CX

- Permissions: AOS-CX has built-in user groups (administrators, operators, auditors), and it is **unverified** which one allows ACL/port configuration with the smallest permission. By default `administrators` must be used: state this plainly in the interface and advise reducing the risk with (a) a management VRF and an ACL that lets only the box's IP into SSH/REST, (b) TACACS+/RADIUS command authorisation if the customer has it.
- SSH connection: the model of 5.1 (host key pinned, each line sent separately, an error beginning with `%` or CX's own error message line is treated as a failure, the message form being unverified).
- **ACL that blocks an IP (SSH, syntax unverified, try on a lab machine)**:

```
configure terminal
access-list ip VEDETTE-BLOCK
    {seq} deny any {ip}/32 any
exit
```

  Rollback: `no {seq}` in the `access-list ip VEDETTE-BLOCK` mode. Attach once: `interface <uplink>` / `apply access-list ip VEDETTE-BLOCK in`. An AOS-CX ACL also has an implicit `deny` at the end: a `permit any any any` at a large sequence number is needed (the written form is unverified). Re-check: `show access-list ip VEDETTE-BLOCK` (unverified).
- **ACL through REST** (paths per the reference page): `POST /rest/v10.xx/system/acls/{name},{list_type}/cfg_aces` creates a line, and each line is edited/deleted by sequence number (`.../cfg_aces/{sequence_number}`) [verified: the path exists and addressing is by sequence number; the fields of the request body are **unverified**, ACL name 1 to 64 characters]. The login session `POST /rest/v10.xx/login` is unverified in the sources downloaded (the page `post_login` was seen but not read). Enabling REST on the switch (`https-server rest access-mode read-write`, `https-server vrf mgmt`) is unverified.
- **Turn a port off/on** (CLI, unverified): `interface 1/1/{n}` / `shutdown`; rollback `no shutdown`; re-check `show interface 1/1/{n}`. AOS-CX port names have the form `1/1/1`; regex `^\d{1,2}/\d{1,2}/\d{1,3}$`. Note that on AOS-CX an unused interface may be `shutdown` by default (unverified): `precheck` reads the old state as in 5.3.
- **Move a port to the quarantine VLAN** (CLI, unverified): `interface 1/1/{n}` / `vlan access {vlan}`; rollback returns the old value that was read (`show interface 1/1/{n}` or `show running-config interface 1/1/{n}`); the `precheck` conditions are as in 5.4 (an access port, the quarantine VLAN exists).
- **Save the configuration**: AOS-CX separates running and startup configuration; `write memory` or `copy running-config startup-config` (unverified). The principle of 5.5 applies verbatim: by default do not save.
- Risk, TTL, rollback: as for Cisco (5.2 to 5.5), `high` for the quarantine VLAN.

### 6.2 ArubaOS-Switch (HPE ProVision)

- **No official documentation could be found when drafting**: every command below is unverified. There is no confirmation of REST v7 for ACLs; the first version is **SSH only**.
- Permissions: the `operator` role can only view and `manager` has full rights (unverified); `manager` is needed. Reduce the risk with TACACS+ command authorisation and an `ip authorized-managers` list that contains only the box's IP (command name unverified).
- ACL that blocks an IP (speculative syntax):

```
configure
ip access-list extended VEDETTE-BLOCK
    {seq} deny ip {ip} 0.0.0.0 any
exit
```

  The GUI currently writes `deny any {ip} 0.0.0.0` (the source/destination order is doubtful). It must be tried on a real device. Attaching the ACL: `vlan <n>` / `ip access-group VEDETTE-BLOCK in` or per port (unverified). Rollback: `no {seq}` (unverified).
- Turn a port off/on: `interface {n}` / `disable`; rollback `enable` (unverified). Port names have the form `5`, `A1` (unverified).
- Move to a VLAN: attach **untagged** to the quarantine VLAN: `vlan {vlan}` / `untagged {n}`; rollback `vlan <old VLAN>` / `untagged {n}` (unverified; this command removes the port from the old untagged VLAN by itself, so the old VLAN must be read in `precheck` with `show vlans ports {n} detail`, unverified).
- Save: `write memory` (unverified); the principle of 5.5.
- Risk as for Cisco. For ArubaOS-Switch: not in the built-in templates, only a custom template with a warning "not tested" until a lab confirms it.

---

## 7. Pi-hole v6

**Versions**: Pi-hole v6 (the REST API integrated in FTL). Version v5 does not have this API.

**Sources**:
- API overview: https://docs.pi-hole.net/api/
- Authentication: https://docs.pi-hole.net/api/auth/
- The machine-readable specification of `domains`: https://github.com/pi-hole/FTL/blob/master/src/api/docs/content/specs/domains.yaml (a YAML file; its content was read)
- Interactive documentation running on the device itself: `http://pi.hole/api/docs` [verified]

### 7.1 Connection and permissions

- Login: `POST /api/auth` body `{"password":"<app password>"}` (add `"totp":123456` if 2FA is on). It returns `session.sid`, `session.csrf`, `session.validity` seconds [verified]. Send the sid in the header `X-FTL-SID: <sid>` (it can also go through the query, JSON, a cookie) [verified]; use the header, not the query (to keep it out of logs).
- App password: generated on the web settings page; the documentation page says there is only **one** app password [verified]. The number of concurrent sessions is limited (the figure is not stated) [verified]: the box **always** does `DELETE /api/auth` (204) when done [verified] and reuses one session for a whole batch, not logging in on every request. Exceeding the login limit returns 429 [verified]: do not retry continuously.
- Minimum permissions: the documentation read has **no** concept of a write-only-for-domains app password or permission per endpoint; an app password is treated as Pi-hole administrator permission (`app_sudo` unverified). Risk reduction: run Pi-hole on a separate machine for DNS, let the web/API interface listen only from the box's IP (firewall), and do not use the same password elsewhere.
- HTTPS: Pi-hole v6 can serve HTTPS; use it, pinning the certificate the administrator imports.

### 7.2 `pihole_block` / `pihole_unblock`: block/unblock a domain

- Description: "Add a domain to Pi-hole's deny list; devices on the network can no longer resolve that name".
- Parameters: `domain` (normalised and checked in 1.2). Only `exact`; **no** `regex` in the first version (regex-escaping a value controlled by the agent is a separate risk).
- Run [verified from the FTL specification]: `POST /api/domains/deny/exact` body `{"domain":"{domain}","comment":"vedette:<request_id>","groups":[0],"enabled":true}`. Success: 201 with a `Location` header; errors 400/401. `groups: [0]` (the default group) is an inference, and the group value is unverified.
- `precheck`/`verify`: `GET /api/domains/deny/exact/{domain}` (the path `{domain}` must go through `url.PathEscape`) returns 200 with a `domains` array (each element has `domain`, `type`, `kind`, `comment`, `enabled`, `id`) [verified]. If it is not there the response is an error that is not 200 (the exact code is unverified, treat 404/400 as "not there yet").
- Rollback: `DELETE /api/domains/deny/exact/{domain}` → 204 when done, 404 when absent, 400 when missing/inexact [verified]. Remove only when the `comment` of the entry read starts with `vedette:` (an administrator's entries are not touched).
- There is also a batch delete `POST` (the body is an array of `{item, type, kind}`) but the path does not appear in the specification [partly verified]; the first version deletes entry by entry.
- Risk: `low`. Pitfalls:
  - **A duplicate add returns 400** `database_error` "The item is already present." [verified]: the box tells "already exists" from "a real error" with `precheck`, and does not ignore every 400.
  - Blocking `exact` blocks only that exact name, not subdomains (a regex is needed to block the whole tree; not supported yet).
  - The DNS cache on clients and on earlier resolvers can keep the old answer until the TTL ends; the result explains clearly "applies to new queries".
  - Whether an allow-list (`allow`) domain wins or loses against `deny` follows Pi-hole's rules (unverified); `precheck` warns if the name is in `allow`.
  - Whether the "gravity" needs updating for a list domain to take effect: unverified (it probably is not needed for a custom domain). `verify` really checks with a trial DNS query (`dig @<pihole> {domain}`) only when the box has permission to send DNS to Pi-hole; not mandatory.
  - No native TTL: Vedette rolls back by itself.
- Version: Pi-hole v6.0 and above.

---

## 8. AdGuard Home

**Versions**: the OpenAPI specification read states version 0.107 [verified]. The path root is `/control` [verified].

**Sources**: the official OpenAPI specification: https://github.com/AdguardTeam/AdGuardHome/blob/master/openapi/openapi.yaml (read through `raw.githubusercontent.com`); descriptions: https://github.com/AdguardTeam/AdGuardHome/wiki/Configuration and https://adguard-dns.io/kb/adguard-home/ (not read).

### 8.1 Connection and permissions

- Authentication is HTTP Basic for every endpoint by default [verified]; there are `POST /login` (`name`, `password`) and `GET /logout` [verified]. Use Basic with a dedicated user; AdGuard Home has **no role-based permissions**: an authenticated user is a full administrator (unverified, not seen in the specification). Risk reduction: run AdGuard Home separately, let the API listen only from the box's IP (firewall), and use HTTPS.

### 8.2 `adguard_block` / `adguard_unblock`: block/unblock a domain

- Description: "Add a domain-block rule to the user's rule set in AdGuard Home".
- Parameters: `domain` (1.2). The generated rule: `||{domain}^` [verified: an example of the syntax in the specification; it blocks both the domain and its subdomains per AdGuard syntax, the full syntax table was not read]. The box **generates** the rule string from the checked `domain` and does not accept a rule string from the agent. Add a comment line `# vedette:<request_id>` before the rule for rollback (the specification has an example `# comment` [verified]).
- Protocol: there is **no "add one rule" endpoint** in the part read. There is only `POST /control/filtering/set_rules` body `{"rules":[ ... ]}` ("Set user-defined filter rules"), and the specification does not say clearly whether it replaces everything [partly verified]. Treat it as **replacing everything**.
  1. `GET /control/filtering/status` → the `user_rules` array [verified].
  2. The box computes the new list = old + (comment + rule), skipping it if the rule already exists.
  3. `POST /control/filtering/set_rules` body `{"rules":<the new list>}`.
  4. Store the old list verbatim in the audit (the whole thing can be restored if it breaks).
- Rollback: read `user_rules` again, remove exactly the pair (comment, rule) carrying the `request_id`, and write the whole list back.
- Re-check: `GET /control/filtering/check_host?name={domain}` (`name` is mandatory) returns `reason` and `rules` [verified field names; the `reason` values are unverified]; expecting the `rules` array to contain Vedette's rule or `reason` to indicate it is filtered. A substitute check: read `user_rules` again and see that it contains the rule.
- Risk: `low`. Pitfalls:
  - **A full read-modify-write**, so it can overwrite a concurrent change by an administrator or another box: lock per connection (one writer at a time), read again right before writing, and refuse to write if the old lines changed between the read and the write (compare a hash).
  - A mistake can lose all user rules: a copy must be saved before writing, and there is a "restore user rules" button in the audit.
  - The `domain` parameter must pass a strict check: the characters `||`, `^`, `$`, `*`, `/`, `@@` have meaning in the rule syntax and must not get in (the regex check in 1.2 already excludes them).
  - No native TTL: Vedette rolls back by itself.
- An alternative pull method: `POST /control/filtering/add_url` body `{"name":"Vedette","url":"https://<box-ip>/blocklist/<token>/domains.txt","whitelist":false}` so AdGuard pulls the box's list by itself [verified endpoint and fields; `url` may be a URL or a file path]. The pull cycle is AdGuard's general setting (`interval` in `filtering/status`, in hours). The file format follows `blocklist-format.md`. This path is the preferred one (the device pulls by itself); it is a one-time setup.
- Version: AdGuard Home 0.107 and above (the specification read).

---

## 9. General actions (custom HTTP and SSH templates)

A custom action added by a customer is also subject to the same rules as a built-in action. The server checks when the template is **saved** and again when it **runs**; a violation = refusing to save, with no "warn and let it through".

> **Implementation status (the `core/conn/write` writer; done).** The server checks at save time (`ValidateTpl`, `cliProblem`) and again at run time (`readOnlyProblem` for the pre-check and the re-read; the writer for every step). Different from the sentences below: (1) one call at a time per connection (and one device step at a time on the whole box, `execMu`); there is no separate limit of 30 requests/minute, the budget is `max_per_hour` and the circuit breaker. (2) After an SSH line is refused by the device at a position after the first line of a write step (run, rollback), the writer types **exactly one** line that leaves configuration mode on the same session and then closes the session (the rule "stop the chain and close the session" stays, and no further line of the template is sent). The leaving line follows the nearest earlier line that entered configuration mode and has not been closed by an `end` line after it (when no block is open, nothing is typed), and is the data `core/conn/write/leave.json`: `configure terminal`/`conf t` → `end` (Cisco IOS/IOS-XE, Aruba AOS-CX: lines in global configuration and sub-modes usually take effect when typed, `end` only returns to the exec prompt); `spanning-tree mst configuration` → `abort` (IOS/NX-OS: MST region changes wait until the sub-mode is left, `exit`/`end` **apply** them); `config …` → `abort` (FortiOS: `next`/`end` **save** the entry being typed, `abort` discards; this replaces the words "`exit` on FortiOS" in 9.3). The leaving line has its own 5-second limit (`LeaveBudget`, outside the 60 seconds of the session, within the 90 seconds of the step), and its error or silence is ignored. Nothing is sent when the error is at the first line, when there was no earlier configuration-entering line matching a rule (including a bare `configure` of ArubaOS-Switch/Junos: Vedette has no Junos pack, and Junos needs `rollback 0` rather than `end`), when the line timed out or the session is already closed, when the step was stopped (an emergency stop), and in a read-only step. FortiOS errors (`command parse error`, `value parse error`, `Command fail. Return code -N`) are now also refused lines; previously the writer did not see them, typed `next`/`end` and reported OK. The result is unchanged: an error after an earlier line was accepted is "State unknown" (read the device again, do not resend). Not yet tried on a real device (lab). (3) The writer sets `Accept: application/json` itself and, when there is a body, `Content-Type: application/json` if the template does not set it. (4) The pre-check, run, re-read and rollback each open a separate SSH session or HTTP call per step; MCP does `initialize` for every step. (5) The writer refuses a command line containing control or shell characters (`;|&$` and the characters in INV-14b), a line longer than 512 characters, and more than 64 lines per step; the limit on the number of lines at save time is kept as before. (6) The pre-check step runs **even when** the action does not overwrite an old value, if the template has `precheck`; its output is passed through `normalizeOutput` and then compared with `precheck_refuse`/`precheck_expect` (empty → refuse); the re-read is sent only when the template has `expect`. (7) A connection that has not passed its most recent Test (`NotReady`) cannot run an action and cannot run a pre-check; rollback and re-read need only an existing pinned key. (8) A template with `expect` has that text read right before `run` (the output of `precheck` when it is the same step as `verify`, otherwise one more `verify` step); only presence/absence is kept. An unclear run whose re-read finds the text counts as applied only when the text was not there before.

### 9.1 General rules

1. A template contains only the typed parameters of table 1.2; there is no `{text}` in a command/API (it may be used only in a send-message action).
2. There must be a `rollback`, unless the author writes "cannot be undone"; in that case the minimum risk is `high`, 2 approvers are mandatory, and there is no `ai_may_propose` and no "pre-approval".
3. There must be a read-only `verify`; without `verify` the action carries the label "not re-checked" and its risk is raised one step.
4. A `ttl` is mandatory for every block action, except the administrator's `permanent` flag.
5. A `precheck` that reads the old state is mandatory for every action that overwrites an existing value.
6. The ownership mark (1.3) is mandatory in every object created.
7. The template's author must do a dry run with a sample event before turning it on; a custom template is off by default and is never `ai_may_propose` until an administrator turns it on.
8. Never leave a secret (token, password, key) in a template; only reference `core/secrets` through the connection. Do not write a secret into a log or the audit (security.md).

### 9.2 Custom HTTP

> **Update 2026-11-09, replacing the following points of this section**: HTTPS only, with no plain-HTTP "lab connection" (left for later); a certificate that does not pass the system root store is pinned by the SHA-256 of the leaf certificate at the first Test; **no redirect is followed** (even to the same host); **no retry**, even for `GET`; forbidden headers: `Authorization`, `Cookie`, `Host`, `Proxy-*`, hop-by-hop, `Forwarded`, `X-Forwarded-*`. The figures 64 KB / 1 MB, 5 s / 15 s stay.

- HTTPS only, certificate verification on, with CA/fingerprint pinning allowed. Plain HTTP only on a "lab connection" marked by an administrator, with a warning shown.
- Scheme, host and port are taken **from the connection**, not from the template or a parameter. A template has only the path part (with parameters in their own segment, `url.PathEscape`), the query (`url.Values`), and the JSON body.
- Methods: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`. `CONNECT`, `TRACE` and unknown methods are not allowed.
- Headers: an allowlist (`Content-Type`, `Accept`, authentication headers set by the connection); **added after a review (2026-11-10)**: besides `Authorization`, `Cookie`, `Host`, `Proxy-*`, hop-by-hop, `Forwarded`, `X-Forwarded*`, the following are also forbidden: `Via`, `X-Real-IP`, `X-Original-URL`, `X-Rewrite-URL` and the method-override headers (`X-HTTP-Method-Override`, `X-HTTP-Method`, `X-Method-Override`), because they change the meaning of the call or impersonate the caller; `\r`, `\n` are rejected in values; no parameter in a header name.
- Body: valid JSON is mandatory; values are replaced on the JSON tree, never by string concatenation. Body and response sizes are limited (proposed 64 KB / 1 MB).
- Redirects (30x) are not followed except to the same host; timeout 15 seconds (connection 5 seconds); at most 1 retry for `GET`, and no automatic retry of `POST`/`PUT`/`DELETE` (the result is ambiguous so it should be re-read with `verify` instead of resent).
- A response is treated as untrusted data: the parser limits depth and size, and it is never put verbatim into an AI prompt or HTML.
- Success is determined by `verify`, not by a 2xx code.
- Rate limit per connection (default 30 requests/minute) and one concurrent request.

### 9.3 Custom SSH

> **Update 2026-11-09, replacing**: timeouts are **20 seconds per line, 60 seconds per session** (replacing 30 seconds and 2 minutes), and a whole item at most 90 seconds; device output is **not** written to the audit (only one cleaned line of ≤ 200 characters in the item's result), and "write the output to the log after filtering secrets" no longer applies; a changed host key is rejected before credentials are sent; only the **safe** algorithm list of `x/crypto/ssh` (`ssh.SupportedAlgorithms()`: no `ssh-rsa` SHA-1, no CBC/RC4, no DH group1 or SHA-1; narrower than the library's "default" list, which also accepts them in order to talk to old devices; the word "default" here has this meaning).

- Use Go's SSH library; do not call `ssh` through the box's shell (the `core/exec` allowlist, security.md). The host key is pinned, and a changed key stops the connection.
- Network devices use an interactive session with a PTY; each command line is sent **separately**, waiting for the prompt, with a timeout per line (30 seconds) and in total (2 minutes). A template is stored line by line; a parameter substituted into a line never increases the number of lines (checked after substitution).
- A template has a maximum number of lines (proposed 20) and a list of **forbidden** commands per vendor (see 5.1), plus a general block: `reload`, `reboot`, `erase`, `format`, `delete`, `factory`, `write erase`, `no username`, `username`, `enable secret`, `crypto key`, `copy` to a network destination.
- Every configuration session always ends with a command that leaves configuration mode (`end` on Cisco/Aruba; a FortiOS `config` block is closed with `end`), even on an error. On an error, the leaving command is the **non-saving** form: `end` on Cisco/Aruba, `abort` on FortiOS and in Cisco's MST sub-mode (`spanning-tree mst configuration`), because there `end`/`next`/`exit` **save** the part being typed.
- A device error (a line beginning `%`, `Error`, `Invalid`, `Unknown command`; FortiOS `command parse error`, `value parse error`, `Command fail`) = failure, stop the chain.
- Saving the configuration is a **separate** action (5.5) and is not merged into another action.
- Write the device output to the audit after filtering secrets (passwords, keys, SNMP communities).

### 9.4 Protection at the rule layer and the circuit breaker

A custom template shares the common safety shell: the never-touch list, duplicate merging, `max_per_hour`, the circuit breaker, the maintenance window, the emergency stop button, and the hash-chain log. A custom action must not turn off these protections.

---

## 10. Minimum permissions: a summary to print in the interface

| Pack | Account to create | Permissions | Must not be granted |
|---|---|---|---|
| FortiGate | a REST API administrator + a separate `accprofile` | `fwgrp custom`: `address`, `policy` read-write; `authgrp` if ban is used (field names unverified) | `super_admin`, `sysgrp`; no `0.0.0.0/0` in trusted hosts |
| MikroTik | a user + a separate group | `read`, `write`, `rest-api` (unverified) | `policy`, `ftp`, `sniff`, `sensitive`, `password`, `reboot` |
| OPNsense | a user + an API key | only the alias permission needed (name unverified) | full administration rights |
| pfSense | a separate user for the unofficial REST package | aliases only (unverified) | `admin`, root over SSH |
| Cisco | a local user with its own privilege level or AAA command authorisation | ACL configuration, interfaces, the needed `show` (mode names unverified) | level 15 |
| Aruba CX | the administrators group (a smaller permission is unverified for now) | ACL, interfaces | |
| ArubaOS-Switch | `manager` (unverified) | ACL, ports, VLAN | |
| Pi-hole v6 | an app password (one) | treated as administrator | sharing another password |
| AdGuard Home | a Basic user | treated as administrator | |

On every platform: limit the source of access to the Vedette box's IP (trusted host, `address=`, management ACL, firewall).

---

## 11. Versions and the tests required before a label changes

| Pack | Target | Required test on a real device |
|---|---|---|
| FortiGate | FortiOS 7.2 to 7.6 | the `accprofile` field names; the path `monitor/user/banned/add_users` and the `expiry` field; whether `status` exists on `firewall vip`; a non-empty address group; behaviour after a reboot (`banned-ip-persistency`) |
| MikroTik | RouterOS 7.9 and above | the policy name `rest-api`; the duplicate-entry error; filtering `?list=&address=`; `timeout` behaviour after a reboot |
| OPNsense | 24.x and above | `alias_util` adding several entries; entries lost after a reboot; the minimum permission name; adding several IPs at once |
| pfSense | CE 2.7.x / Plus (REST package v2) | the minimum URL Table cycle; the v2 endpoint; `apply` |
| Cisco | IOS 15.x, IOS-XE 16.x/17.x | `privilege` for each sub-mode; the maximum sequence number; `log`; automatic VLAN creation |
| Aruba CX | 10.04 to 10.16 | the CLI ACL syntax; the REST ACE body; the smallest permission |
| ArubaOS-Switch | still supported (2530/2930) | all commands |
| Pi-hole | v6.0 and above | `groups`; block/allow precedence; gravity |
| AdGuard Home | 0.107 and above | `set_rules` replacing or adding; the `reason` values |

---

## 12. Differences from the current GUI (the maintainer approves, not changed on its own)

> **Applied (2026-11-09)**: the 11 points below were applied to the template library (data) `web/src/features/response/templates/action-templates.sample.json` (with the test `templates.test.ts`). How it is expressed: each `{...}` is a typed parameter (`ip`, `cidr`, `domain`, `port`, `mac`, `vlan`, `interface`, `id`, `name`; `text` only for a send-message action) or a **value Vedette reads/computes itself at run time** (`{seq}`, `{previous_vlan}`, `{found_id}`, `{expiry_s}`, `{timeout}`, `{rules_before}`; the rule does not supply it, and the interface shows `<seq>`...). A template that the spec still marks "unverified" carries the sentence "Not verified on a device yet — test in a lab first" in its description. **Still missing against the spec** (the template model is currently one call per step): a chain of several REST calls (create an address object and then add it to the group on FortiGate; pfSense apply; AdGuard read-modify-write), `precheck` and the device's native `ttl` appear only in the description/runtime value. The backend needs `steps[]`.

The current catalogue in `web/src/features/response/data.ts`:

1. `nat_off` (FortiGate VIP): uses `{text}` for the VIP name; the spec uses `{name}`. `set status` on `firewall vip` is unverified; a lab is proposed before keeping this action; it replaces `fgt_policy_disable` (2.5).
2. `fgt_ban_ip`: the CLI command `diagnose user banned-ip add src4 {ip}` is unverified; the GUI does not yet have the native TTL parameter (`expiry`).
3. `block_ip` (FortiGate address group): the rollback does not yet remove the address object; a FortiOS group needs an anchor member (2.2).
4. `mt_addrlist_add`: the REST rollback is empty (CLI only); REST needs `GET` and then `DELETE /rest/ip/firewall/address-list/<id>`.
5. `pf_alias_add`: uses the old API v1 branch and an unofficial package; "unofficial" must be stated in the interface and v2 targeted.
6. `opn_alias_add`: the path is right, but it needs an alias of type **External** and the box reports "lost after a restart" (4.1).
7. `sw_acl_deny`: uses one template for Cisco and Aruba/HPE; the ACL syntaxes differ, so it must be split into `cisco_acl_deny`, `aoscx_acl_deny`, `arubasw_acl_deny`; the final `permit ip any any` line is missing; the sequence number for inserting at the top is missing (5.2); rollback should be by sequence number.
8. `sw_port_shut`, `sw_vlan_quarantine`: share one template for three vendors; the syntaxes differ (AOS-CX `vlan access`, ArubaOS-Switch `untagged`); `sw_vlan_quarantine.rollback` uses `no switchport access vlan` instead of restoring the old VLAN that was read (the GUI describes reading the old VLAN, but the template does not yet express it).
9. `pihole_block`: the description says "AdGuard Home: the user copies and changes the API command", but AdGuard is different in nature (a full read-modify-write of the rules, 8.2); it should be its own action.
10. Parameter types: `id` (policyid) and `name` are missing; `{text}` is mixed into device templates.
11. The actions `cisco_save_config` (5.5) and `fgt_ebl_setup`/`opn_urltable_setup`/`adguard_add_url` (one-time setup, pull) are missing in the form of instructions.

### 12.1 Data fixes (applied)

**Fixes after a review (2026-11-10):** ArubaOS-Switch **was removed from the built-in templates** (section 6.2 says not to include it until a lab confirms; the three `arubasw_*` actions can now only be done as custom actions); `cisco_port_shut` also reads `show interfaces {interface}` and refuses `administratively down`, `aoscx_port_shut` refuses `Admin state is down` (a `no shutdown` rollback would turn on a port that the administrator turned off); the two Cisco port actions require `Administrative Mode: static access` (`precheck_expect`) and refuse `Mode: trunk`, `Mode: dynamic`, `Mode: private-vlan trunk`, `Mode: tunnel`, `Switchport: Disabled`; `fgt_policy_disable` has a pre-check that reads the policy and refuses `"action":"deny"` (after JSON compaction) or `set action deny`. The AOS-CX refusal strings and FortiOS's `show full-configuration firewall policy {id}` have not been tried on a device; AOS-CX does not yet have `precheck_expect` (a lab is needed to confirm the line `VLAN Mode: access`).

**Status:** all six items below are in the data and have tests (Go: `TestContract_INV14c_LibraryDataFixes`, `TestBuiltinActionsNeedingADeviceReadAreNotAvailableYet`; GUI: `templates.test.ts` §12.1). Item 5 is implemented in `unavailable()` (computed from the template, with no flag in the data). The command lines, refusal strings and `expect` still carry the label not tried on a device; no code runs them yet.

Applies to both `modules/response/data/action-templates.json` and the mock copy `web/src/features/response/templates/action-templates.sample.json` (the library-drift test must be green). The "unverified" label stays as in the sections above.

1. **`tool` is only for MCP connections**. `fgt_addrgrp_add` (`block_address`), `fgt_vip_disable` (`disable_virtual_ip`), `fgt_policy_disable` (`disable_firewall_policy`) change to `tool: null`. The HTTP and SSH kinds use the fixed tool of the connection kind (`send_request`, `run_approved_command`, `apply_config`, `launch_job`); keeping an MCP tool name on an HTTP action makes the action count as unavailable on a real HTTP connection.
2. **A complete SSH line sequence.** The core does not know vendor commands, so turning off paging and entering/leaving configuration mode are in the data. Each step (`precheck`, `run`, `rollback`, `verify`) is a separate session:

| Platform | First line of every step | Wraps `run`/`rollback` | Label |
|---|---|---|---|
| Cisco IOS/IOS-XE | `terminal length 0` | `configure terminal` … `end` | standard IOS commands (5.1), not tried on a device |
| Aruba AOS-CX | `no page` | `configure terminal` … `end` | unverified |
| ArubaOS-Switch | `no page` | `configure` … `end` | unverified |

   Example `cisco_port_shut`: `run` = `terminal length 0` / `configure terminal` / `interface {interface}` / `shutdown` / `end`; `rollback` the same with `no shutdown`; `verify` = `terminal length 0` / `show interfaces {interface} status`. `cisco_save_config`: `run` = `terminal length 0` / `write memory`; `verify` = `terminal length 0` / `show startup-config` (without the first line the session stops at `--More--` until the 20 s timeout).
3. **Pre-check and refusal strings for port actions** (the table below is the original version; the current strings after the review are in the paragraph "Fixes after a review" above) (closes a review finding: do not touch a trunk/uplink port):

| Action | `precheck` | `precheck_refuse` | Label |
|---|---|---|---|
| `cisco_port_shut`, `cisco_port_vlan_quarantine` | `terminal length 0` / `show interfaces {interface} switchport` | `Administrative Mode: trunk`, `Operational Mode: trunk`, `Administrative Mode: dynamic` | the line form per 5.4 (`Administrative Mode: static access`); not tried on a device |
| `aoscx_port_shut`, `aoscx_vlan_quarantine` | `no page` / `show interface {interface}` | `VLAN Mode: trunk`, `VLAN Mode: native-untagged`, `VLAN Mode: native-tagged` | unverified |
| `arubasw_port_shut`, `arubasw_vlan_quarantine` | `no page` / `show vlans ports {interface} detail` | `Tagged` (case-sensitive, does not match `Untagged`) | unverified |

   An uplink in access mode is not caught by the strings above: it still has to be declared in the never-touch list (INV-10).
4. **`expect` in `verify`** (substring match, JSON compacted, and after a rollback the string must disappear):

| Action | `verify.expect` | Notes |
|---|---|---|
| `fgt_addrgrp_add` | `"vedette-{ip}"` | quotes so that `1.2.3.4` does not match `vedette-1.2.3.45`; right for both JSON and `show firewall addrgrp` |
| `fgt_ban_ip` | `{ip}` | also matches a longer IP with the same prefix (accepted: `verified` is information, not a gate) |
| `fgt_vip_disable`, `fgt_policy_disable` | `"status":"disable"` | the API path only (`verify.cli` is empty) |
| `opn_alias_add` | `"{ip}"` | |
| `pihole_block` | `"domain":"{domain}"` | |
| `cisco_port_shut` | `disabled` | the Status column of `show interfaces status` |
| `aoscx_port_shut` | `Admin state is down` | unverified |
| `cisco_acl_deny` | `deny ip host {ip} any` | not yet available (section 5) |
| `cisco_port_vlan_quarantine` | `Access Mode VLAN: {vlan} ` (trailing space) | not yet available (section 5) |
| `cisco_save_config`, `pf_alias_add`, ArubaOS-Switch | not set | `verified = null` ("not checked") |

5. **Run-time values that do not exist yet**: a template that still has `{seq}`, `{previous_vlan}`, `{found_id}`, `{rules_before}` or `{timeout}` is "not available" with a reason: `cisco_acl_deny`, `aoscx_acl_deny`, `arubasw_acl_deny`, `cisco_port_vlan_quarantine`, `aoscx_vlan_quarantine`, `arubasw_vlan_quarantine`, `mt_addrlist_add`, `adguard_block`. Only `{expiry_s}` = `ttl_min` × 60 is computed in the writer (`fgt_ban_ip`; an item with no TTL makes this action unavailable).
6. **Built-in templates not yet tried on a device are off by default** (a risk in the backend plan): `fgt_addrgrp_add`, `fgt_ban_ip`, `fgt_vip_disable` are `enabled: true` although `unverified: true`; change to `enabled: false` for a new install (the `enabled` of an installed box remains the user's).

## 13. Open questions

1. FortiGate: grant `sysgrp` for setting up an External Block List through REST, or always let the administrator paste the CLI? Proposal: always paste the CLI (2.6).
2. pfSense: accept the unofficial path (the REST package) as the default push path, or only pull and let the customer turn on the package themselves?
3. A FortiOS address group needs an anchor member `192.0.2.1/32`: accept this, or use another way (an isolated address object for each entry)?
4. The parameter type `id` (policyid): add it to the list `PARAM_TYPES` (a new story, the maintainer approves).
5. Cisco: allow the `cisco_save_config` action automatically after a long-lasting block (a large TTL), or always as a separate approval step?
6. Does the box `clear` the state of open connections (OPNsense states, FortiGate sessions) after blocking? Proposal: not in the first version.
7. Add a `regex` type for Pi-hole to block a whole subdomain tree (needs its own regex escaping rule, 7.2).

Every "unverified" item above needs a lab pass (FortiGate-VM, MikroTik CHR, an OPNsense VM, Cisco CML/Catalyst, AOS-CX OVA) before code is written (no scanning of a real network).
