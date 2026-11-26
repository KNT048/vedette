# Exposure contract

> Tier: optional · Stories: S-EXP-1, S-EXP-2 · Tables: `exp_*` ([`docs/DATA_MODEL.md`](../../docs/DATA_MODEL.md) 4.5)

Exposure shows what the Internet can reach of the customer: the box's own public IP, public IPs and domains the customer proves
they own, and what scans find there. Scanning someone else's address is the harm this module must never cause, so most invariants
are gates.

## Endpoints

| Route | Minimum role |
|---|---|
| `GET /exposure/targets`, `/exposure/targets/{id}`, `/exposure/targets/{id}/outside`, `/exposure/tree`, `/exposure/tree/{id}`, `/exposure/tree/{id}/hosts`, `…/addresses`, `…/services`, `…/issues`, `…/scans`, `/exposure/scan`, `/exposure/greenbone` | viewer |
| `GET /exposure/targets/{id}/snapshots`, `…/snapshots/{date}`, `…/diff` | viewer (answer 501: results are rows, INV-8) |
| `POST /exposure/targets/{id}/verify`, `…/scan`, `…/openvas`, `DELETE /exposure/targets/{id}/queue`, `POST /exposure/tree/{id}/verify`, `…/scan`, `POST /exposure/scan/stop`, `POST /exposure/issues/handle`, `…/reopen` | operator |
| `POST /exposure/targets`, `DELETE /exposure/targets/{id}`, `PUT`/`DELETE /exposure/targets/{id}/terms`, `POST /exposure/targets/{id}/outside`, `POST /exposure/tree`, `PATCH`/`DELETE /exposure/tree/{id}`, `PUT`/`DELETE /exposure/tree/{id}/terms`, `POST /exposure/box-ip/verify`, `PUT /exposure/box-ip/settings`, `DELETE /exposure/box-ip/ignored/{ip}`, `PUT /exposure/greenbone` | admin |

Shapes: `web/src/features/exposure/contract.ts`.

## Invariants

IDs are stable (code comments cite them); a retired ID is not reused.

**What may be scanned**
- **INV-1** A target is scanned only when all hold, checked right before every scan (Scan now and a scheduled scan when the run
  starts, the scan module, each deep step): ownership proved and the proof passed within the last 90 days (INV-4); the proof not
  withdrawn; the commitment of the current version recorded (INV-7). Right before the scan the proof is looked for again (a domain's
  TXT record, INV-32; a typed IP's file or name, INV-35; the box's own sighting of its IP, INV-13): found renews it, not found (a
  lookup that failed, or a record, file or egress that is gone) is recorded as the target's last check and shown as a warning, never a
  refusal while the proof is inside its 90 days. Removing the target whose record proved another one withdraws that proof at once
  (the other is unproved); a public suffix is never proved. A missing condition is a 409 or 400 with the reason, never a scan.
- **INV-2** A public IP the box finds itself is only the address it uses to reach the Internet, read from three fixed "my IP"
  services run by three different operators, with no proxy and no redirects.
- **INV-3** Only global unicast IPv4 is accepted; private, reserved, CGNAT and documentation ranges never enter the store.
- **INV-4** A proof holds 90 days from its last pass (`ValidDays`), renewed by every pass: a domain's record found, a typed IP's
  file or name found, the box seeing its IP. The box checks a domain's record and a typed IP's proof again by itself from 7 days
  before they run out (every 6 hours while not found; an expired domain too, since a record found is a new proof).
- **INV-13** Before scanning an IP the box found, it checks whether it still egresses through it (a probe within the last 5 minutes,
  else one full probe): a sighting renews it (INV-4). An IP it does not go out through now (a second Internet line, a router that
  balances two lines, a failover) stays scannable by every step until its 90 days run out, and the node says so (`not_current`).
  The executors' own-IP fences take it on the same proof: `OwnIPProof` gives the latest sighting the gate's yes rests on
  (`Target.ownProof`, only for an IP the box found, `box_egress`; never for a typed IP), sensor-active sends it with each nmap and
  nuclei job (`proven_at`), the web step with each ZAP page (`ScanTarget.ProvenAt`), and the scan container and vedette-host accept
  the address while it holds (`egressip.ProofHolds`, the same 90 days and 5 minutes of clock slack: `TestOwnProofWindowIsValidDays`),
  else they ask for a sighting of their own as before. OpenVAS's own-IP check (`gbOwnNow`) is the same gate
  (`TestContract_INV25_OpenVASScansAProvenIPTheBoxDoesNotGoOutThroughNow`). The Shodan check needs it current (INV-21).
- **INV-32** A domain is proved by its own TXT token (`vedette-verify=<token>`) on the name, on `_vedette-verify.<name>`, on a
  parent name up to the registered domain, or by a verified ancestor target (`core/domainfence`). Proof is checked with
  `proof.go` only. The executors' fence (scan container, vedette-host) still needs the record now for every deep step to an address
  that is not the box's own.
- **INV-35** A public IP the customer types is listed at once but never scanned before its proof is found: its token file
  `/.well-known/vedette-verify.txt` served on the IP, or forward-confirmed reverse DNS to a name under a domain the box proves. Then
  it holds 90 days from its last pass (INV-4); it is sent to Shodan, and its deep steps run, only with the proof found at that moment.
- **INV-6** A domain target is a bare domain name and never a public suffix.
- **INV-12** `CheckScannable` and `ScannableIP` are the only way the scan module asks whether an external target may be scanned.
- **INV-31** Scan speed and exclusions come from the shared safety block (`ScanSafety` port), the same one LAN scans use.
- **INV-39** Domain targets form a tree (a subdomain under its nearest domain target, never across a public suffix); every name
  under a domain is scanned by exactly one target. `settleTree` is the one writer of `parent_id` and `child_target_id`.

**Consent**
- **INV-7** The commitment is recorded by the first Scan now of an admin with two-step sign-in, with exactly the sentence shown and
  its version (`exp_consent`, kind `commitment`, plus an audit row in the same transaction). An older version counts as none.
- **INV-17** Without a commitment: an operator gets `commitment_required`; an admin without two-step is asked to set it up first;
  nothing is written either way.
- **INV-26** Deep testing of a target needs its testing terms accepted (`exp_consent`, kind `terms`), fully disclosed and pinned by
  version.

**Rate limits and outbound data**
- **INV-5** Verification by a person is rate limited (429): a domain check every 30 seconds per target; Detect now and IP checks,
  which ask public services, share 10 attempts per hour per box.
- **INV-9** What leaves the box: the box's own IP to Shodan InternetDB only on an admin's press (INV-21), a proved domain to the CT
  log (`crt.sh`), the scans themselves to proved targets, and the "my IP" checks (INV-2). Each flow is in `PRIVACY.md`.
- **INV-10** Banners, page titles and service answers are untrusted: size-limited, stored as text, parsed fail-closed.
- **INV-11** Public-IP detection runs on the shared schedule `exposure.public_ip` (every 5 to 1,440 minutes, default 60); only an
  admin changes it, and changing it never deletes the IP list.
- **INV-21** Shodan InternetDB is asked only when an admin presses, only for an IP target that is proved, current and still the
  box's egress address. Reading the last answer sends nothing.

**Scans and results**
- **INV-38** A scan is a `core/run` run (kind `exposure_scan`, lane `exposure`): queued in the database, one at a time, the queue
  survives a restart.
- **INV-18** Scan now returns 202 after the gate; the gate's errors stay synchronous.
- **INV-37** Results are rows (`exp_host`, `exp_address`, `exp_service`, `exp_issue`), never a document per scan. What changed is
  read from `first_seen`, `last_seen` and `state`.
- **INV-8** The old per-day snapshot and diff endpoints answer 501.
- **INV-22** A port the scan did not probe, or probed and missed once, is not marked closed.
- **INV-41** A scan to which nothing of the target answered while the box could not reach the public IP services either (INV-2,
  one round asked only then) is incomplete: it ends failed with 502 `unreachable` saying the box could not reach the target, and
  nothing is written, so the target keeps the rows of its last complete scan. When the services answer, "nothing open" is a result.
- **INV-19** Service identification runs before results are stored.
- **INV-20** Exploited CVEs of a service are matched at scan time through findings' matcher (`Config.Matcher`).
- **INV-23** nuclei templates run only for exploited CVEs matched on a service identified in this run.
- **INV-24** ZAP runs passive (baseline, GET only) on services that answered HTTP on a target that passed this run's gate.
- **INV-25** Greenbone (OpenVAS) is optional and off by default; it runs as its own unmodified project beside Vedette and is
  driven over GMP. Each address has a time cap (INV-25a).
- **INV-27** A proved domain's surface: names from the CT log, the domain itself, its MX and NS hosts under it, and a short common
  wordlist.
- **INV-28** Deep scanning of addresses of names under a domain happens only in a full scan with the domain's terms accepted.
- **INV-29**, **INV-30**, **INV-34** A running scan shows its step's progress; each engine step keeps its outcome and one sentence;
  a scan is named by its start and shows its end.
- **INV-33** Admin and VPN pages are named from one fingerprint table (`content/adminpages/adminpages.json`), shared with the scan
  module.
- **INV-36** Every target has a schedule `exposure.target:<id>` (default weekly, Monday 02:30 in the scan window; at most every 6
  hours; admin only), created and deleted in the same write as the target. What a scan finds new is announced once.

**Targets and issues**
- **INV-14** Removing an IP can put it on the ignore list (at most 200), in the same transaction.
- **INV-15** A target's open-ports preview holds at most 20 services.
- **INV-16** The gateway line says which device probably answers the open ports of the box's own public IP.
- **INV-40** Issues are handled in the findings vocabulary (`patched`, `mitigated`, `accepted` with a last day from tomorrow to
  365 days ahead, `not_relevant`, `false_positive`); an accepted issue reopens after its last day.

## Preconditions and postconditions

- **PRE-1 / POST-1** `StartScan`: operator and INV-1 (first scan of a target: INV-17); when the run ends, its rows are written and
  `exposure.scan.written` is published.
- **PRE-2 / POST-2** `Verify`: operator; a domain by TXT lookup, an IP by one full probe.
- **PRE-3 / POST-3** `CheckScannable` (scan module): whether a target may be scanned now and why not; the TXT recheck is audited
  when its result changes. **PRE-7 / POST-7** `ScannableIP`: true only for an IP target that passes the gate now.
- **PRE-4** Adding, removing targets and the box-IP settings: admin.
- **PRE-5 / POST-5** Detect now: admin, counts as one attempt; 400 `not_public` when every address is refused.
- **PRE-6 / POST-6** `Remove` deletes the target, its rows and its consent (and may ignore the IP); `Restore` removes an IP from the
  ignore list.

## Forbidden

- **FORBID-1** Scanning a target whose ownership is not proved, was withdrawn, or has not passed for 90 days.
- **FORBID-3** A consent tick box or text separate from the first Scan now.
- **FORBID-4** Relying on inventory's LAN scope confirmation for an external target.
- **FORBID-5** Sending internal data (devices, logs) to the CT log or the "my IP" services.
- **FORBID-6** Recording a commitment with a sentence the person did not see, or by anyone but an admin with two-step.
- **FORBID-7** Sending Shodan anything but one proved IP of the box, or sending without an admin's press.
- **FORBID-8** Running a nuclei template on anything but an identified port of a proved target with a matching exploited CVE, or
  sending a probe before its probe log row is written.
- **FORBID-9** Sending ZAP anything but GET requests to the web pages of a target that passed this run's gate.
- **FORBID-10** Letting Greenbone scan anything but a proved, committed address allowed by this run's fence, or starting a task
  before its probe log row is written.
- **FORBID-11** Sending a deep step to an address under a domain whose terms are not accepted, to a private address or to IPv6.

FORBID-2 (no typed-in IPs) is retired: typed-in IPs are allowed with proof (INV-35).

## Events

| Event | Subscribers |
|---|---|
| `exposure.scan.written` | response (new open port trigger) |
| `exposure.target.verified` | none today |

New findings of a scan are announced through `Config.Alert`, which `cmd/vedette` sends through notify.

## Dependencies

- **Depends on**: `core` (runs, schedules, audit, domain fence, progress), `inventory` (the gateway device). Wired ports
  (`cmd/vedette/exposure*.go`): the scan module's runner and probe log, findings' matcher, nuclei templates, ZAP, Greenbone through
  `vedette-host`, the outside view, notify for alerts.
- **Used by**: the scan module (`CheckScannable`, `ScannableIP`), response (`exposure.scan.written`), reports (the exposure
  section).

## When off

No routes, no detection and no scans; data is kept. The home page shows exposure as off.
