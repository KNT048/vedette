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
| `POST /exposure/targets`, `DELETE /exposure/targets/{id}`, `PUT`/`DELETE /exposure/targets/{id}/terms`, `POST /exposure/targets/{id}/outside`, `POST /exposure/tree`, `PATCH`/`DELETE /exposure/tree/{id}`, `PUT`/`DELETE /exposure/tree/{id}/terms`, `PUT /exposure/tree/{id}/deep-settings`, `POST /exposure/box-ip/verify`, `PUT /exposure/box-ip/settings`, `DELETE /exposure/box-ip/ignored/{ip}`, `PUT /exposure/greenbone` | admin |

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
  (`Target.ownProof`, only for an IP the box found, `box_egress`; never for a typed IP, nor from a sighting stored ahead of the
  clock: `TestOwnIPProofOfASightingDatedInTheFutureIsNone`), sensor-active sends it with each nmap and
  nuclei job (`proven_at`), the web step with each ZAP page (`ScanTarget.ProvenAt`), and the scan container and vedette-host accept
  the address while it holds (`egressip.ProofHolds`, the same 90 days and 5 minutes of clock slack: `TestOwnProofWindowIsValidDays`),
  else they ask for a sighting of their own as before. **Overlap rule** (`egressnow.go`): the proof is sent only while the address's
  latest sighting is after the first sighting (`created_at`) of the box's current egress address (the box_egress IP(s) of the latest
  sighting overall), i.e. the two lines were in use at the same time; an address last seen before that was replaced (a dynamic
  address the provider took back): no proof, the executors scan it only if they see the box go out through it, and its node's
  `proof.replaced` says by which address and since when (the Ownership tab shows one line). Seen again later, it is not replaced. When
  the current egress cannot be told (no datable sighting, one stored ahead of the clock) no proof is sent (fail closed). An address that
  comes back after its proof expired, its target kept, counts from its first sighting ever. OpenVAS's own-IP check (`gbOwnNow`) is the same gate
  (`TestContract_INV25_OpenVASScansAProvenIPTheBoxDoesNotGoOutThroughNow`). The Shodan check needs it current (INV-21).
- **INV-32** A domain is proved by its own TXT token (`vedette-verify=<token>`) on the name, on `_vedette-verify.<name>`, on a
  parent name up to the registered domain, or by a verified ancestor target (`core/domainfence`). Proof is checked with
  `proof.go` only. The record is read through the box's resolver; when that answer (records or no such name, never a failed lookup)
  proves nothing, from the zone's own name servers (every NS of the registered domain, at most 8, asked without recursion; every
  server that answers with authority from the registered domain's own zone must serve it, never through a CNAME or a wildcard:
  `domainfence.Owned`, `TestOwnedAsksTheZonesOwnServers`). The executors' fence (scan container, vedette-host) applies
  the same rule and still needs the record now for every deep step to an address that is not the box's own.
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
  version. One acceptance (an administrator with two-step sign-in, a target verified and not expired, the version the page showed)
  covers the deep scan and the disruptive checks, which are a paragraph of the terms text; the full text is stored with each
  acceptance. Only a scan a person starts runs the disruptive checks; a scan the box runs by itself (the schedule) never does. The
  box's own IP it does not go out through now can be accepted while its proof holds; the box's own IP behind a gateway in
  100.64.0.0/10 cannot (409 `shared_address`, checked after verified and not expired), and a scan of it drops the disruptive checks
  while its gateway is in 100.64.0.0/10 or cannot be read (an acceptance stored before keeps the deep scan); a typed IP shows its own
  warning and can be accepted. A request from an older page that sends `disruptive: false` is 409 `notice_changed`. On a domain's
  run the disruptive checks go only to an address that is a proven public IP of this box (the box's own IP inside its proof, its
  name's CNAME inside the domain, its gateway not in 100.64.0.0/10); every other address (hosting, a CDN, a proxy, a typed IP, a name
  pointing outside) gets the deep scan without them and a line that says so (`deepGate`). The run's check step (`modeNote`) and the
  Deep scan dialog never claim them for a domain or a typed IP: a domain's says they run only on its addresses that are this box's
  own public IP (the dialog names the ones its last scans saw that the tree has as an IP the box found, never a typed-in IP of kind
  `box`, or says none is), a typed IP's says they are not included
  (`TestModeNote_ADomainsDeepScanSaysWhichAddressesGetTheDisruptiveChecks`). An acceptance of a version in
  `keptTermsVersions` (2026-11-18b) stays valid after the update with its own text and disruptive flag: with the flag the disruptive
  checks keep running, without it the deep scan only until the current terms are accepted. Every refused acceptance is logged at
  WARN with its code and the target id.

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
- **INV-22** A stored port is opened, kept, closed or retired only from the verdict this scan gave it (INV-45), never from one
  probe: "No longer seen" keeps first and last seen. `open` opens or keeps it. `closed` (missed while the address answered, no sign
  of the network) closes it at once when two probes of this run missed it (the runner's connect and a trusted sweep of every TCP
  port, `sweepTrusted`, on a port of the fixed list; or one of them and a reset to the re-check), else only when the newest scan
  before that gave the port a verdict found it closed too (a scan that did not probe the port gives it none: a failed or untrusted
  sweep checks only the fixed list, a default scan only the ports its service step probed, `Content.Probed`). `filtered` (no answer
  at all to the re-check while the address answered on other ports: a firewall or WAF dropping the box) closes it only as the third
  filtered scan in a row since it was last seen, at least 24 hours after the first. `unreached`, `lost` and `unknown` never close
  it: it stays as it was, and once it was last seen more than 30 days ago it is no longer listed ("not reached for 30 days": not
  counted as closed by the target, no alert, said in the save step and in a line of its address). Until then the services list
  gives it `not_reached_since`: the start of the first scan of the newest unbroken streak of those verdicts of the port (at most
  the bounded read of INV-45's verdict items), null when its newest verdict is any other or it has none (`TestServices_NotReachedSince`). `network` with a syn-ack (the network accepts the port for
  every address) retires it (no longer listed, its issues gone, not counted as closed) only when this scan read the target's own
  answer on that port and found it the network's (INV-44), and no scan ever saw it open over a path the network-path check found
  clean; otherwise it is kept (a port this scan did not probe, or whose comparison failed, says nothing about the target). A row
  with open issues needs a second scan that agrees: it is retired only when the newest verdict before this scan was `network` with a
  syn-ack too; until then it is kept and a line of its address says so. Every row a scan no longer lists without the target having
  closed it (the network's, not reached for 30 days) is named in a `network_path` line of its address, the first of the target's
  lines, so a wrong retire is never silent. `network` with a reset (the network refuses the port for
  every address) never closes or retires it: such a network cannot have made the row. Right before the results are written, the
  ports open before that this scan did not see, on the addresses it probed (an IP target, a domain's swept, own-box or by-name
  addresses; not an address that stopped answering, nor a name whose lookup got no answer) and among the ports it may probe there
  (on an address checked by name only, 80 and 443: never more than PRIVACY flow 9 allows without the deep scan of that address),
  get one more TCP connect (`recheckMissed`, `PortProber`: cmd/vedette's liveness check, at most 8 addresses and 32 ports
  each): what each got is a probe of the run. The scans before are read from the run items of kind `verdict` only; items of runs
  older than the model are ignored, which only delays a close. `TestSilentPorts_AWAFThatBlocksTheBoxClosesNothing`,
  `TestSilentPorts_ThreeSilentScansWithinADayCloseNothing`, `TestSilentPorts_AResetClosesAndAnAnswerKeeps`,
  `TestSilentPorts_AnAnswerInBetweenStartsTheSilentCountAgain`, `TestSilentPorts_AnAnsweredOrSilentScanIsNotTheMissBefore`,
  `TestSilentPorts_ASweepMissAndAResetOfTheRecheckCloseAtOnce`, `TestSilentPorts_ManySilentPortsKeepTheirLine`,
  `TestLiveness_ATargetThatStopsAnsweringIsSaidAndIsNotAMiss`, `TestCoverage_AFullPortScanThatDidNotSeeAPortClosesIt`,
  `TestCoverage_AnEmptySweepWithClosedRepliesCounts`, `TestCoverage_AnUntrustworthyFullPortScanNeverClosesAPort`,
  `TestCoverage_AListPortTheRunnerDidNotProbeNeedsTwoSweeps`, `TestCoverage_AScanThatReachedNothingIsNotAMiss`,
  `TestCoverage_AnEmptyScanOfAnAddressThatAnsweredIsAMiss`, `TestCoverage_EmptyScansWithNoReplyNeverCloseAndRetireAfterThirtyDays`,
  `TestCoverage_EmptyDeepScansWithNoReplyKeepAPortOutsideTheList`, `TestVerdicts_FilteredStreakAndCleanSighting`.
- **INV-44** A port answered by the box's own network is not the target's. Some networks answer a TCP connect on a few ports for any
  destination: a firewall's SIP or SCCP helper on 5060 or 2000 or a transparent or SYN proxy accepts it, an egress filter (an ISP
  blocking 25) refuses it. The vantage of each run is calibrated (`Config.Path`, `PathChecker`; cmd/vedette `exposurePath`: a plain
  TCP connect, closed at once, to 192.0.2.1, 198.51.100.1 and 203.0.113.1, the never-routed RFC 5737 ranges; what two of the three
  get is the network's answer: accepted, refused or nothing): at the start of the run for the fixed list and the ports open before,
  then for each port a scan step finds open, each port once a run. A port the network accepts for every address is the target's
  only when the target's own answer differs from what a never-routed address gets through the same network (`SameAsPath`: for a web
  or TLS port of the fixed list, the TLS certificate, else the status, Server header and title of GET /; for any other port, the
  banner a server that speaks first sends by itself, at most 512 bytes within 2 seconds, nothing sent, its digits folded; a target
  that sends nothing of its own, a client-speaks-first service such as SIP, cannot be told apart from a network that sends nothing
  either and stays the network's; when the network sends a banner of its own there, the target's silence is its own; on a web or
  TLS port, a read of the target that got no certificate and no HTTP answer, a slow page or a failed handshake, compares nothing and
  the check returns an error, however the never-routed addresses ended): a real
  web, SSH or SMTP service behind a transparent proxy is still found, and its row stored before the check is kept. Otherwise the port is left out of the results before any
  engine step (no service, admin page, certificate or script result, no template, ZAP or OpenVAS job) and its verdict is `network`.
  A reset the network gives for every address is not the target's either: the port's verdict is `network`, and the runner's and the
  sweep's resets no longer show the address answered. The run's log says which ports, once each, and the target's "Not checked"
  lines get one line per address of kind `network_path` ("Ports 2000 and 5060 are answered by your own network …, so they were left
  out of the results."; "Port 25 is refused by your own network for every address …"). No check wired: the ports stay as found, seen
  over a path that was not checked (`open_unchecked`). A check that fails: the ports stay as found, their verdict is `unknown`, the
  run is partly done and a `network_path` line says the box could not tell. A row stored open for a port the network accepts is retired
  only when this scan compared the target's answer there with the network's and found them the same, and no scan saw it open over a
  checked clean path (a row stored before the check existed, or the network's own port), and, when it holds open issues, the scan
  before found it the network's too; a row a
  clean scan saw is kept, so a proxy or a SIP helper added later never makes real services and their issues disappear. The save step
  and the run's log say "Ports 2000 and 5060 of <ip> are no longer listed: they are answered by your own network, not by <ip>.", and
  so does the first `network_path` line of that address.
  `TestNetworkPath_APortAnsweredForANeverRoutedAddressIsLeftOut`, `TestNetworkPath_EarlierRowsOfAPortTheNetworkAnswersAreRetired`,
  `TestNetworkPath_NoCheckKeepsTheOpenPorts`, `TestNetworkPath_ManyPortsKeepTheirLine`, `TestVerdicts_ATargetsOwnAnswerThroughAProxyIsOpen`;
  `TestObservationMatrix_EveryRetireIsNamed`; cmd/vedette `TestExposurePathConnectsOnlyToNeverRoutedAddresses`,
  `TestExposurePathComparesTheTargetsAnswerWithTheNetworks`, `TestExposurePathDoesNotCompareATargetsWebAnswerThatFailed`.
- **INV-45** One observation model for an external scan (`observe.go`): every probe source records what it got in the run's probe
  log (the runner, nmap's sweep, the liveness checks of INV-42, the re-check of INV-22, the calibration of INV-44), and one pure
  function, `verdicts`, gives each address and port of the run (a port open before, or open now) one verdict: `open`, `closed`,
  `filtered`, `unreached` (nothing of the address answered, or the box's own IP reached through NAT loopback flipped to resets on
  every port with nothing open: the router answers for itself), `lost` (answered earlier in the run, then stopped), `network` or
  `unknown` (the calibration failed, or a probe step failed or was cut), and each address a rollup (reachable, unreached, lost) with
  a reason: the loopback vantage (the box's own public IP, while it is the box's current egress address) or a block in front of the
  target. Every consumer reads the verdict only: the rows (INV-22), the engines (the open ports; a lost port gets no engine), the
  run's outcome (partly done when a port open before is `filtered`, or any port is `lost`, `unreached` or `unknown`, or a step
  failed or was cut, such as a deep sweep that missed ports the runner saw moments before; failed `unreachable` when the box is
  offline, INV-41) and the customer's words: one function (`vantageLines`) writes one line per address and fact from the reason,
  the NAT-loopback hint only for the loopback vantage, "allow this box's public IP <ip> during [deep] scans" otherwise, and the
  run's log and its reason use the same text. The verdicts are the run's items of kind `verdict` (subject `ip:port`, outcome the
  verdict, `open_unchecked` for an open port whose path was not checked). The 26 rows of `TestObservationMatrix` (and its guard,
  every done step has a note) are the cases: a new vantage case is a new row first. `TestVerdicts_OneVerdictPerAddressAndPort`,
  `TestVerdicts_ProbesThatMissedAClosedPort`, `TestVerdicts_TheLinesSayTheReason`.
- **INV-41** A scan to which nothing of the target answered while the box could not reach the public IP services either (INV-2,
  one round asked only then) is incomplete: it ends failed with 502 `unreachable` saying the box could not reach the target, and
  nothing is written, so the target keeps the rows of its last complete scan. When the services answer, "nothing open" is a result.
- **INV-42** A target can stop answering in the middle of a scan (the router in front of the box's own IP loses its NAT loopback, a
  firewall or ban list drops the box, a link goes down). Before each engine step (templates, ZAP passive, ZAP active, OpenVAS, nmap's
  disruptive scripts) and before the results are written, the scan checks that the ports seen open earlier in the run still accept
  a TCP connection (`Config.Liveness`: a connect, closed at once, nothing sent; at most 4 addresses and 16 ports each; every check
  is a line of the run's log). A port that no longer answers is lost for the rest of the run: the later engines skip it and the
  step that lost it ends partly done with "Results incomplete: <ip>:<port> stopped answering during the scan."; when it is the
  box's own public IP the note adds the likely cause (the box could not reach its own public address from inside the network: the
  router may not support NAT loopback, or something blocked it), never an IPS without evidence, and never for a typed IP among a
  domain's addresses (scannable, but not the box's). When no port of the target answers
  any more, the later engine steps are skipped with that note. nuclei's own sign counts too: a port where at least half of 20 or
  more templates got no answer (only connection errors, skipped after nuclei gave the address up, or lines about another address)
  makes the template step partly done (inside a domain's address step, that step). Such a run, and a run whose engine image
  is not on the box yet (INV-24, INV-25), ends partly done (`core/run` `Partial`, its first problem as the reason), never done.
  `TestLiveness_ATargetThatStopsAnsweringIsSaidAndIsNotAMiss`, `TestLiveness_APortThatStopsAnsweringMakesTheStepIncomplete`, `TestLiveness_NucleiErrorsOnAPortThatStoppedAnsweringMakeItIncomplete`,
  `TestLiveness_TheNATLoopbackHintIsOnlyForTheBoxsOwnIP`, `cmd/vedette` `TestExposureLivenessConnectsAndSendsNothing`. The
  disruptive step of a domain whose own-box address stopped answering says so ("Not run on <ip>. Results incomplete: …"), never
  "No open port was found" nor that no address is the box's own (`TestDisruptive_ADomainWhoseOwnAddressStoppedAnsweringSaysSo`).
  A scan to which no port of an address with open ports answered at all (its verdict `unreached`, INV-45) ends partly done the same
  way, with one "Not checked" line of kind `unanswered` per address: "No port of <ip> (<names>) answered this box. If the site has a
  WAF or firewall, allow this box's public IP <ip> during deep scans." (the box's own public IP gets the NAT-loopback hint instead).
  Its results are written and it is not a miss of any port (INV-22). It is said only of an address this run resolved and probed on a
  port stored open there, while the box reached the Internet: the rows of a name whose lookup got no answer this time are kept
  (INV-27) and say nothing, whatever flags its carried row has, and a light scan that probes a hosting address on 80 and 443 says
  nothing of its other ports (`TestUnanswered_PortsOfANameNotLookedUpSayNothing`). `TestUnanswered_NoPortOfTheBoxsOwnIPAnsweredEndsPartlyDone`,
  `TestUnanswered_NoPortOfADomainAnsweredNamesTheBoxsIP`, `TestUnanswered_ResetsAreAnAnswer`, `TestUnanswered_OnlyRowsOfTheNetworkSayNothing`.
- **INV-43** The deep scan runs its light checks before its heavy ones, so a ban or an overloaded firewall costs only the last
  steps (`scanPlan`, the one source of the order the run page shows): the runner, nmap's sweep of every TCP port with service
  identification and the reviewed safe scripts (`external_full`; the later steps need the ports and the services; with a scan
  container that runs it in two runs, `PortsFirstScanner`, the "Find open ports" step is the port scan of every TCP port alone and
  the service step runs -sV and the scripts only on the open ports it found, without the ports the target's settings skip and those
  the box's own network answers (INV-44); when none is left the service step is skipped ("Not needed: the port scan found no open
  TCP port of this address…") and no second run is sent; a port that opens between the two runs is seen by the next scan; a port the port scan found open that the service run then does not
  see open is neither open nor missed on that scan (no verdict but unknown, never closed on it; the service step is partly done and
  says so, `TestDeepScanNeverClosesAPortItsPortScanFoundOpen`); an
  older scan container (`ErrPortsFirstUnsupported`) gets the one run on every port as before; `TestDeepScanWithNoOpenPortSkipsTheServiceStep`,
  `TestDeepScanReadsOnlyTheTargetsOwnOpenPorts`, `TestDeepScanFallsBackToOneRunOnAnOlderWorker`), the templates,
  ZAP passive, ZAP active, the comparison and the save, OpenVAS, and last nmap's disruptive scripts (`nmap_disruptive`: the dos,
  brute and the login and crash checks, `external_disruptive`) on the open ports the scan found, only when the run allows the
  disruptive checks (a person's scan, the terms include them, the box's own IP not behind carrier-grade NAT, `runMode`), the gate
  or the domain's deep gate re-checked right before, then the liveness check; skipped with why otherwise. What they confirm is an
  issue of the surface engine in its own key space (`nse-disruptive:`), closed only by a later run of these scripts that finished on
  the address, never by the first nmap run. `TestScanPlan_TheDisruptiveScriptsRunLast`,
  `TestDisruptive_TheScriptsRunLastOnTheOpenPorts`, `TestDisruptive_SkippedWhenTheRunMayNotRunThem`, `cmd/vedette`
  `TestExposureDisruptiveScriptsRunOnTheOpenPorts`, sensor-active `TestScanDisruptiveRunsOnTheOpenPortsOnly`.
- **INV-46** Each target has deep-scan settings (`exp_deep_setting`, one row per target, removed with it; no row is the defaults):
  the groups `dos` (off by default), `logins`, `web_active`, `data_change` and `openvas`, a speed (`normal`, `gentle`), the ports to
  skip and the URL path prefixes to skip (two separate lists; one is never turned into the other). They only narrow: `narrow` is the
  last step of `runMode`, after the terms, the scheduled-scan rule and carrier-grade NAT, so every `ModeNow` re-read takes them, and
  it only clears bits (`ScanMode.DoS`, `Logins`, `Change`, `WebActive`, `OpenVAS`; `Disruptive` is `DoS || Logins || Change`). The
  adapters AND the re-read with the run's mode bit by bit (`ScanMode.And`), so a group turned off during a run is left out from its next step and a group turned on never reaches it; the ports and web
  paths to skip and the speed are read once at the check step and apply from the next scan. Nothing is stopped. A domain's address that is also an IP target of the box takes both targets' settings
  (`deepGate`, `withSettings`; the active web scan of its pages too). Each engine core feeds honours them: nuclei leaves out the
  templates of a group that is off (classified in core, `cmd/vedette` `templateGroup`: a check that can exhaust or crash a service is
  in the denial-of-service group whatever its tags) and every template that can send a request under a path to skip: it runs only
  when every request it can send is known and outside every prefix (`pack.Template.Requests` lists them: every `path:` entry and
  raw request line, inline payload and plain variable values put in), so a later request under a prefix, a path built while it runs
  (an extracted value, a helper function, a variable with no value in the pack, the cut end of a long line; only the target's host,
  port and domain parts and random strings or numbers keep a path judged, as they cannot hold "/" or "..") or an index without the
  list leaves it out. A path is held against a prefix as written and as each web server may resolve it (dot segments and repeated
  slashes resolved with the path not decoded, decoded once or fully, `\` and tabs kept or read, `;` parameters kept or dropped), in
  any letter case like the ZAP exclude, so `/res/../admin/x`, `/q/../admin%2f..` and `/Admin/x` are under `/admin`; a value put in
  right after an open percent escape (`%2{{SD}}`) makes the path unknown. The step says how many were left out per port
  and why (`cmd/vedette` `templatePathOf`, `pathsLine`). Redirects: nuclei runs with `-dr`, which overrides a
  template's `redirects: true` / `host-redirects: true` for its http client, so no redirect reaches a skipped path that way; the one
  exception in nuclei 3.11.1 is an `unsafe: true` raw request with `redirects: true` (its raw client follows them), which the pack
  builder lists as unknown, so such a template is left out too (none in pack 2026.11.5). A server can still answer a request outside
  the prefixes with a page that names a skipped path: nuclei does not follow it; nmap's full sweep runs the script groups the target's settings allow
  (`ScanTarget.Groups`; scheduled scans too) and its disruptive scripts those of the groups the run allows, narrowed again right
  before the job (`cmd/vedette` `ownGate.GroupsNow`; sensor-active INV-19a), and the ports to skip go to nmap as `--exclude-ports`
  or are left out of its port lists; ZAP's active pass is skipped with `web_active` off, its disruptive rules run with `dos` or
  `data_change` and the host leaves out the class that is off (`no_dos`, `no_change`), the web paths to skip are excluded by the
  host in both passes (host INV-31d; a web scanner that cannot leave them out, `PathExcluder`, gets no ZAP run), an issue of a rule
  the settings left out of a page is never closed by that page (`WebSkippedRules`), and gentle runs ZAP on one thread with 500 ms
  between requests; the surface runner never dials a port to skip and connects more slowly when gentle; nuclei's full jobs run at
  its gentle rate when gentle (the step's bound stretches by `GentleTemplateScale`, within its cap); OpenVAS is skipped with `openvas` off, and its scan config follows the mask of the disruptive
  groups (`levelFor`: the Brute force and Default Accounts families and their two checkboxes with `logins`, the Denial of Service
  family with `dos`, each family read back by itself; `safe_checks` off only when `dos` and `data_change` are both allowed, since it
  gates both: with one of them off the run says both are narrowed for OpenVAS); the gentle speed runs its task with `max_checks` 2 and
  `max_hosts` 1, and its port list leaves out the ports to skip. A skipped port is not observed (INV-45): it is dropped
  from what the runner and the sweep report, gets no engine, liveness check or re-check, and its stored row keeps its state and
  issues (`dropSkipped`, `observation`). The check step names the settings a run used and `exp_scan.summary` (`settings`) keeps
  them; every group or step the settings removed says "Turned off in this target's settings." A value the box cannot read narrows: a
  toggle counts as off, the speed as gentle, and an exclusion list it cannot parse makes the scan refuse at its check step
  (`settings_unreadable`), so nothing is sent without the person's exclusions. `PUT /exposure/tree/{id}/deep-settings` is an
  administrator's, needs two-step sign-in to turn `dos` on (the one change that adds risk), refuses ports outside 1-65535, more than
  64 ports, a path that does not start with "/" or holds anything but the characters of a URL path, and more than 20 paths, and is
  audited (`exposure.deep_settings`, before and after). `TestDeepSettings_*`, the `settings/` rows of `TestObservationMatrix`,
  `cmd/vedette` `TestExposureGroups_*`.
- **INV-47** A domain's deep scan reuses the address-level layer of a fresh deep scan of the same address (`reuse.go`), so a name
  that points at an address scanned a moment ago as its own target (203.0.113.5 as an IP target, then example.com on it) does not
  send the same port sweep, nmap -sV and scripts, OpenVAS and disruptive scripts again. Per address, after `deepGate` passed: the
  source is the newest finished run of the IP target whose value is the address, and it is reused only when it is a deep run that
  ended done (never a partly done, failed or stopped one), started within 24 hours (`ReuseWindow`) and not after now, the IP target's
  terms and deep-scan settings were last changed before it started, its port and service steps ran, its recorded settings allowed at
  least what the step allows now (`scopeCovers`: no group turned off that the step has on, the normal speed unless the step is
  gentle, every port and web path it skipped skipped by the step too), and its OpenVAS and disruptive steps ran when the step would
  run them now on an address with open ports. Every open port this run itself found at the address was seen by the source (else the
  address changed since). A reuse never reports what the domain's own terms and settings would not have found (`reuseNarrower`):
  when it would take a script finding and the source's full sweep ran the scripts of a group the step's settings turn off, or an
  OpenVAS or disruptive-script finding and the source's run could have had a disruptive group the step does not have (its OpenVAS
  config and disruptive scripts follow those groups; a run a person started with the disruptive terms), or a script finding when the
  step skips a port and the source skipped none (the full sweep leaves out the scripts that follow ports another service names once
  a port is skipped), the address is scanned; so is it when the step skips every open port the source saw and a finding would be
  taken (the step would send nothing there).
  A reuse never closes or reopens anything by itself (`reuseKeepsRows`): when the domain
  holds an open port there the source did not see, an open address-level issue (nmap's scripts, OpenVAS, the comparison with
  exploited CVEs) it did not report, or one gone or marked patched or mitigated that it did report, the address is scanned as
  before; the reused findings are written as the domain's (`issueIn.reused`: added and kept, never opened again), and the comparison
  closes nothing on reused services. Every doubt (a row that cannot be read, a run of an older release without its settings) scans.
  The web layer always runs for the domain: the templates again with the domain's step (a template job's host is the address
  itself, as in every deep step), ZAP by name, the certificates by name.
  OpenVAS is not split: its task scans the address with one config, with no host name, so its network and service checks cannot
  be taken apart from its web checks; the whole OpenVAS result of the address is reused, and ZAP and the templates are the
  domain's web checks. Nothing is sent to the address for the reused layer but the liveness checks before the web layer (INV-42).
  The address's step says "Reused from the deep scan of <ip> at <time>" with what was reused, the OpenVAS and disruptive steps say
  it for that address, and a run item (subject `run`, outcome `reused`) links the source run's page; the address counts as
  deep-scanned, with its last deep scan the source's start. Only an IP target's run is a source (another domain's run of the same address
  is not). `TestDomainReuse_*`.
- **INV-19** Service identification runs before results are stored.
- **INV-20** Exploited CVEs of a service are matched at scan time through findings' matcher (`Config.Matcher`).
- **INV-23** nuclei templates run only for exploited CVEs matched on a service identified in this run.
- **INV-24** ZAP runs passive (baseline, GET only) on services that answered HTTP on a target that passed this run's gate. Its
  image is fetched when the module is switched on and at the box's start with the module on (`PrepareEngines`, the host's
  `zap.prepare`), so the first scan does not find it missing; a scan whose ZAP image is still downloading (`Unavailable.Pending`)
  skips its web steps with "the ZAP image (about 1.2 GB) is still downloading to this box; it will run in the next scan." and ends
  partly done. `TestEngineImage_AStepWhoseImageIsDownloadingIsSkippedAndTheRunSaysSo`, `TestEngineImage_TheModuleOnFetchesTheImages`.
- **INV-24a** ZAP's **active** scan (`ActiveWebScanner`, host `zap.active`) runs after the passive baseline, only on the pages that
  baseline read in this run, and only in a scan a person started (Scan now, Run once now) of a target whose testing terms are
  accepted, read again right before each page (`ModeNow`). A scheduled scan keeps the passive baseline only and says so in one line
  ("Active web checks run when a person presses Scan now; scheduled scans read the pages without attacking them.") on the scan and
  as the note of its run step "Active web scan (ZAP)", skipped. The disruptive rules of the host's rule split (denial of service, data-changing checks, SQL injection's boolean
  and UNION payloads, the hosting provider's metadata service, remote file inclusion's third-party URLs) and form posting run only on the box's own proven public IP (an IP
  target that is not typed, the page on exactly that address) when the run's mode allows the disruptive checks (`runMode`: a
  person's scan, the terms include them, the gateway not in 100.64.0.0/10); a domain's page, on hosting or a CDN, gets the active
  scan without them, and the scan says so. The host checks two of those itself (host INV-31c): a person's press of Scan now or
  Run once now on such a target asks the host for its grant (`zap.authorize`, `DisruptiveGranter`, at the press, without waiting;
  a scan the box runs by itself never asks), each page that asks for the disruptive rules hands it back (`ScanTarget.Grant`; a page without a grant asks for none and says why), and
  the host also reads the box's gateway itself; when the host runs a page without them (`WebScan.DisruptiveRefused`), the page
  counts as a page of a pass without them (its alerts are not disruptive and close no issue of a disruptive rule) and the scan's
  line and the step's note say why in the host's words. ZAP's context includes the page's origin (anchored to scheme,
  host and port; ZAP adds its own unescaped "<url>.*", which a look-alike name matches); the boundary is the host's network fence
  (that address and port only, no DNS, the one name pinned). Bounds: 21 minutes a page (the host's own 20: spider 2 minutes, depth 5, 20
  children a node; active rules 12 minutes, 2 a rule, 2 threads, 100 ms between requests; a 2 GiB container), 60 minutes for the
  active pass of a scan (a page starts only while a whole page still fits; the rest are named as not attacked). Every page is in
  the probe log before ZAP attacks it. A page that reached the 12 minutes keeps what it found and says it was cut short. A
  stopped scan stops ZAP on the host (`zap.stop`: the container removed and proven gone before it answers). Active alerts are
  issues of the `zap` engine apart from the exploited CVEs, one per alert and site (an alert both passes report is one issue), with
  ZAP's risk, confidence and pass in `detail.zap`; an active alert goes "gone" only when the active scan finished on its page again
  (a page cut short does not close one), never because a scheduled scan read the page; an alert of a rule the host runs only
  with the disruptive rules (`ZapActiveResult.disruptive_rules`), found by a pass that ran them, carries `detail.zap.disruptive`
  and goes "gone" only after a later active scan that ran them again (a pass without them keeps it open). The active pass is one step of the run (`zap_active` in `scanPlan`, right after the passive
  ZAP step, in a deep scan's plan only): while it runs its note is the page it attacks; it ends with the pages attacked of those it
  takes, with or without the disruptive rules, the alerts and the pages cut short at their limit, or is skipped with why. Tests:
  `zapactive_test.go` (`TestZapActive_*`), `zapgrant_test.go`, `cmd/vedette/exposureweb_test.go` (`TestExposureWeb_Active*`,
  `TestExposureWeb_AStoppedScanStopsZAPOnTheHost`), `cmd/vedette/exposureweb_grant_test.go`.
- **INV-24b** One ZAP run per page for both scans: a page whose active scan the run takes anyway (`aheadCall`: the checks of
  INV-24a and `activeTarget`, made right before the run: a person's deep scan, the terms and the settings read now, the port not
  skipped, the whole run (`CombinedScanTimeout`, 25 minutes) fitting in the active pass's 60 minutes counted from the first such
  page, the passive and active web paths to skip the same) runs
  its passive and active scans in one ZAP run (`CombinedWebScanner`, host `zap.active` with `passive`): one probe-log row for both
  before it starts, one ZAP start and one spider. The passive step reads its passive report as it reads the baseline's; the active
  pass takes the active outcome (`Content.webAhead`) instead of running the page again, keeps only the alerts of the rules the host
  ran (`WebScan.Rules`; the rest of that report are the passive alerts of the same run), and ends its step as before. The passive
  results stand when the active part ends without its report (`ErrActiveTimedOut`, or another error: the active step's line says
  the page's active results are not known). A scheduled scan, a surface scan, a target whose active scan is off and a scanner
  without it run the baseline alone; a host that refuses the run before starting (`ErrNoCombined`, older than `passive`) makes
  the rest of the pass run the baseline then the active scan as before. A one-run page whose passive report gives no page or cannot
  be read is not taken by the active pass and says so (`notActiveNotRead`); nothing of it closes. The passive check line says
  which pages were read by the active scan's spider (which sends forms) instead of "no form sent". `TestWebCombined_*`,
  `TestExposureWeb_Combined*`.
- **INV-25** Greenbone (OpenVAS) is optional and off by default; it runs as its own unmodified project beside Vedette and is
  driven over GMP. Each address has a time cap (INV-25a). Its probe log row, written before the task starts, is completed once the
  scan ended: `matched` (results), `not_matched` (it scanned, no result), `not_run` (it never started scanning); a failure, a stop
  or results the domain fence discarded keep `no_response` (`TestGreenboneProbeRowSaysHowTheScanEnded`). An OpenVAS issue's
  description is Greenbone's own text of the result: the test's summary, the detection result on the host, insight, affected
  software and impact, plain text with its lines kept, at most 1,500 characters (`TestOpenVASDescriptionKeepsItsLines`); a result with none names the test
  (`TestContract_INV25_IssueDetailHasGreenbonesDescription`). Vedette's scan configs (one per level, defined as data in `gbLevel`) are
  copies of "Full and fast" whose family selection is the base config's own, growing flags and the NVTs it selects in part included;
  a level takes away only the disruptive families (`TestOpenVASTuning_FamiliesAreTheBaseConfigs`). Generic web fuzzing is off at every
  level: its checkbox is off and the three generic directory-traversal NVTs are out of the web family
  (`TestOpenVASTuning_WebFuzzingIsOffInEveryLevel`); the web scan (ZAP) is the web attack engine. The report is read with every
  level and QoD; QoD 70 and a severity above 0 stay the cut for every result except a short allowlist of configuration facts
  (`gmpFacts`: SSH password logins, DHE key exchange, BREACH, TRACE, certificate problems; TRACE only from the NVT that confirms the echo, never from the HTTP methods enumeration; read with a second get_reports request for those OIDs only, best effort: the main read keeps its QoD 70 filter and caps), each a Low issue with a plain
  title and a fix line, no CVE, one per port (`TestOpenVASFactsHaveTitleAndFix`, `TestOpenVASTuning_ConfigurationFactBecomesALowIssue`).
  Each Greenbone service has a memory limit (`deploy/greenbone`).
  OpenVAS enabled but still starting (its images pull when it is turned on) or loading its feed: the step is skipped with why and
  that it will run in the next scan, and the run ends partly done (INV-42). OpenVAS that had nothing to scan in a run (no open port
  on any address, or an address that answers on every port: state `not_run`) has its step skipped with its "Not checked" lines as
  the reason, never done with an empty note (`TestContract_INV28_Deep_OpenVASWithNoOpenPortIsSkippedWithWhy`). OpenVAS that was due
  and never got going (the task stayed queued for 90 minutes, OpenVAS ended it before it scanned, OpenVAS not available, no probe
  log) has its step failed with those lines, and the run ends partly done with them; on a domain, one address that never got going
  does so too, whatever the others did (`TestContract_INV25_OpenVASThatNeverStartedEndsTheRunPartlyDone`). A refusal (the gate, the
  terms, the own IP, the domain fence or its re-check) is an expected decision: a plain skip with the reason, the run not partly done
  for it (`TestContract_INV28_Deep_OpenVASOnTheDeepAddresses`, `TestContract_INV25_OpenVASNeverScansAReplacedAddress`).
- **INV-27** A proved domain's surface: names from the CT log, the domain itself, its MX and NS hosts under it, and a short common
  wordlist.
- **INV-28** Deep scanning of addresses of names under a domain happens only in a full scan with the domain's terms accepted.
- **INV-29**, **INV-30**, **INV-34** A running scan shows its step's progress; each engine step keeps its outcome and one sentence;
  a scan is named by its start and shows its end. Its run lists every step of its plan (`runsteps.go` `scanPlan`: the check, the
  surface step, nmap's port discovery and service step for an IP, a step per deep-scanned address of a domain, nuclei, ZAP passive,
  ZAP active (deep), the comparison and save, OpenVAS, nmap's disruptive scripts (deep, last: INV-43)) from the moment the plan is known, each one queued, running, ended or skipped with why; a step counts
  as one ("3 of 8 steps"), a running step's note is where it is (the engines' progress reports, at most every 3 s), each start and end
  is a log line, and the steps the run ends before are skipped as not reached. Every probe of the scan names its run
  (`RunIDOf` of the scan's context, set with `WithRunID`; `scan_probe.run_id`), the safe templates' rows too.
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
