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
- **INV-22** A port the scan did not probe, or probed and missed once, is not marked closed (two scans in a row that probed it
  must miss it), with two exceptions that close at once ("No longer seen"; first and last seen stay). (1) A trusted sweep: a deep
  scan's nmap step that probed every TCP port of the address, saw every port the runner found open there this run and saw at least
  one open port or got closed replies (`sweepTrusted`) closes a port of the runner's fixed list that the runner's connect also
  missed this scan (two probes of this run missed it). A port outside the fixed list, or on an address the runner did not
  port-scan, keeps the two-miss rule (two trusted sweeps in a row). A sweep that is not trusted checks only the fixed list; a failed
  nmap step checks only the fixed list. (2) An address with nothing open: "nothing open" is a result when the address answered this
  scan (a TCP reset to the runner's connect or to nmap, `Content.Answered`), and the scan counts as usual. When it answered nothing
  at all (a lost NAT loopback, a firewall dropping the probes) the scan is not a miss (run item `checked_empty`), until the third
  such scan in a row at least 24 hours after the first, which closes the ports they all probed (`emptyStreak`).
  (3) Right before the results are written, the ports open before that this scan did not see, on the addresses it port-scanned
  (an IP target, a domain's swept or own-box addresses; not an address that stopped answering), get one more TCP connect
  (`recheckMissed`, `PortProber`: cmd/vedette's liveness check, at most 8 addresses and 32 ports each). A port that accepts it is
  not a miss (`Content.Answering`); a reset leaves the rules above as they are; no answer at all (a firewall or WAF that blocks the
  box drops its packets while other ports still answer, so the runner and a trusted sweep both miss the port) is not a miss
  (`Content.Silent`, run item `silent_port`) until the third such scan in a row at least 24 hours after the first (`silentStreak`),
  which closes it. A port that accepted the re-check (run item `answered_port` / `still_open`) starts that count again, and neither
  such a scan nor a silent one is the scan before that missed the port for the two-miss rule (`previousCheck`). The run's log and a
  "Not checked" line of kind `silent_ports` say so (it also says a port the owner closed is marked closed after three scans over a
  day; past 6 ports it counts the rest, so it stays within a line's 300 characters). No prober, a failed check or a port past the bounds: the rules above.
  `TestSilentPorts_AWAFThatBlocksTheBoxClosesNothing`, `TestSilentPorts_ThreeSilentScansWithinADayCloseNothing`,
  `TestSilentPorts_AResetClosesAndAnAnswerKeeps`, `TestSilentPorts_AnAnswerInBetweenStartsTheSilentCountAgain`,
  `TestSilentPorts_AnAnsweredOrSilentScanIsNotTheMissBefore`, `TestSilentPorts_ManySilentPortsKeepTheirLine`. (3) An address
  that stopped answering during the scan (INV-42: a port seen open earlier in the run no longer accepted a TCP connection before
  the results were written) is not a miss of any port: its run item is `stopped_answering`, which checks no port and does not count
  in `emptyStreak` (a router that lost its NAT loopback may answer with resets on its unforwarded ports, which (1) and (2) would
  take as an answer). `TestLiveness_ATargetThatStopsAnsweringIsSaidAndIsNotAMiss`,
  `TestCoverage_AFullPortScanThatDidNotSeeAPortClosesIt`, `TestCoverage_AnEmptySweepWithClosedRepliesCounts`,
  `TestCoverage_AnUntrustworthyFullPortScanNeverClosesAPort`, `TestCoverage_AListPortTheRunnerDidNotProbeNeedsTwoSweeps`,
  `TestCoverage_AScanThatReachedNothingIsNotAMiss`, `TestCoverage_AnEmptyScanOfAnAddressThatAnsweredIsAMiss`,
  `TestCoverage_EmptyScansWithNoReplyCloseOnlyAfterThreeOverADay`.
- **INV-44** A port answered by the box's own network is not the target's. Some networks answer a TCP connect on a few ports for any
  destination (a firewall's SIP or SCCP helper on 5060 or 2000, a transparent or SYN proxy), so every target would show them open.
  Each port a scan step finds open (the runner's connect, nmap's discovery and service scan of an IP or of a domain's address) is
  checked once a run (`Config.Path`, `PathChecker`; cmd/vedette: a plain TCP connect, closed at once, to 192.0.2.1, 198.51.100.1 and
  203.0.113.1, the never-routed RFC 5737 ranges; two of the three answering means the network answers). Such a port is left out of
  the results before any engine step: no service, admin page, certificate or script result, no template, ZAP or OpenVAS job; it is
  neither seen nor missed for INV-22 (`closeVanished` skips it, its run item `path_port` / `answered_by_network` makes
  `previousCheck` skip the run for it). The run's log says which ports, once each, and the target's "Not checked" lines get one line
  of kind `network_path` ("Ports 2000 and 5060 are answered by your own network …, so they were left out of the results."). No
  check wired, or a check that fails: the ports stay as found. A row an earlier scan stored open for such a port (before the check
  existed, or when it failed) is retired by the scan whose check flagged that port on that address: state `closed` ("No longer
  seen"), its issues gone as for any closed service, not counted in the run's closed services; the save step and the run's log say
  "Ports 2000 and 5060 of <ip> are no longer listed: they are answered by your own network, not by <ip>." A port the network
  answered on another address only, or a check that failed or did not run, retires nothing; the same port seen open later from a
  clean network is a new open service. `TestNetworkPath_APortAnsweredForANeverRoutedAddressIsLeftOut`,
  `TestNetworkPath_EarlierRowsOfAPortTheNetworkAnswersAreRetired`, `TestNetworkPath_NoCheckKeepsTheOpenPorts`,
  `TestNetworkPath_ManyPortsKeepTheirLine` (past 6 ports and 3 addresses the line counts the rest); cmd/vedette
  `TestExposurePathConnectsOnlyToNeverRoutedAddresses`.
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
  makes the template step partly done. Such a run, and a run whose engine image
  is not on the box yet (INV-24, INV-25), ends partly done (`core/run` `Partial`, its first problem as the reason), never done.
  `TestLiveness_ATargetThatStopsAnsweringIsSaidAndIsNotAMiss`, `TestLiveness_APortThatStopsAnsweringMakesTheStepIncomplete`, `TestLiveness_NucleiErrorsOnAPortThatStoppedAnsweringMakeItIncomplete`,
  `TestLiveness_TheNATLoopbackHintIsOnlyForTheBoxsOwnIP`, `cmd/vedette` `TestExposureLivenessConnectsAndSendsNothing`. The
  disruptive step of a domain whose own-box address stopped answering says so ("Not run on <ip>. Results incomplete: …"), never
  "No open port was found" nor that no address is the box's own (`TestDisruptive_ADomainWhoseOwnAddressStoppedAnsweringSaysSo`).
  A scan to which no port of a target with open ports answered at all (nothing open, no reset from any address, no port of the
  re-check of INV-22 (3) answering, no address that stopped answering during the scan) ends partly done the same way, with one
  "Not checked" line of kind `unanswered`: "No port of <target> answered this box. If the site has a WAF or firewall, allow this
  box's public IP <ip> during deep scans." (the box's own public IP gets the NAT-loopback hint instead). Its results are written and
  it is not a miss of any port (INV-22 (2), (3) keep holding, so three silent scans over a day may still close them). Only the open
  ports on addresses the scan asked count (an IP target's own, a domain's addresses port-scanned or checked by name): the rows of a
  name whose lookup got no answer this time are kept (INV-27) and say nothing (`TestUnanswered_PortsOfANameNotLookedUpSayNothing`).
  `TestUnanswered_NoPortOfTheBoxsOwnIPAnsweredEndsPartlyDone`, `TestUnanswered_NoPortOfADomainAnsweredNamesTheBoxsIP`,
  `TestUnanswered_ResetsAreAnAnswer`, `TestUnanswered_OnlyRowsOfTheNetworkSayNothing` (rows of ports the network answers, retired by
  the same scan, are not open ports of the target).
- **INV-43** The deep scan runs its light checks before its heavy ones, so a ban or an overloaded firewall costs only the last
  steps (`scanPlan`, the one source of the order the run page shows): the runner, nmap's sweep of every TCP port with service
  identification and the reviewed safe scripts (`external_full`; the later steps need the ports and the services), the templates,
  ZAP passive, ZAP active, the comparison and the save, OpenVAS, and last nmap's disruptive scripts (`nmap_disruptive`: the dos,
  brute and the login and crash checks, `external_disruptive`) on the open ports the scan found, only when the run allows the
  disruptive checks (a person's scan, the terms include them, the box's own IP not behind carrier-grade NAT, `runMode`), the gate
  or the domain's deep gate re-checked right before, then the liveness check; skipped with why otherwise. What they confirm is an
  issue of the surface engine in its own key space (`nse-disruptive:`), closed only by a later run of these scripts that finished on
  the address, never by the first nmap run. `TestScanPlan_TheDisruptiveScriptsRunLast`,
  `TestDisruptive_TheScriptsRunLastOnTheOpenPorts`, `TestDisruptive_SkippedWhenTheRunMayNotRunThem`, `cmd/vedette`
  `TestExposureDisruptiveScriptsRunOnTheOpenPorts`, sensor-active `TestScanDisruptiveRunsOnTheOpenPortsOnly`.
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
  scan without them, and the scan says so. ZAP's context includes the page's origin (anchored to scheme,
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
  `zapactive_test.go` (`TestZapActive_*`), `cmd/vedette/exposureweb_test.go` (`TestExposureWeb_Active*`,
  `TestExposureWeb_AStoppedScanStopsZAPOnTheHost`).
- **INV-25** Greenbone (OpenVAS) is optional and off by default; it runs as its own unmodified project beside Vedette and is
  driven over GMP. Each address has a time cap (INV-25a). Its probe log row, written before the task starts, is completed once the
  scan ended: `matched` (results), `not_matched` (it scanned, no result), `not_run` (it never started scanning); a failure, a stop
  or results the domain fence discarded keep `no_response` (`TestGreenboneProbeRowSaysHowTheScanEnded`). An OpenVAS issue's
  description is Greenbone's own text of the result: the test's summary, the detection result on the host, insight, affected
  software and impact, plain text with its lines kept, at most 1,500 characters (`TestOpenVASDescriptionKeepsItsLines`); a result with none names the test
  (`TestContract_INV25_IssueDetailHasGreenbonesDescription`). Each Greenbone service has a memory limit (`deploy/greenbone`).
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
