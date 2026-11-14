# Deferred — feat/tune-5b-windows-ubr-match (D-546, 2026-11-14)

- [ ] **N100 / lab check** (agents do not SSH or deploy; owner: Mac supervisor as tester after Trưởng deploys): a Windows lab PC with
  osquery 5.12.1 enrolled to the N100 shows a software row "Windows 11 <release>" with version 10.0.<build>.<UBR> (= `winver`) within
  minutes of enrolment; an exploited CVE whose fix is newer than the PC's UBR is a version finding (high) with "What to do" naming the
  fixed build; after installing the monthly update, within about two hours, those findings close "Not affected". Also with a Wazuh
  Windows agent (row target x64 from `os.arch`). Closes `.ai/deferred/tune-5.md` item 1 once seen (that file is TUNE-5's; its owner
  marks it).
- [ ] **Windows entries not read by revision** (owner: findings; decide when a customer meets one): CISA "Microsoft | Multiple
  Products" entries and entries whose ranges come from CVE.org (D-556) still go through `decide`, so a Windows release row with an
  unknown target gets "not checked" there instead of a version answer. Rare for Windows; measure on the N100 feed first.
- [ ] **Unverified NVD names** (owner: findings): `windows_10_1511` and `windows_10_1703` in `core/winrel` were not confirmed against
  NVD's CPE dictionary (rate limit, 2026-11-14). Only those out-of-service releases are affected; check with the N100's feed data.

## From Opus review r1 of #786 (sessions/tune5b-review1.md), owner "Mac (ex-Mlee)"

- [ ] **M4 — Windows component KEV products never reach the OS row** (owner: Mac (ex-Mlee); findings + agent-intake). The OS row is
  keyed only `microsoft|windows`; CISA lists ~40–45 exploited Windows OS flaws under component products (`content/catalog/
  kev-products.json`: "Win32k" 25, "SMBv1"/"SMBv1 server"/"SMBv3" 5, "Windows CNG Key Isolation Service", "Windows COM+ Event
  System Service", "Windows Ancillary Function Driver for WinSock"; older: "Graphics Device Interface (GDI)", "DirectX Graphics
  Kernel", "CSRSS", "HTTP.sys", "Ancillary Function Driver (afd.sys)", "ATM Font Driver"). Measure on the N100 feed first (how many
  carry `o:microsoft:windows_*` release rows), then give the row those keys (catalog-driven list) so `windowsDecide` reads them.
- [ ] **LOW-3 — wording** (owner: Mac (ex-Mlee)): (a) `windows.go` "newer ones among them … check that <release> is still supported"
  also fires when the newer listed releases are of the other kind (Server 2022 on a client-only entry): compute `newest` over the
  device's own kind for that sentence and say "NVD lists only client releases" otherwise; (b) the target-only note names the
  device's release when the rows were a sibling's ("… for Windows 11 25H2 on arm64 only" for 24H2 rows): name the sibling;
  (c) `winNames` prints 6.x products lower case ("windows 7"): give them display names.
- [ ] **LOW-6 — first-hour polling** (owner: Mac (ex-Mlee)): a Windows 6.x node (Server 2012 R2 on ESU) never gets a usable
  `os_revision`, so `programs` stays at 60 s for its whole first hour (`ingest.go` `deliver`). Count `packages` when the stored
  release is empty and the request's `os_version` is not `10.0.*`, or document 6.x in agent-intake IMPACT next to osquery < 5.12.
- [ ] **LOW-7 — feature update with a hand-added "Windows" row** (owner: Mac (ex-Mlee)): between clearing the old release and the new
  revision (up to ~2 h) the manual row is matched again, so a device that never had them gets ~175 medium "not checked" findings
  (created, notified) that close or regrade when the new row arrives. Keep the manual row covered while the node is mid-upgrade
  (`os_version` Windows 10.0, no stored release), or record it in findings INV-15.
- [ ] **LOW-8 — fixes with manual steps close by build** (owner: Mac (ex-Mlee)): an entry whose remediation needs steps beyond the
  cumulative update (BlackLotus-class Secure Boot revocations) closes "Not affected" once the UBR passes NVD's end. Add to the close
  note "steps the advisory lists beyond the update are not checked", or keep a list of such CVEs open.
- [ ] **LOW-9 — test gaps** (owner: Mac (ex-Mlee)): `windowsDecide` cases not tested: all-older entry with a family row that `mayBe`
  (undecidable → Unknown); unknown target with mixed Yes/No rows → Unknown; an entry listing only 6.x releases; cross-kind `newest`.
- [ ] **winrel upkeep** (owner: Mac (ex-Mlee); trigger: each new Windows release GA, and the Patch Tuesday after it): add the release
  (build, NVD name once NVD lists it, line, GA date, GA revision) to `core/winrel`; check whether Windows 11 26H1 (build 28000,
  new Arm devices) and 26H2 exist in NVD's CPE dictionary now. Fill `LastFreeRev` for releases whose servicing ended (23H2
  Enterprise ended 2026-11-10: its last revision; 22H2 22621.6060) once a case needs it. Until then those builds get the
  keyless row (review r1 M3) and every Windows entry is "not checked".
- [ ] **GA revisions not confirmed** (owner: Mac (ex-Mlee)): `GARev` is set only where known (D-546 r1 list); Server 2016/2019/2022,
  Server 2022 23H2, 1511–1909 are 0 (no date proof). Server 2025's 2314 and 22H2's 521 are the stricter of the candidate values;
  confirm from Microsoft's release-information tables.
