# Beta feedback plan (kien, N100 box, v0.1.0-beta.1, 2026-11-13)

Owner: AI-Trưởng (Ubuntu lead). The supervisor follows up. Source: kien's 15 items after trying the beta on a real N100 box (Ubuntu 26.04.1). Each item was checked against the code at main 6f43df8e by three read-only agents. The full evidence, with file:line, is kept outside the repo in `~/vedette-wt/beta-verify/`; the summary is below.

Rules that apply to every group:
- story criterion first (`no-imagined-features.md`)
- the mock is the contract (`gui-first.md`)
- plan → build → critique for screens (`docs/FRONTEND.md` §5)
- Playwright of the touched specs runs **before** merge, because CI does not run e2e (lesson from #636)
- Opus review for host / core / response / sensor / untrusted input
- one PR per group, merged through the lead's merge-step

The reference layout doc kien pointed to is from another project. It is git-ignored: its method and density ideas may be used, but never its names or branding, and it is never committed.

## 1. Verify result

| # | Item | Verdict | What the code shows |
|---|---|---|---|
| 1 | Honeypot protocols | TRUE | **Have:** OpenCanary 0.9.10 has 17 modules (ftp, git, http, https, httpproxy, mongodb, mssql, mysql, ntp, rdp, redis, sip, ssh, tcpbanner, telnet, tftp, vnc). snmp and llmnr load only with scapy; smb and portscan only on Linux. Vedette exposes 5 and forces the other 14 off (INV-2, FORBID-2).<br>**Could add:** ftp, telnet, httpproxy, mysql, mongodb, redis, vnc, git, tcpbanner, ntp, tftp and sip work in our container. https needs a certificate. snmp needs scapy (GPL-2).<br>**Can't:** llmnr needs raw sockets; portscan needs iptables and the kernel log. |
| 2 | "Trap IP" wording | TRUE | One thing has three names: secondary IP, decoy IP, decoy machine. |
| 3 | Decoy personalities + bug | TRUE | **The bug:** every form error shows under Decoy IP, and the empty name field's placeholder `FILESRV-OLD` looks like a value. The name rule itself is fine.<br>**Personalities:** they only switch the HTTP login page, for every trap IP at once. The ports they list (9100 / 554) never open. Samba's name is fixed (`FILESERVER`). |
| 4 | Trap IP = profile | PARTLY | **Reshape:** the secondary IP plus the decoys table become one list of profiles.<br>**New:** per-IP service sets, using a per-IP allow-list in the trap namespace's firewall rules (host).<br>**Bug:** a hit on any decoy IP is labelled with the secondary IP's hostname (`ingest.go:418`), which is also what response receives. |
| 5 | Honey tokens | TRUE | Every token is made by hand.<br>**URL and DNS tokens can never fire:** there is no route and no listener (D-90 (7)), yet the GUI promises "calls home" and Coverage marks them Covered. |
| 6 | Tabs, one style | TRUE | A `Tabs` component exists, but only Scans (`?tab=`), Response (`#hash`) and Reports (`?tab=`) use it, each in its own way.<br>Honeypot has 7 stacked sections, Logs 6, device detail 5. There is no KPI card component. |
| 7 | Blocklist empty | TRUE (expected) | **Expected:** only an approved `blocklist_add` action fills the list, and its template ships disabled, so empty is correct on that box.<br>**Bug:** a block on a private IP is accepted and reported "Added", but never published, and no `refused` line is written. The page doesn't say what fills the list. |
| 8 | `https://vedette…` links | TRUE | **Cause:** the appliance's certificate lists the fixed name `vedette` first, so `baseURL` gives `https://vedette:8443`.<br>**Affected:** every notify link (finding, incident, approval, login mail), the blocklist URL, the URL token.<br>**Why tests missed it:** the mock uses the box IP. |
| 9 | osquery on the box | PARTLY | osquery is not installed on the box.<br>**Bigger:** on a real box the box device has **no packages at all**. The dpkg feed of D-53 was never connected (`cmd/vedette/inventory.go:33`), yet the UI says "read from the box (dpkg), exact". Software is a section, not a tab. |
| 10 | Ways to add a device | TRUE | The GUI offers only "Add a device" and "Import CSV"; osquery and Wazuh sit at the bottom of /devices/setup (admin only).<br>The API needs a login session. SSH has no code; there is no HTTP push. |
| 11 | /devices | TRUE | **Finding a device:** no tabs, no "Approved" filter, no link after approving. The device lands in "All" (by last seen, 50 per page), often as "Unknown &lt;IP&gt;".<br>**Versions:** one generic check for every vendor, and nothing compares the typed version with what a scan sees.<br>**The "— —" row:** a hand-added product with no name and no IP (the form allows it). Each module names it differently, and scan calls it "outside scope". |
| 12 | Box can't scan itself | TRUE | The inventory scan rule `box` refuses it, even when a person picks it (`scanpolicy.go:57,134`). This came from a PR #66 review fix with no D and no written reason; it is not D-446. |
| 13 | /scans with 500 devices | TRUE | The picker has no search, filter, grouping or paging.<br>"Select all → 1" is D-126 working as designed: it skips unapproved, unknown-type, fragile and hand-added devices. The button doesn't say so. |
| 14 | /findings bulk | TRUE | No bulk actions, no way to edit a version, no "accept risk" status.<br>One Office entry with no version gives about 29 Critical/Suspected findings: every KEV entry with ransomware use counts as Critical, even on a product-only match. |
| 15 | Exposure confirm step | TRUE (as D-26 says) | The separate admin confirmation is the D-26 record (legal, D-5). kien has now OKed replacing it (§3, D-473). |

Also found while verifying (no item number):
- Scan detection never fires on a real box: portscan is off, so only "Test scan" makes a hit.
- Coverage over-claims scanning, URL tokens and DNS tokens.
- Decoy hits carry the wrong hostname (#4).
- Private-IP blocks are dropped silently (#7).
- The box's package list is empty (#9).

## 2. Groups, decisions, owners, order

D numbers come from the lead's range (D-450..D-479); D-464..D-473 are reserved here. Each PR writes its own `docs/decisions/D-nnn.md` (one table row, with sources) and adds its story criteria first.

| Group | Items | D | Story (criterion added) | Owner | Review |
|---|---|---|---|---|---|
| **B0 Page layout** | 6 | D-464 | new S-UI-1 "every page has the same frame" | Trưởng agent (web shell) | QA critique + Opus (UI) |
| **B1 Box address** | 8 | D-465 | S-CORE-8 (Box network), S-NOT-1, S-RESP-3 | Trưởng agent (core, cmd, host) | Opus |
| **B2 Trap IP profiles** | 2, 3, 4 + hit-hostname bug | D-466 | S-HP-1 | Trưởng agent (honeypot, host, web) | Opus |
| **B3 Honeypot services + sweep detection** | 1 + scan-detection gap | D-467 | S-HP-1 | Trưởng agent, after B2 | Opus |
| **B4 Honey token presets** | 5 + dead URL/DNS tokens | D-468 | S-HP-2 | Trưởng agent, after B3 | Opus |
| **B5 Blocklist honesty** | 7 | D-469 | S-RESP-3 | Trưởng agent (response, web) | Opus |
| **B6 The box covers itself** | 9, 12 | D-470 | S-INV-5 | Trưởng agent (host, inventory, scan) | Opus |
| **B7 Devices page** | 10, 11 | D-471 | S-INV-1, S-INV-2, S-INV-4 | Trưởng agent (inventory, web), after B0 | Opus (inventory API) |
| **B8 Scan target picker** | 13 | D-472 | S-SCAN-4 | Trưởng agent (scan, web), after B0 | Opus |
| **M1 Findings at scale** | 14 | Mlee's range | S-FND story Mlee picks | **Mlee** (findings). Needs B7's "edit version" call. | Mlee's rule |
| **M2 Exposure: Scan now is the confirmation** | 15 | D-473 | S-EXP-1 | **Mlee** (exposure) | Opus (legal record) |

**Order:**
- **Wave 1:** B0, B1 and B5 in parallel (independent).
- **Wave 2:** B2, B6 and B8. B8 needs B0's tab frame.
- **Wave 3:** B3 (after B2: same honeypot files) and B7 (after B0).
- **Wave 4:** B4 (after B3).

**Limits:**
- At most 3–4 agents at a time and 2 heavy jobs.
- Lab L1/L2 wait until wave 1 is merged (supervisor's priority).
- M1 and M2 start when Mlee is free (Zalo + email OAuth first); the supervisor relays.

## 3. Decisions (what each D will say)

- **D-464 Page frame.** Every menu page uses one frame:
  - **Header:** page title and short description on one line (`PageHeader`).
  - **KPI strip:** optional, at most 4 small cards with a number, a label and a link.
  - **Tab row:** horizontal, shown when the page has more than one area. One shared component; the open tab lives in `?tab=<id>` (Scans and Reports already do this; Response moves from `#hash`, with old hash links redirected). Tabs never hide a required action: a red count on the tab when something there needs the user.
  - **Settings** keeps its vertical sub-menu: settings are many short forms, and Grafana and GitLab admin do it this way.
  - **Density:** body 13–14 px, page title about 20 px.
  - **Rollout:** B0 builds the frame and moves Scans, Response and Reports onto it. Honeypot, Devices, device detail and Logs adopt it in B2, B7 and Mlee's work. Logs is Mlee's module: she adopts it when she touches the page.
  - **Sources:** kien's screenshot (title, tab row, KPI cards), and the tab and density rules of the console reference doc (method only).
- **D-465 Box address.** Settings → Box network gets a **Box address** field: a host name or IP the LAN can reach.
  - **Default:** the management IPv4 the host reports.
  - **Used by:** every link the box makes (notify messages, approval links, login mail, blocklist URL, URL tokens, osquery/Wazuh enrol commands). The fixed name `vedette` is never used for links again.
  - **Certificate:** includes it as a SAN, re-issued on save.
  - **Sources:** Grafana `root_url`, GitLab `external_url`, Home Assistant internal URL (default from the detected address), Jenkins URL.
- **D-466 Trap IPs are profiles.** One list of trap IPs replaces "secondary IP" + "Decoy personalities".
  - **Each profile:** name, IP, host name, a vendor MAC prefix and its own set of services.
  - **Presets** fill the profile: File server (SMB 445, RDP 3389), NAS (HTTP NAS login, SMB), Printer, Camera, Linux server (SSH), Database (MSSQL / MySQL). Custom picks services.
  - **Per-IP services:** OpenCanary still runs one process (D-90 (1)). The host enforces each IP's service set with a per-IP allow-list in the trap namespace's nft rules (host API change).
  - **Login page and SMB name:** only one per box, so a profile's host name is its label. The first SMB-serving profile's name becomes the share's NetBIOS name.
  - **Hits** are labelled with the profile of the IP that was hit. The form shows each error under its own field.
  - **Source:** Thinkst Canary device personalities (one device = one personality + its services).
- **D-467 Honeypot services and sweep detection.**
  - **New services:** ftp, telnet, httpproxy, mysql, mongodb, redis, vnc, git, tcpbanner, ntp, tftp, sip, and https (core issues its certificate) become selectable per profile.
  - **Not offered:**
    - snmp and llmnr: they need scapy (GPL-2, `legal.md`) and raw sockets.
    - portscan: it needs iptables in the container. **Instead,** core flags a **sweep** when one source touches 2 or more trap IPs or ports within 60 s, and that is what "Scan detection" means.
  - Coverage claims only what really fires.
- **D-468 Honey token presets.** The tokens page starts with presets the user only switches on or off:
  - a bait file set placed in the trap's own share
  - one bait credential accepted by the trap's SSH, RDP and SMB
  
  "Advanced" is today's manual form. URL and DNS tokens are removed from "create" until the box has a listener for them; existing ones are shown as "not active: the box has no listener yet". Coverage no longer marks them covered.
- **D-469 Blocklist honesty.**
  - A `blocklist_add` on a private or reserved address is refused when the plan is made (code `not_public`), and the spec's `refused` log line is written.
  - **The empty list explains itself:** it is filled only by approved "block" actions, has public addresses only, the template is off by default, and here is where to turn it on.
- **D-470 The box covers itself.** vedette-host reads the box's installed packages (`dpkg-query`, read-only, through the existing peer-checked socket) and inventory fills the box device's software from it (finishes D-53 / S-INV-5); findings then match the box's own packages exactly.
  - **No osquery on the appliance:** the dpkg list already gives exact packages, with no extra daemon on the box. kien can still enrol it with osquery like any server.
  - **Self-scan:** a person may pick the box itself as a scan target. Sweeps still skip it, and so does "select all".
  - **Sources:** Tenable treats scanning the scanner host as normal; Lansweeper and runZero list their own collector.
- **D-471 Devices page.**
  - **Tabs:** To review (pending), All devices, Software, Add devices. After approving, the toast links to the device, and the device is found under All with a filter "approved by me / last 24 h".
  - **Add devices** lists every way that exists: network scan (automatic), add by hand, CSV import, osquery, Wazuh. Each has a short "when to use". Methods that do not exist (SSH, HTTP push, API key) are not listed.
  - **One naming rule** for every module: name → host name → IP → "&lt;product&gt; (no device)". A hand-added product with no name and no IP is offered "attach to a device" or a name. Scan gets a `no_ip` reason instead of "outside scope".
  - **Versions:** an "edit version" call, which M1 needs too. When a scan or osquery sees a different version than the typed one, the device shows "version on the device looks like X" with Accept.
  - **Sources:** runZero inventory views and bulk select, Lansweeper's required fields for hand-made assets.
- **D-472 Scan target picker.** Search, filter (type, subnet, approved, last seen), group by subnet, paging. "Select all" says "N selected; M need your own tick (unknown type, fragile, hand-added)" with a "Show them" link, keeping D-126's per-device consent. The backend reads inventory in one batch. **Source:** runZero target selection by search and saved queries.
- **D-473 Exposure: an admin's Scan now is the authorization** (kien 2026-11-13, through the supervisor).
  - **The trigger:** the first **Scan now** on a target by an **admin with two-step sign-in** records the D-26 confirmation: who, when, which target, and the exact legal sentence shown next to the button.
  - **What goes away:** the separate confirm step. Operators still cannot scan an unconfirmed target.
  - **Basis:** amends D-26 and keeps D-5's record. **Sources:** Detectify, Qualys and Tenable authorize through ownership and permissions, not a scan-time step. Implemented by Mlee.

## 4. Per-group acceptance (each PR adds these to its story)

- **B0:** every page in the main menu renders the frame. Changing tab updates `?tab=`, and reload and back keep the tab. Old Response `#hash` links open the right tab. A phone has no sideways scroll: the tab row scrolls inside itself. axe has no new violations.
- **B1:**
  - **Fresh install:** the Box address equals the management IP; a test notify message and an approval link use it; the blocklist URL on the Response page uses it.
  - **Changing it:** a new certificate whose SAN includes it.
  - **No fixed name:** no `https://vedette` in any link the box makes (a test greps the rendered templates).
- **B2:**
  - **Wording:** "Trap IP" everywhere; no "secondary IP" left in the GUI.
  - **Profiles:** a File server preset opens 445 and 3389 only on its IP, proven by a lab nmap in the trap netns.
  - **Hits:** a hit on profile B shows B's name.
  - **Form errors:** each one sits under its own field; an empty name says "Enter a name".
- **B3:**
  - **Lab:** every offered service answers in a lab run (nmap service probe from another netns).
  - **Sweep detection:** two trap IPs touched by one source within 60 s make one "sweep" hit.
  - **Coverage:** marks nothing that cannot fire.
- **B4:**
  - **Presets:** switching on "bait files" places them in the trap share, and opening one makes a hit naming the file.
  - **URL/DNS:** they are not offered for create.
- **B5:**
  - **Private address:** a block on 192.168.1.5 is refused at plan time with `not_public`, and the `refused` log line is written.
  - **Empty list:** the page says what fills it and links to the template.
- **B6:**
  - **Box software:** on a lab VM install, the box device shows its dpkg packages (count matches `dpkg-query -W`), and findings match them.
  - **Self-scan:** a person can scan the box; a sweep does not include it.
- **B7:**
  - **Approve and find:** approve a device, follow the toast link, then find it again under All with "approved last 24 h".
  - **Naming:** a product with no device reads "Microsoft Office (no device)" in devices, scans and findings.
  - **Versions:** a typed version differing from the scanned one shows the hint.
- **B8:**
  - **500 devices (mock):** search and subnet grouping work, and paging keeps the selection.
  - **Select all:** states how many need their own tick.

## 5. Not in this plan

- kien's "API / SSH / HTTP" ways to add a device: SSH (scan-credentialed) has no code, and API keys don't exist. Each needs its own story; they are not listed in B7's "Add devices".
- snmp, llmnr and OpenCanary portscan (D-467 says why).
- Mlee's own design for M1 (bulk by filter, accepted risk with expiry, "I updated X").
