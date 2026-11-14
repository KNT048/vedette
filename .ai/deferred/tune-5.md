# Deferred — feat/tune-5-osquery-ubr (D-524, 2026-11-14)

- [ ] **KEV matching by the UBR — owner: Mlee (findings), moved by the supervisor's split after review round 1.** The UBR is collected
  and shown (agent-intake INV-20); matching is as on main. The removed first design is in commit 662e9736 (branch
  feat/tune-5-osquery-ubr) and can be reused:
  - agent-intake `mapper.go`: `winReleases` (build → client/server release, NVD product name: 10240, 14393, 17763, 19044, 19045,
    20348, 22621, 22631, 25398, 26100, 26200), `windowsRow` (vendor microsoft, product "Windows 11 23H2", version
    "10.0.22631.4460", KEV key `microsoft|windows`, CPE `cpe:2.3:o:microsoft:windows_11_23h2:<version>:*:*:*:*:*:<target_hw>:*`),
    a `windows_os` row put by `withWindows` on every `programs` list and turned into the first software row by `mapPackages`;
    Wazuh `wazuhWindows` (an `os.version` with 4 parts gives the same row, target any). The node already stores name, full
    version and target (`intake_osquery_nodes.win_*`, `nodeRow.win`), so the row needs no new storage.
  - findings `schemes.go` `windowsOthersOnly` + `match.go` `decide` call: an entry naming only other Windows releases → No without
    proof. With tests `TestMatchAsset_D524_WindowsByUpdateRevision`, `TestWindowsRow`, `TestWazuhWindows`.
  - Design input: /home/byn/vedette-wt/tune5-review1.md — H1 suppress only when the device's build is above every listed
    release's build (out-of-service releases are absent from new entries; table NVD product → build incl. `windows_10:1607`,
    `windows_10:-`, `windows_11:-`, 6.x); H2 sibling releases (25H2/24H2, 23H2/22H2, 10 22H2/21H2) evaluated by revision, guard
    "the device's product is named by NVD somewhere", check `windows_11_25h2` and `windows_server_2022_23h2` against real NVD
    data and record the CVE ids; M1 Wazuh `os.arch` → target_hw (and/or Yes when inside every target row); M2 feature upgrades:
    no stale release row when the request's os_version build differs, and what closes the old release's findings; M4 a manual
    "Windows 11" row next to the agent's (the Junos `covered` model); L1 a target-only No is not a proof; L2 old-style
    `windows_server_2019:-` entries stay "not checked"; L3 "I updated it" text for agent rows; L4 22000 and 19041–19043 builds.
- [ ] **N100 / lab measurement** (agents do not SSH or deploy): on a Windows lab PC with osquery 5.12.1 enrolled to the N100, the
  device shows "Microsoft Windows 11 Pro 10.0.22631.<UBR>" (= `winver`, or `reg query "HKLM\SOFTWARE\Microsoft\Windows
  NT\CurrentVersion" /v UBR`) within minutes of enrolment, and the new UBR within an hour of a monthly update. Owner: Mac
  supervisor (tester) after Trưởng deploys. (A KEV CVE clearing by the UBR belongs to the matching follow-up above.)
