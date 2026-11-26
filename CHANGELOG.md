# Changelog

All notable changes to Vedette are recorded here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/). Releases and their git tags are made by a maintainer; each release page on GitHub carries the same notes.

## [Unreleased]

### Added
- External targets: a Scan now of a target whose testing terms are accepted runs ZAP's active web scan after the passive one, on the same pages: SQL injection, cross-site scripting, path traversal and other attack checks, bounded in time and rate, with the disruptive rules only on the box's own IP. Scheduled scans keep the passive web scan and say so. Issues show ZAP's risk and confidence; the active web scan is a step of the run page.
- A backup downloaded with a password carries the box's decryption key inside its encryption, so restoring it on a new box keeps every saved secret and two-step sign-in, with no separate key file. A backup downloaded without a password still never holds the key.

### Changed
- External targets: before ZAP's disruptive web rules run on the box's own IP, the box's host helper checks for itself that a person pressed Scan now (or Run once now) for that address within the last 6 hours (one active pass of at most 4 pages), and reads the box's gateway itself (not carrier-grade NAT, and readable). When either check fails, the page gets the active web scan without the disruptive rules and the scan says why.
- External targets: a deep scan runs its light checks first and nmap's password-guessing and crash scripts last, after OpenVAS, on the ports it found open, so a firewall that blocks the box during them costs only that step.
- External targets: before each step a scan checks that the ports it saw open still answer; when the target stops answering (for example a router that loses its NAT loopback), the later steps say so, the run ends partly done instead of done, and the scan does not count as a miss of any port.
- External targets: the ZAP image is downloaded when the External exposure module is turned on and when the box starts with it on, so the first scan does not skip the web checks; a scan that finds an engine image still downloading says so and ends partly done.
- External targets: one button accepts the testing terms, disruptive checks included (they run only in a scan a person starts, never on the schedule). The box's own IP it does not go out through now can be accepted while its proof holds. Acceptances made before the update stay valid; one made without the disruptive checks keeps the deep scan only until the terms are accepted again. A refused acceptance is logged with its reason.

### Fixed
- External targets: a port that the box's own network answers for any address (for example a firewall's SIP or SCCP helper on 5060 or 2000) is no longer shown as an open service of every target. Before a port found open counts, the box checks it against never-routed documentation addresses; such a port is left out, neither opened nor closed, and the target says so in one line.
- External targets: a firewall or WAF that blocks the box's public IP no longer closes the target's ports. A port open before that a scan did not see is connected to once more before the results are saved: a reset closes it as before, no answer at all keeps it open until three scans over at least a day find it silent.
- External targets: the deep scan of a domain no longer says "Disruptive checks are included" when they cannot run there. The dialog and the run say they run only on the domain's addresses that are this box's own public IP; a typed-in IP says they are not included.
- An update or rollback follows the module a person switched when it starts or stops a service, and an automatic install that waits for a restart says so.
- A network card that answers on two addresses has one main address in the inventory.
- VMware ESXi fixed builds are read from the wording of VMware's CVE records.
- Missing CVE records of catalogue CVEs are read by ID; a CVE named only by a custom feed and without a record makes the box read the whole CVE list early.
- Incidents and other features' screens show a device's current name.
- Confirmed recommendation packs carry example values, a Linux host firewall step, check commands and vendor links.

## [0.1.5] - 2026-11-24

Fifth test release of the 0.1 line, for a lab or spare box. Boxes on 0.1.1 to 0.1.4 update in place from Settings → Updates.

### Changed
- A distribution kernel is judged once, on the running kernel, with a restart offered.
- Each finding has one "What to do", with the fix first, then the workaround and a firewall step from confirmed packs for sixteen exploited CVEs.
- Questions are asked only when an answer can change something.
- Alerts and lists state each finding's status once; device names, versions and last-seen times are consistent across screens.
- Updates and backups say what will happen and what did.
- Downloaded backups can be protected with a password.
- Runs cut off by a restart end cleanly.

## [0.1.4] - 2026-11-24

Fourth test release of the 0.1 line. Boxes on 0.1.1 to 0.1.3 update in place from Settings → Updates.

### Changed
- Automatic updates install on a box that never checked for operating system updates.
- Run pages show the true order, progress and stop reasons.
- Alert lines say why they were sent, with Send now for alerts not sent.
- Home shows the first-run summary.
- Findings follow a device when it is split in two.
- A version change names the person who made it.

## [0.1.3] - 2026-11-23

Third test release of the 0.1 line. Boxes on 0.1.1 or 0.1.2 update in place from Settings → Updates. Rolling back to 0.1.2 restores the database backup taken just before the update.

### Changed
- Declared and scanned software get the CVEs their record names: precise vendor versions, distribution builds, one catalogue entry per product.
- Every finding that enters the urgent layers is alerted once; alert mails carry the reasons and the verification lines; the report mail carries the report.
- Scans and device checks queue instead of being refused, and show their place in line.
- One consistent status on every findings screen; search on every list; one scan-scope editor that shows its cost.
- Empty lists no longer fail; an update asks before it starts.
- A new box installed from a beta release follows the beta channel.

## [0.1.2] - 2026-11-23

Second test release of the 0.1 line. Boxes on 0.1.1 update in place from Settings → Updates; boxes on 0.1.0-beta.1 still need a fresh install (see 0.1.1). Rolling back to 0.1.1 restores the database backup taken just before the update.

### Changed
- Stored software lines are identified again when an update brings a new product catalogue, so devices without an agent and hand-entered software no longer keep an outdated answer.
- The advisory banner says how to get the fix that is really offered.

## [0.1.1] - 2026-11-23

First release of the 0.1 line, for testing on a lab or spare box. Install on Ubuntu 24.04, Ubuntu 26.04 or Debian 13 (amd64 or arm64) with the `install.sh` of the release. After install, choose Settings → Updates → Software channel → Beta to receive the next test releases.

### Upgrade notes
- Boxes on 0.1.0-beta.1 cannot update to this release in place because the database format changed: uninstall with `sh install.sh --uninstall --yes`, then install this release.

### Added
- SNMP credentials take an optional UDP port (1 to 65535; empty means 161) for devices that answer SNMP on another port; Test, Read now and the scan window's reads use it, and the answer names the port tried.

## [0.1.0-beta.1] - 2026-11-13

First public beta, for testing on a lab or spare box, not for production. Install on Ubuntu 24.04, Ubuntu 26.04 or Debian 13 (amd64 or arm64) with the `install.sh` of the release.

### Known limits
- SPAN capture and the offline update bundle are not in this beta.
- Zalo personal is experimental.

[Unreleased]: https://github.com/KNT048/vedette/compare/v0.1.5...HEAD
[0.1.5]: https://github.com/KNT048/vedette/releases/tag/v0.1.5
[0.1.4]: https://github.com/KNT048/vedette/releases/tag/v0.1.4
[0.1.3]: https://github.com/KNT048/vedette/releases/tag/v0.1.3
[0.1.2]: https://github.com/KNT048/vedette/releases/tag/v0.1.2
[0.1.1]: https://github.com/KNT048/vedette/releases/tag/v0.1.1
[0.1.0-beta.1]: https://github.com/KNT048/vedette/releases/tag/v0.1.0-beta.1
