# Roadmap

Work is tracked in GitHub issues. Issues labelled `v1` block the v1 release; ideas and work for later are labelled `post-v1`. Released
changes are in [CHANGELOG.md](../CHANGELOG.md).

## v1: who it is for

v1 is for the **one-person IT team** (persona P2 in [PRODUCT.md](PRODUCT.md) §3): within an hour, know whether something they use is
being exploited for real, what they have, and what to do about it.

## v1 is done when

These customer journeys work on a real box (a fresh Ubuntu 26.04 install), checked the way a customer would use them, and the release
is signed. v1 is not "every module finished".

| # | Journey | Stories |
|---|---|---|
| 1 | Install from a signed release on a clean machine, sign in, turn on two-step sign-in | S-CORE-2, S-CORE-3 |
| 2 | Scan the LAN and see the devices with their vendor and version | S-INV-1, S-INV-5 |
| 3 | A newly exploited CVE that matches a device becomes a finding and an alert by email or Telegram within an hour | S-FEED-1, S-ALERT-1, S-NOT-1 |
| 4 | Open a finding and get the patch guidance and a mitigating configuration for the firewall | S-MIT-1, S-MIT-3 |
| 5 | See what needs updating, and to which release | S-TIER-1, S-TIER-2, S-TIER-4 |
| 6 | For the box's public IP, see the exposed ports and the service versions behind them | S-EXP-1, S-EXP-2 |
| 7 | Update to a new release; back up and restore | S-CORE-2 |

Release gates that come with it: the release job (the release `install.sh`, the images pushed to `ghcr.io` and signed), `make vuln-scan`
clean, and no open security finding of High severity.

Ubuntu 24.04 and Debian 13 are supported by the installer; v1 is tested on Ubuntu 26.04, and problems on the other two are welcome as
issues.

## Modules in v1

The groups below are what the web interface offers (`web/src/lib/v1.ts`). Every module is in the same build.

| Group | Modules | What it means |
|---|---|---|
| v1 | core, host (`vedette-host`), feeds, inventory, sensor-active, sensor-passive, agent-intake, findings, mitigation, notify, exposure | Covered by the v1 promise: a defect that breaks one of the journeys above blocks the release |
| Preview | scan, honeypot, logs, ids, ai, reports | Shipped, off by default and labelled "Preview" in the interface. A defect blocks v1 only when it is a security defect, loses data or breaks a journey above |
| After v1 | response, mcp-server, auth-oidc, scan-credentialed | Not offered in the v1 interface; the code stays. A box that already has one turned on sees it read-only with the way to turn it off |

## After v1

The `post-v1` issues hold the work planned after the v1 tag. The larger items:

- Offer the "After v1" modules again and recheck their stories ([#838](https://github.com/KNT048/vedette/issues/838)).
- A review of every screen against "only the action by default, details one click away" ([#1066](https://github.com/KNT048/vedette/issues/1066)).
- Scheduled backups ([#1068](https://github.com/KNT048/vedette/issues/1068)).
- Agentless package reads over a read-only SSH login ([#971](https://github.com/KNT048/vedette/issues/971)), and an osquery agent for macOS ([#954](https://github.com/KNT048/vedette/issues/954)).
- Linux package matching from OSV.dev for more distributions ([#963](https://github.com/KNT048/vedette/issues/963)), and Windows matching from Microsoft's update data ([#964](https://github.com/KNT048/vedette/issues/964)).
- More confirmed mitigation packs for the exploited CVEs that boxes match ([#895](https://github.com/KNT048/vedette/issues/895)).

## Known risks

| Risk | Mitigation |
|---|---|
| Devices that hide their version (some NAS, firewall and router firmware) give a wrong "Do you have it?" | Confidence levels with "suspected" shown clearly, confirmation by a safe check or an agent, and a version a person can declare |
| A free public source changes or disappears | Each feed is pulled directly from its source and can be turned off; a failing source shows its error in Settings → Feeds and the user can point it at a mirror |
| An indicator false positive | Vedette does not block traffic; it only alerts |
| Prompt injection through logs or web pages | Feed, log and web text goes to the AI only as fenced data the model is told never to obey, and the AI has no write tools ([AI_ASSISTANT.md](AI_ASSISTANT.md) §5) |
| A commercial fork | Accepted (Apache-2.0) |
