# Modules: switched on/off separately

Principle: the user switches on exactly what they need. Each module is a Go package in `modules/<name>/` with:

```
modules/<name>/
  MANIFEST.yaml   # id, display name, a 1-sentence description, dependencies, permissions needed, ports opened, data written, stories served
  CONTRACT.md     # INV/PRE/POST/FORBID — docs/MODULE_CONTRACTS.md
  IMPACT.md       # who calls what, who is affected when this module is switched off
  module.go       # implements core.Module: Init, Routes, Jobs, Migrations, Enable, Disable, Health
  migrations/     # tables prefixed <name>_ ; switching off does not delete
  ...
```

General rules:
- **Off** = no routes registered, no jobs run, no ports opened; the data is kept as is; the UI shows "off" where data is missing (S-CORE-1).
- **Dependencies** are declared in the MANIFEST; switching on a module with missing dependencies → the UI asks to turn them on together, never silently.
- **Needs `vedette-host`**: `needs_host: true` in the MANIFEST (honeypot, scan-credentialed). A container-only install cannot turn that module on: `GET /modules` reports `available: false`, turning on → 409 `not_appliance`, the setup bundle leaves it out.
- **Permissions** (raw socket, port <1024, reading files) are declared; core grants exactly those (capabilities / a systemd socket), and does not run everything as root.
- **Stories**: the MANIFEST lists the story IDs the module serves; no story → no module.
- Tiers: *core* is always on; *standard* is on by default for an SMB; *optional* is off by default.

| ID (contract) | Name | Tier | Depends on | Container | Permissions/ports | Tables owned | Stories | Milestone |
|---|---|---|---|---|---|---|---|---|
| [`core`](../modules/core/CONTRACT.md) | Core: UI, auth, configuration, module registry, job scheduler, audit, update client | core | host (Appliance type) | `core` | HTTPS 8443 | `core_*` | S-CORE-1..7 | M2 |
| [`feeds`](../modules/feeds/CONTRACT.md) | Local feed store: the box pulls and parses feeds directly from the sources, the hot board, CVE/IOC lookup | standard | core | `core` | out to the Internet (HTTPS) | `feeds_*` | S-FEED-1..5 | M2 |
| [`inventory`](../modules/inventory/CONTRACT.md) | Asset inventory: hand declaration + import from sensors/agents; matched against feeds; "This box" is the first device | standard | core, feeds | `core` | none | `inv_*` | S-INV-1..3, 5; S-FEED-1 the "Do you have it?" column | M2 (by hand), M3 (automatic) |
| [`notify`](../modules/notify/CONTRACT.md) | Channels Zalo OA/personal Zalo/Telegram/Slack/email/webhook, merging, quiet schedule, approvers in each channel | standard | core | `core` | out to the Internet | `notify_*` | S-NOT-1, 2; S-ALERT-1, 3 | M2 |
| [`sensor-passive`](../modules/sensor-passive/CONTRACT.md) | Passive: DHCP/mDNS/SSDP/ARP/LLDP listeners, a SPAN metadata analyser written in Go (no Zeek/Suricata), OUI, optional Fingerbank API | standard | inventory | `sensor` | raw socket, pcap | `inv_*` (source=passive, through an interface) | S-INV-1, 3; S-LOG-4 | M3 |
| [`sensor-active`](../modules/sensor-active/CONTRACT.md) | Active: nmap (`-sV -O`, a time window in the organisation's time zone, throttling), a fragile or unclassified device gets one light scan (no `-sV`) inside the window; read-only SNMP (GET system + ENTITY-MIB index 1) from the `scan` worker to approved devices in scope, one pass per window and a Test button; v2c/v3 credentials in Settings › Scanning › Engines | standard | inventory | `scan` (nmap; for now it runs from core) | raw socket | `sa_*` (writes observations into inventory through `core/observe`) | S-INV-1, S-SCAN-4 | M3 |
| [`findings`](../modules/findings/CONTRACT.md) | Matches flaw × device → a suspected/confirmed finding, a handling lifecycle | standard | inventory, feeds | `core` | none | `fnd_*` | S-MIT-1 (list, status), S-INV-2, S-SCAN-3, S-ALERT-1 | M2 |
| [`mitigation`](../modules/mitigation/CONTRACT.md) | Mitigation packs: patch guidance, temporary fixes, vendor-specific configuration, exploitation indicators; confirmed recommendations ship with the signed update | standard | findings, inventory | `core` | none | `mit_*` | S-MIT-1 ("What to do"), 3, 4; S-AI-2 | M3 |
| [`exposure`](../modules/exposure/CONTRACT.md) | External surface: ownership verification, CT (crt.sh) → DNS → a web check by name on 80/443; ports, admin pages, certificates only on the box's verified IP (the scanner of `scan`, pure Go), a daily snapshot | optional | inventory | `scan` | out to the Internet | `exp_*` | S-EXP-1 | M4 |
| [`scan`](../modules/scan/CONTRACT.md) | Nuclei confirmation scans (the kev/vkev safe set), rescans on a KEV event, evidence | optional | inventory, feeds | `scan` | out to the LAN/Internet | `scan_*` | S-SCAN-1..4 | M4 |
| [`scan-credentialed`](../modules/scan-credentialed/CONTRACT.md) | Greenbone CE in its own container, SSH key | optional | scan | `greenbone` | OCI | `scan_*` | S-SCAN-5 | M7 |
| [`honeypot`](../modules/honeypot/CONTRACT.md) | Traps (OpenCanary, BSD-3): fake SMB/RDP/SSH/MSSQL/HTTP and 13 other OpenCanary services, device roles taken from the inventory, honey tokens, detection of scans of trap IPs | optional | inventory | `honeypot` (+ API in `core`) | ports 445/3389/22/1433/80 on a secondary IP (macvlan) | `hp_*` | S-HP-1, 2 | M5 |
| [`logs`](../modules/logs/CONTRACT.md) | Receives syslog (UDP/TCP/TLS 514/6514), parsers by a catalogue of 48 sources, aggregation + a 7-day baseline, IOC matching, SPAN metadata, SIEM forwarding | optional | feeds, inventory | `sensor` (listening) + `core` (storage, API) | ports 514/6514 | `logs_*` | S-LOG-1..4 | M5 |
| [`ids`](../modules/ids/CONTRACT.md) | Intrusion detection: reads the IPS/IDS events in the firewall logs sent to the box (FortiGate, Suricata/Snort, Sophos, SonicWall, Palo Alto, Meraki), one alert per signature, source, destination and hour with the CVE code; links to the finding of the targeted device (the "under attack" tier) | optional | inventory, logs | `core` | none | `ids_*` | S-IDS-1 | M5 |
| [`response`](../modules/response/CONTRACT.md) | Response: WHEN-IF-THEN rules and AI proposals → actions on a firewall/switch/DNS, **approval required by default**, 2 people for high risk, a blocklist for firewalls to pull; a separate execution switch is OFF by default. The only exception to SYS-8 | optional (high risk) | notify, inventory (soft: ai; the connection to devices belongs to `core`) | `core` | none (public routes on 8443) | `resp_*` | S-RESP-1..4, S-AI-8 | M1 (GUI) |
| [`agent-intake`](../modules/agent-intake/CONTRACT.md) | Receives packages from osquery (Vedette is the TLS server, a one-line install script for Linux/Windows Server) or pulls the read-only Wazuh API; ships no agent, only the server | optional | inventory | `core` | HTTPS 8443 | `intake_*` (writes observations with source=agent into `inv_*` through an interface) | S-INV-4 | M7 |
| [`ai`](../modules/ai/CONTRACT.md) | BYOK assistant: several profiles + job assignment with fallback, the harness (rules, memory, skills, RAG, external connections, hooks), a tamper-resistant AI log, 3 token levels, **no write tools** | optional | core (+ any module that has data) | `core` | out to the Internet to the provider | `ai_*` | S-AI-1..8 | M6 |
| [`reports`](../modules/reports/CONTRACT.md) | A weekly report, a PDPL report (Law 91/2025/QH15, Decree 356/2025/ND-CP), print/save as PDF | optional | inventory, feeds (+notify to send; scan, logs if present) | `core` | none | `rep_*` | S-REP-1, 2 | M7 |
| `fleet` | ~~A central server for many sites/customers~~ **postponed, not in the GUI** | none | none | none | none | none | S-FLEET-1 `[failed]` | postponed |
| [`mcp-server`](../modules/mcp-server/CONTRACT.md) | A read-only MCP for outside agents/SIEMs (7 tools, tokens scoped to assets/findings/feeds) | optional | core | `core` | HTTP 127.0.0.1:8765 | `mcp_*` | S-MCP-1 | M6 |
| [`auth-oidc`](../modules/auth-oidc/CONTRACT.md) | OIDC/SSO (code + PKCE), maps groups → 3 roles | optional | core | `core` | out to the IdP | `oidc_*` | S-CORE-3 | M7 |

The "Container" column follows the container list in `ARCHITECTURE.md` §2; the group A modules follow that list and may be adjusted in their own `MANIFEST.yaml`, and `MANIFEST.yaml` wins on a difference.

**`host`: a component, not a module.** [`vedette-host`](../modules/host/CONTRACT.md) is a very small systemd process that runs as root and runs only a **fixed command list** (OS updates, network/SPAN/secondary IP, pulling and rolling back cosign-signed images, backups); only `core` can call it, through an internal socket. It is not switched on/off in Settings, it is present on the **Appliance** install type and **absent on the "Container only" type** (features that need it say "not supported"). It has `modules/host/{MANIFEST.yaml,CONTRACT.md,IMPACT.md}` like a module so others can work on it in parallel.

Notes:
- `feeds` also pulls **feeds that need the customer's key** (VulnCheck, AbuseIPDB, VirusTotal, GreyNoise, Shodan, OTX, urlscan, OpenPhish, Censys) directly from the source; each source has its own key field, off by default (`DATA_PIPELINE.md` §BYOK feeds).
- `sensor-*`, `honeypot` and `logs` can run in **sensor** mode separate from the server (`ARCHITECTURE.md` §Sensor/Server).
- The milestone order follows `ROADMAP.md`; **every module has a GUI screen before it has a backend**.
