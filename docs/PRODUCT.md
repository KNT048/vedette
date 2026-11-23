# Vedette: product description

Document version: 2026-11-06

## 1. In one sentence

Free, open-source software that tells a business **within 1 hour** if a device/software it uses is on the list of flaws **being exploited by attackers for real**, shows what it **has** and **where it is exposed**, and hands over a ready **way to fix it**, without getting in the way of the network.

## 2. The problem (measurable)

| Fact | Source |
|---|---|
| Exploiting a vulnerability is the number 1 intrusion vector (31%), ahead of credentials for the first time | Verizon DBIR 2026 |
| Only 26% of the flaws in CISA KEV are fully patched; median 43 days | DBIR 2026 |
| 29% of exploitation happens before/on the day a CVE is published; 36% targets a CVE more than 1 year old | VulnCheck 2026 |
| The most targeted class: network edge devices (firewall/VPN/NAS), then CMS | VulnCheck 2026, DBIR 2025 |
| Companies of 100-250 people stop only 34% of ransomware attacks before encryption | Sophos 2026 |
| Time from intrusion to hand-over to a ransomware group: 22 seconds | Mandiant M-Trends 2026 |
| VN: 52.3% of organisations suffered damage; 47.7% have no security staff; >50% have no central anti-malware | NCA 2025 (5,300 organisations) |
| VN: the Personal Data Protection Law 91/2025 (1/1/2026) fines up to 5% of revenue; Decrees 330/2026 and 363/2026 have specific fine schedules | thuvienphapluat, PwC |

In short: edge devices cannot run an EDR, they are exploited faster than they are patched, and an SMB has nobody to read the warnings. The gap: **"what is being exploited" × "do I have it" × "what to do now"**. No free product connects all three (competitor survey: §12).

## 3. Audience

| Persona | Situation | What they need | What they **do not** do |
|---|---|---|---|
| **P1: SMB owner/manager with no IT** (10-100 people) | Has 1 home/SMB firewall, 1 Synology/QNAP NAS, a few old servers, a WordPress site. IT is an outside person or a staff member who does it on the side | To know "is there danger, who to call, what to tell them", in Vietnamese, through Zalo | Does not read dashboards, configure scans, or understand CVEs |
| **P2: one-person IT** (100-500 people) | Manages everything: network, servers, users. Has FortiGate/MikroTik/pfSense, AD, a few web apps, maybe Wazuh/Zabbix | A short list of "what to do this morning", copy-paste configuration, evidence to ask for budget | Has no time to read English advisories, does not write IPS rules |
| **P3: deployment team / MSP** (postponed: multiple sites not supported yet) | Manages 10-200 customers | One place to see many customers, to know which customer is hit by a new KEV, mitigation packs to send to customers, a monthly report | Does not want to sign in to each box |
| **P4: enterprise SOC/IT** (500+ people, with a SOC or an outsourced SOC) | Already has a commercial SIEM/EDR/VM | A cheap extra signal "KEV × inventory", an internal honeypot, API/MCP to pull into the SIEM, SSO/RBAC | Does not replace the SIEM; does not accept an inline box |

Build priority: P2 → P1 → P3 → P4. P2 is the person who will **install and keep** the product; P1 is the person who will **pay for deployment**; P3/P4 are expansion.

## 4. Promises (allowed in marketing; each line traces to a story)

**Know early**
- 24/7 monitoring of the sources of flaws being exploited for real (CISA KEV, VulnCheck KEV, CVE.org, EPSS, PSIRTs of Microsoft/Fortinet/Synology/Cisco...), updated every hour. (S-FEED-1)
- A "hot this week" board: which vendors/devices are hit the most, worldwide and in Vietnam. (S-FEED-2)
- Zalo/Telegram/email alerts only for devices you have. (S-ALERT-1)

**Know what you have**
- Automatic network inventory: devices, vendor, model, OS, version, open services, with nothing installed on employee machines. (S-INV-1)
- Lists what is exposed to the Internet: domains, subdomains, IPs, ports, admin interfaces. (S-EXP-1)
- Reports a new unknown device when it appears. (S-INV-3)

**Know where you are exposed**
- Vulnerability scans for declared assets (only an IP/domain is needed) or ones the box finds itself; **whenever a new exploited flaw appears, it rescans by itself**. (S-SCAN-1, S-SCAN-2)
- Reports "has the flaw" only when it can be confirmed; clearly separates "confirmed" from "suspected by version". (S-SCAN-3)
- Safe scanning: a speed limit, no dangerous tests, inside an allowed time window. (S-SCAN-4)

**Know what to do**
- For every matching flaw: the right-version patch guidance, a temporary fix, and a **ready configuration snippet** for the firewall you have (FortiGate, MikroTik, pfSense/OPNsense, Sophos, Cisco, Windows Firewall, Synology/QNAP). (S-MIT-1)
- Signs to tell whether that flaw has already been exploited on your machine. (S-MIT-3)

**Know when someone gets in**
- An internal honeypot that pretends to be a file/RDP/SSH/SQL server: touching it raises an alert at once, with almost no false alarms. (S-HP-1)
- Receives logs from your existing firewall/servers, compares them with the previous 7 days to point out what is new, and matches them against malicious IP/domain lists updated every hour. (S-LOG-1, S-LOG-2)

**Your own AI assistant**
- Plug in the AI API key you choose (Anthropic, OpenAI, Gemini, or an internal model through Ollama/vLLM). The key stays on your device. (S-AI-1)
- Explains in Vietnamese what a flaw means for exactly your devices, writes a mitigation configuration, summarises news/PoCs. (S-AI-2, S-AI-3)
- Reads logs for you at 3 cost levels; a token gauge and a daily cap. (S-AI-4)
- A one-page weekly report; a safety assessment report under the Personal Data Protection Law. (S-REP-1, S-REP-2)

**Mô hình**
- Open source, free forever (Apache-2.0). Install it yourself or hire someone to deploy/operate it.
- Your data stays where you are: inventory, logs and AI keys never leave the device. The only thing sent out is an **anonymous signal** (the number of times a trap was touched, the number of connections to IOCs, counts by device type) so the hot board can have a Vietnam column; this is stated in `PRIVACY.md` and can be turned off with one click. (S-CORE-4)
- Any x86 machine (4 cores, 8 GB), not in the network path, can be taken out at any time.

## 5. What we do not do (said plainly to customers)

- Does not replace the firewall, **does not block traffic by itself** (the inline IPS/WAF idea was dropped on 2026-11-06).
- Not an antivirus/EDR; does not back up data.
- No actions taken by the AI on its own: the AI is an adviser, a person clicks.
- Does not sell a feed, does not sell AI, does not charge for the software.
- Does not defend against Zalo/email phishing (the market already has that).

## 6. Release forms (editions = the same binary, different configuration)

| | SMB | Mid | Enterprise/MSP |
|---|---|---|---|
| Deployment | 1 box = server + sensor | 1 server + 1-5 sensors (one per site/VLAN) | 1 central server + many sensors; or 1 server per customer + an MSP overview |
| DB | SQLite | SQLite or PostgreSQL | PostgreSQL |
| Sign-in | Local user | Local + 3-role RBAC | OIDC/SSO + RBAC + audit |
| Integrations | Zalo/Telegram/email | + webhook, syslog out | + API/MCP, SIEM forward, multi-tenant |
| AI | BYOK | BYOK | BYOK or an internal gateway |

All from **one** codebase, modules switched on/off, no separate branches. Sensor/server can be separated from day one (`ARCHITECTURE.md` §Sensor/Server) so Mid/Enterprise can use it early.

## 7. Real differences (against the competitor survey)

1. Connects the LAN inventory with the 7-day hot board, so it alerts only on what you have. Nobody has done that for free.
2. Copy-paste mitigation packs by firewall vendor. Nobody has them, commercial products included.
3. BYOK AI in Vietnamese, 3 token levels, a PDPL report. No OSS has this yet.
4. Rescans on a KEV event (not on a schedule).
5. Honeypot + syslog + inventory in the same box.

Do not say: "the first exploitation feed", "the first AI EASM".

## 8. Tên

**Vedette** (chosen 2026-11-06). Checked: there is no security product/repo with the same name. Avoid: Exploit Shield, KEV Watch, PatchWatch, the word "Shield" (CyRadar Internet Shield in VN). Vietnamese tagline: *Know early. Know clearly. Know what to do.*
