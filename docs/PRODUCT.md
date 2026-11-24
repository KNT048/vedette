# Vedette: product description

Document version: 2026-11-24 (v1 scope: [ROADMAP.md](ROADMAP.md))

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

In short: edge devices cannot run an EDR, they are exploited faster than they are patched, and an SMB has nobody to read the warnings. The gap: **"what is being exploited" × "do I have it" × "what to do now"**. No free product connects all three.

## 3. Audience

| Persona | Situation | What they need | What they **do not** do |
|---|---|---|---|
| **P1: SMB owner/manager with no IT** (10-100 people) | Has 1 home/SMB firewall, 1 Synology/QNAP NAS, a few old servers, a WordPress site. IT is an outside person or a staff member who does it on the side | To know "is there danger, who to call, what to tell them", in plain language, through a chat app they already use | Does not read dashboards, configure scans, or understand CVEs |
| **P2: one-person IT** (100-500 people) | Manages everything: network, servers, users. Has FortiGate/MikroTik/pfSense, AD, a few web apps, maybe Wazuh/Zabbix | A short list of "what to do this morning", copy-paste configuration, evidence to ask for budget | Has no time to read English advisories, does not write IPS rules |
| **P3: deployment team / MSP** (postponed: multiple sites not supported yet) | Manages 10-200 customers | One place to see many customers, to know which customer is hit by a new KEV, mitigation packs to send to customers, a monthly report | Does not want to sign in to each box |
| **P4: enterprise SOC/IT** (500+ people, with a SOC or an outsourced SOC) | Already has a commercial SIEM/EDR/VM | A cheap extra signal "KEV × inventory", an internal honeypot, API/MCP to pull into the SIEM, SSO/RBAC | Does not replace the SIEM; does not accept an inline box |

Build priority: P2 → P1 → P3 → P4. P2 is the person who will **install and keep** the product; P1 is the person who will **pay for deployment**; P3/P4 are expansion.

## 4. Promises (allowed in marketing; each line traces to a story)

**Know early**
- 24/7 monitoring of the sources of flaws being exploited for real (CISA KEV, VulnCheck KEV with your own free key, the CVE Program, EPSS, the exploitation claims of Microsoft, Cisco, Fortinet, Google and Android, public exploit indexes), the exploited list checked every hour. (S-FEED-1)
- A "hot this week" board: which vendors and devices are hit the most. (S-FEED-2)
- Email, Telegram, Slack, Zalo or webhook alerts, only for devices you have. (S-ALERT-1)

**Know what you have**
- Automatic network inventory: devices, vendor, model, OS, version, open services, with nothing installed on employee machines. (S-INV-1)
- Lists what is exposed to the Internet: domains, subdomains, IPs, ports, admin interfaces. (S-EXP-1)
- Reports a new unknown device when it appears. (S-INV-3)

**Know where you are exposed**
- Vulnerability scans for declared assets (only an IP/domain is needed) or ones the box finds itself; **whenever a new exploited flaw appears, it rescans by itself**. (S-SCAN-1, S-SCAN-2)
- Reports "has the flaw" only when it can be confirmed; clearly separates "confirmed" from "suspected by version". (S-SCAN-3)
- Safe scanning: a speed limit, no dangerous tests, inside an allowed time window. (S-SCAN-4)

**Know what to do**
- For every matching flaw: the right-version patch guidance and a temporary fix; for a growing list of exploited CVEs, a **confirmed recommendation pack** with vendor-specific configuration steps; for the rest, a draft from your own AI, labelled as such. (S-MIT-1)
- Signs to tell whether that flaw has already been exploited on your machine. (S-MIT-3)

**Know when someone gets in**
- An internal honeypot that pretends to be a file/RDP/SSH/SQL server: touching it raises an alert at once, with almost no false alarms. (S-HP-1)
- Receives logs from your existing firewall/servers, compares them with the previous 7 days to point out what is new, and matches them against malicious IP/domain lists updated every hour. (S-LOG-1, S-LOG-2)

**Your own AI assistant**
- Plug in the AI API key you choose (Anthropic, OpenAI, Gemini, or an internal model through Ollama/vLLM). The key stays on your box and goes only to your provider. (S-AI-1)
- Explains what a flaw means for exactly your devices, drafts a mitigation configuration, summarises news and public exploits. (S-AI-2, S-AI-3)
- Reads logs for you at 3 cost levels, within a monthly token budget you set. (S-AI-4)
- A one-page weekly report; a safety assessment report under the Personal Data Protection Law. (S-REP-1, S-REP-2)

**Model**
- Open source, free forever (Apache-2.0). Install it yourself or hire someone to deploy/operate it.
- Your data stays where you are: inventory, logs and AI keys never leave the device. The box sends no anonymous signal or usage data to the Vedette project (the project runs no server that could receive it); every outbound connection is listed in `PRIVACY.md` and can be turned off in Settings → Privacy. (S-CORE-4)
- Any amd64 or arm64 machine with 4 GB of memory (8 GB recommended), not in the network path, can be taken out at any time.

## 5. What we do not do (said plainly to customers)

- Does not replace the firewall, **does not block traffic by itself** (the inline IPS/WAF idea was dropped on 2026-11-06).
- Not an antivirus/EDR; does not back up data.
- No actions taken by the AI on its own: the AI is an adviser, a person clicks.
- Does not sell a feed, does not sell AI, does not charge for the software.
- Does not defend against Zalo/email phishing (the market already has that).

## 6. Deployment forms

v1 ships one form: **one box = server + sensor**, on SQLite, with local users in three roles (viewer, operator, administrator) and
two-step sign-in, installed either as an appliance (`install.sh`, with the system helper `vedette-host`) or as containers only
(`docs/INSTALL-CONTAINER.md`, without the features that need the helper). Every feature comes from **one** codebase with modules
switched on or off, no separate editions.

Later, for larger customers: separate sensors per site or VLAN (the sensor link already uses its own mutual-TLS protocol,
`ARCHITECTURE.md` §6), single sign-on (`auth-oidc`), the MCP server for a SIEM, and response actions. Several sites or customers in one
place (P3) is not planned yet.

## 7. Real differences (against the competitor survey)

1. Connects the LAN inventory with the 7-day hot board, so it alerts only on what you have. Nobody has done that for free.
2. Copy-paste mitigation packs by firewall vendor. Nobody has them, commercial products included.
3. BYOK AI with token levels and a budget, and a data protection report. No OSS has this yet.
4. Rescans on a KEV event (not on a schedule).
5. Honeypot + syslog + inventory in the same box.

Do not say: "the first exploitation feed", "the first AI EASM".

## 8. Name

**Vedette** (chosen 2026-11-06). Checked: there is no security product/repo with the same name. Avoid: Exploit Shield, KEV Watch, PatchWatch, the word "Shield" (CyRadar Internet Shield in VN). Tagline: *Know early. Know exactly. Know what to do.*
