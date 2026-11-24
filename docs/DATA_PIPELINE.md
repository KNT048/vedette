# Data pipeline: the box fetches its own feeds

Each box pulls every feed **directly from its publisher**, parses it on the box and keeps one vulnerability catalogue plus the signals
that make a CVE urgent. No feed data goes through the project's repository or a server of the project: there is none. GitHub has one
job, publishing signed software updates ([UPDATES.md](UPDATES.md)), and the confirmed recommendation packs ship inside them (§4).
The rules the code holds to are in [`modules/feeds/CONTRACT.md`](../modules/feeds/CONTRACT.md); every host a pull reaches, and what it
sends, is flow 1 of [PRIVACY.md](../PRIVACY.md).

## 1. The flow

```
publishers (cisa.gov, NVD, the CVE Program, FIRST, Canonical, Debian, OSV.dev, vendor advisories, exploit indexes, indicator lists, custom feeds)
     │  a GET of each feed on its schedule (conditional on ETag / Last-Modified where the source supports it; size, row and time limits)
     ▼
parser on the box (fails closed: a bad row is dropped and counted by reason, never stored)
     ▼
catalogue: CVEs, affected ranges by origin, exploited-list entries, signals, indicators  (feeds_* tables)
     ▼
inventory and findings: match against the devices the box knows → findings → alerts (notify)
```

- A pull sends no customer data: only the request a public file needs, with `User-Agent: Vedette/<version>`.
- A pull never connects to Vedette itself, to link-local or to cloud metadata addresses; redirects stay on the same host.
- A failing pull records its error, backs off (5 minutes, doubling, never past the feed's interval) and shows the error in
  Settings → Feeds. A built-in feed cannot be deleted, only switched off or pointed at a mirror.
- A new box loads older exploitation claims from the seed shipped in the release (`content/signals/seed.json`) without a request.

## 2. Built-in sources

The list is `builtinSources` in [`modules/feeds/sources.go`](../modules/feeds/sources.go); this table follows it.

### Vulnerabilities and fixed versions

| Feed | Source | Interval | What the box keeps |
|---|---|---|---|
| CISA KEV | `www.cisa.gov`, and CISA's GitHub copy of the same file (the newer plausible list wins) | 1 hour | the exploited list: CVE, product, date added, ransomware use, required action |
| EPSS, every CVE | FIRST's daily file on `epss.empiricalsecurity.com` | daily | the score and percentile of every CVE (an EPSS of 10 % or more marks a recommended update as likely to be exploited) |
| NVD affected versions | NVD CVE API 2.0, `?hasKev` | daily | affected CPE entries and version ranges of the exploited CVEs |
| NVD, CVEs of the last 12 months | NVD CVE API 2.0, by publication and change date | daily | date, status, CVSS and affected ranges of recent CVEs |
| CVE records | the CVE Program's `CVEProject/cvelistV5` on GitHub: the whole list once, then the daily change files | 1 hour | vendor (CNA and ADP) affected ranges, descriptions, references |
| VulnCheck KEV | `api.vulncheck.com`, only with the customer's own free key (off until then) | 6 hours | a second exploited list, shown as "VulnCheck KEV" |
| Ubuntu fixed versions, Ubuntu not affected | Canonical's OSV and VEX files | daily | fixed package versions per Ubuntu release (backports) |
| Debian security tracker | `security-tracker.debian.org` | daily | fixed package versions per Debian release |
| Alpine fixed versions | OSV.dev's Alpine file, only while a device states Alpine Linux | daily | fixed package releases per Alpine release |
| Windows releases | Microsoft's Windows release information pages | daily | builds, dates and monthly security updates of Windows 10, 11 and Server |

After its first fill, a distribution feed is pulled only while a device runs that distribution.

### Signals: public exploits and vendors' word on exploitation (facts only, never exploit code)

| Feed | Source | Interval |
|---|---|---|
| nuclei-templates | ProjectDiscovery's CVE list on GitHub (a check exists) | daily |
| Metasploit modules, Exploit-DB, PoC-in-GitHub | the public indexes of each (date, link, and for GitHub proofs of concept star and author counts) | daily |
| Microsoft exploited CVEs | MSRC Security Update Guide, "Exploited: Yes" | 6 hours |
| Cisco and Fortinet PSIRT advisories | the vendors' advisory feeds and CSAF documents | 6 hours |
| Chrome Releases, Android Security Bulletins, Rapid7 blog, Google Threat Intelligence blog | the publishers' feeds and bulletin pages (date and link of the claim, never the text) | 6 hours |

Apple's word on exploitation is read from the descriptions of Apple's CVE records the box already holds, with no request of its own.

### Indicators (known-bad addresses and domains)

| Feed | Source | Interval |
|---|---|---|
| IPsum (level 3) | `stamparm/ipsum` on GitHub | 6 hours |
| ET Open compromised IPs | `rules.emergingthreats.net` | 6 hours |
| abuse.ch Feodo Tracker | `feodotracker.abuse.ch` | 6 hours |
| Tor exit list | `check.torproject.org` (informational) | 6 hours |
| hagezi TIF (mini) | `hagezi/dns-blocklists` on GitHub, unmodified | 6 hours |

Indicators are matched against what the logs and the mirror port see; Vedette alerts and never blocks traffic.

### Custom feeds

An administrator can add a feed of their own in Settings → Feeds: JSON, CSV, RSS, STIX or one entry per line, with a field mapping
tested on a sample before saving (`POST /feeds/parse-test` writes nothing and calls nothing). The same limits apply: `https` (plain
`http` only to an internal host), 5,000,000 bytes, 50,000 rows and 60 seconds a pull.

## 3. What the catalogue keeps

- A CVE stays while it was published in the last 365 days, has an exploited-list entry or a qualifying signal, or an open finding
  pins it. Pulls store only what this rule keeps.
- Affected ranges are kept per origin (NVD, the CNA, ADP); NVD's rows win when read, and a vendor row that no version scheme can order
  is shown, never matched.
- A distribution's own fixed version (Ubuntu, Debian, Alpine) decides a package on that distribution; without it the upstream ranges
  apply.
- Urgency comes from these facts: under attack (an IDS hit on the device), exploited (on an exploited list or a vendor's claim),
  public exploit, critical on an edge device, then update recommended. See `modules/findings/CONTRACT.md`.
- **Display names**: a vendor and product pair of the exploited list is shown by the name a person recognises ("Synology NAS (DSM)"),
  from `displaySlugs` in `modules/feeds/display.go`; a pair not listed reads "Vendor Product".
- **Indicator verdict** (`Judge` in `modules/feeds/verdict.go`, computed on read): a whitelisted domain, or a value that is not a public
  IP address or domain, gets no verdict; otherwise `block` for two independent sources or one block-class source, `alert` below that.
  An informational source (the Tor exit list) never counts toward `block`, and an aggregate list (IPsum) never blocks alone. `block`
  is a confidence level for alerts and for the firewall block list a person chooses to publish; Vedette itself blocks nothing.

## 4. Confirmed recommendation packs

A recommendation pack is the "What to do" of a CVE: the fix, a workaround and vendor-specific mitigation steps. Packs live in
[`content/mitigation/packs/`](../content/mitigation/packs/) as one JSON file per CVE.

1. A pack starts as a draft: research from public sources (the exploited-list entry, the CVE record, vendor advisories), every step
   cited in `sources`; how it was drafted is recorded in `drafted_with`.
2. A maintainer checks every step, sets `status: confirmed`, `confirmed_by` and `confirmed_at`, and merges it through a reviewed pull
   request.
3. The release accepts only confirmed packs; they ship inside the signed software update.

On the box, a CVE with a confirmed pack shows it as "Confirmed by Vedette". A CVE without one shows "No confirmed recommendation yet",
the original information, and, when the `ai` module is on, "Ask my AI" (the `mitigation-config` job with the customer's own key,
labelled AI-generated). No customer data is in this flow.
