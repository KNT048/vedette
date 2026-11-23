# Data pipeline: the box fetches its own feeds

> **Current model:** each box **pulls and parses by itself** feeds directly from the sources (CISA KEV, FIRST EPSS, NVD, vendor advisories, IOC feeds, the customer's custom feeds). **There is no central builder any more, and no data is distributed through GitHub/Cloudflare.** GitHub now has **one job: publishing signed software updates** (`docs/UPDATES.md`); the confirmed recommendation packs (§5b) ship with that update. Sections 1, 4, 5 below are the old model (2026-11-06), kept for historical reference; sections 2 (sources) and 3 (normalisation, scoring) now run **on the box**.

## 0. The current flow

```
feed sources (cisa.gov, api.first.org, services.nvd.nist.gov, vendor RSS/advisories, abuse.ch..., custom feeds)
     │  the box pulls each feed on a schedule (ETag/If-Modified-Since, size + time limits)
     ▼
the parser on the box (fail closed; field mapping/regex adjusted by the customer for their own feeds)
     ▼
normalise → deduplicate → score (section 3) → feeds_* → match against the device store → findings/alerts
```

- Each feed source is an outbound data flow (only a download request, no customer data is sent) → listed in `PRIVACY.md` and Settings → Privacy; a custom feed the customer adds shows its host name in the same list.
- A source blocked by geography/rate limits: the box backs off and shows the error in Settings → Feeds; the user changes the address to a mirror.

## Old model (2026-11-06, replaced)

The old decision: one builder VM (located in Vietnam) only to **prepare** data; stored on GitHub; distributed through Cloudflare; everything static; no per-customer state.

## 1. Flow

```
source feeds ──► vedette-builder (Go, builder VM; GitHub Actions as a fallback)
                 │ pull (ETag/git pull) → normalise → deduplicate → score → sign
                 ▼
            data repo (an orphan branch `data`, squashed monthly)
            Releases (a daily snapshot, large files)  ·  R2 (files >25 MiB)
                 ▼
            Cloudflare Pages (a static site + small files) + a custom domain
                 ▼
            customer box: GET index.json (ETag, 30-60 minutes) → download the changed parts → verify the signature → write feeds_*
```

Free limits measured 2026-11-06: GitHub Actions is unlimited for a public repo; Releases has no size/bandwidth limit; the repo should stay <1 GB, files >100 MiB are blocked; Pages 500 builds/month, 25 MiB/file, 20k files; R2 10 GB, free egress.

## 2. Sources

### 2a. Flaws being exploited (merged centrally, redistributed)

| Source | How it is pulled | Interval | Licence | Signal |
|---|---|---|---|---|
| CISA KEV | JSON, ETag + If-Modified-Since (304 when unchanged) | 1 hour (default) | CC0 | exploited, ransomware flag, dueDate |
| cisagov/vulnrichment | git | hourly | CC0 | SSVC, CWE, extra CPE |
| CVE.org cvelistV5 | git pull | hourly | public | the fastest record, `affected[]` |
| FIRST EPSS | daily CSV | daily | credit the source | epss, 7-day delta |
| **FIRST EPSS, every CVE (in use, feed `epss-all`)** | the daily gzip CSV file `epss.empiricalsecurity.com`, one conditional GET (~2.8 MB, 406,543 CVEs on 2026-11-14) | daily | credit the source | the score + percentile of every CVE → tier 2 (EPSS ≥ 0.1) |
| nuclei-templates | git log | hourly | MIT | a new template = a check exists; the `kev,vkev` subset goes into the content pack |
| GHSA, OSV | git/API | hourly | CC-BY / Apache | PURL for packages |
| NVD 2.0 | API key | 2 hours | free | extra CPE/CVSS (slow) |
| **NVD 2.0 `?hasKev` (in use, feed `nvd-kev`)** | an API without a key, 100 CVEs/request, 6 s/request; complete the first time (~18 requests, ~19 MB), then `lastModStartDate` | daily (and right after a new KEV CVE) | public domain + the sentence NVD requires | the `vulnerable` CPE entries + version ranges of every CVE in KEV → findings that compare versions |
| **NVD 2.0 CVEs of 12 months (in use, feed `nvd-recent`)** | an API without a key, 1,000 CVEs/request, 6 s/request; the first time by a 120-day `pubStartDate` window (~105 requests, ~60 MB, ~25 minutes, split over several pulls with a cursor), then `lastModStartDate` (~2 requests/day) | daily | public domain + the sentence NVD requires | the date, status, CVSS level and `vulnerable` CPE entries of every CVE published in 12 months → tier 3 |
| PSIRT: MSRC CSAF, Cisco openVuln, Fortinet RSS, Synology RSS, PAN CSAF, QNAP/Ivanti RSS | poll | hourly | free | "exploited in the wild" earlier than KEV |
| NCSC VN (alert.khonggianmang.vn), chongluadao | HTML, **needs a VN IP** | weekly/daily | none | Vietnam context |
| VulnCheck KEV Community | the **project's** API key | hourly | ⚠ redistribution not confirmed → for now the box pulls it with the customer's key | earlier than CISA, canary, PoC |

### 2b. IOC (merged centrally, redistributed)

Spamhaus DROP (⚠ ask about embedding), ET Open block/compromised (BSD), IPsum level≥3 (Unlicense), hagezi TIF mini/medium (GPL-3, with its licence), Tor exit, Cymru bogons, CINS/Blocklist.de/GreenSnow (inbound direction), abuse.ch Feodo (CC0), Phishing.Database (MIT), a whitelist of Umbrella top-1M + Majestic + the AWS/Google/Azure/Cloudflare cloud ranges + the VN ISP ranges (APNIC delegated).

### 2c. BYOK feeds (the box pulls with the customer's key, not through the central side)

VulnCheck Community, AbuseIPDB, VirusTotal, GreyNoise, Shodan, OTX, urlscan, OpenPhish, Censys, abuse.ch ThreatFox/URLhaus (Auth-Key). Each source: a key field, a test button, a request limit, off by default.

## 3. Normalisation and scoring

- Key: CVE → (vendor, product, version_ranges) from the CNA `affected[]` + NVD CPE + PURL; the `vendor_product_slug` table maps CPE vendor ↔ PSIRT name ↔ Nuclei tag ↔ the Vietnamese commercial name (for example "Synology DSM").
- `hot_score(vendor,product,7d) = w1·new KEV + w2·VulnCheck/canary + w3·max ΔEPSS + w4·Nuclei commits + w5·exploited sightings + w6·PSIRT says exploited + w7·hits from the fleet (opt-in)`, multiplied by a VN exposure factor (the anonymous fleet inventory, if any).
- IOC: `score = Σ source_weight × e^(−age/τ)`; τ is 7 days for scanners, 30 days for C2/phish, ∞ for DROP; `block` when ≥2 independent sources or 1 source of DROP/CC0 grade; `alert` when 1 source; minus the whitelist **by domain** (not by CDN IP); never a /24.
- The Vietnamese sentence for S-FEED-2 is generated from a template (no AI needed): "`<Product>` `<version>` is being exploited by `<group/ransomware>` (KEV `<date>`). If you use it: `<short action>`."

## 4. Distribution format

```
index.json            { generated_at, builder_version, files: [{path, sha256, size, kind, since}], revoked: [...], signature }
feeds/vulns.json      feeds_vuln records (zstd compressed, daily delta versions)
feeds/hot.json        the 7-day hot board + the Vietnamese sentence
feeds/ioc/block-ip.txt (≤50k), alert-ip.txt, domains-mini.txt, domains-medium.txt, ja3.txt
feeds/slug.json       vendor_product_slug
content-packs/<name>-<ver>.tar.zst   skill, mitigation pack, nuclei subset, recog DB, parser log, rule pack
```

- Signed with **minisign** (the private key only on the builder VM, with a YubiKey as a fallback); the public key is in the Vedette source; `revoked[]` withdraws a bad bundle.
- The box: `If-None-Match`; downloads files whose sha256 changed; verifies the signature before writing; keeps the previous version for rollback.

## 5. Builder

- `cmd/vedette-builder` (Go, the same code repo): `fetch` → `normalize` → `score` → `render` → `sign` → `publish`. Each step is idempotent and writes `build.log` + metrics into `status.json` (public: the last run, which sources failed).
- Runs on the builder VM (cron every 30 minutes, a VN IP for geo-fenced sources) **and** on GitHub Actions (cron every 60 minutes, publishes only when the VM is more than 3 hours late); both places share the public key but have different private keys (`builder-vn`, `builder-gh`), and both are in the box's trust list.
- The public web = static Pages: the hot board, CVE/IP/domain lookup, the pipeline status. No server, no accounts.

## 5b. Mitigation recommendations: drafted with AI by the project, confirmed by a maintainer through GitHub (S-MIT-4). Still applies; since the central builder was dropped, confirmed packs ship with the **signed software update**, not through the builder

```
new KEV (high hot_score, no pack yet) ─► vedette-author draft <CVE>   (CLI, the project's AI key, the mitigation-config skill)
   │  gathers KEV + cvelist + vendor advisories (public data) → content/mitigation/<CVE>.yaml  status: draft
   ▼
a maintainer edits, sets confirmed_by / confirmed_at, status: confirmed → PR → CODEOWNERS approve → merge
   ▼
release: accepts only status: confirmed → packed into the signed update (GitHub Releases) → the customer box
```

- A pack records `drafted_with` (the model), `confirmed_by`, `confirmed_at`, `sources[]`; the UI shows "Confirmed by Vedette, drafted with AI".
- On the box: a CVE with no confirmed pack → "No confirmed recommendation yet" + the original information + "Ask my AI" (the `mitigation-config` skill runs with the customer's key, labelled "AI generated").
- No customer data is in this flow; `PRIVACY.md` does not change.
- Simplest option: `content/` in the code repo + CODEOWNERS; upgrade: split out a vedette-content repo when content PRs become numerous.

## 6. Decisions

1. **No** shared Vedette instance is hosted. The central side is static data only; customers host it themselves or hire someone to deploy their own instance. Review when the project grows well.
2. **The anonymous fleet signal: on by default**, can be turned off with one click. Every hour the box sends to `telemetry.vedette.<domain>` (a small service of the project, not through GitHub) a package with **no customer name, no internal IP, no raw logs**:
   ```json
   {"install_id": "<a random sha256 made at install>", "country": "VN", "version": "1.2.0",
    "hits": [{"kind": "honeypot/smb", "count": 1}, {"kind": "ioc/ip", "count": 3}, {"kind": "suricata/CVE-2026-109618", "count": 7}],
    "inventory_counts": {"synology:dsm:7.1": 12, "fortinet:fortios:7.2": 1}}
   ```
   Used for: the "being hit in VN" column on the hot board; the `hot_score` weights by what VN SMBs really use; detecting a bad data rollout by cohort. The exact payload is shown in Settings → Share signal; the README and `PRIVACY.md` state it plainly. The central side keeps **aggregates** and deletes raw records after 30 days.
3. Spamhaus DROP/CINS/ThreatView: the central side or the box pulls them: waiting for Spamhaus to answer.
