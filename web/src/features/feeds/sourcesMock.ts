// Mock API for feed sources and custom parsing (S-FEED-4, S-FEED-5). The parser is real (parsers.ts), the network is not:
// "fetching" a feed reads the built-in sample of its format, so Fetch now and Test show what the rules would do.
import { http, HttpResponse } from 'msw'
import kev from '@/mocks/fixtures/kev.json'
import { API, audit, body, fail, guard } from '@/mocks/http'
import { collection, newId, nowIso } from '@/mocks/db'
import { tierState } from '@/mocks/tiers'
import { fmtNumber } from '@/lib/format'
import { FeedInput as FeedInputSchema, FeedPatch as FeedPatchSchema, ParseTestInput } from './contract'
import { BLOCKED_TEXT, blockedFeedHost, OWN_TEXT, checkFeedUrl, defaultParser, FORMATS, PREVIEW_ROWS, sameFeedAddress } from './defaults'
import { checkParser, ParserConfigError, parseFeed } from './parsers'
import { sampleFor } from './samples'
import type { Feed, FeedFormat, FeedStatus, FeedKind, ParseResult } from './types'

interface Def { id: string; name: string; kind: FeedKind; format: FeedFormat; url: string; license: string; records: number }
// Only sources already listed in THIRD_PARTY_NOTICES.md / PRIVACY.md (no new third parties).
const DEFS: Def[] = [
  { id: 'cisa-kev', name: 'CISA KEV', kind: 'vulnerabilities', format: 'json', url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', license: 'CC0', records: (kev as { vulns: unknown[] }).vulns.length },
  // The data of CVE tiers 2 and 3: every CVE's EPSS score, and NVD's records of the CVEs of the last 12 months
  { id: 'epss-all', name: 'EPSS, every CVE', kind: 'vulnerabilities', format: 'csv', url: 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz', license: 'Attribution: EPSS by FIRST', records: 406543 },
  { id: 'nvd-kev', name: 'NVD affected versions', kind: 'vulnerabilities', format: 'json', url: 'https://services.nvd.nist.gov/rest/json/cves/2.0', license: 'Public domain. This product uses the NVD API but is not endorsed or certified by the NVD.', records: 1779 },
  { id: 'nvd-recent', name: 'NVD, CVEs of the last 12 months', kind: 'vulnerabilities', format: 'json', url: 'https://services.nvd.nist.gov/rest/json/cves/2.0', license: 'Public domain. This product uses the NVD API but is not endorsed or certified by the NVD.', records: 104135 },
  { id: 'cve-org', name: 'CVE records', kind: 'vulnerabilities', format: 'json', url: 'https://github.com/CVEProject/cvelistV5', license: 'CVE Program Terms of Use. CVE records © The MITRE Corporation.', records: 107276 },
  { id: 'vulncheck-kev', name: 'VulnCheck KEV', kind: 'vulnerabilities', format: 'json', url: 'https://api.vulncheck.com/v3/index/vulncheck-kev', license: 'VulnCheck Known Exploited Vulnerabilities (VulnCheck KEV), used with your own free VulnCheck Community key. Data stays on this box.', records: 37 },
  // Ubuntu and Debian say which package version fixes a CVE (backports); each file covers every release
  { id: 'ubuntu-osv', name: 'Ubuntu fixed versions', kind: 'vulnerabilities', format: 'json', url: 'https://security-metadata.canonical.com/osv/osv-all.tar.xz', license: 'CC BY-SA 4.0, Canonical Ltd. Ubuntu security data.', records: 2131 },
  { id: 'ubuntu-vex', name: 'Ubuntu not affected', kind: 'vulnerabilities', format: 'json', url: 'https://security-metadata.canonical.com/vex/vex-all.tar.xz', license: 'CC BY-SA 4.0, Canonical Ltd. Ubuntu security data.', records: 3294 },
  { id: 'debian-tracker', name: 'Debian security tracker', kind: 'vulnerabilities', format: 'json', url: 'https://security-tracker.debian.org/tracker/data/json', license: 'Debian Security Tracker data; no licence stated. Attributed, not redistributed.', records: 899 },
  // Alpine says which apk release fixes an exploited CVE, per branch (OSV.dev's conversion of Alpine's secdb); fetched only while a device states Alpine
  { id: 'alpine-osv', name: 'Alpine fixed versions', kind: 'vulnerabilities', format: 'json', url: 'https://osv-vulnerabilities.storage.googleapis.com/Alpine/all.zip', license: 'CC BY-SA 4.0, Alpine Linux security database, converted by OSV.dev.', records: 1472 },
  { id: 'windows-releases', name: 'Windows releases', kind: 'vulnerabilities', format: 'lines', url: 'https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information', license: "Facts from Microsoft's public Windows release information pages, Microsoft Terms of Use. Not endorsed by Microsoft.", records: 6 },
  { id: 'nuclei-templates', name: 'nuclei-templates', kind: 'vulnerabilities', format: 'json', url: 'https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json', license: 'MIT', records: 3920 },
  // Public-exploit indexes: facts only (CVE id, date, link, star and author counts), never exploit code
  { id: 'metasploit', name: 'Metasploit modules', kind: 'vulnerabilities', format: 'json', url: 'https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json', license: 'BSD-3-Clause, Rapid7 metasploit-framework module metadata. Facts only; no module code is fetched.', records: 3215 },
  { id: 'exploit-db', name: 'Exploit-DB', kind: 'vulnerabilities', format: 'csv', url: 'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv', license: 'GPL-2.0, OffSec exploitdb repository index. Facts only; no exploit file is fetched.', records: 25094 },
  { id: 'poc-in-github', name: 'PoC-in-GitHub', kind: 'vulnerabilities', format: 'json', url: 'https://codeload.github.com/nomi-sec/PoC-in-GitHub/tar.gz/refs/heads/master', license: 'CC0, nomi-sec PoC-in-GitHub index. Facts only; no repository is fetched.', records: 11875 },
  // Vendor exploitation claims: facts only (CVE id, date of the claim, advisory link)
  { id: 'msrc', name: 'Microsoft exploited CVEs', kind: 'vulnerabilities', format: 'json', url: "https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability?$filter=exploited%20eq%20%27Yes%27", license: "Facts from Microsoft's Security Update Guide (the Exploited flag), Microsoft Terms of Use. Not endorsed by Microsoft.", records: 191 },
  { id: 'cisco-psirt', name: 'Cisco PSIRT advisories', kind: 'vulnerabilities', format: 'rss', url: 'https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml', license: "Facts from Cisco's public security advisories (CSAF), Cisco Terms of Use. Each claim links its advisory.", records: 3 },
  { id: 'fortinet-psirt', name: 'Fortinet PSIRT advisories', kind: 'vulnerabilities', format: 'rss', url: 'https://filestore.fortinet.com/fortiguard/rss/ir.xml', license: "Facts from Fortinet's public PSIRT advisories (CSAF), Fortinet Terms of Use. Each claim links its advisory.", records: 1 },
  // Exploitation claims in prose: facts only (CVE id, date of the post or bulletin, link)
  { id: 'chrome-releases', name: 'Chrome Releases', kind: 'vulnerabilities', format: 'rss', url: 'https://chromereleases.googleblog.com/feeds/posts/default?redirect=false', license: "Facts from Google's Chrome Releases blog (its Atom feed), Google Terms of Service. Each claim links its post.", records: 10 },
  { id: 'android-bulletin', name: 'Android Security Bulletins', kind: 'vulnerabilities', format: 'lines', url: 'https://source.android.com/docs/security/bulletin/', license: 'Facts from the Android Security Bulletins (source.android.com, content under CC BY 4.0). Each claim links its bulletin.', records: 4 },
  { id: 'rapid7-blog', name: 'Rapid7 blog', kind: 'vulnerabilities', format: 'rss', url: 'https://www.rapid7.com/rss.xml', license: "Facts from Rapid7's blog (its RSS feed), Rapid7 website terms of use. Each claim links its post; no text is kept.", records: 5 },
  { id: 'gti-blog', name: 'Google Threat Intelligence blog', kind: 'vulnerabilities', format: 'rss', url: 'https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/', license: "Facts from Google Threat Intelligence's blog (its RSS feed), Google Terms of Service. Each claim links its post; no text is kept.", records: 5 },
  { id: 'ipsum', name: 'IPsum', kind: 'ioc', format: 'lines', url: 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt', license: 'Unlicense', records: 41230 },
  { id: 'et-open', name: 'ET Open compromised IPs', kind: 'ioc', format: 'lines', url: 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt', license: 'BSD', records: 1480 },
  { id: 'abusech-feodo', name: 'abuse.ch Feodo Tracker', kind: 'ioc', format: 'lines', url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt', license: 'CC0', records: 212 },
  { id: 'tor-exit', name: 'Tor exit list', kind: 'ioc', format: 'lines', url: 'https://check.torproject.org/torbulkexitlist', license: 'Attribution: torproject', records: 1190 },
  { id: 'hagezi-tif', name: 'hagezi TIF', kind: 'ioc', format: 'lines', url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt', license: 'GPL-3.0, unmodified', records: 438900 },
]

interface BuiltinState { key_last4?: string | null; enabled: boolean; interval_hours: number; url: string; last_fetch: string | null; last_success?: string | null; records: number | null; status: 'ok' | 'error' | 'never'; error: string | null }
interface Config { builtin: Record<string, BuiltinState>; custom: Feed[] }

// The built-in feed that needs the customer's own API key: off until one is saved.
const BYOK = 'vulncheck-kev'
// Every other built-in feed, the tier feeds epss-all and nvd-recent included, is on by default.
const ago = (h: number) => new Date(Date.now() - h * 36e5).toISOString()
/** LEAN: the mock inventory has Ubuntu devices and no Debian one, so the Debian tracker, filled once 9 days ago, is not
 * updated and says why. A clean box has never filled it, so it is fetched like any other feed. */
const IDLE = 'debian-tracker'
const NO_DEBIAN = 'Not updated: no Debian device now. Vedette updates it on the next check after an agent reports the packages of a Debian device.'
/** As modules/feeds heldNotes: the feeds whose count can be 0 on a healthy box, or counts something else than the name says, say
 * what they hold on every good pull. */
const HELD: Record<string, string> = {
  'nvd-kev': "NVD records of 1,779 exploited CVEs; 1,702 of them name affected versions.",
  'cve-org': '107,276 of 107,715 catalogue CVEs have their record read; 60,940 without affected versions from NVD, 33,512 of them with versions from the record. Exploited: 77 without affected versions from NVD, 41 of them with versions from the record.',
  'ubuntu-osv': 'Counts one record per package, release and CVE: 312 exploited CVEs and 1,204 other CVEs of the packages your devices run.',
  'ubuntu-vex': 'Counts one record per package, release and CVE: 401 exploited CVEs.',
  'alpine-osv': 'Counts one record per package, release and CVE: 288 exploited CVEs.',
  'windows-releases': "6 Windows releases on Microsoft's release information pages, with 412 monthly updates, the newest of 11 Nov 2026.",
}
const seedBuiltin = (clean: boolean): Record<string, BuiltinState> => Object.fromEntries(DEFS.map((d, i) => [d.id, {
  enabled: d.id !== BYOK, interval_hours: d.kind === 'ioc' || d.id === BYOK ? 6 : d.id === 'cisa-kev' || d.id === 'cve-org' ? 1 : 24, url: d.url,
  ...(clean || d.id === BYOK
    ? { last_fetch: null, records: null, status: 'never' as const, error: null }
    : { last_fetch: ago(d.id === IDLE ? 9 * 24 : 1 + i * 0.7), records: d.records, status: 'ok' as const, error: d.id === IDLE ? NO_DEBIAN : HELD[d.id] ?? null }),
}]))

function seedCustom(): Feed[] {
  const parser = defaultParser('ioc', 'csv')
  const out = parseFeed(sampleFor('ioc', 'csv')!.text, 'ioc', parser)
  return [{
    id: 'cf-watchlist', builtin: false, name: 'Botnet C2 blocklist (partner)', kind: 'ioc', format: 'csv', url: 'https://threat-share.example.net/c2-blocklist.csv', default_url: null, enabled: true, interval_hours: 6,
    auth: { type: 'bearer', header_name: null, username: null, secret_last4: 'x7Qk' }, parser, last_fetch: ago(2), records: out.accepted, status: 'ok', error: null, license: null, answered_by: null,
  }]
}
const config = collection<Config>('feeds_config', () => ({ builtin: seedBuiltin(false), custom: seedCustom() }), () => ({ builtin: seedBuiltin(true), custom: [] }))

const builtinFeed = (d: Def, s: BuiltinState): Feed => ({
  id: d.id, builtin: true, name: d.name, kind: d.kind, format: d.format, url: s.url, default_url: d.url, enabled: s.enabled, interval_hours: s.interval_hours,
  auth: { type: s.key_last4 ? 'bearer' : 'none', header_name: null, username: null, secret_last4: s.key_last4 ?? null }, parser: null, last_fetch: s.last_fetch, records: s.records, status: s.status, error: s.error, license: d.license, answered_by: d.id === 'cisa-kev' && s.last_fetch ? 'CISA' : null,
})
/** What Home needs to know about the CISA list: turned off, loaded at least once, or never loaded (with the last error). */
/** As modules/feeds FeedsGetFeedsStatus: the state, why the last pull failed (also once loaded), how often, when last asked and loaded. */
export function kevStatus(): FeedStatus['kev'] {
  const s = config.get().builtin['cisa-kev']
  const last_success = s ? (s.last_success !== undefined ? s.last_success : s.status === 'ok' ? s.last_fetch : null) : null
  // the mock's CISA list always comes from cisa.gov (builtinFeed) and does not model the two copies
  const times = { interval_hours: s?.interval_hours ?? 1, checked_at: s?.last_fetch ?? null, last_success, answered_by: last_success ? 'CISA' : null, copies: [] }
  if (s && !s.enabled) return { state: 'off', error: null, ...times }
  const error = s?.status === 'error' ? s.error : null
  if (!s || s.records === null) return { state: 'never_loaded', error: error ?? s?.error ?? null, ...times }
  return { state: 'loaded', error, ...times }
}
/** Whether the feed with this id is switched on (built-in or custom): what a lookup of an indicator may name (POST-4). */
export const feedOn = (id: string) => allFeeds(config.get()).some((f) => f.id === id && f.enabled)
// Like feeds.Store.IOCListed: a switched-on IOC feed has loaded indicators (logs' digest says when nothing can be matched).
export const iocListed = () => allFeeds(config.get()).some((f) => f.kind === 'ioc' && f.enabled && (f.records ?? 0) > 0)
const allFeeds = (c: Config): Feed[] => [...DEFS.map((d) => builtinFeed(d, c.builtin[d.id] ?? seedBuiltin(false)[d.id]!)), ...c.custom]
const hostOf = (u: string) => { try { return new URL(u).hostname } catch { return '' } }
// Like modules/feeds mostOften: the most common reason with one of its rows' value shown, not the masked "…".
const mostOften = (out: ReturnType<typeof parseFeed>) => { const top = out.reasons[0]!.reason; return out.rejects.find((r) => r.reason.replace(/"[^"]*"/g, '"…"') === top)?.reason ?? top }
const parseErr = (e: unknown) => e instanceof ParserConfigError ? fail(e.code === 'too_large' ? 413 : 400, e.code, e.message) : null

function runSample(f: { kind: FeedKind; parser: NonNullable<Feed['parser']> }, text?: string) {
  const s = sampleFor(f.kind, f.parser.format)
  return { s, out: parseFeed(text ?? s?.text ?? '', f.kind, f.parser) }
}

function checkInput(i: ReturnType<typeof FeedInputSchema.parse>, c: Config, selfId: string | null, hadLast4: boolean) {
  const name = i.name.trim()
  if (!name) return fail(400, 'invalid_name', 'Enter a name.')
  if (DEFS.some((d) => d.name.toLowerCase() === name.toLowerCase()) || c.custom.some((x) => x.id !== selfId && x.name.toLowerCase() === name.toLowerCase())) return fail(400, 'duplicate_name', 'A feed with this name already exists.')
  const u = checkFeedUrl(i.url)
  if (u !== 'ok') return fail(400, 'invalid_url', u === 'https' ? 'Use an https:// address (http:// is only allowed for internal addresses).' : 'Enter a full address such as https://example.com/feed.json.')
  if (blockedFeedHost(i.url)) return fail(400, 'blocked_host', blockedFeedHost(i.url) === 'own' ? OWN_TEXT : BLOCKED_TEXT) // refused at save, as the pull would
  if (!FORMATS[i.kind].includes(i.parser.format)) return fail(400, 'invalid_format', `This format does not fit a ${i.kind === 'ioc' ? 'IOC' : 'vulnerability'} feed.`)
  const a = i.auth
  if (a.type === 'header' && !/^[A-Za-z0-9-]{1,80}$/.test(a.header_name ?? '')) return fail(400, 'invalid_auth', 'Enter a valid header name, for example X-Api-Key.')
  if (a.type === 'basic' && !(a.username ?? '').trim()) return fail(400, 'invalid_auth', 'Enter the user name.')
  if (a.type !== 'none' && !a.secret && !hadLast4) return fail(400, 'invalid_auth', 'Enter the secret.')
  if (a.secret !== undefined && (a.secret.length < 8 || /\s/.test(a.secret))) return fail(400, 'invalid_auth', 'The secret must be at least 8 characters with no spaces.')
  try { checkParser(i.kind, i.parser) } catch (e) { const r = parseErr(e); if (r) return r; throw e }
  // Last, as on the server: another feed, built-in or custom, already pulls this address
  const same = allFeeds(c).find((f) => f.id !== selfId && sameFeedAddress(f.url, i.url))
  return same ? fail(400, 'duplicate_url', `The feed "${same.name}" already uses this address.`) : null
}

function toCustom(i: ReturnType<typeof FeedInputSchema.parse>, prev: Feed | null): Feed {
  const last4 = i.auth.type === 'none' ? null : i.auth.secret !== undefined ? i.auth.secret.slice(-4) : prev?.auth.secret_last4 ?? null
  return {
    id: prev?.id ?? newId('cf'), builtin: false, name: i.name.trim(), kind: i.kind, format: i.parser.format, url: i.url.trim(), default_url: null, enabled: i.enabled, interval_hours: i.interval_hours,
    auth: { type: i.auth.type, header_name: i.auth.type === 'header' ? i.auth.header_name : null, username: i.auth.type === 'basic' ? (i.auth.username ?? '').trim() : null, secret_last4: last4 },
    parser: i.parser, last_fetch: prev?.last_fetch ?? null, records: prev?.records ?? null, status: prev?.status ?? 'never', error: prev?.error ?? null, license: null, answered_by: null,
  }
}

export const sourceHandlers = [
  http.get(`${API}/feeds/sources`, () => {
    const denied = guard('viewer'); if (denied) return denied
    return HttpResponse.json({ items: allFeeds(config.get()) })
  }),

  http.put(`${API}/feeds/sources/:id`, async ({ params, request }) => {
    const denied = guard('admin'); if (denied) return denied
    const id = String(params.id)
    const p = FeedPatchSchema.safeParse(await body(request))
    if (!p.success) return fail(400, 'invalid_body', 'Check the values and try again.')
    const c = config.get()
    const def = DEFS.find((d) => d.id === id)
    const cust = c.custom.find((x) => x.id === id)
    if (!def && !cust) return fail(404, 'not_found', 'No such feed.')
    let url: string | undefined
    if (p.data.url !== undefined) {
      url = p.data.url.trim() === '' && def ? def.url : p.data.url.trim()
      if (checkFeedUrl(url) !== 'ok') return fail(400, 'invalid_url', 'Use an https:// address (http:// is only allowed for internal addresses).')
      if (blockedFeedHost(url)) return fail(400, 'blocked_host', blockedFeedHost(url) === 'own' ? OWN_TEXT : BLOCKED_TEXT)
    }
    const name = def?.name ?? cust!.name
    const key = p.data.api_key?.trim()
    if (key !== undefined && id !== BYOK) return fail(400, 'invalid_auth', 'This feed does not use an API key.')
    if (key && (key.length < 8 || /\s/.test(key))) return fail(400, 'invalid_auth', 'The secret must be 8 to 500 characters with no spaces.')
    if (p.data.enabled && id === BYOK && !key && !c.builtin[id]?.key_last4) return fail(400, 'invalid_auth', 'Add your VulnCheck API key to turn this feed on.')
    if (def && key !== undefined) { // saving a key turns the feed on; removing it turns the feed off and drops what it loaded
      config.update((x) => ({ ...x, builtin: { ...x.builtin, [id]: { ...x.builtin[id]!, key_last4: key ? key.slice(-4) : null, enabled: p.data.enabled ?? !!key, ...(!key && { last_fetch: null, records: null, status: 'never' as const, error: null }) } } }))
    }
    if (def) config.update((x) => ({ ...x, builtin: { ...x.builtin, [id]: { ...x.builtin[id]!, ...(p.data.enabled !== undefined && key === undefined && { enabled: p.data.enabled }), ...(p.data.interval_hours !== undefined && { interval_hours: p.data.interval_hours }), ...(url !== undefined && { url }) } } }))
    else config.update((x) => ({ ...x, custom: x.custom.map((f) => f.id === id ? { ...f, ...(p.data.enabled !== undefined && { enabled: p.data.enabled }), ...(p.data.interval_hours !== undefined && { interval_hours: p.data.interval_hours }), ...(url !== undefined && { url }) } : f) }))
    // The two tier feeds of Updates to plan: on starts their first load, off empties them, as the box's tier state does.
    const tier = id === 'epss-all' ? 'epss' : id === 'nvd-recent' ? 'recent' : null
    if (tier && p.data.enabled !== undefined) tierState.update((st) => ({ ...st, [tier]: p.data.enabled ? (st[tier] === 'off' ? 'loading' : st[tier]) : 'off' }))
    audit('feeds.update', name, [key !== undefined && (key ? 'API key saved' : 'API key removed'), p.data.enabled !== undefined && (p.data.enabled ? 'enabled' : 'disabled'), p.data.interval_hours !== undefined && `every ${p.data.interval_hours} h`, url !== undefined && 'address changed'].filter(Boolean).join(', '))
    return HttpResponse.json(allFeeds(config.get()).find((f) => f.id === id))
  }),

  http.post(`${API}/feeds/sources/:id/fetch`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const id = String(params.id)
    const c = config.get()
    const f = allFeeds(c).find((x) => x.id === id)
    if (!f) return fail(404, 'not_found', 'No such feed.')
    if (!f.enabled) return fail(409, 'feed_disabled', 'Turn the feed on before fetching it.')
    if (id === IDLE && f.records !== null) return HttpResponse.json(f) // Filled, no Debian device, so nothing is fetched; the row keeps its note
    const host = hostOf(f.url)
    let status: Feed['status'] = 'ok', error: string | null = null, records = f.records
    if (/\.(invalid|example)$/.test(host) && !f.builtin) { status = 'error'; error = `Could not resolve ${host}. Check the address.` }
    else if (/\.invalid$/.test(host)) { status = 'error'; error = `Could not resolve ${host}. Check the mirror address or reset it.` }
    else if (f.parser) {
      try {
        const { out } = runSample({ kind: f.kind, parser: f.parser })
        records = out.accepted
        // Same text as the server (modules/feeds/pull.go accepted, note).
        if (out.accepted === 0) { status = 'error'; error = out.rejected ? `All ${fmtNumber(out.rejected)} rows were rejected: ${out.reasons[0] ? mostOften(out) : 'unknown reason'}.` : 'The feed returned no records.' }
        else if (out.rejected) error = `${fmtNumber(out.rejected)} of ${fmtNumber(out.accepted + out.rejected)} rows were rejected.${out.reasons[0] ? ` Most often: ${mostOften(out)}.` : ''} A few bad lines in a public list are normal; they are skipped.`
      } catch (e) { status = 'error'; error = e instanceof Error ? e.message : String(e) }
    } else records = f.records
    if (status === 'ok' && f.builtin && records !== null && HELD[id]) error = HELD[id] // every good pull says what the feed holds
    const now = nowIso()
    const patch = { last_fetch: now, records, status, error, ...(status === 'ok' && { last_success: now }) }
    if (f.builtin) config.update((x) => ({ ...x, builtin: { ...x.builtin, [id]: { ...x.builtin[id]!, ...patch } } }))
    else config.update((x) => ({ ...x, custom: x.custom.map((y) => y.id === id ? { ...y, ...patch } : y) }))
    audit('feeds.fetch', f.name, status === 'ok' ? `${records ?? 0} records` : error ?? 'failed')
    return HttpResponse.json(allFeeds(config.get()).find((x) => x.id === id))
  }),

  http.post(`${API}/feeds/custom`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const p = FeedInputSchema.safeParse(await body(request))
    if (!p.success) return fail(400, 'invalid_body', 'Check the values and try again.')
    const c = config.get()
    const bad = checkInput(p.data, c, null, false); if (bad) return bad
    const feed = toCustom(p.data, null)
    config.update((x) => ({ ...x, custom: [...x.custom, feed] }))
    audit('feeds.add_custom', feed.name, `${feed.kind}, ${feed.format}`)
    return HttpResponse.json(feed, { status: 201 })
  }),

  http.put(`${API}/feeds/custom/:id`, async ({ params, request }) => {
    const denied = guard('admin'); if (denied) return denied
    const id = String(params.id)
    const c = config.get()
    const prev = c.custom.find((x) => x.id === id)
    if (!prev) return fail(404, 'not_found', 'No such feed.')
    const p = FeedInputSchema.safeParse(await body(request))
    if (!p.success) return fail(400, 'invalid_body', 'Check the values and try again.')
    const bad = checkInput(p.data, c, id, !!prev.auth.secret_last4 && p.data.auth.type !== 'none'); if (bad) return bad
    const feed = toCustom(p.data, prev)
    config.update((x) => ({ ...x, custom: x.custom.map((f) => f.id === id ? feed : f) }))
    audit('feeds.edit_custom', feed.name)
    return HttpResponse.json(feed)
  }),

  http.delete(`${API}/feeds/custom/:id`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const id = String(params.id)
    const prev = config.get().custom.find((x) => x.id === id)
    if (!prev) return fail(404, 'not_found', 'No such feed (built-in feeds cannot be deleted).')
    config.update((x) => ({ ...x, custom: x.custom.filter((f) => f.id !== id) }))
    audit('feeds.delete_custom', prev.name)
    return new HttpResponse(null, { status: 204 })
  }),

  http.post(`${API}/feeds/parse-test`, async ({ request }) => {
    const denied = guard('admin'); if (denied) return denied
    const p = ParseTestInput.safeParse(await body(request))
    if (!p.success) return fail(400, 'invalid_body', 'Check the values and try again.')
    const { kind, parser, sample } = p.data
    if (!FORMATS[kind].includes(parser.format)) return fail(400, 'invalid_format', `This format does not fit a ${kind === 'ioc' ? 'IOC' : 'vulnerability'} feed.`)
    try {
      checkParser(kind, parser)
      const { s, out } = runSample({ kind, parser }, sample)
      const text = sample ?? s?.text ?? ''
      const columns = kind === 'ioc' ? ['indicator', 'kind', 'confidence', 'first_seen'] : ['cve', 'vendor', 'product', 'date', 'description', 'link']
      return HttpResponse.json({ sample: text, sample_label: sample ? 'Your sample' : s?.label ?? 'Sample', columns, records: out.records.slice(0, PREVIEW_ROWS), accepted: out.accepted, rejected: out.rejected, reasons: out.reasons, rejects: out.rejects, truncated: out.truncated } satisfies ParseResult)
    } catch (e) { const r = parseErr(e); if (r) return r; throw e }
  }),
]
