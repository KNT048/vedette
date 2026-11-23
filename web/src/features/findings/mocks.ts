// Mock API of the findings module (S-MIT-1/2/3, S-SCAN-3, S-AI-2). Findings live in the shared findingsStore; AI results live in the mit_ai_outputs collection. Every displayed string is English.
import { http, HttpResponse } from 'msw'
import kev from '@/mocks/fixtures/kev.json'
import { API, audit, body, currentUser, fail, guard } from '@/mocks/http'
import { collection, nowIso } from '@/mocks/db'
import { aiAvailable, aiCandidates, assetsStore, findingsStore, isOn, recordAiRun, type AiJob } from '@/mocks/stores'
import { liveSoftware } from '@/mocks/match'
import { kevPublished as published } from '@/mocks/tiers'
import type { Asset, Finding } from '@/lib/types'
import { untilOk } from './accept'
import { compromise, packs } from './packs'
import { mockHardening } from './hardeningMock'
import type { AiAnswer, AiResult, ApplyItem, Cvss, FindingAsset, FindingDetail, FindingRow, FirewallGuide, KevInfo, KnownVersion, MitigationPack } from './types'
import { fmtDate } from '@/lib/format'
import { displayName } from '@/features/inventory/nameOf'
import { metaStore } from '@/features/inventory/mocks'
import { deviceStatus } from './modelMocks'
import type { DeviceStatusCode } from '@/lib/statusCodes'
import { modelHandlers } from './modelMocks'

interface Vuln { cve: string; vendor: string; product: string; name: string; required_action: string; links: string[]; date_added: string; due_date: string | null; ransomware: boolean; epss: number | null; has_template: boolean }
const vulns = (kev as { vulns: Vuln[] }).vulns

// Mitigation packs and signs of exploitation are signed content of the Vedette project (content pack), not user data: read from packs.ts.
const aiOutputs = collection<Record<string, AiResult>>('mit_ai_outputs', () => ({}))
// Accepted risks, finding id → last day. The shared store keeps them as not_relevant (closed for every other mock);
// the findings API answers risk_accepted with accepted_until, and the day after it they reopen by themselves.
export const accepted = collection<Record<string, string>>('fnd_risk_accepted', () => ({}))

const APPLY_ITEMS: ApplyItem[] = ['patch', 'workaround', 'fortigate', 'mikrotik', 'generic']
const RESOLUTIONS = ['patched', 'mitigated', 'accepted', 'not_relevant', 'false_positive']

const DISPLAY: Record<string, string> = {
  'qnap|photo station': 'Photo Station app on a QNAP NAS',
  'wordpress|wordpress core': 'WordPress website',
  'microsoft|windows': 'Windows computers and servers',
}

/** #825: the CVSS base score the box reads from NVD's records (feeds INV-28), for the sample CVEs. A CVE not here has no score ("No score"):
 *  CVE-2026-96951 (f-3) on purpose, as NVD answers for a CVE it has not scored yet. CVE-2015-5477 has only CVSS 2.0 (v2 bands: High). */
const CVSS: Record<string, Cvss> = {
  'CVE-2022-27593': { score: 9.8, version: '3.1', source: 'nvd', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
  'CVE-2026-119977': { score: 8.5, version: '4.0', source: 'cna', vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N' },
  'CVE-2024-27834': { score: 8.8, version: '3.1', source: 'nvd', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H' },
  'CVE-2025-61624': { score: 6.5, version: '3.1', source: 'cna', vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N' },
  'CVE-2026-21589': { score: 7.5, version: '3.1', source: 'nvd', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' },
  'CVE-2015-5477': { score: 7.8, version: '2.0', source: 'nvd', vector: 'AV:N/AC:L/Au:N/C:N/I:N/A:C' },
  'CVE-2023-22894': { score: 7.7, version: '3.1', source: 'nvd', vector: 'CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H' },
}
const cvssOf = (cve: string): Cvss | null => CVSS[cve] ?? null

function kevInfo(cve: string): KevInfo | null {
  const v = vulns.find((x) => x.cve === cve)
  if (!v) return null
  const display = DISPLAY[`${v.vendor}|${v.product}`.toLowerCase()] ?? `${v.vendor} ${v.product}`
  return { name: v.name, vendor: v.vendor, product: v.product, display, required_action: v.required_action, links: v.links, date_added: v.date_added, due_date: v.due_date, ransomware: v.ransomware, epss: v.epss, has_template: v.has_template,
    published: published(v.cve) }
}


/** A device's badge as the box computes it (findings' device status, through inventory). null when it has none, and while the
 *  findings module is off. */
type Risk = { code: DeviceStatusCode; count: number }
/** The box (inventory's BOX_ID) is never marked. */
const MOCK_BOX = 'a-box'
export function deviceRisk(assetId: string): Risk | null {
  if (!isOn('findings') || assetId === MOCK_BOX) return null
  return deviceStatus(assetId)
}

/** Name as on the Devices page (`displayName`): host name, manually declared product ("… (no device)" when there is no IP), vendor + model, IP, then software; never an id. */
function nameOf(a: Asset): string {
  return displayName(a) || a.software[0]?.display || a.kind
}

function assetView(a: Asset | undefined): FindingAsset | null {
  return a ? { id: a.id, name: nameOf(a), hostname: a.hostname, ip: a.ip || '—', kind: a.kind, display: a.software[0]?.display ?? a.kind, approved: a.approved, ignored: !!metaStore.get()[a.id]?.ignored_at } : null
}

function row(f: Finding): FindingRow {
  const until = accepted.get()[f.id] ?? null
  const status = until ? 'risk_accepted' : f.status
  // as findings.ShownConfidence: a finding its evidence confirms is never shown below a scan's confirmation (0.95), in any status
  const confirmedBy = f.basis === 'scan' || f.basis === 'person' || (f.basis === 'version' && f.status === 'confirmed')
  const confidence = confirmedBy ? Math.max(f.confidence, 0.95) : f.confidence
  const urgency = kevInfo(f.cve) ? 2 : 5 // a CVE on an exploited list is layer 2; any other catalogue CVE is an update to recommend
  return { ...f, status, confidence, urgency, accepted_until: until, resolution_reason: null, proved_version: null, software_id: '', asset: assetView(assetsStore.get().find((a) => a.id === f.asset_id)), kev: kevInfo(f.cve), cvss: cvssOf(f.cve) }
}

const today = () => { const d = new Date(); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}` }
const clearAccepted = (id: string) => accepted.update((m) => { const n = { ...m }; delete n[id]; return n })

/** INV-13: an acceptance whose day has passed reopens, by the system user (the box does it in its hourly pass). */
function expireAccepted() {
  for (const [id, until] of Object.entries(accepted.get())) {
    if (until >= today()) continue
    const f = find(id)
    clearAccepted(id)
    if (!f) continue
    patch(id, (x) => ({ ...x, status: x.basis === 'scan' || x.basis === 'person' || (x.basis === 'version' && !!x.evidence?.source) ? 'confirmed' : 'suspected', resolved_at: null, resolved_by: null, resolution_note: null,
      history: [...x.history, { ts: nowIso(), user: 'system', action: 'reopened', note: `Risk acceptance expired (accepted by ${f.resolved_by ?? 'someone'} until ${fmtDate(until)}).` }] }))
  }
}

const fill = (s: string, ip: string, host: string) => s.replaceAll('{IP}', ip).replaceAll('{HOST}', host)

/** The pack for a real device: replace IP/host name, mark the firewall vendor the customer declared (S-MIT-1). */
function renderPack(p: MitigationPack, asset: FindingAsset | null): MitigationPack {
  const ip = asset?.ip ?? '<IP-NAS>'
  const host = asset?.hostname ?? ip
  const has = (name: string) => assetsStore.get().some((a) => (a.kind === 'firewall' || a.kind === 'router') && (a.vendor?.value ?? '').toLowerCase() === name)
  const detected: Record<string, boolean> = { fortigate: has('fortinet'), mikrotik: has('mikrotik'), generic: false }
  const out = JSON.parse(fill(JSON.stringify(p), ip, host)) as MitigationPack
  out.firewall = out.firewall.map((g: FirewallGuide) => ({ ...g, detected: detected[g.vendor] ?? false }))
  return out
}

const VERSION_SOURCE: Record<string, KnownVersion['source']> = { agent: 'agent', snmp: 'snmp', manual: 'manual', nmap: 'scan', scan: 'scan', passive: 'stated' }

/** findings knownVersion: the device's row keyed to the finding's KEV entry that has a version, and who gave it. */
function knownFor(f: Finding, k: KevInfo | null): KnownVersion | null {
  if (!k) return null
  const key = `${k.vendor}|${k.product}`.toLowerCase()
  const a = assetsStore.get().find((x) => x.id === f.asset_id)
  const s = a?.software.find((x) => x.kev.includes(key) && !!x.version)
  const source = s ? VERSION_SOURCE[s.source] : undefined
  if (!a || !s || !s.version || !source) return null
  const name = source === 'manual' ? s.display : s.display.endsWith(` ${s.version}`) ? s.display.slice(0, -s.version.length - 1) : s.display
  // As the box: a row a scan, an agent or a person gave has its own time (the sample rows keep none, so the device's last sighting stands
  // in); the OS a device states over SNMP or LLDP has the time of that statement, null when the device's OS reading is not one.
  const stated = source === 'snmp' || source === 'stated'
  const statement = a.os && (a.os.source === 'snmp' || a.os.source === 'passive') ? a.os.seen_at : null
  return { software: name, version: s.version, source, seen_at: stated ? statement : a.last_seen }
}

/** mitigation knownRecheck: the version and who gave it, how a newer one reaches Vedette, what a scan template adds. */
function knownRecheck(f: Finding, kv: KnownVersion, k: KevInfo | null, device: string, reachable: boolean) {
  const sw = `${kv.software} ${kv.version}`
  const [from, again] = {
    agent: [`the agent on ${device} reports ${sw}`, 'its agent reports the new one by itself, usually within two hours'],
    snmp: [`Vedette read ${sw} from ${device} over SNMP`, 'press "Read with SNMP now" on its device page (Vedette also reads it again in each scan window)'],
    stated: [`${device} states on the network (LLDP) that it runs ${sw}`, 'it states the new one on the network by itself'],
    scan: [`a network scan read ${sw} from ${device}`, reachable ? 'rescan it with the button below' : 'the next network scan of it reads the new one'],
    manual: [`${sw} was entered for ${device} on the Devices page`, `press "I updated ${kv.software}" at the top of this page and type the new one`],
  }[kv.source]
  return { steps: [
    f.basis === 'product'
      ? `Nothing to look up: ${from} (Evidence above), but Vedette cannot compare it with the versions NVD lists for this CVE: compare it with the fixed version in the vendor advisory (link in the source section).`
      : `Nothing to look up: ${from}. Vedette compared it with the affected versions (Evidence above).`,
    `If ${device} now runs another version, ${again}: Vedette then closes the findings it can prove that version fixes. If this one stays open, press "Mark as handled" and choose Patched.`,
    k?.has_template && reachable ? 'This CVE has a safe scan template: click "Rescan this device" to confirm.'
      : k?.has_template ? 'This CVE has a safe scan template, but this device has no IP address in your inventory, so it cannot be scanned. Add its IP on the device page to scan it.'
      : 'This CVE has no safe scan template yet, so Vedette concludes from the version alone.',
  ] }
}

function recheckFor(f: Finding, k: KevInfo | null, a: FindingAsset | null, kv: KnownVersion | null) {
  if (f.cve === 'CVE-2022-27593' && a) {
    return {
      steps: [
        'Sign in to QTS, open App Center and check the Photo Station version. Lower than the fixed version in advisory QSA-22-24 means the flaw is still there.',
        'Run the safe scan template again with the "Rescan this device" button.',
        'Run the command below from a machine on the network: a 200 or 302 reply means Photo Station is running and reachable.',
      ],
      code: `curl -sI http://${a.ip}/photo/`,
    }
  }
  const reachable = !!a && a.ip !== '—'
  if (kv && !f.evidence?.agent && !f.evidence?.agent_row && !(f.basis === 'scan' && reachable)) return knownRecheck(f, kv, k, a?.name ?? 'the device', reachable)
  if (f.evidence?.agent) { // The agent reports the installed version; nothing to look up (mitigation genericRecheck)
    // as the box: no agent reports the device now (agent-intake off, or no agent row) → the last report, no promise it arrives
    const dev = a?.name ?? 'the device'
    if (a && a.id !== 'a-box' && !(isOn('agent-intake') && assetsStore.get().find((x) => x.id === a.id)?.software.some((s) => s.source === 'agent'))) {
      return { steps: [
        `Nothing to look up: an agent last reported the installed version of ${k?.display ?? 'the software'} on ${dev}, and Vedette compared it with the affected versions (Evidence above). No agent reports ${dev} now.`,
        `Install the update (What to do below). No agent reports ${dev} to Vedette now, so the new version does not arrive by itself: install its agent again so it reports the new one, and Vedette then closes the findings it can prove that version fixes. If this one stays open, press "Mark as handled" and choose Patched.`,
      ] }
    }
    return { steps: [
      `Nothing to look up: the agent on ${a?.name ?? 'the device'} reports the installed version of ${k?.display ?? 'the software'}, and Vedette compared it with the affected versions (Evidence above).`,
      'Install the update (What to do below). The agent reports the new version by itself, usually within two hours (after the restart the update needs), and Vedette then closes this finding by itself.',
      ...(k?.has_template && reachable ? ['This CVE also has a safe scan template: "Rescan this device" checks it from the network.'] : []),
    ] }
  }
  return {
    steps: f.basis === 'scan' && reachable
      ? ['Run the scan template again with the "Rescan this device" button.']
      : [
          f.evidence?.agent_row // The agent reported the installed version; Vedette could not compare it (mitigation genericRecheck)
            ? `Nothing to look up on ${a?.name ?? 'the device'}: its agent reports the installed version of ${k?.display ?? 'the software'} (Evidence above), but Vedette cannot compare it with the versions NVD lists for this CVE.`
            : `Check which version of ${k?.display ?? 'the software'} runs on ${a?.name ?? 'the device'} (in its settings, its admin page or its About screen).`,
          'Compare it with the fixed version in the vendor advisory (link in the source section). An older version means the flaw is still there.',
          k?.has_template && reachable ? 'This CVE has a safe scan template: click "Rescan this device" to confirm.'
            : k?.has_template ? 'This CVE has a safe scan template, but this device has no IP address in your inventory, so it cannot be scanned. Add its IP on the device page to scan it, or check by hand as above.'
            : 'This CVE has no safe scan template yet, so Vedette can only conclude from the version. Check by hand as above.',
        ],
  }
}

const SOURCE_TEXT: Record<KnownVersion['source'], string> = {
  agent: 'The agent on the device', snmp: "The device's own SNMP answer", stated: "The device's own statement on the network",
  scan: 'A network scan (a guess from what a service answers)', manual: 'A person (entered on the Devices page)',
}

/** findings.WhySuspected: from the version and who gave it, whether a check exists for the CVE; the scan's reach is not mocked (the sample box
 *  has the scan on). The ways to confirm come in order: the device reports its version itself, a safe check (only when one exists), last a person. */
function whySuspected(f: Finding, kv: KnownVersion | null, k: KevInfo | null): string {
  const byDevice = !!kv && (kv.source === 'snmp' || kv.source === 'agent')
  const head = f.basis === 'version' && kv && byDevice ? `Version match only: ${SOURCE_TEXT[kv.source]} states ${kv.software} ${kv.version}, inside NVD's affected range, but that range does not clearly cover this release (no end, or listed for another edition or release), so the version alone does not confirm it.`
    : f.basis === 'version' && kv ? `Version match only: ${SOURCE_TEXT[kv.source]} states ${kv.software} ${kv.version}, inside NVD's affected range.`
    : f.basis === 'version' ? "Version match only: the version of the software is inside NVD's affected range."
    : "Product match only: the device runs the product, but its version is not known, so it could not be compared with NVD's affected range."
  const device = byDevice ? '' : ' It is confirmed by itself once the device reports its version: turn on SNMP for the device, or install the agent on it.'
  const check = !k ? '' : !k.has_template ? ' No safe vulnerability check exists for this CVE.' : ' A safe vulnerability check exists for this CVE: run the check to confirm it.'
  return `${head}${device}${check}`
}

function detail(f: Finding): FindingDetail {
  const r = row(f)
  const pack = packs()[f.cve]
  const check = compromise()[f.cve] ?? null
  const ip = r.asset?.ip ?? '<IP>'
  const host = r.asset?.hostname ?? ip
  const outs = aiOutputs.get()
  const kv = knownFor(f, r.kev)
  return {
    ...r,
    fixed_in: null,
    known_version: kv,
    suspected_why: f.status === 'suspected' ? whySuspected(f, kv, r.kev) : null,
    pack: pack ? renderPack(pack, r.asset) : null,
    compromise: check ? JSON.parse(fill(JSON.stringify(check), ip, host)) : null,
    recheck: recheckFor(f, r.kev, r.asset, kv),
    ai: { explain: outs[`${f.id}:explain`] ?? null, config: outs[`${f.id}:mitigation-config`] ?? null },
    ai_available: { explain: aiAvailable('explain-finding'), config: aiAvailable('mitigation-config') },
    applied: f.history.filter((h) => h.action.startsWith('applied:')).map((h) => ({ item: h.action.slice(8), ts: h.ts, user: h.user })),
    hardening: hardeningFor(f, r, pack, check),
  }
}

/** Mitigation INV-8: the general checks fill in when the confirmed pack has no compromise signs of its own (no firewall config). */
function hardeningFor(f: Finding, r: FindingRow, _pack: MitigationPack | undefined, check: unknown) {
  if (check) return null
  return mockHardening(f.cve, r.kev, r.asset)
}

const who = () => currentUser()?.email ?? 'system'
/** The basis a finding had before a person confirmed it (Undo returns to it). */
const priorBasis = new Map<string, Finding['basis']>()
const find = (id: unknown) => findingsStore.get().find((f) => f.id === String(id))
const patch = (id: string, fn: (f: Finding) => Finding) => findingsStore.update((l) => l.map((f) => (f.id === id ? fn(f) : f)))

const BASIS: Record<Finding['basis'], string> = {
  scan: 'A safe scan template confirmed the flaw is still present on this device.',
  version: 'The device matches by version or operating system. No scan template has confirmed it yet, so this is only suspected.',
  product: 'The device only matches by product name; the version is unknown, so it may not be affected.',
  person: 'A person confirmed the device is affected, beyond the version match.',
}

const HARDEN: Record<string, string[]> = {
  'wordpress|wordpress core': [
    'Update WordPress to the latest release of the branch you use. Check the fixed version number in the security notice on wordpress.org (Vedette does not assert a version number itself).',
    'Until you update: temporarily block outside access to the admin area and run the upgrade outside peak hours, from a machine on the internal network.',
    'Back up the website and database before upgrading.',
  ],
  'microsoft|windows': [
    'Install the latest security update for Windows Server through Windows Update or WSUS, and check the CVE ID on the MSRC page.',
    'Do not expose the server SMB (445) and RDP (3389) to the Internet.',
    'An AD server is a high-value target: update outside working hours and take a system-state backup first.',
  ],
}

const jobOf = (skill: AiResult['skill']): AiJob => (skill === 'explain' ? 'explain-finding' : 'mitigation-config')
function aiResult(f: Finding, skill: AiResult['skill']): AiResult {
  const r = row(f)
  const k = r.kev
  const dev = r.asset?.name ?? 'a removed device'
  const key = k ? `${k.vendor}|${k.product}`.toLowerCase() : ''
  const date = k ? fmtDate(k.date_added) : ''
  const paragraphs = skill === 'explain'
    ? [
        `${dev} matches ${f.cve}${k ? ` (${k.name})` : ''}. ${BASIS[f.basis]}`,
        k ? `CISA has listed this flaw as exploited in the wild since ${date}${k.ransomware ? ', and ransomware groups have used it' : ''}. So handle it early rather than waiting for the normal update cycle.` : 'There is no KEV information for this CVE yet.',
      ]
    : ['Vedette has no confirmed recommendation for this CVE yet. Below are general suggestions drafted by your AI from public information. Check them against the vendor advisory before applying.']
  const harden = HARDEN[key]
  const steps = skill === 'explain'
    ? ['Patch: follow the vendor advisory in the sources below.', 'If you cannot patch yet: cut the path in from the Internet and turn off the affected component if unused.', 'Signs of exploitation: check access logs and unfamiliar processes around the time the flaw was published.']
    : harden ? harden : ['Update to the fixed version per the vendor advisory.', 'If you cannot patch yet, restrict Internet access to this device (firewall, VPN).', 'Watch the device logs for a few days after applying.']
  const citations = (k?.links ?? []).slice(0, 3).map((u) => ({ title: new URL(u).hostname.replace(/^www\./, ''), url: u }))
  // the config skill answers with config blocks to paste: a rule that keeps other networks off the vulnerable service's port of
  // this device (nftables when no firewall vendor is known). No admin-network rule: Vedette writes none.
  const ip = r.asset?.ip && r.asset.ip !== '—' ? r.asset.ip : '<DEVICE_IP>'
  const configs = skill === 'explain' ? undefined : [{
    title: `Linux gateway (nftables): block other networks from the vulnerable web service of ${dev}`,
    code: `nft add rule inet filter forward ip daddr ${ip} tcp dport 443 drop`,
    note: 'Based on: general practice, no source in the data names it',
    side_effect: `Devices on other networks can no longer open port 443 of ${dev} until you delete the rule; its own network is not routed through the gateway and still can.`,
  }]
  const answers = skill === 'explain' ? undefined : askAnswers(f, r.kev, dev)
  const len = paragraphs.join('').length + steps.join('').length + (configs?.[0]?.code.length ?? 0) + (answers ?? []).reduce((n, a) => n + a.text.length, 0)
  const prof = aiCandidates(jobOf(skill))[0]
  return { skill, ts: nowIso(), model: prof?.model ?? '', profile: prof?.name, tokens: { input: 1200 + len, output: Math.round(len / 3.2) }, paragraphs, steps, citations, configs, answers }
}

/** "Ask my AI": the four answers, rephrasing only what the finding and the exploited-list entry hold, each with its links. */
function askAnswers(f: Finding, k: KevInfo | null, dev: string): AiAnswer[] {
  const kv = knownFor(f, k)
  const by = [...f.history].reverse().find((h) => h.action === 'confirmed')?.user
  const version = kv ? ` ${dev} runs ${kv.software} ${kv.version}.` : ''
  const affected = f.basis === 'person' ? `Yes: confirmed by ${by ?? 'a person'}.${version}`
    : f.basis === 'scan' ? `Yes: a safe check confirmed it on ${dev}.${version}`
    : f.basis === 'version' ? `Likely: the version matches the affected range, nothing has confirmed it yet.${version}`
    : `Needs a check: only the product name matches; the version of ${dev} is not known.`
  const links = (k?.links ?? []).filter((u) => /^https?:\/\//i.test(u)).map((u) => ({ title: new URL(u).hostname.replace(/^www\./, ''), url: u }))
  const vendor = links.filter((l) => !/(^|\.)(cisa|nist)\.gov$/.test(l.title))
  const cisa = links.filter((l) => /(^|\.)cisa\.gov$/.test(l.title))
  return [
    { key: 'affected', text: affected, links: [] },
    { key: 'fix', text: 'Install the fixed release the vendor advisory names.', links: vendor.slice(0, 2) },
    { key: 'workaround', text: 'None published.', links: [] },
    { key: 'urgency', text: k ? `Attackers use it in real attacks: on CISA KEV since ${fmtDate(k.date_added)}${k.due_date ? `, due ${fmtDate(k.due_date)}` : ''}${k.ransomware ? '; ransomware groups use it' : ''}.` : 'No sign of exploitation in the data.', links: cisa.slice(0, 1) },
  ]
}


const cveOf = (cve: string, name: string, added: string, ransomware: boolean, advisory: string | null) => ({ cve, name, date_added: added, ransomware, advisory })
/** GET /findings?asset=: the software row each finding rests on, as the box stored it when it matched (here: the row keyed to the entry). */
function withSoftware(r: FindingRow): FindingRow {
  if (r.software_id) return r
  const a = assetsStore.get().find((x) => x.id === r.asset_id)
  const key = r.kev ? `${r.kev.vendor}|${r.kev.product}`.toLowerCase() : ''
  return { ...r, software_id: (a ? liveSoftware(a).find((x) => key && x.kev.includes(key))?.id : undefined) ?? '' }
}

/** The finding the box closes by itself once a release it can read is entered (the BN340 question below): not relevant, reason
 *  not_affected_version, on the row that carries the release. */
function enteredClosed(asset: string): FindingRow[] {
  const a = assetsStore.get().find((x) => x.id === asset)
  const sw = a && asset === BN340.asset ? liveSoftware(a).find((x) => x.display === BN340.software) : undefined
  if (!a || !sw?.pkg_version || !releaseOf(sw.pkg_version)) return []
  const at = sw.set_at ?? nowIso()
  const note = `Not affected: OpenSSH ${sw.pkg_version} is outside the range Alpine lists for ${BN340.cve.cve}. Vedette closed this by itself and reopens it if a later match says the device is affected.`
  const f: Finding = { id: `f-${BN340.cve.cve}-${a.id}`, asset_id: a.id, cve: BN340.cve.cve, status: 'not_relevant', severity: 'high', confidence: 0.6, basis: 'version', evidence: null,
    first_seen: at, last_seen: at, resolved_by: 'system', resolved_at: at, resolution_note: note, history: [{ ts: at, user: 'system', action: 'not_relevant', note }] }
  return [{ ...row(f), resolution_reason: 'not_affected_version', proved_version: sw.pkg_version, software_id: sw.id }]
}

/** Mock, BN340 (an Alpine router): CVE-2026-123158 affects only OpenSSH built with musl and without PAM (Alpine's openssh-server).
 *  The scan reads OpenSSH 10.2 and an OS guess, so the platform is the question; once a person sets Alpine Linux, the package release
 *  is; a release Vedette reads settles it (the item leaves; the real box closes the CVE with Alpine's reason), one it cannot read comes
 *  back as question.error. As findings.platformQuestion words it. */
const BN340 = { asset: 'a-bn340', software: 'OpenSSH', cve: cveOf('CVE-2026-123158', 'OpenSSH Remote Code Execution', '2026-11-12', false, 'https://security.alpinelinux.org/vuln/CVE-2026-123158') }
/** The release of what a person typed: the bare release, or the line apk prints ("openssh-server-10.2_p1-r1"); null when unreadable. */
const releaseOf = (v: string) => { const m = /^(?:[a-z][a-z0-9+._-]*?-(?=\d))?(\d[\w.:~+-]*)$/.exec(v.trim()); return m ? m[1]! : null }
export const handlers = [
  ...modelHandlers, // first: /findings/devices and the other new paths must not be read as /findings/:id
  // One device's findings in every state (asset is required: the box's validator refuses a request without it).
  http.get(`${API}/findings`, ({ request }) => {
    const denied = guard('viewer'); if (denied) return denied
    expireAccepted()
    const asset = new URL(request.url).searchParams.get('asset')
    if (!asset) return fail(400, 'invalid', 'asset is required.')
    const list = findingsStore.get().filter((f) => f.asset_id === asset)
    return HttpResponse.json({ items: [...list.map(row), ...enteredClosed(asset)].map(withSoftware) })
  }),

  http.get(`${API}/findings/:id`, ({ params }) => {
    const denied = guard('viewer'); if (denied) return denied
    expireAccepted()
    const f = find(params.id)
    return f ? HttpResponse.json(detail(f)) : fail(404, 'not_found', 'No such finding. It may have been removed when the sample data was restored.')
  }),

  // The finding page's writes on findingsStore ids (modelMocks passes them through): Mark as handled, Reopen, Confirm vulnerability
  // and its Undo, with the rules of modelMocks.
  http.post(`${API}/findings/handle`, async ({ request }) => {
    const denied = guard('operator'); if (denied) return denied
    const b = await body<{ ids?: string[]; resolution: string; note?: string; until?: string }>(request)
    const found = (b.ids ?? []).map((id) => find(id))
    if (!found.length || found.some((f) => !f)) return fail(404, 'not_found', 'A finding in the list does not exist.')
    const resolution = String(b.resolution ?? '')
    if (!RESOLUTIONS.includes(resolution)) return fail(400, 'invalid', 'The request is not valid.')
    const note = typeof b.note === 'string' ? b.note.trim() : ''
    if (note.length > 500) return fail(400, 'invalid', 'The request is not valid.')
    if (['false_positive', 'not_relevant', 'accepted'].includes(resolution) && note.length < 3) return fail(400, 'note_required', 'Write why this is a false positive, not relevant or an accepted risk (at least 3 characters) so the next person understands.')
    if (resolution === 'accepted' ? !untilOk(String(b.until ?? '')) : b.until !== undefined) return fail(400, 'bad_until', 'Accept the risk until a date from tomorrow up to one year from today.')
    const ts = nowIso()
    const user = who()
    for (const f of found as Finding[]) {
      clearAccepted(f.id)
      if (resolution === 'accepted') {
        const until = String(b.until)
        patch(f.id, (x) => ({ ...x, status: 'not_relevant', resolved_by: user, resolved_at: ts, resolution_note: note, history: [...x.history, { ts, user, action: 'risk_accepted', note: `${note} (until ${fmtDate(until)})` }] }))
        accepted.update((m) => ({ ...m, [f.id]: until }))
      } else {
        patch(f.id, (x) => ({ ...x, status: resolution as Finding['status'], resolved_by: user, resolved_at: ts, resolution_note: note || null, history: [...x.history, { ts, user, action: resolution, note: note || undefined }] }))
      }
      audit('findings.status', f.id, `${f.cve} ${resolution}${note ? `: ${note}` : ''}`)
    }
    return HttpResponse.json({ handled: found.length, skipped: 0 })
  }),

  http.post(`${API}/findings/:id/reopen`, async ({ params, request }) => {
    const denied = guard('operator'); if (denied) return denied
    const f = find(params.id)
    if (!f) return fail(404, 'not_found', 'This finding does not exist.')
    const b = await body<{ note?: string }>(request)
    const note = typeof b.note === 'string' ? b.note.trim() : ''
    if ((f.status === 'confirmed' || f.status === 'suspected') && !accepted.get()[f.id]) return fail(409, 'already_open', 'This finding is already open.')
    clearAccepted(f.id)
    const ts = nowIso()
    patch(f.id, (x) => ({ ...x, status: x.basis === 'scan' || x.basis === 'person' || (x.basis === 'version' && !!x.evidence?.source) ? 'confirmed' : 'suspected', resolved_by: null, resolved_at: null, resolution_note: null, history: [...x.history, { ts, user: who(), action: 'reopened', note: note || undefined }] }))
    audit('findings.status', f.id, `${f.cve}${note ? `: ${note}` : ''}`)
    return HttpResponse.json({})
  }),

  // A person confirms a suspected finding (admin): basis person, the note in the history; Undo goes back to the basis it had.
  http.post(`${API}/findings/:id/verify`, async ({ params, request }) => {
    const denied = guard('admin'); if (denied) return denied
    const f = find(params.id)
    if (!f) return fail(404, 'not_found', 'This finding does not exist.')
    const b = await body<{ note: string }>(request)
    const note = typeof b.note === 'string' ? b.note.trim() : ''
    if (note.length > 500) return fail(400, 'invalid', 'The request is not valid.')
    if (f.status !== 'suspected') return fail(409, 'already_verified', 'This finding is already confirmed.')
    if (note.length < 3) return fail(400, 'confirm_note_required', 'Write what makes you sure (at least 3 characters) so the next person understands.')
    const user = who()
    priorBasis.set(f.id, f.basis)
    patch(f.id, (x) => ({ ...x, status: 'confirmed', basis: 'person', history: [...x.history, { ts: nowIso(), user, action: 'confirmed', note: `Confirmed by ${user}: ${note}` }] }))
    audit('findings.confirm', f.id, `${f.cve}: confirmed by ${user}: ${note}`)
    return HttpResponse.json({})
  }),

  http.post(`${API}/findings/:id/unverify`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const f = find(params.id)
    if (!f) return fail(404, 'not_found', 'This finding does not exist.')
    if (f.status !== 'confirmed' || f.basis !== 'person') return fail(409, 'not_confirmed_by_person', 'Only a confirmation a person made can be undone; a scan or the device itself confirmed this one.')
    const user = who()
    const was = priorBasis.get(f.id) ?? 'version'
    patch(f.id, (x) => ({ ...x, status: 'suspected', basis: was, history: [...x.history, { ts: nowIso(), user, action: 'confirm_undone', note: `Confirmation undone by ${user}: back to suspected.` }] }))
    audit('findings.unconfirm', f.id, `${f.cve}: confirmation undone by ${user}`)
    return HttpResponse.json({})
  }),

  // "Applied": writes a log entry, does not change the status by itself; only a rescan confirms it is gone.
  http.post(`${API}/findings/:id/applied`, async ({ params, request }) => {
    const denied = guard('operator'); if (denied) return denied
    const f = find(params.id)
    if (!f) return fail(404, 'not_found', 'No such finding.')
    if (!packs()[f.cve]) return fail(400, 'no_pack', 'This CVE has no confirmed recommendation yet, so there is nothing to mark as applied.')
    const b = await body<{ item: ApplyItem }>(request)
    if (!b.item || !APPLY_ITEMS.includes(b.item)) return fail(400, 'bad_item', 'Invalid item to apply.')
    if (!f.history.some((h) => h.action === `applied:${b.item}`)) {
      patch(f.id, (x) => ({ ...x, history: [...x.history, { ts: nowIso(), user: who(), action: `applied:${b.item}` }] }))
      audit('findings.applied', f.id, `${f.cve}: ${b.item}`)
    }
    return HttpResponse.json(detail(find(f.id)!))
  }),

  // S-AI-2: runs with the customer's AI key; only when the ai module is on and a key exists. The result is stored so it survives a page reload.
  http.post(`${API}/findings/:id/ai`, async ({ params, request }) => {
    const denied = guard('operator'); if (denied) return denied
    const f = find(params.id)
    if (!f) return fail(404, 'not_found', 'No such finding.')
    const b = await body<{ skill: AiResult['skill'] }>(request)
    if (b.skill !== 'explain' && b.skill !== 'mitigation-config') return fail(400, 'bad_skill', 'skill must be explain or mitigation-config.')
    if (!aiAvailable(jobOf(b.skill))) return fail(409, 'ai_unavailable', 'No AI profile is assigned to this job, or the AI assistant is off. Open Settings, AI assistant to set it up.')
    const res = aiResult(f, b.skill)
    aiOutputs.update((m) => ({ ...m, [`${f.id}:${b.skill}`]: res }))
    recordAiRun(jobOf(b.skill), res.tokens.input, res.tokens.output, `${f.cve} ${f.asset_id}`, aiCandidates(jobOf(b.skill))[0])
    audit('findings.ai', f.id, b.skill)
    return HttpResponse.json(detail(find(f.id)!))
  }),
]
