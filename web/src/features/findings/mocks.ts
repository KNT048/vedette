// Mock API module findings (S-MIT-1/2/3, S-SCAN-3, S-AI-2). Phát hiện nằm ở findingsStore dùng chung; kết quả AI nằm ở collection mit_ai_outputs. Mọi chuỗi hiển thị bằng tiếng Anh.
import { http, HttpResponse } from 'msw'
import kev from '@/mocks/fixtures/kev.json'
import { API, audit, body, currentUser, fail, guard } from '@/mocks/http'
import { collection, nowIso } from '@/mocks/db'
import { aiAvailable, aiCandidates, assetsStore, findingsStore, isOn, recordAiRun, type AiJob } from '@/mocks/stores'
import { liveSoftware, usableVersion, versionNeeded } from '@/mocks/match'
import { epssDate, kevPublished as published, planSeed, recentSince, tierFact, tierOf, tierState, withinYear } from '@/mocks/tiers'
import type { Asset, Finding } from '@/lib/types'
import { untilOk } from './accept'
import { compromise, packs } from './packs'
import { mockHardening } from './hardeningMock'
import type { AiAnswer, AiResult, ApplyItem, Cvss, FindingAsset, FindingDetail, FindingRow, FirewallGuide, HomeSummary, KevInfo, KnownVersion, MitigationPack, Plan, PlanCve, PlanDone, PlanItem, RowFix, StatusAction, ToFix, ToFixAction, ToFixDevice, UncheckedItem } from './types'
import { fmtDate } from '@/lib/format'
import { displayName } from '@/features/inventory/nameOf'
import { metaStore } from '@/features/inventory/mocks'
import { openIncidents, sentSince } from '@/features/notify/mocks'
import { SUMMARY_DAYS, SUMMARY_TOP } from './contract'
import { modelHandlers } from './modelMocks'

interface Vuln { cve: string; vendor: string; product: string; name: string; required_action: string; links: string[]; date_added: string; due_date: string | null; ransomware: boolean; epss: number | null; has_template: boolean }
const vulns = (kev as { vulns: Vuln[] }).vulns

// Gói giảm thiểu và dấu hiệu khai thác là nội dung ký của dự án Vedette (content pack), không phải dữ liệu người dùng: đọc từ packs.ts.
const aiOutputs = collection<Record<string, AiResult>>('mit_ai_outputs', () => ({}))
// Accepted risks, finding id → last day. The shared store keeps them as not_relevant (closed for every other mock);
// the findings API answers risk_accepted with accepted_until, and the day after it they reopen by themselves.
export const accepted = collection<Record<string, string>>('fnd_risk_accepted', () => ({}))
// The update that fixes a finding with others (FindingRow.fix), finding id → fix. The box computes it from NVD's ranges, which
// the mock does not have, so it is empty unless a test or a sample sets it.
export const fixes = collection<Record<string, RowFix>>('fnd_fixes', () => ({}))

const APPLY_ITEMS: ApplyItem[] = ['patch', 'workaround', 'fortigate', 'mikrotik', 'generic']
const ACTIONS: StatusAction[] = ['patched', 'mitigated', 'false_positive', 'not_relevant', 'accept_risk', 'reopen']
const MAX_BULK = 500

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


/** A device's risk marker as the box computes it (findings RiskOf, through inventory): read from what To fix shows for it (one
 *  rule): its open exploited findings To fix lists (an update named, or proved), else its recommended updates with a likely CVE or of
 *  High or Critical severity. null when clean, and while the findings module is off. */
type Risk = { level: 'exploited' | 'update'; exploited: number; updates: number }
/** The box (inventory's BOX_ID) is never marked; its updates stay in To fix. */
const MOCK_BOX = 'a-box'
export function deviceRisk(assetId: string): Risk | null {
  if (!isOn('findings') || assetId === MOCK_BOX) return null
  return riskOfCard(toFix(assetId).devices[0] ?? null)
}
/** findings.RiskOf of one To fix card. */
function riskOfCard(d: Omit<ToFixDevice, 'risk'> | null): Risk | null {
  if (!d || d.asset.id === MOCK_BOX) return null
  const exploited = [...d.exploited, ...d.no_update.filter((x) => x.confirmed + x.detected > 0)].reduce((n, x) => n + Math.max(x.finding_ids.length, x.cves.length), 0)
  const updates = d.planned.filter((x) => x.likely > 0 || sevRank(x.worst) >= sevRank('high')).length
  if (exploited > 0) return { level: 'exploited', exploited, updates }
  return updates > 0 ? { level: 'update', exploited: 0, updates } : null
}

/** The recommended updates a person marked done (POST /findings/plan/done), by item key, with the CVEs the item had then. */
const planDone = new Map<string, PlanDone & { cves: string[] }>()
/** As the box: a mark holds while the item has the same version and no CVE it did not have. */
const doneOf = (i: PlanItem) => {
  const m = planDone.get(i.group)
  return m && m.version === i.version && i.cves.every((c) => m.cves.includes(c.cve)) ? m : null
}

/** GET /findings/plan: the sample items, filtered by tier and device; a CVE older than 12 months only with basis scan. Items marked
 *  done are listed only with done. */
function plan(tier: string, asset: string | null, done = false): Plan {
  const shown = (t: string) => tierPlan(t, asset).items.filter((i) => !!doneOf(i) === done)
  const n = (t: string) => shown(t).length // every tab's number in one answer, as the box gives it
  const base = tierPlan(tier, asset)
  const doneN = tierPlan('all', asset).items.filter((i) => !!doneOf(i)).length
  // Each item carries its device's risk marker, so the page needs no device list
  return { ...base, items: base.items.filter((i) => !!doneOf(i) === done).map((i) => {
    const m = doneOf(i)
    return { ...i, risk: deviceRisk(i.asset.id), done: m ? { by: m.by, at: m.at, note: m.note, version: m.version } : null }
  }), counts: { likely: n('likely'), recent: n('recent'), all: n('all'), done: doneN } }
}

function tierPlan(tier: string, asset: string | null): Omit<Plan, 'counts'> {
  const feedsOn = isOn('feeds')
  const st = feedsOn ? tierState.get() : { ...tierState.get(), epss: 'module_off' as const, recent: 'module_off' as const }
  const ready = st.epss === 'ready' || st.recent === 'ready'
  const assets = assetsStore.get()
  const readable = assets.filter((a) => a.software.some((s) => !!s.version))
  const items: PlanItem[] = []
  let old = 0
  if (ready && st.compared) {
    for (const p of planSeed.get()) {
      const a = assets.find((x) => x.id === p.asset_id)
      if (!a || (asset && a.id !== asset)) continue
      const cves: PlanCve[] = []
      for (const c of p.cves) {
        const f = tierFact(c.cve)
        if (!f || (!withinYear(f) && c.basis !== 'scan')) continue // Older only when a scan engine found it
        const t = tierOf(f)
        if (t === 'likely' ? st.epss !== 'ready' : st.recent !== 'ready') continue
        if (tier !== 'all' && t !== tier) continue
        if (!withinYear(f)) old++
        cves.push({ cve: f.cve, tier: t, basis: c.basis, severity: f.severity, score: f.score, published: f.published, epss: f.epss, percentile: f.percentile })
      }
      if (cves.length === 0) continue
      // Likely first by EPSS, then the recent ones by CVSS score, then EPSS, then newest (findings' sortPlanCVEs)
      cves.sort((x, y) => (x.tier === y.tier ? 0 : x.tier === 'likely' ? -1 : 1)
        || (x.tier === 'likely' ? (y.epss ?? -1) - (x.epss ?? -1) || (y.score ?? -1) - (x.score ?? -1) : (y.score ?? -1) - (x.score ?? -1) || (y.epss ?? -1) - (x.epss ?? -1))
        || y.published.localeCompare(x.published))
      // As the box: an agent row's version is the last list an agent sent once no agent reports the device (agent-intake off, or no
      // agent row: the inventory mock binds an osquery agent to a device with one; the box reads its own packages)
      const gone = cves.some((c) => c.basis === 'agent') && a.id !== 'a-box' && !(isOn('agent-intake') && a.software.some((s) => s.source === 'agent'))
      items.push({ group: `${a.id}/${p.software_id}`, asset: { id: a.id, name: nameOf(a) }, risk: null, software: p.software, version: p.version, fixed: p.fixed, kind: p.kind, pro: p.pro ?? false, distro: p.distro ?? '', nvd_lag: p.nvd_lag ?? false, kb: p.kb ?? '',
        distro_data: p.kind === 'distro' ? (p.fixed ? 'fixed' : 'none') : '', done: null,
        cves, likely: cves.filter((c) => c.tier === 'likely').length, recent: cves.filter((c) => c.tier === 'recent').length,
        agent_gone: gone, agent_reported: gone ? p.reported ?? null : null })
    }
  }
  const top = (i: PlanItem) => Math.max(-1, ...i.cves.map((c) => c.epss ?? -1))
  items.sort((x, y) => y.likely - x.likely || top(y) - top(x) || y.cves.length - x.cves.length)
  return { items, compared: st.compared, compared_devices: readable.length, unchecked_devices: assets.length - readable.length, old_evidence: old,
    data: { epss: st.epss, recent: st.recent, epss_date: st.epss === 'ready' ? epssDate() : null, recent_since: st.recent === 'ready' ? recentSince() : null } }
}

/** Tên như trang Devices (`displayName`): tên máy, sản phẩm khai tay ("… (no device)" khi không có IP), hãng + model, IP, rồi phần mềm; không bao giờ là id. */
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
  return { ...f, status, confidence, accepted_until: until, resolution_reason: null, proved_version: null, software_id: '', asset: assetView(assetsStore.get().find((a) => a.id === f.asset_id)), kev: kevInfo(f.cve), cvss: cvssOf(f.cve),
    fix: status === 'confirmed' || status === 'suspected' ? fixes.get()[f.id] ?? null : null }
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

/** Gói theo thiết bị thật: thay IP/tên máy, đánh dấu hãng firewall khách đã khai (S-MIT-1). */
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
  return `${head}${device}${check} Last, confirm it yourself.`
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

/** GET /findings/summary (#825), computed as the box does: open = confirmed + suspected; the trend counts, at the end of each UTC day, the
 *  findings first seen by then and not closed by then. */
export function summary(): HomeSummary {
  const rows = findingsStore.get().map(row)
  const open = rows.filter((r) => r.status === 'confirmed' || r.status === 'suspected')
  const rank = (r: FindingRow) => [r.status === 'confirmed' ? 0 : 1, r.kev?.ransomware ? 0 : 1, -(r.cvss?.score ?? -1)] as const
  const top = [...open].sort((a, b) => {
    const x = rank(a), y = rank(b)
    return x[0] - y[0] || x[1] - y[1] || x[2] - y[2] || b.first_seen.localeCompare(a.first_seen)
  }).slice(0, SUMMARY_TOP)
  const now = Date.now()
  const today = new Date(now); today.setUTCHours(24, 0, 0, 0)
  const trend = Array.from({ length: SUMMARY_DAYS }, (_, i) => {
    const end = i === SUMMARY_DAYS - 1 ? now : today.getTime() - (SUMMARY_DAYS - 1 - i) * 864e5
    return rows.filter((r) => Date.parse(r.first_seen) <= end && (!r.resolved_at || Date.parse(r.resolved_at) > end)).length
  })
  const assets = assetsStore.get()
  return {
    open: { total: open.length, confirmed: open.filter((r) => r.status === 'confirmed').length, devices: new Set(open.map((r) => r.asset_id)).size, ransomware: open.filter((r) => r.kev?.ransomware).length },
    top: top.map((r) => ({ id: r.id, cve: r.cve, status: r.status === 'confirmed' ? 'confirmed' as const : 'suspected' as const, severity: r.severity, asset: r.asset, product: r.kev ? (r.kev.display || `${r.kev.vendor} ${r.kev.product}`) : '', software: r.fix?.software ?? '', ransomware: !!r.kev?.ransomware, source: r.kev ? (r.kev.source ?? 'cisa-kev') : null, cvss: r.cvss, first_seen: r.first_seen })),
    trend,
    devices: { total: assets.length, pending: assets.filter((a) => !a.approved).length },
    alerts: isOn('notify') ? { ...sentSince(new Date(now - 7 * 864e5).toISOString()), days: 7 } : null,
    incidents: isOn('notify') ? openIncidents() : null,
    unchecked: uncheckedCounts(),
    generated_at: nowIso(),
  }
}

const cveOf = (cve: string, name: string, added: string, ransomware: boolean, advisory: string | null) => ({ cve, name, date_added: added, ransomware, advisory })
const UNCHECKED_SEED: { asset: string; software: string; reason: UncheckedItem['reason']; action: UncheckedItem['action']; cves: UncheckedItem['cves'] }[] = [
  { asset: 'a-srvacc', software: 'Windows Server 2022', reason: 'no_nvd_data', action: 'none', cves: [
    cveOf('CVE-2026-20001', 'Windows Kernel Privilege Escalation', '2026-11-12', true, 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20001'),
    cveOf('CVE-2026-20002', 'Windows SMB Remote Code Execution', '2026-11-10', false, null)] },
  { asset: 'a-web01', software: 'WordPress website', reason: 'no_nvd_versions', action: 'none', cves: [
    cveOf('CVE-2026-20003', 'WordPress Core Authentication Bypass', '2026-11-05', false, 'https://wordpress.org/news/category/security/')] },
  { asset: 'a-nas01', software: 'Synology NAS (DSM)', reason: 'not_comparable', action: 'none', cves: [
    cveOf('CVE-2026-20004', 'Synology DSM Command Injection', '2026-10-28', true, 'https://www.synology.com/en-global/security/advisory/Synology_SA_26_10'),
    cveOf('CVE-2026-20005', 'Synology DSM Path Traversal', '2026-10-20', false, null),
    cveOf('CVE-2026-20006', 'Synology DSM Authentication Bypass', '2026-10-02', false, null),
    cveOf('CVE-2026-20007', 'Synology DSM Buffer Overflow', '2026-09-18', false, null)] },
  { asset: 'a-rt02', software: 'MikroTik router', reason: 'not_named', action: 'none', cves: [
    cveOf('CVE-2026-20008', 'MikroTik RouterOS Memory Corruption', '2026-09-01', false, 'https://mikrotik.com/supportsec')] },
]
/** Mock: SQL Server added by hand without a version on SRV-FILE, and a camera seen only in traffic. Their
 *  exploited CVEs are not in the KEV fixture, so the items are seeded here; it leaves once the row has a usable version, as the real box re-matches. */
const VERSION_SEED: { asset: string; software: string; cves: number }[] = [
  { asset: 'a-srvfile', software: 'Microsoft SQL Server', cves: 6 },
  { asset: 'a-cam01', software: 'Hikvision camera', cves: 4 }, // seen in traffic, no version: a scan reads it
]
function versionSeed(asset?: string | null) {
  return VERSION_SEED.flatMap((v) => {
    const a = assetsStore.get().find((x) => x.id === v.asset)
    const sw = a ? liveSoftware(a).find((x) => x.display === v.software) : undefined
    return a && sw && (!asset || a.id === asset) && !usableVersion(sw.version) ? [{ asset: a, software: sw, cves: v.cves }] : []
  })
}
const seedVersions = new Map<string, string | null>()
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

/** #910 phase 1 mock: the unchecked list; an item leaves it once its software's version changes (the real box re-checks), a person's
 *  correction included (INV-41: the rows matching reads). */
export function unchecked(asset?: string | null): UncheckedItem[] {
  const out: UncheckedItem[] = []
  for (const u of UNCHECKED_SEED) {
    const a = assetsStore.get().find((x) => x.id === u.asset)
    const sw = a ? liveSoftware(a).find((x) => x.display === u.software) : undefined
    if (!a || !sw || (asset && a.id !== asset)) continue
    const key = `${a.id}/${u.software}`
    if (!seedVersions.has(key)) seedVersions.set(key, sw.version || null)
    if (seedVersions.get(key) !== (sw.version || null)) continue
    out.push({ asset: assetView(a), asset_id: a.id, software_id: sw.id, software: sw.display, version: sw.version || null, reason: u.reason, cves: u.cves, action: u.action })
  }
  const q = platformItem()
  if (q && (!asset || q.asset_id === asset)) out.push(q)
  return out
}

/** Mock, BN340 (an Alpine router): CVE-2026-123158 affects only OpenSSH built with musl and without PAM (Alpine's openssh-server).
 *  The scan reads OpenSSH 10.2 and an OS guess, so the platform is the question; once a person sets Alpine Linux, the package release
 *  is; a release Vedette reads settles it (the item leaves; the real box closes the CVE with Alpine's reason), one it cannot read comes
 *  back as question.error. As findings.platformQuestion words it. */
const BN340 = { asset: 'a-bn340', software: 'OpenSSH', cve: cveOf('CVE-2026-123158', 'OpenSSH Remote Code Execution', '2026-11-12', false, 'https://security.alpinelinux.org/vuln/CVE-2026-123158') }
const APK = 'apk info -e -v openssh-server'
/** The release of what a person typed: the bare release, or the line apk prints ("openssh-server-10.2_p1-r1"); null when unreadable. */
const releaseOf = (v: string) => { const m = /^(?:[a-z][a-z0-9+._-]*?-(?=\d))?(\d[\w.:~+-]*)$/.exec(v.trim()); return m ? m[1]! : null }
function platformItem(): UncheckedItem | null {
  const a = assetsStore.get().find((x) => x.id === BN340.asset)
  const sw = a ? liveSoftware(a).find((x) => x.display === BN340.software) : undefined
  if (!a || !sw) return null
  const pkg = sw.pkg_version ?? ''
  if (pkg && releaseOf(pkg)) return null // settled
  const device = assetView(a)?.name ?? 'this device'
  const base = { asset: assetView(a), asset_id: a.id, software_id: sw.id, software: sw.display, version: sw.version || null, cves: [BN340.cve], action: 'answer_platform' as const }
  const alpine = a.os?.source === 'manual' && /alpine/i.test(a.os.value)
  if (alpine || pkg) {
    return { ...base, reason: 'package_unknown', question: {
      text: `Which openssh-server package release does ${device} have? Alpine Linux fixed CVE-2026-123158 in 10.2_p1-r1 (3.23) and 10.0_p1-r10 (3.22).`, command: APK,
      answers: [{ label: 'Enter the package release', ask: ['pkg_version'] }],
      ...(pkg ? { error: `Vedette could not read the release you entered ("${pkg}"): enter it as ${APK} prints it, for example openssh-server-10.2_p1-r1 or 10.2_p1-r1.` } : {}),
    } }
  }
  return { ...base, reason: 'platform_unknown', question: {
    text: `Is the OpenSSH on ${device} Alpine Linux's openssh-server package, or another build? CVE-2026-123158 affects only OpenSSH built with musl libc and without PAM, such as Alpine Linux's openssh-server package. Choose the Alpine Linux release it runs (cat /etc/alpine-release prints it), or Another system to give its OS and the OpenSSH package release (that settles it).`,
    command: 'cat /etc/alpine-release',
    answers: [{ label: 'Alpine Linux 3.22', os: 'Alpine Linux 3.22' }, { label: 'Alpine Linux 3.23', os: 'Alpine Linux 3.23' }, { label: 'Another system', ask: ['os', 'pkg_version'] }],
  } }
}
const uncheckedCounts = () => {
  const l = unchecked()
  return { cves: new Set(l.flatMap((i) => i.cves.map((c) => c.cve))).size, devices: new Set(l.map((i) => i.asset_id)).size }
}

const SEV = ['info', 'low', 'medium', 'high', 'critical']
const sevRank = (s: string) => SEV.indexOf(s.toLowerCase())
const buildOf = (v: string) => v.replace(/^10\.0\./, '')
/** As findings updateSentence (updates.go): what to install, in the words the box writes. */
function sentence(u: Pick<ToFixAction, 'kind' | 'software' | 'version' | 'fixed' | 'windows' | 'distro' | 'pro' | 'kb'>): string {
  const sw = u.software || 'the software'
  const fixed = u.windows ? buildOf(u.fixed) : u.fixed
  const build = `${u.windows && u.version ? `from build ${buildOf(u.version)} to ${fixed}` : `build ${fixed}`} or later${u.kb ? `; ${u.kb}` : ''}`
  switch (u.kind) {
    case 'none': return `No update is named that fixes these: follow the vendor's advice for ${sw}`
    case 'distro':
      if (fixed) return `Upgrade the ${sw} package from ${u.version} to ${fixed} or later${u.pro ? ' (Ubuntu Pro)' : ''}`
      return u.distro ? `Install ${u.distro}'s security updates for ${sw}` : `Install the distribution's security updates for ${sw}`
    case 'feature_update': return `Upgrade ${sw} to ${fixed}: some of these get no update for this release`
    case 'esu': return `Install the Extended Security Update for ${sw} (${build}; it needs an ESU subscription)`
    case 'windows': return `Install the latest cumulative update for ${sw} (${build})`
  }
  return u.windows ? `Install the latest cumulative update for ${sw} (${build})` : `Upgrade ${sw} from ${u.version} to ${fixed} or later`
}

/** GET /findings/to-fix, as findings.ToFix builds it: per device, the open findings grouped by their fix (or by product when
 *  no update is named), then the device's plan items; the most urgent device first. */
function toFix(asset: string | null): ToFix {
  const rows = findingsStore.get().filter((f) => !asset || f.asset_id === asset).map(row).filter((r) => r.status === 'confirmed' || r.status === 'suspected')
  const assets = assetsStore.get()
  const feedsOn = isOn('feeds')
  const planItems = feedsOn ? tierPlan('all', asset).items : []
  const ids = [...new Set([...rows.map((r) => r.asset_id), ...planItems.map((i) => i.asset.id)])]
  const devices: ToFixDevice[] = []
  for (const id of ids) {
    const a = assets.find((x) => x.id === id)
    const view = assetView(a)
    if (!a || !view) continue
    const groups = new Map<string, ToFixAction>()
    for (const r of rows.filter((x) => x.asset_id === id).sort((x, y) => sevRank(y.severity) - sevRank(x.severity) || x.cve.localeCompare(y.cve))) {
      const f = r.basis === 'product' ? null : r.fix
      const kevKey = r.kev ? `${r.kev.vendor}|${r.kev.product}`.toLowerCase() : ''
      const swRow = a.software.find((x) => x.kev.includes(kevKey))
      const sw = f?.software ?? swRow?.display ?? r.kev?.display ?? ''
      const key = f ? `fix:${f.group}` : `row:${swRow?.id ?? sw}`
      let g = groups.get(key)
      if (!g) {
        g = f
          ? { group: f.group, software_id: '', software: f.software, version: f.version, product: kevKey, source: a.software.find((x) => `${id}/${x.id}` === f.group)?.source ?? '', fixed: f.fixed, kind: f.kind, windows: f.windows, distro: f.distro, pro: f.pro, distro_data: '', action: '', cves: [], finding_ids: [], worst: '', ransomware: 0, likely: 0, confirmed: 0, detected: 0, reported: 0, suspected: 0, checkable: 0, nvd_lag: false, kb: '' }
          : { group: `${id}/${swRow?.id ?? ''}`, software_id: swRow?.id ?? '', software: sw, version: swRow?.version ?? '', product: swRow ? `${swRow.vendor}|${swRow.product}`.toLowerCase() : '', source: swRow?.source ?? '', fixed: '', kind: 'none', windows: false, distro: '', pro: false, distro_data: '', action: '', cves: [], finding_ids: [], worst: '', ransomware: 0, likely: 0, confirmed: 0, detected: 0, reported: 0, suspected: 0, checkable: 0, nvd_lag: false, kb: '' }
        if (f) g.software_id = a.software.find((s) => `${id}/${s.id}` === f.group)?.id ?? ''
        groups.set(key, g)
      }
      g.cves.push(r.cve); g.finding_ids.push(r.id)
      if (!g.worst) g.worst = r.severity
      if (r.kev?.ransomware) g.ransomware++
      if (r.kev?.has_template) g.checkable++
      if (r.status === 'confirmed') g.confirmed++ // a scan, a person or the version the device reports (findings proofOf)
      else if (r.basis === 'version') g.detected++
      else g.reported++
    }
    const acts = [...groups.values()].map((g) => ({ ...g, action: sentence(g) }))
    const order = (x: ToFixAction, y: ToFixAction) => sevRank(y.worst) - sevRank(x.worst) || y.cves.length - x.cves.length || y.ransomware - x.ransomware || x.software.localeCompare(y.software)
    const planned: ToFixAction[] = planItems.filter((i) => i.asset.id === id).map((i) => {
      const worst = i.cves.reduce((w, c) => (c.severity && sevRank(c.severity) > sevRank(w) ? c.severity : w), '')
      const row = a.software.find((x) => x.id === (i.group.split('/')[1] ?? ''))
      const u = { group: i.group, software_id: i.group.split('/')[1] ?? '', software: i.software, version: i.version, product: row ? `${row.vendor}|${row.product}`.toLowerCase() : '', source: row?.source ?? '', fixed: i.fixed, kind: i.kind, windows: i.kind === 'windows' || i.kind === 'esu', distro: i.distro, pro: i.pro, distro_data: i.distro_data, action: '', cves: i.cves.map((c) => c.cve), finding_ids: [], worst, ransomware: 0, likely: i.likely, confirmed: 0, detected: 0, reported: 0, suspected: 0, checkable: 0, nvd_lag: i.nvd_lag, kb: i.kb }
      return { ...u, action: sentence(u) }
    })
    const card = { asset: view, open: rows.filter((x) => x.asset_id === id).length, exploited: acts.filter((x) => x.kind !== 'none').sort(order), no_update: acts.filter((x) => x.kind === 'none').sort(order), planned, plan_compared: true }
    devices.push({ ...card, risk: riskOfCard(card) })
  }
  const urgency = (d: ToFixDevice) => {
    const act = [...d.exploited, ...d.no_update.filter((x) => x.confirmed + x.detected > 0)]
    return [act.length ? 1 : 0, Math.max(-1, ...act.map((x) => sevRank(x.worst))), act.reduce((n, x) => n + x.ransomware, 0), act.reduce((n, x) => n + x.confirmed + x.detected, 0), act.reduce((n, x) => n + x.cves.length, 0),
      Math.max(-1, ...d.planned.map((x) => sevRank(x.worst))), d.planned.reduce((n, x) => n + x.likely, 0), d.planned.reduce((n, x) => n + x.cves.length, 0)]
  }
  devices.sort((x, y) => { const a = urgency(x); const b = urgency(y); for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return b[i]! - a[i]!; return x.asset.id.localeCompare(y.asset.id) })
  const risks = asset ? {} : Object.fromEntries(devices.flatMap((d) => (d.risk ? [[d.asset.id, d.risk]] : [])))
  return { devices, truncated: false, plan_ran: feedsOn, plan_off: !feedsOn, risks }
}

export const handlers = [
  ...modelHandlers, // first: /findings/devices and the other new paths must not be read as /findings/:id
  http.get(`${API}/findings`, ({ request }) => {
    const denied = guard('viewer'); if (denied) return denied
    expireAccepted()
    const asset = new URL(request.url).searchParams.get('asset')
    const list = findingsStore.get().filter((f) => !asset || f.asset_id === asset)
    const version_needed = [...versionNeeded(asset), ...versionSeed(asset)].map(({ asset: a, software: s, cves }) => ({
      asset: assetView(a), asset_id: a.id, software_id: s.id, software: s.display, version: s.version || null, cves,
    }))
    return HttpResponse.json({ items: [...list.map(row), ...(asset ? enteredClosed(asset) : [])].map((r) => (asset ? withSoftware(r) : r)), version_needed, unchecked: unchecked(asset) })
  }),

  // Before /findings/:id: "summary" is not a finding id.
  http.get(`${API}/findings/summary`, () => {
    const denied = guard('viewer'); if (denied) return denied
    expireAccepted()
    return HttpResponse.json(summary())
  }),

  // Before /findings/:id: "to-fix" is not a finding id.
  http.get(`${API}/findings/to-fix`, ({ request }) => {
    const denied = guard('viewer'); if (denied) return denied
    expireAccepted()
    return HttpResponse.json(toFix(new URL(request.url).searchParams.get('asset')))
  }),

  // Before /findings/:id: "plan" is not a finding id.
  http.get(`${API}/findings/plan`, ({ request }) => {
    const denied = guard('viewer'); if (denied) return denied
    const q = new URL(request.url).searchParams
    const tier = q.get('tier') ?? 'all'
    if (!['likely', 'recent', 'all'].includes(tier)) return fail(400, 'invalid', 'tier must be likely, recent or all.')
    return HttpResponse.json(plan(tier, q.get('asset'), q.get('done') === 'true'))
  }),
  http.post(`${API}/findings/plan/done`, async ({ request }) => {
    const denied = guard('operator'); if (denied) return denied
    const b = (await request.json()) as { group?: string; note?: string }
    const it = tierPlan('all', null).items.find((i) => i.group === b.group)
    if (!it) return fail(404, 'not_found', 'No such recommended update: the plan may have changed. Reload the page.')
    const note = (b.note ?? '').trim()
    if (note.length > 500) return fail(400, 'note_too_long', 'The note can be at most 500 characters. Shorten it.')
    const m = { by: currentUser()?.email ?? 'someone', at: nowIso(), note, version: it.version, cves: it.cves.map((c) => c.cve) }
    planDone.set(it.group, m)
    return HttpResponse.json({ by: m.by, at: m.at, note: m.note, version: m.version })
  }),
  http.post(`${API}/findings/plan/undone`, async ({ request }) => {
    const denied = guard('operator'); if (denied) return denied
    const b = (await request.json()) as { group?: string }
    if (!b.group || !planDone.delete(b.group)) return fail(404, 'not_found', 'No such recommended update: the plan may have changed. Reload the page.')
    return HttpResponse.json({ group: b.group })
  }),

  http.get(`${API}/findings/:id`, ({ params }) => {
    const denied = guard('viewer'); if (denied) return denied
    expireAccepted()
    const f = find(params.id)
    return f ? HttpResponse.json(detail(f)) : fail(404, 'not_found', 'No such finding. It may have been removed when the sample data was restored.')
  }),

  // Đổi trạng thái kèm ghi chú (S-MIT-1). false_positive / not_relevant bắt buộc ghi chú để lần sau biết vì sao.
  http.post(`${API}/findings/:id/status`, async ({ params, request }) => {
    const denied = guard('operator'); if (denied) return denied
    const f = find(params.id)
    if (!f) return fail(404, 'not_found', 'No such finding.')
    const b = await body<{ action: StatusAction; note: string; until?: string }>(request)
    if (!b.action || !ACTIONS.includes(b.action)) return fail(400, 'bad_action', 'Choose one of: patched, mitigated, false positive, not relevant, accept risk, or reopen.')
    const note = typeof b.note === 'string' ? b.note.trim() : ''
    if (note.length > 500) return fail(400, 'note_too_long', 'The note can be at most 500 characters. Shorten it.')
    if ((b.action === 'false_positive' || b.action === 'not_relevant' || b.action === 'accept_risk') && note.length < 3) return fail(400, 'note_required', 'Write why this is a false positive, not relevant or an accepted risk (at least 3 characters) so the next person understands.')
    if (b.action === 'accept_risk' ? !untilOk(String(b.until ?? '')) : b.until !== undefined) return fail(400, 'bad_until', 'Accept the risk until a date from tomorrow up to one year from today.')
    const ts = nowIso()
    const user = who()
    clearAccepted(f.id)
    if (b.action === 'accept_risk') {
      const until = String(b.until)
      patch(f.id, (x) => ({ ...x, status: 'not_relevant', resolved_by: user, resolved_at: ts, resolution_note: note, history: [...x.history, { ts, user, action: 'risk_accepted', note: `${note} (until ${fmtDate(until)})` }] }))
      accepted.update((m) => ({ ...m, [f.id]: until }))
    } else if (b.action === 'reopen') {
      if (f.status === 'confirmed' || f.status === 'suspected') return fail(409, 'already_open', 'This finding is already open.')
      patch(f.id, (x) => ({ ...x, status: x.basis === 'scan' || x.basis === 'person' || (x.basis === 'version' && !!x.evidence?.source) ? 'confirmed' : 'suspected', resolved_by: null, resolved_at: null, resolution_note: null, history: [...x.history, { ts, user, action: 'reopened', note: note || undefined }] }))
    } else {
      patch(f.id, (x) => ({ ...x, status: b.action as Finding['status'], resolved_by: user, resolved_at: ts, resolution_note: note || null, history: [...x.history, { ts, user, action: b.action as string, note: note || undefined }] }))
    }
    audit('findings.status', f.id, `${f.cve} → ${b.action}${note ? `: ${note}` : ''}`)
    return HttpResponse.json(detail(find(f.id)!))
  }),

  // A person confirms a suspected finding (admin): basis person, the note in the history; Undo goes back to the basis it had.
  http.post(`${API}/findings/:id/confirm`, async ({ params, request }) => {
    const denied = guard('admin'); if (denied) return denied
    const f = find(params.id)
    if (!f) return fail(404, 'not_found', 'No such finding.')
    const b = await body<{ note: string }>(request)
    const note = typeof b.note === 'string' ? b.note.trim() : ''
    if (note.length > 500) return fail(400, 'note_too_long', 'The note can be at most 500 characters. Shorten it.')
    if (f.status !== 'suspected') return fail(409, 'not_suspected', 'Only a suspected finding can be confirmed.')
    if (note.length < 3) return fail(400, 'confirm_note_required', 'Write what makes you sure (at least 3 characters) so the next person understands.')
    const user = who()
    priorBasis.set(f.id, f.basis)
    patch(f.id, (x) => ({ ...x, status: 'confirmed', basis: 'person', history: [...x.history, { ts: nowIso(), user, action: 'confirmed', note: `Confirmed by ${user}: ${note}` }] }))
    audit('findings.confirm', f.id, `${f.cve}: confirmed by ${user}: ${note}`)
    return HttpResponse.json(detail(find(f.id)!))
  }),

  http.post(`${API}/findings/:id/unconfirm`, ({ params }) => {
    const denied = guard('admin'); if (denied) return denied
    const f = find(params.id)
    if (!f) return fail(404, 'not_found', 'No such finding.')
    if (f.status !== 'confirmed' || f.basis !== 'person') return fail(409, 'not_confirmed_by_person', 'Only a finding a person confirmed can be returned to suspected; a scan or the version the device reports confirmed this one.')
    const user = who()
    const was = priorBasis.get(f.id) ?? 'version'
    patch(f.id, (x) => ({ ...x, status: 'suspected', basis: was, history: [...x.history, { ts: nowIso(), user, action: 'confirm_undone', note: `Confirmation undone by ${user}: back to suspected.` }] }))
    audit('findings.unconfirm', f.id, `${f.cve}: confirmation undone by ${user}`)
    return HttpResponse.json(detail(find(f.id)!))
  }),

  // Một hành động, một ghi chú cho các phát hiện đang mở (INV-10): tất cả hoặc không gì; mỗi phát hiện một dòng lịch sử và kiểm toán; phát hiện đã đóng được đếm và bỏ qua.
  http.post(`${API}/findings/status`, async ({ request }) => {
    const denied = guard('operator'); if (denied) return denied
    const b = await body<{ ids: string[]; action: StatusAction; note: string; until?: string }>(request)
    const ids = [...new Set(Array.isArray(b.ids) ? b.ids.map(String) : [])]
    if (ids.length === 0 || ids.length > MAX_BULK) return fail(400, 'invalid', `Select between 1 and ${MAX_BULK} findings.`)
    if (!b.action || b.action === 'reopen' || !ACTIONS.includes(b.action)) return fail(400, 'bad_action', 'Choose one of: patched, mitigated, false positive, not relevant, or accept risk.')
    const note = typeof b.note === 'string' ? b.note.trim() : ''
    if (note.length > 500) return fail(400, 'note_too_long', 'The note can be at most 500 characters. Shorten it.')
    if ((b.action === 'false_positive' || b.action === 'not_relevant' || b.action === 'accept_risk') && note.length < 3) return fail(400, 'note_required', 'Write why this is a false positive, not relevant or an accepted risk (at least 3 characters) so the next person understands.')
    if (b.action === 'accept_risk' ? !untilOk(String(b.until ?? '')) : b.until !== undefined) return fail(400, 'bad_until', 'Accept the risk until a date from tomorrow up to one year from today.')
    if (ids.some((id) => !find(id))) return fail(404, 'not_found', 'No such finding.')
    const ts = nowIso()
    const user = who()
    let skipped = 0
    for (const id of ids) {
      const f = find(id)!
      if (f.status !== 'confirmed' && f.status !== 'suspected') { skipped++; continue } // a closed finding keeps its reason
      if (b.action === 'accept_risk') {
        const until = String(b.until)
        patch(id, (x) => ({ ...x, status: 'not_relevant', resolved_by: user, resolved_at: ts, resolution_note: note, history: [...x.history, { ts, user, action: 'risk_accepted', note: `${note} (until ${fmtDate(until)})` }] }))
        accepted.update((m) => ({ ...m, [id]: until }))
      } else {
        patch(id, (x) => ({ ...x, status: b.action as Finding['status'], resolved_by: user, resolved_at: ts, resolution_note: note || null, history: [...x.history, { ts, user, action: b.action as string, note: note || undefined }] }))
      }
      audit('findings.status', id, `${f.cve} → ${b.action}${note ? `: ${note}` : ''}`)
    }
    return HttpResponse.json({ updated: ids.length - skipped, skipped })
  }),

  // "Đã áp dụng": ghi nhật ký, không tự đổi trạng thái; chỉ quét lại mới xác nhận đã hết.
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

  // S-AI-2: chạy bằng khoá AI của khách; chỉ khi module ai bật và đã có khoá. Kết quả lưu lại để còn sau khi tải lại trang.
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
