// Builds the safety assessment report (S-REP-2) from the inventory, findings and module state. It states only what the box CAN SEE;
// legal duties that need a person to carry them out (an impact assessment file, a breach notice...) are only listed, never claimed as met.
// Basis checked against the original texts (2026-11-06): the Personal Data Protection Law 91/2025/QH15 (in force 01/01/2026) and Decree 356/2025/NĐ-CP
// (Official Gazette No. 18, 18/01/2026): Article 41 of Decree 356 decides which enterprises are exempt from, or may choose to do, Articles 21, 22 and clause 2 of Article 33 of the Law.

import type { ModuleId } from '@/lib/modules'
import { assetsStore, findingsStore, isOn } from '@/mocks/stores'
import { newId, nowIso } from '@/mocks/db'
import { EOL_OS, rowOf } from './weekly'
import type { Measure, Obligation, PdplOrg, PdplReport } from './types'
import { actsAs } from '@/lib/deviceTypes'

/** Article 41 of Decree 356/2025/NĐ-CP. The exemption/choice is lost when: it does business in personal data processing services, directly processes sensitive data, or accumulates 100,000 data subjects or more. */
export function regimeOf(o: Pick<PdplOrg, 'size' | 'processing_service' | 'sensitive' | 'data_volume'>): 'required' | 'optional' | 'exempt' {
  if (o.processing_service || o.sensitive || o.data_volume === 'gte100k') return 'required'
  if (o.size === 'household' || o.size === 'micro') return 'exempt'
  if (o.size === 'small' || o.size === 'startup') return 'optional'
  return 'required'
}

export function buildPdpl(org: PdplOrg): PdplReport {
  const all = assetsStore.get()
  const open = findingsStore.get().filter((f) => f.status === 'confirmed' || f.status === 'suspected')
  const full = view(all, open)
  // As pdpl.go: the view without the devices not approved yet; its unapproved measure stays the full one.
  const left = new Set(all.filter((a) => !a.approved).map((a) => a.id))
  const a = left.size ? view(all.filter((x) => !left.has(x.id)), open.filter((f) => !left.has(f.asset_id))) : full
  const approvedOnly = { ...a, measures: a.measures.map((x) => (x.id === 'unapproved' ? full.measures.find((y) => y.id === 'unapproved')! : x)) }
  const regime = regimeOf(org)
  const obligations: Obligation[] = [
    { id: 'dpia', applies: true, regime, done: null },
    { id: 'dpo', applies: true, regime, done: !!(org.contact_name && org.contact_email) },
    { id: 'breach', applies: true, regime: 'required', done: null },
    { id: 'consent', applies: true, regime: 'required', done: null },
    { id: 'sensitive', applies: org.sensitive, regime: 'required', done: null },
    { id: 'cross_border', applies: org.cross_border, regime: 'required', done: null },
    { id: 'processors', applies: org.processors, regime: 'required', done: null },
  ]
  return {
    id: newId('pdpl'), generated_at: nowIso(), org, ...full, obligations,
    coverage: (['inventory', 'scan', 'logs', 'honeypot', 'exposure'] as const).map((module) => ({ module, on: isOn(module) })),
    ai_summary: null, approved_only: approvedOnly,
  }
}

type Asset = ReturnType<typeof assetsStore.get>[number]
type OpenFinding = ReturnType<typeof findingsStore.get>[number]

function view(assets: Asset[], open: OpenFinding[]): Pick<PdplReport, 'inventory' | 'measures' | 'risks'> {
  const label = (a: (typeof assets)[number]) => a.name ?? a.hostname ?? a.ip
  const by = new Map<string, number>()
  const src = new Map<string, number>()
  for (const a of assets) {
    by.set(a.kind, (by.get(a.kind) ?? 0) + 1)
    for (const o of [a.vendor, a.model, a.os]) if (o) src.set(o.source, (src.get(o.source) ?? 0) + 1)
  }
  const eol = assets.filter((a) => EOL_OS.test(a.os?.value ?? ''))
  const rdp = assets.filter((a) => a.services.some((s) => s.port === 3389))
  const unapproved = assets.filter((a) => !a.approved)
  const m = (id: Measure['id'], status: Measure['status'], list: string[] = []): Measure => ({ id, status, n: list.length, names: list.slice(0, 4) })
  // Mirrors modules/reports/pdpl.go: something found is "attention"; nothing found is "ok" only when the box could look.
  const seen = (list: string[], ...needs: ModuleId[]): Measure['status'] => (list.length ? 'attention' : assets.length === 0 || needs.some((n) => !isOn(n)) ? 'unknown' : 'ok')
  const measures: Measure[] = [
    m('firewall', assets.some((a) => actsAs(a.kind) === 'firewall') ? 'ok' : assets.length === 0 ? 'unknown' : 'attention'),
    m('patching', seen(open.map((f) => f.cve), 'feeds'), open.map((f) => f.cve)),
    m('eol', seen(eol.map(label)), eol.map(label)),
    m('unapproved', seen(unapproved.map(label)), unapproved.map(label)),
    m('remote', seen(rdp.map(label), 'scan'), rdp.map(label)),
    m('logging', isOn('logs') ? 'ok' : 'unknown'),
    m('honeypot', isOn('honeypot') ? 'ok' : 'unknown'),
    m('scan', isOn('scan') ? 'ok' : 'unknown'),
    m('backup', 'unknown'),
  ]
  return {
    inventory: {
      total: assets.length, approved: assets.length - unapproved.length, unapproved: unapproved.length, fragile: assets.filter((a) => a.fragile).length,
      by_kind: [...by.entries()].map(([kind, n]) => ({ kind, n })).sort((a, b) => b.n - a.n),
      key_systems: assets.filter((a) => ['server', 'nas', 'firewall'].includes(actsAs(a.kind))).map((a) => ({ id: a.id, name: label(a), ip: a.ip, kind: a.kind, os: a.os?.value ?? '–' })),
      sources: [...src.entries()].map(([source, n]) => ({ source, n })).sort((a, b) => b.n - a.n),
    },
    measures, risks: open.map(rowOf),
  }
}
