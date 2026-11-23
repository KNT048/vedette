import type { DeviceAddress, DeviceRow, MergeChoice, MergeField, MergePreview, MergeSide, SameReason } from './types'

/** The most devices one merge takes: the kept device and 8 that join it (MergeInput.from). */
export const MERGE_MAX_FROM = 8

/** How much of a name a person or the network gave a device: 2 = a person named it in Vedette, 1 = a host name, 0 = neither (a
 *  maker and model, an IP). A named row is usually the one the person knows the machine by. */
export function nameScore(row: Pick<DeviceRow, 'name' | 'hostname'> | undefined): number {
  if (row?.name?.trim()) return 2
  return row?.hostname?.trim() ? 1 : 0
}

/**
 * The device a merge keeps unless the person picks another: the one an agent reports from (its machine), then an approved one, a
 * watched one, the one with a name, the most findings, the most software, the most addresses, the one seen last; on a tie the first
 * given. These are what the person would lose sight of if the wrong row stayed: an agent's binding, the approval, the name the
 * device is known by, the findings already handled.
 */
export function defaultKeep(sides: MergeSide[], named: (id: string) => number = () => 0): string {
  const key = (s: MergeSide) => [Number(s.agent), Number(s.approved), Number(!s.ignored), named(s.id), s.findings, s.software, s.addresses.length, Date.parse(s.last_seen) || 0]
  let best = sides[0]
  for (const s of sides.slice(1)) {
    const a = key(s); const b = key(best!)
    const i = a.findIndex((v, j) => v !== b[j])
    if (i >= 0 && a[i]! > b[i]!) best = s
  }
  return best?.id ?? ''
}

/** A merge field as the dialog shows it: each distinct value once, with the devices that state it, the kept device's first. */
export type FieldOption = { value: string; devices: string[] }
export type ShownField = { field: MergeField['field']; choosable: boolean; kept: string; options: FieldOption[] }

/** Only the fields the devices state differently (two values or more); the server already leaves out the ones they agree on. */
export function shownDiffers(differs: MergeField[]): ShownField[] {
  const out: ShownField[] = []
  for (const f of differs) {
    const options: FieldOption[] = []
    for (const v of f.values) {
      const o = options.find((x) => x.value === v.value)
      if (o) o.devices.push(v.device)
      else options.push({ value: v.value, devices: [v.device] })
    }
    if (options.length < 2) continue
    out.push({ field: f.field, choosable: f.choosable, kept: f.kept, options })
  }
  return out
}

/** What the merge sends as `fields`: only a choosable field the person set to another value than the merge's own result. */
export function choiceFields(fields: ShownField[], picked: Partial<Record<MergeField['field'], string>>): MergeChoice | undefined {
  const out: Record<string, string> = {}
  for (const f of fields) {
    const v = picked[f.field]
    if (!f.choosable || v === undefined || v === f.kept || !f.options.some((o) => o.value === v)) continue
    if (f.field === 'name' || f.field === 'kind' || f.field === 'os') out[f.field] = v
  }
  return Object.keys(out).length ? (out as MergeChoice) : undefined
}

/** An address in one word: its IP, else its MAC. */
export const addressText = (a: Pick<DeviceAddress, 'ip' | 'mac'>) => a.ip ?? a.mac ?? ''

/** The pieces of "What moves", the most urgent first, each only when there is one: exploited CVEs, findings, software lines, open
 *  ports, then the addresses by name (the first 3, then how many more). */
export type MovePiece =
  | { key: 'exploited' | 'findings' | 'ports'; count: number }
  | { key: 'software'; count: number; fresh: number }
  | { key: 'addresses'; count: number; list: string[]; more: number }
export function movePieces(p: Pick<MergePreview, 'moves' | 'from'>, shown = 3): MovePiece[] {
  const m = p.moves
  const out: MovePiece[] = []
  if (m.exploited > 0) out.push({ key: 'exploited', count: m.exploited })
  if (m.findings > 0) out.push({ key: 'findings', count: m.findings })
  const lines = m.software_new + m.software_shared
  if (lines > 0) out.push({ key: 'software', count: lines, fresh: m.software_new })
  if (m.open_ports > 0) out.push({ key: 'ports', count: m.open_ports })
  const addrs = [...new Set(p.from.flatMap((s) => s.addresses.map(addressText)).filter(Boolean))]
  if (addrs.length) out.push({ key: 'addresses', count: addrs.length, list: addrs.slice(0, shown), more: Math.max(0, addrs.length - shown) })
  return out
}

/** Why an address cannot be split off, or '' when it can: the address an agent reports from stays with the agent's machine, and a
 *  device keeps at least one address. */
export function splitBlock(a: Pick<DeviceAddress, 'agent'>, all: readonly unknown[]): '' | 'agent' | 'only' {
  if (all.length < 2) return 'only'
  return a.agent ? 'agent' : ''
}

// ---- The picker: which devices to offer first for "Merge with…". ----

/** A candidate row and why it is offered where it is: a suggestion of the box (its reason), a row that looks like the same machine
 *  (same maker, model or name), one at a nearby address, or any other device. */
export type Candidate = {
  row: DeviceRow
  group: 'suggested' | 'similar' | 'nearby' | 'other'
  reason?: SameReason
  why?: string
  similar?: { what: 'model' | 'name' | 'maker'; value: string }
  near?: string
}
export type PickerMe = Pick<DeviceRow, 'id' | 'hostname' | 'name' | 'vendor' | 'model'> & { ips: string[] }
export type Suggestion = { id: string; reason: SameReason; why: string }

const MAKER_SUFFIX = new Set(['inc', 'incorporated', 'corp', 'corporation', 'co', 'company', 'ltd', 'limited', 'llc', 'gmbh', 'sa', 'ag', 'plc', 'bv', 'pte', 'networks', 'network', 'technologies', 'technology', 'systems', 'communications'])
/** A maker's name without its legal suffix and punctuation ("Fortinet, Inc." and "Fortinet" are one maker). */
export function makerKey(v: string | null | undefined): string {
  const w = (v ?? '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim().split(' ').filter(Boolean)
  while (w.length > 1 && MAKER_SUFFIX.has(w[w.length - 1]!)) w.pop()
  return w.join(' ')
}
/** A host name's first label, lowercased ("FW-HQ.corp.example" → "fw-hq"). */
const nameKey = (h: string | null | undefined) => (h ?? '').split('.')[0]!.trim().toLowerCase()
const ipNum = (ip: string) => {
  const p = ip.split('.').map(Number)
  return p.length === 4 && p.every((n) => Number.isInteger(n) && n >= 0 && n <= 255) ? ((p[0]! * 256 + p[1]!) * 256 + p[2]!) * 256 + p[3]! : null
}
/** The nearest of `mine` in the same /24 as `ip`, with the distance; null when none is. */
function nearest(ip: string, mine: string[]): { ip: string; d: number } | null {
  const n = ipNum(ip)
  if (n === null) return null
  let best: { ip: string; d: number } | null = null
  for (const m of mine) {
    const x = ipNum(m)
    if (x === null || Math.floor(x / 256) !== Math.floor(n / 256)) continue
    const d = Math.abs(x - n)
    if (!best || d < best.d) best = { ip: m, d }
  }
  return best
}

/** The words a candidate is searched by: names, IP, MAC (with or without separators), maker and model. */
export function matchesQuery(row: DeviceRow, display: string, q: string): boolean {
  const s = q.trim().toLowerCase()
  if (!s) return true
  const hay = [display, row.name, row.hostname, row.ip, row.mac, row.vendor?.value, row.model?.value].filter(Boolean).join(' ').toLowerCase()
  if (hay.includes(s)) return true
  const hex = s.replace(/[^0-9a-f]/g, '')
  return hex.length >= 4 && /^[0-9a-f:.\- ]+$/.test(s) && (row.mac ?? '').toLowerCase().replace(/[^0-9a-f]/g, '').includes(hex)
}

/**
 * The devices "Merge with…" offers for `me`, ranked: the box's suggestions first (their order), then rows of the same model, name
 * or maker, then rows at a nearby address (same /24, nearest first), then every other device by name. The box itself and `me`
 * are never offered.
 */
export function rankCandidates(me: PickerMe, rows: DeviceRow[], suggested: Suggestion[], display: (r: DeviceRow) => string): Candidate[] {
  const out: Candidate[] = []
  const seen = new Set<string>([me.id])
  for (const s of suggested) {
    const row = rows.find((r) => r.id === s.id)
    if (!row || seen.has(row.id) || row.is_box) continue
    seen.add(row.id)
    out.push({ row, group: 'suggested', reason: s.reason, why: s.why })
  }
  const rest = rows.filter((r) => !seen.has(r.id) && !r.is_box)
  const myModel = (me.model?.value ?? '').trim().toLowerCase()
  const myName = nameKey(me.name) || nameKey(me.hostname)
  const myMaker = makerKey(me.vendor?.value)
  const similar = (r: DeviceRow): Candidate['similar'] => {
    if (myModel && (r.model?.value ?? '').trim().toLowerCase() === myModel) return { what: 'model', value: r.model!.value }
    const n = nameKey(r.name) || nameKey(r.hostname)
    if (myName.length >= 3 && n === myName) return { what: 'name', value: display(r) }
    if (myMaker && makerKey(r.vendor?.value) === myMaker) return { what: 'maker', value: r.vendor!.value }
    return undefined
  }
  const order = { model: 0, name: 1, maker: 2 }
  const sims: Candidate[] = []
  const near: (Candidate & { d: number })[] = []
  const other: Candidate[] = []
  for (const r of rest) {
    const s = similar(r)
    if (s) { sims.push({ row: r, group: 'similar', similar: s }); continue }
    const n = nearest(r.ip, me.ips)
    if (n) { near.push({ row: r, group: 'nearby', near: n.ip, d: n.d }); continue }
    other.push({ row: r, group: 'other' })
  }
  const byName = (a: Candidate, b: Candidate) => display(a.row).localeCompare(display(b.row))
  sims.sort((a, b) => order[a.similar!.what] - order[b.similar!.what] || byName(a, b))
  near.sort((a, b) => a.d - b.d || byName(a, b))
  other.sort(byName)
  return [...out, ...sims, ...near.map(({ d: _d, ...c }) => c), ...other]
}

/** What the kept device is after the merge, as the box decides it (inventory joinAs): it keeps its own state, except that an
 *  approved device a person watches is never hidden, so an ignored device merged with one is watched again. "" when both are
 *  watched or both ignored. */
export function watchAfterMerge(kept: { ignored?: boolean }, gone: { ignored?: boolean; approved: boolean }): '' | 'staysIgnored' | 'staysWatched' | 'watchedAgain' {
  if (!!kept.ignored === !!gone.ignored) return ''
  if (!kept.ignored) return 'staysWatched'
  return gone.approved ? 'watchedAgain' : 'staysIgnored'
}
/** watchAfterMerge over every device that joins: the one change that matters most (watched again, then stays ignored, then
 *  stays watched). */
export function watchAfterMergeAll(kept: { ignored?: boolean }, gone: { ignored?: boolean; approved: boolean }[]) {
  const all = gone.map((g) => watchAfterMerge(kept, g))
  return (['watchedAgain', 'staysIgnored', 'staysWatched'] as const).find((w) => all.includes(w)) ?? ''
}
