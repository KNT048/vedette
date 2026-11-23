import i18n from '@/lib/i18n'
import { actsAs, categoryLabel, categoryOf, DEVICE_CATEGORIES, DEVICE_TYPES, kindLabel, lookupType } from '@/lib/deviceTypes'
import { parseQuery, type TokenKey, type TokenValue } from '@/components/common/TokenSearch'
import { shownKind } from './kinds'
import { nameOf } from './nameOf'
import type { DeviceRow, ListSoftware, SoftwareName } from './types'

// The Devices search (#849): free text over name, IP, MAC, vendor, model and OS, plus tokens. Same key twice = either
// (`source:snmp source:osquery`), different keys = both. The list is bounded (MaxListed = 2000) and loaded whole, so this runs in the client,
// except `software:`: the list carries no software lines, so the server says which lines of which devices hold the words (SoftwareMatches).

/** The six feeds a customer names (#849): DeviceRow.sources from the box (#855: osquery is a bound node key, wazuh an address the Wazuh
 *  connection delivered), so `source:osquery` and `source:wazuh` are exact. */
export const SOURCES = ['snmp', 'osquery', 'wazuh', 'scan', 'passive', 'manual'] as const
export type SourceToken = (typeof SOURCES)[number]
export const feedsOfRow = (d: DeviceRow): ReadonlySet<SourceToken> => new Set(d.sources)

/** The lines of each device that the search's `software:` words hold, as GET /inventory/devices?software= answered (matched_software). */
export type SoftwareMatches = ReadonlyMap<string, ListSoftware[]>
export const softwareMatches = (items: DeviceRow[]): SoftwareMatches => new Map(items.map((d) => [d.id, d.matched_software ?? []]))

/** The software lines of a device that `software:` values match (the "Matched software" column, #849): of the lines the server
 *  matched, the ones that hold one of `values` (the server's answer may be for the words typed just before). */
export const matchSoftware = (d: DeviceRow, values: string[], matches?: SoftwareMatches) =>
  (matches?.get(d.id) ?? []).filter((s) => values.some((v) => `${s.display} ${s.vendor} ${s.product}`.toLowerCase().includes(v)))
/** The `software:` values of a query. */
export const softwareValues = (q: string) => parseQuery(q, DEVICE_KEYS).tokens.filter((t) => t.key === 'software' && t.value).map((t) => t.value!)

/** The risk words of the search, worst first (contract DevicesQuery.risk). */
export const RISKS = ['exploited', 'update', 'none'] as const

const DAY = 24 * 60 * 60 * 1000
export const APPROVED_WITHIN = { '24h': DAY, '7d': 7 * DAY } as const

/** Whether a row is of `type`: a type id, a category id, or the kind it acts as (`type:server` holds every server type). */
function isType(d: DeviceRow, type: string): boolean {
  const kind = shownKind(d).kind
  const want = lookupType(type) ?? type
  return kind === want || categoryOf(kind) === type || actsAs(kind) === want
}

const mac = (s: string) => s.toLowerCase().replace(/[^0-9a-f]/g, '')

/** The text one row is searched in. */
function haystack(d: DeviceRow): string {
  return [nameOf(d, kindLabel(d.kind)), d.hostname, d.ip, d.mac, d.vendor?.value, d.model?.value, d.os?.value].filter(Boolean).join(' ').toLowerCase()
}

/** Ids of the devices that may be the same machine as another (GET /inventory/possible-same), for `possible:same`. */
export type SameIds = ReadonlySet<string>
const NONE: SameIds = new Set()

function tokenMatch(d: DeviceRow, key: string, value: string | null, now: number, same: SameIds, matches?: SoftwareMatches): boolean {
  switch (key) {
    case 'type': return !!value && isType(d, value)
    case 'source': return feedsOfRow(d).has(value as SourceToken)
    case 'fragile': return d.fragile
    case 'suspicious': return d.suspicious
    case 'has': return value === 'findings' ? d.findings_count > 0 : value === 'software' ? d.software_count > 0 : value === 'ports' ? d.service_count > 0 : false
    case 'software': return !!value && matchSoftware(d, [value], matches).length > 0
    case 'possible': return value === 'same' && same.has(d.id)
    case 'risk': return (d.risk?.code ?? 'none') === value // the device statuses, none (GET /inventory/devices?risk= reads the same words)
    case 'approved': {
      const span = APPROVED_WITHIN[value as keyof typeof APPROVED_WITHIN]
      return !!span && !!d.approved_at && now - new Date(d.approved_at).getTime() < span
    }
    default: return true
  }
}

/** The rows a query keeps. `now`: when the list was read, so "approved in the last 24 h" does not move while the page is open.
 *  `matches`: the server's answer for the `software:` words (none yet: no row matches them). */
export function filterDevices(rows: DeviceRow[], q: string, now: number, same: SameIds = NONE, matches?: SoftwareMatches): DeviceRow[] {
  const p = parseQuery(q, DEVICE_KEYS)
  if (!p.text.length && !p.tokens.length) return rows
  const byKey = new Map<string, (string | null)[]>()
  for (const tk of p.tokens) byKey.set(tk.key, [...(byKey.get(tk.key) ?? []), tk.value])
  return rows.filter((d) => {
    const hay = haystack(d)
    const hayMac = d.mac ? mac(d.mac) : ''
    if (!p.text.every((w) => hay.includes(w) || (hayMac && mac(w).length >= 4 && hayMac.includes(mac(w))))) return false
    for (const [key, values] of byKey) if (!values.some((v) => tokenMatch(d, key, v, now, same, matches))) return false
    return true
  })
}

const t = (k: string, o?: Record<string, string>) => i18n.t(`inventory:search.${k}`, o)

/** The 12 software names most devices of the list have, for `software:` suggestions (#849): counted by the server over the list's
 *  devices (DevicesResponse.top_software), since the rows carry no software lines. */
const topSoftware = (top: SoftwareName[]): TokenValue[] => top.map((x) => ({ value: x.name.toLowerCase(), label: x.name, count: x.count }))

/** The keys, with the values offered for each counted over `rows` (only types some device has; every source, so `source:wazuh` is
 *  findable); `top`: the list's most common software names (DevicesResponse.top_software). */
export function deviceKeys(rows: DeviceRow[], now: number, same: SameIds = NONE, top: SoftwareName[] = []): TokenKey[] {
  const types = new Map<string, number>()
  const cats = new Map<string, number>()
  for (const d of rows) {
    const k = shownKind(d).kind
    types.set(k, (types.get(k) ?? 0) + 1)
    cats.set(categoryOf(k), (cats.get(categoryOf(k)) ?? 0) + 1)
  }
  const typeValues: TokenValue[] = [
    ...DEVICE_TYPES.filter((ty) => types.has(ty.id)).map((ty) => ({ value: ty.id, label: ty.label, count: types.get(ty.id) })),
    ...DEVICE_CATEGORIES.filter((c) => cats.has(c.id) && !types.has(c.id)).map((c) => ({ value: c.id, label: t('anyType', { category: categoryLabel(c.id) }), count: cats.get(c.id) })),
  ]
  const count = (key: string, value: string | null) => rows.filter((d) => tokenMatch(d, key, value, now, same)).length
  return [
    { key: 'type', label: t('key.type'), values: typeValues },
    { key: 'source', label: t('key.source'), values: SOURCES.map((s) => ({ value: s, label: t(`source.${s}`), count: count('source', s) })) },
    { key: 'fragile', label: t('key.fragile') },
    { key: 'has', label: t('key.has'), values: (['findings', 'software', 'ports'] as const).map((v) => ({ value: v, label: t(`has.${v}`), count: count('has', v) })) },
    // the software most devices run, as examples; any text still works (free)
    { key: 'software', label: t('key.software'), values: topSoftware(top), free: true },
    { key: 'suspicious', label: t('key.suspicious') },
    { key: 'approved', label: t('key.approved'), values: (['24h', '7d'] as const).map((v) => ({ value: v, label: t(`approved.${v}`), count: count('approved', v) })) },
    { key: 'possible', label: t('key.possible'), values: [{ value: 'same', label: t('possible.same'), count: count('possible', 'same') }] },
    { key: 'risk', label: t('key.risk'), values: RISKS.map((v) => ({ value: v, label: t(`risk.${v}`), count: count('risk', v) })) },
  ]
}

/** The keys without counts, for parsing (labels are not needed there). */
export const DEVICE_KEYS: TokenKey[] = [
  { key: 'type', label: 'type', values: [] }, { key: 'source', label: 'source', values: [] }, { key: 'fragile', label: 'fragile' },
  { key: 'has', label: 'has', values: [] }, { key: 'software', label: 'software', values: [], free: true }, { key: 'suspicious', label: 'suspicious' },
  { key: 'approved', label: 'approved', values: [] }, { key: 'possible', label: 'possible', values: [] },
  { key: 'risk', label: 'risk', values: [] },
]

/** The old Devices URLs (`?show=`, `?cat=`, the Software and Add devices tabs) as the new query (#849). */
export function fromOldUrl(params: URLSearchParams): URLSearchParams | null {
  const tab = params.get('tab')
  const show = params.get('show')
  const cat = params.get('cat')
  if (!show && !cat && !['all', 'software', 'add'].includes(tab ?? '')) return null
  const p = new URLSearchParams(params)
  const words: string[] = []
  if (show === 'recent') words.push('approved:24h')
  else if (show === 'manual') words.push('source:manual')
  else if (show === 'agent') words.push('source:osquery', 'source:wazuh')
  else if (show === 'fragile') words.push('fragile')
  if (cat) words.push(`type:${cat}`)
  if (tab === 'software') words.push('has:software') // the old Software tab: the devices with software, then software: narrows it
  if (words.length) p.set('q', [p.get('q'), ...words].filter(Boolean).join(' '))
  if (tab === 'add') p.set('add', p.get('add') ?? 'manual')
  if (tab === 'all' || tab === 'software' || tab === 'add') p.delete('tab')
  p.delete('show'); p.delete('cat')
  return p
}
