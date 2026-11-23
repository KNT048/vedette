// S-INV-2: a device added by hand, from CSV or by an agent is matched right away against the exploited-CVE list
// (mock: the recent KEV fixture). The mock has no affected-version ranges, so a software with a version gets
// "suspected, product only" (basis 'product', severity medium: the version was not compared) and never
// "confirmed"; a scan or the vendor advisory decides. A software WITHOUT a usable version gets no finding at all.
// Adds only, never removes.
import kev from './fixtures/kev.json'
import { newId, nowIso } from './db'
import { assetsStore, findingsStore } from './stores'
import { kevAged } from './tiers'
import type { Asset, Finding } from '@/lib/types'

interface Kev { cve: string; vendor: string; product: string; ransomware: boolean; epss: number; has_template: boolean; date_added: string }
const vulns = (kev as { vulns: Kev[] }).vulns

type Sw = Asset['software'][number]
/** INV-41: the rows matching reads: a reported row a person corrected is replaced by the correction; a "not installed" correction
 *  (INV-41 (6)) replaces it with nothing. */
export const liveSoftware = (a: Asset): Sw[] => a.software.filter((s) => !s.not_installed && !a.software.some((c) => c.corrects === s.id))
/** Mirrors the Go matcher's versionKnown: empty, an all-zero placeholder ("0.0") or text without a number is no version. */
export const usableVersion = (v: string | null) => !!v && /\d/.test(v) && !/^[0.\s]+$/.test(v)

function keyed(s: Sw, v: Kev): boolean {
  const multi = /^multiple products$/i.test(v.product)
  const vendor = `${v.vendor}|`.toLowerCase()
  const key = `${v.vendor}|${v.product}`.toLowerCase()
  return multi ? s.kev.some((k) => k.startsWith(vendor)) : s.kev.includes(key)
}

export function matchAssetToKev(assetId: string): number {
  const a = assetsStore.get().find((x) => x.id === assetId)
  if (!a) return 0
  const have = new Set(findingsStore.get().filter((f) => f.asset_id === a.id).map((f) => f.cve))
  const now = nowIso()
  const name = a.name ?? a.hostname ?? a.ip // the name in Vedette first
  const fresh: Finding[] = []
  for (const v of vulns) {
    if (have.has(v.cve)) continue
    if (kevAged(v.cve, v.date_added) && !v.has_template) continue // An older KEV CVE is not a finding on a product-only match (the mock has no ranges)
    const multi = /^multiple products$/i.test(v.product)
    const s = liveSoftware(a).find((x) => usableVersion(x.version) && keyed(x, v))
    if (!s) continue
    have.add(v.cve)
    const sw = `${s.display} ${s.version}`
    fresh.push({
      id: newId('f'), asset_id: a.id, cve: v.cve, status: 'suspected', severity: 'medium',
      confidence: multi ? 0.3 : 0.5, basis: 'product',
      evidence: {
        summary: multi
          ? `${name} runs ${sw}. CISA lists this flaw for several ${v.vendor} products; check the advisory to see whether yours is one of them.`
          : `${name} runs ${sw}. NVD lists no affected versions for ${v.cve} yet, so Vedette cannot tell whether this version is affected; compare it with the vendor advisory.`,
        checked_at: now,
      },
      first_seen: now, last_seen: now, resolved_by: null, resolved_at: null, resolution_note: null,
      history: [{ ts: now, user: 'system', action: 'created', note: `Matched product ${s.display}` }],
    })
  }
  if (fresh.length) findingsStore.update((l) => [...fresh, ...l])
  return fresh.length
}

/** The note of a finding closed because a person said its software is not installed (findings INV-6c, NotInstalledNote). */
export const NOT_INSTALLED_NOTE = 'Closed: a person said the software is not installed.'

/** Findings INV-6c: the open suspected findings that only `sw` (a row a person said is not installed) produced close, the person named;
 *  a finding another live row still produces stays. No notice. */
export function closeNotInstalled(assetId: string, sw: Sw, who: string): number {
  const a = assetsStore.get().find((x) => x.id === assetId)
  if (!a) return 0
  const live = liveSoftware(a)
  const now = nowIso()
  const day = new Date(now).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' })
  const note = `${NOT_INSTALLED_NOTE} ${who || 'a person'} said ${[sw.display, sw.version].filter(Boolean).join(' ')} (${sw.source}) is not installed on ${a.name ?? a.hostname ?? a.ip} (${day}).`
  let n = 0
  findingsStore.update((l) => l.map((f) => {
    if (f.asset_id !== a.id || f.status !== 'suspected') return f
    const v = vulns.find((x) => x.cve === f.cve)
    if (!v || !keyed(sw, v) || live.some((s) => keyed(s, v))) return f
    n++
    return { ...f, status: 'not_relevant', resolved_by: 'system', resolved_at: now, resolution_note: note, history: [...f.history, { ts: now, user: 'system', action: 'not_relevant', note }] }
  }))
  return n
}

/** INV-6c: a finding closed for "Not installed" whose CVE a live row produces again (the person cleared it, or said what is installed)
 *  reopens. */
export function reopenNotInstalled(assetId: string): number {
  const a = assetsStore.get().find((x) => x.id === assetId)
  if (!a) return 0
  const live = liveSoftware(a)
  const now = nowIso()
  let n = 0
  findingsStore.update((l) => l.map((f) => {
    if (f.asset_id !== a.id || f.status !== 'not_relevant' || f.resolved_by !== 'system' || !f.resolution_note?.startsWith(NOT_INSTALLED_NOTE)) return f
    const v = vulns.find((x) => x.cve === f.cve)
    if (!v || !live.some((s) => keyed(s, v))) return f
    n++
    return { ...f, status: 'suspected', resolved_by: null, resolved_at: null, resolution_note: null,
      history: [...f.history, { ts: now, user: 'system', action: 'matches_again', note: 'The device matches this entry again, so Vedette reopened it (it had closed it because a person said the software is not installed).' }] }
  }))
  return n
}
