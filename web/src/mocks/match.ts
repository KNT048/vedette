// S-INV-2: a device added by hand, from CSV or by an agent is matched right away against the exploited-CVE list
// (mock: the recent KEV fixture). The mock has no affected-version ranges, so every match is "suspected, product
// only" (basis 'product') and never "confirmed"; a scan or the vendor advisory decides. Adds only, never removes.
import kev from './fixtures/kev.json'
import { newId, nowIso } from './db'
import { assetsStore, findingsStore } from './stores'
import type { Finding } from '@/lib/types'

interface Kev { cve: string; vendor: string; product: string; ransomware: boolean; epss: number }
const vulns = (kev as { vulns: Kev[] }).vulns

export function matchAssetToKev(assetId: string): number {
  const a = assetsStore.get().find((x) => x.id === assetId)
  if (!a) return 0
  const have = new Set(findingsStore.get().filter((f) => f.asset_id === a.id).map((f) => f.cve))
  const now = nowIso()
  const name = a.hostname ?? a.ip
  const fresh: Finding[] = []
  for (const v of vulns) {
    if (have.has(v.cve)) continue
    const multi = /^multiple products$/i.test(v.product)
    const vendor = `${v.vendor}|`.toLowerCase()
    const key = `${v.vendor}|${v.product}`.toLowerCase()
    const s = a.software.find((x) => (multi ? x.kev.some((k) => k.startsWith(vendor)) : x.kev.includes(key)))
    if (!s) continue
    have.add(v.cve)
    const sw = `${s.display}${s.version ? ` ${s.version}` : ''}`
    fresh.push({
      id: newId('f'), asset_id: a.id, cve: v.cve, status: 'suspected', severity: v.ransomware || v.epss >= 0.5 ? 'critical' : 'high',
      confidence: multi ? 0.3 : 0.5, basis: 'product',
      evidence: {
        summary: multi
          ? `${name} runs ${sw}. CISA lists this flaw for several ${v.vendor} products; check the advisory to see whether yours is one of them.`
          : `${name} runs ${sw}. Vedette has not checked whether this version is in the affected range; compare it with the vendor advisory or run a scan.`,
        checked_at: now,
      },
      first_seen: now, last_seen: now, resolved_by: null, resolved_at: null, resolution_note: null,
      history: [{ ts: now, user: 'system', action: 'created', note: `Matched product ${s.display}` }],
    })
  }
  if (fresh.length) findingsStore.update((l) => [...fresh, ...l])
  return fresh.length
}
