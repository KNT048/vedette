// S-INV-2: a device added by hand, from CSV or by an agent is matched right away against the exploited-CVE list
// (mock: the recent KEV fixture). The mock has no affected-version ranges, so a software with a version gets
// "suspected, product only" (basis 'product', severity medium: the version was not compared, D-500) and never
// "confirmed"; a scan or the vendor advisory decides. A software WITHOUT a usable version gets no finding at all:
// it is one "add the version" item (versionNeeded, D-500). Adds only, never removes.
import kev from './fixtures/kev.json'
import { newId, nowIso } from './db'
import { assetsStore, findingsStore } from './stores'
import type { Asset, Finding } from '@/lib/types'

interface Kev { cve: string; vendor: string; product: string; ransomware: boolean; epss: number }
const vulns = (kev as { vulns: Kev[] }).vulns

type Sw = Asset['software'][number]
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
  const name = a.hostname ?? a.ip
  const fresh: Finding[] = []
  for (const v of vulns) {
    if (have.has(v.cve)) continue
    const multi = /^multiple products$/i.test(v.product)
    const s = a.software.find((x) => usableVersion(x.version) && keyed(x, v))
    if (!s) continue
    have.add(v.cve)
    const sw = `${s.display} ${s.version}`
    fresh.push({
      id: newId('f'), asset_id: a.id, cve: v.cve, status: 'suspected', severity: 'medium',
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

/** D-500: per device, each software on the exploited list with no usable version, and how many CVEs its version would decide. */
export function versionNeeded(assetId?: string | null) {
  const out: { asset: Asset; software: Sw; cves: number }[] = []
  for (const a of assetsStore.get()) {
    if (assetId && a.id !== assetId) continue
    for (const s of a.software) {
      if (usableVersion(s.version)) continue
      const cves = vulns.filter((v) => keyed(s, v)).length
      if (cves > 0) out.push({ asset: a, software: s, cves })
    }
  }
  return out.sort((x, y) => y.cves - x.cves)
}
