import { beforeEach, describe, expect, it } from 'vitest'
import { assetsStore, findingsStore } from '@/mocks/stores'
import { buildPdpl } from './pdpl'
import { DEFAULT_FILTERS, FILTERS_KEY, pdplView } from './filters'
import type { PdplOrg } from './types'

// The assessment's switch over devices not in the Devices list (not approved yet; in by default). The security report keeps the
// same choices in its saved settings instead (reports.test.tsx).

function seed(rows: { id: string; asset: string; status: 'not_relevant' | 'confirmed' }[]) {
  const tpl = findingsStore.get()[0]!
  const now = new Date().toISOString()
  findingsStore.set([...findingsStore.get(), ...rows.map((r, i) => ({ ...tpl, id: r.id, asset_id: r.asset, cve: `CVE-2026-7100${i}`, status: r.status, first_seen: now, resolved_at: null }))])
}
const unapprovedAsset = () => assetsStore.get().find((a) => !a.approved)!.id

beforeEach(() => { try { localStorage.removeItem(FILTERS_KEY) } catch { /* none */ } })

describe('assessment include switch: the view', () => {
  it('the assessment leaves the devices out of its inventory and risks; its unapproved measure stays', () => {
    const org: PdplOrg = { name: 'Acme', tax_code: '', address: '', sector: '', employees: 5, data_volume: 'lt1k', size: 'micro', processing_service: false,
      contact_name: '', contact_email: '', contact_phone: '', sensitive: false, cross_border: false, processors: false, level: '' }
    seed([{ id: 'un-2', asset: unapprovedAsset(), status: 'confirmed' }])
    const full = buildPdpl(org)
    const { report, left } = pdplView(full, { unapproved: false, notRelevant: false })
    expect(left).toEqual({ devices: full.inventory.unapproved })
    expect(report.inventory.total).toBe(full.inventory.approved)
    expect(report.risks.some((f) => f.id === 'un-2')).toBe(false)
    expect(report.measures.find((m) => m.id === 'unapproved')).toEqual(full.measures.find((m) => m.id === 'unapproved'))
    expect(pdplView(full, DEFAULT_FILTERS).report).toBe(full)
  })
})
