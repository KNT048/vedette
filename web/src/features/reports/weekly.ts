// The assessment's finding rows from the shared stores (assetsStore, findingsStore) and the real KEV, for the PDPL mock (pdpl.ts).
import kev from '@/mocks/fixtures/kev.json'
import { assetsStore } from '@/mocks/stores'
import type { Finding } from '@/lib/types'
import { displayOf } from '@/features/feeds/slug'
import type { FindingRow } from './types'

interface Kev { cve: string; vendor: string; product: string; date_added: string }
const data = kev as { generated_at: string; vulns: Kev[] }

export const vulnOf = (cve: string) => data.vulns.find((v) => v.cve === cve)

export function rowOf(f: Finding): FindingRow {
  const a = assetsStore.get().find((x) => x.id === f.asset_id)
  const v = vulnOf(f.cve)
  return { id: f.id, cve: f.cve, device: a?.name ?? a?.hostname ?? a?.ip ?? f.asset_id, asset_id: f.asset_id, product: v ? displayOf(v.vendor, v.product) : f.cve, status: f.status, severity: f.severity, since: f.first_seen, ...(f.evidence?.agent ? { agent: true } : {}), device_approved: a?.approved !== false }
}

export const EOL_OS = /windows 10|server 2016/i
