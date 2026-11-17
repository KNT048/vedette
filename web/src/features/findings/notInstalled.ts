// Inventory INV-41 (6), findings INV-6c: marking a row a scan, SNMP or an agent reported as not installed closes the open findings only
// that row produced, in the same request. The toast says what actually happened: how many closed, and why any stayed open (a scan
// confirmed it, a person reopened it or accepted its risk after the mark, or another source still reports the software). The same
// helper serves Needs your input and the device's Software tab.
import type { TFunction } from 'i18next'
import { useDeviceAction } from '@/features/inventory/api'
import { api } from '@/lib/api'
import type { FindingRow } from './types'

export type NotInstalledOutcome = { closed: number; scanned: number; reopened: number; accepted: number; other: number }

/** The sentence findings writes on a finding a person kept open on a row they said is not installed (findings INV-6c). */
const KEPT = 'This finding stays open because a person reopened it or accepted its risk'

/** Why a finding stayed open: a person's newest reopen or acceptance when findings says a person kept it, else another source. */
export function keptBy(f: Pick<FindingRow, 'history'>): 'reopened' | 'accepted' | 'other' {
  if (!f.history.some((h) => h.note?.includes(KEPT))) return 'other'
  const last = f.history.filter((h) => h.user !== 'system' && (h.action === 'reopened' || h.action === 'risk_accepted')).at(-1)
  return last?.action === 'risk_accepted' ? 'accepted' : 'reopened'
}

const OPEN = new Set(['confirmed', 'suspected'])
const deviceFindings = (assetId: string) => api.get<{ items: FindingRow[] }>(`/findings?asset=${encodeURIComponent(assetId)}`).then((r) => r.items)

/** Marks the row and compares the device's open findings on its CVEs before and after. */
export function useNotInstalled(assetId: string) {
  const act = useDeviceAction(assetId)
  const mark = async (sw: { id: string; kev_cves?: string[] }): Promise<NotInstalledOutcome> => {
    const cves = new Set(sw.kev_cves ?? [])
    const before = await deviceFindings(assetId).catch(() => [] as FindingRow[])
    const open = before.filter((f) => OPEN.has(f.status) && cves.has(f.cve)).map((f) => f.id)
    await act.notInstalled.mutateAsync(sw.id)
    const after = new Map((await deviceFindings(assetId).catch(() => [] as FindingRow[])).map((f) => [f.id, f]))
    const out: NotInstalledOutcome = { closed: 0, scanned: 0, reopened: 0, accepted: 0, other: 0 }
    for (const id of open) {
      const f = after.get(id)
      if (!f || !OPEN.has(f.status)) out.closed++
      else if (f.basis === 'scan') out.scanned++
      else out[keptBy(f)]++
    }
    return out
  }
  return { mark, isPending: act.notInstalled.isPending }
}

/** "OpenSSH is marked not installed on router-1. 2 findings closed. 1 stays open: a scan confirmed it." */
export function notInstalledText(t: TFunction, software: string, device: string, o: NotInstalledOutcome) {
  return [
    t('findings:notInstalled.done', { software, device }),
    o.closed ? t('findings:notInstalled.closed', { count: o.closed }) : o.scanned || o.reopened || o.accepted || o.other ? '' : t('findings:notInstalled.none'),
    o.scanned ? t('findings:notInstalled.keptScan', { count: o.scanned }) : '',
    o.reopened ? t('findings:notInstalled.keptReopened', { count: o.reopened }) : '',
    o.accepted ? t('findings:notInstalled.keptAccepted', { count: o.accepted }) : '',
    o.other ? t('findings:notInstalled.keptOther', { count: o.other }) : '',
  ].filter(Boolean).join(' ')
}
