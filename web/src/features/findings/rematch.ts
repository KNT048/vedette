// "I updated <software>" (D-499, S-MIT-1): save the new version through inventory, then read the device's findings
// until the re-match (inventory.match.changed on the event bus) shows, and say what it closed.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { DeviceDetail, SoftwareView } from '@/features/inventory/types'
import { isOpen } from './basis'
import type { FindingRow, VersionNeeded } from './types'

/** Reads of the findings list after the save, and the pause between them: about 6 s in all (D-499). */
export const POLLS = 12
export const POLL_MS = 500

/** The device's software, read from inventory's device API (its own key under 'findings', so a findings change refreshes it). */
export const useDeviceSoftware = (assetId: string | undefined) =>
  useQuery({
    queryKey: ['findings', 'software', assetId ?? ''],
    queryFn: () => api.get<DeviceDetail>(`/inventory/devices/${encodeURIComponent(assetId ?? '')}`),
    enabled: !!assetId, retry: false,
  })

/** The software a CVE was matched to: the rows whose KEV keys give it. Empty when none does (an alias or CPE match). */
export const softwareFor = (sw: SoftwareView[] | undefined, cve: string) => (sw ?? []).filter((s) => s.kev_cves.includes(cve))

export type Outcome = { settled: boolean; closed: number; still: number }

/** Whether the re-match has run: a finding of this software changed, or a new one appeared (it touches last_seen of every match). */
export function settled(before: FindingRow[], after: FindingRow[], cves: Set<string>): boolean {
  const old = new Map(before.map((f) => [f.id, f]))
  return after.some((f) => {
    if (!cves.has(f.cve)) return false
    const b = old.get(f.id)
    return !b || b.status !== f.status || b.last_seen !== f.last_seen || b.history.length !== f.history.length
  })
}

/** closed = open before and closed now, on the whole device; still = open findings of this software's CVEs now. */
export function outcome(before: FindingRow[], after: FindingRow[], cves: Set<string>, done: boolean): Outcome {
  const now = new Map(after.map((f) => [f.id, f]))
  const closed = before.filter((f) => isOpen(f.status) && now.has(f.id) && !isOpen(now.get(f.id)!.status)).length
  const still = after.filter((f) => isOpen(f.status) && cves.has(f.cve)).length
  return { settled: done, closed, still }
}

type List = { items: FindingRow[]; version_needed: VersionNeeded[] }
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms))

/** PATCH the version (inventory INV-26 (3)), then re-read the device's findings until the re-match shows, at most POLLS times. */
export function useSetVersion(assetId: string) {
  const qc = useQueryClient()
  const list = () => api.get<List>(`/findings?asset=${encodeURIComponent(assetId)}`).then((d) => d.items)
  return useMutation({
    mutationFn: async ({ sid, version, cves }: { sid: string; version: string; cves: string[] }): Promise<Outcome> => {
      const set = new Set(cves)
      const before = await list()
      await api.patch(`/inventory/devices/${encodeURIComponent(assetId)}/software/${encodeURIComponent(sid)}`, { version })
      let after = before
      try {
        for (let i = 0; i < POLLS; i++) {
          if (i > 0) await wait(POLL_MS)
          after = await list()
          if (settled(before, after, set)) return outcome(before, after, set, true)
        }
      } catch { /* the version is saved; a failed read only means the page says "checking" and refreshes later */ }
      return outcome(before, after, set, false)
    },
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: ['findings'] })
      void qc.invalidateQueries({ queryKey: ['inventory'] })
    },
  })
}
