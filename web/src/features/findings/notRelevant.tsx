import { useModuleEnabled } from '@/lib/modules'
import { useDeviceCards } from './api'
import { PAGE_MAX } from './contract'

// Open-finding counts for pages outside the Findings screen, from the By device cards (GET /findings/devices): the same numbers
// the Findings screen and the device's Findings tab show. A finding closed as not relevant is handled, so it is never counted.

/** One device's open findings and their CVEs; undefined while loading, off or failed. */
export function useDeviceFindingCounts(assetId: string): { open: number; cves: string[] } | undefined {
  const on = useModuleEnabled('findings')
  const q = useDeviceCards({ device: assetId }, { offset: 0, limit: 1 }, on === true)
  if (on !== true || !q.data) return undefined
  const card = q.data.items.find((c) => c.device.id === assetId)
  if (!card) return { open: 0, cves: [] }
  return { open: card.findings, cves: [...new Set(card.blocks.flatMap((b) => b.findings.map((f) => f.cve)))] }
}

/** Open findings per device: what a "N findings" link that opens the findings of a device must count. The most urgent devices
 *  first, at most one page of By device (PAGE_MAX devices); undefined while loading or off. */
export function useOpenFindingsByAsset(enabled: boolean): Map<string, number> | undefined {
  const q = useDeviceCards({}, { offset: 0, limit: PAGE_MAX }, enabled)
  if (!enabled || !q.data) return undefined
  return new Map(q.data.items.map((c) => [c.device.id, c.findings]))
}
