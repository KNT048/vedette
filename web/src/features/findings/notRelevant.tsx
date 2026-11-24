import { useModuleEnabled } from '@/lib/modules'
import { useDeviceCards, useOpenFindingsOf } from './api'

// Open-finding counts for pages outside the Findings screen, from the By device cards (GET /findings/devices): the same numbers
// the Findings screen and the device's Findings tab show. A finding closed as not relevant is handled, so it is never counted.

/** One device's open findings and their CVEs, and those a restart fixes (the fixed kernel is installed: `restartTo` names it);
 *  undefined while loading, off or failed. */
export function useDeviceFindingCounts(assetId: string): { open: number; cves: string[]; restart: number; restartTo: string | null } | undefined {
  const on = useModuleEnabled('findings')
  const q = useDeviceCards({ device: assetId }, { offset: 0, limit: 1 }, on === true)
  if (on !== true || !q.data) return undefined
  const card = q.data.items.find((c) => c.device.id === assetId)
  if (!card) return { open: 0, cves: [], restart: 0, restartTo: null }
  const restarts = card.blocks.filter((b) => b.fix.kind === 'restart')
  return {
    open: card.findings, cves: [...new Set(card.blocks.flatMap((b) => b.findings.map((f) => f.cve)))],
    restart: restarts.reduce((n, b) => n + b.findings.length, 0), restartTo: restarts[0]?.fix.version ?? null,
  }
}

/** Open findings of these devices: what a "N findings" link that opens the findings of a device must count, exact for any number
 *  of devices (a device with none is not in the map); undefined while loading or off. */
export function useOpenFindingsByAsset(ids: readonly string[], enabled: boolean): Map<string, number> | undefined {
  const q = useOpenFindingsOf(ids, enabled)
  if (!enabled) return undefined
  if (ids.length === 0) return new Map()
  return q.data
}
