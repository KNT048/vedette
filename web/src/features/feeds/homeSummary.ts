import { useQuery } from '@tanstack/react-query'
import type { z } from 'zod'
import { api } from '@/lib/api'
import type { HomeSummary } from '@/features/findings/types'
import type { Scanning } from '@/features/scanning/contract'

export const KEY = ['findings', 'summary'] as const

/**
 * Home's one read (#825, INV-23): the cached `GET /findings/summary` under the query key the shell's nav badges share (app/nav.ts). The
 * shell is the one poller (every 60 s, paused in a hidden tab, stopped on error); Home only subscribes: a second timer would ask twice a
 * minute. `staleTime` matches the box's 60 s cache, so going back to Home asks nothing new. Finding changes invalidate the key
 * (findings/api.ts useWrite, useBulkStatus), so the page is fresh after a status change.
 */
export function useHome(enabled: boolean) {
  return useQuery({ queryKey: KEY, queryFn: () => api.get<HomeSummary>('/findings/summary'), enabled, staleTime: 60_000, retry: false })
}

/** A box with no device but itself and nothing open: Home shows the first-run path instead of tiles of zeros. */
export const isFirstRun = (s: HomeSummary) => s.devices.total <= 1 && s.open.total === 0

export const SCANNING_KEY = ['scanning'] as const

/** `GET /scanning` (#850): the scope ranges, the discovery engine's next window and the runs going on. The first-run step reads it to
 *  say whether a range is set and when it is scanned; the range dialog reads the same key, so one request serves both. */
export function useScanning(enabled: boolean) {
  return useQuery({ queryKey: SCANNING_KEY, queryFn: () => api.get<z.infer<typeof Scanning>>('/scanning'), enabled, retry: false })
}
