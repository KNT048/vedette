import { useQuery } from '@tanstack/react-query'
import type { z } from 'zod'
import { api } from '@/lib/api'
import type { Overview } from '@/features/findings/types'
import { OPEN_FINDING_STATUSES } from '@/lib/statusCodes'
import type { Scanning } from '@/features/scanning/contract'

/** The one overview read of the findings model, shared with the nav badges (app/nav.ts). */
export const KEY = ['findings', 'model', 'overview'] as const

/**
 * Home's one read: `GET /findings/overview`, computed on the box by the same status function as the Findings screen's lists, so
 * Home's counts are that screen's counts. The shell is the one poller (every 60 s, paused in a hidden tab, stopped on error); Home
 * only subscribes. A finding change invalidates every `findings` read (findings/api.ts), so the page is fresh after one.
 */
export function useHome(enabled: boolean) {
  return useQuery({ queryKey: KEY, queryFn: () => api.get<Overview>('/findings/overview'), enabled, staleTime: 60_000, retry: false })
}

/** A box with no device but itself and nothing open: Home shows the first-run path instead of tiles of zeros. */
export const isFirstRun = (o: Overview) => o.devices.total <= 1 && o.open.findings === 0

/** Devices with an open finding: each is counted once, under its most urgent status, the Vedette box included (it carries no badge,
 *  but "3 open findings on 0 devices" next to its three findings was wrong). */
export const affectedDevices = (o: Overview) => OPEN_FINDING_STATUSES.reduce((n, s) => n + o.devices.affected[s], 0)

/** Devices whose most urgent finding is one attackers use: under attack here, or exploited in the wild (the box included). */
export const exploitedDevices = (o: Overview) => o.devices.affected.under_attack + o.devices.affected.exploited

export const SCANNING_KEY = ['scanning'] as const

/** `GET /scanning` (#850): the scope ranges, the discovery engine's next window and the runs going on. The first-run step reads it to
 *  say whether a range is set and when it is scanned; the range dialog reads the same key, so one request serves both. */
export function useScanning(enabled: boolean) {
  return useQuery({ queryKey: SCANNING_KEY, queryFn: () => api.get<z.infer<typeof Scanning>>('/scanning'), enabled, retry: false })
}
