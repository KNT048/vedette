import type { ScanTarget } from './types'

/** The most targets of one run (contract.ts POST /scans/runs, scan errTooMany). */
export const MAX_TARGETS = 200

/** 1 = Monday … 7 = Sunday (D-57). */
export const DAY_ORDER = [1, 2, 3, 4, 5, 6, 7]

/** Where the history of a run opens (Settings › Scanning, #850). */
export const runHref = (id: string) => `/settings/scanning?tab=history&run=${encodeURIComponent(id)}`

/** "Scan the LAN now": the devices a sweep may take without a person's own tick (D-126 (2), D-470: never the box, never a
 *  fragile, unclassified or hand-added device). The server resolves the same list; this only sends their ids. */
export const lanTargets = (all: ScanTarget[]) => all.filter((x) => x.kind === 'internal' && x.selectable && !x.pick_only && !x.box).map((x) => x.id).slice(0, MAX_TARGETS)
