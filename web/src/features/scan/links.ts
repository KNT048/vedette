/** 1 = Monday … 7 = Sunday. */
export const DAY_ORDER = [1, 2, 3, 4, 5, 6, 7]

/** Where the history of a run opens (Settings › Scanning, #850). */
export const runHref = (id: string) => `/settings/scanning?tab=history&run=${encodeURIComponent(id)}`
