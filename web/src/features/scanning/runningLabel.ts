import type { TFunction } from 'i18next'

/** "2 scans running", "1 scan running, 2 queued" or "1 scan queued": the runs going on and the runs that wait for the scanner, apart. */
export function runningLabel(t: TFunction, jobs: ReadonlyArray<{ queued: boolean }>): string {
  const queued = jobs.filter((j) => j.queued).length
  const going = jobs.length - queued
  if (going === 0) return t('scanning:running.queuedOnly', { count: queued })
  if (queued === 0) return t('scanning:running.count', { count: going })
  return t('scanning:running.countAndQueued', { count: going, queued })
}
