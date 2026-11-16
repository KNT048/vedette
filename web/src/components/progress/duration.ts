import type { TFunction } from 'i18next'

/** A duration as the progress component says it: "45 s", "2 min 10 s", "12 min", "1 h 5 min". Seconds are dropped from 10 minutes on. */
export function sayDuration(t: TFunction<'progress'>, ms: number): string {
  const sec = Math.max(0, Math.floor(ms / 1000))
  if (sec < 60) return t('time.s', { s: sec })
  const m = Math.floor(sec / 60)
  if (m < 10) return sec % 60 ? t('time.ms', { m, s: sec % 60 }) : t('time.m', { m })
  if (m < 60) return t('time.m', { m })
  return t('time.hm', { h: Math.floor(m / 60), m: m % 60 })
}
