import { useEffect, useState, useSyncExternalStore } from 'react'
import { useTranslation } from 'react-i18next'
import { useQueryClient } from '@tanstack/react-query'
import { Button } from '@/components/ui/button'
import { api } from '@/lib/api'
import type { SetupStatus } from './types'
import { nav } from './util'

// S-CORE-1 (A13-4): Delete all data makes the box restart. From the purge answer on, the app is replaced by this page so
// nothing fires API calls (they would answer 401 for ~20 s) until the box is back and says first-run setup is open.
let active = false
let keptNow: string[] = []
const subs = new Set<() => void>()
/** kept: what the box could not delete; said on the waiting page (nothing else may fire while the administrator reads it). */
export const beginBoxRestart = (kept: string[] = []) => { active = true; keptNow = kept; subs.forEach((f) => f()) }
export const resetBoxRestart = () => { active = false; subs.forEach((f) => f()) }
export function useBoxRestarting() {
  return useSyncExternalStore((f) => { subs.add(f); return () => { subs.delete(f) } }, () => active)
}

/** Backoff start (ms); a test sets 0 so it does not sleep. */
export const restartWait = { firstMs: 1000 }
const GIVE_UP_MS = 180_000
const nextDelay = (ms: number) => Math.min(ms * 2, 5000)

/** Full-page waiting state. Polls GET /setup with backoff (state-based: it moves on only when the box says setup is open). */
export function BoxRestarting() {
  const { t } = useTranslation('core')
  const qc = useQueryClient()
  const [gaveUp, setGaveUp] = useState(false)
  const kept = keptNow
  useEffect(() => {
    void qc.cancelQueries()
    qc.clear()
    let stop = false
    let timer: ReturnType<typeof setTimeout> | undefined
    const started = Date.now()
    const poll = async (delay: number) => {
      let open = false
      try { open = !(await api.get<SetupStatus>('/setup')).complete } catch { /* the box is down or restarting: keep waiting */ }
      if (stop) return
      if (open) { nav.toSetup(); return }
      if (Date.now() - started > GIVE_UP_MS) { setGaveUp(true); return }
      timer = setTimeout(() => void poll(nextDelay(delay)), delay)
    }
    void poll(restartWait.firstMs)
    return () => { stop = true; clearTimeout(timer) }
  }, [qc])
  const wait = gaveUp ? (
    <>
      <p role="alert" className="text-sm">{t('data.purge.restarting.slow')}</p>
      <div><Button variant="primary" onClick={() => nav.reload()}>{t('data.purge.restarting.reload')}</Button></div>
    </>
  ) : (
    <>
      <p role="status" className="text-base font-medium">{t('data.purge.restarting.title')}</p>
      <p className="text-[13px] text-muted">{t('data.purge.restarting.body')}</p>
    </>
  )
  return (
    <main className="fixed inset-0 z-50 grid place-items-center bg-canvas p-6 text-center" aria-live="polite">
      {kept.length > 0 ? (
        <div role="dialog" aria-label={t('data.purge.done.title')} className="grid max-w-lg gap-3 rounded-md border border-rule bg-surface p-5 text-left">
          <h2 className="text-base font-medium">{t('data.purge.done.title')}</h2>
          <p className="text-sm">{t('data.purge.done.body')}</p>
          <ul className="list-disc pl-5 text-sm">{kept.map((k) => <li key={k}>{t(`data.purge.done.kept.${k}`)}</li>)}</ul>
          {wait}
          <div><Button variant="danger" onClick={() => nav.toSetup()}>{t('data.purge.done.continue')}</Button></div>
        </div>
      ) : <div className="grid max-w-md gap-3">{wait}</div>}
    </main>
  )
}
