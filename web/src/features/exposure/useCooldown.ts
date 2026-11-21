import { useCallback, useEffect, useState } from 'react'

/** The seconds of the pause the box keeps between two ownership checks of one target (tests shorten it, as scanPoll). */
export const checkPause = { seconds: 30 }

/**
 * A countdown for a button that may be pressed again only after a pause: `left` is the whole seconds still to wait (0: free), `start(n)` begins
 * a pause of n seconds. The box enforces the pause (429 rate_limited says the seconds left); this only shows it.
 */
export function useCooldown() {
  const [until, setUntil] = useState(0)
  const [now, setNow] = useState(() => Date.now())
  // The tick keeps `now` moving until the pause is over, then stops. It must start even when the pause has already ended by the time the
  // effect runs (a zero-second pause, or a slow render): otherwise `now` stays behind `until` and the button would wait for ever.
  useEffect(() => {
    if (until === 0) return
    const id = setInterval(() => { const n = Date.now(); setNow(n); if (n >= until) clearInterval(id) }, 250)
    return () => clearInterval(id)
  }, [until])
  // `now` and `until` come from one reading of the clock, so start(0) is exactly free
  const start = useCallback((seconds: number) => { const n = Date.now(); setNow(n); setUntil(n + seconds * 1000) }, [])
  return { left: Math.max(0, Math.ceil((until - now) / 1000)), start }
}

/** The seconds a rate_limited answer asks to wait ("The next check is allowed in 12 seconds"), or the whole pause when it says none. */
export function secondsToWait(e: unknown): number {
  const code = (e as { code?: string } | null)?.code
  if (code !== 'rate_limited') return 0
  const m = /(\d+)\s+seconds?/.exec(e instanceof Error ? e.message : '')
  return m ? Number(m[1]) : checkPause.seconds
}
