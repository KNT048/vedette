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
  useEffect(() => {
    if (until <= Date.now()) return
    const id = setInterval(() => setNow(Date.now()), 250)
    return () => clearInterval(id)
  }, [until])
  const start = useCallback((seconds: number) => { setNow(Date.now()); setUntil(Date.now() + seconds * 1000) }, [])
  return { left: Math.max(0, Math.ceil((until - now) / 1000)), start }
}

/** The seconds a rate_limited answer asks to wait ("The next check is allowed in 12 seconds"), or the whole pause when it says none. */
export function secondsToWait(e: unknown): number {
  const code = (e as { code?: string } | null)?.code
  if (code !== 'rate_limited') return 0
  const m = /(\d+)\s+seconds?/.exec(e instanceof Error ? e.message : '')
  return m ? Number(m[1]) : checkPause.seconds
}
