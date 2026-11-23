import { useEffect, useState } from 'react'

/** Count down by the second (the "resend code" button). `start(n)` resets; it follows the clock so it does not drift when the tab sleeps. */
export function useCountdown() {
  const [until, setUntil] = useState(0)
  const [left, setLeft] = useState(0)
  useEffect(() => {
    if (!until) return
    const tick = () => { const s = Math.max(0, Math.ceil((until - Date.now()) / 1000)); setLeft(s); if (s === 0) setUntil(0) }
    tick()
    const id = setInterval(tick, 500)
    return () => clearInterval(id)
  }, [until])
  return { left, start: (seconds: number) => setUntil(Date.now() + seconds * 1000) }
}
