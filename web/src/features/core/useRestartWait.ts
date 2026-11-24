import { useEffect, useState } from 'react'
import { useLocation, useNavigate } from 'react-router'
import { useQueryClient } from '@tanstack/react-query'
import { ApiError } from '@/lib/api'

/**
 * The one waiting rule of every page that follows a run during which Vedette restarts (a software update or its rollback, a
 * restore of a kept backup or of a file, the first-run restore). The page keeps polling the read of its own run, and each
 * answer says where the box is:
 * - an answer: the box is up and this browser is still signed in; the run's own status says when it is done;
 * - 401: the box is up, but this browser's session is gone (a restore brings back the accounts and sessions of the backup):
 *   the run is over, and nothing this page polls will ever answer again. The person is taken to sign in, where the page says
 *   why, and comes back here after;
 * - anything else (no connection, a 5xx while it starts, a certificate the browser no longer accepts): still restarting,
 *   keep polling and say so; after `slowMs` the page also offers a reload.
 */
export type BoxAnswer = 'up' | 'signedOut' | 'down'

export function boxAnswer(error: unknown): BoxAnswer {
  if (!error) return 'up'
  return error instanceof ApiError && error.status === 401 ? 'signedOut' : 'down'
}

/** What the sign-in page says when a wait ended there (LoginPage, `after`). */
export type RestartReason = 'restore' | 'update'

/** How long the box may stay unreachable before the page offers a reload (a test lowers it). */
export const restartWaitConfig = { slowMs: 180_000 }

export function useRestartWait(waiting: boolean, error: unknown, reason: RestartReason): { reconnecting: boolean; slow: boolean } {
  const answer = waiting ? boxAnswer(error) : 'up'
  const navigate = useNavigate()
  const loc = useLocation()
  const qc = useQueryClient()
  const here = loc.pathname + loc.search
  useEffect(() => {
    if (answer !== 'signedOut') return
    // Stop every read of this page first: each would only answer 401 again. The sign-in drops the cache it reads ('me').
    void qc.cancelQueries()
    navigate(`/login?after=${reason}&next=${encodeURIComponent(here)}`, { replace: true })
    qc.removeQueries()
  }, [answer, reason, here, navigate, qc])
  const slow = useSlow(answer === 'down')
  return { reconnecting: answer === 'down', slow }
}

/** true once down has stayed true for restartWaitConfig.slowMs (the effect runs again only when down changes). */
function useSlow(down: boolean): boolean {
  const [slow, setSlow] = useState(false)
  useEffect(() => {
    if (!down) return
    const timer = setTimeout(() => setSlow(true), restartWaitConfig.slowMs)
    return () => { clearTimeout(timer); setSlow(false) }
  }, [down])
  return down && slow
}
