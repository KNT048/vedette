// The schedules mock answers like the box for the editor: next three starts per rule kind, the owner's limits with their reason,
// pause and run once.
import { beforeEach, describe, expect, it } from 'vitest'
import { orgStore, sessionStore } from '@/mocks/stores'
import { Schedule, SchedulePreview } from './contract'

const api = (path: string, init?: RequestInit) => fetch(`${location.origin}/api/v1${path}`, { headers: { 'Content-Type': 'application/json' }, ...init })
const rule = (r: Record<string, unknown>) => ({ every_minutes: null, at_time: null, weekdays: null, month_day: null, once_at: null, tz: 'America/New_York', window: 'none', window_days: null, window_from: null, window_to: null, ...r })

describe('schedules', () => {
  beforeEach(() => {
    orgStore.update((o) => ({ ...o, setup_complete: true, timezone: 'Europe/Berlin' }))
    sessionStore.set({ userId: 'u-admin' })
  })

  it('previews the next three starts of every kind of rule in the box\'s zone, whatever zone a client still sends', async () => {
    for (const r of [
      rule({ freq: 'interval', every_minutes: 360 }),
      rule({ freq: 'interval', every_minutes: 4320, at_time: '02:30', window: 'custom', window_days: [1, 2, 3, 4, 5], window_from: '00:00', window_to: '00:00' }),
      rule({ freq: 'daily', at_time: '02:30' }),
      rule({ freq: 'weekly', at_time: '08:00', weekdays: [1, 4] }),
      rule({ freq: 'monthly', at_time: '08:00', month_day: 31 }),
    ]) {
      const res = await api('/schedules/preview', { method: 'POST', body: JSON.stringify({ rule: r }) })
      expect(res.status).toBe(200)
      const p = SchedulePreview.parse(await res.json())
      expect(p.zone).toBe('Europe/Berlin')
      expect(p.upcoming).toHaveLength(3)
      expect([...p.upcoming].sort()).toEqual(p.upcoming)
    }
  })

  it('refuses what the owner does not allow and says why', async () => {
    const res = await api('/schedules/preview', { method: 'POST', body: JSON.stringify({ owner_key: 'feeds.source:nvd', rule: rule({ freq: 'interval', every_minutes: 10 }) }) })
    expect(res.status).toBe(400)
    const { error } = (await res.json()) as { error: { code: string; field: string; message: string } }
    expect(error).toMatchObject({ code: 'invalid', field: 'every_minutes' })
    expect(error.message).toBe('The interval is at least 1 hour. Sources ask clients not to poll more often.')
  })

  it('saves, pauses and runs once', async () => {
    const before = Schedule.parse(await (await api('/schedules/exposure.target:xt-14')).json())
    expect(before.saved).toBe(false)
    const paused = new Date(Date.now() + 5 * 864e5).toISOString()
    const res = await api('/schedules/exposure.target:xt-14', { method: 'PUT', body: JSON.stringify({ enabled: true, paused_until: paused, rule: rule({ freq: 'daily', at_time: '02:30' }) }) })
    const saved = Schedule.parse(await res.json())
    expect(saved.saved).toBe(true)
    expect(Date.parse(saved.next_due_at!)).toBeGreaterThan(Date.parse(paused))
    const run = (await (await api('/schedules/exposure.target:xt-14/run', { method: 'POST' })).json()) as { run_id: string | null }
    expect(run.run_id).toBeTruthy()
  })
})
