import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import { renderApp } from '@/test/render'
import { assetsStore, sessionStore } from '@/mocks/stores'
import { historyStore } from '@/features/scanning/mocks'
import { setDisplayTimeZone } from '@/lib/format'
import { ensureBox } from './mocks'
import { firstCheck, windowOpen, type FirstCheckInput } from './firstCheck'

vi.setConfig({ testTimeout: 30_000 })
beforeEach(() => ensureBox())
afterEach(() => setDisplayTimeZone(null))

const T = { timeout: 5000 }
const ZONE = 'Asia/Ho_Chi_Minh' // UTC+7
const window = { days: [1, 2, 3, 4, 5, 6, 7], from: '22:00', to: '05:00', time_zone: ZONE }
const input = (over: Partial<FirstCheckInput> = {}): FirstCheckInput => ({
  ip: '100.65.254.1', window, scope: { lan_ranges: ['100.65.0.0/16'], confirmed_at: '2026-11-13T07:39:30.000Z' },
  discovery: { enabled: true, next_run_at: '2026-11-18T15:00:00.000Z' }, // 22:00 on the 18th in the zone
  now: new Date('2026-11-18T05:00:00.000Z'), // 12:00 on the 18th in the zone
  ...over,
})

describe('the first check of a device whose network scan is on', () => {
  it('is tonight at the window time, from the real window setting and the box zone', () => {
    setDisplayTimeZone(ZONE)
    expect(firstCheck(input())).toEqual({ when: 'tonight', time: '22:00' })
  })

  it('says tomorrow, or the day, when the next opening is not today', () => {
    setDisplayTimeZone(ZONE)
    expect(firstCheck(input({ discovery: { enabled: true, next_run_at: '2026-11-19T15:00:00.000Z' } }))).toEqual({ when: 'tomorrow', time: '22:00' })
    expect(firstCheck(input({ discovery: { enabled: true, next_run_at: '2026-11-22T15:00:00.000Z' } }))).toEqual({ when: 'day', day: '22 Nov', time: '22:00' })
  })

  it('words the day from calendar days in the zone: today for a morning opening, tomorrow across a clock change', () => {
    setDisplayTimeZone('America/New_York') // clocks went forward on 2026-03-08: that day has 23 hours
    const w = { ...window, time_zone: 'America/New_York' }
    const at = (iso: string, next: string) => firstCheck(input({ window: w, now: new Date(iso), discovery: { enabled: true, next_run_at: next } }))
    expect(at('2026-03-07T15:00:00.000Z', '2026-03-09T02:00:00.000Z')).toEqual({ when: 'tomorrow', time: '22:00' }) // 10:00 on the 7th -> 22:00 on the 8th
    expect(at('2026-03-08T12:00:00.000Z', '2026-03-08T16:00:00.000Z')).toEqual({ when: 'today', time: '12:00' }) // a noon opening is not "tonight"
    expect(at('2026-03-08T12:00:00.000Z', '2026-03-09T02:00:00.000Z')).toEqual({ when: 'tonight', time: '22:00' })
  })

  it('runs now when the window opened tonight and is still open, across midnight too', () => {
    setDisplayTimeZone(ZONE)
    expect(firstCheck(input({ now: new Date('2026-11-18T17:30:00.000Z') }))).toEqual({ when: 'now' }) // 00:30 on the 19th, the 18th's window
    expect(windowOpen(window, new Date('2026-11-18T15:30:00.000Z'))).toBe(true) // 22:30
    expect(windowOpen(window, new Date('2026-11-18T22:00:00.000Z'))).toBe(false) // 05:00 on the 19th: closed
    expect(windowOpen(window, new Date('2026-11-18T14:59:00.000Z'))).toBe(false) // 21:59
    expect(windowOpen({ ...window, days: [3] }, new Date('2026-11-18T17:30:00.000Z'))).toBe(true) // the 18th is a Wednesday: its window runs into the 19th
    expect(windowOpen({ ...window, days: [4] }, new Date('2026-11-18T17:30:00.000Z'))).toBe(false) // a Thursday-only window has not started yet
  })

  it('says what stops it instead of a time', () => {
    setDisplayTimeZone(ZONE)
    expect(firstCheck(input({ ip: '10.0.0.5' }))).toEqual({ when: 'waiting', why: 'outside' })
    expect(firstCheck(input({ discovery: { enabled: false, next_run_at: null } }))).toEqual({ when: 'waiting', why: 'off' })
    expect(firstCheck(input({ scope: { lan_ranges: ['100.65.0.0/16'], confirmed_at: null } }))).toEqual({ when: 'waiting', why: 'scope' })
    expect(firstCheck(input({ discovery: { enabled: true, next_run_at: null }, now: new Date('2026-11-18T05:00:00.000Z') }))).toEqual({ when: 'next' })
  })
})

describe('Device page: the network scan row while the switch is on and nothing has checked the device', () => {
  const old = new Date(Date.now() - 48 * 3_600_000).toISOString()
  const add = (id: string, ip: string) => assetsStore.update((l) => [{ id, site: 'hq', ip, mac: null, hostname: null, name: 'firewall-01', kind: 'firewall', vendor: null,
    model: null, os: null, software: [], services: [], first_seen: old, last_seen: old, approved: true, fragile: false, origin: 'manual' }, ...l])
  const hand = async (id: string, ip: string, scan: 'on' | 'off') => {
    add(id, ip)
    sessionStore.set({ userId: 'u-admin' })
    const r = await fetch(`${location.origin}/api/v1/inventory/devices/${id}/sources`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ scan }) })
    expect(r.status).toBe(200)
  }
  const scanRow = async () => within(await screen.findByRole('list', { name: 'Sources' }, T)).getByText('Network scan').closest('li') as HTMLElement

  it('reads the first check, with a way to check now, and never "Not set up"', async () => {
    sessionStore.set({ userId: 'u-admin' })
    historyStore.set([])
    await hand('a-hand-fw', '192.168.10.80', 'on')
    renderApp('/devices/a-hand-fw', { role: 'admin' })
    const row = await scanRow()
    expect(await within(row).findByText(/^On · first check (tonight|today|tomorrow|on \d+ \w+) at \d\d:\d\d, in the scan window$|^On · first check runs during this scan window/, {}, T)).toBeInTheDocument()
    expect(row).not.toHaveTextContent('Not set up')
    expect(within(row).getByRole('button', { name: 'Check this device now' })).toBeInTheDocument()
  })

  it('after a check it reads On with the time of the last check', async () => {
    sessionStore.set({ userId: 'u-admin' })
    await hand('a-hand-fw2', '192.168.10.81', 'on')
    const ago = (h: number) => new Date(Date.now() - h * 3_600_000).toISOString()
    historyStore.set([{ id: 'saj-fw', kind: 'device', engine: 'nmap-versions', trigger: 'automatic', label: '192.168.10.81', target_id: null, started_at: ago(3), ended_at: ago(2.9), outcome: 'ok', text: 'Scanned 192.168.10.81' }])
    const { markReached } = await import('@/features/scanning/mocks')
    markReached('saj-fw', ['192.168.10.81'])
    renderApp('/devices/a-hand-fw2', { role: 'admin' })
    const row = await scanRow()
    expect(await within(row).findByText(/^On · last check 3 hours ago/, {}, T)).toBeInTheDocument()
    expect(row).not.toHaveTextContent('Not set up')
    expect(row).not.toHaveTextContent('first check')
  })

  it('a device whose switch is off keeps its words', async () => {
    sessionStore.set({ userId: 'u-admin' })
    historyStore.set([])
    await hand('a-hand-fw3', '192.168.10.82', 'off')
    renderApp('/devices/a-hand-fw3', { role: 'admin' })
    const row = await scanRow()
    expect(row).not.toHaveTextContent('first check')
  })
})
