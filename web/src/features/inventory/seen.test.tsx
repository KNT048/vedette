import { beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, screen, waitFor, within } from '@testing-library/react'
import { renderApp } from '@/test/render'
import { assetsStore } from '@/mocks/stores'
import { fmtDateTime } from '@/lib/format'
import type { Asset } from '@/lib/types'
import { ensureBox } from './mocks'
import { neverSeen } from './nameOf'
import { devicePoll } from './api'

// A value a person entered is labelled as entered, never as "seen on the network"; "Last seen" is only a report of a sensor, a scan
// or an agent. A hand-added device keeps last_seen = first_seen = the time it was added until a report moves it.
vi.setConfig({ testTimeout: 30_000 })
beforeEach(() => ensureBox())

const T = { timeout: 5000 }
const ago = (h: number) => new Date(Date.now() - h * 3_600_000).toISOString()
const ADDED = ago(30)

/** A firewall a person added by hand 30 hours ago, with the host name they typed; `seen` is a later scan's report, if any. */
function addFirewall(id: string, ip: string, seen?: string) {
  const fw: Asset = { id, site: 'hq', ip, mac: null, hostname: 'fw-edge-01', kind: 'firewall', vendor: { value: 'Fortinet', source: 'manual', confidence: 1, seen_at: ADDED },
    model: null, os: null, software: [], services: [], first_seen: ADDED, last_seen: seen ?? ADDED, approved: true, fragile: false, origin: 'manual' }
  assetsStore.update((l) => [fw, ...l])
}

/** The Overview's general information as label → value. */
async function overview() {
  await screen.findByRole('heading', { level: 1 }, T)
  const dl = (await screen.findByText('Device type', undefined, T)).closest('dl') as HTMLElement
  const out = new Map<string, string>()
  for (const dt of within(dl).getAllByRole('term')) out.set(dt.textContent?.trim() ?? '', (dt.nextElementSibling?.textContent ?? '').trim())
  return out
}

/** The Last seen cell of the device list row named `name`. */
async function listSeen(name: string) {
  renderApp('/devices')
  const table = await screen.findByRole('table', { name: 'Device list' }, T)
  const row = (await within(table).findByText(name, undefined, T)).closest('tr') as HTMLElement
  // by its column: an admin's list also has the selection and row menu columns
  const col = within(table).getAllByRole('columnheader').findIndex((h) => /Last seen/.test(h.textContent ?? ''))
  return within(row).getAllByRole('cell')[col]!
}

describe('neverSeen', () => {
  it('is a hand-added device no report has moved; a discovered device is always seen', () => {
    expect(neverSeen({ origin: 'manual', first_seen: ADDED, last_seen: ADDED })).toBe(true)
    expect(neverSeen({ origin: 'manual', first_seen: ADDED, last_seen: ago(1) })).toBe(false)
    expect(neverSeen({ origin: 'discovered', first_seen: ADDED, last_seen: ADDED })).toBe(false)
  })
})

describe('Device page and list: what a person entered, what the network saw', () => {
  it('a hand-added device never seen: entered host name, added by hand, never seen on the network', async () => {
    addFirewall('a-hand-never', '192.168.10.81')
    renderApp('/devices/a-hand-never')
    const o = await overview()
    expect(o.get('Host name (entered by hand)')).toMatch(/^fw-edge-01/)
    expect(o.has('Host name (seen on the network)')).toBe(false)
    expect(o.get('Added by hand')).toBe(fmtDateTime(ADDED))
    expect(o.has('First seen')).toBe(false)
    expect(o.get('Last seen')).toBe('Never seen on the network')
    expect(screen.getByText(/^Firewall, added by hand (yesterday|1 day ago), never seen on the network$/)).toBeInTheDocument()
    expect(screen.queryByText(/last seen/)).toBeNull()
    cleanup()

    const cell = await listSeen('fw-edge-01')
    expect(cell).toHaveTextContent(/^Never$/)
    expect(within(cell).getByText('Never')).toHaveAttribute('title', `Never seen on the network. Added by hand on ${fmtDateTime(ADDED)}.`)
  })

  it('a device a sensor found: host name seen on the network, first and last seen', async () => {
    const nas = assetsStore.get().find((a) => a.id === 'a-nas02')!
    renderApp('/devices/a-nas02')
    const o = await overview()
    expect(o.get('Host name (seen on the network)')).toMatch(/^NAS-PHOTOS/)
    expect(o.has('Host name (entered by hand)')).toBe(false)
    expect(o.get('First seen')).toBe(fmtDateTime(nas.first_seen))
    expect(o.get('Last seen')).toContain(fmtDateTime(nas.last_seen))
    expect(o.has('Added by hand')).toBe(false)
    expect(screen.getByText(/^NAS, last seen/)).toBeInTheDocument()
    cleanup()

    const cell = await listSeen('NAS-PHOTOS')
    expect(cell).not.toHaveTextContent('Never')
    expect(within(cell).getByText(/ago|now/)).toHaveAttribute('title', fmtDateTime(nas.last_seen))
  })

  it('a hand-added device a scan saw later: still added by hand and entered, last seen is the scan', async () => {
    const scan = ago(2)
    addFirewall('a-hand-seen', '192.168.10.82', scan)
    renderApp('/devices/a-hand-seen')
    const o = await overview()
    expect(o.get('Host name (entered by hand)')).toMatch(/^fw-edge-01/)
    expect(o.get('Added by hand')).toBe(fmtDateTime(ADDED))
    expect(o.get('Last seen')).toBe(`${fmtDateTime(scan)} (2 hours ago)`)
    expect(screen.getByText('Firewall, last seen 2 hours ago')).toBeInTheDocument()
    cleanup()

    const cell = await listSeen('fw-edge-01')
    expect(cell).not.toHaveTextContent('Never')
    expect(within(cell).getByText(/ago/)).toHaveAttribute('title', fmtDateTime(scan))
  })

  it('an open device page shows a new report by itself: "last seen" moves without a reload', async () => {
    devicePoll.ms = 200
    try {
      addFirewall('a-hand-live', '192.168.10.83', ago(2))
      renderApp('/devices/a-hand-live')
      expect(await screen.findByText('Firewall, last seen 2 hours ago', undefined, T)).toBeInTheDocument()
      assetsStore.update((l) => l.map((a) => (a.id === 'a-hand-live' ? { ...a, last_seen: new Date().toISOString() } : a))) // an agent report
      expect(await screen.findByText(/^Firewall, last seen (now|less than a minute ago|\d+ seconds? ago)$/, undefined, T)).toBeInTheDocument()
    } finally { devicePoll.ms = 60_000 }
  })

  it('the open Devices list reads again by itself: a device that moved to To review is not left claiming it is not there', async () => {
    devicePoll.ms = 200
    try {
      addFirewall('a-moved', '192.168.10.84', ago(1))
      renderApp('/devices?tab=devices')
      const table = await screen.findByRole('table', { name: 'Device list' }, T)
      expect(await within(table).findByText('fw-edge-01', undefined, T)).toBeInTheDocument()
      assetsStore.update((l) => l.map((a) => (a.id === 'a-moved' ? { ...a, approved: false, origin: 'discovered' as const } : a))) // no longer added
      await waitFor(() => expect(within(table).queryByText('fw-edge-01')).toBeNull(), T)
      expect(screen.getByRole('tab', { name: /To review/ })).toHaveTextContent(/\d+ not added yet/)
    } finally { devicePoll.ms = 60_000 }
  })
})
