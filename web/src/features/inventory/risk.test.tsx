import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { http, HttpResponse } from 'msw'
import { server } from '@/test/server'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { toggleFilter } from '@/test/filters'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { sessionStore } from '@/mocks/stores'
import { BOX_ID, ensureBox } from './mocks'
import type { DeviceRow } from './types'

// Every list shows each device's badge, the device status of the findings lists (one function): its most urgent open status with the
// distinct CVEs at it, else Needs your input, nothing when it has none.

vi.setConfig({ testTimeout: 30_000 })
beforeEach(() => { ensureBox(); sessionStore.set({ userId: 'u-admin' }) })
afterEach(() => { server.events.removeAllListeners() })

const T = { timeout: 5000 }
const get = async (path: string) => {
  const res = await fetch(`${location.origin}/api/v1${path}`)
  return { status: res.status, json: (await res.json()) as Record<string, any> } // eslint-disable-line @typescript-eslint/no-explicit-any
}
const rows = async () => (await get('/inventory/devices')).json.items as DeviceRow[]

describe('inventory: risk marker', () => {
  it('the badge is the device status of the findings lists for every device: the most urgent status with its distinct CVEs', async () => {
    const list = await rows()
    const cards = (await get('/findings/devices?limit=100')).json.items as { device: { id: string }; status: { code: string; count: number } | null }[]
    for (const d of list) {
      const card = cards.find((c) => c.device.id === d.id)
      if (card && d.id !== BOX_ID) expect(d.risk, d.id).toEqual(card.status)
    }
    expect(list.some((d) => d.risk?.code === 'exploited')).toBe(true) // the sample data shows several statuses and devices without one
    expect(list.some((d) => !d.risk)).toBe(true)
  })

  it('GET /inventory/devices?risk= filters by level (none = clean), unknown words are 400 bad_filter', async () => {
    const all = await rows()
    for (const level of ['exploited', 'update_recommended', 'none'] as const) {
      const got = (await get(`/inventory/devices?risk=${level}`)).json.items as DeviceRow[]
      expect(got.map((d) => d.id).sort()).toEqual(all.filter((d) => (d.risk?.code ?? 'none') === level).map((d) => d.id).sort())
    }
    const bad = await get('/inventory/devices?risk=high')
    expect([bad.status, bad.json.error.code]).toEqual([400, 'bad_filter'])
  })

  it('Devices: a Risk column with words, linked to the device\'s findings with that status, sortable worst first and filtered by its chips; no a11y violations', async () => {
    const user = userEvent.setup()
    const list = await rows()
    const red = list.find((d) => d.risk?.code === 'exploited')!
    renderApp('/devices')
    const table = await screen.findByRole('table', { name: 'Device list' }, T)
    const marker = await waitFor(() => within(table).getAllByRole('link', { name: new RegExp(`^${red.risk!.count} exploited: open its findings`) }).find((a) => a.getAttribute('href') === `/devices/${red.id}?tab=findings&status=exploited`)!, T)
    expect(marker).toHaveTextContent(`${red.risk!.count} exploited`)
    await expectNoA11yViolations()
    // sort: worst first on the first click
    await user.click(within(table).getByRole('button', { name: /Risk/ }))
    await waitFor(() => expect(within(within(table).getAllByRole('row')[1]!).getByRole('link', { name: /^\d+ (under attack|exploited): / })).toBeInTheDocument(), T)
    // the Exploited chip keeps the red devices only
    await toggleFilter(user, /^Exploited/)
    await waitFor(() => expect(within(table).getAllByRole('row').length - 1).toBe(list.filter((d) => d.approved && d.risk?.code === 'exploited').length), T)
  })

  it('the device page shows the badge next to the title, a link to its Findings tab with that status; a clean device shows none', async () => {
    const list = await rows()
    const red = list.find((d) => d.risk?.code === 'exploited')!
    const first = renderApp(`/devices/${red.id}`)
    const title = (await screen.findByRole('heading', { level: 1 }, T)).closest('header') ?? document.body
    expect(await within(title as HTMLElement).findByRole('link', { name: /exploited/ }, T)).toHaveAttribute('href', `/devices/${red.id}?tab=findings&status=exploited`)
    first.unmount()
    // clean on both reads: no marker, and no card of the findings model (no open finding) and no question
    const cards = (await get('/findings/devices?limit=100')).json.items as { device: { id: string } }[]
    const asked = (await get('/findings/input?limit=100')).json.items as { device: { id: string } }[]
    const busy = new Set([...cards, ...asked].map((c) => c.device.id))
    const clean = list.find((d) => !d.risk && !d.is_box && !busy.has(d.id))!
    renderApp(`/devices/${clean.id}`)
    await screen.findByRole('heading', { level: 1 }, T)
    expect(screen.queryByRole('link', { name: /open its findings|exploited$|^Update recommended/ })).toBeNull()
  })

  it('the CSV export has a risk column in the marker\'s words', async () => {
    const red = (await rows()).find((d) => d.risk?.code === 'exploited')!
    const csv = await (await fetch(`${location.origin}/api/v1/inventory/export.csv`)).text()
    expect(csv).toContain('name_in_vedette,risk\r\n')
    expect(csv).toContain(`,${red.risk!.count} exploited\r\n`)
  })

  it('the Vedette box is marked by the rule of every device: no open finding, no marker (risk=none)', async () => {
    const box = (await rows()).find((d) => d.id === BOX_ID)!
    const none = ((await get('/inventory/devices?risk=none')).json.items as DeviceRow[]).some((d) => d.id === BOX_ID)
    expect(none).toBe(box.risk === null)
  })

  it('a list whose risk marks could not be read says so quietly and shows none', async () => {
    const real = (await get('/inventory/devices')).json
    server.use(http.get(`${location.origin}/api/v1/inventory/devices`, () =>
      HttpResponse.json({ ...real, risk_unavailable: true, items: (real.items as DeviceRow[]).map((d) => ({ ...d, risk: null })) })))
    renderApp('/devices')
    expect(await screen.findByText(/^Risk marks could not be read just now/, undefined, T)).toBeInTheDocument()
    const table = await screen.findByRole('table', { name: 'Device list' }, T)
    expect(within(table).queryByRole('link', { name: /exploited: |Update recommended: / })).toBeNull()
  })
})
