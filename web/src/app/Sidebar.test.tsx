// docs/UI.md §2 (#842): pinned entries, collapsible groups remembered per user, single-entry groups as plain items, the icon rail,
// badges from GET /findings/overview.
import { beforeEach, describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import axe from 'axe-core'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { server } from '@/test/server'
import { API } from '@/mocks/http'
import { modulesStore } from '@/mocks/stores'

const mainNav = () => screen.findByRole('navigation', { name: 'Main navigation' })
const off = (...ids: string[]) => modulesStore.update((l) => l.map((m) => (ids.includes(m.id) ? { ...m, enabled: false } : m)))
// A nav link's name, its count badge allowed after it ("Incidents 2 high or critical open"): the mock box answers GET /findings/overview.
const named = (label: string) => new RegExp(`^${label}( \\d+ .+)?$`)
const region = (button: HTMLElement) => document.getElementById(button.getAttribute('aria-controls')!)!

beforeEach(() => localStorage.clear())

describe('sidebar groups (docs/UI.md §2)', () => {
  it('Home, Findings and Incidents are always there (no Plan entry: its updates are findings); other groups start closed and hidden, the current page opens its own', async () => {
    renderApp('/devices')
    const nav = within(await mainNav())
    for (const name of ['Home', 'Findings', 'Incidents']) expect(await nav.findByRole('link', { name: named(name) })).toBeInTheDocument()
    expect(nav.queryByRole('link', { name: named('Recommended updates'), hidden: true })).toBeNull()
    expect(nav.getByRole('link', { name: named('Incidents') }).closest('[role=group]')).toBeNull() // pinned, in no group
    const assets = await nav.findByRole('button', { name: 'Assets, holds this page' })
    expect(assets).toHaveAttribute('aria-expanded', 'true') // holds /devices: open, and its header does nothing
    expect(assets).toHaveAttribute('aria-disabled', 'true')
    expect(region(assets)).not.toHaveAttribute('hidden')
    const detect = nav.getByRole('button', { name: 'Intrusion detection' })
    expect(detect).toHaveAttribute('aria-expanded', 'false')
    expect(region(detect)).toHaveAttribute('hidden')
    await expectNoA11yViolations()
  })

  it('a closed group\'s links are out of the accessibility tree and the tab order; opening brings them back, closing hides them again', async () => {
    const u = userEvent.setup()
    renderApp('/')
    const nav = within(await mainNav())
    const assets = await nav.findByRole('button', { name: named('Assets') })
    expect(assets).toHaveAttribute('aria-expanded', 'false')
    expect(region(assets)).toHaveAttribute('id', assets.getAttribute('aria-controls'))
    expect(region(assets)).toHaveAttribute('hidden')
    for (const name of ['Devices', 'External exposure']) expect(nav.queryByRole('link', { name: named(name) })).toBeNull()
    // Keyboard: Tab from the closed header goes past the group's links to the next header.
    assets.focus()
    await u.tab()
    expect(document.activeElement?.closest('#' + assets.getAttribute('aria-controls'))).toBeNull()

    await u.click(assets)
    expect(assets).toHaveAttribute('aria-expanded', 'true')
    expect(region(assets)).not.toHaveAttribute('hidden')
    for (const name of ['Devices', 'External exposure']) expect(nav.getByRole('link', { name: named(name) })).toBeVisible()
    await u.tab()
    expect(nav.getByRole('link', { name: named('Devices') })).toHaveFocus()

    await u.click(assets)
    expect(assets).toHaveAttribute('aria-expanded', 'false')
    for (const name of ['Devices', 'External exposure']) expect(nav.queryByRole('link', { name: named(name) })).toBeNull()
  })

  it('opening a group is remembered after a reload; the current group opening by itself is not saved', async () => {
    const u = userEvent.setup()
    const first = renderApp('/')
    const nav = within(await mainNav())
    await u.click(await nav.findByRole('button', { name: 'Intrusion detection' }))
    expect(nav.getByRole('button', { name: 'Intrusion detection' })).toHaveAttribute('aria-expanded', 'true')
    first.unmount()
    renderApp('/')
    const again = within(await mainNav())
    expect(await again.findByRole('button', { name: 'Intrusion detection' })).toHaveAttribute('aria-expanded', 'true')
    expect(again.getByRole('button', { name: 'Assets' })).toHaveAttribute('aria-expanded', 'false')
  })

  it('a group with one visible entry is that plain entry, a group with none is not drawn (default v1 box: Preview modules off)', async () => {
    off('honeypot', 'logs', 'response', 'ai', 'reports', 'scan')
    renderApp('/')
    const nav = within(await mainNav())
    // While the module list loads every entry shows; wait for the box's own list.
    await waitFor(() => expect(nav.queryByRole('button', { name: /Intrusion detection/ })).toBeNull())
    expect(nav.getByRole('link', { name: named('Incidents') })).toBeInTheDocument()
    expect(nav.getByRole('link', { name: 'Lookup' })).toBeInTheDocument()
    expect(nav.queryByRole('button', { name: /Assistant and reports/ })).toBeNull()
    expect(nav.getByRole('button', { name: 'Assets' })).toBeInTheDocument() // Devices + External exposure
  })
})

describe('badges from the one overview read', () => {
  it('Findings and Incidents carry their counts; Devices has none, and a closed group sums only the urgent ones', async () => {
    server.use(http.get(`${API}/findings/overview`, () => HttpResponse.json({ open: { findings: 9, by_status: { under_attack: 0, exploited: 2, public_exploit: 1, critical_edge: 0, update_recommended: 6 } }, devices: { total: 30, not_added: 15, by_status: { under_attack: 0, exploited: 2, public_exploit: 1, critical_edge: 0, update_recommended: 6, needs_input: 0 }, affected: { under_attack: 0, exploited: 2, public_exploit: 1, critical_edge: 0, update_recommended: 6 } }, input: 0, first: [], trend: [], trend_start: '2026-10-18', generated_at: '2026-11-16T00:00:00Z', incidents: { open: 4, urgent: 2 }, alerts: null })))
    renderApp('/')
    const nav = within(await mainNav())
    expect(await nav.findByRole('link', { name: 'Findings 3 urgent to handle' }, { timeout: 3000 })).toBeInTheDocument()
    const assets = nav.getByRole('button', { name: 'Assets' }) // no count and no "waiting" words: pending devices are not an alarm
    expect(assets).toHaveAttribute('aria-expanded', 'false')
    await userEvent.setup().click(assets)
    expect(nav.getByRole('link', { name: 'Devices' })).toHaveAccessibleName('Devices')
    expect(nav.getByRole('link', { name: 'Devices' })).not.toHaveTextContent(/\d/)
    // WCAG 2.5.3: every name starts with its visible text (axe's label-content-name-mismatch, off by default, is turned on here).
    const r = await axe.run(await mainNav(), { runOnly: ['label-content-name-mismatch'] })
    expect(r.violations.map((v) => v.nodes.map((n) => n.target.join(' ')).join(', '))).toEqual([])
    expect(nav.getByRole('link', { name: /^Incidents/ })).toHaveAccessibleName('Incidents 2 high or critical open')
  })
})

describe('icon rail without a Devices count', () => {
  it('the collapsed Devices link carries no count either', async () => {
    server.use(http.get(`${API}/findings/overview`, () => HttpResponse.json({ open: { findings: 9, by_status: { under_attack: 0, exploited: 2, public_exploit: 1, critical_edge: 0, update_recommended: 6 } }, devices: { total: 30, not_added: 15, by_status: { under_attack: 0, exploited: 2, public_exploit: 1, critical_edge: 0, update_recommended: 6, needs_input: 0 }, affected: { under_attack: 0, exploited: 2, public_exploit: 1, critical_edge: 0, update_recommended: 6 } }, input: 0, first: [], trend: [], trend_start: '2026-10-18', generated_at: '2026-11-16T00:00:00Z', incidents: { open: 4, urgent: 2 }, alerts: null })))
    localStorage.setItem('vedette.nav.u-admin', JSON.stringify({ rail: true, open: [] }))
    renderApp('/')
    const nav = within(await mainNav())
    expect(await nav.findByRole('link', { name: /^Findings 3/ }, { timeout: 3000 })).toBeInTheDocument()
    expect(nav.getByRole('link', { name: 'Devices' })).toHaveAccessibleName('Devices')
  })
})

describe('icon rail', () => {
  it('"Collapse menu" turns the list into named icons and is remembered', async () => {
    const u = userEvent.setup()
    const first = renderApp('/')
    await u.click(await screen.findByRole('button', { name: 'Collapse menu' }))
    expect(screen.getByRole('button', { name: 'Expand menu' })).toBeInTheDocument()
    const nav = within(await mainNav())
    expect(nav.queryByRole('button', { name: 'Assets' })).toBeNull() // groups flatten
    expect(nav.getByRole('group', { name: 'Assets' })).toBeInTheDocument()
    expect(nav.getByRole('link', { name: named('Devices') })).toBeInTheDocument()
    first.unmount()
    renderApp('/')
    expect(await screen.findByRole('button', { name: 'Expand menu' })).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('a rail link focused by keyboard shows its tooltip but is not described by it (its name already says it)', async () => {
    localStorage.setItem('vedette.nav.u-admin', JSON.stringify({ rail: true, open: [] }))
    const u = userEvent.setup()
    renderApp('/')
    const nav = within(await mainNav())
    const home = await nav.findByRole('link', { name: 'Home' })
    home.focus()
    await u.keyboard('{Shift>}{Tab}{/Shift}{Tab}') // a keyboard focus, as Radix opens tooltips on focus-visible
    expect(await screen.findByRole('tooltip')).toHaveTextContent('Home')
    expect(home).not.toHaveAttribute('aria-describedby')
  })
})

describe('phone drawer', () => {
  it('Esc gives focus back to "Open menu"; a link closes it', async () => {
    const u = userEvent.setup()
    renderApp('/')
    const open = await screen.findByRole('button', { name: 'Open menu' })
    await u.click(open)
    const drawer = await screen.findByRole('dialog', { name: 'Main navigation' })
    expect(within(drawer).getByRole('link', { name: 'Home' })).toBeInTheDocument()
    await u.keyboard('{Escape}')
    expect(screen.queryByRole('dialog', { name: 'Main navigation' })).toBeNull()
    expect(open).toHaveFocus()
    await u.click(open)
    await u.click(within(await screen.findByRole('dialog', { name: 'Main navigation' })).getByRole('link', { name: named('Findings') }))
    expect(screen.queryByRole('dialog', { name: 'Main navigation' })).toBeNull()
    // The Findings page's own heading: Home's stays on screen while the lazy Findings route loads, so any h1 could be Home's, about to go.
    expect(await screen.findByRole('heading', { level: 1, name: /finding/i })).toBeInTheDocument()
  })
})
