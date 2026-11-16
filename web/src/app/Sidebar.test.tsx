// docs/UI.md §2 (#842): pinned entries, collapsible groups remembered per user, single-entry groups as plain items, the icon rail,
// badges from GET /findings/summary.
import { beforeEach, describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { server } from '@/test/server'
import { API } from '@/mocks/http'
import { modulesStore } from '@/mocks/stores'

const mainNav = () => screen.findByRole('navigation', { name: 'Main navigation' })
const off = (...ids: string[]) => modulesStore.update((l) => l.map((m) => (ids.includes(m.id) ? { ...m, enabled: false } : m)))
const region = (button: HTMLElement) => document.getElementById(button.getAttribute('aria-controls')!)!

beforeEach(() => localStorage.clear())

describe('sidebar groups (docs/UI.md §2)', () => {
  it('Home, Findings, Updates to plan and Incidents are always there; other groups start closed and inert, the current page opens its own', async () => {
    renderApp('/devices')
    const nav = within(await mainNav())
    for (const name of ['Home', 'Findings', 'Updates to plan', 'Incidents']) expect(await nav.findByRole('link', { name })).toBeInTheDocument()
    expect(nav.getByRole('link', { name: 'Incidents' }).closest('[role=group]')).toBeNull() // pinned, in no group
    const assets = await nav.findByRole('button', { name: 'Assets, holds this page' })
    expect(assets).toHaveAttribute('aria-expanded', 'true') // holds /devices: open, and its header does nothing
    expect(assets).toHaveAttribute('aria-disabled', 'true')
    expect(region(assets)).not.toHaveAttribute('inert')
    const detect = nav.getByRole('button', { name: 'Intrusion detection' })
    expect(detect).toHaveAttribute('aria-expanded', 'false')
    expect(region(detect)).toHaveAttribute('inert')
    await expectNoA11yViolations()
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
    expect(nav.getByRole('link', { name: 'Incidents' })).toBeInTheDocument()
    expect(nav.getByRole('link', { name: 'Lookup' })).toBeInTheDocument()
    expect(nav.queryByRole('button', { name: /Assistant and reports/ })).toBeNull()
    expect(nav.getByRole('button', { name: 'Assets' })).toBeInTheDocument() // Devices + External exposure
  })
})

describe('badges from one summary read', () => {
  it('Findings and Devices carry their counts; a closed group shows the urgent total and names its parts', async () => {
    server.use(http.get(`${API}/findings/summary`, () => HttpResponse.json({ open: { total: 9, confirmed: 3, devices: 2, ransomware: 0 }, top: [], trend: [], devices: { total: 30, pending: 15 }, incidents: { open: 4, urgent: 2 }, alerts: null, generated_at: '2026-11-16T00:00:00Z' })))
    renderApp('/')
    const nav = within(await mainNav())
    expect(await nav.findByRole('button', { name: 'Assets: Devices 15 to review' }, { timeout: 3000 })).toHaveAttribute('aria-expanded', 'false')
    expect(nav.getByRole('link', { name: /^Findings/ })).toHaveAccessibleName('Findings 3 confirmed to handle')
    expect(nav.getByRole('link', { name: /^Incidents/ })).toHaveAccessibleName('Incidents 2 high or critical open')
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
    expect(nav.getByRole('link', { name: 'Devices' })).toBeInTheDocument()
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
    await u.click(within(await screen.findByRole('dialog', { name: 'Main navigation' })).getByRole('link', { name: 'Findings' }))
    expect(screen.queryByRole('dialog', { name: 'Main navigation' })).toBeNull()
    expect(await screen.findByRole('heading', { level: 1 })).toBeInTheDocument()
  })
})
