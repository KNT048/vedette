import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { server } from '@/test/server'
import { assetsStore, sessionStore } from '@/mocks/stores'
import type { Asset } from '@/lib/types'
import { ensureBox } from './mocks'

// D-599, #829 gap 3 (J2): "Possibly the same device as X" with Merge / Keep separate on the device page, a hint in To review.
vi.setConfig({ testTimeout: 30_000 })

const T = { timeout: 5000 }
const BASE = `${location.origin}/api/v1/inventory`
const ago = (days: number) => new Date(Date.now() - days * 864e5).toISOString()
const phone = (p: Partial<Asset> & { id: string }): Asset => ({
  site: 'hq', ip: '192.168.10.160', mac: null, hostname: 'iPhone', kind: 'smartphone', vendor: null, model: null, os: null, software: [], services: [],
  first_seen: ago(30), last_seen: ago(0), approved: true, fragile: false, origin: 'discovered', ...p,
})
// The approved phone, then the same phone back with a new private Wi-Fi address (locally administered MACs), waiting for review.
const KNOWN = phone({ id: 'a-ph1', hostname: 'iPhone.lan', mac: 'da:a1:19:00:00:01', last_seen: ago(2) })
const BACK = phone({ id: 'a-ph2', ip: '192.168.10.161', mac: '6a:b2:19:00:00:02', approved: false, first_seen: ago(0) })

beforeEach(() => {
  ensureBox()
  assetsStore.update((l) => [...l.filter((a) => !a.id.startsWith('a-ph')), KNOWN, BACK])
})

const notice = () => screen.findByTestId('possible-same', undefined, T)
const pairs = async () => {
  sessionStore.set({ userId: 'u-admin' })
  return ((await (await fetch(`${BASE}/possible-same`)).json()) as { items: unknown[] }).items
}

describe('Device page: possibly the same device (D-599)', () => {
  it('an admin merges the new row into the approved device and lands on it', async () => {
    const user = userEvent.setup()
    const { container } = renderApp('/devices/a-ph2', { role: 'admin' })
    const box = await notice()
    expect(box).toHaveTextContent('Possibly the same device as iPhone.lan')
    expect(box).toHaveTextContent('Same name "iPhone", never online at the same time')
    expect(box).toHaveTextContent(/Approved, seen 2 days ago/)
    expect(within(box).getByRole('link', { name: 'iPhone.lan' })).toHaveAttribute('href', '/devices/a-ph1')
    // above the approval notice: merging answers the approval too
    expect(box.compareDocumentPosition(screen.getByRole('button', { name: 'Approve' })) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    await expectNoA11yViolations(container)

    await user.click(within(box).getByRole('button', { name: 'Merge' }))
    const dialog = await screen.findByRole('dialog', { name: 'Merge iPhone into iPhone.lan?' }, T)
    // #876 r1 M2: destructive, and the warning is in the visible description, not only behind the info tip
    expect(dialog).toHaveTextContent('iPhone disappears; its addresses, software and findings move to iPhone.lan. This cannot be undone.')
    expect(within(dialog).getByLabelText('Device to keep')).toHaveValue('a-ph1') // the approved one by default
    const go = within(dialog).getByRole('button', { name: 'Merge into iPhone.lan' })
    expect(go).toHaveClass('bg-danger')
    await user.click(go)

    expect(await screen.findByText('Merged into iPhone.lan.', undefined, T)).toBeInTheDocument()
    expect(await screen.findByRole('heading', { level: 1, name: 'iPhone.lan' }, T)).toBeInTheDocument()
    expect(screen.queryByTestId('possible-same')).toBeNull()
    expect(assetsStore.get().some((a) => a.id === 'a-ph2')).toBe(false)
    expect(await pairs()).toHaveLength(0)
  })

  it('the admin may keep the device of this page instead; twins with one name read "this" and "the other"', async () => {
    assetsStore.update((l) => l.map((a) => (a.id === 'a-ph1' ? { ...a, hostname: 'iPhone' } : a)))
    const user = userEvent.setup()
    renderApp('/devices/a-ph2', { role: 'admin' })
    await user.click(within(await notice()).getByRole('button', { name: 'Merge' }))
    const dialog = await screen.findByRole('dialog', { name: 'Merge this iPhone into the other iPhone?' }, T)
    await user.selectOptions(within(dialog).getByLabelText('Device to keep'), 'This iPhone (waiting for review)')
    expect(within(dialog).getByRole('heading', { name: 'Merge the other iPhone into this iPhone?' })).toBeInTheDocument()
    expect(dialog).toHaveTextContent('The other iPhone disappears;')
    await user.click(within(dialog).getByRole('button', { name: 'Merge into this iPhone' }))
    expect(await screen.findByText('Merged into iPhone.', undefined, T)).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByTestId('possible-same')).toBeNull(), T)
    // the kept row took the approval of the one merged in
    expect(assetsStore.get().find((a) => a.id === 'a-ph2')?.approved).toBe(true)
    expect(assetsStore.get().some((a) => a.id === 'a-ph1')).toBe(false)
  })

  it('Keep separate asks first, naming both devices; then the pair is not offered again', async () => {
    const user = userEvent.setup()
    renderApp('/devices/a-ph1', { role: 'admin' })
    const box = await notice()
    expect(box).toHaveTextContent(/Waiting for review, seen/)
    // #876 r1 M1: one click by mistake must not split the phone for good
    await user.click(within(box).getByRole('button', { name: 'Keep separate' }))
    let dialog = await screen.findByRole('dialog', { name: 'Keep iPhone.lan and iPhone separate?' }, T)
    expect(dialog).toHaveTextContent('Vedette will not ask again for these two and will not join them on its own. This cannot be undone.')
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull(), T)
    expect(await pairs()).toHaveLength(1)
    await user.click(within(await notice()).getByRole('button', { name: 'Keep separate' }))
    dialog = await screen.findByRole('dialog', { name: 'Keep iPhone.lan and iPhone separate?' }, T)
    await user.click(within(dialog).getByRole('button', { name: 'Keep separate' }))
    expect(await screen.findByText('Kept separate from iPhone. Vedette will not ask again for these two.', undefined, T)).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByTestId('possible-same')).toBeNull(), T)
    expect(await pairs()).toHaveLength(0)
  })

  it('the box refuses two machines (409 not_same_device): its words stay in the dialog, nothing moves', async () => {
    const words = 'These are two machines: an agent reports from each of them. Keep them separate; delete a device only when its machine is gone.'
    server.use(http.post(`${BASE}/devices/:id/merge`, () => HttpResponse.json({ error: { code: 'not_same_device', message: words } }, { status: 409 })))
    const user = userEvent.setup()
    renderApp('/devices/a-ph2', { role: 'admin' })
    await user.click(within(await notice()).getByRole('button', { name: 'Merge' }))
    const dialog = await screen.findByRole('dialog', undefined, T)
    await user.click(within(dialog).getByRole('button', { name: 'Merge into iPhone.lan' }))
    expect(await within(dialog).findByRole('alert', undefined, T)).toHaveTextContent(words)
    // the page behind the modal dialog is hidden from the accessibility tree while it is open
    expect(screen.getByRole('heading', { level: 1, name: 'iPhone', hidden: true })).toBeInTheDocument()
    expect(assetsStore.get().filter((a) => a.id.startsWith('a-ph'))).toHaveLength(2)
  })

  it('an operator or viewer sees the hint without buttons: "An admin can merge these."', async () => {
    renderApp('/devices/a-ph2', { role: 'operator' })
    const box = await notice()
    expect(box).toHaveTextContent('Possibly the same device as iPhone.lan')
    expect(box).toHaveTextContent('An admin can merge these.')
    expect(within(box).queryByRole('button', { name: /Merge|Keep separate/ })).toBeNull()
  })

  it('several candidates: one row each, with its own buttons named after the device', async () => {
    assetsStore.update((l) => [...l, phone({ id: 'a-ph3', hostname: 'iPhone.home', ip: '192.168.10.162', mac: '7a:b2:19:00:00:03', approved: false, last_seen: ago(5) })])
    renderApp('/devices/a-ph2', { role: 'admin' })
    const box = await notice()
    const list = within(box).getByRole('list', { name: 'Possibly the same device as one of 2 other devices' })
    expect(within(list).getAllByRole('listitem')).toHaveLength(2)
    expect(within(list).getByRole('button', { name: 'Merge with iPhone.lan' })).toBeInTheDocument()
    expect(within(list).getByRole('button', { name: 'Keep separate from iPhone.home' })).toBeInTheDocument()
  })
})

describe('Devices › To review: the possibly-same hint (D-599)', () => {
  it('Devices (approved): a row in a pair carries "Possibly the same", linking to the question (#876 r1)', async () => {
    renderApp('/devices?tab=devices', { role: 'viewer' })
    const chip = await screen.findByRole('link', { name: 'Possibly the same device as iPhone' }, T)
    expect(chip).toHaveAttribute('href', '/devices/a-ph1#possible-same')
    expect(chip).toHaveTextContent('Possibly the same')
  })

  it('links the row to the question on its device page; possible:same keeps only those rows', async () => {
    const user = userEvent.setup()
    renderApp('/devices?tab=review', { role: 'viewer' })
    const hint = await screen.findByRole('link', { name: 'Possibly the same device as iPhone.lan' }, T)
    expect(hint).toHaveAttribute('href', '/devices/a-ph2#possible-same')
    const pending = screen.getByRole('list', { name: /new devices? not approved/ })
    expect(within(pending).getAllByRole('link', { name: /^Possibly the same/ })).toHaveLength(1)
    await user.click(screen.getByRole('button', { name: /^Possibly the same 1/ }))
    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Search devices' })).toHaveValue('possible:same'), T)
    await waitFor(() => expect(within(screen.getByRole('list', { name: /new devices? not approved/ })).getAllByRole('listitem')).toHaveLength(1), T)
  })
})
