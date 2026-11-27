import { describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { assetsStore, modulesStore } from '@/mocks/stores'
import type { Asset } from '@/lib/types'
import { addrStore } from './mocks'

// Removing a device (S-INV-3): the removal stays, so it is listed under Removed in To review, where Forget lets the device come back.
// A device whose osquery agent reports asks what happens to the agent, and says what each choice does: an administrator can stop it
// with the device; Remove only leaves it running, and it adds the device back on its next report.
vi.setConfig({ testTimeout: 30_000 })
const T = { timeout: 5000 }
const enableModule = (id: string, enabled: boolean) => modulesStore.update((l) => l.map((m) => (m.id === id ? { ...m, enabled } : m)))

async function openRemove(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole('button', { name: 'More' }, T))
  await user.click(await screen.findByRole('menuitem', { name: 'Remove from list' }, T))
  return screen.findByRole('dialog', undefined, T)
}

describe('removing a device', () => {
  it('an administrator stops the agent with the device; the removal is listed and can be forgotten', async () => {
    const user = userEvent.setup()
    enableModule('agent-intake', true)
    renderApp('/devices/a-fw01', { role: 'admin' })
    const dialog = await openRemove(user)
    const choice = within(dialog).getByTestId('delete-agent-choice')
    expect(within(choice).getByRole('radio', { name: /Remove and stop its agent/ })).toBeChecked()
    expect(choice).toHaveTextContent('a token other machines use stays')
    expect(dialog).toHaveTextContent('Discovery keeps it out from now on')
    await user.click(within(dialog).getByRole('button', { name: 'Remove and stop its agent' }))
    await waitFor(() => expect(assetsStore.get().some((a) => a.id === 'a-fw01')).toBe(false), T)
    const removed = await (await fetch(`${location.origin}/api/v1/inventory/removed`)).json() as { items: { name: string; agent: string }[] }
    expect(removed.items).toHaveLength(1)
    expect(removed.items[0]).toMatchObject({ agent: 'stopped' })

    renderApp('/devices?tab=review', { role: 'admin' })
    const group = await screen.findByTestId('removed-devices', undefined, T)
    expect(group).toHaveTextContent('Removed: 1 device kept out')
    await user.click(within(group).getByText('Removed: 1 device kept out'))
    await user.click(within(group).getByRole('button', { name: /^Forget the removal of / }))
    await waitFor(() => expect(screen.queryByTestId('removed-devices')).toBeNull(), T)
  })

  it('an operator can only remove the device and leave its agent running, and the dialog says it comes back', async () => {
    const user = userEvent.setup()
    enableModule('agent-intake', true)
    renderApp('/devices/a-fw01', { role: 'operator' })
    const dialog = await openRemove(user)
    const choice = within(dialog).getByTestId('delete-agent-choice')
    expect(within(choice).getByRole('radio', { name: /Remove and stop its agent/ })).toBeDisabled()
    expect(within(choice).getByRole('radio', { name: /Remove only/ })).toBeChecked()
    expect(choice).toHaveTextContent('adds the device back on its next report')
    expect(dialog).not.toHaveTextContent('Discovery keeps it out')
    await user.click(within(dialog).getByRole('button', { name: 'Remove from list' }))
    await waitFor(() => expect(assetsStore.get().some((a) => a.id === 'a-fw01')).toBe(false), T)
    const removed = await (await fetch(`${location.origin}/api/v1/inventory/removed`)).json() as { items: unknown[] }
    expect(removed.items).toHaveLength(0)
  })

  it('with the Agents module off, nothing reports for the agent: no choice, and the device is kept out', async () => {
    const user = userEvent.setup()
    enableModule('agent-intake', false)
    renderApp('/devices/a-fw01', { role: 'admin' })
    const dialog = await openRemove(user)
    expect(within(dialog).queryByTestId('delete-agent-choice')).toBeNull()
    expect(dialog).toHaveTextContent('Discovery keeps it out from now on')
    await user.click(within(dialog).getByRole('button', { name: 'Remove from list' }))
    await waitFor(() => expect(assetsStore.get().some((a) => a.id === 'a-fw01')).toBe(false), T)
    const removed = await (await fetch(`${location.origin}/api/v1/inventory/removed`)).json() as { items: { agent: string }[] }
    expect(removed.items).toEqual([expect.objectContaining({ agent: 'none' })])
  })

  it('a device with no agent asks nothing about one', async () => {
    const user = userEvent.setup()
    renderApp('/devices/a-pc02', { role: 'admin' })
    const dialog = await openRemove(user)
    expect(within(dialog).queryByTestId('delete-agent-choice')).toBeNull()
    expect(dialog).toHaveTextContent('Discovery keeps it out from now on')
  })

  it('a device with a private main address and a fixed card on another address is said to be kept out, and is', async () => {
    const now = new Date().toISOString()
    assetsStore.update((l) => [...l.filter((a) => a.id !== 'a-rp2'), {
      id: 'a-rp2', site: 'hq', ip: '10.0.10.74', mac: '6a:b2:19:00:00:0a', hostname: 'Sales-Laptop', kind: 'laptop', vendor: null, model: null, os: null,
      software: [], services: [], first_seen: now, last_seen: now, approved: true, fragile: false, origin: 'discovered',
    } as Asset])
    addrStore.update((m) => ({ ...m, 'a-rp2': [{ ip: '10.0.10.75', mac: '3c:22:fb:00:00:75', main: false, source: 'passive', first_seen: now, last_seen: now, agent: false }] }))
    const user = userEvent.setup()
    renderApp('/devices/a-rp2', { role: 'admin' })
    const dialog = await openRemove(user)
    expect(dialog).toHaveTextContent('Discovery keeps it out from now on')
    expect(dialog).not.toHaveTextContent('private Wi-Fi address')
    await user.click(within(dialog).getByRole('button', { name: 'Remove from list' }))
    await waitFor(() => expect(assetsStore.get().some((a) => a.id === 'a-rp2')).toBe(false), T)
    const removed = await (await fetch(`${location.origin}/api/v1/inventory/removed`)).json() as { items: unknown[] }
    expect(removed.items).toHaveLength(1)
  })

  it('a device known only by a private Wi-Fi address is not said to be kept out, and no removal is kept', async () => {
    const now = new Date().toISOString()
    assetsStore.update((l) => [...l.filter((a) => a.id !== 'a-rp1'), {
      id: 'a-rp1', site: 'hq', ip: '10.0.10.70', mac: '6a:b2:19:00:00:09', hostname: 'Guest-Phone', kind: 'smartphone', vendor: null, model: null, os: null,
      software: [], services: [], first_seen: now, last_seen: now, approved: true, fragile: false, origin: 'discovered',
    } as Asset])
    const user = userEvent.setup()
    renderApp('/devices/a-rp1', { role: 'admin' })
    const dialog = await openRemove(user)
    expect(dialog).not.toHaveTextContent('Discovery keeps it out')
    expect(dialog).toHaveTextContent('private Wi-Fi address')
    await user.click(within(dialog).getByRole('button', { name: 'Remove from list' }))
    await waitFor(() => expect(assetsStore.get().some((a) => a.id === 'a-rp1')).toBe(false), T)
    const removed = await (await fetch(`${location.origin}/api/v1/inventory/removed`)).json() as { items: unknown[] }
    expect(removed.items).toHaveLength(0)
  })
})
