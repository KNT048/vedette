import { describe, expect, it } from 'vitest'
import { cleanup, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { assetsStore, findingsStore } from '@/mocks/stores'
import { metaStore } from '@/features/inventory/mocks'

const T = { timeout: 5000 }

/** A finding of a device nobody approved (the first device, marked not approved). */
function unapprovedDevice() {
  const f = findingsStore.get().find((x) => x.status === 'suspected' || x.status === 'confirmed')!
  assetsStore.set(assetsStore.get().map((a) => (a.id === f.asset_id ? { ...a, approved: false } : a)))
  return f
}

/** Every device not approved: each device block of To fix and Needs your input is one of a device not added yet. */
function noDeviceApproved() {
  assetsStore.set(assetsStore.get().map((a) => ({ ...a, approved: false })))
}

describe('findings of a device that is not added yet', () => {
  it('All open marks them with a compact "Not added yet" chip next to the device; the device link is the way to act', async () => {
    unapprovedDevice()
    renderApp('/findings?tab=open')
    const table = await screen.findByRole('table', undefined, T)
    expect((await within(table).findAllByText('Not added yet', undefined, T)).length).toBeGreaterThan(0)
    expect(within(table).queryByRole('button', { name: 'Add device' })).toBeNull()
  })

  it('To fix: the device block has the chip, and Add device approves the device right there', async () => {
    noDeviceApproved()
    const user = userEvent.setup()
    renderApp('/findings')
    const blocks = await screen.findByRole('list', { name: 'Devices to fix, the most urgent first' }, T)
    const block = blocks.querySelector<HTMLElement>(':scope > li')!
    expect(within(block).getByText('Not added yet')).toBeInTheDocument()
    expect(within(block).getByRole('button', { name: 'Ignore' })).toBeInTheDocument()
    const approved = () => assetsStore.get().filter((a) => a.approved).length
    const before = approved()
    await user.click(within(block).getByRole('button', { name: 'Add device' }))
    await waitFor(() => expect(approved()).toBe(before + 1), T)
  })

  it('Needs your input: the device block has the chip, Add device and Ignore, without opening it', async () => {
    noDeviceApproved()
    renderApp('/findings?tab=input')
    const blocks = await screen.findByRole('list', { name: 'Devices that need your input, the most urgent first' }, T)
    const block = within(blocks).getAllByRole('listitem')[0]!
    expect(within(block).getByText('Not added yet')).toBeInTheDocument()
    expect(within(block).getByRole('button', { name: 'Add device' })).toBeInTheDocument()
    expect(within(block).getByRole('button', { name: 'Ignore' })).toBeInTheDocument()
  })

  it('the finding page says "Device not added yet" once, with Add device and Ignore', async () => {
    const f = unapprovedDevice()
    renderApp(`/findings/${f.id}`)
    expect(await screen.findByText(/Nobody approved this device yet/, undefined, T)).toBeInTheDocument()
    expect(screen.getAllByText('Device not added yet')).toHaveLength(1)
    expect(screen.getByRole('button', { name: 'Add device' })).toBeInTheDocument()
  })

  it('Ignore on the finding hides the device and its findings from Open; they are under Ignored; Restore brings them back', async () => {
    const f = unapprovedDevice()
    const user = userEvent.setup()
    renderApp(`/findings/${f.id}`)
    expect(await screen.findByText(/Nobody approved this device yet/, undefined, T)).toBeInTheDocument()
    await user.click(screen.getAllByRole('button', { name: 'Ignore' })[0]!)
    const dialog = await screen.findByRole('dialog', undefined, T)
    await user.click(within(dialog).getByRole('button', { name: /^Ignore/ }))
    await waitFor(() => expect(metaStore.get()[f.asset_id]?.ignored_at).toBeTruthy(), T)

    cleanup()
    renderApp('/findings?tab=ignored')
    expect(await screen.findByRole('button', { name: 'Restore' }, T)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: f.cve })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Restore' }))
    await waitFor(() => expect(metaStore.get()[f.asset_id]?.ignored_at).toBeFalsy(), T)
  })
})
