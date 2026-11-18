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

describe('findings of a device that is not added yet', () => {
  it('the list marks them and Add device approves the device right there', async () => {
    const f = unapprovedDevice()
    const user = userEvent.setup()
    renderApp('/findings?tab=open')
    const marks = await screen.findAllByText('Device not added yet', undefined, T)
    expect(marks.length).toBeGreaterThan(0)
    await user.click(screen.getAllByRole('button', { name: 'Add device' })[0]!)
    await waitFor(() => expect(assetsStore.get().find((a) => a.id === f.asset_id)!.approved).toBe(true), T)
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
