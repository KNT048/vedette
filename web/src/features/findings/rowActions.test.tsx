// A finding is handled on its own row, without ticking it first: one visible action (Confirm on a suspected finding, else
// "Mark as handled…"), the rest in a More actions menu; every label names the CVE and the device.
import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { assetsStore, findingsStore } from '@/mocks/stores'

const T = { timeout: 5000 }

describe('row actions of a finding', () => {
  it('All open: a suspected row shows only Confirm; Mark as handled… is in its menu and marks it with the usual dialog', async () => {
    const f = findingsStore.get().find((x) => x.status === 'suspected')!
    const user = userEvent.setup()
    renderApp('/findings?tab=open')
    const table = await screen.findByRole('table', undefined, T)
    const confirm = await within(table).findByRole('button', { name: new RegExp(`^Confirm ${f.cve} on `) }, T)
    const row = confirm.closest('tr')!
    expect(within(row).queryByRole('button', { name: /^Mark as handled/ })).toBeNull()
    await user.click(within(row).getByRole('button', { name: new RegExp(`^More actions for ${f.cve} on `) }))
    await user.click(await screen.findByRole('menuitem', { name: 'Mark as handled…' }, T))
    const dialog = await screen.findByRole('dialog', { name: 'Mark as handled' }, T)
    await user.click(within(dialog).getByRole('radio', { name: /^Mitigated/ }))
    await user.click(within(dialog).getByRole('button', { name: 'Save status' }))
    await waitFor(() => expect(findingsStore.get().find((x) => x.id === f.id)!.status).toBe('mitigated'), T)
  })

  it('a device not added yet: the row keeps the chip; Add device and Ignore are in the row menu, not buttons on the row', async () => {
    const f = findingsStore.get().find((x) => x.status === 'confirmed')!
    assetsStore.set(assetsStore.get().map((a) => (a.id === f.asset_id ? { ...a, approved: false } : a)))
    const user = userEvent.setup()
    renderApp('/findings?tab=open')
    const table = await screen.findByRole('table', undefined, T)
    const mark = await within(table).findByRole('button', { name: new RegExp(`^Mark as handled: ${f.cve} on `) }, T)
    const row = mark.closest('tr')!
    expect(within(row).getByText('Not added yet')).toBeInTheDocument()
    expect(within(row).queryByRole('button', { name: /^Add device/ })).toBeNull()
    await user.click(within(row).getByRole('button', { name: new RegExp(`^More actions for ${f.cve} on `) }))
    expect(await screen.findByRole('menuitem', { name: 'Add device' }, T)).toBeInTheDocument()
    expect(screen.getByRole('menuitem', { name: 'Ignore' })).toBeInTheDocument()
  })

  it('the All open status filter names every choice (no raw key)', async () => {
    renderApp('/findings?tab=open')
    const group = await screen.findByRole('group', { name: 'Filter by status' }, T)
    expect(within(group).getAllByRole('button').map((b) => b.textContent)).toEqual(['All unresolved', 'Confirmed', 'Suspected or detected'])
  })
})
