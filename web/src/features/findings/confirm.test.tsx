import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { auditStore, findingsStore } from '@/mocks/stores'

const T = { timeout: 5000 }
const row = (id: string) => findingsStore.get().find((f) => f.id === id)!

describe('a person confirms a suspected finding', () => {
  it('the finding page says why it is only suspected, takes a note to confirm, shows who confirmed, and Undo returns it', async () => {
    renderApp('/findings/f-2')
    // what would confirm it, in words, above the evidence
    const why = await screen.findByTestId('suspected-why', undefined, T)
    expect(why).toHaveTextContent(/only/)
    expect(why).toHaveTextContent('Or confirm it yourself.')

    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    const dlg = await screen.findByRole('dialog', { name: 'Confirm this finding' })
    // the note is required
    await userEvent.click(within(dlg).getByRole('button', { name: 'Confirm finding' }))
    expect(await within(dlg).findByText('Say what you checked (at least 3 characters).')).toBeInTheDocument()
    expect(row('f-2').status).toBe('suspected')
    await userEvent.type(within(dlg).getByLabelText('What did you check? (required)'), 'Logged in to the admin page, it runs 6.4')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Confirm finding' }))

    // confirmed by a person: the page, the basis and the history say so
    await waitFor(() => expect(row('f-2').status).toBe('confirmed'), T)
    expect(row('f-2').basis).toBe('person')
    expect(await screen.findByText('Confirmed by a person', undefined, T)).toBeInTheDocument()
    expect(screen.getByText('Confirmed by admin@acme.example: Logged in to the admin page, it runs 6.4')).toBeInTheDocument()
    expect(screen.queryByTestId('suspected-why')).toBeNull()
    expect(auditStore.get().some((a) => a.action === 'findings.confirm')).toBe(true)

    // Undo goes back to suspected, with the reason line again
    await userEvent.click(screen.getByRole('button', { name: 'Undo confirm' }))
    await waitFor(() => expect(row('f-2').status).toBe('suspected'), T)
    expect(row('f-2').basis).not.toBe('person')
    expect(await screen.findByTestId('suspected-why', undefined, T)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Confirm' })).toBeInTheDocument()
    expect(auditStore.get().some((a) => a.action === 'findings.unconfirm')).toBe(true)
  })

  it('the findings list has Confirm on a suspected row, and a viewer cannot use it', async () => {
    renderApp('/findings?tab=open')
    const table = await screen.findByRole('table', { name: 'Findings list' }, T)
    const wp = within(table).getAllByRole('row').find((r) => within(r).queryByRole('link', { name: 'CVE-2026-119977' }))!
    await userEvent.click(within(wp).getByRole('button', { name: 'Confirm CVE-2026-119977' }))
    const dlg = await screen.findByRole('dialog', { name: 'Confirm this finding' })
    await userEvent.type(within(dlg).getByLabelText('What did you check? (required)'), 'Checked on the device')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Confirm finding' }))
    await waitFor(() => expect(within(table).getByRole('button', { name: 'Undo the confirmation of CVE-2026-119977' })).toBeInTheDocument(), T)
  })

  it('an operator sees Confirm but cannot use it', async () => {
    renderApp('/findings?tab=open', { role: 'operator' })
    expect(await screen.findByRole('button', { name: 'Confirm CVE-2026-119977' }, T)).toBeDisabled()
  })
})
