import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp } from '@/test/render'
import { server } from '@/test/server'
import { api } from '@/lib/api'
import { auditStore, findingsStore, sessionStore } from '@/mocks/stores'
import { basisLabel } from './basis'
import type { FindingDetail } from './types'

const T = { timeout: 5000 }
const row = (id: string) => findingsStore.get().find((f) => f.id === id)!

describe('a person confirms a suspected finding', () => {
  it('the finding page says why it is only suspected, takes a note to confirm, shows who confirmed, and Undo returns it', async () => {
    renderApp('/findings/f-2')
    // what would confirm it, in words, above the evidence
    const why = await screen.findByTestId('suspected-why', undefined, T)
    expect(why).toHaveTextContent(/only/)
    expect(why).toHaveTextContent('Last, confirm it yourself.')

    await userEvent.click(screen.getByRole('button', { name: 'Confirm vulnerability' }))
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
    expect((await screen.findAllByText('Confirmed by a person', undefined, T)).length).toBeGreaterThan(0)
    expect(screen.getByText('Confirmed by admin@acme.example: Logged in to the admin page, it runs 6.4')).toBeInTheDocument()
    expect(screen.queryByTestId('suspected-why')).toBeNull()
    expect(auditStore.get().some((a) => a.action === 'findings.confirm')).toBe(true)

    // Undo goes back to suspected, with the reason line again
    await userEvent.click(screen.getByRole('button', { name: 'Undo confirm' }))
    await waitFor(() => expect(row('f-2').status).toBe('suspected'), T)
    expect(row('f-2').basis).not.toBe('person')
    expect(await screen.findByTestId('suspected-why', undefined, T)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Confirm vulnerability' })).toBeInTheDocument()
    expect(auditStore.get().some((a) => a.action === 'findings.unconfirm')).toBe(true)
  })

  it('on a suspected finding the ways to confirm it come in order: the device reports its version, then a check only when one exists, Confirm last', async () => {
    renderApp('/findings/f-2')
    const ways = await screen.findByTestId('confirm-ways', undefined, T)
    const items = within(ways).getAllByRole('listitem')
    expect(items[0]).toHaveTextContent(/^Let the device report its version itself/)
    expect(items.at(-1)).toHaveTextContent(/^Last, if you checked the device yourself, confirm it\./)
    expect(within(items.at(-1)!).getByRole('button', { name: 'Confirm vulnerability' })).toBeInTheDocument()
    // "Run the check" is offered only when the CVE has a safe check
    const check = within(ways).queryByRole('link', { name: 'run the check on the device page' })
    const finding = findingsStore.get().find((f) => f.id === 'f-2')!
    expect(finding.status).toBe('suspected')
    expect(!!check).toBe(items.length === 3)
  })

  it('an operator or a viewer, who cannot confirm, is not told to confirm it: no "confirm it yourself" and no Confirm step', async () => {
    for (const role of ['operator', 'viewer'] as const) {
      const { unmount } = renderApp('/findings/f-2', { role })
      const why = await screen.findByTestId('suspected-why', undefined, T)
      expect(why).toHaveTextContent(/only/)
      expect(why).not.toHaveTextContent(/confirm it yourself/)
      const ways = screen.getByTestId('confirm-ways')
      expect(within(ways).queryByText(/if you checked the device yourself/)).toBeNull()
      expect(within(ways).queryByRole('button', { name: 'Confirm vulnerability' })).toBeNull()
      unmount()
    }
  })

})

describe('a finding open again after a handling', () => {
  it('says on its page why it is open again', async () => {
    renderApp('/findings/fv-srvad-win-2')
    expect(await screen.findByTestId('reopened-line', undefined, T)).toHaveTextContent(/^Reopened: a reading newer than the patched mark still shows the affected version \(/)
  })
})

describe('an update-recommended finding asks for no confirmation', () => {
  it('offers no Confirm anywhere on its page, no "confirm it yourself", and its title says an update is recommended', async () => {
    sessionStore.set({ userId: 'u-admin' })
    const real = await api.get<FindingDetail>('/findings/f-2')
    server.use(http.get('*/api/v1/findings/f-2', () => HttpResponse.json({ ...real, urgency: 5 })))
    renderApp('/findings/f-2')
    expect(await screen.findByRole('heading', { level: 1, name: /may be affected by CVE-2026-119977: an update is recommended$/ }, T)).toBeInTheDocument()
    expect(await screen.findByTestId('suspected-why', undefined, T)).not.toHaveTextContent(/confirm it yourself/)
    expect(screen.queryByTestId('confirm-ways')).toBeNull()
    expect(screen.queryByRole('button', { name: 'Confirm vulnerability' })).toBeNull()
  })

  it('a layer that asks for one (exploited) still offers it', async () => {
    sessionStore.set({ userId: 'u-admin' })
    const real = await api.get<FindingDetail>('/findings/f-2')
    server.use(http.get('*/api/v1/findings/f-2', () => HttpResponse.json({ ...real, urgency: 2 })))
    renderApp('/findings/f-2')
    expect(await screen.findByRole('heading', { level: 1, name: /needs checking$/ }, T)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Confirm vulnerability' })).toBeInTheDocument()
  })
})

describe('a version the device itself reports', () => {
  it('reads as confirmed by it; a banner or a typed version stays "By version"', () => {
    const at = '2026-11-18T00:00:00Z'
    expect(basisLabel({ basis: 'version', evidence: { summary: 's', checked_at: at, source: 'snmp' } })).toBe('basis.device')
    expect(basisLabel({ basis: 'version', evidence: { summary: 's', checked_at: at, source: 'agent' } })).toBe('basis.device')
    expect(basisLabel({ basis: 'version', evidence: { summary: 's', checked_at: at } })).toBe('basis.version')
    expect(basisLabel({ basis: 'scan', evidence: null })).toBe('basis.scan')
  })
})
