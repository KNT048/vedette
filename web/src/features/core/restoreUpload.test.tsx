// Restore from a backup file on a new box, the decryption key kept apart, and the list read again after a restore (S-CORE-1, D-518).
import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, renderHook, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { renderApp } from '@/test/render'
import { server } from '@/test/server'
import { MOCK_SETUP_CODE } from './mocks'
import { useRestoreRun } from './api'
import type { RestoreRun } from './types'

const user = () => userEvent.setup()
const gzip = () => new File([new Uint8Array([0x1f, 0x8b, 8, 0, 0, 0, 0, 0])], 'vedette-backup-2026-11-01.tar.gz', { type: 'application/gzip' })

/** D-544: the restore is offered on the Account step, after the terms of use were ticked on the first. */
async function openRestore(u: ReturnType<typeof user>) {
  renderApp('/setup', { role: null, setupComplete: false })
  await u.click(await screen.findByRole('checkbox', { name: 'I have read, understood and agree to the terms of use' }))
  await u.click(screen.getByRole('button', { name: 'Continue' }))
  await u.click(await screen.findByRole('button', { name: 'Restore from a backup' }))
}

async function checkBackup(u: ReturnType<typeof user>) {
  await openRestore(u)
  await u.type(screen.getByLabelText('Setup code'), MOCK_SETUP_CODE)
  await u.upload(screen.getByLabelText('Backup file'), gzip())
}

describe('first-run restore from a backup file (D-518)', () => {
  it('without the key: says what is lost before Restore, which waits for "I understand", then sends to sign in', async () => {
    const u = user()
    await checkBackup(u)
    expect(screen.getByText('Without the decryption key:')).toBeInTheDocument()
    await u.click(screen.getByRole('button', { name: 'Check the backup' }))
    const held = await screen.findByLabelText('What the backup holds')
    within(held).getByText(/Backup of Acme Manufacturing/)
    within(held).getByText('6 saved secrets will be lost and must be entered again.')
    within(held).getByText('1 users sign in with two-step and will not be able to sign in.')
    const restore = screen.getByRole('button', { name: 'Restore' })
    expect(restore).toBeDisabled()
    await u.click(within(held).getByLabelText(/I understand/))
    await u.click(restore)
    await screen.findByText(/Your data is back/)
    expect(screen.getByRole('button', { name: 'Go to sign in' })).toBeInTheDocument()
  })

  it('with the key: no loss to confirm; a file that is not a key is refused next to its field', async () => {
    const u = user()
    await checkBackup(u)
    await u.upload(screen.getByLabelText('Decryption key file (optional)'), new File([new Uint8Array(5)], 'notakey.key'))
    expect(screen.queryByText('Without the decryption key:')).toBeNull()
    await u.click(screen.getByRole('button', { name: 'Check the backup' }))
    await screen.findByText(/Backup of Acme Manufacturing/)
    expect(screen.queryByLabelText(/I understand/)).toBeNull()
    await u.click(screen.getByRole('button', { name: 'Restore' }))
    await screen.findByText(/not a Vedette decryption key file/)
    await u.upload(screen.getByLabelText('Decryption key file (optional)'), new File([new Uint8Array(32).fill(7)], 'vedette-key-2026-11-01.key'))
    await u.click(screen.getByRole('button', { name: 'Restore' }))
    await screen.findByText(/Your data is back/)
  })

  it('a backup with no saved secrets: the key file is not needed and not sent', async () => {
    const u = user()
    server.use(http.post('*/api/v1/core/setup/restore/upload', () => HttpResponse.json({ id: 'a'.repeat(32), created_at: '2026-11-01T08:30:00Z', org: 'Acme Manufacturing', users: 2, twofa_users: 0, admins_without_key: 2, secrets: 0 })))
    let sent: Record<string, unknown> = {}
    server.use(http.post('*/api/v1/core/setup/restore', async ({ request }) => { sent = await request.json() as Record<string, unknown>; return HttpResponse.json({ status: 'running', error: null }, { status: 202 }) }))
    await checkBackup(u)
    await u.upload(screen.getByLabelText('Decryption key file (optional)'), new File([new Uint8Array(32).fill(7)], 'vedette-key-2026-11-01.key'))
    await u.click(screen.getByRole('button', { name: 'Check the backup' }))
    await screen.findByText(/the key file is not needed: the box keeps its own key/)
    await u.click(screen.getByRole('button', { name: 'Restore' }))
    await waitFor(() => expect(sent.upload_id).toBe('a'.repeat(32)))
    expect(sent.key).toBeUndefined()
    expect(sent.accept_terms).toBe(true) // the box refuses a restore without it (D-544)
  })

  it('a wrong setup code is said next to the code', async () => {
    const u = user()
    await openRestore(u)
    await u.type(screen.getByLabelText('Setup code'), 'nope')
    await u.upload(screen.getByLabelText('Backup file'), gzip())
    await u.click(screen.getByRole('button', { name: 'Check the backup' }))
    await screen.findByText(/The setup code is missing or wrong/)
  })
})

describe('Settings → Data: the decryption key kept apart (A13-2)', () => {
  afterEach(() => vi.restoreAllMocks())
  it('says what the backup cannot restore without the key, and downloads the key behind the password', async () => {
    const u = user()
    renderApp('/settings/data')
    await screen.findByText('Keep the decryption key apart')
    expect(screen.getByText(/not the saved secrets/)).toBeInTheDocument()
    URL.createObjectURL = vi.fn(() => 'blob:x'); URL.revokeObjectURL = vi.fn()
    let saved = ''
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) { saved = this.download })
    await u.click(screen.getByRole('button', { name: 'Download decryption key' }))
    const dlg = await screen.findByRole('dialog', { name: 'Download the decryption key?' })
    await u.type(within(dlg).getByLabelText('Your current password'), 'wrong')
    await u.click(within(dlg).getByRole('button', { name: 'Download' }))
    await within(dlg).findByText(/Wrong password/)
    expect(saved).toBe('')
    await u.clear(within(dlg).getByLabelText('Your current password'))
    await u.type(within(dlg).getByLabelText('Your current password'), 'vedette-demo')
    await u.click(within(dlg).getByRole('button', { name: 'Download' }))
    await waitFor(() => expect(saved).toMatch(/^vedette-key-\d{4}-\d{2}-\d{2}\.key$/))
  })
})

describe('A13-1: the list of backups is read again when a restore ends', () => {
  it('a run seen running and then ended invalidates the backups', async () => {
    const run = (status: RestoreRun['status']): RestoreRun => ({ id: 'r1', backup_id: 'b', backup_created_at: '2026-11-01T00:00:00Z', status, started_at: '2026-11-14T00:00:00Z', finished_at: null, user: 'admin@acme.example', pre_restore_backup_id: null, error: null })
    let n = 0
    server.use(http.get('*/api/v1/core/data/restore/run', () => HttpResponse.json(run(n++ === 0 ? 'running' : 'done'))))
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    const { result } = renderHook(() => useRestoreRun(), { wrapper })
    await waitFor(() => expect(result.current.data?.status).toBe('running'))
    const spy = vi.spyOn(qc, 'invalidateQueries')
    await act(async () => { await result.current.refetch() })
    await waitFor(() => expect(result.current.data?.status).toBe('done'))
    expect(spy).toHaveBeenCalledWith({ queryKey: ['core', 'backups'] })
    qc.clear()
  })
})
