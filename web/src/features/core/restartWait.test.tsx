// The one waiting rule of every page that follows a run during which Vedette restarts (useRestartWait): an answer = up, a 401 =
// up with this browser's session gone (the run is over: sign in, the page says why), anything else = still restarting.
import { afterEach, describe, expect, it } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp } from '@/test/render'
import { server } from '@/test/server'
import { sessionStore } from '@/mocks/stores'
import { ApiError } from '@/lib/api'
import { boxAnswer, restartWaitConfig } from './useRestartWait'
import { mockSealed } from './mocks'
import type { RestoreRun } from './types'

const user = () => userEvent.setup()
const run = (status: RestoreRun['status']): RestoreRun => ({ id: 'r1', backup_id: 'b', backup_created_at: '2026-11-01T00:00:00Z', status, started_at: '2026-11-14T00:00:00Z', finished_at: status === 'running' ? null : '2026-11-14T00:04:00Z', user: 'admin@acme.example', pre_restore_backup_id: null, error: null })
const unauthenticated = () => HttpResponse.json({ error: { code: 'unauthenticated', message: 'Sign in first.' } }, { status: 401 })
const signedIn = () => sessionStore.get().userId !== null

describe('boxAnswer', () => {
  it('an answer is up, a 401 is up without this session, anything else is still restarting', () => {
    expect(boxAnswer(null)).toBe('up')
    expect(boxAnswer(new ApiError(401, 'unauthenticated', 'Sign in first.'))).toBe('signedOut')
    expect(boxAnswer(new ApiError(503, 'starting', 'Starting.'))).toBe('down')
    expect(boxAnswer(new ApiError(429, 'rate_limited', 'Slow down.'))).toBe('down')
    expect(boxAnswer(new TypeError('Failed to fetch'))).toBe('down')
  })
})

describe('a restore followed on Settings › Data', () => {
  afterEach(() => { restartWaitConfig.slowMs = 180_000 })

  it('when the restored data does not know this session, the page says the restore finished and takes the person to sign in, then back', async () => {
    const u = user()
    // The box as after a restore: the run is followed while this session lives; the restored data has no such session.
    let restored = false
    server.use(http.get('*/api/v1/core/data/restore/run', () => (signedIn() ? HttpResponse.json(run(restored ? 'done' : 'running')) : unauthenticated())))
    renderApp('/settings/data')
    expect(await screen.findByText(/Vedette is restarting; this page reconnects by itself/)).toBeInTheDocument()
    restored = true
    sessionStore.set({ userId: null })
    const note = await screen.findByText(/The restore has finished and Vedette runs on the restored data/, undefined, { timeout: 8000 })
    expect(note.closest('[role="status"]')).not.toBeNull()
    await u.type(screen.getByLabelText('Email'), 'admin@acme.example')
    await u.type(screen.getByLabelText('Password'), 'vedette-demo')
    await u.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByText(/^Restored the backup from/)).toBeInTheDocument()
    expect(screen.queryByText(/this page reconnects by itself/)).toBeNull()
  })

  it('while the box stays unreachable the page keeps waiting, and after a few minutes offers a reload', async () => {
    restartWaitConfig.slowMs = 0
    let down = false
    server.use(http.get('*/api/v1/core/data/restore/run', () => (down ? HttpResponse.error() : HttpResponse.json(run('running')))))
    renderApp('/settings/data')
    expect(await screen.findByText(/Vedette is restarting; this page reconnects by itself/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Reload the page' })).toBeNull()
    down = true
    expect(await screen.findByRole('button', { name: 'Reload the page' }, { timeout: 8000 })).toBeInTheDocument()
    expect(screen.getByText(/has not answered for a few minutes/)).toBeInTheDocument()
    expect(screen.getByText(/this page reconnects by itself/)).toBeInTheDocument() // still waiting
  })
})

describe('an update followed on Settings › Updates', () => {
  it('a 401 while the run is followed ends the wait on the sign-in page, which says the update finished', async () => {
    const u = user()
    renderApp('/settings/updates')
    await u.click(await screen.findByRole('button', { name: 'Update Vedette software' }))
    await u.click(within(await screen.findByRole('dialog')).getByRole('button', { name: /^Update to / }))
    expect(await screen.findByRole('heading', { name: 'Updating Vedette software to 0.9.4' })).toBeInTheDocument()
    server.use(http.get('*/api/v1/core/updates', () => unauthenticated()))
    expect(await screen.findByText('The update has finished and Vedette has restarted. Sign in again to continue.', undefined, { timeout: 8000 })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Sign in' })).toBeInTheDocument()
  })
})

describe('restore from a file: too many wrong backup passwords', () => {
  it('the wait is said next to the backup password, in the box\'s words', async () => {
    const u = user()
    const msg = 'Too many wrong backup passwords. Try again in 30 seconds.'
    server.use(http.post('*/api/v1/core/data/restore/upload', () => HttpResponse.json({ error: { code: 'rate_limited', message: msg, retry_after: 30 } }, { status: 429, headers: { 'Retry-After': '30' } })))
    renderApp('/settings/data')
    await u.click(await screen.findByRole('button', { name: 'Restore from a file' }))
    const dlg = await screen.findByRole('dialog', { name: 'Restore from a backup file' })
    await u.upload(within(dlg).getByLabelText('Backup file'), new File([await mockSealed('right password', '{}')], 'vedette-backup-2026-11-01-0830.tar.gz.age'))
    const pw = await within(dlg).findByLabelText('Backup password')
    await u.type(pw, 'another wrong one')
    await u.click(within(dlg).getByRole('button', { name: 'Check the file' }))
    expect(await within(dlg).findByText(msg)).toBeInTheDocument()
    expect(pw).toHaveAccessibleDescription(new RegExp(msg))
    expect(within(dlg).queryByText(/sign-in/)).toBeNull()
  })
})
