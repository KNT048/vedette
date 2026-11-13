// A withdrawn running release and stale update information are shown (S-CORE-2 criterion D-386).
import { describe, expect, it } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp } from '@/test/render'
import { server } from '@/test/server'
import { collection } from '@/mocks/db'
import { installStore, sessionStore } from '@/mocks/stores'
import { updIndex } from './mocks'

const SINCE = '2026-11-10T00:00:00Z'
const revoke = (action: 'block_install' | 'block_install_and_warn' | 'rollback_if_possible', id = '0.9.3') =>
  updIndex.update((x) => ({ ...x, revoked: [{ kind: 'release', id, reason: 'the log receiver can lose data.', since: SINCE, action }] })) // its own period is not doubled
const WARN_TITLE = 'Vedette 0.9.3, which this box runs, has been withdrawn'

describe('core: withdrawn running release and stale update information (S-CORE-2 criterion D-386)', () => {
  it.each(['block_install_and_warn', 'rollback_if_possible'] as const)('%s: a banner on every page, for a viewer too, linking to Updates', async (action) => {
    revoke(action)
    renderApp('/', { role: 'viewer' })
    const alert = (await screen.findByText(WARN_TITLE)).closest('[role="alert"]') as HTMLElement
    expect(alert).toHaveTextContent('Reason given by the Vedette project: the log receiver can lose data. Replace it with another release as soon as you can.')
    expect(within(alert).getByRole('link', { name: 'Open Updates' })).toHaveAttribute('href', '/settings/updates')
  })

  it('block_install: no every-page banner; a warning on the Updates page only', async () => {
    revoke('block_install')
    renderApp('/settings/updates')
    const note = (await screen.findByText('Vedette 0.9.3 has been withdrawn')).closest('[role="status"]') as HTMLElement
    expect(note).toHaveTextContent('No box installs it any more; this box keeps running it until the next update.')
    expect(screen.queryByText(WARN_TITLE)).toBeNull() // the every-page banner (Layout) is the same read: it stays empty
  })

  it('a revocation of another release, or of a key, shows nothing', async () => {
    revoke('block_install_and_warn', '0.9.1')
    updIndex.update((x) => ({ ...x, revoked: [...x.revoked, { kind: 'key', id: 'ABCDEF0123456789', reason: 'old key', since: SINCE, action: 'block_install_and_warn' }] }))
    renderApp('/settings/updates')
    await screen.findByRole('table', { name: 'Versions in use' })
    expect(screen.queryByText(/has been withdrawn/)).toBeNull()
  })

  it('stale information: a warning with Check now; a successful check clears it', async () => {
    updIndex.update((x) => ({ ...x, expires_at: SINCE }))
    renderApp('/settings/updates')
    expect(await screen.findByText('The update information on this box is out of date')).toBeInTheDocument()
    expect(screen.getByText(/so newer releases and withdrawn ones may be missing\. The box gets new information at its next update check; if it stays out of date, make sure the box can reach github\.com over HTTPS\./)).toBeInTheDocument()
    await userEvent.setup().click(screen.getByRole('button', { name: 'Check for Vedette releases' }))
    await expect.poll(() => screen.queryByText('The update information on this box is out of date')).toBeNull()
  })

  it('stale information with update checks off: says to turn them on, and no offline bundle in v1 (D-408)', async () => {
    updIndex.update((x) => ({ ...x, expires_at: SINCE }))
    collection<{ update_check: boolean }>('core_privacy', () => ({ update_check: true })).update((p) => ({ ...p, update_check: false }))
    renderApp('/settings/updates')
    expect(await screen.findByText(/Update checks are off in Privacy: turn them on\.$/)).toBeInTheDocument()
    expect(screen.queryByText(/bundle/i)).toBeNull()
  })

  it('stale information and no advisory: does not say there is no known vulnerability (D-408)', async () => {
    sessionStore.set({ userId: 'u-admin' })
    const s = await (await fetch(`${location.origin}/api/v1/core/updates`)).json()
    server.use(http.get('*/api/v1/core/updates', () => HttpResponse.json({ ...s, advisories: [], stale_since: SINCE })))
    renderApp('/settings/updates')
    expect(await screen.findByText('None in the update information this box holds, but that information is out of date: a newer advisory may be missing.')).toBeInTheDocument()
    expect(screen.queryByText('None: no known vulnerability in Vedette.')).toBeNull()
  })

  it('container-only: the same notices, without the offline bundle', async () => {
    installStore.set({ kind: 'container' })
    revoke('block_install')
    updIndex.update((x) => ({ ...x, expires_at: SINCE }))
    collection<{ update_check: boolean }>('core_privacy', () => ({ update_check: true })).update((p) => ({ ...p, update_check: false }))
    renderApp('/settings/updates')
    expect(await screen.findByText('Vedette 0.9.3 has been withdrawn')).toBeInTheDocument()
    expect(await screen.findByText(/Update checks are off in Privacy: turn them on\.$/)).toBeInTheDocument()
  })
})
