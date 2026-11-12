// A withdrawn running release and stale update information are shown (S-CORE-2 criterion D-386).
import { describe, expect, it } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { collection } from '@/mocks/db'
import { updIndex } from './mocks'

const SINCE = '2026-11-10T00:00:00Z'
const revoke = (action: 'block_install' | 'block_install_and_warn' | 'rollback_if_possible', id = '0.9.3') =>
  updIndex.update((x) => ({ ...x, revoked: [{ kind: 'release', id, reason: 'the log receiver can lose data', since: SINCE, action }] }))
const WARN_TITLE = 'Vedette 0.9.3, which this box runs, has been withdrawn'

describe('core: withdrawn running release and stale update information (S-CORE-2 criterion D-386)', () => {
  it.each(['block_install_and_warn', 'rollback_if_possible'] as const)('%s: a banner on every page, for a viewer too, linking to Updates', async (action) => {
    revoke(action)
    renderApp('/', { role: 'viewer' })
    const alert = (await screen.findByText(WARN_TITLE)).closest('[role="alert"]') as HTMLElement
    expect(alert).toHaveTextContent('Reason given by the Vedette project: the log receiver can lose data. Install the newer release, or roll back, as soon as you can.')
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

  it('stale information with update checks off: says to turn them on or import a bundle', async () => {
    updIndex.update((x) => ({ ...x, expires_at: SINCE }))
    collection<{ update_check: boolean }>('core_privacy', () => ({ update_check: true })).update((p) => ({ ...p, update_check: false }))
    renderApp('/settings/updates')
    expect(await screen.findByText(/Update checks are off in Privacy: turn them on or import an offline bundle\./)).toBeInTheDocument()
  })
})
