// Home shows the first-run summary Vedette sent (or could not send): its title, where the message is, the list it names; Hide keeps
// that summary away, and the summary of a later load comes back.
import { afterEach, describe, expect, it } from 'vitest'
import { cleanup, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { server } from '@/test/server'
import type { FirstRunSummary } from '@/features/findings/types'

const sent: FirstRunSummary = {
  id: 'nt-first-run-install-20261123T094000.000', load: 'install', title: 'Patch first: 7 urgent findings on 3 devices',
  made_at: '2026-11-23T09:40:00.000Z', state: 'sent', sent_at: '2026-11-23T09:42:00.000Z', channels: ['email', 'telegram'],
  due_at: null, quiet: false, not_sent: null, reason: null, link: '/findings?tab=device&status=exploited,public_exploit', later: 0, later_title: null,
}

async function withSummary(f: FirstRunSummary | null, open?: Partial<Record<'exploited' | 'public_exploit', number>>) {
  const { overview } = await import('@/features/findings/modelMocks')
  server.use(http.get('*/api/v1/findings/overview', () => {
    const v = overview()
    return HttpResponse.json({ ...v, first_run_summary: f, open: { ...v.open, by_status: { ...v.open.by_status, ...open } } })
  }))
}

const card = () => screen.findByRole('region', { name: "Vedette's first look at your network" })

describe('feeds: the first-run summary on Home', () => {
  afterEach(() => { for (const k of Object.keys(localStorage)) if (k.startsWith('vedette.home.')) localStorage.removeItem(k) })

  it('a delivered summary: its title, when and where it went, and the list it names; a11y clean', async () => {
    await withSummary(sent, { exploited: 2 })
    renderApp('/')
    const c = await card()
    expect(within(c).getByText('Patch first: 7 urgent findings on 3 devices')).toBeInTheDocument()
    expect(await within(c).findByText(/^Sent .+ by Email and Telegram\.$/)).toBeInTheDocument()
    expect(within(c).getByRole('link', { name: 'Open the list' })).toHaveAttribute('href', '/findings?tab=device&status=exploited,public_exploit')
    expect(within(c).queryByText('Nothing on that list is open any more.')).toBeNull()
    await expectNoA11yViolations()
  })

  it('a summary still waiting says when it goes out, or that quiet hours hold it', async () => {
    const due = new Date(Date.now() + 5 * 60_000).toISOString()
    await withSummary({ ...sent, state: 'waiting', sent_at: null, channels: [], due_at: due })
    renderApp('/')
    expect(await within(await card()).findByText(/^Goes out at .+\. Vedette waits a few minutes so one message covers the whole first pass\.$/)).toBeInTheDocument()
    cleanup()
    await withSummary({ ...sent, state: 'waiting', sent_at: null, channels: [], due_at: due, quiet: true })
    renderApp('/')
    expect(await within(await card()).findByText(/^Held for quiet hours\. It goes out at .+\.$/)).toBeInTheDocument()
  })

  it('a summary no channel took is shown all the same, with why; an administrator gets the way to set up a channel, a viewer does not', async () => {
    const notSent: FirstRunSummary = { ...sent, load: 'catalogue', state: 'not_sent', sent_at: null, channels: [], reason: 'no_channel',
      not_sent: 'Not sent: no alert channel was set up when it was made.' }
    await withSummary(notSent)
    renderApp('/')
    const c = await screen.findByRole('region', { name: 'First load of the vulnerability catalogue' })
    expect(within(c).getByText('Patch first: 7 urgent findings on 3 devices')).toBeInTheDocument()
    expect(within(c).getByText(/^Not sent: no alert channel was set up when it was made\./)).toBeInTheDocument()
    expect(within(c).getByRole('link', { name: 'Set up an alert channel' })).toHaveAttribute('href', '/settings/channels#channels')
    cleanup()
    renderApp('/', { role: 'viewer' })
    const v = await screen.findByRole('region', { name: 'First load of the vulnerability catalogue' })
    expect(within(v).getByText(/^Not sent: no alert channel was set up/)).toBeInTheDocument()
    expect(within(v).queryByRole('link', { name: 'Set up an alert channel' })).toBeNull()
  })

  it('a later summary of the load is named; once nothing on the list is open, the card says so', async () => {
    await withSummary({ ...sent, later: 1, later_title: '2 more urgent findings on 1 device to patch first' }, { exploited: 0, public_exploit: 0 })
    renderApp('/')
    const c = await card()
    expect(within(c).getByText('Since then: 2 more urgent findings on 1 device to patch first')).toBeInTheDocument()
    expect(within(c).getByText('Nothing on that list is open any more.')).toBeInTheDocument()
  })

  it('Hide keeps that summary away; the summary of a later load shows again; none, no card', async () => {
    await withSummary(sent)
    renderApp('/')
    await userEvent.click(within(await card()).getByRole('button', { name: 'Hide' }))
    await waitFor(() => expect(screen.queryByRole('region', { name: "Vedette's first look at your network" })).toBeNull())
    cleanup()
    renderApp('/')
    await screen.findByRole('list', { name: 'Today at a glance' })
    expect(screen.queryByRole('region', { name: "Vedette's first look at your network" })).toBeNull()
    cleanup()
    await withSummary({ ...sent, id: 'nt-first-run-kev-20261201-20261201T080000.000', load: 'source' })
    renderApp('/')
    expect(await screen.findByRole('region', { name: 'First load of a new exploitation news source' })).toBeInTheDocument()
    cleanup()
    await withSummary(null)
    renderApp('/')
    await screen.findByRole('list', { name: 'Today at a glance' })
    expect(screen.queryByRole('region', { name: /first look|First load/ })).toBeNull()
  })
})
