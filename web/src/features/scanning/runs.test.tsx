// Runs: every run of every engine on one list, each with its own page that says where it is, why, and what can be done about it.
import { describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { server } from '@/test/server'
import { auditStore } from '@/mocks/stores'
import { runsPoll } from './api'
import { runsStore } from './mocks'

vi.setConfig({ testTimeout: 20_000 })
const T = { timeout: 5000 }
const range = () => screen.getAllByRole('status').map((s) => s.textContent ?? '').find((x) => /^\d+–\d+ of \d+/.test(x)) ?? ''

describe('Settings › Scanning › Runs', () => {
  it('lists every engine\'s runs with their state and reason; a state filter asks the box and the run opens its page', async () => {
    const asked: string[] = []
    server.events.on('request:start', ({ request }) => { const u = new URL(request.url); if (u.pathname === '/api/v1/runs') asked.push(u.search) })
    const user = userEvent.setup()
    renderApp('/settings/scanning?tab=runs')
    const table = await screen.findByRole('table', { name: 'Runs of every engine' }, T)
    const sweep = within(table).getByRole('link', { name: 'LAN sweep of 192.0.2.0/24, 10.20.0.0/16' })
    expect(sweep).toHaveAttribute('href', '/runs/run-m1')
    // each row reads as the box's own line of words
    expect(within(table).getByText('Waiting for the scan window (opens 23:00); 6,528 of 65,792 addresses')).toBeInTheDocument()
    expect(within(table).getByText('Stopped: Vedette restarted')).toBeInTheDocument()
    expect(within(table).getByText('Queued behind “Check NAS-PHOTOS”; it starts when that run ends')).toBeInTheDocument()
    await user.selectOptions(screen.getByRole('combobox', { name: 'State' }), 'queued')
    await waitFor(() => expect(asked.at(-1)).toBe('?status=queued&limit=25'), T)
    await waitFor(() => expect(within(screen.getByRole('table', { name: 'Runs of every engine' })).queryByRole('link', { name: /LAN sweep/ })).toBeNull(), T)
    expect(within(screen.getByRole('table', { name: 'Runs of every engine' })).getByRole('link', { name: 'Check WEB01' })).toHaveAttribute('href', '/runs/run-m3')
    server.events.removeAllListeners()
  })

  it('a list on page 2 stays on page 2 while it is read again', async () => {
    runsPoll.waitingMs = 200
    runsStore.update((l) => [...l, ...Array.from({ length: 40 }, (_, i) => ({ ...l[3]!, id: `run-x${i}`, title: `Vulnerability checks ${i}`, queued_at: new Date(Date.UTC(2026, 10, 1, 0, i)).toISOString() }))])
    renderApp('/settings/scanning?tab=runs&runs.page=2')
    await screen.findByRole('table', { name: 'Runs of every engine' }, T)
    await waitFor(() => expect(range()).toMatch(/^26–\d+ of \d+/), T)
    const first = range()
    await new Promise((r) => setTimeout(r, 600)) // a few reads of the list
    expect(range()).toBe(first)
    runsPoll.waitingMs = 30_000
  })
})

describe('/runs/<id>: one run', () => {
  it('a waiting sweep says what it waits for, its progress per range and the devices it found; an admin resumes it', async () => {
    const user = userEvent.setup()
    renderApp('/runs/run-m1')
    expect(await screen.findByRole('heading', { level: 1, name: 'LAN sweep of 192.0.2.0/24, 10.20.0.0/16' }, T)).toBeInTheDocument()
    expect(screen.getByText('Waiting for the scan window (opens 23:00); 6,528 of 65,792 addresses')).toBeInTheDocument()
    expect(screen.getByText('About 9 more nights at 50 packets/s')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'NAS-PHOTOS' })).toHaveAttribute('href', '/devices/a-nas02')
    expect(screen.getByText('10.20.3.17').closest('a')).toBeNull() // an address no device has yet is not a link
    expect(screen.getByRole('link', { name: 'Runs' })).toHaveAttribute('href', '/settings/scanning?tab=runs')
    await user.click(screen.getByRole('button', { name: 'Resume' }))
    await waitFor(() => expect(runsStore.get().find((r) => r.id === 'run-m1')!.status).toBe('queued'), T)
    expect(auditStore.get().some((a) => a.action === 'scanning.run_resume' && a.target === 'run-m1')).toBe(true)
  })

  it('an operator may stop it, after a question; Resume of a sweep is not offered (the box says it needs an administrator)', async () => {
    const user = userEvent.setup()
    renderApp('/runs/run-m1', { role: 'operator' })
    await user.click(await screen.findByRole('button', { name: 'Stop' }, T))
    expect(screen.queryByRole('button', { name: 'Resume' })).toBeNull()
    const dlg = await screen.findByRole('dialog', { name: 'Stop this run?' })
    await user.click(within(dlg).getByRole('button', { name: 'Stop the run' }))
    await waitFor(() => expect(runsStore.get().find((r) => r.id === 'run-m1')!.status).toBe('stopped'), T)
    expect(await screen.findByText('Stopped by it@acme.example; 6,528 of 65,792 addresses done', {}, T)).toBeInTheDocument()
  })

  it('a queued run names the run it waits for, with its link; a viewer gets no Stop', async () => {
    renderApp('/runs/run-m3', { role: 'viewer' })
    expect(await screen.findByRole('link', { name: 'Check NAS-PHOTOS' }, T)).toHaveAttribute('href', '/runs/run-m2')
    expect(screen.getByText('Queued behind')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Stop' })).toBeNull()
  })

  it('a run that is not kept says so and leads to every run', async () => {
    renderApp('/runs/run-nope')
    expect(await screen.findByText('This run is not kept: it does not exist, or it ended more than 400 days ago.', {}, T)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'See every run' })).toHaveAttribute('href', '/settings/scanning?tab=runs')
  })
})
