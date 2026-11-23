// The shared schedule editor against the schedules mock: the line it shows, the dialog with the next three starts, the owner's limits
// with their reason, pause and resume, and Run now opening the run it started.
import { useState } from 'react'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import { server } from '@/test/server'
import userEvent from '@testing-library/user-event'
import { QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router'
import { Toaster } from 'sonner'
import { beforeEach, describe, expect, it } from 'vitest'
import { makeQueryClient } from '@/app/App'
import { orgStore, sessionStore } from '@/mocks/stores'
import { expectNoA11yViolations } from '@/test/render'
import { ScheduleEditor } from './ScheduleEditor'

const T = { timeout: 3000 }

function Harness({ ownerKey, runNow }: { ownerKey: string; runNow?: boolean }) {
  const [qc] = useState(makeQueryClient)
  return (
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/']}>
        <Routes>
          <Route path="/" element={<ScheduleEditor ownerKey={ownerKey} name="Outside scan" runNow={runNow} />} />
          <Route path="/runs/:id" element={<p>Run page</p>} />
        </Routes>
      </MemoryRouter>
      <Toaster />
    </QueryClientProvider>
  )
}

const as = (userId: string) => { orgStore.update((o) => ({ ...o, setup_complete: true, timezone: 'Europe/Berlin' })); sessionStore.set({ userId }) }

describe('ScheduleEditor', () => {
  beforeEach(() => as('u-admin'))

  it('shows the rule and the next start, and changes it in a dialog with the next three starts', async () => {
    const u = userEvent.setup()
    render(<Harness ownerKey="exposure.target:xt-11" />)
    expect(await screen.findByText('Every 3 days at 02:30, only Mon–Fri, all day', undefined, T)).toBeInTheDocument()
    expect(screen.getByText(/^Next start: /)).toBeInTheDocument()
    await u.click(screen.getByRole('button', { name: 'Change the schedule of Outside scan' }))
    const dlg = within(await screen.findByRole('dialog', { name: 'Schedule: Outside scan' }))
    // the window this rule has is shown at once, the rest of the details stay one click away
    expect(dlg.getByRole('button', { name: 'Time zone, window, pause' })).toHaveAttribute('aria-expanded', 'true')
    await u.selectOptions(dlg.getByLabelText('Repeat'), 'weekly')
    await u.click(within(dlg.getByRole('group', { name: 'On' })).getByLabelText('Thursday'))
    expect((await dlg.findAllByRole('listitem', undefined, T))).toHaveLength(3)
    await u.click(dlg.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('Weekly on Mon, Thu at 02:30, only Mon–Fri, all day', undefined, T)).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('refuses what the owner does not allow and says why at the field', async () => {
    const u = userEvent.setup()
    render(<Harness ownerKey="feeds.source:nvd" />)
    await u.click(await screen.findByRole('button', { name: 'Change the schedule of Outside scan' }, T))
    const dlg = within(await screen.findByRole('dialog'))
    // only an interval: no Repeat choice, and no minutes below the owner's hour
    expect(dlg.queryByLabelText('Repeat')).toBeNull()
    expect(within(dlg.getByLabelText('Unit')).getAllByRole('option').map((o) => o.textContent)).toEqual(['hour', 'day'])
    expect(dlg.getByText('Sources ask clients not to poll more often.')).toBeInTheDocument()
    await u.clear(dlg.getByLabelText('Every'))
    await u.type(dlg.getByLabelText('Every'), '0')
    // 0 reads as every other value below the owner's minimum, in plain words (never the API's field name), and Save sends nothing
    expect(await dlg.findByText('The interval is at least 1 hour. Sources ask clients not to poll more often.', undefined, T)).toBeInTheDocument()
    await u.click(dlg.getByRole('button', { name: 'Save' }))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(dlg.queryByText(/every_minutes/)).toBeNull()
  })

  it('the next starts name their zone, and a start the window moved off the asked time says so and why', async () => {
    const u = userEvent.setup()
    render(<Harness ownerKey="exposure.target:xt-14" />)
    await u.click(await screen.findByRole('button', { name: 'Change the schedule of Outside scan' }, T))
    const dlg = within(await screen.findByRole('dialog'))
    expect(await dlg.findByText(/^Next starts \(.+ time\)$/, undefined, T)).toBeInTheDocument()
    await u.selectOptions(dlg.getByLabelText('Repeat'), 'interval')
    await u.clear(dlg.getByLabelText('Every'))
    await u.type(dlg.getByLabelText('Every'), '3')
    await u.selectOptions(dlg.getByLabelText('Unit'), 'days')
    fireEvent.change(dlg.getByLabelText(/^At/), { target: { value: '02:30' } })
    await waitFor(() => expect(dlg.getAllByRole('listitem').length).toBeGreaterThan(0), T)
    // the box moves a start to the window's opening (22:00 in Ho Chi Minh City): the line says when and why
    server.use(http.post('*/api/v1/schedules/preview', () => HttpResponse.json({ zone: 'Asia/Ho_Chi_Minh', upcoming: ['2026-11-25T19:30:00.000Z', '2026-11-30T15:00:00.000Z'] })))
    await u.clear(dlg.getByLabelText('Every'))
    await u.type(dlg.getByLabelText('Every'), '4')
    expect(await dlg.findByText(/moved off 02:30 into the/, undefined, T)).toBeInTheDocument()
    expect(dlg.getAllByText(/moved off/)).toHaveLength(1) // the 02:30 start is not
    expect(dlg.getByText('Next starts (Asia/Ho_Chi_Minh time)')).toBeInTheDocument()
  })

  it('"Only on chosen days and hours" starts with every day; with no day left it says so in words and asks the box nothing', async () => {
    const u = userEvent.setup()
    let previews = 0
    render(<Harness ownerKey="exposure.target:xt-14" />)
    await u.click(await screen.findByRole('button', { name: 'Change the schedule of Outside scan' }, T))
    const dlg = within(await screen.findByRole('dialog'))
    if (dlg.getByRole('button', { name: 'Time zone, window, pause' }).getAttribute('aria-expanded') !== 'true') await u.click(dlg.getByRole('button', { name: 'Time zone, window, pause' }))
    await u.selectOptions(dlg.getByLabelText('When it may start'), 'custom')
    const days = within(dlg.getByRole('group', { name: 'Days' }))
    expect(days.getAllByRole('checkbox').every((c) => c.getAttribute('aria-checked') === 'true' || (c as HTMLInputElement).checked)).toBe(true)
    expect(await dlg.findByText(/^Next starts/, undefined, T)).toBeInTheDocument()
    server.events.on('request:start', ({ request }) => { if (request.url.includes('/schedules/preview')) previews++ })
    for (const c of days.getAllByRole('checkbox')) await u.click(c)
    expect(await dlg.findByText('Pick at least one day: with no day chosen it never starts.', undefined, T)).toBeInTheDocument()
    expect(dlg.queryByText(/window_days/)).toBeNull()
    const before = previews
    await new Promise((r) => setTimeout(r, 400))
    expect(previews).toBe(before)
    server.events.removeAllListeners('request:start')
  })

  it('a stored window of chosen days with an empty day list opens with every day ticked', async () => {
    const { toDraft } = await import('./rule')
    const s = { enabled: true, rule: { freq: 'weekly', every_minutes: null, at_time: '02:00', weekdays: [1], month_day: null, once_at: null, tz: 'org', window: 'custom', window_days: [], window_from: '22:00', window_to: '06:00' }, limits: { min_every_minutes: 60, max_every_minutes: 43200 } }
    expect(toDraft(s as never, 'Europe/Berlin').windowDays).toEqual([1, 2, 3, 4, 5, 6, 7])
  })

  it('pauses, resumes and runs once, opening the run it started', async () => {
    const u = userEvent.setup()
    render(<Harness ownerKey="exposure.target:xt-14" />)
    await u.click(await screen.findByRole('button', { name: 'Change the schedule of Outside scan' }, T))
    const dlg = within(await screen.findByRole('dialog'))
    // nobody saved this one yet: a target's scans are on by default (weekly), so the fields show at once
    expect(dlg.getByRole('switch', { name: 'Run on a schedule' })).toBeChecked()
    await u.click(dlg.getByRole('button', { name: 'Time zone, window, pause' }))
    fireEvent.change(dlg.getByLabelText('Pause until'), { target: { value: new Date(Date.now() + 10 * 864e5).toISOString().slice(0, 10) } })
    await u.click(dlg.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText(/^Paused until /, undefined, T)).toBeInTheDocument()
    await u.click(screen.getByRole('button', { name: 'Resume' }))
    expect(await screen.findByText(/^Next start: /, undefined, T)).toBeInTheDocument()
    await u.click(screen.getByRole('button', { name: 'Run Outside scan now' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Open the run' }, T)) // the toast's own pointer handling needs a real browser
    expect(await screen.findByText('Run page')).toBeInTheDocument()
  })

  it('a schedule only an administrator may change is read-only for an operator', async () => {
    as('u-op')
    render(<Harness ownerKey="scan.vuln" />)
    const change = await screen.findByRole('button', { name: 'Change the schedule of Outside scan' }, T)
    expect(change).toBeDisabled()
    expect(change).toHaveAttribute('title', 'Requires Admin role')
    expect(screen.getByRole('button', { name: 'Run Outside scan now' })).toBeDisabled()
  })
})
