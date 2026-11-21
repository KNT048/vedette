// The shared schedule editor against the schedules mock: the line it shows, the dialog with the next three starts, the owner's limits
// with their reason, pause and resume, and Run now opening the run it started.
import { useState } from 'react'
import { fireEvent, render, screen, within } from '@testing-library/react'
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
    expect(await dlg.findByText(/The interval is 1 minute to 366 days\./, undefined, T)).toBeInTheDocument()
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
