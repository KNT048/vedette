import { act, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { JobProgress as Progress } from '@/lib/progress'
import { expectNoA11yViolations } from '@/test/render'
import { JobProgress } from './JobProgress'
import i18n from '@/lib/i18n'
import { sayDuration } from './duration'

const NOW = Date.parse('2026-11-16T10:00:00Z')
const ago = (ms: number) => new Date(NOW - ms).toISOString()
const ahead = (ms: number) => new Date(NOW + ms).toISOString()
const job = (p: Partial<Progress> = {}): Progress => ({
  phase: 'ports', percent: 42.4, done: null, total: null, unit: null,
  started_at: ago(130_000), phase_started_at: ago(60_000), updated_at: ago(2_000), eta: null, ends_by: null, message: null, ...p,
})
const freeze = () => { vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] }); vi.setSystemTime(NOW) }
const live = () => document.querySelector('[aria-live="polite"]')!

afterEach(() => vi.useRealTimers())

describe('JobProgress (#830)', () => {
  it('nothing reported yet: "Starting" and an indeterminate bar, with no value for screen readers', async () => {
    freeze()
    render(<JobProgress progress={null} />)
    const bar = screen.getByRole('progressbar', { name: 'Starting' })
    expect(bar).not.toHaveAttribute('aria-valuenow')
    expect(bar).toHaveAttribute('aria-valuemin', '0')
    expect(bar).toHaveAttribute('aria-valuemax', '100')
    expect(bar.querySelector('[data-indeterminate]')).not.toBeNull()
    expect(screen.queryByText(/elapsed/)).toBeNull()
    vi.useRealTimers()
    await expectNoA11yViolations()
  })

  it('a phase without a measure yet (discovery): its step in words, indeterminate bar, elapsed time', () => {
    freeze()
    render(<JobProgress progress={job({ phase: 'discovery', percent: null })} />)
    const bar = screen.getByRole('progressbar', { name: 'Finding the device' })
    expect(bar).not.toHaveAttribute('aria-valuenow')
    expect(screen.queryByText('42%')).toBeNull()
    expect(screen.getByText('2 min 10 s elapsed')).toBeInTheDocument()
  })

  it('nmap with a percent and an estimate: determinate bar, "about N min left in this step"', async () => {
    freeze()
    render(<JobProgress progress={job({ eta: ahead(3 * 60_000 + 20_000) })} />)
    const bar = screen.getByRole('progressbar', { name: 'Checking open ports' })
    expect(bar).toHaveAttribute('aria-valuenow', '42')
    expect(bar).toHaveAttribute('aria-valuetext', '42%')
    expect(bar.querySelector('[data-indeterminate]')).toBeNull()
    expect(screen.getByText('42%')).toBeInTheDocument()
    expect(screen.getByText('about 4 min left in this step')).toBeInTheDocument()
    vi.useRealTimers()
    await expectNoA11yViolations()
  })

  it('vulnerability checks: "3 of 8 checks" next to the bar and in its value text; one check is singular', () => {
    freeze()
    const { rerender } = render(<JobProgress progress={job({ phase: 'vulns', percent: 37.5, done: 3, total: 8, unit: 'checks' })} />)
    expect(screen.getByText('3 of 8 checks')).toBeInTheDocument()
    expect(screen.getByRole('progressbar', { name: 'Checking for known vulnerabilities' })).toHaveAttribute('aria-valuetext', '38%, 3 of 8 checks')
    rerender(<JobProgress progress={job({ phase: 'vulns', percent: 0, done: 0, total: 1, unit: 'checks' })} />)
    expect(screen.getByText('0 of 1 check')).toBeInTheDocument()
    rerender(<JobProgress progress={job({ phase: 'discovery', percent: 25, done: 64, total: 256, unit: 'hosts' })} />)
    expect(screen.getByText('64 of 256 addresses')).toBeInTheDocument()
  })

  it('an estimate under a minute or already passed: "less than a minute", then nothing (never a negative time)', () => {
    freeze()
    const { rerender } = render(<JobProgress progress={job({ eta: ahead(40_000) })} />)
    expect(screen.getByText('less than a minute left in this step')).toBeInTheDocument()
    rerender(<JobProgress progress={job({ eta: ago(5_000) })} />)
    expect(screen.queryByText(/left in this step/)).toBeNull()
  })

  it('announces a change of step and its note, never the ticking time or the percent', () => {
    freeze()
    const { rerender } = render(<JobProgress progress={job()} />)
    expect(live()).toHaveTextContent(/^Checking open ports$/)
    act(() => { vi.advanceTimersByTime(3000) })
    expect(screen.getByText('2 min 13 s elapsed')).toBeInTheDocument()
    expect(live()).not.toHaveTextContent(/elapsed|%/)
    rerender(<JobProgress progress={job({ phase: 'ports', percent: 5, message: 'Second pass: administration and alternative ports' })} />)
    expect(live()).toHaveTextContent('Checking open portsSecond pass: administration and alternative ports')
    rerender(<JobProgress progress={job({ phase: 'services', percent: 10 })} />)
    expect(live()).toHaveTextContent(/^Identifying services$/)
  })

  it('a report older than 30 s says when the last one came, with the reason behind an ⓘ (#824)', () => {
    freeze()
    const { rerender } = render(<JobProgress progress={job({ updated_at: ago(29_000) })} />)
    expect(screen.queryByText(/Last report/)).toBeNull()
    rerender(<JobProgress progress={job({ updated_at: ago(45_000) })} />)
    expect(screen.getByText(/Last report 45 s ago/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'About quiet scanner' })).toHaveAccessibleDescription(/^The scanner reports at most every 5 seconds/)
  })

  it('out-of-range percents are clamped; every phase has words', () => {
    freeze()
    const { rerender } = render(<JobProgress progress={job({ percent: 140 })} />)
    expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '100')
    for (const phase of ['discovery', 'ports', 'services', 'scripts', 'vulns', 'web', 'openvas', 'saving'] as const) {
      rerender(<JobProgress progress={job({ phase })} />)
      const name = screen.getByRole('progressbar').getAttribute('aria-label')
      expect(name).toBe(i18n.t(`phase.${phase}`, { ns: 'progress' }))
      expect(name).not.toMatch(/^phase\./)
    }
  })

  it('durations read as people say them', () => {
    const s = i18n.getFixedT('en', 'progress')
    expect(sayDuration(s, -5)).toBe('0 s')
    expect(sayDuration(s, 45_400)).toBe('45 s')
    expect(sayDuration(s, 120_000)).toBe('2 min')
    expect(sayDuration(s, 130_000)).toBe('2 min 10 s')
    expect(sayDuration(s, 12 * 60_000 + 5_000)).toBe('12 min')
    expect(sayDuration(s, 65 * 60_000)).toBe('1 h 5 min')
  })

  it('OpenVAS at 95% or more (or past its ETA): no minutes-left, the box\'s latest end; below: the normal estimate (#915)', () => {
    freeze()
    const endsBy = ahead(10 * 60_000)
    const stop = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit' }).format(new Date(endsBy))
    const { rerender } = render(<JobProgress progress={job({ phase: 'openvas', percent: 98, ends_by: endsBy, eta: ahead(2 * 60_000) })} />)
    expect(screen.getByText(`OpenVAS is finishing its last checks (its slowest part). It stops by ${stop} at the latest and keeps what it found.`)).toBeInTheDocument()
    expect(screen.queryByText(/left in this step/)).toBeNull()
    rerender(<JobProgress progress={job({ phase: 'openvas', percent: 60, ends_by: endsBy, eta: ahead(10 * 60_000) })} />)
    expect(screen.getByText(/about 10 min left in this step/)).toBeInTheDocument()
    expect(screen.queryByText(/finishing its last checks/)).toBeNull()
    rerender(<JobProgress progress={job({ phase: 'openvas', percent: 60, ends_by: endsBy, eta: ago(1_000) })} />)
    expect(screen.getByText(/finishing its last checks/)).toBeInTheDocument()
    rerender(<JobProgress progress={job({ phase: 'vulns', percent: 97, ends_by: null, eta: ahead(3 * 60_000) })} />)
    expect(screen.getByText(/about 3 min left in this step/)).toBeInTheDocument()
    expect(screen.queryByText(/finishing its last checks/)).toBeNull()
    rerender(<JobProgress progress={job({ phase: 'openvas', percent: 99, ends_by: ago(1_000), eta: ago(5_000) })} />)
    expect(screen.getByText('OpenVAS reached its time limit and is collecting what it found.')).toBeInTheDocument()
    expect(screen.queryByText(/stops by/)).toBeNull()
  })
})
