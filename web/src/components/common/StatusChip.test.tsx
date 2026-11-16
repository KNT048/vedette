// docs/UI.md §7, decision (c): each severity has its own level meter inside the four tones; solid belongs to "Confirmed" only.
import { describe, expect, it } from 'vitest'
import { render } from '@testing-library/react'
import '@/lib/i18n'
import { SeverityChip, StatusChip } from './StatusChip'

describe('severity and status chips', () => {
  it('every severity shows its word and a meter with its own number of filled bars', () => {
    const levels = { critical: 4, high: 3, medium: 2, low: 1, info: 0 } as const
    for (const [sev, level] of Object.entries(levels)) {
      const { container, unmount } = render(<SeverityChip severity={sev as keyof typeof levels} />)
      const meter = container.querySelector('svg[data-level]')!
      expect(meter).toHaveAttribute('aria-hidden', 'true')
      expect(meter.getAttribute('data-level')).toBe(String(level))
      expect([...meter.querySelectorAll('rect')].filter((r) => r.getAttribute('opacity') === '1')).toHaveLength(level)
      expect(container.textContent).toMatch(/\w/)
      unmount()
    }
  })
  it('Critical is not the solid block of "Confirmed" (they sit side by side on a finding)', () => {
    const crit = render(<SeverityChip severity="critical" />).container.firstElementChild!
    const conf = render(<StatusChip status="confirmed" />).container.firstElementChild!
    expect(conf.className).toContain('bg-danger ')
    expect(crit.className).not.toContain('bg-danger ')
    expect(crit.className).toContain('bg-danger-soft')
  })
})
