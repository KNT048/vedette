// #825: the trend line of Home's lead tile, inline SVG, readable by hover and keyboard.
import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { expectNoA11yViolations } from '@/test/render'
import { Sparkline } from './Sparkline'

const values = [2, 3, 3, 5, 4]
const show = (v = values) => render(<Sparkline values={v} label="Open findings: 2 then, 4 now" point={(i) => `Day ${i + 1}: ${v[i]} open`} start="Day 1" end="Now" tone="danger" />)

describe('Sparkline (#825)', () => {
  it('is one named image, shows the range ends, a11y clean', async () => {
    show()
    expect(screen.getByRole('img', { name: 'Open findings: 2 then, 4 now' })).toBeInTheDocument()
    expect(screen.getByText('Day 1')).toBeInTheDocument()
    expect(screen.getByText('Now')).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('the dot sits on the last value, scaled from 0 to the highest value', () => {
    show()
    const dot = screen.getByTestId('sparkline-dot')
    expect(dot.style.left).toBe('100%')
    // H 40, pad 4: 4 of max 5 → y = 40 - 4 - 0.8 * 32 = 10.4 → 26 %
    expect(parseFloat(dot.style.top)).toBeCloseTo(26, 0)
  })

  it('focus reads the last day; arrows, Home and End move along the days and stop at the ends', async () => {
    const u = userEvent.setup()
    show()
    await u.tab()
    expect(screen.getByRole('img')).toHaveFocus()
    expect(screen.getByText('Day 5: 4 open')).toBeInTheDocument()
    await u.keyboard('{ArrowRight}')
    expect(screen.getByText('Day 5: 4 open')).toBeInTheDocument()
    await u.keyboard('{ArrowLeft}')
    expect(screen.getByText('Day 4: 5 open')).toBeInTheDocument()
    await u.keyboard('{Home}')
    expect(screen.getByText('Day 1: 2 open')).toBeInTheDocument()
    await u.keyboard('{ArrowLeft}')
    expect(screen.getByText('Day 1: 2 open')).toBeInTheDocument()
    await u.keyboard('{End}')
    expect(screen.getByText('Day 5: 4 open')).toBeInTheDocument()
  })

  it('hovering a day names it; leaving shows the range ends again', () => {
    const { container } = show()
    fireEvent.pointerEnter(container.querySelector('rect[data-day="1"]')!)
    expect(screen.getByText('Day 2: 3 open')).toBeInTheDocument()
    fireEvent.pointerLeave(screen.getByRole('img'))
    expect(screen.getByText('Day 1')).toBeInTheDocument()
  })

  it('all zero stays a flat line at the bottom (no division by zero); fewer than 2 points draw nothing', () => {
    const { unmount } = show([0, 0, 0])
    expect(parseFloat(screen.getByTestId('sparkline-dot').style.top)).toBeCloseTo(90, 0)
    unmount()
    show([3])
    expect(screen.queryByRole('img')).toBeNull()
  })
})
