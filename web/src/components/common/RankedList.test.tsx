// #825: a short ranked list (Home's "Fix first"): an ordered list, a real link per row, rank hidden from screen readers (the order is the list's).
import { render, screen, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { expectNoA11yViolations } from '@/test/render'
import { RankedList, RankedRow } from './RankedList'

describe('RankedList (#825)', () => {
  it('rows in order, each with its link, meta line and aside', async () => {
    render(
      <RankedList label="Fix first">
        <RankedRow rank={1} title={<a href="/findings/f1">PAN-OS GlobalProtect</a>} meta={<span>CVE-2024-3400</span>} aside={<span>CVSS 10.0 Critical</span>} />
        <RankedRow rank={2} title={<a href="/findings/f2">Fortinet FortiOS</a>} />
      </RankedList>,
    )
    const list = screen.getByRole('list', { name: 'Fix first' })
    expect(list.tagName).toBe('OL')
    const rows = within(list).getAllByRole('listitem')
    expect(rows).toHaveLength(2)
    expect(within(rows[0]!).getByRole('link', { name: 'PAN-OS GlobalProtect' })).toHaveAttribute('href', '/findings/f1')
    expect(within(rows[0]!).getByText('CVE-2024-3400')).toBeInTheDocument()
    expect(within(rows[0]!).getByText('CVSS 10.0 Critical')).toBeInTheDocument()
    expect(within(rows[0]!).getByText('1')).toHaveAttribute('aria-hidden', 'true')
    expect(rows[1]!.textContent).toBe('2Fortinet FortiOS')
    await expectNoA11yViolations()
  })
})
