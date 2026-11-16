// #825: stat tiles in one divided row; the whole tile links to the list it counts, its sub-links stay their own links.
import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { describe, expect, it } from 'vitest'
import { expectNoA11yViolations } from '@/test/render'
import { KpiGrid, KpiTile } from './KpiTile'

describe('KpiTile (#825)', () => {
  it('number and label are one link to the list; a sub-link and the chart slot are their own; a tile without `to` is plain', async () => {
    render(
      <MemoryRouter>
        <KpiGrid label="Today at a glance">
          <KpiTile to="/findings?tab=open" value={7} tone="danger" label="open exploited findings"
            sub={<a href="/findings?tab=open&status=confirmed">3 confirmed by scan</a>} chart={<span>chart</span>} />
          <KpiTile value={12} label="alerts sent, last 7 days" sub={<span>None failed</span>} />
        </KpiGrid>
      </MemoryRouter>,
    )
    const grid = screen.getByRole('list', { name: 'Today at a glance' })
    const [lead, plain] = within(grid).getAllByRole('listitem')
    expect(within(lead!).getByRole('link', { name: '7 open exploited findings' })).toHaveAttribute('href', '/findings?tab=open')
    expect(within(lead!).getByRole('link', { name: '3 confirmed by scan' })).toBeInTheDocument()
    expect(within(lead!).getByText('7')).toHaveClass('text-danger')
    expect(within(lead!).getByText('chart')).toBeInTheDocument()
    expect(within(plain!).queryByRole('link')).toBeNull()
    expect(within(plain!).getByText('12')).not.toHaveClass('text-danger')
    await expectNoA11yViolations()
  })
})
