// The one row anatomy of every list (docs/UI.md §5): rank, toggle, title (RowTitle), note, badges, at most two meta lines, actions.
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { useState } from 'react'
import { describe, expect, it } from 'vitest'
import { expectNoA11yViolations } from '@/test/render'
import { ListRow, RowList, RowTitle } from './ListParts'

function Opening() {
  const [open, setOpen] = useState(false)
  return (
    <ListRow rank={2} title="Update OpenSSH to 10.6" toggle={{ open, onToggle: () => setOpen((o) => !o), label: 'Show the devices', controls: 'p' }}
      meta={['2 devices, 5 findings']}>
      {open ? <p id="p">FW-HQ</p> : null}
    </ListRow>
  )
}

describe('ListRow, RowList, RowTitle', () => {
  it('a ranked list: an ordered list of rows, each a named row with its title link, note, badges, meta lines and actions', async () => {
    render(
      <MemoryRouter>
        <RowList ordered boxed label="Fix first">
          <ListRow key="a" label="FW-HQ" rank={1} title="FW-HQ" to="/devices/a-fw01" sub="192.168.10.1" badges={<span>1 exploited</span>}
            meta={['5 findings, 5 CVEs', 'Worst: Update FortiOS']} actions={<button type="button">Ignore</button>} />
          <Opening key="b" />
        </RowList>
      </MemoryRouter>,
    )
    const list = screen.getByRole('list', { name: 'Fix first' })
    expect(list.tagName).toBe('OL')
    expect(within(list).getAllByRole('listitem')).toHaveLength(2)
    const row = within(list).getByRole('article', { name: 'FW-HQ' })
    const link = within(row).getByRole('link', { name: 'FW-HQ' })
    expect(link).toHaveAttribute('href', '/devices/a-fw01')
    // the title is the primary text colour: a link only by its hover underline
    expect(link.className).toMatch(/\btext-ink\b/)
    expect(link.className).not.toMatch(/\btext-accent\b/)
    expect(link.className).toMatch(/\bno-underline\b.*\bhover:underline\b/)
    expect(within(row).getByText('1', { selector: '[data-rank]' })).toHaveAttribute('aria-hidden', 'true')
    for (const text of ['192.168.10.1', '1 exploited', '5 findings, 5 CVEs', 'Worst: Update FortiOS']) expect(within(row).getByText(text)).toBeInTheDocument()
    expect(within(row).getByRole('button', { name: 'Ignore' })).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('a row that opens shows its part under the title on the toggle, and a title without a page is no link', async () => {
    render(<MemoryRouter><Opening /></MemoryRouter>)
    expect(screen.queryByRole('link')).toBeNull()
    expect(screen.getByText('Update OpenSSH to 10.6').className).toMatch(/\bfont-medium\b/)
    expect(screen.queryByText('FW-HQ')).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Show the devices' }))
    expect(screen.getByText('FW-HQ')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Show the devices' })).toHaveAttribute('aria-expanded', 'true')
  })

  it('RowTitle names a table cell the same way: an external page opens in a new tab', () => {
    render(<MemoryRouter><RowTitle href="https://example.com/advisory">Advisory</RowTitle></MemoryRouter>)
    const link = screen.getByRole('link', { name: 'Advisory' })
    expect(link).toHaveAttribute('target', '_blank')
    expect(link).toHaveAttribute('rel', 'noopener noreferrer')
  })
})
