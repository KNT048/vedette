import { useState } from 'react'
import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { createMemoryRouter, RouterProvider, useLocation } from 'react-router'
import '@/lib/i18n'
import { expectNoA11yViolations } from '@/test/render'
import { DataTable, type ColumnDef } from './DataTable'
import { ListSearch, Pager, pageItems, pageSizes } from './Pager'
import { listKey } from './listParams'

describe('pageItems', () => {
  it('lists every page up to 7, else the ends, the current page and its neighbours with gaps of one page filled', () => {
    expect(pageItems(0, 1)).toEqual([0])
    expect(pageItems(3, 7)).toEqual([0, 1, 2, 3, 4, 5, 6])
    expect(pageItems(0, 20)).toEqual([0, 1, 2, 3, 4, null, 19])
    expect(pageItems(9, 20)).toEqual([0, null, 8, 9, 10, null, 19])
    expect(pageItems(19, 20)).toEqual([0, null, 15, 16, 17, 18, 19])
    expect(pageItems(2, 8)).toEqual([0, 1, 2, 3, 4, null, 7])
    expect(pageItems(4, 9)).toEqual([0, null, 3, 4, 5, null, 8])
  })
  it('offers the usual sizes plus the list\'s own', () => {
    expect(pageSizes(50)).toEqual([25, 50, 100, 200])
    expect(pageSizes(20)).toEqual([20, 25, 50, 100, 200])
  })
  it('makes a short URL key of a caption', () => {
    expect(listKey('Software on the device')).toBe('software-on-the-device')
    expect(listKey('A very long caption that goes on and on')).toBe('a-very-long-caption-that')
    expect(listKey('!!!')).toBe('list')
  })
})

function PagerHarness({ pages = 20 }: { pages?: number }) {
  const [page, setPage] = useState(0)
  const [size, setSize] = useState(50)
  return <><Pager page={page} pages={pages} onPage={setPage} label="Pages" size={size} onSize={setSize} /><span data-testid="state">{`${page}/${size}`}</span></>
}
const state = () => screen.getByTestId('state').textContent

describe('Pager', () => {
  it('moves first, previous, to a numbered page, next and last; the current page is marked', async () => {
    const user = userEvent.setup()
    render(<PagerHarness />)
    const nav = screen.getByRole('navigation', { name: 'Pages' })
    expect(within(nav).getByRole('button', { name: 'First page' })).toBeDisabled()
    expect(within(nav).getByRole('button', { name: 'Previous' })).toBeDisabled()
    await user.click(within(nav).getByRole('button', { name: 'Last page' }))
    expect(state()).toBe('19/50')
    expect(within(nav).getByRole('button', { name: 'Page 20' })).toHaveAttribute('aria-current', 'page')
    expect(within(nav).getByRole('button', { name: 'Next' })).toBeDisabled()
    await user.click(within(nav).getByRole('button', { name: 'Previous' }))
    await user.click(within(nav).getByRole('button', { name: 'Page 16' }))
    expect(state()).toBe('15/50')
    await user.click(within(nav).getByRole('button', { name: 'First page' }))
    expect(state()).toBe('0/50')
    await expectNoA11yViolations()
  })

  it('"Go to page" jumps on Enter and keeps a page out of range at the nearest end', async () => {
    const user = userEvent.setup()
    render(<PagerHarness />)
    const go = screen.getByLabelText('Go to page')
    await user.type(go, '10{Enter}')
    expect(state()).toBe('9/50')
    expect(go).toHaveValue(null)
    await user.type(go, '99{Enter}')
    expect(state()).toBe('19/50')
    await user.type(go, '0')
    await user.click(screen.getByRole('button', { name: 'Go' }))
    expect(state()).toBe('0/50')
  })

  it('changes the page size; with one page and the default size there is nothing to show', async () => {
    const user = userEvent.setup()
    render(<PagerHarness />)
    await user.selectOptions(screen.getByLabelText('Rows per page'), '200')
    expect(state()).toBe('0/200')
    const { container } = render(<Pager page={0} pages={1} onPage={() => {}} label="One" />)
    expect(container).toBeEmptyDOMElement()
  })
})

describe('ListSearch', () => {
  it('applies the text once typing rests, and at once on Enter; a change from outside shows in the box', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    const { rerender } = render(<ListSearch value="" onChange={onChange} label="Search things" />)
    const box = screen.getByRole('searchbox', { name: 'Search things' })
    await user.type(box, 'ssh')
    expect(onChange).not.toHaveBeenCalled()
    await waitFor(() => expect(onChange).toHaveBeenCalledWith('ssh'))
    expect(onChange).toHaveBeenCalledTimes(1)
    onChange.mockClear()
    await user.type(box, 'd{Enter}')
    expect(onChange).toHaveBeenCalledWith('sshd')
    rerender(<ListSearch value="nginx" onChange={onChange} label="Search things" />)
    expect(box).toHaveValue('nginx')
  })
})

type Row = { id: number; name: string }
const rows: Row[] = Array.from({ length: 290 }, (_, i) => ({ id: i + 1, name: i === 200 ? 'OpenSSH' : `package-${String(i + 1).padStart(3, '0')}` }))
const cols: ColumnDef<Row>[] = [{ id: 'name', header: 'Name', accessorFn: (r) => r.name }]

function Where() {
  const l = useLocation()
  return <span data-testid="url">{l.search}</span>
}
function inRouter(path: string, el: React.ReactNode) {
  const router = createMemoryRouter([{ path: '/list', element: <>{el}<Where /></> }, { path: '/other', element: <p>Elsewhere</p> }], { initialEntries: [path] })
  render(<RouterProvider router={router} />)
  return router
}
const url = () => screen.getByTestId('url').textContent ?? ''
const shownNames = () => within(screen.getByRole('table', { name: 'Packages' })).getAllByRole('row').slice(1).map((r) => r.textContent)

describe('DataTable: search and pages', () => {
  it('a list that pages has a search box and the same pager above and below it; "x–y of N" says where you are', async () => {
    const user = userEvent.setup()
    inRouter('/list', <DataTable caption="Packages" data={rows} columns={cols} />)
    expect(screen.getByRole('searchbox', { name: 'Search Packages' })).toBeInTheDocument()
    const top = screen.getByRole('navigation', { name: 'Pages of Packages, above the list' })
    const bottom = screen.getByRole('navigation', { name: 'Pages of Packages, below the list' })
    expect(screen.getAllByRole('status').map((s) => s.textContent)).toEqual(['1–50 of 290', '1–50 of 290'])
    await user.click(within(bottom).getByRole('button', { name: 'Last page' }))
    expect(shownNames()).toHaveLength(40)
    expect(within(top).getByRole('button', { name: 'Page 6' })).toHaveAttribute('aria-current', 'page')
    expect(url()).toBe('?packages.page=6')
    await user.type(within(top).getByLabelText('Go to page'), '3{Enter}')
    expect(shownNames()[0]).toBe('package-101')
    expect(screen.getAllByRole('status')[0]).toHaveTextContent('101–150 of 290')
    await expectNoA11yViolations()
  })

  it('a search filters the whole list, goes back to page 1 and is kept in the URL; reload and back restore it', async () => {
    const user = userEvent.setup()
    const router = inRouter('/list?packages.page=4', <DataTable caption="Packages" data={rows} columns={cols} />)
    expect(shownNames()[0]).toBe('package-151')
    await user.type(screen.getByRole('searchbox', { name: 'Search Packages' }), 'openssh')
    await waitFor(() => expect(shownNames()).toEqual(['OpenSSH']))
    expect(url()).toBe('?packages.q=openssh')
    expect(screen.getAllByRole('status')[0]).toHaveTextContent('1–1 of 1 matching (290 in all)')
    await router.navigate('/other')
    await router.navigate(-1)
    expect(await screen.findByRole('searchbox', { name: 'Search Packages' })).toHaveValue('openssh')
    expect(shownNames()).toEqual(['OpenSSH'])
  })

  it('opens on the page and size of the URL; a page past the end shows the last one', async () => {
    inRouter('/list?packages.page=99&packages.size=100', <DataTable caption="Packages" data={rows} columns={cols} />)
    expect(shownNames()).toHaveLength(90)
    expect(screen.getByLabelText('Rows per page')).toHaveValue('100')
  })

  it('a short list has the search but no pager, an empty one neither; a page with its own search turns the box off', () => {
    inRouter('/list', <><DataTable caption="Few" data={rows.slice(0, 10)} columns={cols} /><DataTable caption="None" data={[]} columns={cols} /><DataTable caption="Packages" data={rows} columns={cols} search={false} /></>)
    expect(screen.getAllByRole('searchbox').map((b) => b.getAttribute('aria-label'))).toEqual(['Search Few'])
    expect(screen.queryByRole('navigation', { name: /Few/ })).toBeNull()
    expect(screen.getByRole('navigation', { name: 'Pages of Packages, above the list' })).toBeInTheDocument()
  })

  it('a list of cards (list={…}) has the same search and pager as a table', async () => {
    const user = userEvent.setup()
    inRouter('/list', <DataTable caption="Cards" urlKey="cards" data={rows} columns={cols} pageSize={25} list={(r) => <article>{r.name}</article>} />)
    expect(screen.queryByRole('table')).toBeNull()
    expect(within(screen.getByRole('list', { name: 'Cards' })).getAllByRole('article')).toHaveLength(25)
    expect(screen.getByRole('navigation', { name: 'Pages of Cards, above the list' })).toBeInTheDocument()
    await user.type(screen.getByRole('searchbox', { name: 'Search Cards' }), 'OpenSSH')
    await waitFor(() => expect(within(screen.getByRole('list', { name: 'Cards' })).getAllByRole('article').map((a) => a.textContent)).toEqual(['OpenSSH']))
  })

  it('a list the server pages shows the server\'s page and asks for another one', async () => {
    const user = userEvent.setup()
    function Server() {
      const [page, setPage] = useState(0)
      const list = { q: '', page, size: 25, sort: '', set: (p: { page?: number }) => setPage(p.page ?? 0) }
      return <DataTable caption="Packages" data={rows.slice(page * 25, page * 25 + 25)} columns={cols} pageSize={25} server={{ total: 290, list }} />
    }
    inRouter('/list', <Server />)
    expect(shownNames()).toHaveLength(25)
    expect(screen.getAllByRole('status')[0]).toHaveTextContent('1–25 of 290')
    await user.type(screen.getAllByLabelText('Go to page')[0]!, '12{Enter}')
    expect(shownNames()[0]).toBe('package-276')
    expect(screen.getAllByRole('status')[0]).toHaveTextContent('276–290 of 290')
    expect(screen.queryByRole('searchbox')).toBeNull()
  })
})
