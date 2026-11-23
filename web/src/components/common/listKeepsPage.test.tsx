// A list's page, search, size and sort change only when the user changes them: a refetch (the same rows in another order, new row
// objects, a filter value rebuilt on every render), a server list that is empty for a moment, and a link of the page's own
// (a "N software" tile) leave them where they are.
import { useState } from 'react'
import { describe, expect, it } from 'vitest'
import { act, render, screen, within, cleanup } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { createMemoryRouter, RouterProvider, useLocation } from 'react-router'
import '@/lib/i18n'
import { DataTable, type ColumnDef } from './DataTable'
import { KpiGrid, KpiTile } from './KpiTile'
import { KpiStrip } from './PageFrame'
import { keepListParams, useListParams } from './listParams'

type Row = { id: number; name: string }
const make = (n: number, reverse = false): Row[] => {
  const r = Array.from({ length: n }, (_, i) => ({ id: i + 1, name: `package-${String(i + 1).padStart(3, '0')}` }))
  return reverse ? r.reverse() : r
}
const cols: ColumnDef<Row>[] = [{ id: 'name', header: 'Name', accessorFn: (r) => r.name }]

function Where() {
  return <span data-testid="url">{useLocation().search}</span>
}
const url = () => screen.getByTestId('url').textContent ?? ''
const range = () => screen.getAllByRole('status')[0]?.textContent ?? ''

/** A page like a device's Software tab: tiles above a table, and a button that hands the table new data. */
function Page({ initial = make(290), urlKey = 'software', resetPageOn }: { initial?: Row[]; urlKey?: string; resetPageOn?: () => unknown }) {
  const [data, setData] = useState(initial)
  return (
    <>
      <KpiGrid label="Counts"><KpiTile value={data.length} label="software" to="?tab=software" /></KpiGrid>
      <button type="button" onClick={() => setData([...data].reverse())}>Refetch reordered</button>
      <button type="button" onClick={() => setData(data.map((r) => ({ ...r })))}>Refetch same</button>
      <DataTable caption="Software of this device" urlKey={urlKey} data={data} columns={cols} resetPageOn={resetPageOn?.()} />
      <Where />
    </>
  )
}
function inRouter(path: string, el: React.ReactNode) {
  const router = createMemoryRouter([{ path: '/devices/d1', element: el }], { initialEntries: [path] })
  render(<RouterProvider router={router} />)
  return router
}

describe('a list keeps its page', () => {
  it('through a refetch that returns the rows in another order, or as new objects', async () => {
    const user = userEvent.setup()
    inRouter('/devices/d1?tab=software&software.page=3', <Page />)
    expect(range()).toBe('101–150 of 290')
    await user.click(screen.getByRole('button', { name: 'Refetch reordered' }))
    await user.click(screen.getByRole('button', { name: 'Refetch same' }))
    expect(range()).toBe('101–150 of 290')
    expect(url()).toBe('?tab=software&software.page=3')
  })

  it('when the page rebuilds its filter value on every render (an array or object, not a string)', async () => {
    const user = userEvent.setup()
    inRouter('/devices/d1?software.page=3', <Page resetPageOn={() => ({ tab: 'open', status: ['a'] })} />)
    await user.click(screen.getByRole('button', { name: 'Refetch same' }))
    expect(range()).toBe('101–150 of 290')
    expect(url()).toBe('?software.page=3')
  })

  it('and still goes back to page 1 when the filter really changes', async () => {
    const user = userEvent.setup()
    function Filtered() {
      const [f, setF] = useState('a')
      return <><button type="button" onClick={() => setF('b')}>Filter b</button><DataTable caption="Packages" urlKey="pk" data={make(120)} columns={cols} resetPageOn={{ f }} /><Where /></>
    }
    inRouter('/devices/d1?pk.page=3', <Filtered />)
    await user.click(screen.getByRole('button', { name: 'Filter b' }))
    expect(url()).toBe('')
  })

  it('when a tile that says "290 software" is clicked from another tab; on its own tab it is no link (it would lead where you are)', async () => {
    const user = userEvent.setup()
    inRouter('/devices/d1?tab=software&software.page=3', <Page />)
    expect(screen.queryByRole('link', { name: /software/ })).toBeNull()
    expect(screen.getByText('290')).toBeInTheDocument()
    cleanup()
    inRouter('/devices/d1?tab=overview&software.page=3&software.q=pack&software.sort=-name', <Page />)
    await user.click(screen.getByRole('link', { name: /software/ }))
    const p = new URLSearchParams(url())
    expect(p.get('tab')).toBe('software')
    expect(p.get('software.page')).toBe('3')
    expect(p.get('software.q')).toBe('pack')
    expect(p.get('software.sort')).toBe('-name')
  })

  it('on a strip of numbers at the head of a page, too', async () => {
    const user = userEvent.setup()
    inRouter('/devices/d1?software.page=2', <><KpiStrip label="Numbers" items={[{ value: 5, label: 'services', to: '?tab=services' }]} /><Where /></>)
    await user.click(screen.getByRole('link', { name: /services/ }))
    expect(url()).toBe('?software.page=2&tab=services')
  })

  it('a server-paged list that is empty for a moment (total 0 while it loads) keeps the page of the URL', () => {
    function Server({ total, rows }: { total: number; rows: Row[] }) {
      const list = useListParams('audit')
      return <><DataTable caption="Audit" data={rows} columns={cols} server={{ total, list }} pageSize={50} /><Where /></>
    }
    const router = createMemoryRouter([{ path: '/devices/d1', element: <Server total={200} rows={make(50)} /> }], { initialEntries: ['/devices/d1?audit.page=3'] })
    const { rerender } = render(<RouterProvider router={router} />)
    expect(url()).toBe('?audit.page=3')
    const empty = createMemoryRouter([{ path: '/devices/d1', element: <Server total={0} rows={[]} /> }], { initialEntries: ['/devices/d1?audit.page=3'] })
    rerender(<RouterProvider router={empty} />)
    expect(new URLSearchParams(empty.state.location.search).get('audit.page')).toBe('3')
  })
})

describe('a list keeps its sort and search', () => {
  it('the sort is in the URL, survives the list being built again, and goes back to the default with it', async () => {
    const user = userEvent.setup()
    function Remount() {
      const [n, setN] = useState(0)
      return <><button type="button" onClick={() => setN(n + 1)}>Rebuild</button><DataTable key={n} caption="Packages" urlKey="pk" data={make(30)} columns={cols} initialSort={[{ id: 'name', desc: false }]} /><Where /></>
    }
    inRouter('/devices/d1', <Remount />)
    const first = () => within(screen.getByRole('table', { name: 'Packages' })).getAllByRole('row')[1]?.textContent
    expect(first()).toBe('package-001')
    await user.click(screen.getByRole('button', { name: 'Name' }))
    expect(first()).toBe('package-030')
    expect(url()).toBe('?pk.sort=-name')
    await act(async () => { await user.click(screen.getByRole('button', { name: 'Rebuild' })) })
    expect(first()).toBe('package-030')
    expect(url()).toBe('?pk.sort=-name')
  })
})

describe('keepListParams', () => {
  it('lays the link over the current query and carries only the list keys', () => {
    expect(keepListParams('?tab=software', '?tab=services&software.page=3&sw.q=x&severity=high')).toBe('?software.page=3&sw.q=x&tab=software')
    expect(keepListParams('?tab=open&software.page=1', '?software.page=3')).toBe('?tab=open&software.page=1')
    expect(keepListParams('?tab=a#top', '')).toBe('?tab=a#top')
    expect(keepListParams('/findings?tab=open', '?x.page=2')).toBe('/findings?tab=open')
  })
})
