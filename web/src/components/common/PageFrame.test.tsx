import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { createMemoryRouter, RouterProvider, useLocation } from 'react-router'
import { describe, expect, it, vi } from 'vitest'
import { expectNoA11yViolations } from '@/test/render'
import { KpiStrip, OldHashToTab, PageTabs, type PageTab } from './PageFrame'

const TABS: PageTab[] = [
  { id: 'one', label: 'First', panel: <p>first panel</p> },
  { id: 'two', label: 'Second', panel: <p>second panel</p>, badge: { count: 3, label: 'waiting for you' } },
  { id: 'three', label: 'Third', panel: <p>third panel</p>, badge: { count: 0, label: 'none' } },
]

function Where() {
  const l = useLocation()
  return <output data-testid="where">{l.pathname + l.search + l.hash}</output>
}

function show(url: string, tabs = TABS) {
  const router = createMemoryRouter([
    { path: '/page', element: <><PageTabs label="Sections of the page" tabs={tabs} /><Where /></> },
    { path: '/other', element: <Where /> },
  ], { initialEntries: ['/other', url], initialIndex: 1 })
  render(<RouterProvider router={router} />)
  return router
}

describe('PageTabs (D-464)', () => {
  it('opens the tab named in ?tab= and shows only its panel', () => {
    show('/page?tab=two')
    expect(screen.getByRole('tablist', { name: 'Sections of the page' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /Second/ })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByText('second panel')).toBeInTheDocument()
    expect(screen.queryByText('first panel')).toBeNull()
  })

  it('falls back to the first tab for no tab or an unknown one', () => {
    show('/page?tab=nonsense')
    expect(screen.getByRole('tab', { name: 'First' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByText('first panel')).toBeInTheDocument()
  })

  it('writes the chosen tab to ?tab=, keeps other parameters, and replaces the history entry so Back leaves the page', async () => {
    const router = show('/page?run=r-1')
    await userEvent.click(screen.getByRole('tab', { name: 'Third' }))
    expect(screen.getByTestId('where')).toHaveTextContent('/page?run=r-1&tab=three')
    expect(screen.getByText('third panel')).toBeInTheDocument()
    await router.navigate(-1)
    await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent(/^\/other$/))
    await router.navigate(1)
    expect(await screen.findByRole('tab', { name: 'Third' })).toHaveAttribute('aria-selected', 'true')
  })

  it('keyboard: arrows, Home and End change the tab and ?tab=, replacing the history entry', async () => {
    const router = show('/page')
    await userEvent.tab()
    expect(screen.getByRole('tab', { name: 'First' })).toHaveFocus()
    await userEvent.keyboard('{ArrowRight}')
    expect(screen.getByRole('tab', { name: /^Second/ })).toHaveFocus()
    await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent('/page?tab=two'))
    expect(screen.getByRole('tab', { name: /^Second/ })).toHaveAttribute('aria-selected', 'true')
    await userEvent.keyboard('{End}')
    await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent('/page?tab=three'))
    expect(screen.getByRole('tab', { name: 'Third' })).toHaveAttribute('aria-selected', 'true')
    await userEvent.keyboard('{Home}')
    expect(screen.getByRole('tab', { name: 'First' })).toHaveFocus()
    await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent('/page?tab=one'))
    // three tab changes, still one history entry for the page: Back leaves it
    await router.navigate(-1)
    await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent(/^\/other$/))
  })

  it('shows a count badge with a spoken label only when the count is above zero', () => {
    show('/page')
    // the name holds the visible text ("Second 3") so a voice user can say what they see (WCAG 2.5.3)
    expect(screen.getByRole('tab', { name: 'Second 3 waiting for you' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'Third' })).not.toHaveTextContent('0')
  })

  it('draws no tab row when only one area is left (for example after role filtering)', () => {
    show('/page', TABS.slice(0, 1))
    expect(screen.queryByRole('tablist')).toBeNull()
    expect(screen.getByText('first panel')).toBeInTheDocument()
  })

  it('has no axe violations', async () => {
    show('/page?tab=two')
    await expectNoA11yViolations()
  })
})

describe('OldHashToTab (D-519)', () => {
  function open(url: string) {
    render(<RouterProvider router={createMemoryRouter([
      { path: '/page', element: <><OldHashToTab map={{ agents: 'agents', ranges: 'scope' }} /><PageTabs label="Parts" tabs={[{ id: 'scope', label: 'Scope', panel: <p>scope panel</p> }, { id: 'agents', label: 'Agents', panel: <p>agents panel</p> }]} /><Where /></> },
    ], { initialEntries: [url] })} />)
  }

  it('an old #section link opens its tab through ?tab=, keeps the other parameters and drops the hash', async () => {
    open('/page?run=r-1#agents')
    await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent(/^\/page\?run=r-1&tab=agents$/))
    expect(screen.getByRole('tab', { name: 'Agents' })).toHaveAttribute('aria-selected', 'true')
  })

  it('leaves any other hash alone (the skip link\'s #main) and a hash that is an inherited object key', async () => {
    open('/page?tab=agents#main')
    expect(screen.getByTestId('where')).toHaveTextContent(/^\/page\?tab=agents#main$/)
    expect(screen.getByRole('tab', { name: 'Agents' })).toHaveAttribute('aria-selected', 'true')
    open('/page#constructor')
    expect(screen.getAllByTestId('where')[1]).toHaveTextContent(/^\/page#constructor$/)
  })
})

describe('KpiStrip (D-464)', () => {
  const kpis = [
    { value: 4, label: 'Waiting for approval', to: '/devices?tab=pending' },
    { value: 120, label: 'Devices', to: '/devices' },
    { value: '2', label: 'Unknown vendor', to: '/devices?vendor=unknown' },
  ]

  it('renders each number as a link to its detail, in a labelled list', async () => {
    render(<RouterProvider router={createMemoryRouter([{ path: '/', element: <KpiStrip label="Devices at a glance" items={kpis} /> }])} />)
    const list = screen.getByRole('list', { name: 'Devices at a glance' })
    expect(list.querySelectorAll('li')).toHaveLength(3)
    expect(screen.getByRole('link', { name: '4 Waiting for approval' })).toHaveAttribute('href', '/devices?tab=pending')
    await expectNoA11yViolations()
  })

  it('more than four numbers: a console error while developing, the first four shown, the page keeps working', () => {
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    const five = [...kpis, { value: 1, label: 'D', to: '/' }, { value: 1, label: 'E', to: '/' }]
    render(<RouterProvider router={createMemoryRouter([{ path: '/', element: <KpiStrip label="Five" items={five} /> }])} />)
    expect(screen.getByRole('list', { name: 'Five' }).querySelectorAll('li')).toHaveLength(4)
    expect(screen.queryByRole('link', { name: '1 E' })).toBeNull()
    expect(err).toHaveBeenCalledWith(expect.stringMatching(/at most 4 items/))
    vi.restoreAllMocks()
  })
})

// D-543 (một kiểu cho cả ứng dụng): module không tự dựng hàng tab; mọi tab của trang đi qua PageTabs (?tab=, cùng hình, cùng bàn phím).
describe('one style gate (D-543)', () => {
  const sources = import.meta.glob<string>('../../features/**/*.tsx', { query: '?raw', import: 'default', eager: true })
  // Ngoại lệ: một bộ chuyển nhỏ bên trong một khối (không phải các phần của trang), ví dụ xem trước tin theo từng kênh.
  const INNER = ['../../features/notify/IncidentDetailPage.tsx']
  it('no feature page imports the raw tab primitives; pages use PageTabs', () => {
    expect(Object.keys(sources).length).toBeGreaterThan(50)
    const raw = Object.entries(sources).filter(([f, src]) => !f.endsWith('.test.tsx') && !INNER.includes(f) && /from '@\/components\/ui\/tabs'/.test(src)).map(([f]) => f)
    expect(raw).toEqual([])
  })
})
