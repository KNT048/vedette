import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { createMemoryRouter, RouterProvider, useLocation } from 'react-router'
import { describe, expect, it, vi } from 'vitest'
import { expectNoA11yViolations } from '@/test/render'
import { KpiStrip, PageTabs, type PageTab } from './PageFrame'

const TABS: PageTab[] = [
  { id: 'one', label: 'First', panel: <p>first panel</p> },
  { id: 'two', label: 'Second', panel: <p>second panel</p>, badge: { count: 3, label: 'waiting for you' } },
  { id: 'three', label: 'Third', panel: <p>third panel</p>, badge: { count: 0, label: 'none' } },
]

function Where() {
  const l = useLocation()
  return <output data-testid="where">{l.pathname + l.search}</output>
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

  it('refuses more than four numbers', () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const five = [...kpis, { value: 1, label: 'D', to: '/' }, { value: 1, label: 'E', to: '/' }]
    expect(() => render(<KpiStrip label="x" items={five} />)).toThrow(/at most 4/)
    vi.restoreAllMocks()
  })
})
