import { describe, expect, it } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { server } from '@/test/server'
import { assetsStore, modulesStore } from '@/mocks/stores'

describe('feeds: home (S-FEED-1, S-FEED-2)', () => {
  it('shows the answer line and the hot board from real KEV data, a11y clean', async () => {
    renderApp('/')
    expect(await screen.findByRole('heading', { level: 1, name: /^Today: \d+ vulnerabilit/ })).toBeInTheDocument()
    const table = await screen.findByRole('table', { name: 'Newly exploited' })
    expect(within(table).getAllByRole('row').length).toBeGreaterThan(1)
    expect(await screen.findByText(/Sources: CISA KEV/)).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('"I have this" adds a manual device', async () => {
    const before = assetsStore.get().length
    renderApp('/')
    const buttons = await screen.findAllByRole('button', { name: 'I have this' })
    await userEvent.click(buttons[0]!)
    expect(await screen.findByText('Added to your devices')).toBeInTheDocument()
    expect(assetsStore.get().length).toBe(before + 1)
    expect(assetsStore.get()[0]!.origin).toBe('manual')
  })

  it('a viewer cannot press "I have this"', async () => {
    renderApp('/', { role: 'viewer' })
    const buttons = await screen.findAllByRole('button', { name: 'I have this' })
    expect(buttons[0]).toBeDisabled()
  })

  it('with inventory off the "In your network?" column says why (S-CORE-1)', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'inventory' ? { ...m, enabled: false } : m)))
    renderApp('/')
    expect((await screen.findAllByText('Inventory is off')).length).toBeGreaterThan(0)
  })

  it('a server error shows the message and a retry button', async () => {
    server.use(http.get('*/api/v1/feeds/hot', () => HttpResponse.json({ error: { code: 'x', message: 'The data service is not responding.' } }, { status: 503 })))
    renderApp('/')
    expect(await screen.findByText('The data service is not responding.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument()
  })

  it('no Vietnamese text on the page (D-28)', async () => {
    renderApp('/')
    await screen.findByRole('table', { name: 'Newly exploited' })
    expect(document.body.textContent).not.toMatch(/[ăâđêôơưạảấầẩẫậắằẳẵặẹẻẽếềểễệỉịọỏốồổỗộớờởỡợụủứừửữựỳỵỷỹ]/i)
  })
})

describe('feeds: lookup and CVE (S-FEED-3)', () => {
  it('looking up a bad IP shows sources and advice', async () => {
    renderApp('/lookup?q=185.220.101.47')
    expect(await screen.findByText('Block')).toBeInTheDocument()
    expect(screen.getByText(/Tor exit list/)).toBeInTheDocument()
  })

  it('the CVE page shows matching devices', async () => {
    renderApp('/cve/CVE-2022-27593')
    expect(await screen.findByRole('heading', { level: 1, name: /CVE-2022-27593/ })).toBeInTheDocument()
    expect(await screen.findByText('NAS-PHOTOS')).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('a CVE not in KEV is reported as not found, without a retry button', async () => {
    renderApp('/cve/CVE-2020-0001')
    expect(await screen.findByText(/not on the exploited list/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Try again' })).toBeNull()
  })
})
