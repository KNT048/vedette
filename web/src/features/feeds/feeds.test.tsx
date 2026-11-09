import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { eachOption } from '@/test/formMatrix'
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

describe('feeds: custom feed form matrix (docs/QA.md §2)', () => {
  async function openAdd() {
    renderApp('/settings/feeds')
    await userEvent.click((await screen.findAllByRole('button', { name: 'Add a feed' }))[0]!)
    return screen.findByRole('dialog', { name: 'Add a feed' })
  }
  const pick = (dlg: HTMLElement, label: string) => async (o: string) => { const s = within(dlg).getByLabelText(label); await userEvent.selectOptions(s, within(s).getByRole('option', { name: o })) }

  it('each authentication type shows only its own fields, and the secret typed for one is dropped when the type changes', async () => {
    const dlg = await openAdd()
    await eachOption([
      { option: 'None', hidden: ['Header name', 'User name', 'Password', 'Secret'] },
      { option: 'Custom header', shown: ['Header name', 'Secret'], hidden: ['User name', 'Password'] },
      { option: 'Bearer token', shown: ['Secret'], hidden: ['Header name', 'User name', 'Password'] },
      { option: 'Basic (user and password)', shown: ['User name', 'Password'], hidden: ['Header name', 'Secret'] },
      { option: 'None', hidden: ['Header name', 'User name', 'Password', 'Secret'] },
    ], pick(dlg, 'Authentication'), dlg)
    await pick(dlg, 'Authentication')('Bearer token')
    await userEvent.type(within(dlg).getByLabelText('Secret'), 'abcdefgh-secret')
    await pick(dlg, 'Authentication')('Basic (user and password)')
    expect(within(dlg).getByLabelText('Password')).toHaveValue('')
  })

  it('a header name error is shown at the header name, a missing user at the user name, not under the secret', async () => {
    const dlg = await openAdd()
    await userEvent.type(within(dlg).getByLabelText('Name'), 'Partner IOC')
    await userEvent.type(within(dlg).getByLabelText('Address'), 'https://feeds.partner.example/ioc.json')
    await pick(dlg, 'Authentication')('Custom header')
    await userEvent.clear(within(dlg).getByLabelText('Header name')); await userEvent.type(within(dlg).getByLabelText('Header name'), 'bad header!')
    await userEvent.type(within(dlg).getByLabelText('Secret'), 'abcdefgh-secret')
    await userEvent.click(within(dlg).getByRole('button', { name: /^Add feed$|^Add$/ }))
    expect(within(dlg).getByLabelText('Header name')).toBeInvalid()
    expect(within(dlg).getByLabelText('Secret')).toBeValid()
    await pick(dlg, 'Authentication')('Basic (user and password)')
    await userEvent.type(within(dlg).getByLabelText('Password'), 'abcdefgh-secret')
    await userEvent.click(within(dlg).getByRole('button', { name: /^Add feed$|^Add$/ }))
    expect(within(dlg).getByLabelText('User name')).toBeInvalid()
    expect(within(dlg).getByLabelText('Password')).toBeValid()
  })

  it('each format shows its own reading rules; a vulnerability feed offers no STIX or plain list', async () => {
    const dlg = await openAdd()
    const fmt = pick(dlg, 'Format')
    await eachOption([
      { option: 'JSON', shown: ['Records path'], hidden: ['Delimiter', 'First row is a header'] },
      { option: 'CSV', shown: ['Delimiter', 'First row is a header'], hidden: ['Records path'] },
      { option: 'RSS / Atom', hidden: ['Records path', 'Delimiter', 'First row is a header'] },
      { option: 'STIX 2.1 / TAXII 2.1', hidden: ['Records path', 'Delimiter'] },
      { option: 'Plain list (one per line)', hidden: ['Records path', 'Delimiter'] },
      { option: 'JSON', shown: ['Records path'], hidden: ['Delimiter'] },
    ], fmt, dlg)
    const formats = within(within(dlg).getByLabelText('Format')).getAllByRole('option').map((o) => o.textContent)
    expect(formats).toEqual(['JSON', 'CSV', 'RSS / Atom', 'STIX 2.1 / TAXII 2.1', 'Plain list (one per line)'])
    await userEvent.click(within(dlg).getByRole('button', { name: 'Vulnerabilities' }))
    await waitFor(() => expect(within(within(dlg).getByLabelText('Format')).getAllByRole('option').map((o) => o.textContent)).toEqual(['JSON', 'CSV', 'RSS / Atom']))
    // a format the new type does not offer falls back to the first one, with that format's default rules
    expect(within(dlg).getByLabelText('Format')).toHaveValue('json')
  })
})

describe('feeds: what the real backend needs from the GUI (mock → real)', () => {
  it('asks the API for a CVE in capitals even when the address bar has it in lower case', async () => {
    const asked: string[] = []
    server.use(http.get('*/api/v1/feeds/cve/:id', ({ params }) => { asked.push(String(params.id)); return HttpResponse.json({ error: { code: 'not_in_kev', message: 'This CVE is not on the exploited list (CISA KEV) in the current data.' } }, { status: 404 }) }))
    renderApp('/cve/cve-2022-27593')
    expect(await screen.findByText(/not on the exploited list/)).toBeInTheDocument()
    expect(asked).toEqual(['CVE-2022-27593'])
  })

  it('a box that has never fetched (generated_at 1970) says so instead of showing the date', async () => {
    server.use(http.get('*/api/v1/feeds/status', () => HttpResponse.json({ generated_at: '1970-01-01T00:00:00Z', kev_catalog_version: '', sources: [], inventory_on: false })))
    server.use(http.get('*/api/v1/feeds/hot', () => HttpResponse.json({ window: '7d', rows: [], latest: null })))
    renderApp('/')
    expect(await screen.findByRole('heading', { level: 1, name: 'Today: no data yet' })).toBeInTheDocument()
    expect(screen.getByText(/No data has been fetched yet/)).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/1970/)
  })

  it('the search boxes stop at 200 characters, the most the API accepts', async () => {
    renderApp('/')
    expect(await screen.findByRole('textbox', { name: 'CVE, product, IP or domain' })).toHaveAttribute('maxlength', '200')
  })
})

describe('feeds: CVE links (contract.ts: http(s) only)', () => {
  it('renders http(s) links, anchors included, and never a javascript: href', async () => {
    server.use(http.get('*/api/v1/feeds/cve/:id', () => HttpResponse.json({
      cve: 'CVE-2026-20001', vendor: 'Acme', product: 'Widget', name: 'n', description: 'd', required_action: 'a', display: 'Acme Widget',
      links: ['https://example.com/CHANGELOG.md#563', 'javascript:alert(1)', 'data:text/html,x'], date_added: '2026-11-03', due_date: null, ransomware: false, epss: null, epss_7d_ago: null, has_template: false, matched: null,
    })))
    renderApp('/cve/CVE-2026-20001')
    const ok = await screen.findByRole('link', { name: 'https://example.com/CHANGELOG.md#563' })
    expect(ok).toHaveAttribute('href', 'https://example.com/CHANGELOG.md#563')
    expect(document.querySelectorAll('a[href^="javascript:"], a[href^="data:"]')).toHaveLength(0)
  })
})
