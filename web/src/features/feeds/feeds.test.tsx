import { describe, expect, it } from 'vitest'
import { cleanup, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { eachOption } from '@/test/formMatrix'
import { server } from '@/test/server'
import { api } from '@/lib/api'
import { assetsStore, modulesStore, sessionStore } from '@/mocks/stores'

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
    expect(await screen.findByText('Alerts on for this product')).toBeInTheDocument()
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

  it('a feed that is switched off is not named in a lookup, and an indicator only it lists is not found (POST-4)', async () => {
    sessionStore.set({ userId: 'u-admin' })
    await api.put('/feeds/sources/et-open', { enabled: false })
    renderApp('/lookup?q=45.148.10.95')
    expect(await screen.findByText(/IPsum \(5 sources\)/)).toBeInTheDocument()
    expect(screen.queryByText(/ET Open compromised/)).not.toBeInTheDocument()
    cleanup()
    await api.put('/feeds/sources/ipsum', { enabled: false })
    renderApp('/lookup?q=45.148.10.95')
    expect(await screen.findByText(/is not on the bad IP\/domain lists/)).toBeInTheDocument()
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

  it('a user name or header name typed for one type does not come back with it (walk 2026-11-12)', async () => {
    const dlg = await openAdd()
    await pick(dlg, 'Authentication')('Basic (user and password)')
    await userEvent.type(within(dlg).getByLabelText('User name'), 'alice')
    await pick(dlg, 'Authentication')('Custom header')
    await userEvent.clear(within(dlg).getByLabelText('Header name')); await userEvent.type(within(dlg).getByLabelText('Header name'), 'X-Token')
    await pick(dlg, 'Authentication')('Basic (user and password)')
    expect(within(dlg).getByLabelText('User name')).toHaveValue('')
    await pick(dlg, 'Authentication')('Custom header')
    expect(within(dlg).getByLabelText('Header name')).toHaveValue('X-Api-Key')
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

  it('D-92: Home never says 0 newly exploited when the CISA list never loaded: it says why and links to Settings, Feeds', async () => {
    const status = (kev: unknown) => server.use(http.get('*/api/v1/feeds/status', () => HttpResponse.json({ generated_at: '2026-11-09T10:00:00Z', kev_catalog_version: '', sources: [], inventory_on: true, kev })))
    server.use(http.get('*/api/v1/feeds/hot', () => HttpResponse.json({ window: '7d', rows: [], latest: null })))
    status({ state: 'never_loaded', error: 'cisa.gov answered HTTP 403' })
    renderApp('/')
    const h1 = await screen.findByRole('heading', { level: 1, name: /The CISA list could not be fetched yet: cisa\.gov answered HTTP 403\./ })
    expect(within(h1).getByRole('link', { name: 'See Settings → Feeds.' })).toHaveAttribute('href', '/settings/feeds')
    expect(h1.textContent).not.toMatch(/\b0 vulnerabilit/)
  })

  it('D-92: a turned-off CISA list says so; a loaded one keeps its count even when the last pull failed', async () => {
    server.use(http.get('*/api/v1/feeds/hot', () => HttpResponse.json({ window: '7d', rows: [], latest: null })))
    server.use(http.get('*/api/v1/feeds/status', () => HttpResponse.json({ generated_at: '2026-11-09T10:00:00Z', kev_catalog_version: '', sources: [], inventory_on: true, kev: { state: 'off', error: null } })))
    const first = renderApp('/')
    expect(await screen.findByRole('heading', { level: 1, name: /The CISA list is turned off\. See Settings → Feeds\./ })).toBeInTheDocument()
    first.unmount()
    server.use(http.get('*/api/v1/feeds/status', () => HttpResponse.json({ generated_at: '2026-11-09T10:00:00Z', kev_catalog_version: '', sources: [], inventory_on: true, kev: { state: 'loaded', error: null } })))
    renderApp('/')
    expect(await screen.findByRole('heading', { level: 1, name: /Today: 0 vulnerabilities newly exploited/ })).toBeInTheDocument()
  })

  it('D-134 (4): the hot board does not read as "none" when the CISA list never loaded; it says why and links to Settings, Feeds', async () => {
    server.use(http.get('*/api/v1/feeds/hot', () => HttpResponse.json({ window: '7d', rows: [], latest: null })))
    server.use(http.get('*/api/v1/feeds/status', () => HttpResponse.json({ generated_at: '2026-11-09T10:00:00Z', kev_catalog_version: '', sources: [], inventory_on: true, kev: { state: 'never_loaded', error: 'cisa.gov answered HTTP 403' } })))
    renderApp('/')
    await screen.findByRole('heading', { level: 1, name: /The CISA list could not be fetched yet/ })
    const hot = within(document.getElementById('hot')!)
    expect(await hot.findByText(/The CISA list could not be fetched yet: cisa\.gov answered HTTP 403\./)).toBeInTheDocument()
    expect(hot.getByRole('link', { name: 'See Settings → Feeds.' })).toHaveAttribute('href', '/settings/feeds')
    expect(hot.queryByText(/No newly exploited/)).toBeNull()
  })

  it('D-134 (4): the hot board of a turned-off CISA list says so; a loaded, enabled one keeps the empty sentence', async () => {
    server.use(http.get('*/api/v1/feeds/hot', () => HttpResponse.json({ window: '7d', rows: [], latest: null })))
    server.use(http.get('*/api/v1/feeds/status', () => HttpResponse.json({ generated_at: '2026-11-09T10:00:00Z', kev_catalog_version: '', sources: [], inventory_on: true, kev: { state: 'off', error: null } })))
    const first = renderApp('/')
    await screen.findByRole('heading', { level: 1, name: /The CISA list is turned off/ })
    const hot = within(document.getElementById('hot')!)
    expect(await hot.findByText(/The CISA list is turned off\./)).toBeInTheDocument()
    expect(hot.getByRole('link', { name: 'See Settings → Feeds.' })).toHaveAttribute('href', '/settings/feeds')
    expect(hot.queryByText(/No newly exploited/)).toBeNull()
    first.unmount()
    server.use(http.get('*/api/v1/feeds/status', () => HttpResponse.json({ generated_at: '2026-11-09T10:00:00Z', kev_catalog_version: '', sources: [], inventory_on: true, kev: { state: 'loaded', error: null } })))
    renderApp('/')
    expect(await screen.findByText(/No newly exploited vulnerabilities in the last 7 days/)).toBeInTheDocument()
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

describe('feeds: after a refused submit the first wrong field takes focus (phone: the message is off-screen)', () => {
  async function openAdd() {
    renderApp('/settings/feeds')
    await userEvent.click((await screen.findAllByRole('button', { name: 'Add a feed' }))[0]!)
    return screen.findByRole('dialog', { name: 'Add a feed' })
  }
  const add = (dlg: HTMLElement) => userEvent.click(within(dlg).getByRole('button', { name: /^Add feed$|^Add$/ }))

  it('the browser-side checks: name, then address, then the secret', async () => {
    const dlg = await openAdd()
    await add(dlg)
    expect(within(dlg).getByLabelText('Name')).toHaveFocus()
    await userEvent.type(within(dlg).getByLabelText('Name'), 'Partner IOC')
    await add(dlg)
    expect(within(dlg).getByLabelText('Address')).toHaveFocus()
    await userEvent.type(within(dlg).getByLabelText('Address'), 'https://feeds.partner.example/ioc.json')
    await userEvent.selectOptions(within(dlg).getByLabelText('Authentication'), 'bearer')
    await add(dlg)
    expect(within(dlg).getByLabelText('Secret')).toHaveFocus()
  })

  it('an answer from the server: a name that exists takes focus; an unknown error takes the message', async () => {
    const dlg = await openAdd()
    await userEvent.type(within(dlg).getByLabelText('Name'), 'CISA KEV')
    await userEvent.type(within(dlg).getByLabelText('Address'), 'https://feeds.partner.example/ioc.json')
    await userEvent.click(within(dlg).getByLabelText('Address')) // focus away from the name
    await add(dlg)
    await waitFor(() => expect(within(dlg).getByLabelText('Name')).toHaveFocus())
    server.use(http.post('*/api/v1/feeds/custom', () => HttpResponse.json({ error: { code: 'x', message: 'The box is busy.' } }, { status: 503 })))
    await userEvent.clear(within(dlg).getByLabelText('Name')); await userEvent.type(within(dlg).getByLabelText('Name'), 'Another one')
    await userEvent.click(within(dlg).getByLabelText('Address'))
    await add(dlg)
    await waitFor(() => expect(within(dlg).getByRole('alert')).toHaveFocus())
  })
})

describe('feeds: Lookup keeps a long query inside the page', () => {
  it('a 200-character string without spaces is allowed to break anywhere', async () => {
    const q = 'a'.repeat(200)
    renderApp(`/lookup?q=${q}`)
    const title = await screen.findByText(`No exploited vulnerability matches "${q}"`)
    // jsdom has no layout: the rule is inherited from the wrapper that holds the result
    expect(title.closest('[class*="overflow-wrap:anywhere"]')).not.toBeNull()
  })
})

describe('feeds: a button\'s accessible name contains its visible text (WCAG 2.5.3)', () => {
  it('Settings -> Feeds: no label-content-name-mismatch on any button', async () => {
    renderApp('/settings/feeds')
    await screen.findByRole('button', { name: /^Fetch now: CISA KEV$|^Fetch CISA KEV now$/ })
    // axe's own rule needs a real layout engine; this is the same rule: the label must contain what is written on the button
    const bad = [...document.querySelectorAll('button[aria-label]')].filter((b) => {
      const visible = (b.textContent ?? '').trim().toLowerCase()
      return visible && !(b.getAttribute('aria-label') ?? '').toLowerCase().includes(visible)
    }).map((b) => `${b.getAttribute('aria-label')} (shows "${b.textContent}")`)
    expect(bad).toEqual([])
  })
})

describe('feeds: plain words for what is not a CVE, and dates that mean one thing', () => {
  it('/cve/hello says it is not a CVE ID, with an example, and never asks the API', async () => {
    let asked = 0
    server.use(http.get('*/api/v1/feeds/cve/:id', () => { asked++; return HttpResponse.json({ error: { code: 'invalid', message: 'Invalid request. The parameter "id" is not valid.' } }, { status: 400 }) }))
    renderApp('/cve/hello')
    expect(await screen.findByText('“hello” is not a CVE ID')).toBeInTheDocument()
    expect(screen.getByText(/CVE IDs look like CVE-2021-44228/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Look up this ID' })).toHaveAttribute('href', '/lookup?q=hello')
    expect(document.body.textContent).not.toMatch(/Invalid request|parameter "id"/)
    expect(asked).toBe(0)
  })

  it('dates are written with the month in letters', async () => {
    renderApp('/cve/CVE-2024-27834')
    expect(await screen.findByText(/Added to exploited list 4 Nov 2026/)).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/\b\d{2}\/\d{2}\/20\d\d\b/)
  })
})

describe('feeds: which address answered the CISA list (D-91)', () => {
  it('Settings -> Feeds says who answered; the CISA GitHub mirror is named as such', async () => {
    renderApp('/settings/feeds')
    expect(await screen.findAllByText('Answered by CISA')).toHaveLength(1) // the mock's own list: only the CISA list has an answer
    const feed = { id: 'cisa-kev', builtin: true, name: 'CISA KEV', kind: 'vulnerabilities', format: 'json', url: 'https://www.cisa.gov/x.json', default_url: 'https://www.cisa.gov/x.json', enabled: true, interval_hours: 24,
      auth: { type: 'none', header_name: null, username: null, secret_last4: null }, parser: null, last_fetch: '2026-11-09T10:00:00Z', records: 1769, status: 'ok', error: null, license: 'CC0', answered_by: 'CISA GitHub mirror' }
    server.use(http.get('*/api/v1/feeds/sources', () => HttpResponse.json({ items: [feed] })))
    cleanup()
    renderApp('/settings/feeds')
    expect(await screen.findByText('Answered by CISA GitHub mirror')).toBeInTheDocument()
  })

  it('W3-1: the NVD versions still loading say how far they got, not "fetched at the next check"; Fetch now shows it as progress', async () => {
    const line = 'Loading version ranges from NVD: page 8 of 18. NVD was busy (HTTP 503); trying page 8 again in 30 s.'
    const feed = { id: 'nvd-kev', builtin: true, name: 'NVD affected versions', kind: 'vulnerabilities', format: 'json', url: 'https://services.nvd.nist.gov/rest/json/cves/2.0', default_url: 'https://services.nvd.nist.gov/rest/json/cves/2.0', enabled: true, interval_hours: 24,
      auth: { type: 'none', header_name: null, username: null, secret_last4: null }, parser: null, last_fetch: null, records: null, status: 'never', error: line, license: null, answered_by: null }
    server.use(http.get('*/api/v1/feeds/sources', () => HttpResponse.json({ items: [feed] })))
    server.use(http.post('*/api/v1/feeds/sources/nvd-kev/fetch', () => HttpResponse.json(feed)))
    renderApp('/settings/feeds')
    expect((await screen.findAllByText(line)).length).toBeGreaterThan(0)
    expect(screen.queryByText(/Fetched at the next scheduled check/)).toBeNull()
    await userEvent.click(screen.getAllByRole('button', { name: /Fetch now/ })[0]!)
    expect(await screen.findByText(`NVD affected versions: ${line}`)).toBeInTheDocument()
  })
})

describe('feeds: a custom vulnerability feed does not drive matching (S-FEED-4, D-218)', () => {
  const feed = (kind: 'ioc' | 'vulnerabilities') => ({ id: 'cf-x', builtin: false, name: 'Partner list', kind, format: 'json', url: 'https://feeds.partner.example/x.json', default_url: null, enabled: true, interval_hours: 24, auth: { type: 'none' }, parser: null, last_fetch: null, records: null, status: 'never', error: null, license: null, answered_by: null })
  const note = /does not create findings or alerts: only the CISA list is matched/

  it('says so under Your own feeds when a custom vulnerability feed exists, and not for an IOC list alone', async () => {
    server.use(http.get('*/api/v1/feeds/sources', () => HttpResponse.json({ items: [feed('vulnerabilities')] })))
    renderApp('/settings/feeds')
    expect(await screen.findByText(note)).toBeInTheDocument()
    cleanup()
    server.use(http.get('*/api/v1/feeds/sources', () => HttpResponse.json({ items: [feed('ioc')] })))
    renderApp('/settings/feeds')
    await screen.findByText('Partner list')
    expect(screen.queryByText(note)).toBeNull()
  })

  it('the add dialog says it when the type is Vulnerabilities', async () => {
    renderApp('/settings/feeds')
    await userEvent.click((await screen.findAllByRole('button', { name: 'Add a feed' }))[0]!)
    const dlg = await screen.findByRole('dialog', { name: 'Add a feed' })
    expect(within(dlg).queryByText(/never creates findings or alerts/)).toBeNull()
    await userEvent.click(within(dlg).getByRole('button', { name: 'Vulnerabilities' }))
    expect(within(dlg).getByText(/never creates findings or alerts/)).toBeInTheDocument()
  })
})

describe('feeds: Settings -> Feeds lists every host the box pulls from (INV-13, PRIVACY flow 1)', () => {
  it('lists built-in and custom hosts from the API, marks a feed that is off, and links to Privacy', async () => {
    const list = [
      { id: 'cisa-kev', builtin: true, name: 'CISA KEV', kind: 'vulnerabilities', format: 'json', url: 'https://www.cisa.gov/x.json', default_url: 'https://www.cisa.gov/x.json', enabled: true, interval_hours: 24, auth: { type: 'none' }, parser: null, last_fetch: null, records: null, status: 'never', error: null, license: null, answered_by: null },
      { id: 'tor-exit', builtin: true, name: 'Tor exit list', kind: 'ioc', format: 'lines', url: 'https://check.torproject.org/torbulkexitlist', default_url: 'https://check.torproject.org/torbulkexitlist', enabled: false, interval_hours: 6, auth: { type: 'none' }, parser: null, last_fetch: null, records: null, status: 'never', error: null, license: null, answered_by: null },
      { id: 'cf-1', builtin: false, name: 'Partner list', kind: 'ioc', format: 'json', url: 'https://intel.partner.example:8443/feed.json?token=s3cret', default_url: null, enabled: true, interval_hours: 24, auth: { type: 'none' }, parser: null, last_fetch: null, records: null, status: 'never', error: null, license: null, answered_by: null },
    ]
    server.use(http.get('*/api/v1/feeds/sources', () => HttpResponse.json({ items: list })))
    renderApp('/settings/feeds')
    const sec = (await screen.findByRole('heading', { name: 'Where this box connects' })).closest('section')!
    expect(within(sec).getByText('www.cisa.gov')).toBeInTheDocument()
    expect(within(sec).getByText(/raw\.githubusercontent\.com if www\.cisa\.gov/)).toBeInTheDocument()
    expect(within(sec).getByText('intel.partner.example')).toBeInTheDocument()
    expect(within(sec).getByText(/Partner list, your feed/)).toBeInTheDocument()
    expect(within(sec).getByText(/Tor exit list, off, not pulled/)).toBeInTheDocument()
    expect(sec.textContent).not.toContain('s3cret')
    expect(within(sec).getByRole('link', { name: 'See Privacy, flow 1' })).toHaveAttribute('href', '/settings/privacy')
  })
})

describe('feeds: parser preview form matrix (docs/QA.md §2, QA walk 2026-11-12)', () => {
  it('a preview belongs to the type and format it ran with: changing either hides it', async () => {
    renderApp('/settings/feeds')
    await userEvent.click((await screen.findAllByRole('button', { name: 'Add a feed' }))[0]!)
    const dlg = await screen.findByRole('dialog', { name: 'Add a feed' })
    const ran = /rows? accepted/
    await eachOption([
      { option: 'CSV', hidden: [ran] },
      { option: 'Vulnerabilities', hidden: [ran] },
    ], async (o) => {
      await userEvent.click(within(dlg).getByRole('button', { name: 'Test on a sample' }))
      await within(dlg).findByText(ran)
      if (o === 'CSV') await userEvent.selectOptions(within(dlg).getByLabelText('Format'), 'CSV')
      else await userEvent.click(within(dlg).getByRole('button', { name: o }))
    }, dlg)
  })
})

describe('feeds: Settings -> Feeds walk 2026-11-12 (S-FEED-4)', () => {
  it('the header names GitHub-hosted lists, and long schedules read in days and weeks', async () => {
    renderApp('/settings/feeds')
    expect(await screen.findByText(/Some sources publish their lists on GitHub, so those come from raw\.githubusercontent\.com/)).toBeInTheDocument()
    await userEvent.click((await screen.findAllByRole('button', { name: /^Settings for / }))[0]!)
    const dlg = await screen.findByRole('dialog')
    const opts = within(within(dlg).getByLabelText('Fetch schedule')).getAllByRole('option')
    expect(opts.map((o) => [o.textContent, (o as HTMLOptionElement).value])).toEqual(expect.arrayContaining([['Every 3 days', '72'], ['Every week', '168'], ['Every 24 hours', '24']]))
  })
})

describe('feeds: Add a feed walk 2, 2026-11-12 (S-FEED-5)', () => {
  it('the JSON Source hint gives an example that fits the field and the feed type', async () => {
    renderApp('/settings/feeds')
    await userEvent.click((await screen.findAllByRole('button', { name: 'Add a feed' }))[0]!)
    const dlg = await screen.findByRole('dialog', { name: 'Add a feed' })
    await userEvent.selectOptions(within(dlg).getByLabelText('Format'), 'json')
    expect(within(dlg).getByText('JSONPath, for example $.type. Empty = not mapped.')).toBeInTheDocument()
    expect(within(dlg).getByText('JSONPath, for example $.score. Empty = not mapped.')).toBeInTheDocument()
    expect(dlg.textContent).not.toContain('$.cveID')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Vulnerabilities' }))
    expect(within(dlg).getByText('JSONPath, for example $.cveID. Empty = not mapped.')).toBeInTheDocument()
    expect(within(dlg).getByText('JSONPath, for example $.vendorProject. Empty = not mapped.')).toBeInTheDocument()
  })

  it('a pasted plain list names the rejected lines and shows each value as text', async () => {
    renderApp('/settings/feeds')
    await userEvent.click((await screen.findAllByRole('button', { name: 'Add a feed' }))[0]!)
    const dlg = await screen.findByRole('dialog', { name: 'Add a feed' })
    await userEvent.selectOptions(within(dlg).getByLabelText('Format'), 'lines')
    await userEvent.click(within(dlg).getByText('Test with your own sample (optional)', { selector: 'summary' }))
    await userEvent.click(within(dlg).getByLabelText('Test with your own sample (optional)'))
    await userEvent.paste('# partner list\n203.0.113.9\n\nnot an ip!!\n<img src=x onerror=alert(1)>\n')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Test on a sample' }))
    expect(await within(dlg).findByText('First rejected lines of the sample')).toBeInTheDocument()
    const items = within(dlg).getAllByRole('listitem').filter((li) => /^Line \d+:/.test(li.textContent ?? ''))
    expect(items.map((li) => li.textContent)).toEqual(['Line 4: indicator: "not" is not a valid indicator', 'Line 5: indicator: "<img" is not a valid indicator'])
    expect(dlg.querySelector('img')).toBeNull()
  })
})

describe('feeds: an address Vedette never pulls from is refused when the feed is saved (D-420)', () => {
  async function openAdd() {
    renderApp('/settings/feeds')
    await userEvent.click((await screen.findAllByRole('button', { name: 'Add a feed' }))[0]!)
    return screen.findByRole('dialog', { name: 'Add a feed' })
  }
  const add = (dlg: HTMLElement) => userEvent.click(within(dlg).getByRole('button', { name: /^Add feed$|^Add$/ }))

  it('loopback, the box itself and cloud metadata show the pull\'s sentence under the address; a copy of a built-in names it', async () => {
    const dlg = await openAdd()
    await userEvent.type(within(dlg).getByLabelText('Name'), 'Metadata')
    for (const [url, text] of [['https://169.254.169.254/latest/meta-data', 'Vedette does not pull feeds from link-local, multicast, unspecified or cloud metadata addresses.'],
      ['https://localhost:8443/x', "That address is Vedette itself: loopback, Vedette's own container, or one of its ports (8443, 8444, 8765, 514, 6514) on the machine that runs it. For another program on that machine, enter the machine's LAN address and that program's port."],
      ['https://127.0.0.1/list.txt', 'That address is Vedette itself']] as const) { // D-446: Vedette itself has its own sentence
      await userEvent.clear(within(dlg).getByLabelText('Address')); await userEvent.type(within(dlg).getByLabelText('Address'), url)
      await add(dlg)
      expect(within(dlg).getByLabelText('Address')).toHaveFocus()
      expect(dlg.querySelector('#cf-url-error')).toHaveTextContent(text)
    }
    await userEvent.clear(within(dlg).getByLabelText('Address')); await userEvent.type(within(dlg).getByLabelText('Address'), 'https://check.torproject.org/torbulkexitlist')
    await add(dlg)
    await waitFor(() => expect(dlg.querySelector('#cf-url-error')).toHaveTextContent('The feed "Tor exit list" already uses this address.'))
    expect(within(dlg).getByLabelText('Address')).toHaveFocus()
  })

  it('a new feed that has not been fetched says when it will be; the name field says its limit', async () => {
    const dlg = await openAdd()
    expect(within(dlg).getByText('Up to 60 characters.')).toBeInTheDocument()
    // walk 3: an IOC feed in JSON gets an IOC example for the records path, not the vulnerability one (D-420 (8))
    expect(within(dlg).getByText(/for example \$\.data\[\*\] or \$\.indicators\[\*\]/)).toBeInTheDocument()
    expect(within(dlg).queryByText(/\$\.vulnerabilities\[\*\]/)).toBeNull()
    await userEvent.type(within(dlg).getByLabelText('Name'), 'Partner IOC')
    await userEvent.type(within(dlg).getByLabelText('Address'), 'https://feeds.partner.example/ioc.json')
    await add(dlg)
    expect((await screen.findAllByText('Fetched at the next scheduled check (every 5 minutes), or now with Fetch now.')).length).toBeGreaterThan(0)
  })
})
