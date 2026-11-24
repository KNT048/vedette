import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { server } from '@/test/server'
import { assetsStore, aiRunsStore, auditStore, modulesStore, sessionStore } from '@/mocks/stores'
import { regimeOf } from './pdpl'
import type { ReportDefinition, ReportDocument } from './types'

const enabled = (el: HTMLElement) => waitFor(() => expect(el).toBeEnabled())
const api = (path: string, init?: RequestInit) => fetch(`${location.origin}/api/v1${path}`, { headers: { 'Content-Type': 'application/json' }, ...init })
const DIACRITICS = /[àáảãạăắằẳẵặâấầẩẫậèéẻẽẹêếềểễệìíỉĩịòóỏõọôốồổỗộơớờởỡợùúủũụưứừửữựỳýỷỹỵđ]/i
const report = () => screen.findByRole('article', { name: 'Security report' })
async function define(change: (d: ReportDefinition) => ReportDefinition) {
  sessionStore.set({ userId: 'u-admin' })
  const d = await (await api('/reports/definition')).json() as ReportDefinition
  const next = change(d)
  expect((await api('/reports/definition', { method: 'PUT', body: JSON.stringify({ name: next.name, options: next.options, recipients: next.recipients }) })).status).toBe(200)
}

describe('reports: the security report (S-REP-1)', () => {
  it('the title and first line say where things stand; seven sections in order; handled findings say who and how; English only; no a11y violations', async () => {
    renderApp('/reports')
    expect(await screen.findByRole('heading', { level: 1, name: "8 findings are open; 6 handled in this report's period" })).toBeInTheDocument()
    const doc = await report()
    expect(within(doc).getByText(/^8 findings are open\. 6 are urgent to handle\. 6 were handled in this period\.$/)).toBeInTheDocument()
    expect(within(doc).getAllByRole('heading', { level: 3 }).map((h) => h.textContent?.replace(/^\d+/, ''))).toEqual(['Summary', 'Handled this period', 'Still open', 'New this period', 'External exposure', 'Detections', 'Coverage'])
    const handled = within(doc).getByRole('region', { name: 'Handled this period' })
    expect(within(handled).getAllByText(/^By Vedette: version moved 6\.24 → 7\.23/)).toHaveLength(2)
    expect(within(handled).getByText(/^By Vedette: Notepad\+\+ was removed/)).toBeInTheDocument()
    expect(within(handled).getByText('Vedette saw 3 of them itself, without anyone telling it.')).toBeInTheDocument()
    expect(within(handled).queryByText(/Not relevant/)).toBeNull() // left out by default
    expect(within(doc).getAllByText('Not added yet').length).toBeGreaterThan(0) // the laptop nobody added, included by default
    expect(document.body.textContent).not.toMatch(DIACRITICS)
    await expectNoA11yViolations()
  })

  it('the summary: key figures, the flow of open findings that adds up, and the three things to do first with their fix', async () => {
    renderApp('/reports')
    const doc = await report()
    const kpi = within(doc).getByLabelText('Key figures')
    expect(within(kpi).getByText('Open now').nextElementSibling).toHaveTextContent('8')
    expect(within(kpi).getByText('Median days to fix').nextElementSibling).toHaveTextContent('3 days') // patched and mitigated: 2, 3, 3, 6, 9
    expect(within(doc).getByRole('img', { name: 'Open at the start 7, plus 7 new, minus 6 handled, open now 8.' })).toBeInTheDocument()
    const first = within(doc).getByRole('heading', { name: 'Do these first' }).nextElementSibling as HTMLElement
    expect(within(first).getAllByRole('listitem')).toHaveLength(3)
    expect(within(first).getByText('Update Apache HTTP Server to 2.4.51')).toBeInTheDocument()
    expect(within(first).getByText('CVE-2021-41773')).toBeInTheDocument()
    expect(within(within(doc).getByRole('region', { name: 'Still open' })).getByRole('link', { name: 'CVE-2021-41773' })).toHaveAttribute('href', '/findings/f-101')
  })

  it('external exposure: per target, ports opened and closed in the period, issues by engine, certificate expiry and proof', async () => {
    renderApp('/reports')
    const exp = within(await report()).getByRole('region', { name: 'External exposure' })
    expect(within(exp).getAllByText('example.com').length).toBeGreaterThan(0)
    expect(within(exp).getAllByText('Ownership proved')).toHaveLength(2)
    expect(within(exp).getByText('Covered by example.com')).toBeInTheDocument()
    expect(within(exp).getByText('Opened')).toBeInTheDocument()
    expect(within(exp).getByText('Closed')).toBeInTheDocument()
    expect(within(exp).getByText(/^Expires /)).toBeInTheDocument() // the certificate that ends in 12 days
    expect(within(exp).getByText('ZAP')).toBeInTheDocument()
  })

  it('Handled says how many not-relevant closures it leaves out, so its count is not read as a smaller Findings › Handled', async () => {
    renderApp('/reports')
    const doc = await report()
    expect(within(doc).getByTestId('not-relevant-left-out')).toHaveTextContent(/^1 finding closed as not relevant in this period is left out \(Settings: Include not relevant\)\.$/)
  })

  it('the figures add up: open at the start + new - handled = open now, and new counts the New section, with or without not relevant', async () => {
    for (const nr of [false, true]) {
      await define((d) => ({ ...d, options: { ...d.options, include_not_relevant: nr } }))
      const d = await (await api('/reports/document')).json() as ReportDocument
      const s = d.summary!
      expect(s.open_before + s.new - s.handled, `not relevant ${nr}`).toBe(s.open_now)
      expect(d.new!.total).toBe(s.new)
      expect(d.handled!.totals.reduce((n, x) => n + x.n, 0)).toBe(s.handled)
      expect(d.new!.items.some((f) => f.status === 'patched')).toBe(true) // new in the period and already handled counts as new
    }
  })

  it('Settings: saving the schedule in its dialog does not save the report settings being edited', async () => {
    const puts: string[] = []
    server.events.on('request:start', ({ request }) => { if (request.method === 'PUT') puts.push(new URL(request.url).pathname) })
    renderApp('/reports?tab=settings', { role: 'admin' })
    const title = await screen.findByLabelText('Report title')
    await enabled(title)
    await userEvent.type(title, ' draft')
    await userEvent.click(await screen.findByRole('button', { name: 'Change the schedule of the security report' }))
    const dlg = await screen.findByRole('dialog')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Save' }))
    expect((await screen.findAllByText('Schedule of the security report saved.')).length).toBeGreaterThan(0)
    expect(puts.some((p) => p.endsWith('/schedules/reports.def:rd-1'))).toBe(true)
    expect(puts.some((p) => p.endsWith('/reports/definition'))).toBe(false)
    expect(screen.getByText('Unsaved changes')).toBeInTheDocument()
    expect(screen.queryByText('Report settings saved')).toBeNull()
    server.events.removeAllListeners()
  })

  it('Settings: while the schedule sends the report, the period follows it (each report covers the time since the one before)', async () => {
    renderApp('/reports?tab=settings', { role: 'admin' })
    const period = await screen.findByLabelText('Period')
    await enabled(period)
    await userEvent.selectOptions(period, 'Last 30 days')
    await userEvent.click(await screen.findByRole('button', { name: 'Change the schedule of the security report' }))
    const dlg = await screen.findByRole('dialog')
    const on = within(dlg).getByRole('switch', { name: 'Run on a schedule' })
    if (on.getAttribute('aria-checked') !== 'true') await userEvent.click(on)
    await userEvent.selectOptions(within(dlg).getByLabelText('Repeat'), 'Every month')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(screen.getByLabelText('Period')).toBeDisabled())
    expect(screen.getByLabelText('Period')).toHaveValue('calendar_month')
    expect(screen.getByText('Follows the schedule: each report covers the time since the one before it.')).toBeInTheDocument()
  })

  it('Settings: sections, grouping, not relevant and charts change the next report; the saved settings stay', async () => {
    const first = renderApp('/reports?tab=settings', { role: 'admin' })
    const save = await screen.findByRole('button', { name: 'Save' })
    expect(save).toBeDisabled() // nothing changed yet
    await userEvent.click(await screen.findByRole('checkbox', { name: 'External exposure' }))
    await userEvent.selectOptions(screen.getByLabelText('Group open findings'), 'By CVE')
    await userEvent.click(screen.getByRole('switch', { name: 'Include findings handled as not relevant' }))
    await userEvent.click(screen.getByRole('switch', { name: 'Charts' }))
    expect(screen.getByText('Unsaved changes')).toBeInTheDocument()
    await userEvent.click(save)
    expect((await screen.findAllByText('Report settings saved')).length).toBeGreaterThan(0)
    first.unmount()

    renderApp('/reports')
    const doc = await report()
    expect(within(doc).queryByRole('region', { name: 'External exposure' })).toBeNull()
    expect(within(doc).queryByRole('img', { name: /^Open at the start/ })).toBeNull()
    const open = within(doc).getByRole('region', { name: 'Still open' })
    expect(within(open).getByRole('columnheader', { name: 'Device' })).toBeInTheDocument() // grouped by CVE: one row per device
    expect(within(within(doc).getByRole('region', { name: 'Handled this period' })).getByText(/^By Vedette: the match was corrected/)).toBeInTheDocument()
    expect(within(doc).getByText(/Includes findings handled as not relevant\. Open findings grouped by CVE\./)).toBeInTheDocument()
  })

  it('Settings: an email is checked on Add, a typed but un-added one blocks Save, and at least one section stays on', async () => {
    renderApp('/reports?tab=settings', { role: 'admin' })
    const email = await screen.findByLabelText('Add a recipient')
    await enabled(email)
    await userEvent.type(email, 'not-an-email')
    await userEvent.click(screen.getByRole('button', { name: 'Add' }))
    expect(screen.getByText('Enter an email address like name@company.com.')).toBeInTheDocument()
    await userEvent.clear(email)
    await userEvent.type(email, 'Boss@Example.com{Enter}')
    expect(within(screen.getByRole('list', { name: 'Recipient list' })).getByText('boss@example.com')).toBeInTheDocument()
    await userEvent.type(email, 'boss@example.com')
    await userEvent.click(screen.getByRole('button', { name: 'Add' }))
    expect(screen.getByText('This address is already on the list.')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(screen.getByText('Click Add to put this address on the list, or clear the field.')).toBeInTheDocument()
    await userEvent.clear(email)
    for (const s of ['Summary', 'Handled this period', 'Still open', 'New this period', 'External exposure', 'Detections', 'Coverage']) await userEvent.click(screen.getByRole('checkbox', { name: s }))
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(screen.getByRole('alert')).toHaveTextContent('Turn on at least one section.')
  })

  it('Settings: the schedule is the shared editor (weekly or monthly), and a viewer cannot change anything', async () => {
    renderApp('/reports?tab=settings', { role: 'viewer' })
    expect(await screen.findByText('Only an administrator changes the report settings.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
    expect(screen.getByRole('switch', { name: 'Charts' })).toBeDisabled()
    expect(await screen.findByRole('button', { name: /Change the schedule of the security report/i })).toBeDisabled()
  })

  it('Send now: the confirmation lists recipients; after sending, History and the audit log gain an entry', async () => {
    renderApp('/reports')
    const btn = await screen.findByRole('button', { name: 'Send now' })
    await enabled(btn)
    await userEvent.click(btn)
    const dlg = await screen.findByRole('dialog', { name: 'Send the report now?' })
    expect(within(dlg).getByText('director@acme.example')).toBeInTheDocument()
    await userEvent.click(within(dlg).getByRole('button', { name: 'Send' }))
    expect((await screen.findAllByText('Report sent. It is kept in History.')).length).toBeGreaterThan(0)
    expect(auditStore.get().some((a) => a.action === 'report.send')).toBe(true)
    await userEvent.click(screen.getByRole('tab', { name: 'History' }))
    const table = await screen.findByRole('table', { name: 'Reports sent' })
    await waitFor(() => expect(within(table).getAllByRole('row')).toHaveLength(4))
    expect(within(table).getByText(/^Sent by /)).toBeInTheDocument()
  })

  it('no recipients: no Send now, one line says where to add them', async () => {
    await define((d) => ({ ...d, recipients: [] }))
    renderApp('/reports')
    expect(await screen.findByText('No recipient yet: add one in Settings.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Send now' })).toBeNull()
  })

  it('viewer: can read and print, cannot send; the server refuses too', async () => {
    renderApp('/reports', { role: 'viewer' })
    await report()
    const send = await screen.findByRole('button', { name: 'Send now' })
    await waitFor(() => expect(send).toBeDisabled())
    expect(send).toHaveAttribute('title', 'Requires Operator role')
    expect(screen.getByRole('button', { name: 'Print / Save PDF' })).toBeEnabled()
    expect((await api('/reports/send', { method: 'POST' })).status).toBe(403)
  })

  it('History: the sent reports, a failed one says why; each opens exactly as sent, even after the settings changed, and prints', async () => {
    const print = vi.spyOn(window, 'print').mockImplementation(() => {})
    await define((d) => ({ ...d, options: { ...d.options, period: 'last_30_days' } }))
    renderApp('/reports?tab=history')
    const table = await screen.findByRole('table', { name: 'Reports sent' })
    expect(within(table).getAllByRole('row')).toHaveLength(3)
    expect(within(table).getByText('Not delivered')).toBeInTheDocument()
    expect(within(table).getByText(/The email channel has no valid SMTP settings/)).toBeInTheDocument()
    await userEvent.click(within(table).getAllByRole('link', { name: /^Open the report sent / })[0]!)
    const doc = await report()
    expect(within(doc).getByText(/^Last 7 days · /)).toBeInTheDocument() // as sent, not today's 30 days
    // the page says what it is and to whom it went, and makes no claim about what the e-mail held: the mail is the report's sections
    // (cut when long), or only the digest when the document cannot be read, with a link only when the box has a web address
    expect(screen.getByText(/^The report as it stood when it was sent to director@acme\.example, it@acme\.example\.$/)).toBeInTheDocument()
    expect(screen.queryByText(/e-mail carried/)).toBeNull()
    expect(screen.getByRole('link', { name: 'Reports' })).toHaveAttribute('href', '/reports')
    expect(screen.queryByText('nav.reports')).toBeNull()
    expect(doc.closest('.print-report')).not.toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Print / Save PDF' }))
    expect(print).toHaveBeenCalledTimes(1)
    await expectNoA11yViolations()
    print.mockRestore()
  })

  it('a sent report that is not in the history says so', async () => {
    renderApp('/reports/sent/rh-missing')
    expect(await screen.findByText('This report is not in the history.')).toBeInTheDocument()
  })

  it('only the report prints, in colour on the light tokens (index.css)', async () => {
    const css = readFileSync(resolve(process.cwd(), 'src/index.css'), 'utf8')
    expect(css).toMatch(/:where\(body:has\(\.print-report\)\) :where\(:not\(:has\(\.print-report\)\)/)
    expect(css).toMatch(/@page report \{ size: A4; margin: 16mm; \}/)
    expect(css).toMatch(/print-color-adjust: exact/)
    renderApp('/reports')
    expect((await report()).closest('.print-report')).not.toBeNull()
  })

  it('reports module off: says so and where to turn it on', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'reports' ? { ...m, enabled: false } : m)))
    renderApp('/reports')
    expect(await screen.findByText(/Reports module is off/i)).toBeInTheDocument()
  })

  it('API error: message and a retry button', async () => {
    server.use(http.get('*/api/v1/reports/document', () => HttpResponse.json({ error: { code: 'x', message: 'Could not build the report.' } }, { status: 500 })))
    renderApp('/reports')
    expect((await screen.findAllByText('Could not build the report.')).length).toBeGreaterThan(0)
    expect(screen.getAllByRole('button', { name: 'Try again' }).length).toBeGreaterThan(0)
  })
})

describe('reports: assessment print page', () => {
  it('no assessment report yet: the print page tells you to go back', async () => {
    renderApp('/reports/print/pdpl')
    expect(await screen.findByText('No assessment report to print yet')).toBeInTheDocument()
  })
})

async function fillOrg(over: { tax?: string; crossBorder?: boolean; size?: string; sensitive?: boolean } = {}) {
  const name = await screen.findByLabelText('Organisation name')
  await enabled(name)
  await userEvent.type(screen.getByLabelText('Tax code'), over.tax ?? '0312345678')
  await userEvent.type(screen.getByLabelText('Head office address'), '12 Nguyen Hue, District 1, Ho Chi Minh City')
  await userEvent.selectOptions(screen.getByLabelText('Line of business'), 'Retail and trade')
  await userEvent.type(screen.getByLabelText('Number of staff'), '45')
  await userEvent.selectOptions(screen.getByLabelText('Organisation size'), over.size ?? 'Medium or large enterprise, or other organisation')
  await userEvent.type(screen.getByLabelText('Data protection contact'), 'Tran Van An')
  await userEvent.type(screen.getByLabelText('Contact email'), 'anna@acme.example')
  await userEvent.type(screen.getByLabelText('Contact phone'), '0901234567')
  if (over.sensitive) await userEvent.click(screen.getByRole('checkbox', { name: 'We process sensitive personal data' }))
  if (over.crossBorder) await userEvent.click(screen.getByRole('checkbox', { name: 'We transfer data abroad' }))
}
const generate = async () => {
  await userEvent.click(screen.getByRole('button', { name: 'Save details' }))
  await screen.findAllByText('Organisation details saved')
  await waitFor(() => expect(screen.getByRole('button', { name: 'Generate report' })).toBeEnabled())
  await userEvent.click(screen.getByRole('button', { name: 'Generate report' }))
  return screen.findByRole('article', { name: /Information security and personal data assessment report/ })
}

describe('reports: data protection assessment under Vietnam\'s Law 91/2025/QH15 (S-REP-2)', () => {
  it('the tab shows the disclaimer first; without saved organisation details the report cannot be generated', async () => {
    renderApp('/reports?tab=pdpl')
    expect(await screen.findByText('Assessment support, not legal advice')).toBeInTheDocument()
    const gen = await screen.findByRole('button', { name: 'Generate report' })
    expect(gen).toBeDisabled()
    expect(gen).toHaveAttribute('title', 'Save the organisation details first')
    expect(screen.getByLabelText('Organisation name')).toHaveValue('Sample Company')
    await expectNoA11yViolations()
  })

  it('an empty submit explains every field; a bad tax code is flagged at the field and nothing is saved', async () => {
    renderApp('/reports?tab=pdpl')
    await enabled(await screen.findByLabelText('Organisation name'))
    await userEvent.clear(screen.getByLabelText('Organisation name'))
    await userEvent.click(screen.getByRole('button', { name: 'Save details' }))
    for (const m of ['Enter the organisation name', 'The tax code is 10 digits', 'Enter the head office address', 'Pick the field of activity', 'Enter the headcount', 'Pick the organisation size', 'Enter the name of the person', 'Enter the contact email. It is required.', 'Enter the contact phone number. It is required.']) expect(await screen.findByText(new RegExp(m))).toBeInTheDocument()
    expect(screen.getByLabelText('Tax code')).toBeInvalid()
    await userEvent.type(screen.getByLabelText('Organisation name'), 'Sample Co')
    await fillOrg({ tax: '123' })
    await userEvent.click(screen.getByRole('button', { name: 'Save details' }))
    expect(await screen.findByText(/The tax code is 10 digits/)).toBeInTheDocument()
    expect(screen.getByLabelText('Head office address')).toHaveValue('12 Nguyen Hue, District 1, Ho Chi Minh City')
    expect(((await (await api('/reports/pdpl')).json()) as { org: unknown }).org).toBeNull()
  })

  it('fill in, save, generate from inventory and scans; obligations follow the declared traits; legal references and disclaimer are in the report', async () => {
    renderApp('/reports?tab=pdpl')
    await fillOrg({ crossBorder: true })
    const doc = await generate()
    expect(within(doc).getByText(/The inventory records \d+ devices/)).toBeInTheDocument()
    const measures = within(doc).getByRole('table', { name: '3. Technical protection measures' })
    expect(within(measures).getByText(/machines expose RDP \(3389\): .*SRV-AD/)).toBeInTheDocument()
    expect(within(measures).getByText(/operating system at or near end of support: .*SRV-AD/)).toBeInTheDocument()
    expect(within(measures).getAllByText('No data').length).toBeGreaterThan(0)
    expect(within(doc).getByText('Transfer of data abroad')).toBeInTheDocument()
    expect(within(doc).queryByText('Sensitive personal data')).toBeNull()
    expect(within(doc).getByText('Person or unit in charge of personal data protection').parentElement).toHaveTextContent('Contact recorded')
    expect(within(doc).getAllByText('Assessment support, not legal advice')).toHaveLength(2)
    expect(await within(doc).findByRole('table', { name: '4. Unresolved exploited vulnerabilities' })).toBeInTheDocument()
    // legal content checked against the original text
    const text = doc.textContent ?? ''
    for (const must of ['91/2025/QH15', 'Decree 356/2025/ND-CP', '72 hours', '60 days', 'Article 23', 'Articles 21, 22', 'Article 20', 'Form 09']) expect(text).toContain(must)
    expect(text).not.toMatch(DIACRITICS)
    await expectNoA11yViolations()
  })

  it('a device type is printed by its label and counted by the kind it acts as (a virtual machine is a key system)', async () => {
    assetsStore.update((l) => l.map((a) => (a.id === 'a-srvad' ? { ...a, kind: 'virtual_machine' } : a)))
    renderApp('/reports?tab=pdpl')
    await fillOrg()
    const doc = await generate()
    expect(doc.textContent).not.toContain('virtual_machine')
    const key = within(doc).getByRole('table', { name: 'Key systems: servers, NAS and firewalls' })
    expect(within(key).getByText('Virtual machine')).toBeInTheDocument()
  })

  it('with no devices the report has no raw translation keys, one measures heading and sensible empty text', async () => {
    assetsStore.set([])
    renderApp('/reports?tab=pdpl')
    await fillOrg()
    const doc = await generate()
    expect(doc.textContent).not.toMatch(/\bdoc\.[a-z]/)
    expect(within(doc).getAllByText('3. Technical protection measures')).toHaveLength(1)
    expect(within(doc).getByText('No devices are recorded yet.')).toBeInTheDocument()
    expect(doc.textContent).not.toContain('By type:')
  })

  it('AI commentary sits in the AI block with model and profile; the print page shows the same report', async () => {
    renderApp('/reports?tab=pdpl')
    await fillOrg()
    const doc = await generate()
    const aiBtn = screen.getByRole('button', { name: 'Write AI commentary' })
    const aiBlock = aiBtn.closest('[data-ai="true"]') as HTMLElement
    expect(aiBlock).not.toBeNull()
    await userEvent.click(aiBtn)
    expect(await within(doc).findByText('AI-generated, needs human review')).toBeInTheDocument()
    expect(within(aiBlock).getByText(/Model claude-sonnet-5-5 \(Claude Sonnet\)/)).toBeInTheDocument()
    expect(aiRunsStore.get().some((r) => r.skill === 'pdpl-assessment')).toBe(true)
    expect(screen.getByRole('link', { name: 'Print / Save PDF' })).toHaveAttribute('href', '/reports/print/pdpl')
  })

  it('size decides the obligations: a micro enterprise is exempt from the dossier and the data protection person (Decree 356 Article 41); sensitive data makes them mandatory', async () => {
    renderApp('/reports?tab=pdpl')
    await fillOrg({ size: 'Micro enterprise' })
    const doc = await generate()
    expect(within(doc).getAllByText('Not mandatory at your size')).toHaveLength(2)
    expect(within(doc).getByText('7. Legal basis and sources')).toBeInTheDocument()
    expect(regimeOf({ size: 'micro', processing_service: false, sensitive: true, data_volume: 'lt1k' })).toBe('required')
    expect(regimeOf({ size: 'small', processing_service: false, sensitive: false, data_volume: 'lt1k' })).toBe('optional')
    expect(regimeOf({ size: 'micro', processing_service: false, sensitive: false, data_volume: 'gte100k' })).toBe('required')
    expect(regimeOf({ size: 'household', processing_service: true, sensitive: false, data_volume: 'lt1k' })).toBe('required')
    expect(regimeOf({ size: 'other', processing_service: false, sensitive: false, data_volume: 'lt1k' })).toBe('required')
  })

  it('server: generating without organisation details is refused (409); AI without a report is refused; bad bodies are 400', async () => {
    sessionStore.set({ userId: 'u-op' })
    const g = await api('/reports/pdpl/generate', { method: 'POST', body: '{}' })
    expect(g.status).toBe(409)
    expect(((await g.json()) as { error: { message: string } }).error.message).toMatch(/Fill in and save the organisation details/)
    expect((await api('/reports/pdpl/ai-summary', { method: 'POST', body: '{}' })).status).toBe(409)
    for (const body of [{ name: 'A' }, { name: 'Company A', tax_code: '0312345678', address: 'abc', sector: 'it' }]) expect((await api('/reports/pdpl/org', { method: 'PUT', body: JSON.stringify(body) })).status).toBe(400)
  })

  it('viewer: the form is read-only and the server refuses writes', async () => {
    renderApp('/reports?tab=pdpl', { role: 'viewer' })
    const name = await screen.findByLabelText('Organisation name')
    expect(name).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Save details' })).toBeDisabled()
    expect((await api('/reports/pdpl/org', { method: 'PUT', body: '{}' })).status).toBe(403)
    expect((await api('/reports/pdpl/generate', { method: 'POST', body: '{}' })).status).toBe(403)
  })

  it('load error: message and retry button', async () => {
    server.use(http.get('*/api/v1/reports/pdpl', () => HttpResponse.json({ error: { code: 'x', message: 'Could not read the assessment.' } }, { status: 500 })))
    renderApp('/reports?tab=pdpl')
    expect(await screen.findByText('Could not read the assessment.')).toBeInTheDocument()
  })
})
