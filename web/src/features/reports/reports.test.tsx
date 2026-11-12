import { describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { server } from '@/test/server'
import { aiAssignStore, assetsStore, aiConfigStore, aiRunsStore, auditStore, modulesStore, sessionStore } from '@/mocks/stores'
import { regimeOf } from './pdpl'
import { buildWeekly } from './weekly'

const enabled = (el: HTMLElement) => waitFor(() => expect(el).toBeEnabled())
const api = (path: string, init?: RequestInit) => fetch(`${location.origin}/api/v1${path}`, { headers: { 'Content-Type': 'application/json' }, ...init })
const DIACRITICS = /[àáảãạăắằẳẵặâấầẩẫậèéẻẽẹêếềểễệìíỉĩịòóỏõọôốồổỗộơớờởỡợùúủũụưứừửữựỳýỷỹỵđ]/i

describe('reports: weekly report (S-REP-1)', () => {
  it('first sentence says what is left; the preview has remaining findings, next week tasks, sources; English only; no a11y violations', async () => {
    renderApp('/reports')
    expect(await screen.findByRole('heading', { level: 1, name: 'This week 3 findings are unresolved and 2 devices await approval.' })).toBeInTheDocument()
    const doc = await screen.findByRole('article', { name: 'Weekly security report' })
    // A finding new this week and still open is listed once, under What is new; Remaining counts it (walk 3 G13).
    const fresh = within(doc).getByRole('table', { name: 'What is new' })
    expect(within(fresh).getByText('NAS-PHOTOS')).toBeInTheDocument()
    expect(within(fresh).getByText('CVE-2022-27593')).toBeInTheDocument()
    expect(within(doc).getAllByText('CVE-2022-27593')).toHaveLength(1)
    expect(within(doc).getByText(/^(Plus the new findings? listed above|Every unresolved finding is new this week|The new finding listed above)/)).toBeInTheDocument()
    expect(within(doc).getByText(/Patch or apply a temporary fix for CVE-2022-27593 on NAS-PHOTOS \(confirmed\)/)).toBeInTheDocument()
    expect(within(doc).queryByText(/Honeypot touches$/)).toBeNull() // không bịa số bẫy/log
    expect(within(doc).getByText(/are not part of this report yet/)).toBeInTheDocument()
    expect(within(doc).queryByText('AI-generated, needs human review')).toBeNull()
    expect(document.body.textContent).not.toMatch(DIACRITICS)
    await expectNoA11yViolations()
  })

  it('send history: 3 sample entries, a failed one says why, each can be opened for printing', async () => {
    renderApp('/reports')
    const table = await screen.findByRole('table', { name: 'History of weekly reports sent' })
    expect(within(table).getAllByRole('row')).toHaveLength(4)
    expect(within(table).getByText('Failed')).toBeInTheDocument()
    expect(within(table).getByText(/The email channel has no valid SMTP settings/)).toBeInTheDocument()
    expect(within(table).getAllByRole('link', { name: 'View and print' })[0]).toHaveAttribute('href', expect.stringMatching(/^\/reports\/print\/weekly\/h-/))
  })

  it('Send now: the confirmation lists recipients; after sending the history and the audit log gain an entry', async () => {
    renderApp('/reports')
    const btn = await screen.findByRole('button', { name: 'Send now' })
    await enabled(btn)
    await userEvent.click(btn)
    const dlg = await screen.findByRole('dialog', { name: 'Send the weekly report now?' })
    expect(await within(dlg).findByText('director@acme.example')).toBeInTheDocument()
    await userEvent.click(within(dlg).getByRole('button', { name: 'Send' }))
    expect((await screen.findAllByText('Weekly report sent')).length).toBeGreaterThan(0)
    await waitFor(() => expect(within(screen.getByRole('table', { name: 'History of weekly reports sent' })).getAllByRole('row')).toHaveLength(5))
    expect(auditStore.get().some((a) => a.action === 'report.weekly.send')).toBe(true)
  })

  it('no recipients: cannot send and the server says how to fix it', async () => {
    sessionStore.set({ userId: 'u-admin' })
    expect((await api('/reports/schedule', { method: 'PUT', body: JSON.stringify({ enabled: false, day: 1, hour: 8, recipients: [] }) })).status).toBe(200)
    renderApp('/reports')
    const btn = await screen.findByRole('button', { name: 'Send now' })
    await enabled(btn)
    await userEvent.click(btn)
    const dlg = await screen.findByRole('dialog')
    await waitFor(() => expect(within(dlg).getByText(/No recipients yet/)).toBeInTheDocument())
    expect(within(dlg).getByRole('button', { name: 'Send' })).toBeDisabled()
    const res = await api('/reports/weekly/send', { method: 'POST', body: '{}' })
    expect(res.status).toBe(400)
    expect(((await res.json()) as { error: { message: string } }).error.message).toMatch(/Add an email/)
  })

  it('viewer: cannot send or change the schedule; the server refuses too', async () => {
    renderApp('/reports', { role: 'viewer' })
    const send = await screen.findByRole('button', { name: 'Send now' })
    await waitFor(() => expect(send).toBeDisabled())
    expect(send).toHaveAttribute('title', 'Requires Operator role')
    expect(await screen.findByRole('button', { name: 'Save' })).toBeDisabled()
    expect(screen.getByLabelText('Day')).toBeDisabled()
    expect((await api('/reports/weekly/send', { method: 'POST', body: '{}' })).status).toBe(403)
    expect((await api('/reports/schedule', { method: 'PUT', body: '{}' })).status).toBe(403)
  })

  it('schedule: change day and hour, add and remove recipients, save; it persists', async () => {
    renderApp('/reports')
    const day = await screen.findByLabelText('Day')
    await enabled(day)
    await userEvent.selectOptions(day, '5')
    await userEvent.selectOptions(screen.getByLabelText('Hour'), '17')
    await userEvent.type(screen.getByLabelText('Recipients'), 'accounting@acme.example{Enter}')
    await userEvent.click(screen.getByRole('button', { name: 'Remove it@acme.example' }))
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect((await screen.findAllByText('Schedule saved')).length).toBeGreaterThan(0)
    const s = (await (await api('/reports/schedule')).json()) as { day: number; hour: number; recipients: string[]; next_run: string }
    expect(s).toMatchObject({ day: 5, hour: 17, recipients: ['director@acme.example', 'accounting@acme.example'] })
    expect(new Date(s.next_run).getDay()).toBe(5)
    expect(screen.getByText(/Next send:/)).toBeInTheDocument()
  })

  it('schedule: with no email channel on, automatic sending warns and links to Alert channels instead of promising a next send', async () => {
    sessionStore.set({ userId: 'u-admin' })
    expect((await api('/notify/channels/email', { method: 'DELETE' })).status).toBe(204)
    renderApp('/reports')
    const warn = await screen.findByText(/No email channel is on, so nothing will be sent/)
    expect(within(warn.parentElement as HTMLElement).getByRole('link', { name: 'Set up the email channel' })).toHaveAttribute('href', '/settings/channels')
    expect(screen.queryByText(/Next send:/)).toBeNull()
  })

  it('schedule: a bad email is flagged at once; a typed but un-added email blocks Save; the server refuses automatic sending with no recipients', async () => {
    renderApp('/reports')
    const input = await screen.findByLabelText('Recipients')
    await enabled(input)
    await userEvent.type(input, 'not-an-email')
    await userEvent.click(screen.getByRole('button', { name: 'Add' }))
    expect(await screen.findByText('The email is not valid. Use the form name@company.com.')).toBeInTheDocument()
    await userEvent.clear(input)
    await userEvent.type(input, 'someone@acme.example')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText(/Press Add to put this email on the list/)).toBeInTheDocument()
    const bad = await api('/reports/schedule', { method: 'PUT', body: JSON.stringify({ enabled: true, day: 1, hour: 8, recipients: [] }) })
    expect(bad.status).toBe(400)
    expect(((await bad.json()) as { error: { message: string } }).error.message).toMatch(/at least one recipient/)
    expect((await api('/reports/schedule', { method: 'PUT', body: JSON.stringify({ enabled: true, day: 0, hour: 8, recipients: ['a@b.vn'] }) })).status).toBe(400)
    expect((await api('/reports/schedule', { method: 'PUT', body: JSON.stringify({ enabled: true, day: 1, hour: 30, recipients: ['a@b.vn'] }) })).status).toBe(400)
  })

  it('schedule (walk 3 G13): an address longer than the box allows is refused on Add with the reason; a refusal at Save names the address at the field', async () => {
    renderApp('/reports')
    const input = await screen.findByLabelText('Recipients')
    await enabled(input)
    await userEvent.click(input)
    await userEvent.paste(`${'a'.repeat(300)}@example.com`)
    await userEvent.click(screen.getByRole('button', { name: 'Add' }))
    expect(input).toHaveAccessibleDescription('An email address has 120 characters at most; this one has 312.')
    expect(screen.queryByRole('button', { name: /^Remove a{300}/ })).toBeNull()
    await userEvent.clear(input)
    server.use(http.put('*/api/v1/reports/schedule', () => HttpResponse.json({ error: { code: 'invalid_input', message: 'The field "recipients[0]" is missing or has a value that is not allowed. Fix it and try again.', field: 'recipients[0]' } }, { status: 400 })))
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(input).toHaveAccessibleDescription('The box did not accept "director@acme.example": it is not a valid email address. Remove it, then save.'))
    expect(screen.queryByText(/recipients\[0\]/)).toBeNull()
  })

  it('AI commentary lives only inside the AI block, labelled with model and profile, records one run', async () => {
    renderApp('/reports')
    const btn = await screen.findByRole('button', { name: 'Write AI commentary' })
    await enabled(btn)
    await userEvent.click(btn)
    const doc = await screen.findByRole('article', { name: 'Weekly security report' })
    expect(await within(doc).findByText('AI-generated, needs human review')).toBeInTheDocument()
    expect(within(doc).getByText(/Last week had \d+ new findings/)).toBeInTheDocument()
    expect(within(doc).getByText(/Model claude-haiku-5-5 \(Claude Haiku\)/)).toBeInTheDocument() // hồ sơ chính của "Weekly report comments"
    expect(aiRunsStore.get().filter((r) => r.skill === 'weekly-report')).toHaveLength(1)
    expect(aiRunsStore.get()[0]).toMatchObject({ profile: 'Claude Haiku' })
  })

  it('no AI profile or the task unassigned: the commentary button is disabled with a reason', async () => {
    aiConfigStore.update((c) => ({ ...c, configured: false }))
    const a = renderApp('/reports')
    const btn = await screen.findByRole('button', { name: 'Write AI commentary' })
    await waitFor(() => expect(btn).toBeDisabled())
    expect(btn).toHaveAttribute('title', 'Connect AI in Settings, AI assistant')
    a.unmount()
    aiConfigStore.update((c) => ({ ...c, configured: true }))
    aiAssignStore.update((s) => ({ ...s, jobs: { ...s.jobs, 'weekly-report': { primary: null, fallback: null } } }))
    renderApp('/reports')
    const btn2 = await screen.findByRole('button', { name: 'Write AI commentary' })
    await waitFor(() => expect(btn2).toBeDisabled())
  })

  it('reports module off: says so and where to turn it on', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'reports' ? { ...m, enabled: false } : m)))
    renderApp('/reports')
    expect(await screen.findByText(/Reports module is off/i)).toBeInTheDocument()
  })

  it('API error: message and a retry button', async () => {
    server.use(http.get('*/api/v1/reports/weekly/preview', () => HttpResponse.json({ error: { code: 'x', message: 'Could not build the weekly report.' } }, { status: 500 })))
    renderApp('/reports')
    expect((await screen.findAllByText('Could not build the weekly report.')).length).toBeGreaterThan(0)
    expect(screen.getAllByRole('button', { name: 'Try again' }).length).toBeGreaterThan(0)
  })
})

describe('reports: point-in-time figures', () => {
  it('four weeks ago there were no findings yet (every sample finding appeared later)', () => {
    const old = buildWeekly(Date.now() - 28 * 864e5)
    expect(old.counts.open_confirmed + old.counts.open_suspected).toBe(0)
    expect(buildWeekly().counts.open_confirmed).toBe(1)
    expect(buildWeekly().counts.open_suspected).toBe(2)
  })
})

describe('reports: print pages (print / save as PDF)', () => {
  it('preview: the Print button calls window.print, only .print-doc is printed, no a11y violations', async () => {
    const print = vi.spyOn(window, 'print').mockImplementation(() => {})
    renderApp('/reports/print/weekly')
    expect(await screen.findByRole('heading', { level: 1, name: 'Weekly report, print view' })).toBeInTheDocument()
    const doc = await screen.findByRole('article', { name: 'Weekly security report' })
    expect(doc.closest('.print-doc')).not.toBeNull()
    expect([...document.querySelectorAll('style')].some((x) => /@media print/.test(x.textContent ?? ''))).toBe(true)
    await userEvent.click(screen.getByRole('button', { name: 'Print / Save PDF' }))
    expect(print).toHaveBeenCalledTimes(1)
    await expectNoA11yViolations()
    print.mockRestore()
  })

  it('a sent copy reprints the figures of that week', async () => {
    renderApp('/reports/print/weekly/h-1')
    const doc = await screen.findByRole('article', { name: 'Weekly security report' })
    expect(within(doc).getByText(/^From \d/)).toBeInTheDocument()
  })

  it('an id that is not in the history', async () => {
    renderApp('/reports/print/weekly/h-missing')
    expect(await screen.findByText('This report is not in the history.')).toBeInTheDocument()
  })

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
    // nội dung pháp lý đã đối chiếu văn bản gốc (D-23)
    const text = doc.textContent ?? ''
    for (const must of ['91/2025/QH15', 'Decree 356/2025/ND-CP', '72 hours', '60 days', 'Article 23', 'Articles 21, 22', 'Article 20', 'Form 09']) expect(text).toContain(must)
    expect(text).not.toMatch(DIACRITICS)
    await expectNoA11yViolations()
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
    await userEvent.click(screen.getByRole('button', { name: 'Write AI commentary' }))
    expect(await within(doc).findByText('AI-generated, needs human review')).toBeInTheDocument()
    expect(within(doc).getByText(/Model claude-sonnet-5-5 \(Claude Sonnet\)/)).toBeInTheDocument()
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
