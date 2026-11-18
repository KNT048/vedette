import { afterEach, describe, expect, it } from 'vitest'
import { http, HttpResponse } from 'msw'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { server } from '@/test/server'
import { assetsStore } from '@/mocks/stores'

// A package release a person enters says it was saved and which CVEs it closed: in place on Needs your input, and for good on the
// device's Software tab (the release, who entered it and when, the result), with the same words wherever the value is saved.
const T = { timeout: 5000 }
const patches: { url: string; body: unknown }[] = []
server.events.on('request:start', ({ request }) => {
  if (request.method === 'PATCH') void request.clone().json().then((body: unknown) => patches.push({ url: new URL(request.url).pathname, body }))
})
afterEach(() => { patches.length = 0 })

const alpine = () => assetsStore.update((l) => l.map((a) => (a.id === 'a-bn340' ? { ...a, os: { value: 'Alpine Linux 3.23', source: 'manual', confidence: 1, seen_at: new Date().toISOString() } } : a)))
const enterRelease = async (release: string) => {
  alpine()
  renderApp('/findings?tab=input')
  const list = await screen.findByRole('list', { name: 'Devices that need your input, the most urgent first' }, T)
  await userEvent.click(await within(list).findByRole('button', { name: /^BN340/ }, T))
  const block = await screen.findByRole('listitem', { name: 'BN340' }, T)
  await userEvent.type(await within(block).findByLabelText('Package release of OpenSSH', undefined, T), release)
  await userEvent.click(within(block).getByRole('button', { name: 'Save and check' }))
}
const result = () => screen.findByRole('listitem', { name: 'Saved OpenSSH 10.2_p1-r1 on BN340.' }, T)

describe('An entered package release', () => {
  it('Needs your input says what was saved and which CVE it closed, with a link to it, after the item has left', async () => {
    await enterRelease('openssh-server-10.2_p1-r1')
    // the whole apk line was typed; the release it carries is what is saved
    const saved = await screen.findByRole('listitem', { name: /^Saved OpenSSH openssh-server-10\.2_p1-r1 on BN340\.$/ }, T)
    expect(await within(saved).findByText(/Closed 1 CVE as not affected:/, undefined, T)).toBeInTheDocument()
    expect(within(saved).getByRole('link', { name: 'CVE-2026-123158' })).toHaveAttribute('href', expect.stringMatching(/^\/findings\/.+/))
    // the device's question is gone; the result stays, with a way to change the entry and to open the row
    await waitFor(() => expect(screen.queryByRole('listitem', { name: 'BN340' })).toBeNull(), T)
    expect(within(saved).getByRole('button', { name: 'Change OpenSSH on BN340' })).toBeInTheDocument()
    expect(within(saved).getByRole('link', { name: 'Open OpenSSH on the device' })).toHaveAttribute('href', '/devices/a-bn340?tab=software')
    await expectNoA11yViolations()
  })

  it('Change saves another release in place and the result is read again', async () => {
    await enterRelease('10.2_p1-r1')
    const saved = await result()
    await within(saved).findByText(/Closed 1 CVE as not affected:/, undefined, T)
    await userEvent.click(within(saved).getByRole('button', { name: 'Change OpenSSH on BN340' }))
    const field = within(saved).getByLabelText('New package release of OpenSSH')
    await userEvent.clear(field)
    await userEvent.type(field, 'bad release!')
    await userEvent.click(within(saved).getByRole('button', { name: 'Save and check' }))
    expect(await within(saved).findByRole('alert', undefined, T)).toHaveTextContent(/package release may only contain/i)
    await userEvent.clear(field)
    await userEvent.type(field, '10.2_p1-r2')
    await userEvent.click(within(saved).getByRole('button', { name: 'Save and check' }))
    expect(await screen.findByRole('listitem', { name: 'Saved OpenSSH 10.2_p1-r2 on BN340.' }, T)).toBeInTheDocument()
    expect(patches).toContainEqual({ url: '/api/v1/inventory/devices/a-bn340/software/s-bn340-ssh', body: { pkg_version: '10.2_p1-r2' } })
  })

  it('the device Software tab keeps the release, who entered it and when, and what it closed, and it is editable there', async () => {
    await enterRelease('10.2_p1-r1')
    const saved = await result()
    await userEvent.click(within(saved).getByRole('link', { name: 'Open OpenSSH on the device' }))
    const table = await screen.findByRole('table', { name: 'Software on the device' }, T)
    await within(table).findByText(/Closed 1 CVE as not affected:/, undefined, T)
    const note = within(table).getAllByTestId('entered-note')[0]!
    expect(note).toHaveTextContent('Package release 10.2_p1-r1')
    expect(note).toHaveTextContent(/Entered by .+@.+ /)
    expect(within(note).getByRole('link', { name: 'CVE-2026-123158' })).toBeInTheDocument()
    // edit in place: the pencil of the row opens its package release
    await userEvent.click(within(table).getByRole('button', { name: 'Change the version of OpenSSH' }))
    const field = await screen.findByLabelText('Package release', undefined, T)
    expect(field).toHaveValue('10.2_p1-r1')
    await userEvent.clear(field)
    await userEvent.type(field, '10.2_p1-r3')
    await userEvent.click(screen.getByRole('button', { name: 'Save version' }))
    await waitFor(() => expect(patches.some((p) => /^\/api\/v1\/inventory\/devices\/a-bn340\/software\/s-/.test(p.url) && JSON.stringify(p.body) === '{"pkg_version":"10.2_p1-r3"}')).toBe(true), T)
    expect(await screen.findByText('OpenSSH is now package release 10.2_p1-r3. Findings are matched again.', undefined, T)).toBeInTheDocument()
  })

  it('software a person declared says "Entered by hand", as no author or time is on record', async () => {
    renderApp('/devices/a-srvfile?tab=software')
    const table = await screen.findByRole('table', { name: 'Software on the device' }, T)
    const notes = await within(table).findAllByTestId('entered-note', undefined, T)
    expect(notes.some((n) => /Entered by hand/.test(n.textContent ?? ''))).toBe(true)
  })
})

// The result is the box's answer to THIS entry: nothing is said until it has matched the device again, only what the entry proved
// counts as closed by it, and what cannot be read is not turned into an answer.
const F = (o: Record<string, unknown>) => ({ id: 'f-ssh', asset_id: 'a-bn340', cve: 'CVE-2026-123158', status: 'suspected', severity: 'high', last_seen: '2026-11-18T01:00:00.000Z', history: [],
  resolution_reason: null, proved_version: null, software_id: 's-bn340-ssh', ...o })
const closedOn = (v: string | null, o: Record<string, unknown> = {}) => F({ status: 'not_relevant', resolution_reason: 'not_affected_version', proved_version: v, last_seen: '2026-11-18T01:00:00.000Z', ...o })
/** The device's findings as the box answers them: `before` until the entry is saved, then `after(n)` for the n-th read since (a 500 when it returns null). */
function box(before: unknown[], after: (n: number) => unknown[] | null) {
  let saved = false
  let n = 0
  server.events.on('request:start', ({ request }) => { if (request.method === 'PATCH' && request.url.includes('/software/')) saved = true })
  server.use(http.get('*/api/v1/findings', ({ request }) => {
    if (!new URL(request.url).searchParams.get('asset')) return undefined
    if (!saved) return HttpResponse.json({ items: before, version_needed: [], unchecked: [] })
    const items = after(++n)
    return items ? HttpResponse.json({ items, version_needed: [], unchecked: [] }) : HttpResponse.json({ error: { code: 'internal', message: 'down' } }, { status: 500 })
  }))
}
const SLOW = { timeout: 15000 }

describe('An entered package release › the result is the answer to this entry', () => {
  it('says "Checking" while the box has not matched the device again, never "still affected" from before the entry', async () => {
    box([F({})], (n) => (n < 3 ? [F({})] : [closedOn('10.2_p1-r1', { last_seen: '2026-11-18T02:00:00.000Z' })]))
    await enterRelease('10.2_p1-r1')
    const saved = await result()
    expect(await within(saved).findByText('Checking which CVEs this closes…', undefined, T)).toBeInTheDocument()
    expect(within(saved).queryByText(/still affected/)).toBeNull()
    expect(await within(saved).findByText(/Closed 1 CVE as not affected:/, undefined, SLOW)).toBeInTheDocument()
    expect(within(saved).queryByText('Checking which CVEs this closes…')).toBeNull()
  }, 30000)

  it('Change starts over: the previous release\'s "Closed" is not shown as the answer for the new one', async () => {
    let second = false
    box([F({})], (n) => (second ? [closedOn('10.2_p1-r1', { last_seen: '2026-11-18T02:00:00.000Z' })] : n < 2 ? [F({})] : [closedOn('10.2_p1-r1', { last_seen: '2026-11-18T02:00:00.000Z' })]))
    await enterRelease('10.2_p1-r1')
    const saved = await result()
    await within(saved).findByText(/Closed 1 CVE as not affected:/, undefined, SLOW)
    second = true // the box keeps answering as before the new entry until it matches again
    await userEvent.click(within(saved).getByRole('button', { name: 'Change OpenSSH on BN340' }))
    const field = within(saved).getByLabelText('New package release of OpenSSH')
    await userEvent.clear(field)
    await userEvent.type(field, '9.9_p1-r0')
    await userEvent.click(within(saved).getByRole('button', { name: 'Save and check' }))
    const again = await screen.findByRole('listitem', { name: 'Saved OpenSSH 9.9_p1-r0 on BN340.' }, T)
    // the old closure was proved on another release: it is not the answer for this one
    expect(await within(again).findByText('Checking which CVEs this closes…', undefined, T)).toBeInTheDocument()
    expect(within(again).queryByText(/Closed 1 CVE/)).toBeNull()
  }, 30000)

  it('a closure by another rule (no version compared) is not counted as closed by the entry', async () => {
    box([F({})], () => [closedOn(null, { last_seen: '2026-11-18T02:00:00.000Z' })])
    await enterRelease('10.2_p1-r1')
    const saved = await result()
    await within(saved).findByText(/found no exploited CVE left/, undefined, SLOW)
    expect(within(saved).queryByText(/Closed 1 CVE/)).toBeNull()
  }, 30000)

  it('a CVE closed on another row of the same product is not shown on this row', async () => {
    box([F({})], () => [closedOn('10.2_p1-r1', { software_id: 's-other-row', last_seen: '2026-11-18T02:00:00.000Z' }), F({ id: 'f-2', cve: 'CVE-2026-000002', last_seen: '2026-11-18T02:00:00.000Z' })])
    await enterRelease('10.2_p1-r1')
    const saved = await result()
    await within(saved).findByText(/1 CVE is still affected:/, undefined, SLOW)
    expect(within(saved).queryByText(/Closed/)).toBeNull()
    expect(within(saved).getByRole('link', { name: 'CVE-2026-000002' })).toBeInTheDocument()
  }, 30000)

  it('when the findings cannot be read it says nothing about the result', async () => {
    box([F({})], () => null)
    await enterRelease('10.2_p1-r1')
    const saved = await result()
    await new Promise((r) => setTimeout(r, 1500))
    expect(saved).toHaveTextContent('Saved OpenSSH 10.2_p1-r1 on BN340.')
    for (const t of [/Closed/, /still affected/, /found no exploited CVE/]) expect(saved).not.toHaveTextContent(t)
  }, 30000)

  it('findings no match has reached yet (no software row) are not turned into "no CVE left"', async () => {
    box([F({})], () => [F({ software_id: '', last_seen: '2026-11-18T02:00:00.000Z' })])
    await enterRelease('10.2_p1-r1')
    const saved = await result()
    await new Promise((r) => setTimeout(r, 1500))
    expect(saved).not.toHaveTextContent(/found no exploited CVE/)
    expect(saved).not.toHaveTextContent(/Closed/)
  }, 30000)

  it('after about 15 seconds without a new match it says the device is not matched again yet, never a result it does not have', async () => {
    box([F({})], () => [F({})])
    await enterRelease('10.2_p1-r1')
    const saved = await result()
    expect(await within(saved).findByText('Not matched again yet; this page updates when it is.', undefined, { timeout: 25000 })).toBeInTheDocument()
    expect(saved).not.toHaveTextContent(/still affected|found no exploited CVE|Closed/)
  }, 40000)

  it('keeps reading after that: the answer appears when the match lands', async () => {
    let landed = false
    box([F({})], () => (landed ? [closedOn('10.2_p1-r1', { last_seen: '2026-11-18T02:00:00.000Z' })] : [F({})]))
    await enterRelease('10.2_p1-r1')
    const saved = await result()
    await within(saved).findByText('Not matched again yet; this page updates when it is.', undefined, { timeout: 25000 })
    landed = true
    expect(await within(saved).findByText(/Closed 1 CVE as not affected:/, undefined, SLOW)).toBeInTheDocument()
  }, 60000)

  it('a change on another software of the device alone does not end the wait', async () => {
    const other = F({ id: 'f-nginx', cve: 'CVE-2026-000009', software_id: 's-bn340-nginx' })
    box([F({}), other], () => [F({}), { ...other, status: 'not_relevant' }])
    await enterRelease('10.2_p1-r1')
    const saved = await result()
    await new Promise((r) => setTimeout(r, 4000))
    expect(saved).toHaveTextContent('Checking which CVEs this closes…')
    expect(saved).not.toHaveTextContent(/found no exploited CVE/)
  }, 30000)

  it('a CVE still open on the row that describes the software now (the agent\'s) is still affected, never "no CVE left"', async () => {
    server.use(http.get('*/api/v1/inventory/devices/:id/software', () => HttpResponse.json({ items: [{ id: 's-bn340-agent', vendor: 'OpenBSD', product: 'OpenSSH', display: 'OpenSSH',
      version: '10.2p1', pkg_version: '10.2_p1-r1', packaged: true, cpe: '', source: 'agent', set_by: '', seen_at: '2026-11-18T02:00:00.000Z', differs: false,
      also_seen: [{ id: 's-bn340-ssh', source: 'nmap', version: '10.2', pkg_version: '', seen_at: '2026-11-18T01:00:00.000Z', same_release: true }] }] })))
    box([F({})], () => [F({ software_id: 's-bn340-agent', last_seen: '2026-11-18T02:00:00.000Z' })])
    await enterRelease('10.2_p1-r1')
    const saved = await result()
    expect(await within(saved).findByText(/1 CVE is still affected:/, undefined, SLOW)).toBeInTheDocument()
    expect(saved).not.toHaveTextContent(/found no exploited CVE/)
    expect(within(saved).getByRole('link', { name: 'CVE-2026-123158' })).toBeInTheDocument()
  }, 30000)
})
