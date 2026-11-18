import { afterEach, describe, expect, it } from 'vitest'
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
