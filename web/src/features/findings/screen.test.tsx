// The Findings screen: By device, By fix, Needs your input, Handled and Ignored devices on the findings model's API (the mock).
import { afterEach, describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expectNoA11yViolations, mainNavLink, renderApp } from '@/test/render'
import { server } from '@/test/server'
import { auditStore } from '@/mocks/stores'
import { records } from './modelMocks'

const T = { timeout: 5000 }
const posts: { url: string; body: unknown }[] = []
server.events.on('request:start', ({ request }) => {
  if (request.method === 'POST') void request.clone().json().then((body: unknown) => posts.push({ url: new URL(request.url).pathname, body }), () => undefined)
})
afterEach(() => { posts.length = 0 })

const num = (s: string | null | undefined, re: RegExp) => Number(re.exec(s ?? '')?.[1] ?? Number.NaN)
const title = async () => num((await screen.findByRole('heading', { level: 1, name: /open finding/ }, T)).textContent, /^(\d+) open finding/)
const summary = async (tab: 'device' | 'fix') => {
  const el = await waitFor(() => { const e = document.querySelector(`[data-count="${tab}"]`); if (!e) throw new Error('no summary'); return e }, T)
  return num(el.textContent, /^(\d+) open finding/)
}
const devicesTable = () => screen.findByRole('table', { name: 'Devices with open findings' }, T)
const fixesTable = () => screen.findByRole('table', { name: 'Fixes for open findings' }, T)
const card = async (name: string) => within(await devicesTable()).findByRole('article', { name }, T)
/** Every card of a list: the findings it counts ("5 findings, 4 CVEs" on a device; "3 devices, 61 findings" on a fix). */
const sumOf = (table: HTMLElement, re: RegExp) => within(table).getAllByRole('article').reduce((n, a) => n + num(a.textContent, re), 0)
const openTab = async (name: RegExp) => userEvent.click(await screen.findByRole('tab', { name }, T))

describe('Findings: one screen, open = Σ by device = Σ by fix', () => {
  it('the title, By device and By fix count the same open findings, with and without a status filter', async () => {
    renderApp('/findings')
    const open = await title()
    expect(open).toBeGreaterThan(5)
    expect(await summary('device')).toBe(open)
    expect(sumOf(await devicesTable(), /(\d+) findings?, \d+ CVE/)).toBe(open)
    await openTab(/^By fix/)
    expect(await summary('fix')).toBe(open)
    expect(sumOf(await fixesTable(), /\d+ devices, (\d+) findings?/)).toBe(open)
    console.info(`open findings: title ${open}, by device ${open}, by fix ${open}`)

    // one status: both lists still agree, and match the toggle's own count
    const toggle = within(screen.getByRole('group', { name: 'Show findings with these statuses' })).getByRole('button', { name: /^Exploited in the wild/ })
    const exploited = num(toggle.textContent, /(\d+)$/)
    await userEvent.click(toggle)
    expect(toggle).toHaveAttribute('aria-pressed', 'true')
    await waitFor(async () => expect(await summary('fix')).toBe(exploited), T)
    expect(sumOf(await fixesTable(), /\d+ devices, (\d+) findings?/)).toBe(exploited)
    await openTab(/^By device/)
    await waitFor(async () => expect(await summary('device')).toBe(exploited), T)
    expect(sumOf(await devicesTable(), /(\d+) findings?, \d+ CVE/)).toBe(exploited)
  })

  it('By device lists every device with an open finding, a CVE with no known fix included; CVEs show severity and status; no a11y violation', async () => {
    renderApp('/findings')
    const table = await devicesTable()
    const fw = await card('FW-HQ')
    expect(within(fw).getByRole('listitem', { name: 'Update OpenSSH 10.2p1 → 10.6' })).toHaveTextContent(/fixes 3 CVEs/)
    const cves = within(fw).getByRole('list', { name: 'CVEs fixed by: Update OpenSSH 10.2p1 → 10.6' })
    expect(within(cves).getByRole('link', { name: 'CVE-2026-123159' })).toHaveAttribute('href', '/findings/fv-fw01-ssh-1')
    expect(within(cves).getAllByText(/^(High|Medium|Low)/).length).toBeGreaterThan(0)
    // a finding with no fix yet: its device is listed, with the advisory
    const block = within(table).getByRole('listitem', { name: 'No fix known yet for Brother printer firmware' })
    expect(within(block).getByRole('link', { name: 'Vendor advisory' })).toHaveAttribute('href', 'https://support.brother.example.com/security')
    // the device badge leads to that device's findings with that status
    expect(within(fw).getByRole('link', { name: /exploited$/ })).toHaveAttribute('href', '/devices/a-fw01?tab=findings&status=exploited')
    await expectNoA11yViolations()
  })
})

describe('Findings: Mark as handled acts on one device', () => {
  it('accepting a CVE on one of two devices leaves the other open', async () => {
    renderApp('/findings')
    const fw = await card('FW-HQ')
    await userEvent.click(within(fw).getByRole('button', { name: 'Mark as handled: CVE-2026-123159 on FW-HQ' }))
    const dlg = await screen.findByRole('dialog', { name: 'Mark as handled' })
    expect(dlg).toHaveTextContent('Acts on 1 finding (1 CVE) on one device: FW-HQ.')
    await userEvent.click(within(dlg).getByRole('radio', { name: /Accept the risk until/ }))
    await userEvent.click(within(dlg).getByRole('button', { name: '30 days' }))
    // a note is required to accept a risk
    await userEvent.click(within(dlg).getByRole('button', { name: 'Mark 1 finding' }))
    expect(await within(dlg).findByText('Say why (at least 3 characters), so the next person understands.')).toBeInTheDocument()
    await userEvent.type(within(dlg).getByLabelText('Note: why (required)'), 'Behind the VPN until the update window')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Mark 1 finding' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull(), T)
    expect(posts.find((p) => p.url.endsWith('/findings/handle'))?.body).toMatchObject({ ids: ['fv-fw01-ssh-1'], resolution: 'accepted' })
    const all = records.get()
    expect(all.find((r) => r.id === 'fv-fw01-ssh-1')).toMatchObject({ state: 'handled', resolution: 'accepted' })
    expect(all.find((r) => r.id === 'fv-bn340-ssh-2')).toMatchObject({ cve: 'CVE-2026-123159', state: 'open' })
    await waitFor(async () => expect(within(await card('FW-HQ')).queryByRole('link', { name: 'CVE-2026-123159' })).toBeNull(), T)
    expect(within(await card('BN340')).getByRole('link', { name: 'CVE-2026-123159' })).toBeInTheDocument()
  })

  it('By fix: one device of a fix, every CVE ticked, one request by (device, fix), one audit row per finding', async () => {
    renderApp('/findings?tab=fix')
    const table = await fixesTable()
    const ssh = within(table).getByRole('article', { name: 'Update OpenSSH to 10.6' })
    await userEvent.click(within(ssh).getByRole('button', { name: /^Update OpenSSH to 10\.6/ }))
    await userEvent.click(within(ssh).getByRole('button', { name: 'Mark as handled: Update OpenSSH to 10.6 on FW-HQ' }))
    const dlg = await screen.findByRole('dialog', { name: 'Mark as handled' }, T)
    const boxes = within(dlg).getAllByRole('checkbox')
    expect(boxes).toHaveLength(3)
    for (const b of boxes) expect(b).toBeChecked()
    expect(dlg).toHaveTextContent('Acts on 3 findings (3 CVEs) on one device: FW-HQ.')
    const before = auditStore.get().filter((a) => a.action === 'findings.handle').length
    await userEvent.click(within(dlg).getByRole('button', { name: 'Mark 3 findings' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull(), T)
    expect(posts.find((p) => p.url.endsWith('/findings/handle'))?.body).toMatchObject({ device: 'a-fw01', fix: 'openbsd:openssh|update|10.6', resolution: 'patched' })
    expect(auditStore.get().filter((a) => a.action === 'findings.handle').length - before).toBe(3)
    expect(records.get().filter((r) => r.asset_id === 'a-bn340' && r.fix.product === 'OpenSSH').every((r) => r.state === 'open')).toBe(true)
  })

  it('unticking a CVE sends the ids of the rest', async () => {
    renderApp('/findings')
    const fw = await card('FW-HQ')
    await userEvent.click(within(fw).getByRole('button', { name: 'Mark these as handled: Update OpenSSH 10.2p1 → 10.6 on FW-HQ' }))
    const dlg = await screen.findByRole('dialog', { name: 'Mark as handled' })
    await userEvent.click(within(dlg).getByRole('checkbox', { name: 'CVE-2026-123160' }))
    await userEvent.click(within(dlg).getByRole('radio', { name: /Mitigated/ }))
    await userEvent.click(within(dlg).getByRole('button', { name: 'Mark 2 findings' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull(), T)
    const body = posts.find((p) => p.url.endsWith('/findings/handle'))?.body as { ids: string[] }
    expect(body.ids.sort()).toEqual(['fv-fw01-ssh-1', 'fv-fw01-ssh-2'])
  })

  it('a viewer reads every list; the actions say the role they need', async () => {
    renderApp('/findings', { role: 'viewer' })
    const fw = await card('FW-HQ')
    expect(within(fw).getByRole('button', { name: 'Mark as handled: CVE-2026-123159 on FW-HQ' })).toBeDisabled()
  })
})

describe('Findings: Needs your input', () => {
  it('a device not added yet is in the queue with Add device, and leaves it once added', async () => {
    renderApp('/findings?tab=input')
    const table = await screen.findByRole('table', { name: 'What needs your input' }, T)
    const add = await within(table).findByRole('button', { name: /^Add device / }, T)
    const name = add.getAttribute('aria-label')!.replace('Add device ', '')
    await userEvent.click(add)
    await waitFor(() => expect(within(table).queryByRole('button', { name: `Add device ${name}` })).toBeNull(), T)
  })

  it('an urgent finding not confirmed yet: Run the safe check first when one exists, Confirm vulnerability, Not affected…', async () => {
    renderApp('/findings?tab=input')
    const table = await screen.findByRole('table', { name: 'What needs your input' }, T)
    expect(await within(table).findByRole('button', { name: 'Run the safe check for CVE-2024-4577 on WEB01' }, T)).toBeInTheDocument()
    expect(within(table).queryByRole('button', { name: /^Run the safe check for CVE-2026-123890/ })).toBeNull()
    await userEvent.click(within(table).getByRole('button', { name: 'Confirm vulnerability: CVE-2026-123890 on BN340' }))
    const dlg = await screen.findByRole('dialog', { name: 'Confirm CVE-2026-123890 on BN340' })
    await userEvent.type(within(dlg).getByLabelText('What makes you sure? (required)'), 'The banner and the package list agree')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Confirm vulnerability' }))
    await waitFor(() => expect(records.get().find((r) => r.id === 'fv-bn340-ssh-1')?.verified).toBe('person'), T)
    // update-recommended findings never ask
    expect(within(table).queryByRole('button', { name: /^Confirm vulnerability: CVE-2026-123159/ })).toBeNull()
  })

  it('an operator may say Not affected but not confirm', async () => {
    renderApp('/findings?tab=input', { role: 'operator' })
    const table = await screen.findByRole('table', { name: 'What needs your input' }, T)
    expect(await within(table).findByRole('button', { name: 'Confirm vulnerability: CVE-2026-123890 on BN340' }, T)).toBeDisabled()
    await userEvent.click(within(table).getByRole('button', { name: 'Not affected: CVE-2026-123890 on BN340' }))
    const dlg = await screen.findByRole('dialog', { name: 'CVE-2026-123890 does not affect BN340' })
    expect(within(dlg).getAllByRole('radio').map((r) => r.getAttribute('value'))).toEqual(['not_relevant', 'false_positive'])
  })
})

describe('Findings: Handled, Ignored devices and the old links', () => {
  it('Handled says who and how; accepted risks are a filter', async () => {
    renderApp('/findings?tab=handled')
    const table = await screen.findByRole('table', { name: 'Handled findings' }, T)
    expect(await within(table).findByText('Patched by Vedette: version moved 22631.4602 → 22631.4751 (' , { exact: false }, T)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Risk accepted' }))
    await waitFor(() => expect(within(table).getAllByRole('row')).toHaveLength(2), T)
    expect(within(table).getByText(/^Risk accepted until /, { selector: '[data-status]' })).toBeInTheDocument()
  })

  it('no Plan menu; /plan opens the update-recommended findings by device', async () => {
    renderApp('/plan')
    expect(await screen.findByRole('tab', { name: 'By device', selected: true }, T)).toBeInTheDocument()
    const toggle = within(screen.getByRole('group', { name: 'Show findings with these statuses' })).getByRole('button', { name: /^Update recommended/ })
    expect(toggle).toHaveAttribute('aria-pressed', 'true')
    await mainNavLink(/^Findings/)
    expect(screen.queryByRole('link', { name: /Recommended updates/, hidden: true })).toBeNull()
  })

  it('a link of the earlier tabs opens its place here: To fix of one device is By device, filtered', async () => {
    renderApp('/findings?tab=fix&device=a-fw01')
    expect(await screen.findByRole('tab', { name: 'By device', selected: true }, T)).toBeInTheDocument()
    expect(await screen.findByRole('button', { name: 'Only FW-HQ: show every device' }, T)).toBeInTheDocument()
    expect(within(await devicesTable()).getAllByRole('article')).toHaveLength(1)
  })
})
