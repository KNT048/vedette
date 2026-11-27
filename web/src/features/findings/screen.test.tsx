// The Findings screen: By device, By fix, Needs your input, Handled and Ignored devices on the findings model's API (the mock).
import { afterEach, describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { expectNoA11yViolations, mainNavLink, renderApp } from '@/test/render'
import { server } from '@/test/server'
import { auditStore } from '@/mocks/stores'
import { metaStore } from '@/features/inventory/mocks'
import { records } from './modelMocks'
import { openNeeds } from './needsTestUtil'

const T = { timeout: 5000 }
const posts: { url: string; body: unknown }[] = []
server.events.on('request:start', ({ request }) => {
  if (request.method === 'POST') void request.clone().json().then((body: unknown) => posts.push({ url: new URL(request.url).pathname, body }), () => undefined)
})
afterEach(() => { posts.length = 0 })

const num = (s: string | null | undefined, re: RegExp) => Number(re.exec(s ?? '')?.[1] ?? Number.NaN)
const title = async () => num((await waitFor(() => within(screen.getByRole('heading', { level: 1, name: 'Findings' }).closest('header')!).getByText(/^\d+ open finding/), T)).textContent, /^(\d+) open finding/)
const summary = async (tab: 'device' | 'fix') => {
  const el = await waitFor(() => { const e = document.querySelector(`[data-count="by-${tab}"]`); if (!e) throw new Error('no summary'); return e }, T)
  return num(el.textContent, /(\d+) open finding/)
}
const devicesTable = () => screen.findByRole('table', { name: 'Devices with open findings' }, T)
const fixesTable = () => screen.findByRole('table', { name: 'Fixes for open findings' }, T)
/** Findings are collapsed until clicked: opens every closed toggle inside `root`. */
async function expandAll(root: HTMLElement = document.body) {
  for (const b of within(root).queryAllByRole('button').filter((x) => x.getAttribute('aria-expanded') === 'false')) await userEvent.click(b)
}
const card = async (name: string) => { const c = await within(await devicesTable()).findByRole('article', { name }, T); await expandAll(c); return c }
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
    expect(sumOf(await fixesTable(), /\d+ devices?, (\d+) findings?/)).toBe(open)
    console.info(`open findings: title ${open}, by device ${open}, by fix ${open}`)

    // one status: both lists still agree, and match the toggle's own count
    const toggle = within(screen.getByRole('group', { name: 'Show findings with these statuses' })).getByRole('button', { name: /^Exploited in the wild/ })
    const exploited = num(toggle.textContent, /(\d+)$/)
    await userEvent.click(toggle)
    expect(toggle).toHaveAttribute('aria-pressed', 'true')
    await waitFor(async () => expect(await summary('fix')).toBe(exploited), T)
    expect(sumOf(await fixesTable(), /\d+ devices?, (\d+) findings?/)).toBe(exploited)
    await openTab(/^By device/)
    await waitFor(async () => expect(await summary('device')).toBe(exploited), T)
    expect(sumOf(await devicesTable(), /(\d+) findings?, \d+ CVE/)).toBe(exploited)
  })

  it('By device lists every device with an open finding, a CVE with no known fix included; CVEs show severity and status; no a11y violation', async () => {
    renderApp('/findings')
    const table = await devicesTable()
    const fw = await card('FW-HQ')
    await expandAll(table)
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

describe('By fix is the plan: numbered steps, from → to, one machine counted once', () => {
  it('numbers the fixes in the list order, names the version the devices run now, and says when two devices may be one machine', async () => {
    const ref = (id: string, name: string) => ({ id, name, approved: true, last_seen: '2026-11-24T08:00:00Z', never_seen: false })
    server.use(http.get('*/api/v1/inventory/possible-same', () => HttpResponse.json({ items: [{ a: ref('a-fw01', 'FW-HQ'), b: ref('a-bn340', 'BN340'), why: 'Same name', reason: 'rotating_name' }] })))
    renderApp('/findings?tab=fix')
    const table = await fixesTable()
    const steps = within(table).getAllByRole('article')
    expect(steps.length).toBeGreaterThan(2)
    steps.forEach((a, i) => expect(a).toHaveAccessibleName(new RegExp(`^Step ${i + 1}: `)))
    expect(screen.getByText('Do them in this order: the most urgent first, then the fix that clears the most findings.')).toBeInTheDocument()
    const ssh = within(table).getByRole('article', { name: /: Update OpenSSH .*10\.6$/ })
    // FW-HQ and BN340 run different OpenSSH releases: the step names the target and the versions they run now
    if (!/→/.test(ssh.getAttribute('aria-label') ?? '')) expect(ssh).toHaveTextContent(/Now on .+/)
    expect(await within(ssh).findByText('(possibly 1 machine)', {}, T)).toBeInTheDocument()
    await userEvent.click(within(ssh).getByRole('button', { name: /^Update OpenSSH/ }))
    expect(within(ssh).getByRole('link', { name: 'Possibly the same device as BN340' })).toHaveAttribute('href', '/devices/a-fw01#possible-same')
    // a fix every device of which runs one version says from → to
    const one = steps.find((a) => (a.getAttribute('aria-label') ?? '').includes('→'))
    expect(one).toBeDefined()
  })
})

describe('By fix: a line in several steps says so', () => {
  it('a device whose line no single release fixes names its other steps on each step', async () => {
    const sev = { critical: 0, high: 1, medium: 0, low: 0, none: 0, unscored: 0 }
    const device = { id: 'a-sw1', name: 'core-switch', ip: '192.0.2.10', kind: 'switch', added: true, ignored: false }
    const software = { id: 's-junos', name: 'Juniper Junos OS', version: '15.1R7.9' }
    const fix = (version: string) => ({ key: `juniper|junos os|update|${version}`, kind: 'update', product: 'Juniper Junos OS', version, ref: null, url: null })
    const step = (version: string, other: string, cve: string, findings: number) => ({ fix: fix(version), status: 'critical_edge', cause: cve, devices: 1, findings,
      severity: { ...sev, high: findings }, items: [{ device, software, status: 'critical_edge', severity: { ...sev, high: findings }, findings, others: [fix(other)] }] })
    server.use(http.get('*/api/v1/findings/fixes', () => HttpResponse.json({ items: [step('23.2R2-S7.7', '19.1R3-S9', 'CVE-2026-94002', 3), step('19.1R3-S9', '23.2R2-S7.7', 'CVE-2026-94001', 1)], total: 2, findings: 4 })))
    renderApp('/findings?tab=fix')
    const table = await fixesTable()
    const first = within(table).getByRole('article', { name: /^Step 1: Update Juniper Junos OS 15\.1R7\.9 → 23\.2R2-S7\.7$/ })
    await userEvent.click(within(first).getByRole('button', { name: /^Update Juniper Junos OS/ }))
    expect(within(first).getByText('Juniper Junos OS on this device is also in another step (19.1R3-S9): no single release is known to fix all of its findings.')).toBeInTheDocument()
  })
})

describe('Findings: counts read as English', () => {
  it('one device, one fix and one finding are singular in the summaries and on a fix', async () => {
    renderApp('/findings?tab=device&by-device.q=CVE-2022-27593')
    await waitFor(() => expect(document.querySelector('[data-count="by-device"]')).toHaveTextContent(/^1 device, 1 open finding$/), T)
    renderApp('/findings?tab=fix&by-fix.q=CVE-2022-27593')
    await waitFor(() => expect(document.querySelector('[data-count="by-fix"]')).toHaveTextContent(/^1 fix, 1 open finding$/), T)
    expect(within(await fixesTable()).getByRole('article', { name: /Update Photo Station/ })).toHaveTextContent(/1 device, 1 finding/)
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
    const ssh = within(table).getByRole('article', { name: /^Step \d+: Update OpenSSH (to |.* → )10\.6$/ })
    await userEvent.click(within(ssh).getByRole('button', { name: /^Update OpenSSH (to |.* → )10\.6/ }))
    await userEvent.click(within(ssh).getByRole('button', { name: /^Mark as handled: Update OpenSSH (to |.* → )10\.6 on FW-HQ$/ }))
    const dlg = await screen.findByRole('dialog', { name: 'Mark as handled' }, T)
    const boxes = within(dlg).getAllByRole('checkbox')
    expect(boxes).toHaveLength(3)
    for (const b of boxes) expect(b).toBeChecked()
    expect(dlg).toHaveTextContent('Acts on 3 findings (3 CVEs) on one device: FW-HQ.')
    const before = auditStore.get().filter((a) => a.action === 'findings.handle').length
    // nothing is chosen for the person: these CVEs may have no fix, "Patched" is their word, not a default
    for (const r of within(dlg).getAllByRole('radio')) expect(r).not.toBeChecked()
    await userEvent.click(within(dlg).getByRole('button', { name: 'Mark 3 findings' }))
    expect(within(dlg).getByRole('alert')).toHaveTextContent('Choose how it was handled.')
    await userEvent.click(within(dlg).getByRole('radio', { name: /^Patched/ }))
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

  it('the devices not added yet with no open finding are one card, last, whose Review opens the Devices list To review', async () => {
    renderApp('/findings?tab=input')
    const table = await screen.findByRole('table', { name: 'What needs your input' }, T)
    const words = await within(table).findByText(/^\d+ devices? not added yet with no open finding\.$/, {}, T)
    const rows = within(table).getAllByRole('row')
    expect(rows[rows.length - 1]).toContainElement(words)
    expect(within(table).getByRole('link', { name: 'Review' })).toHaveAttribute('href', '/devices?tab=review')
  })

  it('an urgent finding not confirmed yet: Run the safe check first when one exists, Confirm vulnerability, Not affected…', async () => {
    renderApp('/findings?tab=input')
    const table = await screen.findByRole('table', { name: 'What needs your input' }, T)
    await openNeeds(table)
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

  it('searches on the server and keeps the search in the address: only the matching items, the pager counts them', async () => {
    // a shared link with a search opens with it
    renderApp('/findings?tab=input&input.q=CVE-2026-123890')
    const table = await screen.findByRole('table', { name: 'What needs your input' }, T)
    const box = screen.getByRole('searchbox', { name: 'Search devices, software or CVEs' })
    expect(box).toHaveValue('CVE-2026-123890')
    await openNeeds(table)
    expect(await within(table).findByRole('button', { name: 'Confirm vulnerability: CVE-2026-123890 on BN340' }, T)).toBeInTheDocument()
    expect(within(table).queryByRole('button', { name: 'Run the safe check for CVE-2024-4577 on WEB01' })).toBeNull()
    // typing searches the whole queue on the server, not the page in view
    await userEvent.clear(box)
    await userEvent.type(box, 'web01')
    await waitFor(() => expect(within(table).queryByRole('article', { name: 'What BN340 needs' })).toBeNull(), T)
    await openNeeds(table)
    expect(await within(table).findByRole('button', { name: 'Run the safe check for CVE-2024-4577 on WEB01' }, T)).toBeInTheDocument()
    await waitFor(() => expect(within(table).queryByRole('button', { name: 'Confirm vulnerability: CVE-2026-123890 on BN340' })).toBeNull(), T)
  })

  it('an operator may say Not affected but not confirm', async () => {
    renderApp('/findings?tab=input', { role: 'operator' })
    const table = await screen.findByRole('table', { name: 'What needs your input' }, T)
    await openNeeds(table)
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
    expect(await within(table).findByText('By Vedette: version moved 22631.4602 → 22631.4751 (' , { exact: false }, T)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Risk accepted' }))
    await waitFor(() => expect(within(table).getAllByRole('row')).toHaveLength(2), T)
    expect(within(table).getByText(/^Risk accepted until /, { selector: '[data-status]' })).toBeInTheDocument()
  })

  it('Handled leaves out what Vedette closed by correcting its own match, says how many, and shows them on one click', async () => {
    const at = new Date().toISOString()
    const seeded = records.get().filter((r) => r.state === 'handled' && r.via === 'data_corrected' && r.resolved_by === 'system').length
    const n = seeded + 3
    const open = records.get().filter((r) => r.state === 'open').slice(0, 3).map((r) => r.id)
    records.update((all) => all.map((r) => open.includes(r.id) ? { ...r, state: 'handled' as const, resolution: 'not_relevant' as const, via: 'data_corrected' as const, resolved_by: 'system', resolved_at: at } : r))
    renderApp('/findings?tab=handled')
    const table = await screen.findByRole('table', { name: 'Handled findings' }, T)
    const line = await waitFor(() => { const e = document.querySelector('[data-count="corrections"]'); if (!e) throw new Error('no line'); return e }, T)
    expect(line).toHaveTextContent(`${n} findings Vedette closed because it corrected its own match are not listed: they were never a flaw on the device.`)
    const before = within(table).getAllByRole('row').length
    await userEvent.click(screen.getByRole('button', { name: 'Show them' }))
    await waitFor(() => expect(document.querySelector('[data-count="corrections"]')).toHaveTextContent(new RegExp(`^Listed with ${n} findings Vedette closed`)), T)
    await waitFor(() => expect(within(table).getAllByRole('row').length).toBe(before + n), T)
    expect(posts).toHaveLength(0)
  })

  it('Ignored devices: the explanation sits behind the info icon, and the list searches on the server', async () => {
    metaStore.update((m) => ({ ...m, 'a-fw01': { ...m['a-fw01'], ignored_at: new Date().toISOString() }, 'a-bn340': { ...m['a-bn340'], ignored_at: new Date().toISOString() } }))
    renderApp('/findings?tab=ignored')
    const table = await screen.findByRole('table', { name: 'Ignored devices with findings' }, T)
    expect(screen.getByText(/They are hidden from the other lists/)).not.toBeVisible() // only the info icon's description
    expect(screen.getByRole('button', { name: 'About Ignored devices' })).toHaveAccessibleDescription(/They are hidden from the other lists/)
    expect(await within(table).findByRole('article', { name: 'FW-HQ' }, T)).toBeInTheDocument()
    expect(within(table).getByRole('article', { name: 'BN340' })).toBeInTheDocument()
    await userEvent.type(screen.getByRole('searchbox', { name: 'Search ignored devices, software or CVEs' }), 'BN340')
    await waitFor(() => expect(within(table).queryByRole('article', { name: 'FW-HQ' })).toBeNull(), T)
    expect(within(table).getByRole('article', { name: 'BN340' })).toBeInTheDocument()
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
