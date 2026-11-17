import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { server } from '@/test/server'
import { assetsStore } from '@/mocks/stores'
import type { Asset } from '@/lib/types'
import type { FindingAsset, ToFix, ToFixAction, ToFixDevice, UncheckedItem, VersionNeeded } from './types'

// kien G15 (J3, S-MIT-1): Needs your input, one block per device, the worst first; every item says what to do and offers it there.
const T = { timeout: 5000 }
const asset = (id: string, name: string): FindingAsset => ({ id, name, hostname: name, ip: '192.168.18.20', kind: 'server', display: name })
const act = (o: Partial<ToFixAction>): ToFixAction => ({ group: 'g', software_id: '', software: '', version: '', product: '', source: '', fixed: '', kind: 'none', windows: false, distro: '', pro: false, action: '',
  cves: [], finding_ids: [], worst: 'medium', ransomware: 0, likely: 0, confirmed: 0, detected: 0, reported: 1, suspected: 0, ...o })
const dev = (a: FindingAsset, o: Partial<ToFixDevice>): ToFixDevice => ({ asset: a, risk: null, open: 0, exploited: [], no_update: [], planned: [], plan_compared: true, ...o })
const need = (a: FindingAsset, sw: string, o: Partial<VersionNeeded> = {}): VersionNeeded => ({ asset: a, asset_id: a.id, software_id: `s-${a.id}`, software: sw, version: null, cves: 3, ...o })
const unc = (a: FindingAsset, sw: string, cves: string[], o: Partial<UncheckedItem> = {}): UncheckedItem => ({ asset: a, asset_id: a.id, software_id: `u-${a.id}`, software: sw, version: null, reason: 'no_nvd_data', action: 'none',
  cves: cves.map((cve) => ({ cve, name: `${cve} flaw`, date_added: '2026-11-01', ransomware: false, advisory: null })), ...o })
const serve = (list: { version_needed?: VersionNeeded[]; unchecked?: UncheckedItem[] }, tf?: ToFix) => {
  server.use(http.get('*/api/v1/findings', () => HttpResponse.json({ items: [], version_needed: list.version_needed ?? [], unchecked: list.unchecked ?? [] })))
  if (tf) server.use(http.get('*/api/v1/findings/to-fix', () => HttpResponse.json(tf)))
}
const blocks = () => screen.findByRole('list', { name: 'Devices that need your input, the most urgent first' }, T)
const names = async () => { const l = await blocks(); return within(l).getAllByRole('listitem').filter((li) => li.parentElement === l).map((li) => li.getAttribute('aria-label')) }
const toggle = async (device: string) => within(await blocks()).findByRole('button', { name: new RegExp(`^${device.replace(/[()]/g, '\\$&')}`) }, T)
const expand = async (device: string) => { await userEvent.click(await toggle(device)); return screen.findByRole('listitem', { name: device }, T) }

describe('Findings › Needs your input by device (kien G15)', () => {
  it('one block per device, To fix\'s order first, then what is to settle, then what could not be checked; collapsed by default', async () => {
    const pc = asset('a-pc', 'PC-A'), desk = asset('a-desk', 'DESK-B'), zz = asset('a-zz', 'ZZ-SERVER'), yy = asset('a-yy', 'AA-PRINTER')
    serve({ version_needed: [need(zz, 'Microsoft Office'), need(pc, 'Microsoft SQL Server')], unchecked: [unc(yy, 'Printer firmware', ['CVE-2026-1']), unc(desk, 'Windows 11 Pro', ['CVE-2026-2', 'CVE-2026-3'])] },
      { truncated: false, plan_ran: true, plan_off: false, risks: { 'a-pc': { level: 'exploited', exploited: 2, updates: 0 } }, devices: [
        dev(pc, { open: 2, exploited: [act({ kind: 'fixed', detected: 2, cves: ['CVE-2026-9', 'CVE-2026-8'], finding_ids: ['f-9', 'f-8'], worst: 'critical' })] }),
        dev(desk, { open: 1, no_update: [act({ group: 'a-desk/s-w', software_id: 's-w', software: 'Windows 11 Pro', cves: ['CVE-2026-5'], finding_ids: ['f-5'] })] }),
      ] })
    renderApp('/findings?tab=input')
    // AA-PRINTER sorts first by name, but it has only CVEs that could not be checked: ZZ-SERVER, with a version to type, comes before it
    await waitFor(async () => expect(await names()).toEqual(['PC-A', 'DESK-B', 'ZZ-SERVER', 'AA-PRINTER']), T)
    expect(await toggle('PC-A')).toHaveAccessibleName('PC-A, 1 to settle')
    expect(await toggle('DESK-B')).toHaveAccessibleName('DESK-B, 1 to settle, 2 CVEs could not be checked')
    expect(await toggle('AA-PRINTER')).toHaveAccessibleName('AA-PRINTER, 1 CVE could not be checked')
    for (const n of ['PC-A', 'DESK-B', 'ZZ-SERVER', 'AA-PRINTER']) expect(await toggle(n)).toHaveAttribute('aria-expanded', 'false')
    expect(within(screen.getByRole('listitem', { name: 'PC-A' })).getByRole('link', { name: /2 exploited/ })).toHaveAttribute('href', '/findings?tab=fix&device=a-pc')
    expect(screen.queryByRole('list', { name: /What only you can settle/ })).toBeNull()
    const block = await expand('DESK-B')
    expect(await toggle('DESK-B')).toHaveAttribute('aria-expanded', 'true')
    expect(within(block).getByRole('list', { name: 'What only you can settle on DESK-B' })).toHaveTextContent(/Windows 11 Pro, 1 exploited CVE to check/)
    expect(within(block).getByRole('list', { name: 'What Vedette could not check on DESK-B' })).toHaveTextContent(/CVE-2026-2/)
    await userEvent.click(await toggle('DESK-B'))
    expect(screen.queryByRole('list', { name: 'What only you can settle on DESK-B' })).toBeNull()
    await expectNoA11yViolations()
  })

  it('?device= (a link from To fix or the Software tab) opens that device\'s block', async () => {
    renderApp('/findings?tab=input&device=a-srvfile')
    expect(await toggle('SRV-FILE')).toHaveAttribute('aria-expanded', 'true')
    expect(await screen.findByRole('list', { name: 'What only you can settle on SRV-FILE' }, T)).toHaveTextContent(/Microsoft SQL Server has no version: adding it checks 6 exploited CVEs\./)
  })

  it('software a person added: the version is typed in place, Vedette checks it at once and the item leaves (the N100\'s SQL Server)', async () => {
    renderApp('/findings?tab=input')
    const block = await expand('SRV-FILE')
    expect(await within(block).findByText(/You added it by hand: type the version it runs/, undefined, T)).toBeInTheDocument()
    const save = within(block).getByRole('button', { name: 'Save and check' })
    await userEvent.click(save)
    expect(within(block).getByRole('alert')).toHaveTextContent('Type the version it runs now, for example 7.4.5.')
    await userEvent.type(within(block).getByLabelText('Version of Microsoft SQL Server'), 'latest!')
    await userEvent.click(save)
    expect(within(block).getByRole('alert')).toHaveTextContent(/"latest!" is not a version Vedette can store/)
    const field = within(block).getByLabelText('Version of Microsoft SQL Server')
    await userEvent.clear(field)
    await userEvent.type(field, '15.0.2000.5')
    await userEvent.click(save)
    expect(await screen.findByText('Microsoft SQL Server is now version 15.0.2000.5. Vedette checked it again.', undefined, T)).toBeInTheDocument()
    expect(assetsStore.get().find((a) => a.id === 'a-srvfile')!.software.find((s) => s.id === 's-srvfile-sql')!.version).toBe('15.0.2000.5')
    // the item leaves; the re-match may leave other items of the device (the mock matches its Windows by name)
    await waitFor(() => expect(screen.queryByRole('listitem', { name: 'SRV-FILE' }) ?? document.body).not.toHaveTextContent(/Microsoft SQL Server has no version/), T)
  })

  it('a version Vedette cannot compare is corrected in place too (the N100\'s FortiGate "latest")', async () => {
    renderApp('/findings?tab=input')
    const block = await expand('Fortinet')
    expect(block).toHaveTextContent(/FortiGate version "latest" cannot be compared/)
    await userEvent.type(await within(block).findByLabelText('Version of FortiGate', undefined, T), '7.2.5')
    await userEvent.click(within(block).getByRole('button', { name: 'Save and check' }))
    await waitFor(() => expect(document.body).not.toHaveTextContent(/FortiGate version "latest"/), T)
    expect(assetsStore.get().find((a) => a.id === 'a-unk02')!.software[0]!.version).toBe('7.2.5')
  })

  it('Not installed removes software a person added, after one confirmation here', async () => {
    renderApp('/findings?tab=input')
    const block = await expand('Fortinet')
    await userEvent.click(await within(block).findByRole('button', { name: 'Not installed' }, T))
    const ask = within(block).getByRole('group', { name: 'Not installed' })
    expect(ask).toHaveTextContent('Remove FortiGate from Fortinet? Its exploited CVEs stop matching.')
    await userEvent.click(within(ask).getByRole('button', { name: 'Cancel' }))
    expect(within(block).queryByRole('group', { name: 'Not installed' })).toBeNull()
    await userEvent.click(within(block).getByRole('button', { name: 'Not installed' }))
    await userEvent.click(within(within(block).getByRole('group', { name: 'Not installed' })).getByRole('button', { name: 'Remove' }))
    expect(await screen.findByText('Removed FortiGate from Fortinet.', undefined, T)).toBeInTheDocument()
    expect(assetsStore.get().find((a) => a.id === 'a-unk02')!.software).toEqual([])
    await waitFor(() => expect(screen.queryByRole('listitem', { name: 'Fortinet' })).toBeNull(), T)
  })

  it('Not installed on software a scan reads (INV-41 (6)): one confirmation, then the person\'s word is kept as a correction and the item leaves', async () => {
    let sent: unknown = null
    server.events.on('request:start', ({ request }) => { if (request.method === 'PATCH' && request.url.includes('/software/s-cam01')) void request.clone().json().then((b) => { sent = b }) })
    renderApp('/findings?tab=input')
    const cam = await expand('CAM-GATE')
    expect(await within(cam).findByText(/Vedette saw it in network traffic, which carries no version/, undefined, T)).toBeInTheDocument()
    expect(within(cam).getByRole('button', { name: 'Save and check' })).toBeInTheDocument() // the version can still be typed (a correction)
    await userEvent.click(within(cam).getByRole('button', { name: 'Not installed' }))
    const ask = within(cam).getByRole('group', { name: 'Not installed' })
    expect(ask).toHaveTextContent('Say Hikvision camera is not installed on CAM-GATE? The findings only it produced close. If a later scan or agent read finds it at another version, Vedette checks that version. Clear it on the device page to undo.')
    await userEvent.click(within(ask).getByRole('button', { name: 'Not installed' }))
    // the toast says what happened: here no open finding was on the row
    expect(await screen.findByText('Hikvision camera is marked not installed on CAM-GATE. No open finding was on it.', undefined, T)).toBeInTheDocument()
    expect(sent).toEqual({ not_installed: true })
    const row = assetsStore.get().find((a) => a.id === 'a-cam01')!.software
    expect(row.find((s) => s.corrects === 's-cam01')).toMatchObject({ source: 'manual', not_installed: true, display: 'Hikvision camera' })
    await waitFor(() => expect(screen.queryByRole('listitem', { name: 'CAM-GATE' })).toBeNull(), T)
    server.events.removeAllListeners()
  })

  it('a product added as its own device: Not installed removes the device', async () => {
    const own: Asset = { id: 'a-own', site: 'hq', ip: '', mac: null, hostname: null, name: null, kind: 'unknown', vendor: null, model: null, os: null, services: [], first_seen: new Date().toISOString(), last_seen: new Date().toISOString(),
      approved: true, fragile: false, origin: 'manual', software: [{ id: 's-own', display: 'Microsoft SQL Server', vendor: 'Microsoft', product: 'SQL Server', version: null, kev: ['microsoft|sql server'], source: 'manual', confidence: 1 }] }
    assetsStore.update((l) => [...l, own])
    const a = asset('a-own', 'Microsoft SQL Server (no device)')
    serve({ version_needed: [need(a, 'Microsoft SQL Server', { software_id: 's-own' })] })
    renderApp('/findings?tab=input')
    const block = await expand('Microsoft SQL Server (no device)')
    await userEvent.click(await within(block).findByRole('button', { name: 'Not installed' }, T))
    expect(within(block).getByRole('group', { name: 'Not installed' })).toHaveTextContent('Remove Microsoft SQL Server (no device)? It was added only for Microsoft SQL Server; its findings go with it.')
    await userEvent.click(within(block).getByRole('button', { name: 'Remove' }))
    expect(await screen.findByText('Removed Microsoft SQL Server (no device).', undefined, T)).toBeInTheDocument()
    expect(assetsStore.get().some((x) => x.id === 'a-own')).toBe(false)
  })

  it('software a scan reads: when the next version scan reads it, Check this device now, and a link to the exact row', async () => {
    renderApp('/findings?tab=input', { role: 'admin' })
    const cam = await expand('CAM-GATE')
    expect(await within(cam).findByText(/The next version scan reads it again on .+, or check the device now\./, undefined, T)).toBeInTheDocument()
    expect(within(cam).getByRole('link', { name: 'Open Hikvision camera on CAM-GATE' })).toHaveAttribute('href', '/devices/a-cam01?tab=software')
    // the device page's own rule decides whether the check can run now: a button, or the reason
    await waitFor(() => expect(within(cam).queryByRole('button', { name: 'Check this device now' }) ?? within(cam).queryByText(/fragile|gentle|never|scope|address/i)).not.toBeNull(), T)
  })

  it('nothing a person can do: it says so, and when Vedette checks again (the next NVD refresh), or that the feed is off', async () => {
    renderApp('/findings?tab=input')
    const srv = await expand('SRV-ACCOUNTS')
    expect(await within(srv).findByText(/^Nothing to type here: read the advisories to check it yourself\. Vedette checks these again at the next NVD refresh, on .+\.$/, undefined, T)).toBeInTheDocument()
    expect(within(srv).queryByRole('button', { name: 'Save and check' })).toBeNull()
    // a row a scan reads, waiting for NVD: the person can still say it is not installed
    expect(within(srv).getByRole('button', { name: 'Not installed' })).toBeInTheDocument()
  })

  it('a question about the platform or package release of a reported row offers Not installed too', async () => {
    const cam = asset('a-cam01', 'CAM-GATE')
    serve({ unchecked: [unc(cam, 'Hikvision camera', ['CVE-2026-41'], { software_id: 's-cam01', action: 'answer_platform', reason: 'package_unknown',
      question: { text: 'Which firmware build does CAM-GATE run?', command: null, answers: [{ label: 'Enter the package release', ask: ['pkg_version'] }] } })] })
    renderApp('/findings?tab=input')
    const block = await expand('CAM-GATE')
    expect(await within(block).findByText('Which firmware build does CAM-GATE run?', undefined, T)).toBeInTheDocument()
    expect(await within(block).findByRole('button', { name: 'Not installed' }, T)).toBeInTheDocument()
  })

  it('the box\'s own software is never offered Not installed: it reads its own package list', async () => {
    const box = asset('a-box', 'vedette')
    serve({ unchecked: [unc(box, 'OpenSSH server', ['CVE-2026-31'], { software_id: 's-box-openssh' })] })
    renderApp('/findings?tab=input')
    const block = await expand('vedette')
    expect((await within(block).findAllByText(/CVE-2026-31/, undefined, T)).length).toBeGreaterThan(0)
    await waitFor(() => expect(within(block).queryByText(/Reading the device/)).toBeNull(), T)
    expect(within(block).queryByRole('button', { name: 'Not installed' })).toBeNull()
  })

  it('the NVD feed off, and NVD not answered yet: it says so, with the way to turn it on', async () => {
    server.use(http.get('*/api/v1/feeds/sources', () => HttpResponse.json({ items: [{ id: 'nvd-kev', enabled: false, interval_hours: 24, last_fetch: null }] })))
    const a = asset('a-x', 'NAS-X')
    serve({ unchecked: [unc(a, 'QNAP QTS', ['CVE-2026-7'], { cves: [{ cve: 'CVE-2026-7', name: 'QTS flaw', date_added: '2026-11-01', ransomware: false, advisory: null, nvd_pending: true }] })] })
    renderApp('/findings?tab=input')
    const nas = await expand('NAS-X')
    expect(await within(nas).findByText(/Vedette is still waiting for NVD's data on these\. The NVD feed is off, so nothing checks these again\./, undefined, T)).toBeInTheDocument()
    expect(within(nas).getByRole('link', { name: 'Turn it on in Settings, Feeds' })).toHaveAttribute('href', '/settings/feeds')
  })

  it('unproved findings: Not affected closes them as false positives with the person\'s reason, here', async () => {
    const pc = asset('a-srvacc', 'SRV-ACCOUNTS')
    let sent: unknown = null
    server.use(http.post('*/api/v1/findings/status', async ({ request }) => { sent = await request.json(); return HttpResponse.json({ updated: 2, skipped: 0 }) }))
    serve({}, { truncated: false, plan_ran: true, plan_off: false, risks: {}, devices: [
      dev(pc, { open: 2, no_update: [act({ group: 'a-srvacc/s-srvacc', software_id: 's-srvacc', software: 'Windows Server 2022', source: 'nmap', cves: ['CVE-2026-11', 'CVE-2026-12'], finding_ids: ['f-11', 'f-12'] })] }),
    ] })
    renderApp('/findings?tab=input')
    const block = await expand('SRV-ACCOUNTS')
    expect(await within(block).findByText(/check each CVE with the vendor's advice; if the device is not affected, mark them here/, undefined, T)).toBeInTheDocument()
    await userEvent.click(within(block).getByRole('button', { name: 'Not affected' }))
    const submit = within(block).getByRole('button', { name: 'Mark 2 findings not affected' })
    await userEvent.click(submit)
    expect(within(block).getByRole('alert')).toBeInTheDocument()
    expect(sent).toBeNull()
    await userEvent.type(within(block).getByLabelText('Why is the device not affected? (required)'), 'Microsoft says build 20348.4405 is fixed')
    await userEvent.click(submit)
    await waitFor(() => expect(sent).toEqual({ ids: ['f-11', 'f-12'], action: 'false_positive', note: 'Microsoft says build 20348.4405 is fixed' }), T)
    expect(await screen.findByText('Status saved for 2 findings', undefined, T)).toBeInTheDocument()
  })

  it('a viewer reads the steps; the actions are locked with the role they need', async () => {
    renderApp('/findings?tab=input', { role: 'viewer' })
    const block = await expand('SRV-FILE')
    expect(await within(block).findByRole('button', { name: 'Save and check' }, T)).toBeDisabled()
    expect(within(block).getByRole('button', { name: 'Not installed' })).toBeDisabled()
    expect(within(block).getByRole('button', { name: 'Not installed' })).toHaveAttribute('title', 'Requires Operator role')
  })
})
