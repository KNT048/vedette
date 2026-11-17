import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { server } from '@/test/server'
import { assetsStore, findingsStore, modulesStore } from '@/mocks/stores'
import { inventorySettingsStore } from '@/features/inventory/mocks'
import type { ToFix, ToFixAction, ToFixDevice } from './types'

// kien G8: "when the user opens Findings, they know which devices need patching or an action, and what the action is".
const T = { timeout: 5000 }
const act = (o: Partial<ToFixAction>): ToFixAction => ({ group: 'g', software_id: '', software: '', version: '', product: '', source: '', fixed: '', kind: 'fixed', windows: false, distro: '', pro: false, action: '',
  cves: [], finding_ids: [], worst: 'high', ransomware: 0, likely: 0, confirmed: 0, detected: 1, reported: 0, suspected: 0, ...o })
const dev = (id: string, name: string, o: Partial<ToFixDevice>): ToFixDevice => ({ asset: { id, name, hostname: name, ip: '192.168.18.10', kind: 'pc', display: 'Windows 11' }, open: 0, exploited: [], no_update: [], planned: [], plan_compared: true, ...o })
const winUpdate = act({ group: 'a-pc/s-win', software_id: 's-win', software: 'Windows 11 Pro', version: '10.0.26100.1742', fixed: '10.0.26100.33650', windows: true,
  action: 'Install the latest cumulative update for Windows 11 Pro (build 26100.33650 or later)', cves: ['CVE-2026-1001', 'CVE-2026-1002', 'CVE-2026-1003'], finding_ids: ['f-a', 'f-b', 'f-c'], worst: 'critical', ransomware: 1, detected: 3 })
const winrar = (devId: string, name = 'RARLAB WinRAR') => act({ group: `${devId}/s-rar`, software_id: 's-rar', software: name, product: 'rarlab|winrar', version: '7.01', fixed: '7.13', action: 'Upgrade RARLAB WinRAR from 7.01 to 7.13 or later', cves: ['CVE-2025-6218', 'CVE-2025-8088'], finding_ids: ['f-r1', 'f-r2'], worst: 'high', detected: 2 })
const firefox = act({ group: 'a-desk/s-ff', software_id: 's-ff', software: 'Mozilla Firefox', version: '152.0', fixed: '157.0.1', action: 'Upgrade Mozilla Firefox from 152.0 to 157.0.1 or later', cves: Array.from({ length: 228 }, (_, i) => `CVE-2026-${20000 + i}`), worst: 'critical', likely: 3, detected: 0 })
const unprovedWin = act({ group: 'a-desk/s-w', software_id: 's-w', software: 'Windows 11 Pro', version: '10.0.26300.9974', kind: 'none', action: "No update is named that fixes these: follow the vendor's advice for Windows 11 Pro",
  cves: ['CVE-2002-0367', 'CVE-2016-3427'], finding_ids: ['f-u1', 'f-u2'], worst: 'medium', detected: 0, reported: 2 })
const sample: ToFix = { truncated: false, plan_ran: true, plan_off: false, devices: [
  dev('a-pc', 'PC-A', { open: 3, exploited: [winUpdate] }),
  dev('a-desk', 'DESKTOP-55UKKFV', { open: 4, exploited: [winrar('a-desk')], no_update: [unprovedWin], planned: [firefox] }),
  dev('a-lap', 'LAPTOP-B', { open: 2, exploited: [winrar('a-lap', 'WinRAR 7.01 (64-bit)')] }), // the same product under another name: one By fix row
] }
const serve = (tf: ToFix = sample) => server.use(http.get('*/api/v1/findings/to-fix', () => HttpResponse.json(tf)))

describe('Findings › To fix (kien G8)', () => {
  it('opens by device, the most urgent first, each with its actions as sentences: device → what to do', async () => {
    serve()
    renderApp('/findings')
    const list = await screen.findByRole('list', { name: 'Devices to fix, the most urgent first' }, T)
    const cards = within(list).getAllByRole('listitem').filter((li) => li.parentElement === list)
    expect(cards.map((c) => c.getAttribute('aria-label'))).toEqual(['PC-A', 'DESKTOP-55UKKFV', 'LAPTOP-B'])
    const pc = within(cards[0]!).getByRole('list', { name: 'What to do on PC-A' })
    expect(pc).toHaveTextContent('Install the latest cumulative update for Windows 11 Pro (build 26100.33650 or later): fixes 3 exploited CVEs, 1 used by ransomware Critical')
    // the recommended update of a device is its own action row, with every CVE inside: DESKTOP-55UKKFV's Firefox is one row
    const rec = within(cards[1]!).getByRole('list', { name: 'Recommended updates for DESKTOP-55UKKFV' })
    expect(within(rec).getAllByRole('listitem').filter((li) => li.parentElement === rec)).toHaveLength(1)
    expect(rec).toHaveTextContent('Upgrade Mozilla Firefox from 152.0 to 157.0.1 or later: fixes 228 CVEs not exploited yet, 3 likely to be exploited soon')
    // the unproved product match is not "to fix": it says it needs a check, in Needs your input
    expect(within(cards[1]!).getByRole('link', { name: '2 more need your check' })).toHaveAttribute('href', '/findings?tab=input&device=a-desk')
    await expectNoA11yViolations()
  })

  it('an action opens to its CVEs, each linking to its finding (CVSS, basis and status are there)', async () => {
    serve()
    renderApp('/findings')
    const pc = await screen.findByRole('list', { name: 'What to do on PC-A' }, T)
    expect(within(pc).queryByRole('link', { name: 'CVE-2026-1001' })).not.toBeVisible()
    await userEvent.click(within(pc).getByText('Show the 3 CVEs'))
    expect(within(pc).getByRole('link', { name: 'CVE-2026-1001' })).toHaveAttribute('href', '/findings/f-a')
    expect(within(pc).getByRole('link', { name: 'Handle these 3 findings in the list' })).toHaveAttribute('href', '/findings?tab=open&fix=a-pc%2Fs-win')
  })

  it('"By fix" turns it around: one row per update with its devices, kept in the address', async () => {
    serve()
    renderApp('/findings')
    await userEvent.click(await screen.findByRole('button', { name: 'By fix' }, T))
    const fixes = await screen.findByRole('list', { name: 'Fixes, the most urgent first' })
    const rows = within(fixes).getAllByRole('listitem').filter((li) => li.parentElement === fixes)
    expect(rows[0]).toHaveTextContent('Install the latest cumulative update for Windows 11 Pro (build 26100.33650 or later): 1 device, 3 exploited CVEs')
    const rar = rows.find((r) => r.textContent?.startsWith('Upgrade RARLAB WinRAR to 7.13 or later'))!
    expect(rar).toHaveTextContent('2 devices, 4 exploited CVEs')
    await userEvent.click(within(rar).getByText(/^Upgrade RARLAB WinRAR to 7.13/))
    expect(within(rar).getByRole('link', { name: 'LAPTOP-B' })).toHaveAttribute('href', '/devices/a-lap')
    expect(rows.at(-1)).toHaveTextContent('Upgrade Mozilla Firefox to 157.0.1 or later: recommended on 1 device, 228 CVEs')
  })

  it('By fix names a Windows feature update and an ESU as such, not as the monthly cumulative update', async () => {
    const feature = act({ group: 'a-w10/s-w', software_id: 's-w', software: 'Windows 10', product: 'microsoft|windows_10', version: '10.0.19045.1', fixed: '11 24H2', kind: 'feature_update', windows: true,
      action: 'Upgrade Windows 10 to 11 24H2: some of these get no update for this release', cves: ['CVE-2026-3001'], finding_ids: ['f-w1'], worst: 'critical' })
    const esu = act({ group: 'a-esu/s-w', software_id: 's-w', software: 'Windows 10', product: 'microsoft|windows_10', version: '10.0.19045.1', fixed: '10.0.19045.6456', kind: 'esu', windows: true,
      action: 'Install the Extended Security Update for Windows 10 (build 19045.6456 or later; it needs an ESU subscription)', cves: ['CVE-2026-3002'], finding_ids: ['f-w2'], worst: 'high' })
    serve({ ...sample, devices: [dev('a-w10', 'PC-W10', { exploited: [feature] }), dev('a-esu', 'PC-ESU', { exploited: [esu] })] })
    renderApp('/findings?by=fix')
    const fixes = await screen.findByRole('list', { name: 'Fixes, the most urgent first' }, T)
    expect(fixes).toHaveTextContent('Upgrade Windows 10 to 11 24H2')
    expect(fixes).toHaveTextContent('Install the Extended Security Update for Windows 10 (build 19045.6456 or later; it needs an ESU subscription)')
    expect(fixes).not.toHaveTextContent('cumulative update')
  })

  it('a device filter shows as a chip that clears it, and the empty state names the device', async () => {
    serve()
    renderApp('/findings?device=a-none')
    expect(await screen.findByText('Nothing to fix on this device', undefined, T)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Only this device: show every device' }))
    expect(await screen.findByRole('list', { name: 'Devices to fix, the most urgent first' })).toBeInTheDocument()
  })

  it('old link shapes keep their filter: ?cve= and ?fix= open the findings table, a device page\'s "handle" link too', async () => {
    renderApp('/findings?fix=a-srvad%2Fs-win')
    expect(await screen.findByRole('tab', { name: /All open/, selected: true }, T)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Show all findings' })).toBeInTheDocument() // the ?fix= filter is on
  })

  it('the device page\'s "select and handle" link opens the findings table of that device', async () => {
    renderApp('/devices/a-nas02')
    expect(await screen.findByRole('link', { name: 'Select and handle these findings in the Findings list' }, T)).toHaveAttribute('href', '/findings?tab=open&device=a-nas02')
  })

  it('"Needs your input (N)" counts what only a person can settle and lists the unproved matches', async () => {
    serve()
    server.use(http.get('*/api/v1/findings', () => HttpResponse.json({ items: [], unchecked: [], version_needed: [
      { asset: { id: 'a-pc', name: 'PC-A', hostname: 'PC-A', ip: '192.168.18.10', kind: 'pc', display: 'Windows 11' }, asset_id: 'a-pc', software_id: 's-1', software: 'Microsoft Office', version: null, cves: 32 },
    ] })))
    renderApp('/findings')
    const tab = await screen.findByRole('tab', { name: /Needs your input/ }, T)
    await within(tab).findByText('2')
    await userEvent.click(tab)
    expect(await screen.findByRole('region', { name: 'Add the version of 1 software to check it' })).toHaveTextContent(/Microsoft Office has no version/)
    expect(screen.getByRole('heading', { name: '1 software has exploited CVEs Vedette could not prove' })).toBeInTheDocument()
    expect(screen.getByText(/Windows 11 Pro 10.0.26300.9974/)).toBeInTheDocument()
  })

  it('kien G12: a typed version per row; the agent and the check read the whole device, so each shows once per device (n83)', async () => {
    serve({ ...sample, devices: [dev('a-pc', 'PC-A', { open: 5, exploited: [
      { ...winUpdate, source: 'agent' },
      { ...winrar('a-pc'), source: 'manual' },
      act({ group: 'a-pc/s-git', software_id: 's-git', software: 'Git', version: '2.40', fixed: '2.47.3', source: 'nmap', action: 'Upgrade Git from 2.40 to 2.47.3 or later', cves: ['CVE-2025-48384'], finding_ids: ['f-g'] }),
      act({ group: 'a-pc/s-7z', software_id: 's-7z', software: '7-Zip', version: '24.0', fixed: '25.01', source: 'agent', action: 'Upgrade 7-Zip from 24.0 to 25.01 or later', cves: ['CVE-2025-0411'], finding_ids: ['f-z'] }),
    ] })] })
    renderApp('/findings')
    const acts = await screen.findByRole('list', { name: 'What to do on PC-A' }, T)
    const card = screen.getByRole('listitem', { name: 'PC-A' })
    const row = (text: string) => within(acts).getByText(text).closest('li')!
    expect(within(row('Upgrade RARLAB WinRAR from 7.01 to 7.13 or later')).getByRole('button', { name: 'I updated RARLAB WinRAR' })).toBeInTheDocument()
    expect(within(acts).queryByText(/agent/)).toBeNull() // never under every row
    expect(within(acts).queryByRole('button', { name: 'Check this device now' })).toBeNull()
    // agent-intake off: one line for the device, no promise that an agent reports (review r1 L2 of #953)
    expect(within(card).getAllByText(/^No agent reports the software of PC-A to Vedette now/)).toHaveLength(1)
    expect(within(card).getAllByRole('button', { name: 'Check this device now' })).toHaveLength(1)
  })

  it('S-MIT-1: on a device its osquery agent reports, one "ask the agent now" for the device, busy, then the ask on the card', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'agent-intake' ? { ...m, enabled: true } : m)))
    let release!: () => void
    const held = new Promise<void>((r) => { release = r })
    server.use(
      http.get('*/api/v1/inventory/agents/devices/:id/report', () => HttpResponse.json({ agent: 'osquery', asked_at: null, ask_again_at: null, last_seen: new Date().toISOString(), stale: false, wazuh_interval_minutes: null })),
      http.post('*/api/v1/inventory/agents/devices/:id/report', async () => { await held; return HttpResponse.json({ agent: 'osquery', asked_at: '2026-11-17T09:05:00Z', ask_again_at: '2026-11-17T09:15:00Z', last_seen: new Date().toISOString(), stale: false, wazuh_interval_minutes: null }) }),
    )
    serve({ ...sample, devices: [dev('a-pc', 'PC-A', { open: 3, exploited: [{ ...winrar('a-pc'), source: 'agent' }], planned: [{ ...firefox, group: 'a-pc/s-ff', source: 'agent' }] })] })
    renderApp('/findings')
    await screen.findByRole('list', { name: 'What to do on PC-A' }, T)
    const card = screen.getByRole('listitem', { name: 'PC-A' })
    const btns = await within(card).findAllByRole('button', { name: 'I updated it: ask the agent now' }, T)
    expect(btns).toHaveLength(1)
    expect(within(card).queryByText(/restart/i)).toBeNull() // two app rows: no restart
    await userEvent.click(btns[0]!)
    expect(await within(card).findByRole('button', { name: 'Asking…' }, T)).toHaveAttribute('aria-busy', 'true')
    release()
    expect(await within(card).findByText(/^Asked at \d\d:\d\d\. PC-A sends its software list within about 5 minutes; the findings this update fixes then close by themselves\.$/, {}, T)).toBeInTheDocument()
  })

  it('review r1 of #944, n83: one check per device: one button for all its scan-read rows', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'sensor-active' ? { ...m, enabled: true } : m)))
    inventorySettingsStore.update((st) => ({ ...st, active: { ...st.active, enabled: true }, scope_confirmed_at: st.scope_confirmed_at ?? '2026-11-01T00:00:00.000Z' }))
    const scanRow = (g: string, sw: string) => act({ group: `a-srvad/${g}`, software_id: g, software: sw, version: '1.0', fixed: '2.0', source: 'nmap', action: `Upgrade ${sw} from 1.0 to 2.0 or later`, cves: [`CVE-2026-${g.length}0`], finding_ids: [`f-${g}`] })
    serve({ ...sample, devices: [{ ...dev('a-srvad', 'SRV-AD', { open: 2, exploited: [scanRow('s-a', 'Apache'), scanRow('s-bb', 'OpenSSH')] }), asset: { id: 'a-srvad', name: 'SRV-AD', hostname: 'SRV-AD', ip: '192.168.10.10', kind: 'server', display: 'Windows Server 2016' } }] })
    renderApp('/findings')
    await screen.findByRole('list', { name: 'What to do on SRV-AD' }, T)
    const card = screen.getByRole('listitem', { name: 'SRV-AD' })
    const buttons = await within(card).findAllByRole('button', { name: 'Check this device now' }, T)
    expect(buttons).toHaveLength(1)
    await waitFor(() => expect(buttons[0]).toBeEnabled(), T)
    await userEvent.click(buttons[0]!)
    await waitFor(() => expect(within(card).getAllByRole('button', { name: 'Scanning…' })).toHaveLength(1), T)
  })

  it('a device with recommended updates only shows them on its page (review r2 of #943)', async () => {
    const withFindings = new Set(findingsStore.get().map((f) => f.asset_id))
    const quiet = assetsStore.get().find((x) => !withFindings.has(x.id) && x.software.length > 0)!
    server.use(http.get('*/api/v1/findings/to-fix', () => HttpResponse.json({ ...sample, devices: [dev(quiet.id, 'QUIET', { planned: [firefox] })] })))
    renderApp(`/devices/${encodeURIComponent(quiet.id)}`)
    const todo = await screen.findByRole('list', { name: 'What to do on this device' }, T)
    expect(within(todo).getByRole('list', { name: 'Recommended updates for QUIET' })).toHaveTextContent('Upgrade Mozilla Firefox from 152.0 to 157.0.1 or later: fixes 228 CVEs not exploited yet')
    expect(screen.queryByText('No findings for this device yet.')).toBeNull()
  })

  it('a device whose findings all need a check links To fix\'s empty state to Needs your input', async () => {
    serve({ ...sample, devices: [dev('a-cam', 'CAM-01', { open: 2, no_update: [unprovedWin] })] })
    renderApp('/findings?device=a-cam')
    expect(await screen.findByRole('link', { name: 'Its exploited CVEs need your check: see Needs your input.' }, T)).toHaveAttribute('href', '/findings?tab=input&device=a-cam')
    expect(screen.getByRole('button', { name: 'Only CAM-01: show every device' })).toBeInTheDocument()
  })

  it('the device\'s Software tab says what each row needs: a recommended update with its CVEs, nothing on a clean row', async () => {
    // review r2 of #943: a third row for the unproved match, so the check below always runs
    assetsStore.update((l) => l.map((x) => (x.id === 'a-nas02' ? { ...x, software: [...x.software, { ...x.software[0]!, id: 's-g8-third', display: 'Hikvision camera firmware', vendor: 'Hikvision', product: 'firmware', kev: [] }] } : x)))
    const a = assetsStore.get().find((x) => x.id === 'a-nas02')!
    const [first, clean] = a.software
    const third = a.software.find((x) => x.id === 's-g8-third')!
    server.use(http.get('*/api/v1/findings/to-fix', () => HttpResponse.json({ ...sample, devices: [dev('a-nas02', 'NAS-PHOTOS', {
      planned: [act({ group: `a-nas02/${first!.id}`, software_id: first!.id, software: first!.display, version: '1.0', fixed: '1.2.3', cves: ['CVE-2026-1', 'CVE-2026-2'], action: 'Upgrade' })],
      no_update: [act({ ...unprovedWin, group: `a-nas02/${third.id}`, software_id: third.id })],
    })] })))
    renderApp('/devices/a-nas02?tab=software')
    const table = await screen.findByRole('table', { name: 'Software on the device' }, T)
    const row = (name: string) => within(table).getAllByText(name)[0]!.closest('tr')!
    expect(await within(row(first!.display)).findByRole('link', { name: 'Recommended update to 1.2.3 fixes 2 CVEs' }, T)).toBeInTheDocument()
    if (clean) expect(within(row(clean.display)).queryByRole('link', { name: /Recommended|exploited/ })).toBeNull()
    // review r1 of #943: an unproved match is not counted as exploited: it links to Needs your input
    expect(within(row(third.display)).queryByRole('link', { name: /^2 exploited CVEs$/ })).toBeNull()
    expect(within(row(third.display)).getByRole('link', { name: '2 exploited CVEs to check' })).toHaveAttribute('href', '/findings?tab=input&device=a-nas02')
  })
})
