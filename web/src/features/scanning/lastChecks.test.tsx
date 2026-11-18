import { describe, expect, it, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp } from '@/test/render'
import { server } from '@/test/server'
import { assetsStore, findingsStore, modulesStore, sessionStore } from '@/mocks/stores'
import { scannerStore } from '@/features/scan/mocks'
import type { ScanRun } from '@/features/scan/types'
import { historyStore, markReached } from './mocks'

// A person could not tell what the device page's two check buttons do, nor whether a check had run.
const T = { timeout: 5000 }
const IDENT = 'Device check: ports, services, software'
const VULN = 'Vulnerability check: does a known exploit work'
const SNMP = 'SNMP read: model and firmware'
const run = (over: Partial<ScanRun>): ScanRun => ({
  id: 'run-nas', trigger: 'manual', trigger_note: null, started_at: '2026-11-17T03:18:00.000Z', started_by: 'admin@acme.example', ended_at: '2026-11-17T03:25:00.000Z',
  status: 'done', total: 1, done: 1, current: null, progress: null, results: [], matched: 0, stop_reason: null, identification: [], ...over,
})
const result = (target: string, cve: string) => ({ target_id: target, label: target, ip: '192.168.10.21', template: null, result: 'no_template' as const, finding_id: null, note: cve })

describe('the device page says what each check does and when each last ran', () => {
  it('each check button has a line under it: what it does, what it does not, how long', async () => {
    sessionStore.set({ userId: 'u-admin' })
    renderApp('/devices/a-nas02')
    const identify = await screen.findByRole('button', { name: 'Check this device now' }, T)
    expect(identify).toHaveAccessibleDescription(/open ports, services, operating system and software versions\. Does not test whether a flaw can be exploited\. Usually 1 to 5 minutes\./)
    const vuln = await screen.findByRole('button', { name: 'Run vulnerability checks now' }, T)
    expect(vuln).toHaveAccessibleDescription(/exploited flaws this device may have.*patches nothing\. Usually 5 to 15 minutes\./)
  })

  it('Last checks: each kind with when, the History sentence and a link; the vulnerability check counts only this device', async () => {
    // #965: the device's runs come by ?asset=, so a run older than the newest 100 of the LAN is still found
    server.use(http.get('*/api/v1/scans/runs', ({ request }) => new URL(request.url).searchParams.get('asset') === 'a-nas02'
      ? HttpResponse.json({ engine_busy: false, items: [run({ total: 2, results: [result('a-nas02', 'CVE-2026-1001'), result('a-other', 'CVE-2026-1002'), result('a-other', 'CVE-2026-1003')] })] })
      : HttpResponse.json({ engine_busy: false, items: Array.from({ length: 100 }, (_, i) => run({ id: `run-other-${i}`, results: [result('a-other', 'CVE-2026-1002')] })) })))
    renderApp('/devices/a-nas02')
    const ident = await screen.findByRole('group', { name: IDENT }, T)
    expect(within(ident).getByText('Scanned 192.168.10.21: 3 open ports (22 ssh, 80 http, 445 microsoft-ds); OS guess Linux 5.4 - 5.15; nothing changed since the previous check')).toBeInTheDocument()
    expect(within(ident).getByText('Done')).toBeInTheDocument()
    const vuln = screen.getByRole('group', { name: VULN })
    expect(within(vuln).getByText('Checked 1 CVE: 1 no check exists (still suspected)')).toBeInTheDocument()
    expect(within(vuln).getByRole('link', { name: 'See it in History' })).toHaveAttribute('href', '/settings/scanning?tab=history&run=run-nas')
    // an SNMP read asked its address, but SNMP is not set up on it: that read is not its own, so its SNMP card and this row agree
    const snmp = screen.getByRole('group', { name: SNMP })
    expect(within(snmp).getByText('Never')).toBeInTheDocument()
    expect(within(snmp).queryByText('2 of 3 devices answered over SNMP')).toBeNull()
  })

  it('a device with SNMP set up shows the SNMP reads of its read address', async () => {
    server.use(http.get('*/api/v1/scans/runs', () => HttpResponse.json({ engine_busy: false, items: [] })))
    renderApp('/devices/a-fw01')
    const snmp = await screen.findByRole('group', { name: SNMP }, T)
    expect(await within(snmp).findByText('2 of 3 devices answered over SNMP', {}, T)).toBeInTheDocument()
    expect(within(snmp).getByText('Partly done')).toBeInTheDocument()
    expect(within(snmp).getByRole('link', { name: 'See it in History' })).toHaveAttribute('href', '/settings/scanning?tab=history&asset=a-fw01&job=saj-h3')
  })

  it('a kind that never ran says "Never" and what runs it; the checks module off says so', async () => {
    server.use(http.get('*/api/v1/scans/runs', () => HttpResponse.json({ engine_busy: false, items: [] })))
    renderApp('/devices/a-nas01')
    const ident = await screen.findByRole('group', { name: IDENT }, T)
    // the hints name the two buttons, which this device's page shows
    expect(screen.getAllByRole('button', { name: 'Check this device now' }).length).toBeGreaterThan(0)
    expect(screen.getAllByRole('button', { name: 'Run vulnerability checks now' }).length).toBeGreaterThan(0)
    expect(within(ident).getByText('Never')).toBeInTheDocument()
    expect(within(ident).getByText(/Check this device now” above runs it/)).toBeInTheDocument()
    expect(within(ident).queryByRole('link', { name: 'See it in History' })).toBeNull()
    expect(within(screen.getByRole('group', { name: VULN })).getByText(/Run vulnerability checks now” above runs it/)).toBeInTheDocument()
    const snmp = screen.getByRole('group', { name: SNMP })
    expect(within(snmp).getByText('Never')).toBeInTheDocument()
    expect(within(snmp).getByText(/once SNMP is set up on this device/)).toBeInTheDocument()
    // the device's own SNMP card is on this page (admin)
    expect(within(snmp).getByRole('link', { name: 'Set it up in Sources' })).toHaveAttribute('href', '/devices/a-nas01#device-snmp')
  })

  it('a viewer gets no link to the SNMP card, which only an admin sees', async () => {
    server.use(http.get('*/api/v1/scans/runs', () => HttpResponse.json({ engine_busy: false, items: [] })))
    renderApp('/devices/a-nas01', { role: 'viewer' })
    const snmp = await screen.findByRole('group', { name: SNMP }, T)
    expect(within(snmp).getByText(/once SNMP is set up on this device/)).toBeInTheDocument()
    expect(within(snmp).queryByRole('link', { name: 'Set it up in Sources' })).toBeNull()
  })

  it('the vulnerability checks module off: "Off", with where to turn it on', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'scan' ? { ...m, enabled: false } : m)))
    renderApp('/devices/a-nas01')
    const vuln = await screen.findByRole('group', { name: VULN }, T)
    expect(within(vuln).getByText('Off')).toBeInTheDocument()
    expect(within(vuln).getByRole('link', { name: 'Turn them on: Settings, Scanning, Engines' })).toBeInTheDocument()
  })

  it('a failed device check says Failed and why, and its link opens that run on top of the device\'s History', async () => {
    historyStore.set([{ id: 'saj-fail', kind: 'device', engine: 'nmap-versions', trigger: 'person', label: '192.168.10.21', target_id: null, started_at: new Date().toISOString(), ended_at: new Date().toISOString(), outcome: 'failed', text: 'Failed: nmap gave up.' }, ...historyStore.get()])
    markReached('saj-fail', ['192.168.10.21'])
    renderApp('/devices/a-nas02')
    const ident = await screen.findByRole('group', { name: IDENT }, T)
    expect(within(ident).getByText('Failed')).toBeInTheDocument()
    expect(within(ident).getByText('Failed: nmap gave up.')).toBeInTheDocument()
    const link = within(ident).getByRole('link', { name: 'See it in History' })
    expect(link).toHaveAttribute('href', '/settings/scanning?tab=history&asset=a-nas02&job=saj-fail')
    await userEvent.click(link)
    const opened = await screen.findByRole('region', { name: 'The run you opened' }, T)
    expect(within(opened).getByText('Failed: nmap gave up.')).toBeInTheDocument()
    expect(screen.getByText('Only this device’s runs: its device checks and, while SNMP is set up on it, the SNMP reads of its read address.')).toBeInTheDocument()
    // only this device's runs: its two checks, never the sweep, never an SNMP read of a device without SNMP set up
    const table = await screen.findByRole('table', { name: 'History of discovery runs and public scans' }, T)
    expect(within(table).queryByText(/Swept 254 addresses/)).toBeNull()
    expect(within(table).queryByText('2 of 3 devices answered over SNMP')).toBeNull()
    expect(within(table).getByText(/^Scanned 192\.168\.10\.21: 3 open ports/)).toBeInTheDocument()
  })

  // #965: a read that failed or has not answered is never shown as "Never"
  it('History failing shows the error with Try again, never "Never"', async () => {
    server.use(http.get('*/api/v1/scanning/history', () => HttpResponse.json({ error: { code: 'internal', message: 'The box could not read its runs.' } }, { status: 500 })))
    renderApp('/devices/a-nas02')
    const section = await screen.findByRole('region', { name: 'Last checks' }, T)
    expect(await within(section).findByRole('alert', {}, T)).toHaveTextContent('The box could not read its runs.')
    expect(within(section).getByRole('button', { name: 'Try again' })).toBeInTheDocument()
    expect(within(section).queryByText('Never')).toBeNull()
  })

  it('only the vulnerability checks failing: that row shows the error, the others still answer', async () => {
    server.use(http.get('*/api/v1/scans/runs', () => HttpResponse.json({ error: { code: 'internal', message: 'The scan list did not answer.' } }, { status: 500 })))
    renderApp('/devices/a-nas01')
    const vuln = await screen.findByRole('group', { name: VULN }, T)
    expect(await within(vuln).findByRole('alert', {}, T)).toHaveTextContent('The scan list did not answer.')
    expect(within(vuln).queryByText('Never')).toBeNull()
  })

})

// A hint names a button only when the device page shows it for this device; otherwise it says what would let the check run.
describe('Last checks never points at a button the device page does not show', () => {
  const noRuns = () => server.use(http.get('*/api/v1/scans/runs', () => HttpResponse.json({ engine_busy: false, items: [] })))
  const addDevice = (over: Record<string, unknown>) => {
    const pc = assetsStore.get().find((a) => a.id === 'a-pc01')!
    assetsStore.update((l) => [...l, { ...pc, id: 'a-man1', ip: '192.168.10.240', mac: null, hostname: 'MAN-ONE', services: [], software: [], ...over }])
  }
  const lastChecks = () => screen.findByRole('region', { name: 'Last checks' }, T)

  it('a device added by hand: neither button, and the hints point at Sources, where its network scan is turned on', async () => {
    noRuns()
    addDevice({ origin: 'manual' })
    renderApp('/devices/a-man1')
    const section = await lastChecks()
    const ident = await within(section).findByRole('group', { name: IDENT }, T)
    await vi.waitFor(() => expect(ident).toHaveTextContent('Network scan off: see Sources'), T)
    await vi.waitFor(() => expect(screen.getByRole('group', { name: VULN })).toHaveTextContent('Network scan off: see Sources'), T)
    expect(screen.queryAllByRole('button', { name: 'Check this device now' })).toHaveLength(0)
    expect(screen.queryAllByRole('button', { name: 'Run vulnerability checks now' })).toHaveLength(0)
    expect(within(section).queryByText(/above/)).toBeNull()
  })

  it('the Services tab of a device added by hand does not send the person to Check this device now', async () => {
    addDevice({ origin: 'manual' })
    renderApp('/devices/a-man1?tab=services')
    const tip = await screen.findByRole('button', { name: 'About No open port seen yet' }, T)
    expect(tip).toHaveAccessibleDescription('Its network scan is off: Sources, on the Overview tab, turns it on.')
  })

  it('the Services tab of a device that can be checked names the button at the top of the page', async () => {
    addDevice({})
    renderApp('/devices/a-man1?tab=services')
    const tip = await screen.findByRole('button', { name: 'About No open port seen yet' }, T)
    expect(tip).toHaveAccessibleDescription(/press Check this device now under Last checks on the Overview tab/)
  })

  it('a device without an address: one note says the cause once and what it blocks; the rows only say nothing ran', async () => {
    noRuns()
    addDevice({ ip: '—', hostname: null })
    renderApp('/devices/a-man1')
    const section = await lastChecks()
    expect(await within(section).findByText(/can neither identify this device nor run vulnerability checks/, undefined, T)).toBeInTheDocument()
    expect(within(section).getAllByText(/No IP address yet/)).toHaveLength(1)
    expect(within(screen.getByRole('group', { name: IDENT })).getByText('Not run yet.')).toBeInTheDocument()
    expect(within(screen.getByRole('group', { name: VULN })).getByText('Not run yet.')).toBeInTheDocument()
  })

  it('a product declared without an address: no button, no SNMP card link', async () => {
    noRuns()
    addDevice({ origin: 'manual', ip: '—', hostname: null })
    renderApp('/devices/a-man1')
    const section = await lastChecks()
    await within(section).findByRole('group', { name: VULN }, T)
    expect(within(screen.getByRole('group', { name: IDENT })).getByText('Not run yet.')).toBeInTheDocument()
    expect(within(section).queryByRole('link', { name: 'Set it up in Sources' })).toBeNull()
    expect(within(section).queryByText(/above/)).toBeNull()
  })

  // The run can only confirm the findings whose CVE has a safe check (the KEV entry's has_template)
  const suspect = (cves: string[]) => {
    const tpl = findingsStore.get()[0]!
    findingsStore.update((l) => [...l, ...cves.map((cve, i) => ({ ...tpl, id: `f-man-${i}`, asset_id: 'a-man1', cve, status: 'suspected' as const }))])
  }

  it('0 of 2 suspected findings have a safe check: no run is offered, and the note says why and what decides them', async () => {
    noRuns()
    addDevice({ ip: '192.168.10.241' })
    suspect(['CVE-2024-27834', 'CVE-2026-119977'])
    renderApp('/devices/a-man1')
    const section = await lastChecks()
    expect(await within(section).findByText(/No safe check exists for these 2 suspected CVEs/, undefined, T)).toBeInTheDocument()
    expect(within(section).queryByRole('button', { name: 'Run vulnerability checks now' })).toBeNull()
  })

  it('1 of 2 suspected findings has a safe check: the run is offered and the note says 1 of 2', async () => {
    noRuns()
    addDevice({ ip: '192.168.10.241' })
    suspect(['CVE-2024-27834', 'CVE-2026-97229'])
    renderApp('/devices/a-man1')
    const section = await lastChecks()
    expect(await within(section).findByText(/1 of 2 suspected findings can be checked\./, undefined, T)).toBeInTheDocument()
    expect(within(section).getByRole('button', { name: 'Run vulnerability checks now' })).toBeInTheDocument()
  })

  it('a device not approved yet: the device check button is there and named, the vulnerability check says to approve it', async () => {
    noRuns()
    addDevice({ approved: false })
    renderApp('/devices/a-man1')
    const section = await lastChecks()
    await within(section).findByRole('group', { name: VULN }, T)
    expect(await within(section).findAllByText('Not approved in the inventory, so not scanned', undefined, T)).toHaveLength(1)
    expect(screen.queryAllByRole('button', { name: 'Run vulnerability checks now' })).toHaveLength(0)
    expect(screen.getAllByRole('button', { name: 'Check this device now' }).length).toBeGreaterThan(0)
    expect(within(screen.getByRole('group', { name: IDENT })).getByText(/Check this device now” above runs it/)).toBeInTheDocument()
  })

  it('a viewer sees both buttons disabled: the hints say who can run them', async () => {
    noRuns()
    renderApp('/devices/a-nas01', { role: 'viewer' })
    const section = await lastChecks()
    const ident = await within(section).findByRole('group', { name: IDENT }, T)
    expect(within(ident).getByText(/^An admin can run it with “Check this device now” above\./)).toBeInTheDocument()
    expect(within(screen.getByRole('group', { name: VULN })).getByText(/^An operator can run it with “Run vulnerability checks now” above\./)).toBeInTheDocument()
  })

  it('an operator runs the vulnerability checks, an admin the device check', async () => {
    noRuns()
    renderApp('/devices/a-nas01', { role: 'operator' })
    const section = await lastChecks()
    const ident = await within(section).findByRole('group', { name: IDENT }, T)
    expect(within(ident).getByText(/^An admin can run it with “Check this device now” above\./)).toBeInTheDocument()
    expect(within(screen.getByRole('group', { name: VULN })).getByText(/^“Run vulnerability checks now” above runs it\./)).toBeInTheDocument()
  })

  it('the scanner not available: the vulnerability row says why, as the button does, not that the button runs it', async () => {
    noRuns()
    scannerStore.set({ available: false })
    renderApp('/devices/a-nas01')
    const vuln = await screen.findByRole('group', { name: VULN }, T)
    expect(await within(vuln).findByText(/^The vulnerability scanner is not available/, {}, T)).toBeInTheDocument()
    expect(within(vuln).queryByText(/above runs it/)).toBeNull()
  })
})
