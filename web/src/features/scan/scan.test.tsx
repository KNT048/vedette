import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { toast } from 'sonner'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { server } from '@/test/server'
import { assetsStore, auditStore, findingsStore, modulesStore, sessionStore } from '@/mocks/stores'
import { engineStore, runs, scannerStore, timing } from './mocks'
import { runsPoll } from './api'
import type { ScanConfig, ScanRun } from './types'

// V1 does not offer the credentialed scan (no backend yet); its GUI is kept, so this file runs it as offered, and one test runs v1.
const credFlag = vi.hoisted(() => ({ CREDENTIALED_IN_UI: true }))
vi.mock('@/lib/credentialed', () => credFlag)

const base = () => `${location.origin}/api/v1`
const as = (userId: string) => sessionStore.set({ userId })
const json = (method: string, b: unknown) => ({ method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) })
const getRuns = async () => ((await (await fetch(`${base()}/scans/runs`)).json()) as { items: ScanRun[] }).items
const postRun = (targets: string[]) => fetch(`${base()}/scans/runs`, json('POST', { targets }))

timing.engineMs = 0 // the mock's engine is busy after Stop now only where a test says so
runsPoll.runningMs = 1000 // the page reads every 5 s while a scan runs (#830); the tests' mock scans last 2 s
afterEach(() => { timing.stepMs = 2000; timing.stopMs = 1000; timing.engineMs = 0; vi.useRealTimers(); localStorage.removeItem('vedette-mock-egress') })

describe('scan: the API never scans outside the scope (LEGAL §3)', () => {
  it('refuses an unapproved device, an unverified domain, an unknown entry, an empty list, and an overlapping scan', async () => {
    renderApp('/settings/scanning?tab=history')
    await screen.findByRole('table', { name: 'Auto rescan event log' }, { timeout: 4000 }) // the first test loads the page's code
    as('u-op')
    const bad = await postRun(['a-unk01'])
    expect(bad.status).toBe(400)
    expect((await bad.json()).error.message).toMatch(/has not been approved in the inventory, so it cannot be scanned/)
    const ext = await postRun(['ext:xt-3'])
    expect(ext.status).toBe(400)
    expect((await ext.json()).error.message).toMatch(/has no verified ownership/)
    const old = await postRun(['ext:xt-4'])
    expect(old.status).toBe(400)
    expect((await old.json()).error.message).toMatch(/verification expired, verify again/)
    expect((await postRun(['192.168.99.1'])).status).toBe(400)
    expect((await postRun([])).status).toBe(400)
    expect((await getRuns()).filter((r) => !r.id.startsWith('run-seed'))).toHaveLength(0)
    timing.stepMs = 60_000
    expect((await postRun(['a-nas02'])).status).toBe(201)
    const again = await postRun(['a-web01'])
    expect(again.status).toBe(409)
    expect((await again.json()).error.code).toBe('already_running')
  })

  it('a verified external target is not scanned in this build yet: 400 out_of_scope says so plainly, no run starts', async () => {
    renderApp('/settings/scanning?tab=history')
    await screen.findByRole('table', { name: 'Auto rescan event log' })
    as('u-op')
    const targets = (await (await fetch(`${base()}/scans/targets`)).json()).items as { id: string; kind: string; selectable: boolean; reason: string | null }[]
    expect(targets.filter((x) => x.kind === 'external').every((x) => !x.selectable)).toBe(true)
    expect(targets.find((x) => x.id === 'ext:xt-2')!.reason).toBe('not_supported')
    const res = await postRun(['ext:xt-2'])
    expect(res.status).toBe(400)
    const err = (await res.json()).error
    expect(err.code).toBe('out_of_scope')
    expect(err.message).toMatch(/is an external target, and this version does not scan external targets yet, so it cannot be scanned/)
    expect((await getRuns()).filter((r) => !r.id.startsWith('run-seed'))).toHaveLength(0)
  })

  it('a manual pick is consent for hand-declared devices that have network scanning on, fragile, unclassified, and the box itself; a "never" device never', async () => {
    const { ensureBox } = await import('@/features/inventory/mocks')
    ensureBox()
    assetsStore.update((l) => l.map((a) => (a.id === 'a-web01' ? { ...a, origin: 'manual' as const } : a.id === 'a-unk01' ? { ...a, approved: true } : a)))
    as('u-admin')
    expect((await fetch(`${base()}/inventory/devices/a-srvad`, json('PATCH', { regular_scan: 'never' }))).status).toBe(200)
    const items = (await (await fetch(`${base()}/scans/targets`)).json()).items as { id: string; label: string; fragile: boolean; selectable: boolean; reason: string | null }[]
    const byId = (id: string) => items.find((x) => x.id === id)!
    // Added by hand, its network scan off until a person turns it on: not even a pick; turned on, picked by hand
    expect(byId('a-web01')).toMatchObject({ selectable: false, reason: 'regular_scan_never' })
    expect((await fetch(`${base()}/inventory/devices/a-web01/sources`, json('PUT', { scan: 'on' }))).status).toBe(200)
    const again = (await (await fetch(`${base()}/scans/targets`)).json()).items as { id: string; selectable: boolean; reason: string | null }[]
    expect(again.find((x) => x.id === 'a-web01')).toMatchObject({ selectable: true, reason: null })
    expect(byId('a-nas02')).toMatchObject({ selectable: true, fragile: true })
    expect(byId('a-unk01')).toMatchObject({ selectable: true, fragile: true }) // unknown kind counts as fragile: a quarter of the speed
    expect(byId('a-box')).toMatchObject({ selectable: true, pick_only: true, box: true, reason: null }) // A person may scan the box
    expect(byId('a-srvad')).toMatchObject({ selectable: false, reason: 'regular_scan_never' }) // "never" set by a person is absolute
    as('u-op')
    expect((await (await postRun(['a-srvad'])).json()).error.message).toMatch(/is set to never be scanned in the inventory; change that setting first/)
    expect((await postRun(['a-box'])).status).toBe(201)
  })

  it('the scanner is not ready: can_scan=false with a reason, the button is locked, POST returns 503 scanner_unavailable', async () => {
    scannerStore.set({ available: false })
    as('u-admin')
    const cfg = await (await fetch(`${base()}/scans/config`)).json()
    expect(cfg.can_scan).toBe(false)
    expect(cfg.block_reason).toMatch(/^The vulnerability scanner is not available/)
    as('u-op')
    const res = await postRun(['a-nas02'])
    expect(res.status).toBe(503)
    expect((await res.json()).error.code).toBe('scanner_unavailable')
    expect((await getRuns()).filter((r) => !r.id.startsWith('run-seed'))).toHaveLength(0)
  })

  it('no run history: the Nuclei schedule note blames the real reason, not always the commitment', async () => {
    runs.set([])
    scannerStore.set({ available: false })
    renderApp('/settings/scanning?tab=engines#nuclei')
    const card = await screen.findByRole('listitem', { name: /Vulnerability checks \(Nuclei\)/ })
    expect(await within(card).findByText(/nothing runs while the vulnerability scanner is not available/)).toBeInTheDocument()
    expect(screen.queryByText(/until the scan scope commitment is ticked/)).not.toBeInTheDocument()
  })

  it('no run history and no commitment: the Nuclei schedule note asks for the commitment', async () => {
    const { inventorySettingsStore } = await import('@/features/inventory/mocks')
    inventorySettingsStore.update((s) => ({ ...s, scope_confirmed_at: null, scope_confirmed_by: null }))
    runs.set([])
    renderApp('/settings/scanning?tab=engines#nuclei')
    const card = await screen.findByRole('listitem', { name: /Vulnerability checks \(Nuclei\)/ })
    expect(await within(card).findByText(/nothing runs until the scan scope commitment is ticked/)).toBeInTheDocument()
  })

  it('a device in the exclusions is also refused when the API is called directly', async () => {
    renderApp('/settings/scanning?tab=history')
    await screen.findByRole('table', { name: 'Auto rescan event log' })
    as('u-admin')
    await fetch(`${base()}/scans/config`, json('PUT', { exclusions: ['192.168.10.0/24'] }))
    const res = await postRun(['a-web01'])
    expect(res.status).toBe(400)
    expect((await res.json()).error.message).toMatch(/is on the exclusion list/)
  })
})

describe('scan: scan now, progress, stop now (S-SCAN-4)', () => {
  it('scans one device to the end: the result goes into the shared finding, the audit, the probe log', async () => {
    timing.stepMs = 30
    as('u-admin')
    await postRun(['a-nas02']) // fragile: a person's own pick
    await waitFor(async () => expect((await getRuns())[0]!.status).toBe('done'), { timeout: 4000 })
    const run = (await getRuns())[0]!
    expect(run.results.map((r) => r.result)).toContain('matched')
    expect(run.started_by).toBe('admin@acme.example')
    const f = findingsStore.get().find((x) => x.id === 'f-1')!
    expect(f.history.at(-1)!.action).toBe('rescanned')
    expect(auditStore.get().some((a) => a.action === 'scan.start')).toBe(true)
    const probes = (await (await fetch(`${base()}/scans/probes`)).json()).items as { run_id: string | null; ip: string }[]
    expect(probes.some((p) => p.run_id === run.id && p.ip === '192.168.10.21')).toBe(true)
    // Scan now identifies first and says per device what it found or exactly why not (the NAS is fragile: gentle scan only)
    expect(run.identification).toEqual([expect.objectContaining({ target_id: 'a-nas02', reason: 'gentle_only', found: [] })])
    expect(run.results.find((r) => r.result === 'matched')!.finding_id).toBe('f-1')
  })

  it('already mitigated then rescanned: no match is just "no match reported", nothing changes on the finding', async () => {
    timing.stepMs = 30
    findingsStore.update((l) => l.map((f) => (f.id === 'f-1' ? { ...f, status: 'mitigated' as const } : f)))
    const before = findingsStore.get().find((x) => x.id === 'f-1')!.history.length
    as('u-admin')
    await postRun(['a-nas02']) // fragile: only a person's own pick (the device page's button) scans it
    await waitFor(async () => expect((await getRuns())[0]!.status).toBe('done'), { timeout: 4000 })
    const res = (await getRuns())[0]!.results[0]!
    expect(res.result).toBe('not_matched')
    expect(res.note).toBe('CVE-2022-27593: no match reported by the scan template.')
    const f = findingsStore.get().find((x) => x.id === 'f-1')!
    expect(f.status).toBe('mitigated')
    expect(f.history).toHaveLength(before) // nuclei reports matches only: "no match" never marks the finding
  })

  it('"Stop now": clicking stop runs "stopping" then "stopped" within 5 seconds, a device not yet scanned is not touched', async () => {
    timing.stepMs = 60_000
    timing.stopMs = 300
    as('u-admin')
    const started = (await (await postRun(['a-web01', 'a-srvad'])).json()) as ScanRun
    expect((await fetch(`${base()}/scans/runs/${started.id}/stop`, json('POST', {}))).status).toBe(200)
    expect((await getRuns())[0]!.status).toBe('stopping')
    const t0 = Date.now()
    await waitFor(async () => expect((await getRuns())[0]!.status).toBe('stopped'), { timeout: 5000 })
    expect(Date.now() - t0).toBeLessThan(5000)
    const run = (await getRuns())[0]!
    expect(run.stop_reason).toBe('You pressed Stop now.')
    expect(run.results.every((r) => r.result === 'skipped')).toBe(true)
    // the device being scanned when Stop now came: its requests on the way are in the probe log as stopped; the others have none
    const probes = ((await (await fetch(`${base()}/scans/probes`)).json()).items as { run_id: string | null; result: string }[]).filter((p) => p.run_id === run.id)
    expect(probes.length).toBeGreaterThan(0)
    expect(probes.every((p) => p.result === 'stopped')).toBe(true)
    expect(findingsStore.get().find((x) => x.id === 'f-1')!.history.some((h) => h.action === 'rescanned')).toBe(false)
    expect(auditStore.get().some((a) => a.action === 'scanning.run_stop')).toBe(true)
  })

  it('stopping a finished scan reports a clear error; stopping twice is not an error', async () => {
    renderApp('/settings/scanning?tab=history')
    await screen.findByRole('table', { name: 'Auto rescan event log' })
    as('u-op')
    const seeded = (await getRuns())[0]!
    const res = await fetch(`${base()}/scans/runs/${seeded.id}/stop`, json('POST', {}))
    expect(res.status).toBe(409)
    expect((await res.json()).error.code).toBe('not_running')
    expect((await fetch(`${base()}/scans/runs/run-nope/stop`, json('POST', {}))).status).toBe(404)
    timing.stepMs = 60_000
    timing.stopMs = 60_000
    const run = (await (await postRun(['a-nas02'])).json()) as ScanRun
    expect((await fetch(`${base()}/scans/runs/${run.id}/stop`, json('POST', {}))).status).toBe(200)
    expect((await fetch(`${base()}/scans/runs/${run.id}/stop`, json('POST', {}))).status).toBe(200)
    expect((await getRuns())[0]!.status).toBe('stopping')
  })

  it('a device that does not answer: with auto-stop on it stops with a reason; off, it is skipped and the scan continues', async () => {
    timing.stepMs = 30
    renderApp('/settings/scanning?tab=history')
    await screen.findByRole('table', { name: 'Auto rescan event log' })
    as('u-op')
    await postRun(['a-web01', 'a-cam03', 'a-nas02'])
    await waitFor(async () => expect((await getRuns())[0]!.status).toBe('auto_stopped'), { timeout: 4000 })
    const stopped = (await getRuns())[0]!
    expect(stopped.stop_reason).toMatch(/CAM-LOBBY \(192\.168\.20\.13\) stopped responding after 3 failed requests/)
    expect(stopped.done).toBe(1)
    expect(stopped.results.find((r) => r.label === 'NAS-PHOTOS')!.result).toBe('skipped')
    expect(stopped.results.find((r) => r.label === 'CAM-LOBBY')!.result).toBe('no_response')
    as('u-admin')
    await fetch(`${base()}/scans/config`, json('PUT', { stop_on_unresponsive: false }))
    await postRun(['a-web01', 'a-cam03', 'a-nas02'])
    await waitFor(async () => expect((await getRuns())[0]!.status).toBe('done'), { timeout: 4000 })
    const full = (await getRuns())[0]!
    expect(full.results.map((r) => r.result)).toContain('no_response')
    expect(full.results.find((r) => r.label === 'NAS-PHOTOS')!.result).toBe('matched')
  })

  it('a view-only role cannot scan or stop', async () => {
    as('u-view')
    const res = await postRun(['a-nas02'])
    expect(res.status).toBe(403)
  })

  it('the seeded scheduled and KEV runs, and the seeded rescan matches, never touch a device that needs a hand pick', async () => {
    renderApp('/settings/scanning?tab=history')
    await screen.findByRole('table', { name: 'Auto rescan event log' })
    const targets = (await (await fetch(`${base()}/scans/targets`)).json()).items as { id: string; label: string; pick_only: boolean }[]
    const pick = targets.filter((x) => x.pick_only)
    expect(pick.length).toBeGreaterThan(0)
    const auto = (await getRuns()).filter((r) => r.trigger !== 'manual')
    expect(auto.map((r) => r.trigger).sort()).toEqual(['new_kev', 'schedule'])
    for (const r of auto) expect(r.results.map((x) => x.target_id).filter((id) => pick.some((p) => p.id === id)), r.id).toEqual([])
    const events = ((await (await fetch(`${base()}/scans/events`)).json()) as { items: { result: string; devices: string[] }[] }).items
    for (const e of events.filter((x) => x.result === 'matched')) expect(e.devices.filter((d) => pick.some((p) => p.label === d))).toEqual([])
  })

  it('the rescan log lists every automatic rescan with its result; a stopped one links its run', async () => {
    renderApp('/settings/scanning?tab=history')
    const table = await screen.findByRole('table', { name: 'Auto rescan event log' })
    const events = ((await (await fetch(`${base()}/scans/events`)).json()) as { items: { cve: string; run_id: string | null; result: string }[] }).items
    expect(events.length).toBeGreaterThan(0)
    for (const e of events) expect(within(table).getAllByRole('link', { name: e.cve }).length).toBeGreaterThan(0)
    const stopped = events.find((e) => e.result === 'stopped' && e.run_id)
    if (stopped) expect(within(table).getByRole('link', { name: 'see the run' })).toHaveAttribute('href', expect.stringContaining(stopped.run_id!))
    await expectNoA11yViolations(table)
  })
})

describe('scan: schedule and safety (S-SCAN-4)', () => {
  it('shows the current setup, the next scan, and says plainly there is no exploitation and no DoS; no a11y errors', async () => {
    renderApp('/settings/scanning?tab=safety')
    expect(await screen.findByLabelText('From')).toHaveValue('22:00')
    expect(screen.getByLabelText('Until')).toHaveValue('05:00')
    expect(screen.getByLabelText('Vulnerability checks on the LAN')).toHaveValue('5') // The shared block (inventory stores it)
    expect(screen.getByLabelText('Discovery and SNMP')).toHaveValue('50')
    expect(screen.getByText('No changes, no denial of service')).toBeInTheDocument()
    expect(screen.getByText(/Never guesses passwords/)).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('#860: the shared block sends the version it read; a save over settings changed elsewhere is refused, says so, and shows the stored values', async () => {
    const { inventorySettingsStore } = await import('@/features/inventory/mocks')
    const puts: Array<Record<string, unknown>> = []
    server.events.on('request:start', async ({ request }) => {
      if (request.method === 'PUT' && request.url.endsWith('/scanning/safety')) puts.push(await request.clone().json() as Record<string, unknown>)
    })
    renderApp('/settings/scanning?tab=safety')
    await userEvent.selectOptions(await screen.findByLabelText('Vulnerability checks on the LAN'), '2')
    inventorySettingsStore.update((st) => ({ ...st, active: { ...st.active, exclusions: [...st.active.exclusions, '192.168.10.40'] } })) // an inline add elsewhere
    await userEvent.click(screen.getByRole('button', { name: 'Save settings' }))
    expect(await screen.findByText(/Someone else saved these settings/)).toBeInTheDocument()
    expect(puts[0]?.version).toEqual(expect.any(String))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Remove exclusion 192.168.10.40' })).toBeInTheDocument()) // the form was built again on the stored values
    expect(screen.getByLabelText('Vulnerability checks on the LAN')).toHaveValue('2') // and keeps what was typed (#877)
    await userEvent.selectOptions(screen.getByLabelText('Vulnerability checks on the LAN'), '2')
    await userEvent.click(screen.getByRole('button', { name: 'Save settings' }))
    expect(await screen.findByText('Safety settings saved')).toBeInTheDocument()
    expect(puts[1]?.version).not.toBe(puts[0]?.version)
    server.events.removeAllListeners()
    toast.dismiss() // the toasts outlive this page: the next test looks for its own
    await waitFor(() => expect(screen.queryByText('Safety settings saved')).toBeNull())
  })

  it('saves the rate and exclusions: stored durably, audited, still there after reopening', async () => {
    const view = renderApp('/settings/scanning?tab=safety')
    await userEvent.selectOptions(await screen.findByLabelText('Vulnerability checks on the LAN'), '2')
    const { inventorySettingsStore } = await import('@/features/inventory/mocks')
    for (const x of inventorySettingsStore.get().active.exclusions) await userEvent.click(screen.getByRole('button', { name: `Remove exclusion ${x}` }))
    for (const x of ['192.168.10.250', '192.168.20.0/24']) {
      await userEvent.click(screen.getByRole('button', { name: 'Add exclusion' }))
      const dlg = within(await screen.findByRole('dialog', { name: 'Add an exclusion' }))
      await userEvent.type(dlg.getByLabelText('IP address or network'), x)
      await userEvent.click(dlg.getByRole('button', { name: 'Add exclusion' }))
    }
    await userEvent.click(screen.getByRole('button', { name: 'Save settings' }))
    expect(await screen.findByText('Safety settings saved')).toBeInTheDocument()
    as('u-admin')
    const safety = (await (await fetch(`${base()}/scanning`)).json()).safety as { speed: { requests_per_s: number }; exclusions: string[] }
    expect(safety.speed.requests_per_s).toBe(2)
    expect(safety.exclusions).toEqual(['192.168.10.250', '192.168.20.0/24'])
    expect(auditStore.get().some((a) => a.action === 'inventory.settings')).toBe(true)
    view.unmount()
    renderApp('/settings/scanning?tab=safety')
    expect(await screen.findByLabelText('Vulnerability checks on the LAN')).toHaveValue('2')
  })

  it('a wrong exclusion is refused in its dialog, which says how to write it; the box refuses it too', async () => {
    renderApp('/settings/scanning?tab=safety')
    await userEvent.click(await screen.findByRole('button', { name: 'Add exclusion' }))
    const dlg = within(await screen.findByRole('dialog', { name: 'Add an exclusion' }))
    await userEvent.type(dlg.getByLabelText('IP address or network'), 'may-in')
    await userEvent.click(dlg.getByRole('button', { name: 'Add exclusion' }))
    expect(await dlg.findByText(/Enter one IP \(192\.168\.10\.10\)/)).toBeInTheDocument()
    as('u-admin')
    const sf = (await (await fetch(`${base()}/scanning`)).json()).safety as { scope: { lan_ranges: string[] }; window: { days: number[]; from: string; to: string }; speed: unknown; fragile: { kinds: string[]; regular_scan_kinds: string[] }; version: string }
    const r = await fetch(`${base()}/scanning/safety`, json('PUT', { scope: { lan_ranges: sf.scope.lan_ranges, confirmed: true }, window: { days: sf.window.days, from: sf.window.from, to: sf.window.to }, speed: sf.speed, exclusions: ['may-in'], fragile: sf.fragile, version: sf.version }))
    expect(((await r.json()) as { error: { message: string } }).error.message).toMatch(/Exclusion "may-in" is not valid/)
  })

  it('the day of week is 1 to 7 (Monday = 1, Sunday = 7)', async () => {
    renderApp('/settings/scanning?tab=safety')
    await screen.findByLabelText('From')
    expect(screen.getAllByRole('checkbox', { name: /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)$/ }).map((c) => c.getAttribute('id'))).toEqual(['day-1', 'day-2', 'day-3', 'day-4', 'day-5', 'day-6', 'day-7'])
    as('u-admin')
    const put = (b: unknown) => fetch(`${base()}/scans/config`, json('PUT', b))
    expect((await put({ window: { days: [0] } })).status).toBe(400) // the old Sunday = 0 is refused
    expect((await put({ window: { days: [8] } })).status).toBe(400)
  })

  it('the regular checks use the shared schedule editor on their card', async () => {
    renderApp('/settings/scanning?tab=engines#nuclei')
    expect(await screen.findByText('Weekly on Sun at 23:00, in the scan window', undefined, { timeout: 3000 })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Change the schedule of Vulnerability checks' })).toBeEnabled()
    // the card's own Run button starts the checks: the schedule line has no second one
    expect(screen.queryByRole('button', { name: 'Run Vulnerability checks now' })).toBeNull()
    cleanup()
    renderApp('/settings/scanning?tab=engines#nmap-discovery')
    expect(await screen.findByText('Daily at 22:00, in the scan window', undefined, { timeout: 3000 })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Change the schedule of LAN sweep' })).toBeEnabled()
  })

  it('the API checks at the edge and does not allow turning on a dangerous test', async () => {
    renderApp('/settings/scanning?tab=history')
    await screen.findByRole('table', { name: 'Auto rescan event log' })
    as('u-admin')
    const put = (b: unknown) => fetch(`${base()}/scans/config`, json('PUT', b))
    const danger = await put({ dangerous_checks: true })
    expect(danger.status).toBe(400)
    expect((await danger.json()).error.message).toMatch(/no exploitation, no denial of service/)
    expect((await put({ window: { days: [] } })).status).toBe(400)
    expect((await put({ window: { from: '22:00', to: '22:00' } })).status).toBe(400)
    expect((await put({ window: { from: '25:00' } })).status).toBe(400)
    expect((await put({ rate: 500 })).status).toBe(400)
    expect((await put({ unresponsive_after: 1 })).status).toBe(400)
    expect((await put({ exclusions: ['1.2.3.4/99'] })).status).toBe(400)
    expect((await put({ rate: 10 })).status).toBe(200)
  })

  it('an operator role can view but not change the setup', async () => {
    renderApp('/settings/scanning?tab=safety', { role: 'operator' })
    expect(await screen.findByText(/Only an administrator can change these settings/)).toBeInTheDocument()
    expect(screen.getByLabelText('Vulnerability checks on the LAN')).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Save settings' })).toBeDisabled()
    expect((await fetch(`${base()}/scans/config`, json('PUT', { rate: 1 }))).status).toBe(403)
    expect((await fetch(`${base()}/scanning/safety`, json('PUT', {}))).status).toBe(403)
  })
})

describe('scan: rescans itself when a new KEV appears (S-SCAN-2)', () => {
  it('the event log from the real KEV, the CVE links back to the lookup page; no a11y errors', async () => {
    renderApp('/settings/scanning?tab=history')
    const table = await screen.findByRole('table', { name: 'Auto rescan event log' })
    expect(within(table).getAllByRole('link', { name: /^CVE-/ })[0]!.getAttribute('href')).toMatch(/^\/cve\/CVE-/)
    expect(within(table).getAllByText('Matches, alerted').length).toBeGreaterThan(0)
    expect(within(table).getByText('Not scanned: no matching device')).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('a rescan with no match says "No match reported" in a neutral tone, never "Not affected"', async () => {
    const ev = { id: 'ev-clear', ts: new Date().toISOString(), cve: 'CVE-2026-0002', product: 'Acme NAS', devices: ['nas02'], latency_min: 12, run_id: 'run-1', result: 'clear' }
    server.use(http.get('*/api/v1/scans/events', () => HttpResponse.json({ items: [ev], auto_rescan: true })))
    renderApp('/settings/scanning?tab=history')
    const table = await screen.findByRole('table', { name: 'Auto rescan event log' })
    const chip = await within(table).findByText('No match reported')
    expect(chip.className).toContain('text-off')
    expect(within(table).queryByText('Not affected')).toBeNull()
  })

  it('devices that need a hand pick are named with a link to Scan now; a stopped rescan links to its run', async () => {
    const base = { ts: new Date().toISOString(), product: 'Acme NAS', latency_min: null }
    server.use(http.get('*/api/v1/scans/events', () => HttpResponse.json({ auto_rescan: true, items: [
      { ...base, id: 'ev-pick', cve: 'CVE-2026-0003', devices: ['NAS-PHOTOS', 'CAM-03'], run_id: null, result: 'pick_only' },
      { ...base, id: 'ev-stop', cve: 'CVE-2026-0004', devices: ['WEB01'], latency_min: 4, run_id: 'run-seed-3', result: 'stopped' },
    ] })))
    renderApp('/settings/scanning?tab=history')
    const table = await screen.findByRole('table', { name: 'Auto rescan event log' })
    const pick = await within(table).findByText(/^Not scanned automatically: 2 devices need a hand pick on/)
    expect(pick.className).toContain('text-off')
    expect(within(table).getByText('NAS-PHOTOS, CAM-03')).toBeInTheDocument()
    expect(within(table).getByRole('link', { name: 'Devices' })).toHaveAttribute('href', '/devices') // #850: Scan selected is on the Devices list
    expect(within(table).getByText(/^Stopped before the end:/).className).toContain('text-off')
    await expectNoA11yViolations()
    // the run opens on its own page, with why it stopped
    await userEvent.click(within(table).getByRole('link', { name: 'see the run' }))
    expect(await screen.findByRole('heading', { level: 1, name: /Vulnerability checks of/ }, { timeout: 4000 })).toBeInTheDocument()
    expect(await screen.findByText(/^Stopped: You pressed Stop now\./, {}, { timeout: 4000 })).toBeInTheDocument() // the run's own line, from the box
  })

  it('a rescan dropped after 7 days stays in the log with the reason', async () => {
    const base0 = { ts: new Date().toISOString(), product: 'Acme NAS', devices: [], latency_min: null, run_id: null }
    server.use(http.get('*/api/v1/scans/events', () => HttpResponse.json({ auto_rescan: true, items: [
      { ...base0, id: 'ev-a', cve: 'CVE-2026-0006', result: 'expired_no_template' },
      { ...base0, id: 'ev-b', cve: 'CVE-2026-0007', result: 'expired_scanner' },
      { ...base0, id: 'ev-c', cve: 'CVE-2026-0008', result: 'expired_zone' },
    ] })))
    renderApp('/settings/scanning?tab=history')
    const table = await screen.findByRole('table', { name: 'Auto rescan event log' })
    expect((await within(table).findByText('Not scanned for 7 days: the scan template never arrived')).className).toContain('text-off')
    expect(within(table).getByText('Not scanned for 7 days: the scanner was not available')).toBeInTheDocument()
    expect(within(table).getByText('Not scanned for 7 days: the time zone of the organization could not be read')).toBeInTheDocument()
    expect(within(table).queryByText('No matching device')).toBeNull()
    await expectNoA11yViolations()
  })

  it('the seed has a dropped event with its reason', async () => {
    renderApp('/settings/scanning?tab=history')
    const table = await screen.findByRole('table', { name: 'Auto rescan event log' })
    expect(await within(table).findByText('Not scanned for 7 days: the scan template never arrived')).toBeInTheDocument()
  })

  it('after Stop now, while the scanner is still busy, Scan now is locked with the reason and a start is refused', async () => {
    engineStore.set({ busyUntil: Date.now() + 60_000 })
    as('u-admin')
    expect((await (await fetch(`${base()}/scans/runs`)).json()).engine_busy).toBe(true)
    as('u-op')
    const res = await postRun(['a-nas02'])
    expect(res.status).toBe(409)
    expect((await res.json()).error.code).toBe('already_running')
    engineStore.set({ busyUntil: 0 })
    expect((await (await fetch(`${base()}/scans/runs`)).json()).engine_busy).toBe(false)
    expect((await postRun(['a-nas02'])).status).toBe(201)
  })

  it('an admin can turn it off, with an explanatory note; an operator cannot', async () => {
    const view = renderApp('/settings/scanning?tab=engines#nuclei')
    await userEvent.click(await screen.findByRole('switch', { name: 'Rescan automatically when a new KEV has a scan template' }))
    expect(await screen.findByText(/Off: new vulnerabilities will not be rescanned automatically/)).toBeInTheDocument()
    expect(((await (await fetch(`${base()}/scans/config`)).json()).config as ScanConfig).auto_rescan).toBe(false)
    expect(auditStore.get().some((a) => a.action === 'scan.config')).toBe(true)
    view.unmount()
    renderApp('/settings/scanning?tab=engines#nuclei', { role: 'operator' })
    expect(await screen.findByRole('switch', { name: 'Rescan automatically when a new KEV has a scan template' })).toBeDisabled()
  })
})

describe('scan: probe log (S-SCAN-4)', () => {
  it('lists the target, the time, the template; says plainly it is kept at least 90 days; can be filtered; CSV download', async () => {
    renderApp('/settings/scanning?tab=probes')
    const table = await screen.findByRole('table', { name: 'Probe log' })
    expect(await screen.findByText(/Kept for at least 90 days\. \d+ lines now, oldest from/)).toBeInTheDocument()
    expect(within(table).getAllByText('NAS-PHOTOS').length).toBeGreaterThan(0)
    expect(within(table).getAllByText('http/cves/2022/CVE-2022-27593.yaml').length).toBeGreaterThan(0)
    const rows = within(table).getAllByRole('row').length
    await userEvent.type(screen.getByRole('searchbox', { name: 'Filter by target, template, result' }), 'CAM-LOBBY')
    await waitFor(() => expect(within(screen.getByRole('table')).getAllByRole('row').length).toBeLessThan(rows))
    const csv = await fetch(`${base()}/scans/probes.csv`)
    expect(csv.headers.get('Content-Disposition')).toContain('attachment; filename=vedette-probe-log.csv')
    expect((await csv.text()).split('\n')[0]).toBe('time,target,name,template,request,result')
    await expectNoA11yViolations()
  })

  it('the CSV does not let a spreadsheet read a device name as a formula (the name comes from the network)', async () => {
    timing.stepMs = 30
    assetsStore.update((l) => l.map((a) => (a.id === 'a-nas02' ? { ...a, hostname: '=HYPERLINK("http://x","y")' } : a)))
    as('u-op')
    await postRun(['a-nas02'])
    await waitFor(async () => expect((await getRuns())[0]!.status).toBe('done'), { timeout: 4000 })
    const lines = (await (await fetch(`${base()}/scans/probes.csv`)).text()).split('\n')
    expect(lines.some((l) => l.includes(`"'=HYPERLINK(""http://x"",""y"")"`))).toBe(true)
    expect(lines.some((l) => /,"=/.test(l))).toBe(false)
  })

  it('the seed keeps records older than 80 days (nothing is deleted before 90 days)', async () => {
    renderApp('/settings/scanning?tab=history')
    await screen.findByRole('table', { name: 'Auto rescan event log' })
    const items = (await (await fetch(`${base()}/scans/probes`)).json()) as { items: { ts: string }[]; retention_days: number }
    expect(items.retention_days).toBe(90)
    expect(Date.now() - Date.parse(items.items.at(-1)!.ts)).toBeGreaterThan(80 * 864e5)
  })
})

const KEY = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACD1234567890abcdefGHIJKLMNOPQRSTUVWXYZQk2f\n-----END OPENSSH PRIVATE KEY-----'

describe('scan: credentialed scan (S-SCAN-5)', () => {
  const enable = () => modulesStore.update((l) => l.map((m) => (m.id === 'scan-credentialed' ? { ...m, enabled: true } : m)))
  /** Adding a server opens a dialog over the list; this opens it and gives back its server select. */
  const openAddServer = async () => { await userEvent.click(await screen.findByRole('button', { name: 'Add a server' })); return screen.findByLabelText('Target server') }

  it('v1 offers no Credentialed scan tab: the feature has no backend in this build', async () => {
    credFlag.CREDENTIALED_IN_UI = false
    try {
      enable()
      renderApp('/settings/scanning?tab=history')
      expect(await screen.findByRole('tab', { name: 'Safety' })).toBeInTheDocument()
      expect(screen.queryByRole('tab', { name: 'Credentialed scan' })).toBeNull()
    } finally { credFlag.CREDENTIALED_IN_UI = true }
  })

  it('the module is off by default: says so plainly and points where to turn it on', async () => {
    renderApp('/settings/scanning?tab=credentialed')
    expect(await screen.findByText('Credentialed scan module is off')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Open module settings' })).toHaveAttribute('href', '/settings/modules#module-scan-credentialed')
  })

  it('shows the target machine preparation guide, one frame per command; no a11y errors', async () => {
    enable()
    renderApp('/settings/scanning?tab=credentialed')
    expect(await screen.findByText('No server is scanned with an account yet.')).toBeInTheDocument()
    await userEvent.click(screen.getByText('Prepare a Linux target (Debian, Ubuntu)'))
    const codes = [...document.querySelectorAll('pre code')].map((c) => c.textContent)
    expect(codes).toContain('ssh-keygen -t ed25519 -f vedette_scan_key -C "vedette-scan" -N ""')
    expect(codes).toContain('sudo adduser --disabled-password --gecos "" vedette-scan')
    await expectNoA11yViolations()
  })

  it('a device whose type acts as server (a virtual machine) stays an SSH candidate', async () => {
    enable()
    assetsStore.update((l) => l.map((a) => (a.id === 'a-web01' ? { ...a, kind: 'virtual_machine' } : a)))
    renderApp('/settings/scanning?tab=credentialed')
    const select = await openAddServer()
    expect(within(select).getByRole('option', { name: /192\.168\.10\.12/ })).toHaveValue('a-web01')
  })

  it('adds a server with a private key: only the last 4 characters show, the key is not stored or returned; test the connection; delete', async () => {
    enable()
    renderApp('/settings/scanning?tab=credentialed')
    await userEvent.selectOptions(await openAddServer(), 'a-web01')
    const key = screen.getByLabelText('SSH private key')
    await userEvent.click(key)
    await userEvent.paste(KEY)
    await userEvent.click(screen.getByRole('button', { name: 'Save key' }))
    expect(await screen.findByText('Key saved, ends with ••••Qk2f')).toBeInTheDocument()
    const table = await screen.findByRole('table', { name: 'Servers scanned with an account' })
    expect(within(table).getByText('ends with ••••Qk2f')).toBeInTheDocument()
    expect(within(table).getByText('vedette-scan@192.168.10.12:22')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('b3BlbnNzaC1rZXktdjEAAAAABG5v')
    const list = await (await fetch(`${base()}/scans/credentialed`)).text()
    expect(list).not.toContain('b3BlbnNzaC1rZXktdjE')
    expect(list).not.toContain('PRIVATE KEY')
    const { collection } = await import('@/mocks/db')
    expect(JSON.stringify(collection('scc_target', () => []).get())).not.toContain('b3BlbnNzaC1rZXktdjE')
    expect(auditStore.get().some((a) => a.action === 'scan.credentialed.add')).toBe(true)

    await userEvent.click(within(table).getByRole('button', { name: 'Check connection to WEB01' }))
    expect(await within(table).findByText('Connected')).toBeInTheDocument()
    expect(within(table).getByText(/the target accepted the key ending in Qk2f/)).toBeInTheDocument()

    await userEvent.click(within(table).getByRole('button', { name: 'Remove the scan account of WEB01' }))
    const dlg = await screen.findByRole('dialog', { name: 'Remove the scan account of WEB01?' })
    await userEvent.click(within(dlg).getByRole('button', { name: 'Remove' }))
    expect(await screen.findByText('No server is scanned with an account yet.')).toBeInTheDocument()
  })

  it('a failed connection test says plainly what to check', async () => {
    enable()
    renderApp('/settings/scanning?tab=credentialed')
    await userEvent.selectOptions(await openAddServer(), 'a-srvad')
    await userEvent.click(screen.getByLabelText('SSH private key'))
    await userEvent.paste(KEY)
    await userEvent.click(screen.getByRole('button', { name: 'Save key' }))
    const table = await screen.findByRole('table', { name: 'Servers scanned with an account' })
    await userEvent.click(within(table).getByRole('button', { name: 'Check connection to SRV-AD' }))
    expect(await within(table).findByText('Cannot connect')).toBeInTheDocument()
    expect(within(table).getByText(/Check that the SSH service is running and the firewall allows the Vedette box 192\.168\.10\.250/)).toBeInTheDocument()
  })

  it('checks at the edge: a public key, a wrong key, the port, the account, a duplicate, out of scope', async () => {
    enable()
    renderApp('/settings/scanning?tab=credentialed')
    await screen.findByRole('button', { name: 'Add a server' })
    as('u-admin')
    const add = (b: object) => fetch(`${base()}/scans/credentialed`, json('POST', { asset_id: 'a-web01', port: 22, username: 'vedette-scan', private_key: KEY, ...b }))
    const pub = await add({ private_key: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc vedette' })
    expect(pub.status).toBe(400)
    expect((await pub.json()).error.message).toMatch(/This is a public key/)
    expect((await (await add({ private_key: 'abc' })).json()).error.code).toBe('bad_key')
    expect((await add({ private_key: 'x'.repeat(17_000) })).status).toBe(400)
    expect((await (await add({ port: 70000 })).json()).error.code).toBe('bad_port')
    expect((await (await add({ username: 'Root User' })).json()).error.code).toBe('bad_username')
    expect((await (await add({ asset_id: 'a-unk01' })).json()).error.message).toMatch(/has not been approved/)
    expect((await (await add({ asset_id: 'ext:acme.example' })).json()).error.code).toBe('unknown_host')
    expect((await add({})).status).toBe(201)
    expect((await add({})).status).toBe(409)
  })

  it('an operator role can test the connection but not add or delete; view only can do nothing', async () => {
    enable()
    renderApp('/settings/scanning?tab=credentialed', { role: 'operator' })
    const open = await screen.findByRole('button', { name: 'Add a server' })
    expect(open).toBeDisabled()
    expect(open).toHaveAttribute('title', 'Requires Admin role')
    as('u-view')
    expect((await fetch(`${base()}/scans/credentialed`, json('POST', { asset_id: 'a-web01', port: 22, username: 'x', private_key: KEY }))).status).toBe(403)
  })

  it('the key file is read through the file picker', async () => {
    enable()
    renderApp('/settings/scanning?tab=credentialed')
    await openAddServer()
    const input = screen.getByLabelText('SSH private key file') as HTMLInputElement
    await userEvent.upload(input, new File([KEY], 'vedette_scan_key', { type: 'text/plain' }))
    expect(await screen.findByText('Read file vedette_scan_key')).toBeInTheDocument()
  })
})
