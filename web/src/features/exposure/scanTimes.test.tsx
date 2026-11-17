import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { server } from '@/test/server'

// The viewer's time zone, never the box's: pinned to one that is not UTC (CI runs in UTC). 14:29 UTC is 21:29 in Ho Chi Minh City.
let tz: string | undefined
beforeAll(() => { tz = process.env.TZ; process.env.TZ = 'Asia/Ho_Chi_Minh' })
afterAll(() => { if (tz === undefined) delete process.env.TZ; else process.env.TZ = tz })
// The page's clock: 17 Nov 2026, 16:00 UTC (23:00 local), so the scans below are hours old, within the 24 hours of OpenVAS again
beforeEach(() => { vi.useFakeTimers({ toFake: ['Date'], shouldAdvanceTime: true }); vi.setSystemTime(new Date('2026-11-17T16:00:00.000Z')) })
afterEach(() => vi.useRealTimers())

const ip = '203.0.113.10'
const started = '2026-11-17T14:20:00.000Z' // the scan's start: 21:20 local
const stored = '2026-11-17T14:29:00.000Z' // the other results stored, OpenVAS starts: 21:29 local
const stoppedAt = '2026-11-17T15:43:00.000Z' // 22:43 local
type Run = Record<string, unknown> & { state: string }
const snapshotOf = (run: Run, more: Record<string, unknown> = {}) => ({
  id: 'sn-g', date: '2026-11-17', scanned_at: stored, started_at: started, finished_at: stoppedAt, hosts: [],
  ports: [{ ip, port: 443, service: 'https' }, { ip, port: 22, service: 'ssh' }], admin_panels: [], certs: [],
  counts: { subdomains: 0, ips: 1, ports: 2, admin_panels: 0, certs_expiring: 0 }, services: [], templates: [], web_findings: [], vulns: [], version_gaps: [], checks: [],
  not_checked: [{ kind: 'greenbone', text: 'OpenVAS was stopped before it finished (Vedette shut down: an update, a restart or a stop of the service), so its results are not shown. The results of the other checks above are kept.' }],
  greenbone: [], greenbone_run: { addresses: [], started_at: stored, ...run }, ...more,
})
const older = { id: 'sn-o', date: '2026-11-16', scanned_at: '2026-11-16T23:25:00.000Z', started_at: '2026-11-16T23:20:00.000Z', finished_at: '2026-11-17T01:38:00.000Z', counts: { subdomains: 0, ips: 1, ports: 2, admin_panels: 0, certs_expiring: 0 } }

const again = { id: 'sr-a', target_id: 'xt-2', target_value: ip, by: 'op@acme.example', started_at: stoppedAt, finished_at: null, status: 'running', phase: 'greenbone', snapshot_id: null, error: null, progress: null, openvas_only: true }

const openvasReady = { state: 'ready', reason: null, changed_by: null, changed_at: null, enabled: true, feed: null,
  preflight: { memory_bytes: 16e9, disk_free_bytes: 180e9, ok: true, reason: null }, feed_sync: { last_at: null, ok: null, note: null, next_at: null } }

/** The target as the mock lists it, scanned at `started`, with the testing terms accepted unless `terms` is false. */
function targetIs(patch: Record<string, unknown> = {}) {
  server.use(http.get('*/api/v1/exposure/targets/xt-2', async () => {
    const r = await fetch(`${location.origin}/api/v1/exposure/targets`).then((x) => x.json()) as { items: { id: string }[] }
    return HttpResponse.json({ ...r.items.find((x) => x.id === 'xt-2'), last_scan_at: started, last_scan_finished_at: stoppedAt, full_scan: true, blocked_reason: null, scannable: true, ...patch })
  }))
}

function serve(snap: ReturnType<typeof snapshotOf>, openvas: Record<string, unknown> = openvasReady) {
  const posted: string[] = []
  targetIs()
  server.use(
    http.get('*/api/v1/exposure/greenbone', () => HttpResponse.json(openvas)),
    http.get('*/api/v1/exposure/targets/xt-2/snapshots', () => HttpResponse.json({ items: [{ id: snap.id, date: snap.date, scanned_at: snap.scanned_at, started_at: snap.started_at, finished_at: snap.finished_at, counts: snap.counts }, older] })),
    http.get('*/api/v1/exposure/targets/xt-2/snapshots/:date', ({ params }) => HttpResponse.json(params.date === snap.date ? snap : { ...snapshotOf({ state: 'done', ended_at: older.finished_at }), ...older })),
    http.post('*/api/v1/exposure/targets/:id/openvas', ({ params }) => {
      posted.push(String(params.id))
      return HttpResponse.json(again, { status: 202 })
    }),
    // the page follows it like a scan
    http.get('*/api/v1/exposure/scan', () => HttpResponse.json(posted.length > 0 ? again : null)),
  )
  return posted
}
// the first page of a file loads its route code first: give it the time a cold start takes on a busy runner
const section = () => screen.findByRole('region', { name: 'OpenVAS results (unauthenticated, QoD ≥ 70)' }, { timeout: 5000 })

describe('exposure: an OpenVAS step that was stopped says why and when, and runs again on its own', () => {
  it.each([
    [{ reason: 'shutdown', by: null }, 'Stopped at 17 Nov 2026, 22:43: Vedette shut down while OpenVAS ran (an update, a restart or a stop of the service).'],
    [{ reason: 'person', by: 'op@acme.example' }, 'Stopped at 17 Nov 2026, 22:43: op@acme.example pressed Stop.'],
    [{ reason: 'restart', by: null }, 'Stopped: Vedette restarted while OpenVAS ran. It noticed when it started again at 17 Nov 2026, 22:43.'],
    [{ reason: 'module_off', by: null }, 'Stopped at 17 Nov 2026, 22:43: the External exposure module was switched off.'],
    [{ reason: 'terms', by: 'owner@acme.example' }, 'Stopped at 17 Nov 2026, 22:43: owner@acme.example withdrew or lowered the testing terms of this target.'],
  ])('%o', async (stop, line) => {
    serve(snapshotOf({ state: 'stopped', ended_at: stoppedAt, stop }))
    renderApp('/exposure/xt-2')
    const s = await section()
    expect(await within(s).findByText('OpenVAS was stopped before it finished')).toBeInTheDocument()
    expect(within(s).getByText(`${line} Its results are not shown. The results of the other checks above are kept.`)).toBeInTheDocument()
    expect(within(s).getByText('OpenVAS started at 17 Nov 2026, 21:29.')).toBeInTheDocument()
  })

  it.each([
    [{ ended_at: stoppedAt }, 'Stopped at 17 Nov 2026, 22:43. This scan is older than the version of Vedette that records why: someone pressed Stop, Vedette shut down, the External exposure module was switched off, or the testing terms were withdrawn.'],
    [{}, 'Stopped before it finished. This scan is older than the version of Vedette that records why and when: someone pressed Stop, Vedette shut down or restarted, the External exposure module was switched off, or the testing terms were withdrawn.'],
  ])('a step stopped before the reason was recorded says so, with its stop time when known: %o', async (end, line) => {
    serve(snapshotOf({ state: 'stopped', ...end }, { not_checked: [{ kind: 'greenbone', text: 'OpenVAS was stopped before it finished, so its results are not shown. The results of the other checks above are kept.' }] }))
    renderApp('/exposure/xt-2')
    const s = await section()
    expect(await within(s).findByText(`${line} Its results are not shown. The results of the other checks above are kept.`)).toBeInTheDocument()
    expect(within(s).getByText('OpenVAS started at 17 Nov 2026, 21:29.')).toBeInTheDocument()
  })

  it('an operator runs only OpenVAS again for the newest scan, on the ports it found; axe clean', async () => {
    const posted = serve(snapshotOf({ state: 'stopped', ended_at: stoppedAt, stop: { reason: 'shutdown', by: null } }))
    renderApp('/exposure/xt-2', { role: 'operator' })
    const s = await section()
    expect(await within(s).findByText('Checks the open TCP ports this scan found (22, 443) for up to 90 minutes. Its result replaces this OpenVAS part; the other results above stay as they are.')).toBeInTheDocument()
    await expectNoA11yViolations()
    await userEvent.click(within(s).getByRole('button', { name: 'Run OpenVAS again' }))
    await waitFor(() => expect(posted).toEqual(['xt-2']))
    expect(await screen.findByText(`Running OpenVAS again on ${ip}`)).toBeInTheDocument()
  })

  it('a viewer sees why the button is off; a finished step and an older scan have no button', async () => {
    serve(snapshotOf({ state: 'failed', ended_at: stoppedAt }))
    renderApp('/exposure/xt-2', { role: 'viewer' })
    const s = await section()
    expect(await within(s).findByRole('button', { name: 'Run OpenVAS again' })).toBeDisabled()
    // the older scan (its OpenVAS done) has nothing to run again
    await userEvent.selectOptions(screen.getByLabelText('Snapshot of'), '2026-11-16')
    await waitFor(() => expect(within(screen.getByRole('region', { name: 'OpenVAS results (unauthenticated, QoD ≥ 70)' })).queryByRole('button', { name: 'Run OpenVAS again' })).toBeNull())
  })

  it('the button says why the box would refuse now, with the place to fix it', async () => {
    serve(snapshotOf({ state: 'stopped', ended_at: stoppedAt, stop: { reason: 'shutdown', by: null } }), { ...openvasReady, state: 'off', enabled: false })
    renderApp('/exposure/xt-2', { role: 'operator' })
    const s = await section()
    expect(await within(s).findByRole('button', { name: 'Run OpenVAS again' })).toBeDisabled()
    expect(within(s).getByRole('link', { name: 'Turn it on: External exposure, Optional deep scan' })).toBeInTheDocument()
  })

  it('the testing terms come first: OpenVAS runs only under them', async () => {
    serve(snapshotOf({ state: 'stopped', ended_at: stoppedAt, stop: { reason: 'shutdown', by: null } }))
    targetIs({ full_scan: false })
    renderApp('/exposure/xt-2', { role: 'operator' })
    const s = await section()
    expect(await within(s).findByText(/^OpenVAS runs only under the testing terms, and they are not accepted for this target\./)).toBeInTheDocument()
    expect(within(s).getByRole('link', { name: 'Accept them: Ownership, Testing terms' })).toHaveAttribute('href', expect.stringContaining('tab=ownership#step-terms'))
    expect(within(s).getByRole('button', { name: 'Run OpenVAS again' })).toBeDisabled()
  })

  it('no button for a scan older than 24 hours', async () => {
    vi.setSystemTime(new Date('2026-11-18T15:00:00.000Z')) // 24 h 40 min after the scan started
    serve(snapshotOf({ state: 'stopped', ended_at: stoppedAt, stop: { reason: 'shutdown', by: null } }))
    renderApp('/exposure/xt-2', { role: 'operator' })
    const s = await section()
    expect(await within(s).findByText('OpenVAS was stopped before it finished')).toBeInTheDocument()
    expect(within(s).queryByRole('button', { name: 'Run OpenVAS again' })).toBeNull()
  })

  it('no button for a step whose findings it would replace (OpenVAS ended it after it found some)', async () => {
    const high = { ip, port: '443/tcp', severity: 7.5, name: 'Weak TLS', qod: 98, cves: [], solution: 'Fix TLS.', oid: '1.3.6.1.4.1.25623.1.0.1' }
    serve(snapshotOf({ state: 'ended', ended_at: stoppedAt }, { greenbone: [high] }))
    renderApp('/exposure/xt-2', { role: 'operator' })
    const s = await section()
    expect(await within(s).findByRole('table')).toBeInTheDocument()
    expect(within(s).queryByRole('button', { name: 'Run OpenVAS again' })).toBeNull()
  })

  it('a step that ran again says so, with its start and end', async () => {
    serve(snapshotOf({ state: 'done', again: true, started_at: '2026-11-17T16:00:00.000Z', ended_at: '2026-11-17T17:05:00.000Z' }, { not_checked: [], finished_at: '2026-11-17T17:05:00.000Z' }))
    renderApp('/exposure/xt-2')
    const s = await section()
    expect(await within(s).findByText('OpenVAS ran again on its own for this scan, on the open ports it found.')).toBeInTheDocument()
    expect(within(s).getByText('OpenVAS started at 17 Nov 2026, 23:00 and ended at 18 Nov 2026, 00:05.')).toBeInTheDocument() // the end on another day names it
    expect(within(s).queryByRole('button', { name: 'Run OpenVAS again' })).toBeNull()
  })
})

describe('exposure: a scan is named by its start everywhere, with its end next to it, in the viewer\'s time', () => {
  it('the snapshot picker, compare and the result line use the start; the result line adds the end', async () => {
    serve(snapshotOf({ state: 'stopped', ended_at: stoppedAt, stop: { reason: 'shutdown', by: null } }))
    renderApp('/exposure/xt-2')
    const pick = await screen.findByLabelText('Snapshot of')
    await waitFor(() => expect(within(pick).getAllByRole('option').map((o) => o.textContent)).toEqual(['17 Nov 2026, 21:20', '17 Nov 2026, 06:20']))
    for (const name of ['From date', 'To date']) {
      expect(within(screen.getByLabelText(name)).getAllByRole('option').map((o) => o.textContent)).toEqual(['17 Nov 2026, 21:20', '17 Nov 2026, 06:20'])
    }
    expect(await screen.findByText('Scan started 17 Nov 2026, 21:20, finished 22:43')).toBeInTheDocument()
  })

  it('while OpenVAS still scans, the result line says so instead of an end', async () => {
    serve(snapshotOf({ state: 'running', ended_at: null }, { finished_at: null, not_checked: [] }))
    renderApp('/exposure/xt-2')
    expect(await screen.findByText('Scan started 17 Nov 2026, 21:20; OpenVAS is still scanning')).toBeInTheDocument()
  })

  it('the header names the newest scan by its start and adds its end', async () => {
    server.use(http.get('*/api/v1/exposure/targets/xt-2', async () => {
      const r = await fetch(`${location.origin}/api/v1/exposure/targets`).then((x) => x.json()) as { items: { id: string }[] }
      return HttpResponse.json({ ...r.items.find((x) => x.id === 'xt-2'), last_scan_at: started, last_scan_finished_at: stoppedAt })
    }))
    serve(snapshotOf({ state: 'done', ended_at: stoppedAt }))
    renderApp('/exposure/xt-2')
    expect(await screen.findByText('Last scanned 17 Nov 2026, 21:20, finished 22:43')).toBeInTheDocument()
  })
})
