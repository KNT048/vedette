import { describe, expect, it } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp } from '@/test/render'
import { server } from '@/test/server'
import { assetsStore, modulesStore, sessionStore } from '@/mocks/stores'
import { BOX_ID, inventorySettingsStore } from '@/features/inventory/mocks'
import type { ScanRun } from '@/features/scan/types'

// kien G7a: kien ran a vulnerability check and read its "0 matches" as "nothing ran"; his device checks were listed nowhere.
// History says what each run found, in words, and lists every kind of run.
const T = { timeout: 5000 }
const run = (over: Partial<ScanRun>): ScanRun => ({
  id: 'run-3sg', trigger: 'manual', trigger_note: null, started_at: '2026-11-17T03:18:00.000Z', started_by: 'kien@acme.example', ended_at: '2026-11-17T03:19:00.000Z',
  status: 'done', total: 1, done: 1, current: null, progress: null, results: [], matched: 0, stop_reason: null, identification: [], ...over,
})
const row = (result: ScanRun['results'][number]['result'], cve: string) => ({ target_id: 'a-bn340', label: 'BN340', ip: '192.168.18.40', template: result === 'no_template' ? null : cve, result, finding_id: null, note: cve })

describe('History says what each run found (kien G7a)', () => {
  it('a vulnerability check with no template for its CVE says "no check exists (still suspected)", never "0 matches"', async () => {
    server.use(http.get('*/api/v1/scans/runs', () => HttpResponse.json({ items: [run({ results: [row('no_template', 'CVE-2026-1001')] })] })))
    renderApp('/settings/scanning?tab=history')
    const table = await screen.findByRole('table', { name: 'History of scans' }, T)
    expect(within(table).getByText('Checked 1 CVE: 1 no check exists (still suspected)')).toBeInTheDocument()
    expect(within(table).queryByText('0')).toBeNull()
  })

  it('a mixed run counts each outcome; a stopped one says why first', async () => {
    server.use(http.get('*/api/v1/scans/runs', () => HttpResponse.json({ items: [
      run({ id: 'r2', matched: 1, results: [row('matched', 'CVE-1'), row('no_template', 'CVE-2'), row('no_template', 'CVE-3')] }),
      run({ id: 'r1', started_at: '2026-11-16T03:18:00.000Z', status: 'auto_stopped', stop_reason: 'Outside the scan window.', results: [], identification: [] }),
    ] })))
    renderApp('/settings/scanning?tab=history')
    const table = await screen.findByRole('table', { name: 'History of scans' }, T)
    expect(within(table).getByText('Checked 3 CVEs: 1 confirmed, 2 no check exists (still suspected)')).toBeInTheDocument()
    expect(within(table).getByText('Stopped: Outside the scan window. Nothing to check')).toBeInTheDocument()
  })

  it('"Check this device now" is listed with what happened, even with the vulnerability checks module off', async () => {
    sessionStore.set({ userId: 'u-admin' })
    modulesStore.update((l) => l.map((m) => (m.id === 'scan' ? { ...m, enabled: false } : m.id === 'sensor-active' ? { ...m, enabled: true } : m)))
    inventorySettingsStore.update((s) => ({ ...s, active: { ...s.active, enabled: true }, scope_confirmed_at: s.scope_confirmed_at ?? '2026-11-01T00:00:00.000Z' }))
    const device = assetsStore.get().find((a) => a.id !== BOX_ID && a.ip && a.ip !== '—' && !inventorySettingsStore.get().active.exclusions.includes(a.ip))!
    const res = await fetch(`${location.origin}/api/v1/scanning/engines/nmap-discovery/run`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ targets: [device.id] }) })
    expect(res.status).toBe(202)
    renderApp('/settings/scanning')
    await userEvent.click(await screen.findByRole('tab', { name: 'History' }, T))
    const table = await screen.findByRole('table', { name: 'History of discovery runs and public scans' }, T)
    expect(within(table).getByText(`Scanned ${device.ip}: it answered; what it runs is on its device page`)).toBeInTheDocument()
    expect(within(table).getAllByText('Device check, started by a person').length).toBeGreaterThan(0)
  })
})
