import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { getResponse, http, HttpResponse } from 'msw'
import { handlers } from '@/mocks/handlers'
import { renderApp } from '@/test/render'
import { server } from '@/test/server'
import { assetsStore } from '@/mocks/stores'
import { ensureBox } from './mocks'

// The Software tab's "What it needs" column reads To fix's answer, whose actions name the software row their findings or plan item
// rest on. The tab shows one line per software (the effective row) and lists the other sources' rows under it, so an action on any
// row of a software counts on its line, whatever the source of either (agent, SNMP, scan, a person's entry), on every device.
vi.setConfig({ testTimeout: 30_000 })
const T = { timeout: 5000 }

type Act = { sid: string; cves: number }
const action = (deviceId: string, a: Act, kind = 'fixed') => ({
  group: `${deviceId}/${a.sid}`, software_id: a.sid, software: '', version: '', product: '', source: '', fixed: '9.9', kind, windows: false, distro: '', pro: false,
  action: 'Upgrade it', cves: Array.from({ length: a.cves }, (_, i) => `CVE-2026-${1000 + i}`), finding_ids: [], worst: 'high', ransomware: 0, likely: 0,
  confirmed: a.cves, detected: 0, reported: 0, suspected: 0, checkable: 0, nvd_lag: false, kb: '',
})
/** To fix for one device: exploited actions and recommended updates on the given rows. */
function toFix(byDevice: Record<string, { exploited?: Act[]; planned?: Act[] }>) {
  server.use(http.get('*/api/v1/findings/to-fix', ({ request }) => {
    const id = new URL(request.url).searchParams.get('asset') ?? ''
    const d = byDevice[id]
    const asset = { id, name: id, hostname: null, ip: '192.168.10.1', kind: 'firewall', display: id, approved: true, ignored: false }
    return HttpResponse.json({ devices: d ? [{ asset, risk: null, open: 1, exploited: (d.exploited ?? []).map((a) => action(id, a)), no_update: [], planned: (d.planned ?? []).map((a) => action(id, a)), plan_compared: true }] : [],
      truncated: false, plan_ran: true, plan_off: false, risks: {} })
  }))
}

const table = () => screen.findByRole('table', { name: 'Software on the device' }, T)
/** The one line of a software, once the page has settled (the effective rows are read, the session knows the role). */
const line = async (name: string) => {
  const tbl = await table()
  return waitFor(() => {
    const rows = within(tbl).getAllByRole('row').filter((r) => within(r).queryAllByText(name, { exact: true }).length > 0)
    expect(rows).toHaveLength(1)
    return rows[0]!
  }, T)
}
/** The "More" menu button of a line, once it can be used. */
const menuButton = async (name: string) => {
  const row = await line(name)
  return waitFor(() => {
    const b = within(row).getByRole('button', { name: `Actions for ${name}` })
    expect(b).toBeEnabled()
    return b
  }, T)
}
const names = async () => within(await table()).getAllByRole('row').slice(1).map((r) => r.querySelector('td .font-medium')?.textContent ?? '')

beforeEach(() => ensureBox())

describe('Software tab: what each line needs, from any row of the software', () => {
  it('a-fw01: an action on the scan row under the agent\'s line, and on the scan row under a person\'s entry, show on their lines; an SNMP line its own', async () => {
    toFix({ 'a-fw01': { planned: [{ sid: 's-fw01-ssh-nmap', cves: 25 }], exploited: [{ sid: 's-fw01-web-nmap', cves: 2 }, { sid: 's-fw01', cves: 1 }] } })
    renderApp('/devices/a-fw01?tab=software')
    await waitFor(async () => expect(within(await line('OpenSSH')).getByRole('link', { name: 'Recommended update to 9.9 fixes 25 CVEs' })).toBeInTheDocument(), T) // agent line
    expect(within(await line('nginx')).getByRole('link', { name: '2 exploited CVEs' })).toBeInTheDocument() // a person's entry
    expect(within(await line('FortiGate firewall')).getByRole('link', { name: '1 exploited CVE' })).toBeInTheDocument() // SNMP, its own row
    // sorting by "What it needs": exploited first (most CVEs first), then recommended updates, then the rest
    await userEvent.click(within(await table()).getByRole('button', { name: 'What it needs' }))
    await waitFor(async () => expect((await names()).slice(0, 3)).toEqual(['nginx', 'FortiGate firewall', 'OpenSSH']), T)
  })

  it('another device: a scan-read Windows on a PC and a recommended update on its row, and a clean line stays empty', async () => {
    const pc = assetsStore.get().find((a) => a.software.some((s) => s.source === 'nmap' && s.display === 'Windows'))!
    const sid = pc.software[0]!.id
    toFix({ [pc.id]: { planned: [{ sid, cves: 4 }] } })
    renderApp(`/devices/${pc.id}?tab=software`)
    await waitFor(async () => expect(within(await line('Windows')).getByRole('link', { name: 'Recommended update to 9.9 fixes 4 CVEs' })).toBeInTheDocument(), T)
  })

  it('a device with many lines: search finds a line on a later page, the pager jumps to a page, and sorting puts the line that needs something first', async () => {
    const user = userEvent.setup()
    const many = Array.from({ length: 120 }, (_, i) => ({ id: `s-rt02-pkg-${i}`, display: `pkg-${String(i).padStart(3, '0')}`, vendor: 'Alpine', product: `pkg-${i}`, version: '1.0', kev: [], source: 'agent' as const, confidence: 0.95 }))
    assetsStore.update((l) => l.map((a) => (a.id === 'a-rt02' ? { ...a, software: [...a.software, ...many] } : a)))
    toFix({ 'a-rt02': { exploited: [{ sid: 's-rt02-pkg-110', cves: 3 }] } })
    renderApp('/devices/a-rt02?tab=software')
    await table()
    expect(screen.getAllByRole('status').filter((s) => /of 121/.test(s.textContent ?? ''))[0]).toHaveTextContent('1–50 of 121')
    await user.type(screen.getAllByLabelText('Go to page')[0]!, '3{Enter}')
    await waitFor(async () => expect((await names())).toHaveLength(21), T)
    await user.type(screen.getByRole('searchbox', { name: 'Search Software on the device' }), 'pkg-110')
    await waitFor(async () => expect(await names()).toEqual(['pkg-110']), T)
    await user.clear(screen.getByRole('searchbox', { name: 'Search Software on the device' }))
    await waitFor(async () => expect((await names())).toHaveLength(50), T)
    await user.click(within(await table()).getByRole('button', { name: 'What it needs' }))
    await waitFor(async () => expect((await names())[0]).toBe('pkg-110'), T)
  })
})

describe('Software tab: every line can be corrected', () => {
  it('agent, SNMP and scan lines offer "Correct version…" in their menu; a person\'s software is changed or removed', async () => {
    const user = userEvent.setup()
    const patches: string[] = []
    server.events.on('request:start', ({ request }) => { if (request.method === 'PATCH') patches.push(new URL(request.url).pathname) })
    renderApp('/devices/a-fw01?tab=software')
    const menu = async (name: string) => {
      await user.click(await menuButton(name))
      return (await screen.findAllByRole('menuitem', undefined, T)).map((m) => m.textContent)
    }
    expect(await menu('FortiGate firewall')).toEqual(['Correct version…', 'Mark not installed…'])
    await user.keyboard('{Escape}')
    expect(await menu('nginx')).toEqual(['Change version…', 'Remove from the device'])
    await user.keyboard('{Escape}')
    expect(await menu('OpenSSH')).toContain('Correct version…')
    await user.click(screen.getByRole('menuitem', { name: 'Correct version…' }))
    const dlg = await screen.findByRole('dialog', undefined, T)
    expect(dlg).toHaveTextContent('If a newer version is detected later, Vedette uses it automatically.')
    await user.clear(within(dlg).getByLabelText(/^Version/))
    await user.type(within(dlg).getByLabelText(/^Version/), '10.3p1')
    await user.click(within(dlg).getByRole('button', { name: 'Save version' }))
    await waitFor(() => expect(patches).toContain('/api/v1/inventory/devices/a-fw01/software/s-fw01-ssh-agent'), T)
    server.events.removeAllListeners()
  })

  it('a line that shows a person\'s correction says who set it and can be undone', async () => {
    const user = userEvent.setup()
    assetsStore.update((l) => l.map((a) => (a.id === 'a-rt02' ? { ...a, software: [...a.software, { id: 's-rt02-fix', display: 'MikroTik router', vendor: 'MikroTik', product: 'RouterOS', version: '7.16', kev: ['mikrotik|routeros'], source: 'manual' as const, confidence: 1, corrects: 's-rt02', set_at: new Date().toISOString() }] } : a)))
    renderApp('/devices/a-rt02?tab=software')
    const row = await line('MikroTik router')
    expect(within(row).getByText('7.16')).toBeInTheDocument()
    expect(within(row).getByTestId('entered-note')).toHaveTextContent(/^Set by /)
    await user.click(await menuButton('MikroTik router'))
    await user.click(await screen.findByRole('menuitem', { name: 'Undo correction' }, T))
    await waitFor(() => expect(assetsStore.get().find((a) => a.id === 'a-rt02')!.software.some((s) => s.id === 's-rt02-fix')).toBe(false), T)
  })

  it('a line the box will not let a person correct (can_correct false) does not offer it; the others still do', async () => {
    const user = userEvent.setup()
    server.use(http.get('*/api/v1/inventory/devices/:id', async ({ request }) => {
      const res = await getResponse(handlers, request)
      const body = await res!.json() as { asset: { software: { id: string; can_correct?: boolean }[] } }
      body.asset.software = body.asset.software.map((s) => (s.id === 's-fw01' ? { ...s, can_correct: false } : s))
      return HttpResponse.json(body)
    }))
    renderApp('/devices/a-fw01?tab=software')
    await user.click(await menuButton('FortiGate firewall'))
    expect((await screen.findAllByRole('menuitem', undefined, T)).map((m) => m.textContent)).toEqual(['Mark not installed…'])
    await user.keyboard('{Escape}')
    await user.click(await menuButton('OpenSSH'))
    expect(await screen.findByRole('menuitem', { name: 'Correct version…' }, T)).toBeInTheDocument()
  })
})
