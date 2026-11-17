import { describe, expect, it } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { server } from '@/test/server'
import { assetsStore } from '@/mocks/stores'
import type { ToFix, ToFixAction, ToFixDevice } from './types'

// kien G8: "when the user opens Findings, they know which devices need patching or an action, and what the action is".
const T = { timeout: 5000 }
const act = (o: Partial<ToFixAction>): ToFixAction => ({ group: 'g', software_id: '', software: '', version: '', fixed: '', kind: 'fixed', windows: false, distro: '', pro: false, action: '',
  cves: [], finding_ids: [], worst: 'high', ransomware: 0, likely: 0, confirmed: 0, detected: 1, reported: 0, suspected: 0, ...o })
const dev = (id: string, name: string, o: Partial<ToFixDevice>): ToFixDevice => ({ asset: { id, name, hostname: name, ip: '192.168.18.10', kind: 'pc', display: 'Windows 11' }, open: 0, exploited: [], no_update: [], planned: [], plan_compared: true, ...o })
const winUpdate = act({ group: 'a-pc/s-win', software_id: 's-win', software: 'Windows 11 Pro', version: '10.0.26100.1742', fixed: '10.0.26100.33650', windows: true,
  action: 'Install the latest cumulative update for Windows 11 Pro (build 26100.33650 or later)', cves: ['CVE-2026-1001', 'CVE-2026-1002', 'CVE-2026-1003'], finding_ids: ['f-a', 'f-b', 'f-c'], worst: 'critical', ransomware: 1, detected: 3 })
const winrar = (devId: string) => act({ group: `${devId}/s-rar`, software_id: 's-rar', software: 'RARLAB WinRAR', version: '7.01', fixed: '7.13', action: 'Upgrade RARLAB WinRAR from 7.01 to 7.13 or later', cves: ['CVE-2025-6218', 'CVE-2025-8088'], finding_ids: ['f-r1', 'f-r2'], worst: 'high', detected: 2 })
const firefox = act({ group: 'a-desk/s-ff', software_id: 's-ff', software: 'Mozilla Firefox', version: '152.0', fixed: '157.0.1', action: 'Upgrade Mozilla Firefox from 152.0 to 157.0.1 or later', cves: Array.from({ length: 228 }, (_, i) => `CVE-2026-${20000 + i}`), worst: 'critical', likely: 3, detected: 0 })
const unprovedWin = act({ group: 'a-desk/s-w', software_id: 's-w', software: 'Windows 11 Pro', version: '10.0.26300.9974', kind: 'none', action: "No update is named that fixes these: follow the vendor's advice for Windows 11 Pro",
  cves: ['CVE-2002-0367', 'CVE-2016-3427'], finding_ids: ['f-u1', 'f-u2'], worst: 'medium', detected: 0, reported: 2 })
const sample: ToFix = { truncated: false, plan_ran: true, plan_off: false, devices: [
  dev('a-pc', 'PC-A', { open: 3, exploited: [winUpdate] }),
  dev('a-desk', 'DESKTOP-55UKKFV', { open: 4, exploited: [winrar('a-desk')], no_update: [unprovedWin], planned: [firefox] }),
  dev('a-lap', 'LAPTOP-B', { open: 2, exploited: [winrar('a-lap')] }),
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

  it('the device\'s Software tab says what each row needs: a recommended update with its CVEs, nothing on a clean row', async () => {
    const a = assetsStore.get().find((x) => x.id === 'a-nas02')!
    const [first, clean] = a.software
    server.use(http.get('*/api/v1/findings/to-fix', () => HttpResponse.json({ ...sample, devices: [dev('a-nas02', 'NAS-PHOTOS', {
      planned: [act({ group: `a-nas02/${first!.id}`, software_id: first!.id, software: first!.display, version: '1.0', fixed: '1.2.3', cves: ['CVE-2026-1', 'CVE-2026-2'], action: 'Upgrade' })],
    })] })))
    renderApp('/devices/a-nas02?tab=software')
    const table = await screen.findByRole('table', { name: 'Software on the device' }, T)
    const row = (name: string) => within(table).getAllByText(name)[0]!.closest('tr')!
    expect(await within(row(first!.display)).findByRole('link', { name: 'Recommended update to 1.2.3 fixes 2 CVEs' }, T)).toBeInTheDocument()
    if (clean) expect(within(row(clean.display)).queryByRole('link', { name: /Recommended|exploited/ })).toBeNull()
  })
})
