import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import { renderApp } from '@/test/render'
import { server } from '@/test/server'
import { assetsStore } from '@/mocks/stores'
import type { ToFix, ToFixAction, ToFixDevice } from './types'

// "when the user opens Findings, they know which devices need patching or an action, and what the action is".
const T = { timeout: 5000 }
const act = (o: Partial<ToFixAction>): ToFixAction => ({ group: 'g', software_id: '', software: '', version: '', product: '', source: '', fixed: '', kind: 'fixed', windows: false, distro: '', pro: false, distro_data: '', action: '',
  cves: [], finding_ids: [], worst: 'high', ransomware: 0, likely: 0, confirmed: 0, detected: 1, reported: 0, suspected: 0, checkable: 0, nvd_lag: false, kb: '', ...o })
const dev = (id: string, name: string, o: Partial<ToFixDevice>): ToFixDevice => ({ asset: { id, name, hostname: name, ip: '192.168.142.10', kind: 'pc', display: 'Windows 11', approved: true, ignored: false }, risk: null, open: 0, exploited: [], no_update: [], planned: [], plan_compared: true, ...o })
const winUpdate = act({ group: 'a-pc/s-win', software_id: 's-win', software: 'Windows 11 Pro', version: '10.0.26100.1742', fixed: '10.0.26100.33650', windows: true,
  action: 'Install the latest cumulative update for Windows 11 Pro (build 26100.33650 or later)', cves: ['CVE-2026-1001', 'CVE-2026-1002', 'CVE-2026-1003'], finding_ids: ['f-a', 'f-b', 'f-c'], worst: 'critical', ransomware: 1, detected: 3 })
const winrar = (devId: string, name = 'RARLAB WinRAR') => act({ group: `${devId}/s-rar`, software_id: 's-rar', software: name, product: 'rarlab|winrar', version: '7.01', fixed: '7.13', action: 'Upgrade RARLAB WinRAR from 7.01 to 7.13 or later', cves: ['CVE-2025-6218', 'CVE-2025-8088'], finding_ids: ['f-r1', 'f-r2'], worst: 'high', detected: 2 })
const firefox = act({ group: 'a-desk/s-ff', software_id: 's-ff', software: 'Mozilla Firefox', version: '152.0', fixed: '157.0.1', action: 'Upgrade Mozilla Firefox from 152.0 to 157.0.1 or later', cves: Array.from({ length: 228 }, (_, i) => `CVE-2026-${20000 + i}`), worst: 'critical', likely: 3, detected: 0 })
const unprovedWin = act({ group: 'a-desk/s-w', software_id: 's-w', software: 'Windows 11 Pro', version: '10.0.26300.9974', kind: 'none', action: "No update is named that fixes these: follow the vendor's advice for Windows 11 Pro",
  cves: ['CVE-2002-0367', 'CVE-2016-3427'], finding_ids: ['f-u1', 'f-u2'], worst: 'medium', detected: 0, reported: 2 })
const sample: ToFix = { truncated: false, plan_ran: true, plan_off: false, risks: {}, devices: [
  dev('a-pc', 'PC-A', { open: 3, exploited: [winUpdate] }),
  dev('a-desk', 'DESKTOP-55UKKFV', { open: 4, exploited: [winrar('a-desk')], no_update: [unprovedWin], planned: [firefox] }),
  dev('a-lap', 'LAPTOP-B', { open: 2, exploited: [winrar('a-lap', 'WinRAR 7.01 (64-bit)')] }), // the same product under another name: one By fix row
] }


describe('Findings › To fix', () => {

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
    // the row is looked up again on each try: the table draws its rows again once the answer arrives
    await waitFor(() => expect(within(row(first!.display)).getByRole('link', { name: 'Recommended update to 1.2.3 fixes 2 CVEs' })).toBeInTheDocument(), T)
    if (clean) expect(within(row(clean.display)).queryByRole('link', { name: /Recommended|exploited/ })).toBeNull()
    // review r1 of #943: an unproved match is not counted as exploited: it links to Needs your input
    expect(within(row(third.display)).queryByRole('link', { name: /^2 exploited CVEs$/ })).toBeNull()
    expect(within(row(third.display)).getByRole('link', { name: '2 exploited CVEs to check' })).toHaveAttribute('href', '/findings?tab=input&device=a-nas02')
  })
})
