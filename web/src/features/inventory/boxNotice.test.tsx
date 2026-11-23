import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen } from '@testing-library/react'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { collection } from '@/mocks/db'
import { records } from '@/features/findings/modelMocks'
import { BOX_ID, ensureBox } from './mocks'

// The box page offered "Fix by updating the operating system" with nothing to install. The fix line is shown only when an
// update exists; open findings without one get one honest line; not relevant findings are not counted.
vi.setConfig({ testTimeout: 30_000 })
beforeEach(() => ensureBox())
const T = { timeout: 5000 }
type Pkg = { name: string; current: string; new: string; security: boolean; cves: string[] }
const os = collection<{ pending: Pkg[] }>('core_os', () => ({ pending: [] }))
const setPending = (pending: Pkg[]) => os.update((o) => ({ ...o, pending }))
const pkg = (name: string, cves: string[]): Pkg => ({ name, current: '1', new: '2', security: true, cves })
/** The box's findings in the findings model: the first `open` stay open (not confirmed yet), the rest are closed by Vedette as not
 *  relevant. */
function boxFindings(open: string[], notRelevant: string[]) {
  records.update((all) => {
    const tpl = all.find((r) => r.asset_id !== BOX_ID) ?? all[0]!
    const mk = (cve: string, i: number, handled: boolean) => ({ ...tpl, id: `fv-box-${handled ? 'nr' : 'open'}-${i}`, asset_id: BOX_ID, cve, software: null,
      verified: 'no' as const, layer: 5 as const, fix: { ...tpl.fix, key: `box|${cve}` }, reopened: null,
      ...(handled ? { state: 'handled' as const, resolution: 'not_relevant' as const, via: 'data_corrected' as const, resolved_by: 'system', resolved_at: tpl.first_seen }
        : { state: 'open' as const, resolution: null, via: null, resolved_by: null, resolved_at: null }) })
    return [...all.filter((r) => r.asset_id !== BOX_ID), ...open.map((c, i) => mk(c, i, false)), ...notRelevant.map((c, i) => mk(c, i, true))]
  })
}

describe('box notice: a fix is offered only when there is one', () => {
  it('no OS update waiting: no fix link, one honest line, and the open count leaves not relevant out', async () => {
    setPending([])
    boxFindings(['CVE-2025-0001', 'CVE-2025-0002'], ['CVE-2024-0001', 'CVE-2024-0002', 'CVE-2024-0003'])
    renderApp(`/devices/${BOX_ID}`)
    expect(await screen.findByText('No update fixes these yet: see each finding.', undefined, T)).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: /operating system update/ })).toBeNull()
    expect(screen.getByRole('link', { name: '2 open findings on this box' })).toHaveAttribute('href', `/findings?tab=open&device=${BOX_ID}`)
    await expectNoA11yViolations()
  })

  it('an OS update fixes open findings: the link names how many and goes to the OS updates', async () => {
    setPending([pkg('openssl', ['CVE-2025-0001']), pkg('curl', ['CVE-2025-0002', 'CVE-2025-9999']), pkg('tzdata', [])])
    boxFindings(['CVE-2025-0001', 'CVE-2025-0002', 'CVE-2025-0003'], [])
    renderApp(`/devices/${BOX_ID}`)
    expect(await screen.findByRole('link', { name: 'Fix 2 findings: install 2 operating system updates' }, T)).toHaveAttribute('href', '/settings/updates#os')
    expect(screen.queryByText('No update fixes these yet: see each finding.')).toBeNull()
  })

  it('updates waiting that fix none of them: said as waiting, plus the honest line; nothing open and nothing waiting: no fix line at all', async () => {
    setPending([pkg('tzdata', [])])
    boxFindings(['CVE-2025-0001'], [])
    const view = renderApp(`/devices/${BOX_ID}`)
    expect(await screen.findByRole('link', { name: '1 operating system update is waiting' }, T)).toHaveAttribute('href', '/settings/updates#os')
    expect(screen.getByText('No update fixes these yet: see each finding.')).toBeInTheDocument()
    view.unmount()

    setPending([])
    boxFindings([], ['CVE-2024-0001'])
    renderApp(`/devices/${BOX_ID}`)
    expect(await screen.findByText('This is the Vedette box itself', undefined, T)).toBeInTheDocument()
    expect(screen.queryByText('No update fixes these yet: see each finding.')).toBeNull()
    expect(screen.queryByRole('link', { name: /open finding/ })).toBeNull()
  })
})
