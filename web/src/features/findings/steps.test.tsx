import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { renderApp } from '@/test/render'
import { assetsStore } from '@/mocks/stores'
import { useTranslation } from 'react-i18next'
import { FixedInNote, nowParts } from './Recommendation'
import { overdue } from './accept'
import type { FindingDetail } from './types'

// What the steps of a finding without a confirmed pack say about the version the box has (step 1) and how a new one reaches Vedette
// (the last item of "Check that it is fixed"), and what "Fixed version" says.
function Parts({ f, updatable, manual, agentGone }: { f: FindingDetail; updatable: boolean; manual?: string; agentGone?: boolean }) {
  const { t } = useTranslation('findings')
  const p = nowParts(t, f, { product: 'Juniper Junos OS', updatable, manual, agentGone })
  return <ol><li>{p.known}</li><li>{p.verify}</li></ol>
}
const finding = (known: Omit<NonNullable<FindingDetail['known_version']>, 'seen_at'> | null, name = 'Juniper Networks EX4200-48T', status = 'suspected') =>
  ({ asset: { id: 'a-ex', name }, known_version: known && { ...known, seen_at: null }, status }) as FindingDetail
const steps = (f: FindingDetail, opts: { updatable?: boolean; manual?: string } = {}) => {
  render(<MemoryRouter><Parts f={f} updatable={opts.updatable ?? false} manual={opts.manual} /></MemoryRouter>)
  const [known, verify] = screen.getAllByRole('listitem').map((li) => li.textContent)
  return [known, undefined, verify]
}

describe('nowParts', () => {
  it('a version from SNMP is said, not asked for; step 3 names "Read with SNMP now" and links the device', () => {
    const [s1, , s3] = steps(finding({ software: 'Juniper Junos OS', version: '15.1R7.9', source: 'snmp' }))
    expect(s1).toBe('Nothing to look up: Juniper Networks EX4200-48T runs Juniper Junos OS 15.1R7.9 (Vedette read it over SNMP).')
    expect(s3).toMatch(/^Then press "Read with SNMP now" on the page of Juniper Networks EX4200-48T/)
    // a newer Junos may not be provably fixed (INV-4c): no promise that it closes, and the Mark as handled way out
    expect(s3).toMatch(/closes the findings on Juniper Networks EX4200-48T it can prove that version fixes\. If this one stays open, press "Mark as handled" and choose Patched\./)
    expect(screen.getByRole('link', { name: 'Open the device' })).toHaveAttribute('href', '/devices/a-ex')
  })

  it.each([
    ['agent', 'its agent reports it', /^The agent reports the new version by itself/],
    ['stated', 'it announces it on the network over LLDP', /states its new version on the network by itself/],
    ['scan', 'a network scan read it', /^Then rescan 192\.168\.142\.1 with the button under Evidence/],
  ] as const)('a version from %s: step 1 says who gave it, step 3 how the new one arrives', (source, from, s3want) => {
    const [s1, , s3] = steps(finding({ software: 'OpenSSH', version: '10.2', source }, '192.168.142.1'))
    expect(s1).toBe(`Nothing to look up: 192.168.142.1 runs OpenSSH 10.2 (${from}).`)
    expect(s3).toMatch(s3want)
    expect(`${s1} ${s3}`).not.toMatch(/Find which version|mark this finding as Patched/)
    expect(s3).toMatch(/it can prove that version fixes[.;] [Ii]f this one stays open, press "Mark as handled" and choose Patched\.$/)
  })

  it('a version an agent last reported, with no agent reporting the device now: said as the last report, no promise it arrives', () => {
    const f = finding({ software: 'Windows Server 2025', version: '10.0.26100.1742', source: 'agent' }, 'Windows Server 2025 host')
    render(<MemoryRouter><Parts f={f} updatable agentGone /></MemoryRouter>)
    const [s1, s3] = screen.getAllByRole('listitem').map((li) => li.textContent)
    expect(s1).toBe('Nothing to look up: Windows Server 2025 host runs Windows Server 2025 10.0.26100.1742 (an agent last reported it; no agent reports it now).')
    expect(s3).toMatch(/^No agent reports Windows Server 2025 host to Vedette now, so the new version does not arrive by itself: install its agent again so it reports the new one\. .*choose Patched\.$/)
    expect(s3).not.toMatch(/by itself, usually within two hours/)
  })

  it('a typed version names the real "I updated <software>" button; no version and no button names "Mark as handled"', () => {
    const [, , s3] = steps(finding({ software: 'Juniper Junos OS', version: '15.1R7.9', source: 'manual' }), { updatable: true, manual: 'Junos OS (Juniper)' })
    expect(s3).toMatch(/^Then press "I updated Junos OS \(Juniper\)" at the top of this page/) // the row's own display, as the button
  })

  it('a closed finding keeps the plain step, not "rescan"', () => {
    const [, , s3] = steps(finding({ software: 'OpenSSH', version: '10.2', source: 'scan' }, '192.168.142.1', 'patched'))
    expect(s3).toMatch(/^Then press "Mark as handled"/)
  })

  it('without a version: asks for it without gluing product and device, and names the dialog\'s choices', () => {
    const [s1, , s3] = steps(finding(null))
    expect(s1).toBe('Find which version of Juniper Junos OS runs on Juniper Networks EX4200-48T, and add it to the device on the Devices page so Vedette can compare it.')
    expect(s3).toBe('Then press "Mark as handled" at the top of this page and choose Patched. If the version was already fixed, choose False positive and write the version in the note.')
  })
})

describe('FixedInNote end_listed', () => {
  it('says the range end is not the fix and where the fix is', () => {
    const fixed_in = { kind: 'end_listed', version: '15.1R7.9', fixed: '20.4', branches: [], more: 0, no_fix: 0, distro: '', distro_fixed: '', distro_release: '', distro_pro: false, source: 'NVD affected versions' } as const
    render(<FixedInNote finding={{ asset: { name: 'Juniper Networks EX4200-48T' }, fixed_in } as unknown as FindingDetail} />)
    // never says a fix exists for this device (an EX4200 runs nothing after 15.1)
    expect(screen.getByText(/^Juniper Networks EX4200-48T runs 15\.1R7\.9, inside the range NVD lists as "before 20\.4"\. 20\.4 is not the fix: NVD lists 20\.4 itself, or releases of it, as affected too, and names no fixed release for 15\.1R7\.9\. The vendor advisory lists the releases that fix it; if none is one Juniper Networks EX4200-48T can run, protect it another way \(What CISA requires\) or plan to replace it\./)).toBeInTheDocument()
    expect(screen.queryByText(/Fixed version not known yet/)).not.toBeInTheDocument()
  })
})

describe('finding page with a typed version', () => {
  it('the steps wire the typed row: step 1 says the version, the check names the button the page shows; a past deadline is said', async () => {
    assetsStore.update((l) => l.map((a) => (a.id === 'a-web01'
      ? { ...a, software: a.software.map((x) => (x.id === 's-web01-wp' ? { ...x, display: 'WordPress', version: '7.1.3', source: 'manual' as const } : x)) }
      : a)))
    renderApp('/findings/f-2')
    expect(await screen.findByText('Nothing to look up: WEB01 runs WordPress 7.1.3 (entered on the Devices page).')).toBeInTheDocument()
    expect(await screen.findByText(/^Then press "I updated WordPress" at the top of this page/)).toBeInTheDocument() // after the device's software is read
    expect(await screen.findByRole('button', { name: 'I updated WordPress' })).toBeInTheDocument()
    expect(screen.getByText(/^Nothing to look up: WordPress 7\.1\.3 was entered for WEB01 on the Devices page \(Evidence above\)/)).toBeInTheDocument() // mock of knownRecheck
    expect(screen.getByText(overdue('2026-11-06') ? "CISA's deadline passed on 6 Nov 2026." : 'CISA requires action by 6 Nov 2026.')).toBeInTheDocument()
    expect(screen.getByText(overdue('2026-11-06') ? "CISA's deadline for US federal agencies passed on 6 Nov 2026: update now." : "CISA's deadline for US federal agencies: 6 Nov 2026. Use it as your own deadline.")).toBeInTheDocument() // in step 1
  })
})
