import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { FixedInNote, NowSteps } from './Recommendation'
import type { FindingDetail, KevInfo } from './types'

// Walk n74 (M2-3..M2-6): what "Steps you can take now" and "Fixed version" say on a finding without a confirmed pack.
const today = new Date(2026, 10, 16)
const kev = (due: string | null) => ({ display: 'Juniper Junos OS', due_date: due }) as KevInfo
const finding = (known: FindingDetail['known_version'], name = 'Juniper Networks EX4200-48T') =>
  ({ asset: { id: 'a-ex', name }, known_version: known, status: 'suspected' }) as FindingDetail
const steps = (f: FindingDetail, opts: { due?: string | null; updatable?: boolean; manual?: boolean } = {}) => {
  render(<MemoryRouter><NowSteps finding={f} kev={kev(opts.due ?? null)} updatable={opts.updatable ?? false} manual={opts.manual ?? false} today={today} /></MemoryRouter>)
  return screen.getAllByRole('listitem').map((li) => li.textContent)
}

describe('NowSteps (M2-3, M2-5, M2-6)', () => {
  it('a version from SNMP is said, not asked for; step 3 names "Read with SNMP now" and links the device', () => {
    const [s1, , s3] = steps(finding({ software: 'Juniper Junos OS', version: '15.1R7.9', source: 'snmp' }))
    expect(s1).toBe('Nothing to look up: Juniper Networks EX4200-48T runs Juniper Junos OS 15.1R7.9 (Vedette read it over SNMP).')
    expect(s3).toMatch(/^Then press "Read with SNMP now" on the page of Juniper Networks EX4200-48T/)
    expect(screen.getByRole('link', { name: 'Open the device' })).toHaveAttribute('href', '/devices/a-ex')
  })

  it.each([
    ['agent', 'its agent reports it', /^The agent reports the new version by itself/],
    ['stated', 'it announces it on the network over LLDP', /states its new version on the network by itself/],
    ['scan', 'a network scan read it', /^Then rescan 192\.168\.18\.1 \("Rescan this device" under Evidence\)/],
  ] as const)('a version from %s: step 1 says who gave it, step 3 how the new one arrives', (source, from, s3want) => {
    const [s1, , s3] = steps(finding({ software: 'OpenSSH', version: '10.2', source }, '192.168.18.1'))
    expect(s1).toBe(`Nothing to look up: 192.168.18.1 runs OpenSSH 10.2 (${from}).`)
    expect(s3).toMatch(s3want)
    expect(`${s1} ${s3}`).not.toMatch(/Find which version|mark this finding as Patched/)
  })

  it('a typed version names the real "I updated <software>" button; no version and no button names "Mark as handled"', () => {
    const [, , s3] = steps(finding({ software: 'Juniper Junos OS', version: '15.1R7.9', source: 'manual' }), { updatable: true, manual: true })
    expect(s3).toMatch(/^Then press "I updated Juniper Junos OS" at the top of this page/)
  })

  it('without a version: asks for it without gluing product and device, and names the dialog\'s choices', () => {
    const [s1, , s3] = steps(finding(null))
    expect(s1).toBe('Find which version of Juniper Junos OS runs on Juniper Networks EX4200-48T, and add it to the device on the Devices page so Vedette can compare it.')
    expect(s3).toBe('Then press "Mark as handled" at the top of this page and choose Patched. If the version was already fixed, choose False positive and write the version in the note.')
  })

  it('a CISA deadline in the past is "passed on … update now"; a future one stays "by"', () => {
    expect(steps(finding(null), { due: '2023-11-17' })[1]).toBe("If it is older than the fixed version in the advisory, update it now: CISA's deadline passed on 17 Nov 2023.")
  })

  it('a future CISA deadline stays "update it by"', () => {
    expect(steps(finding(null), { due: '2026-12-01' })[1]).toBe('If it is older than the fixed version in the advisory, update it by 1 Dec 2026.')
  })
})

describe('FixedInNote end_listed (M2-4)', () => {
  it('says the range end is not the fix and where the fix is', () => {
    const fixed_in = { kind: 'end_listed', version: '15.1R7.9', fixed: '20.4', branches: [], more: 0, no_fix: 0, distro: '', distro_fixed: '', distro_release: '', distro_pro: false, source: 'NVD affected versions' } as const
    render(<FixedInNote finding={{ asset: { name: 'Juniper Networks EX4200-48T' }, fixed_in } as unknown as FindingDetail} />)
    expect(screen.getByText(/^Juniper Networks EX4200-48T runs 15\.1R7\.9, inside the range NVD lists as "before 20\.4"\. 20\.4 is not the fix: NVD lists 20\.4 itself, or releases of it, as affected too\. The vendor advisory names the release that fixes it\./)).toBeInTheDocument()
    expect(screen.queryByText(/Fixed version not known yet/)).not.toBeInTheDocument()
  })
})
