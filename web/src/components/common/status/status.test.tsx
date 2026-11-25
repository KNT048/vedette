// The status model's components: one look and one wording per status, severity, verification, handling and CVE list.
import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import type { ReactNode } from 'react'
import '@/lib/i18n'
import { FINDING_STATUSES } from '@/lib/statusCodes'
import { CveList, FindingStatusLines, HandledLine, ReasonsLine, ReopenedLine, SeverityBadge, StatusBadge, VerificationLine, bandOf, type CveItem } from '.'

const inRouter = (ui: ReactNode) => render(<MemoryRouter>{ui}</MemoryRouter>)

describe('StatusBadge', () => {
  it('every finding status has its own words, icon and meaning, and only "Under attack here" is filled', () => {
    const labels = new Set<string>()
    for (const code of FINDING_STATUSES) {
      const { container, unmount } = render(<StatusBadge code={code} />)
      const badge = container.querySelector(`[data-status="${code}"]`)!
      expect(badge.querySelector('svg')).toHaveAttribute('aria-hidden', 'true')
      expect(badge.getAttribute('title')).toMatch(/\w/)
      expect(badge.className.includes('bg-danger ')).toBe(code === 'under_attack')
      labels.add(badge.textContent!)
      unmount()
    }
    expect(labels.size).toBe(FINDING_STATUSES.length)
    render(<StatusBadge code="exploited" />)
    expect(screen.getByText('Exploited in the wild')).toBeInTheDocument()
  })

  it('a device badge counts its CVEs, and links to that device\'s findings with that status', () => {
    inRouter(<><StatusBadge code="exploited" count={2} to="/findings?tab=device&device=d1&status=exploited" /><StatusBadge code="update_recommended" count={5} /><StatusBadge code="needs_input" count={1} /></>)
    expect(screen.getByRole('link', { name: '2 exploited' })).toHaveAttribute('href', '/findings?tab=device&device=d1&status=exploited')
    expect(screen.getByText('Update recommended')).toBeInTheDocument()
    expect(screen.getByText('Needs your input')).toBeInTheDocument()
  })

  it('an accepted risk says until when', () => {
    render(<StatusBadge code="accepted" until="2027-03-03" />)
    expect(screen.getByText(/^Risk accepted until .*2027$/)).toBeInTheDocument()
  })
})

describe('SeverityBadge', () => {
  it('the band and the score, with a level meter of its own; no score is "Not scored yet", never 0', () => {
    const { container } = render(<><SeverityBadge severity={{ band: 'critical', score: 9.8, version: '3.1', vector: 'CVSS:3.1/AV:N' }} /><SeverityBadge severity="high" /><SeverityBadge severity={null} /></>)
    const [crit, high, none] = [...container.querySelectorAll('[data-band]')]
    expect(crit!.textContent).toBe('Critical9.8')
    expect(crit!.querySelector('svg')!.getAttribute('data-level')).toBe('4')
    expect(crit!.getAttribute('title')).toContain('CVSS:3.1/AV:N')
    expect(high!.textContent).toBe('High')
    expect(high!.querySelector('svg')!.getAttribute('data-level')).toBe('3')
    expect(none!.textContent).toBe('Not scored yet')
    expect(crit!.className).not.toContain('bg-danger ') // never the filled "Under attack here"
  })

  it('FIRST bands, and NVD\'s three for CVSS 2.0', () => {
    expect([0, 3.9, 4, 6.9, 7, 8.9, 9].map((s) => bandOf(s, '3.1'))).toEqual(['none', 'low', 'medium', 'medium', 'high', 'high', 'critical'])
    expect([3.9, 4, 7, 10].map((s) => bandOf(s, '2.0'))).toEqual(['low', 'medium', 'high', 'high'])
  })
})

describe('VerificationLine', () => {
  it('a second line, not a chip: confirmed how, or not confirmed yet and on what', () => {
    render(<>
      <VerificationLine verified="scan" basis="scan" />
      <VerificationLine verified="device" basis="device_version" />
      <VerificationLine verified="person" basis="person" by="ana" />
      <VerificationLine verified="person" basis="statement" by="bo" entered />
      <VerificationLine verified="no" basis="banner_version" />
      <VerificationLine verified="no" />
    </>)
    for (const s of ['Confirmed by a safe check', 'Confirmed: the device reports this version', 'Confirmed by ana', 'Confirmed: the version bo entered', 'Not confirmed yet: based on a scan banner', 'Not confirmed yet']) {
      expect(screen.getByText(s)).toBeInTheDocument()
    }
  })
})

describe('HandledLine', () => {
  const base = { by: 'system', at: '2026-11-18T08:00:00Z', note: null, accepted_until: null, from_version: null, to_version: null } as const
  it('who and how, from the stored fields', () => {
    render(<>
      <HandledLine handled={{ ...base, resolution: 'patched', via: 'version_moved', from_version: '6.24', to_version: '7.23' }} />
      <HandledLine handled={{ ...base, resolution: 'patched', via: 'software_removed' }} software="WinRAR" />
      <HandledLine handled={{ ...base, resolution: 'mitigated', via: 'person', by: 'ana', note: 'firewall rule on port 443' }} />
      <HandledLine handled={{ ...base, resolution: 'accepted', via: 'person', by: 'ana', accepted_until: '2027-03-03' }} />
    </>)
    expect(screen.getByText('Patched by Vedette: version moved 6.24 → 7.23 (18 Nov 2026)')).toBeInTheDocument()
    expect(screen.getByText('Patched by Vedette: WinRAR was removed (18 Nov 2026)')).toBeInTheDocument()
    expect(screen.getByText('Mitigated by ana (18 Nov 2026): firewall rule on port 443')).toBeInTheDocument()
    expect(screen.getByText(/^Risk accepted until .*2027 by ana \(18 Nov 2026\)$/)).toBeInTheDocument()
  })
})

describe('a version a person changed', () => {
  it('is handled by that person, never "by Vedette"; setting it back reopens with a line that names them', () => {
    render(<>
      <HandledLine handled={{ by: 'qa@example.com', at: '2026-11-24T03:51:00Z', note: null, accepted_until: null, resolution: 'patched', via: 'version_moved', from_version: '1.30.5', to_version: '1.30.6' }} />
      <ReopenedLine reopened={{ why: 'detected_again', at: '2026-11-24T04:08:00Z', by: 'qa@example.com' }} version="1.30.5" />
      <ReopenedLine reopened={{ why: 'detected_again', at: '2026-11-24T04:08:00Z', by: null }} />
      <ReopenedLine reopened={{ why: 'acceptance_expired', at: '2026-11-24T04:08:00Z', by: null }} />
    </>)
    expect(screen.getByText('Patched by qa@example.com: version changed 1.30.5 → 1.30.6 (24 Nov 2026)')).toBeInTheDocument()
    expect(screen.getByText('Reopened: the version was set back to 1.30.5 by qa@example.com (24 Nov 2026)')).toBeInTheDocument()
    expect(screen.getByText('Reopened: Vedette detects it again (24 Nov 2026)')).toBeInTheDocument()
    expect(screen.getByText('Reopened: the accepted risk ended (24 Nov 2026)')).toBeInTheDocument()
  })
})

describe('HandledLine under its badge', () => {
  it('does not say the status the badge beside it says', () => {
    const h = { by: 'ana', at: '2026-11-18T08:00:00Z', note: 'isolated segment', accepted_until: '2026-12-24', from_version: null, to_version: null, resolution: 'accepted', via: 'person' } as const
    const { container } = render(<FindingStatusLines value={{ status: 'accepted', handled: h }} />)
    expect(container.textContent).toMatch(/^Risk accepted until 24 Dec 2026By ana \(18 Nov 2026\): isolated segment$/)
    expect(container.textContent!.match(/Risk accepted/g)).toHaveLength(1)
  })
})

describe('FindingStatusLines', () => {
  const urgency = { internet: null, reasons: [{ layer: 2, source: 'cisa-kev', name: 'CISA KEV', date: '2025-03-04', url: null, detail: null, due: '2025-03-25' }] }
  const verification = { verified: 'no', basis: 'statement', by: null, at: null } as const
  it('the badge, why it has that status and how Vedette knows: one finding, one set of words', () => {
    const { container } = render(<FindingStatusLines value={{ status: 'exploited', urgency, verification }} />)
    expect(container.querySelector('[data-status="exploited"]')).not.toBeNull()
    expect(screen.getByTestId('reasons-line')).toHaveTextContent('Exploited in the wild: CISA KEV (4 Mar 2025); fix by 25 Mar 2025')
    expect(screen.getByText('Not confirmed yet: based on a version someone entered')).toBeInTheDocument()
  })
  it('the lines alone under a badge a row already shows: an update only recommended has no reasons line, only its confirmation', () => {
    const { container } = render(<FindingStatusLines badge={false} value={{ status: 'update_recommended', urgency: { internet: null, reasons: [] }, verification: { verified: 'device', basis: 'device_version', by: null, at: null } }} />)
    expect(container.querySelector('[data-status]')).toBeNull()
    expect(screen.queryByTestId('reasons-line')).toBeNull()
    expect(container).toHaveTextContent('Confirmed: the device reports this version')
  })
})

describe('ReasonsLine', () => {
  const r = (layer: number, source: string, name: string, date: string, extra: { url?: string; detail?: string; due?: string } = {}) =>
    ({ layer, source, name, date, url: extra.url ?? null, detail: extra.detail ?? null, due: extra.due ?? null })
  it('every layer that applies, with sources, date and link; a layer 2 without CISA KEV says so', () => {
    const { container } = render(<ReasonsLine urgency={{ internet: null, reasons: [r(2, 'rapid7', 'Rapid7', '2026-11-19'), r(2, 'gti', 'Mandiant', '2026-11-20'), r(3, 'github-poc', 'GitHub', '2026-11-18', { detail: '244 stars', url: 'https://github.com/example/poc' })] }} />)
    expect(container.textContent).toBe('Exploited in the wild: Rapid7, Mandiant (19 Nov 2026); not yet in CISA KEV · Public exploit available: GitHub, 244 stars (18 Nov 2026)')
    expect(screen.getByRole('link', { name: 'GitHub, 244 stars' })).toHaveAttribute('href', 'https://github.com/example/poc')
  })
  it('CISA KEV with its due date; nothing for an update that is only recommended', () => {
    const { container } = render(<ReasonsLine urgency={{ internet: null, reasons: [r(2, 'cisa-kev', 'CISA KEV', '2026-11-10', { due: '2026-12-01' })] }} />)
    expect(container.textContent).toMatch(/^Exploited in the wild: CISA KEV \(10 Nov 2026\); fix by 1 Dec 2026$/)
    expect(render(<ReasonsLine urgency={{ internet: null, reasons: [] }} />).container).toBeEmptyDOMElement()
  })
})

describe('CveList', () => {
  const sev = (band: 'critical' | 'high' | 'medium' | 'low', score: number) => ({ band, score })
  const items: CveItem[] = [
    { cve: 'CVE-2024-0003', severity: sev('medium', 5.3), to: '/findings/f3' },
    { cve: 'CVE-2024-0001', severity: sev('critical', 9.8), to: '/findings/f1' },
    { cve: 'CVE-2024-0004', severity: null },
    { cve: 'CVE-2024-0002', severity: sev('high', 7.5) },
    { cve: 'CVE-2024-0005', severity: sev('low', 2.1) },
  ]

  it('most severe first, each with its severity, a count line, and Critical and High shown with the rest one click away', async () => {
    const u = userEvent.setup()
    inRouter(<CveList items={items} label="CVEs fixed by this update" />)
    expect(screen.getByText('1 Critical · 1 High · 1 Medium · 1 Low · 1 not scored yet')).toBeInTheDocument()
    const list = screen.getByRole('list', { name: 'CVEs fixed by this update' })
    expect(within(list).getAllByRole('link').map((a) => a.textContent)).toEqual(['CVE-2024-0001', 'CVE-2024-0002'])
    expect(within(list).getByRole('link', { name: 'CVE-2024-0001' })).toHaveAttribute('href', '/findings/f1')
    expect(within(list).getByRole('link', { name: 'CVE-2024-0002' })).toHaveAttribute('href', '/cve/CVE-2024-0002')
    await u.click(screen.getByRole('button', { name: '+3 Medium/Low' }))
    expect(within(list).getAllByRole('link').map((a) => a.textContent)).toEqual(['CVE-2024-0001', 'CVE-2024-0002', 'CVE-2024-0003', 'CVE-2024-0005', 'CVE-2024-0004'])
    expect(within(list).getByRole('link', { name: 'CVE-2024-0003' })).toHaveFocus()
    expect(screen.getByRole('button', { name: 'Show fewer' })).toHaveAttribute('aria-expanded', 'true')
  })

  it('without severity data the order stays and the first eight show', () => {
    const ids = Array.from({ length: 11 }, (_, i) => ({ cve: `CVE-2025-${String(1000 + i)}` }))
    inRouter(<CveList items={ids} label="CVEs" />)
    expect(screen.getAllByRole('link')).toHaveLength(8)
    expect(screen.getByRole('button', { name: '+3 more' })).toBeInTheDocument()
    expect(screen.queryByText(/Critical|not scored/)).toBeNull()
  })

  it('rows with the status and an action of each CVE; all of them on paper', () => {
    inRouter(<CveList rows showStatus all label="CVEs" items={[{ cve: 'CVE-2024-0009', id: 'f9', status: 'exploited', severity: sev('low', 3) }]}
      action={(i) => <button type="button">Mark {i.id} as handled</button>} />)
    expect(screen.getByText('Exploited in the wild')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Mark f9 as handled' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /more/ })).toBeNull()
  })
})
