// The CVE summary card of a finding and "Ask my AI": one sentence from the brief's fields, the status reasons, the fix for this
// device with the vendor advisory, the workaround or the plain "none published" line, and behind one click the affected versions
// per release train; the AI's answer as four headed answers in a fixed order.
import { describe, expect, it } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { server } from '@/test/server'
import { api } from '@/lib/api'
import { sessionStore } from '@/mocks/stores'
import { esxiBrief } from '@/features/feeds/briefSamples'
import type { CveBrief } from '@/features/feeds/types'
import { AiAnswers } from './Recommendation'
import { records } from './modelMocks'
import { FixTable } from '@/features/feeds/BriefParts'
import type { FindingDetail } from './types'

const FIXED = '8.0 U3d (build 24585383)'
const brief: CveBrief = esxiBrief // with VMware's fixed build per release train

/** The finding f-2 shown as the ESXi host's finding of CVE-2025-22225, with the fix the finding names. */
async function esxiFinding(b: CveBrief = brief) {
  sessionStore.set({ userId: 'u-admin' })
  const real = await api.get<FindingDetail>('/findings/f-2')
  const f: FindingDetail = {
    ...real, cve: 'CVE-2025-22225',
    kev: real.kev ? { ...real.kev, display: 'VMware ESXi', links: [] } : null,
    known_version: { software: 'VMware ESXi', version: '8.0 U3c (build 24022510)', source: 'snmp', seen_at: '2026-11-20T08:00:00Z' },
    fixed_in: { kind: 'fixed', version: '8.0 U3c (build 24022510)', fixed: FIXED, branches: [], more: 0, no_fix: 0, distro: '', distro_fixed: '', distro_release: '', distro_pro: false, source: "CVE.org affected versions (from the CVE record's CNA)" },
  }
  server.use(
    http.get('*/api/v1/findings/f-2', () => HttpResponse.json(f)),
    http.get('*/api/v1/feeds/cve/:id', () => HttpResponse.json({ ...b, matched: null, not_affected: 0 })),
  )
}

describe('the CVE summary card on a finding', () => {
  it('says the CVE in one sentence, the fix for this device with the advisory, and that no workaround is published', async () => {
    await esxiFinding()
    renderApp('/findings/f-2')
    const card = (await screen.findByRole('heading', { name: 'About CVE-2025-22225' })).closest('section')!
    expect(await within(card).findByTestId('brief-sentence')).toHaveTextContent(
      'VMware ESXi hypervisor has a flaw of type “Out-of-bounds Write” (CWE-787) that an attacker can use with local access to it, with high privileges and with no action from a user; attackers use it in real attacks.')
    // why it is urgent is the finding's status lines under the title (the words every list says), not a second line from the CVE record
    expect(within(card).queryByTestId('reasons-line')).toBeNull()
    expect(within(card).getByText(/^Fixed in 8\.0 U3d \(build 24585383\): upgrade/)).toBeInTheDocument()
    expect(within(card).getByRole('link', { name: /^Vendor advisory \(support\.broadcom\.com\)/ })).toHaveAttribute('href', esxiBrief.references[0]!.url)
    expect(within(card).getByText('No workaround is published: install the fix.')).toBeInTheDocument()
    expect(within(card).getByRole('link', { name: 'Open CVE-2025-22225 page' })).toHaveAttribute('href', '/cve/CVE-2025-22225')
    // simple by default: the versions table and the sources sit behind one click
    const more = within(card).getByText('Affected versions, sources and score').closest('details')!
    expect(more).not.toHaveAttribute('open')
    await userEvent.click(within(card).getByText('Affected versions, sources and score'))
    // one row per release train: 8.0 U2 has its own fixed build, so a patched U2d host is not told to move to U3d
    expect(within(more).getAllByRole('row').slice(1).map((r) => r.querySelectorAll('td')[0]!.textContent)).toEqual(['8.0 U3', '8.0 U2', '7.0 U3'])
    // the finding names its fixed release but not its product and train: no row is marked rather than one guessed from the text
    expect(within(more).getAllByRole('row').filter((r) => r.hasAttribute('data-device'))).toEqual([])
    expect(within(more).getByText('All affected versions (58 rows)')).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('a record with a workaround gives it, with no "none published" line', async () => {
    await esxiFinding({ ...brief, workaround: 'Turn off the vulnerable service.' })
    renderApp('/findings/f-2')
    expect(await screen.findByText('Turn off the vulnerable service.')).toBeInTheDocument()
    expect(screen.getByText('If you cannot patch yet:')).toBeInTheDocument()
    expect(screen.queryByText('No workaround is published: install the fix.')).toBeNull()
  })

  it('names the product when neither the CVE record nor the exploited list does: the finding\'s software line, never "The product"', async () => {
    sessionStore.set({ userId: 'u-admin' })
    const real = await api.get<FindingDetail>('/findings/f-2')
    server.use(
      http.get('*/api/v1/findings/f-2', () => HttpResponse.json({ ...real, kev: null, known_version: null })),
      http.get('*/api/v1/findings/f-2/view', async () => {
        const v = await (await fetch(`${location.origin}/api/v1/findings/${records.get()[0]!.id}/view`)).json() as Record<string, unknown>
        return HttpResponse.json({ ...v, id: 'f-2', software: { id: 'sw-nginx', name: 'nginx', version: '1.30.5' } })
      }),
      http.get('*/api/v1/feeds/cve/:id', () => HttpResponse.json({ ...brief, display: null, products: [], matched: null, not_affected: 0 })),
    )
    renderApp('/findings/f-2')
    const card = (await screen.findByRole('heading', { name: /^About CVE-/ })).closest('section')!
    const sentence = await within(card).findByTestId('brief-sentence')
    await waitFor(() => expect(sentence).toHaveTextContent(/^nginx has a flaw/))
    expect(sentence).not.toHaveTextContent(/The product/)
  })

  it('without a brief (a CVE the data does not hold) the card still gives the device\'s fix and the list\'s vendor link', async () => {
    renderApp('/findings/f-2')
    const card = (await screen.findByRole('heading', { name: /^About CVE-/ })).closest('section')!
    expect(await within(card).findByRole('link', { name: 'Vendor advisory (wordpress.org)' })).toHaveAttribute('href', 'https://wordpress.org/news/2026/10/wordpress-7-1-4')
  })
})

describe('the fixed releases table', () => {
  it('marks the device\'s row by product and release train, never by the release text', () => {
    const { unmount } = render(<FixTable b={brief} mark={{ key: 'vmware|esxi', train: '8.0 U2' }} />)
    expect(screen.getAllByRole('row').filter((r) => r.hasAttribute('data-device')).map((r) => r.querySelectorAll('td')[0]!.textContent)).toEqual(['8.0 U2'])
    expect(screen.queryByRole('columnheader', { name: 'Product' })).toBeNull() // one product: the page names it already
    unmount()
    render(<FixTable b={brief} mark={{ key: 'vmware|workstation', train: '8.0 U2' }} />)
    expect(screen.getAllByRole('row').filter((r) => r.hasAttribute('data-device'))).toEqual([])
  })
})

describe('Ask my AI: four headed answers', () => {
  it('shows the answers in a fixed order under the page\'s headings, each with its http(s) links, and skips one the AI left out', () => {
    render(<AiAnswers answers={[
      { key: 'urgency', text: 'Exploited in the wild since 4 Mar 2025.', links: [{ title: 'CISA KEV', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' }] },
      { key: 'affected', text: 'Yes: confirmed by qa@example.com.', links: [] },
      { key: 'fix', text: `Install ${FIXED}.`, links: [{ title: 'Broadcom advisory', url: esxiBrief.references[0]!.url }, { title: 'bad', url: 'javascript:alert(1)' }] },
    ]} />)
    expect(screen.getAllByRole('heading', { level: 4 }).map((h) => h.textContent)).toEqual(['Am I affected?', 'How do I fix it?', 'How urgent is it?'])
    expect(screen.getByRole('link', { name: 'Broadcom advisory' })).toHaveAttribute('href', esxiBrief.references[0]!.url)
    expect(screen.queryByRole('link', { name: 'bad' })).toBeNull()
  })
})
