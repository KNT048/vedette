// The finding page tells one story (S-MIT-1, S-MIT-3): one "What to do" section with the fix this device needs first, the vendor's
// workaround or plainly none, the firewall step (a confirmed pack or the customer's own AI writes configuration, never Vedette's
// guesswork, and the firewall can be added right there), a checklist, and "Have I been hit?" that says when nothing is specific to the CVE.
import { describe, expect, it } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp } from '@/test/render'
import { server } from '@/test/server'
import { api } from '@/lib/api'
import { sessionStore } from '@/mocks/stores'
import { esxiBrief } from '@/features/feeds/briefSamples'
import type { CveBrief } from '@/features/feeds/types'
import type { DevicesResponse } from '@/features/inventory/types'
import i18n from '@/lib/i18n'
import { vendorOwned } from './CveBrief'
import { storedFixText } from './WhatToDo'
import { records } from './modelMocks'
import type { DeviceCards, FindingDetail, View } from './types'

/** f-2 as an ESXi host's finding whose fixed_in the page cannot read (NVD lists exact versions), while the stored fix names VMware's build. */
async function esxi(over: Partial<FindingDetail> = {}, brief: Partial<CveBrief> = {}) {
  sessionStore.set({ userId: 'u-admin' })
  const real = await api.get<FindingDetail>('/findings/f-2')
  const view = await api.get<View>(`/findings/${records.get()[0]!.id}/view`)
  const f: FindingDetail = {
    ...real, cve: 'CVE-2025-22225', fixed_in: null, pack: null,
    kev: real.kev ? { ...real.kev, display: 'VMware ESXi', links: [] } : null,
    known_version: { software: 'VMware ESXi', version: '8.0.3', source: 'snmp', seen_at: '2026-11-20T08:00:00Z' },
    ...over,
  }
  server.use(
    http.get('*/api/v1/findings/f-2', () => HttpResponse.json(f)),
    http.get('*/api/v1/findings/f-2/view', () => HttpResponse.json({ ...view, fix: { key: 'vmware|esxi|update|8.0 U3d', kind: 'update', product: 'VMware ESXi', version: '8.0 U3d (build 24585383)', ref: null, url: null } })),
    http.get('*/api/v1/feeds/cve/:id', () => HttpResponse.json({ ...esxiBrief, ...brief, matched: null, not_affected: 0 })),
  )
  return f
}

const todo = async () => (await screen.findByRole('heading', { level: 2, name: 'What to do' })).closest('section')!

describe('What to do: one section, the fix first', () => {
  it('names the stored fix of this device when NVD\'s ranges give none, then the advisory, the workaround line and a checklist', async () => {
    await esxi()
    renderApp('/findings/f-2')
    const s = await todo()
    expect(await within(s).findByText(/^Fixed in 8\.0 U3d \(build 24585383\): update VMware ESXi on .+ from 8\.0\.3 to 8\.0 U3d \(build 24585383\) or later\.$/)).toBeInTheDocument()
    expect(within(s).queryByText('Install the fixed release the vendor advisory names.')).toBeNull()
    expect(within(s).getByText('No workaround is published: install the fix.')).toBeInTheDocument()
    expect(within(s).getByText(/shows 8\.0 U3d \(build 24585383\) or later\.$/)).toBeInTheDocument() // the checklist's version line
    // one "What to do" on the page
    expect(screen.getAllByRole('heading', { name: 'What to do' })).toHaveLength(1)
  })

  it('a vendor\'s workaround is given, and the checklist asks to undo it after the update', async () => {
    await esxi({}, { workaround: 'Disable J-Web, or limit access to only trusted hosts.' })
    renderApp('/findings/f-2')
    const s = await todo()
    expect(await within(s).findByText('Disable J-Web, or limit access to only trusted hosts.')).toBeInTheDocument()
    expect(within(s).getByText(/^If you put the workaround in place, undo it/)).toBeInTheDocument()
  })
})

describe('step 1 names the fix every list names, and what the plan names', () => {
  const t = i18n.getFixedT('en', 'findings')
  // count: every kind of stored fix that carries a version gets its own sentence in step 1 (none falls back to "no advisory is linked")
  it('count: every fix kind with a release has a step-1 sentence (0 missing)', async () => {
    sessionStore.set({ userId: 'u-admin' })
    const f = await api.get<FindingDetail>('/findings/f-2')
    const view = await api.get<View>(`/findings/${records.get()[0]!.id}/view`)
    const kinds = ['update', 'distro_update', 'os_update', 'feature_update', 'restart'] as const
    const missing = kinds.filter((kind) => !storedFixText(t, f, { ...view, fix: { key: `k|${kind}`, kind, product: 'Kernel', version: '7.0.0-44.44', ref: null, channel: 'public', url: null } }))
    console.info(`step 1: ${missing.length} of ${kinds.length} fix kinds without a sentence`, missing)
    expect(missing).toEqual([])
  })

  it('the fixed kernel is installed: step 1 is the restart, no workaround is needed, and the checklist starts with the restart', async () => {
    const f = await esxi({ kev: null, known_version: { software: 'Kernel', version: '7.0.0', source: 'agent', seen_at: '2026-11-20T08:00:00Z' } })
    const view = await api.get<View>(`/findings/${records.get()[0]!.id}/view`)
    server.use(http.get('*/api/v1/findings/f-2/view', () => HttpResponse.json({ ...view, fix: { key: 'linux|kernel|restart|7.0.0-44.44', kind: 'restart', product: 'Kernel', version: '7.0.0-44.44', ref: null, channel: 'public', url: null } })))
    renderApp('/findings/f-2')
    const s = await todo()
    const device = f.asset!.name
    expect(await within(s).findByText(`The fixed Kernel 7.0.0-44.44 is already installed on ${device}: restart ${device} so it runs it.`)).toBeInTheDocument()
    expect(within(s).getByText(`No workaround is needed: the fix is installed and takes effect when ${device} restarts.`)).toBeInTheDocument()
    expect(within(s).queryByText('No workaround is published: install the fix.')).toBeNull()
    expect(within(s).getByText(`Restart ${device}: it runs the old Kernel until then.`)).toBeInTheDocument()
  })

  it('the plan names a later release: step 1 says the plan\'s release also fixes it, never that the two are the same', async () => {
    const f = await esxi()
    server.use(http.get('*/api/v1/findings/devices', () => HttpResponse.json({
      items: [{ device: { id: f.asset!.id, name: f.asset!.name, ip: null, kind: 'hypervisor', added: true, ignored: false }, status: { code: 'exploited', count: 1 }, counts: { under_attack: 0, exploited: 1, public_exploit: 0, critical_edge: 0, update_recommended: 0 }, findings: 1, cves: 1,
        blocks: [{ fix: { key: 'vmware|esxi|update|8.0 U3k', kind: 'update', product: 'VMware ESXi', version: '8.0 U3k', ref: null, url: null }, software: null, status: 'exploited', cause: f.cve,
          severity: { critical: 0, high: 1, medium: 0, low: 0, none: 0, unscored: 0 }, findings: [{ id: f.id, cve: f.cve, status: 'exploited', severity: null, verified: 'no', safe_check: false, urgency: { layer: 2, reasons: [] }, verification: { verified: 'no' } }] }] }],
      total: 1,
    } as unknown as DeviceCards)))
    renderApp('/findings/f-2')
    const s = await todo()
    expect(await within(s).findByText(`The plan updates VMware ESXi on ${f.asset!.name} to 8.0 U3k, a later release that also fixes this CVE.`)).toBeInTheDocument()
    expect(within(s).queryByText(/The same release the findings list and the plan name/)).toBeNull()
  })
})

describe('What to do: the firewall step', () => {
  it('says no configuration is published, names the firewall Vedette knows and offers the customer\'s AI', async () => {
    await esxi()
    renderApp('/findings/f-2')
    const step = await screen.findByTestId('firewall-step')
    expect(within(step).getByText(/^No firewall configuration is published for CVE-2025-22225: Vedette maintainers have not confirmed one/)).toBeInTheDocument()
    expect(await within(step).findByText(/^Which firewall protects .+\?$/)).toBeInTheDocument()
    expect(within(step).getByRole('link', { name: 'Open the device' })).toHaveAttribute('href', '/devices/a-fw01')
    expect(within(step).getByRole('button', { name: 'Ask my AI' })).toBeInTheDocument()
    expect(within(step).queryByRole('textbox')).toBeNull() // no admin-network field, no generated config
  })

  it('without a firewall in Vedette, "Add your firewall" opens the add dialog right there', async () => {
    await esxi()
    server.use(http.get('*/api/v1/inventory/devices', () => HttpResponse.json({ items: [], counts: { all: 0, pending: 0, fragile: 0, manual: 0, ignored: 0 }, notify_new: false, notify_available: true } as unknown as DevicesResponse)))
    renderApp('/findings/f-2')
    const step = await screen.findByTestId('firewall-step')
    await userEvent.click(await within(step).findByRole('button', { name: 'Add your firewall' }))
    expect(await screen.findByRole('dialog')).toBeInTheDocument()
  })
})

describe('Have I been hit? without a confirmed pack', () => {
  it('says nothing specific to the CVE is held and links the reports of the attacks', async () => {
    await esxi({}, {
      signals: [{ kind: 'exploited', source: 'rapid7', source_name: 'Rapid7', first_seen: '2025-03-04T00:00:00Z', last_seen: '2025-03-04T00:00:00Z', qualifies: true, url: 'https://www.rapid7.com/blog/post/esxi-attacks/', detail: null }],
    })
    renderApp('/findings/f-2')
    const r = await screen.findByTestId('attack-reports')
    expect(within(r).getByText(/^No exploitation signs specific to CVE-2025-22225 are in Vedette's data\. These reports/)).toBeInTheDocument()
    expect(within(r).getByRole('link', { name: 'https://www.rapid7.com/blog/post/esxi-attacks/' })).toBeInTheDocument()
  })
})

describe('the headline says one thing', () => {
  it('a suspected finding an attack reached here says both, not "needs checking" beside "Under attack here" alone', async () => {
    await esxi({ status: 'suspected', urgency: 1 })
    renderApp('/findings/f-2')
    expect(await screen.findByRole('heading', { level: 1, name: /^Someone on your network sent the CVE-2025-22225 exploit to .*: whether it is affected still needs checking$/ })).toBeInTheDocument()
  })
})

describe('vendor links', () => {
  it('a code-hosting link is the vendor\'s only when its owner is the vendor or the product', () => {
    const names = ['nginx', 'F5 nginx']
    expect(vendorOwned('https://github.com/nginx/nginx/commit/abc', names)).toBe(true)
    expect(vendorOwned('https://github.com/chainguard-forks/ingress-nginx/pull/68', names)).toBe(false)
    expect(vendorOwned('https://github.com/kubernetes/ingress-nginx/pull/68', names)).toBe(false)
    expect(vendorOwned('https://nginx.org/en/security_advisories.html', names)).toBe(true)
  })

  it('the owner must be the vendor\'s own name, not any account whose name merely contains a product word', () => {
    const nginx = ['nginx', 'F5 nginx']
    expect(vendorOwned('https://github.com/nginxinc/nginx-plus/commit/abc', nginx)).toBe(true)
    expect(vendorOwned('https://github.com/nginx-hater/exploit/blob/main/README.md', nginx)).toBe(false)
    expect(vendorOwned('https://github.com/mynginxtools/patch', nginx)).toBe(false)
    const pan = ['Palo Alto Networks', 'PAN-OS']
    expect(vendorOwned('https://github.com/PaloAltoNetworks/advisories', pan)).toBe(true)
    expect(vendorOwned('https://github.com/altoids/pan-os-poc', pan)).toBe(false)
    expect(vendorOwned('https://gitlab.com/networks-lab/poc', pan)).toBe(false)
    expect(vendorOwned('https://github.com/F5Networks/f5-ansible', ['F5', 'BIG-IP'])).toBe(true)
  })
})
