// "Your firewall" is decided by one rule on the whole finding page: with a confirmed pack (its vendor tab) and without one (the device
// named for the customer's AI). The count test renders both paths over a set of inventories and counts the cases where the two disagree
// or name another firewall than the rule's; it must stay 0.
import { describe, expect, it } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { cleanup } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import { renderApp } from '@/test/render'
import { server } from '@/test/server'
import { api } from '@/lib/api'
import { assetsStore, sessionStore } from '@/mocks/stores'
import type { Asset } from '@/lib/types'
import type { FindingDetail } from './types'
import { wallVendor } from './firewall'

const seen = new Date().toISOString()
const obs = (value: string, source: 'snmp' | 'passive' | 'nmap' = 'snmp') => ({ value, source, confidence: 0.9, seen_at: seen })
function dev(p: Partial<Asset> & { id: string; ip: string; kind: string }): Asset {
  return { site: 'hq', mac: null, hostname: null, vendor: null, model: null, os: null, software: [], services: [], first_seen: seen, last_seen: seen,
    approved: true, fragile: false, origin: 'discovered', ...p } as Asset
}
/** The inventory without its firewalls and routers, confirmed or likely: each case adds its own. */
const base = () => assetsStore.get().filter((a) => !['firewall', 'router'].includes(a.kind) && !['firewall', 'router'].includes(a.guess?.kind ?? '') && !a.id.startsWith('a-w'))

type Case = { name: string; walls: Asset[]; want: string | null; tab: string }
const cases: Case[] = [
  { name: 'a confirmed Fortinet firewall', walls: [dev({ id: 'a-w1', ip: '192.0.2.1', kind: 'firewall', hostname: 'FW-EDGE', vendor: obs('Fortinet') })], want: 'FW-EDGE', tab: 'FortiGate (FortiOS)' },
  // the maker the network card names (Routerboard.com) and the firmware it states tell a MikroTik router, though no row says "MikroTik"
  { name: 'a MikroTik router known by its card and firmware', walls: [dev({ id: 'a-w2', ip: '192.0.2.2', kind: 'router', name: 'ISP router', vendor: obs('Routerboard.com', 'passive'), os: obs('RouterOS 7.16') })], want: 'ISP router', tab: 'MikroTik (RouterOS)' },
  { name: 'only a likely Fortinet firewall', walls: [dev({ id: 'a-w3', ip: '192.0.2.3', kind: 'unknown', hostname: 'fgt-branch', vendor: obs('Fortinet', 'passive'), guess: { kind: 'firewall', confidence: 0.7, evidence: 'FortiGate login page' } } as Partial<Asset> & { id: string; ip: string; kind: string })], want: 'fgt-branch', tab: 'FortiGate (FortiOS)' },
  { name: 'a confirmed router before a likely firewall', walls: [
    dev({ id: 'a-w4', ip: '192.0.2.4', kind: 'unknown', hostname: 'fgt-2', vendor: obs('Fortinet', 'passive'), guess: { kind: 'firewall', confidence: 0.7, evidence: 'FortiGate login page' } } as Partial<Asset> & { id: string; ip: string; kind: string }),
    dev({ id: 'a-w5', ip: '192.0.2.5', kind: 'router', hostname: 'core-rt', vendor: obs('MikroTik'), os: obs('RouterOS 7.16') }),
  ], want: 'core-rt', tab: 'MikroTik (RouterOS)' },
  { name: 'a router whose maker Vedette does not know', walls: [dev({ id: 'a-w6', ip: '192.0.2.6', kind: 'router', hostname: 'gw-home' })], want: 'gw-home', tab: 'Other device' },
  { name: 'no firewall', walls: [], want: null, tab: 'Other device' },
]

/** f-2 without a pack (the no-pack path) and f-1 with QNAP's confirmed pack. */
async function setNoPack() {
  const real = await api.get<FindingDetail>('/findings/f-2')
  server.use(http.get('*/api/v1/findings/f-2', () => HttpResponse.json({ ...real, pack: null })))
}

describe('one firewall rule for the finding page', () => {
  it('count: the pack tab and the no-pack page name the same firewall, the one the rule picks (0 disagreements)', async () => {
    sessionStore.set({ userId: 'u-admin' })
    const wrong: string[] = []
    for (const c of cases) {
      assetsStore.set([...base(), ...c.walls])
      await setNoPack()
      renderApp('/findings/f-2')
      const step = await screen.findByTestId('firewall-step')
      // wait for the firewall list: the picker (a firewall) or the add button (none)
      await within(step).findByText(c.want ? /^Which firewall protects / : /knows no firewall/, {}, { timeout: 3000 }).catch(() => { throw new Error(`${c.name}: ${step.textContent}`) })
      if (c.want && !step.textContent?.includes(c.want)) wrong.push(`${c.name}: the page without a pack does not name ${c.want}`)
      if (!c.want && step.textContent?.match(/192\.0\.2\./)) wrong.push(`${c.name}: the page without a pack names a firewall`)
      cleanup()

      renderApp('/findings/f-1')
      const fw = (await screen.findByRole('heading', { name: '3. Firewall configuration to cut off access' })).closest('section')!
      const pressed = await within(fw).findByRole('button', { pressed: true })
      if (!pressed.textContent?.startsWith(c.tab)) wrong.push(`${c.name}: the pack opens "${pressed.textContent}", not ${c.tab}`)
      if (c.want && !fw.textContent?.includes(c.want)) wrong.push(`${c.name}: the pack does not name ${c.want}`)
      cleanup()
    }
    console.info(`firewall rule: ${wrong.length} of ${cases.length * 2} checks disagree`, wrong)
    expect(wrong).toEqual([])
  }, 30_000)

  it('a likely firewall is offered and confirmed right on the finding', async () => {
    sessionStore.set({ userId: 'u-admin' })
    assetsStore.set([...base(), ...cases[2]!.walls])
    await setNoPack()
    renderApp('/findings/f-2')
    const step = await screen.findByTestId('firewall-step')
    expect(await within(step).findByText(/^fgt-branch \(192\.0\.2\.3\) · likely Firewall$/)).toBeInTheDocument()
    await userEvent.click(within(step).getByRole('button', { name: 'Confirm: Firewall' }))
    expect(await screen.findByText('fgt-branch is now a Firewall in Vedette.')).toBeInTheDocument()
    expect(assetsStore.get().find((a) => a.id === 'a-w3')!.kind).toBe('firewall')
  })

  it('several firewalls: the person picks the one in front of the device, and the pack tab follows', async () => {
    sessionStore.set({ userId: 'u-admin' })
    assetsStore.set([...base(), ...cases[3]!.walls])
    renderApp('/findings/f-1')
    const fw = (await screen.findByRole('heading', { name: '3. Firewall configuration to cut off access' })).closest('section')!
    expect(await within(fw).findByRole('button', { name: 'MikroTik (RouterOS) (your firewall)' })).toHaveAttribute('aria-pressed', 'true')
    await userEvent.selectOptions(within(fw).getByLabelText(/^Which firewall protects /), 'a-w4')
    expect(await within(fw).findByRole('button', { name: 'FortiGate (FortiOS) (your firewall)' })).toHaveAttribute('aria-pressed', 'true')
  })

  it('maker words: Fortinet and MikroTik are told from their maker, model, firmware or names', () => {
    expect(wallVendor({ vendor: null, model: obs('FortiGate 60F'), os: null, hostname: null, name: null })).toBe('fortigate')
    expect(wallVendor({ vendor: null, model: null, os: obs('RouterOS 7.16'), hostname: null, name: null })).toBe('mikrotik')
    expect(wallVendor({ vendor: obs('Cisco'), model: null, os: null, hostname: 'gw', name: null })).toBeNull()
  })
})

describe('a pack for a local flaw', () => {
  it('says no firewall rule helps, never that no firewall is declared, and offers no vendor tabs', async () => {
    sessionStore.set({ userId: 'u-admin' })
    const real = await api.get<FindingDetail>('/findings/f-1')
    server.use(http.get('*/api/v1/findings/f-1', () => HttpResponse.json({ ...real, pack: { ...real.pack!, firewall: [{ vendor: 'generic', label: 'No firewall rule helps', detected: false, intro: 'The attacker works from inside a virtual machine.', steps: [], verify: [], undo: [], plain: ['Update the host.'] }] } })))
    renderApp('/findings/f-1')
    const fw = (await screen.findByRole('heading', { name: '3. Firewall configuration to cut off access' })).closest('section')!
    expect(await within(fw).findByText('No firewall rule helps for this CVE.')).toBeInTheDocument()
    expect(within(fw).queryByText(/No firewall declared/)).toBeNull()
    expect(within(fw).queryByRole('button', { pressed: true })).toBeNull()
    expect(within(fw).queryByRole('button', { name: 'Applied' })).toBeNull()
  })
})

describe('a device with no address', () => {
  it('says what to put in place of <IP> and links to the device to add it', async () => {
    sessionStore.set({ userId: 'u-admin' })
    const real = await api.get<FindingDetail>('/findings/f-1')
    const pack = real.pack!
    server.use(http.get('*/api/v1/findings/f-1', () => HttpResponse.json({ ...real, asset: { ...real.asset!, ip: '—', name: 'nas-office' },
      pack: { ...pack, firewall: pack.firewall.map((g) => ({ ...g, steps: g.steps.map((s) => ({ ...s, code: s.code ? `${s.code}\n# host <IP>` : s.code })) })) } })))
    renderApp('/findings/f-1')
    const fw = (await screen.findByRole('heading', { name: '3. Firewall configuration to cut off access' })).closest('section')!
    const note = await within(fw).findByTestId('no-address')
    expect(note).toHaveTextContent('nas-office has no address in Vedette: replace <IP> in the commands with its address.')
    expect(within(note).getByRole('link', { name: 'Add its address' })).toHaveAttribute('href', `/devices/${real.asset!.id}`)
  })
})
