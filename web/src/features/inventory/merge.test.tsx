import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { assetsStore, sessionStore } from '@/mocks/stores'
import type { Asset } from '@/lib/types'
import { ensureBox } from './mocks'
import { choiceFields, defaultKeep, matchesQuery, movePieces, nameScore, rankCandidates, shownDiffers, splitBlock, watchAfterMergeAll } from './mergeLogic'
import type { DeviceRow, MergeField, MergePreview, MergeSide } from './types'

vi.setConfig({ testTimeout: 30_000 })

const T = { timeout: 5000 }
const BASE = `${location.origin}/api/v1/inventory`
const ago = (days: number) => new Date(Date.now() - days * 864e5).toISOString()
const obs = (value: string, source: 'snmp' | 'passive' | 'agent') => ({ value, source, confidence: 0.9, seen_at: ago(0) })
const dev = (p: Partial<Asset> & { id: string }): Asset => ({
  site: 'hq', ip: '192.0.2.50', mac: null, hostname: null, kind: 'unknown', vendor: null, model: null, os: null, software: [], services: [],
  first_seen: ago(30), last_seen: ago(0), approved: true, fragile: false, origin: 'discovered', ...p,
})
const agentLine = (id: string) => ({ id, display: 'OpenSSH', vendor: 'OpenBSD', product: 'OpenSSH', version: '9.6p1', kev: [], source: 'agent' as const, confidence: 0.95, not_installed: false })
// One firewall seen as two rows: named by SNMP at one interface, and a maker-only row from passive data at another.
const FW = dev({ id: 'a-dm-fw', ip: '192.0.2.1', mac: '00:09:0f:00:00:01', hostname: 'fw-edge', kind: 'firewall', vendor: obs('Fortinet', 'snmp'), model: obs('FortiGate 60F', 'snmp'), last_seen: ago(1) })
const IF2 = dev({ id: 'a-dm-if2', ip: '192.0.2.254', mac: '00:09:0f:00:00:02', vendor: obs('Fortinet, Inc.', 'passive'), services: [{ port: 443, proto: 'tcp', name: 'https', source: 'nmap', confidence: 0.8 }] })
// Two servers an agent reports from each: two machines, the box refuses to merge them.
const SRV = dev({ id: 'a-dm-srv', ip: '192.0.2.10', mac: '00:15:5d:00:00:10', hostname: 'srv-app', kind: 'server', software: [agentLine('s-dm-1')] })
const SRV2 = dev({ id: 'a-dm-srv2', ip: '192.0.2.11', mac: '00:15:5d:00:00:11', hostname: 'srv-db', kind: 'server', software: [agentLine('s-dm-2')] })

beforeEach(() => {
  ensureBox()
  assetsStore.update((l) => [...l.filter((a) => !a.id.startsWith('a-dm-')), FW, IF2, SRV, SRV2])
})

const side = (p: Partial<MergeSide> & { id: string }): MergeSide => ({
  name: p.id, approved: true, ignored: false, agent: false, addresses: [], software: 0, open_ports: 0, findings: 0, risk: null, last_seen: ago(1), ...p,
})
const addr = (ip: string, more: Partial<{ main: boolean; agent: boolean; mac: string }> = {}) => ({ ip, mac: more.mac ?? null, main: !!more.main, source: 'passive', first_seen: ago(3), last_seen: ago(1), agent: !!more.agent })

describe('merge logic', () => {
  it('keeps the agent\'s device, then the approved, watched, named one, then the one with the most findings', () => {
    expect(defaultKeep([side({ id: 'a', findings: 9 }), side({ id: 'b', agent: true, approved: false })])).toBe('b')
    expect(defaultKeep([side({ id: 'a', approved: false, findings: 9 }), side({ id: 'b' })])).toBe('b')
    expect(defaultKeep([side({ id: 'a', ignored: true }), side({ id: 'b' })])).toBe('b')
    const named = (id: string) => (id === 'b' ? 1 : 0)
    expect(defaultKeep([side({ id: 'a', findings: 3 }), side({ id: 'b' })], named)).toBe('b')
    expect(defaultKeep([side({ id: 'a', findings: 1 }), side({ id: 'b', findings: 2 })])).toBe('b')
    // a tie keeps the first given (one last_seen for both: two calls of ago() a millisecond apart are no tie)
    const seen = ago(1)
    expect(defaultKeep([side({ id: 'a', last_seen: seen }), side({ id: 'b', last_seen: seen })])).toBe('a')
    expect(nameScore({ name: 'Edge', hostname: null })).toBe(2)
    expect(nameScore({ name: null, hostname: 'fw' })).toBe(1)
    expect(nameScore({ name: '  ', hostname: null })).toBe(0)
  })

  it('shows only the fields with two values or more, each value once with its devices, and sends only what the person changed', () => {
    const differs: MergeField[] = [
      { field: 'name', values: [{ device: 'a', value: 'fw-edge' }, { device: 'b', value: 'Fortinet, Inc.' }], kept: 'fw-edge', choosable: true, missing: [] },
      { field: 'kind', values: [{ device: 'a', value: 'firewall' }, { device: 'b', value: 'firewall' }], kept: 'firewall', choosable: true, missing: [] },
      { field: 'vendor', values: [{ device: 'a', value: 'Fortinet' }, { device: 'b', value: 'Fortinet, Inc.' }, { device: 'c', value: 'Fortinet' }], kept: 'Fortinet', choosable: false, missing: [] },
    ]
    const shown = shownDiffers(differs)
    expect(shown.map((f) => f.field)).toEqual(['name', 'vendor'])
    expect(shown[1]!.options).toEqual([{ value: 'Fortinet', devices: ['a', 'c'] }, { value: 'Fortinet, Inc.', devices: ['b'] }])
    // a type or OS only one device states is a row too; a guessed type says so, and "unknown" is what the merge keeps without one
    const only = shownDiffers([
      { field: 'kind', values: [{ device: 'b', value: 'hypervisor', guess: true }], kept: 'unknown', choosable: true, missing: ['a'] },
      { field: 'os', values: [{ device: 'b', value: 'VMware ESXi 8.0 Update 3' }], kept: 'VMware ESXi 8.0 Update 3', choosable: true, missing: ['a'] },
      { field: 'model', values: [{ device: 'b', value: 'ProLiant' }], kept: 'ProLiant', choosable: false, missing: [] },
    ])
    expect(only.map((f) => f.field)).toEqual(['kind', 'os'])
    expect(only[0]!.options).toEqual([{ value: 'unknown', devices: [] }, { value: 'hypervisor', devices: ['b'], guess: true }])
    expect(only[1]!.missing).toEqual(['a'])
    expect(choiceFields(only, { kind: 'hypervisor' })).toEqual({ kind: 'hypervisor' })
    expect(choiceFields(shown, {})).toBeUndefined()
    expect(choiceFields(shown, { name: 'fw-edge' })).toBeUndefined() // the merge's own result is not sent
    expect(choiceFields(shown, { name: 'Fortinet, Inc.', vendor: 'Fortinet, Inc.' })).toEqual({ name: 'Fortinet, Inc.' }) // the maker follows the sources
    expect(choiceFields(shown, { name: 'something else' })).toBeUndefined() // never a value none of them has
  })

  it('sums up what moves, the most urgent first, and names the addresses', () => {
    const p: Pick<MergePreview, 'moves' | 'from'> = {
      moves: { addresses: 4, software_new: 9, software_shared: 5, readings: 20, open_ports: 4, findings: 3, exploited: 2 },
      from: [side({ id: 'b', addresses: [addr('192.0.2.254', { main: true }), addr('192.0.2.253')] }), side({ id: 'c', addresses: [addr('192.0.2.252', { main: true }), { ...addr('x'), ip: null, mac: '00:09:0f:00:00:09' }] })],
    }
    expect(movePieces(p)).toEqual([
      { key: 'exploited', count: 2 }, { key: 'findings', count: 3 }, { key: 'software', count: 14, fresh: 9 }, { key: 'ports', count: 4 },
      { key: 'addresses', count: 4, list: ['192.0.2.254', '192.0.2.253', '192.0.2.252'], more: 1 },
    ])
    expect(movePieces({ moves: { addresses: 0, software_new: 0, software_shared: 0, readings: 0, open_ports: 0, findings: 0, exploited: 0 }, from: [side({ id: 'b' })] })).toEqual([])
  })

  it('says why an address cannot be split off: the only one, or the agent\'s', () => {
    const main = addr('192.0.2.1', { main: true, agent: true })
    expect(splitBlock(main, [main])).toBe('only')
    expect(splitBlock(main, [main, addr('192.0.2.2')])).toBe('agent')
    expect(splitBlock(addr('192.0.2.2'), [main, addr('192.0.2.2')])).toBe('')
  })

  it('names the watch state that matters most over every device that joins', () => {
    expect(watchAfterMergeAll({ ignored: true }, [{ ignored: false, approved: false }, { ignored: false, approved: true }])).toBe('watchedAgain')
    expect(watchAfterMergeAll({ ignored: false }, [{ ignored: true, approved: true }])).toBe('staysWatched')
    expect(watchAfterMergeAll({ ignored: false }, [{ ignored: false, approved: true }])).toBe('')
  })

  it('ranks the picker: suggestions, then the same model, name or maker, then the next MAC of the same block, then the rest; never itself or the box', () => {
    const row = (p: Partial<DeviceRow> & { id: string }) => ({ ip: '198.51.100.9', hostname: null, name: null, vendor: null, model: null, is_box: false, mac: null, ...p }) as DeviceRow
    const rows = [
      row({ id: 'me', ip: '192.0.2.1' }), row({ id: 'box', is_box: true, ip: '192.0.2.2' }),
      row({ id: 'far', hostname: 'printer' }), row({ id: 'near5', ip: '192.0.2.5', mac: '52:54:00:76:6d:07' }), row({ id: 'near3', ip: '192.0.2.3', mac: '52:54:00:76:6d:03' }),
      row({ id: 'sameNet', ip: '192.0.2.4' }), row({ id: 'farMac', ip: '192.0.2.6', mac: '52:54:00:76:6d:40' }),
      row({ id: 'maker', vendor: { value: 'Fortinet, Inc.', source: 'passive', confidence: 0.5, seen_at: ago(0) } }),
      row({ id: 'model', model: { value: 'FortiGate 60F', source: 'snmp', confidence: 0.9, seen_at: ago(0) } }),
      row({ id: 'sug', ip: '10.0.0.1' }),
    ]
    const me = { id: 'me', name: null, hostname: 'fw-edge', vendor: { value: 'Fortinet', source: 'snmp' as const, confidence: 0.9, seen_at: ago(0) }, model: { value: 'FortiGate 60F', source: 'snmp' as const, confidence: 0.9, seen_at: ago(0) }, macs: ['52:54:00:76:6d:02'] }
    const out = rankCandidates(me, rows, [{ id: 'sug', reason: 'mac_block', why: 'Burned-in MACs of one block' }], (r) => r.hostname ?? r.id)
    // an address in the same subnet alone is no reason: only a MAC next to one of the device's (the same block, a few apart)
    expect(out.map((c) => c.row.id)).toEqual(['sug', 'model', 'maker', 'near3', 'near5', 'farMac', 'far', 'sameNet'])
    expect(out.map((c) => c.group)).toEqual(['suggested', 'similar', 'similar', 'nearby', 'nearby', 'other', 'other', 'other'])
    expect(out.find((c) => c.row.id === 'near3')!.near).toBe('52:54:00:76:6d:02')
    expect(matchesQuery(row({ id: 'm', mac: '00:09:0f:00:00:02' }), 'x', '0009.0f00.0002')).toBe(true)
    expect(matchesQuery(row({ id: 'm', mac: '00:09:0f:00:00:02' }), 'x', '00:09:0f:00:00:03')).toBe(false)
  })
})

describe('Devices list: select rows and merge them', () => {
  it('Merge (2) opens one dialog: the named device kept, only the fields that differ, what moves; the list keeps its search', async () => {
    const user = userEvent.setup()
    renderApp('/devices?tab=devices&q=192.0.2', { role: 'admin' })
    await user.click(await screen.findByRole('checkbox', { name: 'Select fw-edge' }, T))
    // one row is not a merge: the button is there, off, and says why
    expect(screen.getByRole('button', { name: 'Merge the 1 selected devices' })).toBeDisabled()
    expect(screen.getByText(/Select two or more devices to merge them/)).toBeInTheDocument()
    await user.click(screen.getByRole('checkbox', { name: 'Select Fortinet, Inc. device' }))
    await user.click(screen.getByRole('button', { name: 'Merge the 2 selected devices' }))

    const dialog = await screen.findByRole('dialog', { name: 'Merge 2 devices' }, T)
    const keep = within(dialog).getByRole('radiogroup', { name: 'Device to keep' })
    const kept = await within(keep).findByRole('radio', { name: /^fw-edge/, checked: true }, T)
    expect(kept.closest('div')).toHaveTextContent('Suggested')
    expect(await within(dialog).findByText('Where they differ', undefined, T)).toBeInTheDocument()
    expect(within(dialog).getByRole('radiogroup', { name: 'Name' })).toBeInTheDocument()
    expect(within(dialog).getByText('Keeps Fortinet')).toBeInTheDocument() // the maker follows the sources: no choice
    // only fw-edge states a type: the type row says so, with the device that has none
    expect(within(dialog).getByRole('radiogroup', { name: 'Type' })).toBeInTheDocument()
    expect(within(dialog).getByText('None on Fortinet, Inc. device')).toBeInTheDocument()
    expect(within(dialog).queryByText('Model')).toBeNull()
    expect(within(dialog).getByTestId('merge-moves')).toHaveTextContent('1 open port')
    expect(within(dialog).getByTestId('merge-moves')).toHaveTextContent('address 192.0.2.254')

    await user.click(within(dialog).getByRole('button', { name: 'Merge 2 devices' }))
    expect(await screen.findByText('Merged 2 devices into fw-edge.', undefined, T)).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull(), T)
    // the list stays where it was: same search, the device that went is gone from it, nothing selected any more
    expect(screen.getByRole('combobox', { name: 'Search devices' })).toHaveValue('192.0.2')
    await waitFor(() => expect(screen.queryByRole('checkbox', { name: 'Select Fortinet, Inc. device' })).toBeNull(), T)
    expect(screen.queryByRole('button', { name: /^Merge the/ })).toBeNull()
    expect(assetsStore.get().some((a) => a.id === 'a-dm-if2')).toBe(false)

    // the toast's Split leads to the kept device's addresses, where the merged one can be split off again
    fireEvent.click(screen.getByRole('button', { name: 'Split' })) // no pointer events: sonner's swipe handler needs setPointerCapture, which jsdom lacks
    const section = await screen.findByRole('region', { name: 'Addresses' }, T)
    expect(within(section).getByRole('button', { name: 'Split 192.0.2.254 off' })).toBeEnabled()
  })

  it('the preview\'s refusal is shown plainly and Merge is not offered: two agents say two machines', async () => {
    const user = userEvent.setup()
    renderApp('/devices?tab=devices', { role: 'admin' })
    await user.click(await screen.findByRole('checkbox', { name: 'Select srv-app' }, T))
    await user.click(screen.getByRole('checkbox', { name: 'Select srv-db' }))
    await user.click(screen.getByRole('button', { name: 'Merge the 2 selected devices' }))
    const dialog = await screen.findByRole('dialog', { name: 'Merge 2 devices' }, T)
    const alert = await within(dialog).findByRole('alert', undefined, T)
    expect(alert).toHaveTextContent('These devices cannot be merged')
    expect(alert).toHaveTextContent('an agent reports from each of')
    expect(within(dialog).getByRole('button', { name: 'Merge 2 devices' })).toBeDisabled()
  })

  it('an operator has no selection for merging and no row menu', async () => {
    renderApp('/devices?tab=devices', { role: 'operator' })
    expect(await screen.findByRole('link', { name: 'fw-edge' }, T)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Actions for fw-edge' })).toBeNull()
  })
})

describe('Device page: Merge with… and the Addresses section', () => {
  it('the picker offers the similar rows first, searches by MAC, and Back keeps the picks', async () => {
    const user = userEvent.setup()
    renderApp('/devices/a-dm-fw', { role: 'admin' })
    const section = await screen.findByRole('region', { name: 'Addresses' }, T)
    await user.click(within(section).getByRole('button', { name: 'Merge with…' }))
    const dialog = await screen.findByRole('dialog', { name: 'Merge fw-edge with…' }, T)
    const list = await within(dialog).findByTestId('merge-candidates', undefined, T)
    const similar = within(list).getByRole('region', { name: 'Similar devices' })
    expect(within(similar).getByRole('checkbox', { name: /Fortinet, Inc\..*Same maker: Fortinet, Inc\./ })).toBeInTheDocument()
    expect(within(list).getAllByRole('region')[0]).toBe(similar) // no suggestion of the box here: similar devices come first

    await user.type(within(dialog).getByRole('searchbox', { name: 'Search by name, IP or MAC' }), '00:09:0f:00:00:02')
    expect(within(dialog).getAllByRole('checkbox')).toHaveLength(1)
    // the device itself is never offered: searching for it says why rather than "no device matches"
    const search = within(dialog).getByRole('searchbox', { name: 'Search by name, IP or MAC' })
    await user.clear(search)
    await user.type(search, 'fw-edge')
    expect(within(dialog).getByText('fw-edge is the device you are merging into: pick the other device.')).toBeInTheDocument()
    await user.clear(search)
    await user.type(search, '00:09:0f:00:00:02')
    const next = within(dialog).getByRole('button', { name: 'Continue' })
    expect(next).toBeDisabled()
    await user.click(within(dialog).getByRole('checkbox', { name: /Fortinet, Inc\./ }))
    await user.click(next)
    expect(await within(dialog).findByRole('radiogroup', { name: 'Device to keep' }, T)).toBeInTheDocument()
    expect(screen.getByRole('dialog', { name: 'Merge 2 devices' })).toBe(dialog)
    await user.click(within(dialog).getByRole('button', { name: 'Back' }))
    expect(within(dialog).getByRole('checkbox', { name: /Fortinet, Inc\./ })).toBeChecked()
    await user.click(within(dialog).getByRole('button', { name: 'Continue' }))
    const go = within(dialog).getByRole('button', { name: 'Merge 2 devices' })
    await waitFor(() => expect(go).toBeEnabled(), T)
    await user.click(go)
    expect(await screen.findByText('Merged 2 devices into fw-edge.', undefined, T)).toBeInTheDocument()
    expect(await within(section).findByText('192.0.2.254', undefined, T)).toBeInTheDocument()
  })

  it('Split off is disabled with its reason for the only address and the agent\'s; another address splits off after a confirm', async () => {
    const user = userEvent.setup()
    const { unmount } = renderApp('/devices/a-dm-srv', { role: 'admin' })
    let section = await screen.findByRole('region', { name: 'Addresses' }, T)
    expect(within(section).getByRole('button', { name: 'Split 192.0.2.10 off' })).toBeDisabled()
    expect(section).toHaveTextContent('The only address of this device.')
    unmount()

    // the firewall's second interface joins the server (nothing refuses it), then goes again
    sessionStore.set({ userId: 'u-admin' })
    expect((await fetch(`${BASE}/devices/a-dm-srv/merge`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ from: ['a-dm-if2'] }) })).ok).toBe(true)
    renderApp('/devices/a-dm-srv', { role: 'admin' })
    section = await screen.findByRole('region', { name: 'Addresses' }, T)
    const agentRow = within(section).getByRole('button', { name: 'Split 192.0.2.10 off' })
    expect(agentRow).toBeDisabled()
    expect(agentRow).toHaveAccessibleDescription("The agent reports from this address: it stays with the agent's machine.")
    await user.click(within(section).getByRole('button', { name: 'Split 192.0.2.254 off' }))
    const dialog = await screen.findByRole('dialog', { name: 'Split 192.0.2.254 off srv-app?' }, T)
    expect(dialog).toHaveTextContent('becomes a device of its own')
    await user.click(within(dialog).getByRole('button', { name: 'Split off' }))
    expect(await screen.findByText('192.0.2.254 is now a device of its own.', undefined, T)).toBeInTheDocument()
    await waitFor(() => expect(within(section).queryByText('192.0.2.254')).toBeNull(), T)
    expect(assetsStore.get().some((a) => a.ip === '192.0.2.254' && a.id !== 'a-dm-srv')).toBe(true)
  })

  it('the box keeps Split off and Merge with… on its page, off, each with its reason', async () => {
    renderApp('/devices/a-box', { role: 'admin' })
    const section = await screen.findByRole('region', { name: 'Addresses' }, T)
    const split = within(section).getAllByRole('button', { name: /^Split .* off$/ })
    expect(split.length).toBeGreaterThan(0)
    for (const b of split) {
      expect(b).toBeDisabled()
      expect(b).toHaveAccessibleDescription("The Vedette box's own address: the box is always its own device.")
    }
    const merge = within(section).getByRole('button', { name: 'Merge with…' })
    expect(merge).toBeDisabled()
    expect(merge).toHaveAttribute('title', 'The Vedette box is always its own device: it cannot be merged with another.')
  })

  it('a port open on two addresses of one device is two rows told apart by an Address column', async () => {
    assetsStore.update((l) => l.map((a) => (a.id === 'a-dm-fw' ? { ...a, services: [
      { port: 22, proto: 'tcp' as const, name: 'ssh', source: 'nmap' as const, confidence: 0.8 },
      { port: 22, proto: 'tcp' as const, name: 'ssh', source: 'nmap' as const, confidence: 0.8, address: '192.0.2.254' },
    ] } : a)))
    renderApp('/devices/a-dm-fw?tab=services', { role: 'admin' })
    const table = await screen.findByRole('table', { name: 'Services open on the device' }, T)
    expect(within(table).getByRole('columnheader', { name: /Address/ })).toBeInTheDocument()
    expect(within(table).getByRole('cell', { name: '192.0.2.1' })).toBeInTheDocument()
    expect(within(table).getByRole('cell', { name: '192.0.2.254' })).toBeInTheDocument()
  })
})
