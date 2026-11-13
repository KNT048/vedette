import { describe, expect, it } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router'
import { http, HttpResponse } from 'msw'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { server } from '@/test/server'
import { eachOption } from '@/test/formMatrix'
import { makeQueryClient } from '@/app/App'
import { assetsStore, auditStore, modulesStore, sessionStore } from '@/mocks/stores'
import { seedAssets } from '@/mocks/seed/assets'
import DevicePanel from './DevicePanel'
import { feature } from './index'

const trapRow = (name: RegExp) => within(screen.getByRole('table', { name: 'Traps and their status' })).getByRole('row', { name })

describe('honeypot: main page (S-HP-1)', () => {
  it('first sentence gives the 7-day hit count and latest source; the hits table links to the device; axe clean', async () => {
    renderApp('/honeypot')
    expect(await screen.findByRole('heading', { level: 1, name: /Traps were hit 4 times in 7 days, last .* from PC-HR-01/ })).toBeInTheDocument()
    const hits = await screen.findByRole('table', { name: 'Trap hits' })
    expect(within(hits).getByRole('link', { name: 'PC-HR-01' })).toHaveAttribute('href', '/devices/a-pc07')
    await expectNoA11yViolations()
  })

  it('shows each trap state and the excluded Vedette scanner', async () => {
    renderApp('/honeypot')
    const traps = await screen.findByRole('table', { name: 'Traps and their status' })
    expect(within(traps).getAllByRole('row')).toHaveLength(6)
    expect(within(trapRow(/SMB/)).getByText('Listening')).toBeInTheDocument()
    expect(within(trapRow(/MSSQL/)).getByText('Off')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: /Vedette's own scanner does not count as a trap hit/ })).toBeInTheDocument()
    expect(screen.getByText(/vedette-hq \(192\.168\.10\.250\)/)).toBeInTheDocument()
    expect(screen.getByText('Always excluded')).toBeInTheDocument()
    expect(screen.getByText('Ignored 14 connections from the box')).toBeInTheDocument()
  })

  it('admin turns on the MSSQL trap and it is audited', async () => {
    renderApp('/honeypot')
    const sw = (await screen.findAllByRole('switch', { name: 'MSSQL (SQL Server) trap' }))[0]!
    expect(sw).not.toBeDisabled()
    await userEvent.click(sw)
    expect(await screen.findByText('MSSQL (SQL Server) trap is on')).toBeInTheDocument()
    expect(auditStore.get().some((a) => a.action === 'honeypot.trap_enable')).toBe(true)
  })

  it('"Test trap" creates a hit labelled as a test and does not count it in the statistics', async () => {
    renderApp('/honeypot')
    await userEvent.click((await screen.findAllByRole('button', { name: 'Test trap SSH' }))[0]!)
    expect(await screen.findByText('Recorded a test hit on the SSH trap')).toBeInTheDocument()
    // the toast comes after the refetch that holds the new row; look the table up again inside the wait so a re-rendered table cannot leave a stale one
    const testChip = await waitFor(() => within(screen.getByRole('table', { name: 'Trap hits' })).getByText('Test'))
    const hits = within(testChip.closest('table')!)
    expect(hits.getByText('Vedette box (test)')).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 1 }).textContent).toMatch(/4 times in 7 days/)
  })

  it('cannot test a trap that is off', async () => {
    renderApp('/honeypot')
    const b = (await screen.findAllByRole('button', { name: 'Test trap HTTP (fake admin page)' }))[0]!
    expect(b).toBeDisabled()
    expect(b).toHaveAttribute('title', 'Turn this trap on before testing')
  })

  it('a secondary IP that matches an inventory device is rejected and names the device', async () => {
    renderApp('/honeypot')
    const ip = await screen.findByLabelText('Trap secondary IP')
    await userEvent.clear(ip)
    await userEvent.type(ip, '192.168.10.101')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText(/belongs to device PC-ACCOUNTS-01/)).toBeInTheDocument()
  })

  it('rejects a malformed IP, an IP outside the network, the box IP and a duplicate hostname', async () => {
    renderApp('/honeypot')
    const ip = await screen.findByLabelText('Trap secondary IP')
    const save = screen.getByRole('button', { name: 'Save' })
    for (const [value, msg] of [['abc', /is not valid/], ['10.0.0.5', /must be inside the box's network/], ['192.168.10.250', /the Vedette box's own IP/]] as const) {
      await userEvent.clear(ip)
      await userEvent.type(ip, value)
      await userEvent.click(save)
      expect(await screen.findByText(msg)).toBeInTheDocument()
    }
    await userEvent.clear(ip)
    await userEvent.type(ip, '192.168.10.241')
    const host = screen.getByLabelText('Fake hostname')
    await userEvent.clear(host)
    await userEvent.type(host, 'srv-ad')
    await userEvent.click(save)
    expect(await screen.findByText(/The name srv-ad belongs to device 192\.168\.10\.10/)).toBeInTheDocument()
  })

  it('saves a valid secondary IP and hostname', async () => {
    renderApp('/honeypot')
    const ip = await screen.findByLabelText('Trap secondary IP')
    await userEvent.clear(ip)
    await userEvent.type(ip, '192.168.10.241')
    const host = screen.getByLabelText('Fake hostname')
    await userEvent.clear(host)
    await userEvent.type(host, 'BACKUP-OLD')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('Decoy saved')).toBeInTheDocument()
    expect(auditStore.get().some((a) => a.action === 'honeypot.config' && a.target === '192.168.10.241')).toBe(true)
  })

  it('warns when a new device uses the secondary IP', async () => {
    assetsStore.update((l) => [{ ...seedAssets()[0]!, id: 'a-clash', ip: '192.168.10.240', hostname: 'NEW-PC' }, ...l])
    renderApp('/honeypot')
    expect(await screen.findByRole('alert')).toHaveTextContent(/Secondary IP 192\.168\.10\.240 clashes with a real device/)
    expect(within(trapRow(/SMB/)).getByText('Error: IP clashes with a device')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Open device' })).toHaveAttribute('href', '/devices/a-clash')
  })
})

describe('honeypot: what the box reports (S-HP-1)', () => {
  const trap = (service: string, port: number, state: string) => ({ service, port, enabled: true, state, since: null, hits_7d: 0, last_hit_at: null })
  const overview = (state: string, problem: string | null) => ({
    secondary_ip: '192.168.10.240', secondary_mac: '06:b7:36:4f:54:67', problem, hostname: 'FILESRV-OLD', lan: '192.168.10.0/24', box: { ip: '192.168.10.250', name: 'vedette-hq' }, ignored_7d: 0, conflict_asset: null,
    traps: [trap('smb', 445, state), trap('rdp', 3389, state), trap('ssh', 22, state), trap('mssql', 1433, state), trap('http', 80, state)],
    summary: { today: 0, week: 0, last_hit_at: null, last_src: null }, updated_at: new Date().toISOString(),
  })

  it('a trap that is on but could not be set up shows an error with the host reason, not "Off" and not "No trap was hit"', async () => {
    server.use(http.get('*/api/v1/honeypot', () => HttpResponse.json(overview('failed', 'the honeypot container did not start'))))
    renderApp('/honeypot')
    expect(await screen.findByRole('heading', { level: 1, name: /A trap is on, but the box could not set up the decoy/ })).toBeInTheDocument()
    expect(screen.getByRole('alert')).toHaveTextContent('Reason from the box: the honeypot container did not start.')
    expect(within(trapRow(/SSH/)).getByText('Error: not set up')).toBeInTheDocument()
    expect(screen.getByText(/The box gave this address the MAC address 06:b7:36:4f:54:67/)).toBeInTheDocument()
  })

  it('a trap that is coming up shows Starting', async () => {
    server.use(http.get('*/api/v1/honeypot', () => HttpResponse.json(overview('starting', null))))
    renderApp('/honeypot')
    await screen.findByRole('table', { name: 'Traps and their status' })
    expect(within(trapRow(/SSH/)).getByText('Starting')).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 1, name: 'Traps are starting. Nothing is listening yet.' })).toBeInTheDocument()
  })

  it('an extra decoy shows the state the host reports, with its reason and MAC, not its switch', async () => {
    const base = { personality: 'nas', services: [{ name: 'SMB', port: 445 }], created_at: new Date().toISOString(), enabled: true }
    server.use(http.get('*/api/v1/honeypot/decoys', () => HttpResponse.json({
      items: [
        { ...base, id: 'd1', name: 'NAS-A', ip: '192.168.10.241', state: 'failed', reason: 'the host could not do it (decoy_failed)', mac: null },
        { ...base, id: 'd2', name: 'NAS-B', ip: '192.168.10.242', state: 'starting', reason: null, mac: null },
        { ...base, id: 'd3', name: 'NAS-C', ip: '192.168.10.243', state: 'listening', reason: null, mac: '06:b7:36:0a:0b:0c' },
      ],
      suggestions: [], spare_ips: ['192.168.10.230'], spare_checked: false,
    })))
    renderApp('/honeypot')
    const list = await screen.findByRole('list', { name: 'Decoys' })
    expect(within(list).getByText('Error: not set up')).toBeInTheDocument()
    expect(within(list).getByText('the host could not do it (decoy_failed)')).toBeInTheDocument()
    expect(within(list).getByText('Starting')).toBeInTheDocument()
    expect(within(list).getByText('Listening')).toBeInTheDocument()
    expect(within(list).getByText('06:b7:36:0a:0b:0c')).toBeInTheDocument()
    expect(screen.getByText(/No devices discovered yet, so these are only guesses/)).toBeInTheDocument()
  })

  it('the decoy IP can be removed only while every trap is off', async () => {
    renderApp('/honeypot')
    const ip = await screen.findByLabelText('Trap secondary IP')
    await userEvent.clear(ip)
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('Turn all traps off before removing the decoy IP.')).toBeInTheDocument()
  })
})

describe('honeypot: roles', () => {
  it('viewer: switches, test buttons and Save are locked with a reason', async () => {
    renderApp('/honeypot', { role: 'viewer' })
    const sw = (await screen.findAllByRole('switch', { name: 'MSSQL (SQL Server) trap' }))[0]!
    expect(sw).toBeDisabled()
    expect(sw).toHaveAttribute('title', 'Requires Admin role')
    expect(screen.getAllByRole('button', { name: 'Test trap SMB (file sharing)' })[0]!).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
    expect(screen.getByLabelText('Trap secondary IP')).toBeDisabled()
  })

  it('operator can test traps but not switch them or change the secondary IP', async () => {
    renderApp('/honeypot', { role: 'operator' })
    expect((await screen.findAllByRole('switch', { name: 'MSSQL (SQL Server) trap' }))[0]!).toBeDisabled()
    expect(screen.getAllByRole('button', { name: 'Test trap SMB (file sharing)' })[0]!).not.toBeDisabled()
    expect(screen.getByLabelText('Trap secondary IP')).toBeDisabled()
  })

  it('API rejects a write from a viewer (403)', async () => {
    sessionStore.set({ userId: 'u-view' })
    const res = await fetch(`${location.origin}/api/v1/honeypot/test-hit`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ service: 'smb' }) })
    expect(res.status).toBe(403)
  })
})

describe('honeypot: hit detail', () => {
  it('shows the source device, session excerpt and the hour of events around it; axe clean', async () => {
    renderApp('/honeypot/hits/hit-seed-1')
    expect(await screen.findByRole('heading', { level: 1, name: /SMB.* was hit at .* from PC-HR-01/ })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'PC-HR-01' })).toHaveAttribute('href', '/devices/a-pc07')
    const events = await screen.findByRole('table', { name: 'Events around the trap hit' })
    expect(within(events).getAllByRole('row').length).toBeGreaterThanOrEqual(6)
    expect(within(events).getAllByText('Firewall').length).toBeGreaterThan(0)
    expect(screen.getByRole('heading', { name: /Events in the 60 minutes around the hit/ })).toBeInTheDocument()
    expect(screen.getByText(/listed shares IPC\$ and ADMIN\$/)).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('an unapproved unknown device is labelled', async () => {
    renderApp('/honeypot/hits/hit-seed-2')
    expect(await screen.findByText('Not approved')).toBeInTheDocument()
  })

  it('a missing hit is reported with a way back', async () => {
    renderApp('/honeypot/hits/khong-co')
    expect(await screen.findByText(/No such trap hit/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Back to internal traps' })).toHaveAttribute('href', '/honeypot')
  })

  it('an opened test hit is labelled as a test and has no "What to do" section', async () => {
    renderApp('/honeypot')
    await userEvent.click((await screen.findAllByRole('button', { name: 'Test trap RDP (remote desktop)' }))[0]!)
    const row = (await waitFor(() => within(screen.getByRole('table', { name: 'Trap hits' })).getByText('Test'))).closest('tr')!
    await userEvent.click(within(row).getAllByRole('link')[0]!)
    expect(await screen.findByRole('heading', { level: 1, name: /Test hit on the RDP/ })).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'What to do' })).not.toBeInTheDocument()
  })
})

describe('honeypot: error state and module', () => {
  it('API error shows the message and a retry button', async () => {
    server.use(http.get('*/api/v1/honeypot', () => HttpResponse.json({ error: { code: 'x', message: 'The trap service is not responding.' } }, { status: 503 })))
    renderApp('/honeypot')
    expect(await screen.findByText('The trap service is not responding.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument()
  })

  it('module off says where to turn it on', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'honeypot' ? { ...m, enabled: false } : m)))
    renderApp('/honeypot')
    expect(await screen.findByText('Internal traps module is off')).toBeInTheDocument()
  })

  it('registers the sidebar entry and the device.panels slot', () => {
    expect(feature.nav?.[0]).toMatchObject({ to: '/honeypot', group: 'detect', order: 10, module: 'honeypot' })
    expect(feature.slots?.['device.panels']).toBe(DevicePanel)
  })
})

describe('honeypot: device.panels slot', () => {
  function panel(assetId: string) {
    sessionStore.set({ userId: 'u-admin' })
    return render(<QueryClientProvider client={makeQueryClient()}><MemoryRouter><DevicePanel assetId={assetId} /></MemoryRouter></QueryClientProvider>)
  }

  it('a device that hit a trap sees the hit with a detail link', async () => {
    panel('a-pc07')
    expect(await screen.findByRole('heading', { name: 'Internal trap hits' })).toBeInTheDocument()
    expect(await screen.findByRole('link', { name: /^SMB.* at / })).toHaveAttribute('href', '/honeypot/hits/hit-seed-1')
    await expectNoA11yViolations()
  })

  it('a device that never hit a trap says so', async () => {
    panel('a-pc01')
    expect(await screen.findByText('This device has not hit any trap.')).toBeInTheDocument()
  })

  it('module off renders nothing', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'honeypot' ? { ...m, enabled: false } : m)))
    const { container } = panel('a-pc07')
    await waitFor(() => expect(container).toBeEmptyDOMElement())
  })
})

describe('honeypot: S-HP-2 decoys, tokens, scan, respond, coverage', () => {
  it('a viewer sees the bait password masked (last 4 only), an administrator sees it in full (D-189, L14)', async () => {
    const { unmount } = renderApp('/honeypot', { role: 'viewer' })
    const list = await screen.findByRole('list', { name: 'Honey tokens' })
    await within(list).findByText('svc-backup-old')
    expect(list.textContent).toContain('\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022-Lr9')
    expect(list.textContent).not.toContain('Bk!7mQ2xv')
    unmount()
    renderApp('/honeypot', { role: 'admin' })
    const full = await screen.findByRole('list', { name: 'Honey tokens' })
    await within(full).findByText('svc-backup-old')
    expect(full.textContent).toContain('Bk!7mQ2xv-Lr9')
  })

  it('suggests decoy types from the inventory, lists tokens with last triggered, links Respond, shows coverage', async () => {
    renderApp('/honeypot')
    expect(await screen.findByText(/You have \d+ Synology or QNAP NAS/)).toBeInTheDocument()
    expect(await screen.findByText('NAS-ARCHIVE')).toBeInTheDocument()
    const tokens = await screen.findByRole('list', { name: 'Honey tokens' })
    expect(within(tokens).getByText('svc-backup-old')).toBeInTheDocument()
    expect(within(tokens).getAllByText(/Never triggered/).length).toBe(3)
    const hits = await screen.findByRole('table', { name: 'Trap hits' })
    expect(within(hits).getByText('Credential token svc-backup-old')).toBeInTheDocument()
    expect(within(hits).getAllByRole('link', { name: /^Respond to the hit/ })[0]).toHaveAttribute('href', '/response')
    expect(screen.getByRole('heading', { name: 'Is this enough?' })).toBeInTheDocument()
  })

  it('admin creates a URL token and a test trigger updates last triggered', async () => {
    renderApp('/honeypot')
    await userEvent.selectOptions(await screen.findByLabelText('Token type'), 'url')
    await userEvent.type(screen.getByLabelText('Label'), 'Wiki admin link')
    await userEvent.type(screen.getByLabelText('Where will you plant it?'), 'Intranet wiki')
    await userEvent.click(screen.getByRole('button', { name: 'Create token' }))
    expect(await screen.findByText('Token created')).toBeInTheDocument()
    await userEvent.click(await screen.findByRole('button', { name: 'Test token Wiki admin link' }))
    expect(await screen.findByText('Recorded a test trigger for Wiki admin link')).toBeInTheDocument()
  })
})

describe('honeypot: decoy and honey token form matrix (docs/QA.md §2)', () => {
  const pick = (label: string) => async (o: string) => { const s = screen.getByLabelText(label); await userEvent.selectOptions(s, within(s).getByRole('option', { name: o })) }
  const formOf = (label: string) => screen.getByLabelText(label).closest('form')!

  it('honey token: each type has its own name label, hints and file type; switching drops the name and place typed for the previous type', async () => {
    renderApp('/honeypot')
    await screen.findByRole('list', { name: 'Honey tokens' })
    const FILE = 'File type'
    const form = formOf('Token type')
    await eachOption([
      { option: 'Decoy file', shown: ['File name', FILE, /Looks tempting/], hidden: ['User name', 'Label'] },
      { option: 'Fake credentials', shown: ['User name', /Looks like an old service account/], hidden: ['File name', FILE, 'Label'] },
      { option: 'URL token', shown: ['Label', /intranet wiki page/], hidden: ['File name', FILE, 'User name'] },
      { option: 'DNS token', shown: ['Label', /backup script config/, /cannot alert yet/], hidden: ['File name', FILE, 'User name'] },
      { option: 'Decoy file', shown: ['File name', FILE], hidden: ['Label'] },
    ], pick('Token type'), form)
    await pick('Token type')('DNS token') // D-507: the box answers no DNS, so a DNS token cannot be made
    expect(within(form).getByRole('button', { name: 'Create token' })).toBeDisabled()
    await pick('Token type')('Decoy file')
    expect(within(form).getByRole('button', { name: 'Create token' })).toBeEnabled()
    await userEvent.type(within(form).getByLabelText('File name'), 'Payroll-2026-Q4')
    await userEvent.type(within(form).getByLabelText('Where will you plant it?'), 'SRV-FILE-HR')
    await pick('Token type')('Fake credentials')
    expect(within(form).getByLabelText('User name')).toHaveValue('')
    expect(within(form).getByLabelText('Where will you plant it?')).toHaveValue('')
  })

  it('decoy: each look shows the services it opens; a refused spare IP is cleared when the look changes', async () => {
    renderApp('/honeypot')
    await screen.findByLabelText('Looks like')
    await eachOption([
      { option: 'Windows file server', shown: [/Opens: .*445/] },
      { option: 'Office printer', shown: [/Opens: .*9100/], hidden: [/Opens: .*445/] },
      { option: 'IP camera', shown: [/Opens: .*554/], hidden: [/Opens: .*9100/] },
      { option: 'Windows file server', shown: [/Opens: .*445/], hidden: [/Opens: .*554/] },
    ], pick('Looks like'), formOf('Looks like'))
    await userEvent.type(screen.getByLabelText('Decoy name'), 'FILESRV2')
    await userEvent.type(screen.getByLabelText('Decoy IP'), '192.168.10.1') // taken by the firewall
    await userEvent.click(screen.getByRole('button', { name: 'Add decoy' }))
    await waitFor(() => expect(screen.getByLabelText('Decoy IP')).toBeInvalid())
    await pick('Looks like')('IP camera')
    expect(screen.getByLabelText('Decoy IP')).toBeValid()
  })
})
