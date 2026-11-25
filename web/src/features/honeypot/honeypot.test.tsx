import { describe, expect, it, vi } from 'vitest'
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
import { collection } from '@/mocks/db'
import DevicePanel from './DevicePanel'
import TrapIpsTab from './TrapIps'
import { feature } from './index'

const addToken = async () => userEvent.click(await screen.findByRole('button', { name: 'Create custom token' }))

// Respond opens the response module, which this build does not offer; this file runs it as offered, and
// features/core/v1Scope.test.tsx runs the build's own view.
const postV1 = vi.hoisted(() => ({ POST_V1_IN_UI: true }))
vi.mock('@/lib/postV1', () => postV1)

// The page is the shared page frame with tabs in ?tab= (overview, trap-ips, services, tokens, hits).
const svcRow = (name: RegExp) => within(screen.getByRole('table', { name: 'Services and their status' })).getByRole('row', { name })
const trapIpList = () => screen.findByRole('list', { name: 'Trap IPs' })
const details = (name: string) => screen.getByLabelText(`Details of Trap IP ${name}`)
const itemOf = (name: string) => details(name).closest('li')!

describe('honeypot: main page (S-HP-1)', () => {
  it('first sentence gives the 7-day hit count and latest source; the hits table names the Trap IP and links to the device; axe clean', async () => {
    renderApp('/honeypot?tab=hits')
    expect(await screen.findByRole('heading', { level: 1, name: /Traps were hit 5 times in 7 days, last .* from PC-HR-01/ })).toBeInTheDocument()
    const hits = await screen.findByRole('table', { name: 'Trap hits' })
    expect(within(hits).getByRole('link', { name: 'PC-HR-01' })).toHaveAttribute('href', '/devices/a-pc07')
    // Which Trap IP each hit went to, and the Trap IPs a scan touched.
    const smb = within(hits).getByRole('link', { name: 'PC-HR-01' }).closest('tr')!
    expect(within(smb).getByText('FILESRV-OLD')).toBeInTheDocument()
    expect(within(smb).getByText('192.168.10.240')).toBeInTheDocument()
    expect(within(hits).getByText('NAS-ARCHIVE')).toBeInTheDocument()
    expect(within(hits).getByText('FILESRV-OLD, NAS-ARCHIVE, PRN-FLOOR2')).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('shows each service state and the excluded Vedette scanner', async () => {
    renderApp('/honeypot?tab=services')
    const traps = await screen.findByRole('table', { name: 'Services and their status' })
    expect(within(traps).getAllByRole('row')).toHaveLength(19) // every service on one page (18)
    expect(within(svcRow(/SMB/)).getByText('Listening')).toBeInTheDocument()
    expect(within(svcRow(/SMB/)).getByText('FILESRV-OLD, NAS-ARCHIVE')).toBeInTheDocument()
    expect(within(svcRow(/MSSQL/)).getByText('On no Trap IP')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('tab', { name: /Overview/ }))
    expect(await screen.findByRole('heading', { name: /Vedette's own scanner does not count as a trap hit/ })).toBeInTheDocument()
    expect(screen.getByText(/vedette-hq \(192\.168\.10\.250\)/)).toBeInTheDocument()
    expect(screen.getByText('Always excluded')).toBeInTheDocument()
    expect(screen.getByText('Ignored 14 connections from the box')).toBeInTheDocument()
  })

  it('"Test trap" creates a hit labelled as a test and does not count it in the statistics', async () => {
    renderApp('/honeypot?tab=services')
    await userEvent.click(await screen.findByRole('button', { name: 'Test trap SMB (file sharing)' }))
    // no alert channel is on: the test says a real touch would only show in Vedette
    expect(await screen.findByText(/^Recorded a test hit on the SMB \(file sharing\) trap\. No alert channel is on, so no test alert was sent/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('tab', { name: /Hits/ }))
    const testChip = await waitFor(() => within(screen.getByRole('table', { name: 'Trap hits' })).getByText('Test'))
    const row = testChip.closest('tr')!
    expect(within(row).getByText('Vedette box (test)')).toBeInTheDocument()
    expect(within(row).getByText('FILESRV-OLD')).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 1 }).textContent).toMatch(/5 times in 7 days/)
  })

  it('"Test trap" sends the test alert through the channels that are on and says what each did', async () => {
    collection<unknown[]>('notify_channels', () => []).set([
      { type: 'email', configured: true, enabled: true, min_severity: 'medium' },
      { type: 'telegram', configured: true, enabled: false, min_severity: 'low' },
    ])
    renderApp('/honeypot?tab=services')
    await userEvent.click(await screen.findByRole('button', { name: 'Test trap SMB (file sharing)' }))
    expect(await screen.findByText('Recorded a test hit on the SMB (file sharing) trap. Test alert sent by Email: check that it arrived.')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('tab', { name: /Hits/ }))
    const row = (await waitFor(() => within(screen.getByRole('table', { name: 'Trap hits' })).getByText('Test'))).closest('tr')!
    await userEvent.click(within(row).getAllByRole('link')[0]!)
    expect(await screen.findByText('Test alert sent by Email.')).toBeInTheDocument()
  })

  it('cannot test a service no Trap IP that is on has', async () => {
    renderApp('/honeypot?tab=services')
    const b = await screen.findByRole('button', { name: 'Test trap MSSQL (SQL Server)' })
    expect(b).toBeDisabled()
    expect(b).toHaveAttribute('title', 'No Trap IP that is on has this service. Add it to a Trap IP first.')
  })
})

describe('honeypot: Trap IPs (S-HP-1, S-HP-2)', () => {
  it('each Trap IP shows where it lives: MAC and the vendor a scanner reads, open services, its link and card, last touch; axe clean', async () => {
    renderApp('/honeypot?tab=trap-ips')
    await trapIpList()
    const file = details('FILESRV-OLD')
    expect(file).toHaveTextContent('Windows file server · Dell')
    expect(file).toHaveTextContent('f8:bc:12:a8:0a:f0, which a network scanner shows as Dell Inc.')
    expect(file).toHaveTextContent('SMB (file sharing) 445, RDP (remote desktop) 3389')
    expect(file).toHaveTextContent(/Its own network link vdhc0a80af0 \(macvlan, with its own MAC\) on the box card eth0/)
    expect(file.querySelector('time')).toHaveAttribute('dateTime') // last touched: the SMB hit of yesterday
    expect(details('PRN-FLOOR2')).toHaveTextContent(/Last touched\s*Never/)
    // switched off: not on the network, answers nothing
    const off = details('BUILD-SRV-02')
    expect(off).toHaveTextContent('Given when the box holds the address')
    expect(off).toHaveTextContent('Nothing while it does not listen')
    expect(off).toHaveTextContent('Not on the network yet')
    // the host could not set it up: its reason, not its switch
    expect(within(itemOf('CAM-DOCK')).getByText('Error: not set up')).toBeInTheDocument()
    expect(within(itemOf('CAM-DOCK')).getByText('the host could not do it')).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('a Trap IP whose address a device took links to that device and needs attention', async () => {
    assetsStore.update((l) => [{ ...seedAssets()[0]!, id: 'a-clash', ip: '192.168.10.242', hostname: 'NEW-PC' }, ...l])
    renderApp('/honeypot?tab=trap-ips')
    await trapIpList()
    expect(within(itemOf('PRN-FLOOR2')).getByText('Error: IP clashes with a device')).toBeInTheDocument()
    expect(within(details('PRN-FLOOR2')).getByRole('link', { name: /NEW-PC has this address/ })).toHaveAttribute('href', '/devices/a-clash')
    expect(screen.getByRole('tab', { name: /Trap IPs 2 need attention/ })).toBeInTheDocument()
  })

  it('scan detection names the Trap IPs the last scan touched', async () => {
    renderApp('/honeypot?tab=trap-ips')
    expect(await screen.findByText(/Last scan .* touched FILESRV-OLD, NAS-ARCHIVE, PRN-FLOOR2\./)).toBeInTheDocument()
    expect(screen.getByText(/touches two or more Trap IPs within a minute raises one High alert/)).toBeInTheDocument()
  })

  it('admin adds a Trap IP: errors sit under their own field, a valid one is added and audited', async () => {
    renderApp('/honeypot?tab=trap-ips')
    await userEvent.click(await screen.findByRole('button', { name: 'Add a Trap IP' }))
    const form = screen.getByLabelText('Looks like').closest('form')!
    // the name starts as a free name of the look and follows the look until the person types one
    expect(within(form).getByLabelText('Name')).toHaveValue('FILESRV-OLD-2')
    await userEvent.selectOptions(within(form).getByLabelText('Looks like'), 'linux')
    expect(within(form).getByLabelText('Name')).toHaveValue('BUILD-SRV-03')
    await userEvent.selectOptions(within(form).getByLabelText('Looks like'), 'file_server')
    await userEvent.clear(within(form).getByLabelText('Name'))
    await userEvent.click(within(form).getByRole('button', { name: 'Add Trap IP' }))
    expect(await within(form).findByText('Enter a name, for example FILESRV-OLD.')).toBeInTheDocument()
    expect(within(form).getByText('Enter an address for the Trap IP.')).toBeInTheDocument()
    expect(within(form).getByLabelText('Name')).toHaveFocus()
    await userEvent.type(within(form).getByLabelText('Name'), 'FILESRV-02')
    for (const [value, msg] of [['192.168.10.101', /belongs to device PC-ACCOUNTS-01/], ['10.0.0.5', /must be inside the box's network/], ['192.168.10.250', /the Vedette box's own IP/], ['192.168.10.241', /already another Trap IP/]] as const) {
      const ip = within(form).getByLabelText('Address')
      await userEvent.clear(ip)
      await userEvent.type(ip, value)
      await userEvent.click(within(form).getByRole('button', { name: 'Add Trap IP' }))
      expect(await within(form).findByText(msg)).toBeInTheDocument()
      expect(ip).toBeInvalid()
    }
    const ip = within(form).getByLabelText('Address')
    await userEvent.clear(ip)
    await userEvent.type(ip, '192.168.10.248')
    await userEvent.click(within(form).getByRole('button', { name: 'Add Trap IP' }))
    expect(await screen.findByText('Trap IP FILESRV-02 added')).toBeInTheDocument()
    expect(auditStore.get().some((a) => a.action === 'honeypot.trap_ip_add' && a.target === '192.168.10.248')).toBe(true)
    expect(await screen.findByLabelText('Details of Trap IP FILESRV-02')).toBeInTheDocument()
  })

  it('a coverage action opens the Add dialog on the look it names', async () => {
    renderApp('/honeypot?tab=trap-ips&add=linux')
    const form = (await screen.findByLabelText('Looks like')).closest('form')!
    expect(within(form).getByLabelText('Looks like')).toHaveValue('linux')
    expect(within(form).getByRole('checkbox', { name: /SSH/ })).toBeChecked()
  })

  it('admin switches a Trap IP off; it is audited', async () => {
    renderApp('/honeypot?tab=trap-ips')
    await trapIpList()
    await userEvent.click(screen.getByRole('switch', { name: 'Trap IP PRN-FLOOR2' }))
    await waitFor(() => expect(auditStore.get().some((a) => a.action === 'honeypot.trap_ip_disable' && a.target === '192.168.10.242')).toBe(true))
  })
})

describe('honeypot: what the box reports (S-HP-1)', () => {
  const trap = (service: string, port: number, state: string) => ({ service, port, enabled: true, state, trap_ips: ['FILESRV-OLD'], hits_7d: 0, last_hit_at: null })
  const overview = (state: string, problem: string | null) => ({
    problem, lan: '192.168.10.0/24', box: { ip: '192.168.10.250', name: 'vedette-hq' }, ignored_7d: 0,
    trap_ips: { total: 1, enabled: 1, listening: 0, failing: state === 'failed' ? 1 : 0 }, smb_name: 'FILESRV-OLD', http_page: null,
    traps: [trap('smb', 445, state), trap('rdp', 3389, state), trap('ssh', 22, state), trap('mssql', 1433, state), trap('http', 80, state)],
    summary: { today: 0, week: 0, last_hit_at: null, last_src: null }, updated_at: new Date().toISOString(),
  })

  it('a Trap IP that is on but could not be set up shows an error with the host reason, not "Off" and not "No trap was hit"', async () => {
    server.use(http.get('*/api/v1/honeypot', () => HttpResponse.json(overview('failed', 'the honeypot container did not start'))))
    renderApp('/honeypot?tab=services')
    expect(await screen.findByRole('heading', { level: 1, name: 'A Trap IP is on, but the box could not set it up' })).toBeInTheDocument()
    expect(screen.getByRole('alert')).toHaveTextContent('Reason from the box: the honeypot container did not start.')
    expect(within(svcRow(/SSH/)).getByText('Error: not set up')).toBeInTheDocument()
  })

  it('Trap IPs that are coming up show Starting', async () => {
    server.use(http.get('*/api/v1/honeypot', () => HttpResponse.json(overview('starting', null))))
    renderApp('/honeypot?tab=services')
    await screen.findByRole('table', { name: 'Services and their status' })
    expect(within(svcRow(/SSH/)).getByText('Starting')).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 1, name: 'Trap IPs are starting. Nothing is listening yet.' })).toBeInTheDocument()
  })

  it('an older host program: a listening Trap IP says it answers every service and why', async () => {
    const base = { preset: 'printer', vendor: 'hp', services: ['http'], enabled: true, created_at: new Date().toISOString(), mac_vendor: 'Hewlett Packard', device_id: null, device_name: null, last_hit_at: null }
    server.use(http.get('*/api/v1/honeypot/trap-ips', () => HttpResponse.json({
      items: [{ ...base, id: 't1', name: 'PRN-A', ip: '192.168.10.241', state: 'listening', reason: 'the host program on this box is older', mac: '3c:d9:2b:0a:0b:0c',
        attachment: { kind: 'macvlan', link: 'vdhc0a80af1', parent: '' }, open_services: ['smb', 'http'] }],
      suggestions: [], spare_ips: ['192.168.10.230'], spare_checked: false,
    })))
    renderApp('/honeypot?tab=trap-ips')
    await trapIpList()
    const d = details('PRN-A')
    expect(d).toHaveTextContent('SMB (file sharing) 445, HTTP (fake admin page) 80')
    expect(d).toHaveTextContent(/cannot keep each Trap IP to its own/)
    expect(d).toHaveTextContent(/link vdhc0a80af1 \(macvlan, with its own MAC\) on the box's network card/)
  })
})

describe('honeypot: roles', () => {
  it('viewer: switches, Add and test buttons are locked with a reason', async () => {
    renderApp('/honeypot?tab=trap-ips', { role: 'viewer' })
    await trapIpList()
    const sw = screen.getByRole('switch', { name: 'Trap IP FILESRV-OLD' })
    expect(sw).toBeDisabled()
    expect(sw).toHaveAttribute('title', 'Requires Admin role')
    expect(screen.getByRole('button', { name: 'Add a Trap IP' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Test scan' })).toBeDisabled()
    await userEvent.click(screen.getByRole('tab', { name: /Services/ }))
    expect(await screen.findByRole('button', { name: 'Test trap SMB (file sharing)' })).toBeDisabled()
  })

  it('operator can test traps but not switch or add Trap IPs', async () => {
    renderApp('/honeypot?tab=trap-ips', { role: 'operator' })
    await trapIpList()
    expect(screen.getByRole('switch', { name: 'Trap IP FILESRV-OLD' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Add a Trap IP' })).toBeDisabled()
    await userEvent.click(screen.getByRole('tab', { name: /Services/ }))
    expect(await screen.findByRole('button', { name: 'Test trap SMB (file sharing)' })).not.toBeDisabled()
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
    // Respond is the next step: in "What to do next", not in the header
    expect(within(screen.getByRole('heading', { level: 1 }).closest('header')!).queryByRole('link', { name: /^Respond/ })).toBeNull()
    expect(within(screen.getByRole('region', { name: 'What to do' })).getByRole('link', { name: /^Respond to the hit/ })).toHaveAttribute('href', '/response?tab=rules')
    await expectNoA11yViolations()
  })

  it('an unapproved unknown device is labelled', async () => {
    renderApp('/honeypot/hits/hit-seed-2')
    expect(await screen.findByText('Not added yet')).toBeInTheDocument()
  })

  it('a missing hit is reported with a way back', async () => {
    renderApp('/honeypot/hits/khong-co')
    expect(await screen.findByText(/No such trap hit/)).toBeInTheDocument()
    expect(within(screen.getByRole('navigation', { name: 'Breadcrumb' })).getByRole('link', { name: 'Internal traps' })).toHaveAttribute('href', '/honeypot')
  })

  it('an opened test hit is labelled as a test and has no "What to do" section', async () => {
    renderApp('/honeypot?tab=services')
    await userEvent.click(await screen.findByRole('button', { name: 'Test trap RDP (remote desktop)' }))
    await screen.findByText(/^Recorded a test hit on the RDP \(remote desktop\) trap\./)
    await userEvent.click(screen.getByRole('tab', { name: /Hits/ }))
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

  it('a device that never hit a trap shows no trap hits section at all', async () => {
    const { container } = panel('a-pc01')
    await waitFor(() => expect(container).toBeEmptyDOMElement())
    expect(screen.queryByRole('heading', { name: 'Internal trap hits' })).toBeNull()
    expect(screen.queryByText('This device has not hit any trap.')).toBeNull()
  })

  it('module off renders nothing', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'honeypot' ? { ...m, enabled: false } : m)))
    const { container } = panel('a-pc07')
    await waitFor(() => expect(container).toBeEmptyDOMElement())
  })
})

describe('honeypot: S-HP-2 suggestions, tokens, respond, coverage', () => {
  it('a viewer sees the bait password masked (last 4 only), an administrator sees it in full', async () => {
    const { unmount } = renderApp('/honeypot?tab=tokens', { role: 'viewer' })
    const list = await screen.findByRole('list', { name: 'Honey tokens' })
    await within(list).findByText('svc-backup-old')
    expect(list.textContent).toContain('••••••••-Lr9')
    expect(list.textContent).not.toContain('Bk!7mQ2xv')
    unmount()
    renderApp('/honeypot?tab=tokens', { role: 'admin' })
    const full = await screen.findByRole('list', { name: 'Honey tokens' })
    await within(full).findByText('svc-backup-old')
    expect(full.textContent).toContain('Bk!7mQ2xv-Lr9')
  })

  it('suggests Trap IP types from the inventory, lists tokens with last triggered, links Respond, shows coverage', async () => {
    renderApp('/honeypot?tab=trap-ips')
    expect(await screen.findByText(/You have \d+ Synology or QNAP NAS/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('tab', { name: /Tokens/ }))
    const tokens = await screen.findByRole('list', { name: 'Honey tokens' })
    expect(within(tokens).getByText('svc-backup-old')).toBeInTheDocument()
    expect(within(tokens).getAllByText(/Never triggered/).length).toBe(3)
    await userEvent.click(screen.getByRole('tab', { name: /Hits/ }))
    const hits = await screen.findByRole('table', { name: 'Trap hits' })
    expect(within(hits).getAllByText('Credential token svc-backup-old').length).toBeGreaterThan(0)
    expect(within(hits).getAllByRole('link', { name: /^Respond to the hit/ })[0]).toHaveAttribute('href', '/response?tab=rules') // rules for trap hits live there; the inbox opens first
    await userEvent.click(screen.getByRole('tab', { name: /Overview/ }))
    expect(await screen.findByRole('heading', { name: 'Is this enough?' })).toBeInTheDocument()
  })

  it('admin creates a URL token and a test trigger updates last triggered', async () => {
    renderApp('/honeypot?tab=tokens')
    await addToken()
    await userEvent.selectOptions(await screen.findByLabelText('Token type'), 'url')
    await userEvent.type(screen.getByLabelText('Label'), 'Wiki admin link')
    await userEvent.type(screen.getByLabelText('Where will you plant it?'), 'Intranet wiki')
    await userEvent.click(screen.getByRole('button', { name: 'Create token' }))
    expect(await screen.findByText('Token created')).toBeInTheDocument()
    await userEvent.click(await screen.findByRole('button', { name: 'Test token Wiki admin link' }))
    expect(await screen.findByText(/^Recorded a test trigger for Wiki admin link\./)).toBeInTheDocument()
  })
})

describe('honeypot: Trap IP and honey token form matrix', () => {
  const pick = (label: string) => async (o: string) => { const s = screen.getByLabelText(label); await userEvent.selectOptions(s, within(s).getByRole('option', { name: o })) }
  const formOf = (label: string) => screen.getByLabelText(label).closest('form')!

  it('honey token: each type has its own name label, hints and file type; switching drops the name and place typed for the previous type', async () => {
    renderApp('/honeypot?tab=tokens')
    await screen.findByRole('list', { name: 'Honey tokens' })
    await addToken()
    const FILE = 'File type'
    const form = formOf('Token type')
    await eachOption([
      { option: 'Decoy file', shown: ['File name', FILE, /Looks tempting/], hidden: ['Label'] },
      // #717: the box makes the bait account name (svc_ + 6 letters); the field is only the token's label
      { option: 'Fake credentials', shown: ['Label', /The box makes the account name and password/], hidden: ['File name', FILE, 'User name', /intranet wiki page/] },
      { option: 'URL token', shown: ['Label', /intranet wiki page/], hidden: ['File name', FILE, 'User name', /The box makes the account name/] },
      { option: 'Decoy file', shown: ['File name', FILE], hidden: ['Label'] },
    ], pick('Token type'), form)
    // The box answers no DNS, so a DNS token could never alert and is not offered
    expect(within(within(form).getByLabelText('Token type')).queryByRole('option', { name: 'DNS token' })).toBeNull()
    expect(within(form).getByRole('button', { name: 'Create token' })).toBeEnabled()
    await userEvent.type(within(form).getByLabelText('File name'), 'Payroll-2026-Q4')
    await userEvent.type(within(form).getByLabelText('Where will you plant it?'), 'SRV-FILE-HR')
    await pick('Token type')('Fake credentials')
    expect(within(form).getByLabelText('Label')).toHaveValue('')
    expect(within(form).getByLabelText('Where will you plant it?')).toHaveValue('')
  })

  it('honey token presets: picking one fills type, name, file type and place; every field stays editable; Custom is blank', async () => {
    renderApp('/honeypot?tab=tokens')
    const list = await screen.findByRole('list', { name: 'Honey tokens' })
    // an older DNS token still lists, saying it cannot alert
    expect(within(within(list).getByText('Backup script host').closest('li')!).getByText('Cannot alert')).toBeInTheDocument()
    await addToken()
    const form = formOf('Start from')
    const field = (label: string) => within(form).getByLabelText(label)
    const year = new Date().getFullYear()
    expect(field('File name')).toHaveValue(`Payroll-${year}`) // one click: the first preset is filled in already
    await pick('Start from')('Network diagram (.docx)')
    expect(field('Token type')).toHaveValue('file')
    expect(field('File name')).toHaveValue('Network-diagram')
    expect(field('File type')).toHaveValue('docx')
    expect(field('Where will you plant it?')).toHaveValue('IT folder on the file share')
    await userEvent.clear(field('File name'))
    await userEvent.type(field('File name'), 'Network-map-2019')
    await userEvent.selectOptions(field('File type'), 'xlsx')
    await userEvent.clear(field('Where will you plant it?'))
    await userEvent.type(field('Where will you plant it?'), 'Shared drive, IT')
    expect(field('File name')).toHaveValue('Network-map-2019')
    expect(field('File type')).toHaveValue('xlsx')
    expect(field('Where will you plant it?')).toHaveValue('Shared drive, IT')
    await pick('Start from')('Backup service account')
    expect(field('Token type')).toHaveValue('credential')
    expect(field('Label')).toHaveValue('Backup service account')
    expect(field('Where will you plant it?')).toHaveValue('IT password manager')
    await pick('Start from')('Router admin bookmark')
    expect(field('Token type')).toHaveValue('url')
    expect(field('Label')).toHaveValue('Router admin')
    expect(within(form).queryByLabelText('File type')).toBeNull()
    await pick('Start from')('Custom (blank)')
    expect(field('Token type')).toHaveValue('url')
    expect(field('Label')).toHaveValue('')
    expect(field('Where will you plant it?')).toHaveValue('')
    await pick('Start from')('Payroll spreadsheet (.xlsx)')
    await userEvent.click(within(form).getByRole('button', { name: 'Create token' }))
    expect(await screen.findByRole('button', { name: `Test token Payroll-${year}` })).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull()) // saved: the dialog closes and the list stays
  })

  it('a credential preset shows the bait account the box made (svc_ and six letters), not its label', async () => {
    renderApp('/honeypot?tab=tokens')
    await screen.findByRole('list', { name: 'Honey tokens' })
    await addToken()
    await pick('Start from')('Old admin account (decoy)')
    expect(screen.getByLabelText('Label')).toHaveValue('Old admin account')
    await userEvent.click(screen.getByRole('button', { name: 'Create token' }))
    const item = (await screen.findByRole('button', { name: 'Test token Old admin account' })).closest('li')!
    expect(item.textContent).toMatch(/user: svc_[a-z]{6}\b/)
    expect(item.textContent).not.toMatch(/user: old/i)
  })

  it('one-click Create on a return visit: the form starts on the first preset not already made (#717)', async () => {
    const year = new Date().getFullYear()
    const { unmount } = renderApp('/honeypot?tab=tokens')
    await screen.findByRole('list', { name: 'Honey tokens' })
    await addToken()
    expect(screen.getByLabelText('Start from')).toHaveValue('payroll')
    await userEvent.click(screen.getByRole('button', { name: 'Create token' }))
    await screen.findByRole('button', { name: `Test token Payroll-${year}` })
    unmount()
    renderApp('/honeypot?tab=tokens')
    await screen.findByRole('button', { name: `Test token Payroll-${year}` })
    await addToken()
    expect(screen.getByLabelText('Start from')).toHaveValue('passwords')
    expect(within(formOf('Start from')).getByLabelText('File name')).toHaveValue('Passwords')
  })

  it('Trap IP: each preset fills its own services and vendor; Custom keeps what was picked', async () => {
    renderApp('/honeypot?tab=trap-ips')
    await userEvent.click(await screen.findByRole('button', { name: 'Add a Trap IP' }))
    const form = formOf('Looks like')
    const checked = (name: RegExp) => within(form).getByRole('checkbox', { name })
    const HTTP = /^HTTP \(/ // not HTTPS, not the HTTP proxy
    await pick('Looks like')('Windows file server')
    expect(checked(/SMB/)).toBeChecked()
    expect(checked(/RDP/)).toBeChecked()
    expect(checked(HTTP)).not.toBeChecked()
    expect(within(form).getByText(/Its MAC address starts with F8:BC:12/)).toBeInTheDocument()
    await pick('Looks like')('Office printer')
    expect(checked(HTTP)).toBeChecked()
    expect(checked(/^FTP/)).toBeChecked() // A printer's FTP (HP JetDirect)
    expect(checked(/SMB/)).not.toBeChecked()
    expect(within(form).getByLabelText('Vendor (MAC prefix)')).toHaveValue('hp')
    await pick('Looks like')('Linux server')
    expect(checked(/SSH/)).toBeChecked()
    expect(checked(/^FTP/)).toBeChecked()
    expect(checked(HTTP)).not.toBeChecked()
    expect(checked(/^TFTP/)).not.toBeChecked()
    expect(within(form).getByText('69/udp')).toBeInTheDocument()
    await pick('Looks like')('Custom')
    expect(checked(/SSH/)).toBeChecked()
    await userEvent.click(checked(/SSH/))
    await userEvent.click(checked(/^FTP/))
    await userEvent.type(within(form).getByLabelText('Name'), 'TRAP-9')
    await userEvent.type(within(form).getByLabelText('Address'), '192.168.10.248')
    await userEvent.click(within(form).getByRole('button', { name: 'Add Trap IP' }))
    expect(await within(form).findByText('Pick at least one service.')).toBeInTheDocument()
  })
})

describe('honeypot: the LAN range is not known yet (#875)', () => {
  it('an administrator gets the link to the range field; anyone else is told to ask one, never sent to a forbidden page', async () => {
    for (const [userId, admin] of [['u-op', false], ['u-admin', true]] as const) {
      sessionStore.set({ userId })
      const qc = makeQueryClient()
      const v = render(<QueryClientProvider client={qc}><MemoryRouter><TrapIpsTab hits={[]} lan="" lanKnown={false} smbName={null} /></MemoryRouter></QueryClientProvider>)
      await waitFor(() => expect(qc.getQueryData(['me'])).toBeTruthy())
      if (admin) {
        expect(await screen.findByRole('link', { name: 'Add your LAN range in Settings, Scanning, Safety' })).toHaveAttribute('href', '/settings/scanning?tab=safety#range-input')
      } else {
        expect(await screen.findByText(/Ask an administrator to add it in Settings, Scanning, Safety\./)).toBeInTheDocument()
        expect(screen.queryByRole('link', { name: /LAN range/ })).toBeNull()
      }
      v.unmount()
    }
  })
})
