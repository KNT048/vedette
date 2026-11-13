import { afterEach, describe, expect, it } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClientProvider } from '@tanstack/react-query'
import { http, HttpResponse } from 'msw'
import { Toaster, toast } from 'sonner'
import { makeQueryClient } from '@/app/App'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { eachOption } from '@/test/formMatrix'
import { server } from '@/test/server'
import { collection } from '@/mocks/db'
import { assetsStore, auditStore, modulesStore, orgStore, sessionStore } from '@/mocks/stores'
import type { Role } from '@/lib/session'
import SiemSettings from './SiemSettings'
import { CATALOG, ENTRIES, GROUPS, searchCatalog } from './catalog'
import { KIND_IDS } from './kinds'
import { syslogHeader } from './syslog'
import type { SourceKind } from './types'

const USER: Record<Role, string> = { admin: 'u-admin', operator: 'u-op', viewer: 'u-view' }

// A toast closes itself after 4 s, and sonner then removes it with a 200 ms timer that is not cleared when the Toaster is
// unmounted. On a slow runner a test can end inside that window, and the timer fires after the jsdom environment is gone
// ("window is not defined", uncaught, from this file, in CI). So every test ends with no toast left: dismiss them and wait
// until they are removed, while the DOM still exists. (This hook runs before the global cleanup of src/test/setup.ts.)
afterEach(async () => {
  toast.dismiss()
  await waitFor(() => expect(document.querySelector('[data-sonner-toast]')).toBeNull())
})

function renderSiem(role: Role = 'admin') {
  orgStore.update((o) => ({ ...o, setup_complete: true }))
  sessionStore.set({ userId: USER[role] })
  return render(<QueryClientProvider client={makeQueryClient()}><SiemSettings /><Toaster /></QueryClientProvider>)
}
const getJson = async (path: string) => (await fetch(`${location.origin}/api/v1${path}`)).json() as Promise<Record<string, unknown>>

const IP = '192.168.10.250'
const code = (k: SourceKind, proto: 'udp' | 'tcp' | 'tls' = 'udp', port = 514) => CATALOG[k].snippets({ ip: IP, port, proto }).map((s) => s.code).join('\n')

describe('logs: source catalog (S-LOG-1)', () => {
  it('covers the full list the owner asked for, each entry in a group, with steps, an honest "reads" note and a sane protocol list', () => {
    expect(ENTRIES).toHaveLength(KIND_IDS.length)
    const names = ENTRIES.map((e) => e.name).join(' | ')
    for (const needle of ['FortiGate', 'Sophos Firewall', 'Palo Alto', 'Cisco ASA', 'Cisco Secure Firewall', 'Cisco IOS', 'Meraki', 'MikroTik', 'pfSense', 'OPNsense', 'SonicWall', 'WatchGuard', 'Check Point', 'Juniper SRX', 'Huawei', 'DrayTek', 'Ubiquiti', 'Zyxel', 'Omada',
      'Ivanti', 'NetScaler', 'OpenVPN', 'Windows (via NXLog', 'rsyslog', 'journald', 'syslog-ng', 'Synology', 'QNAP', 'ESXi', 'Proxmox', 'Suricata', 'Zeek', 'Wazuh', 'CrowdSec',
      'nginx', 'Apache', 'Squid', 'Pi-hole', 'BIND', 'Windows DNS', 'Postfix', 'Aruba', 'HPE', 'UniFi', 'RFC 3164 / 5424', 'CEF or LEEF']) expect(names, needle).toContain(needle)
    for (const e of ENTRIES) {
      expect(GROUPS, e.id).toContain(e.group)
      expect(e.protos.length, e.id).toBeGreaterThan(0)
      expect(e.steps({ ip: IP, port: 514, proto: e.protos[0]! }).length, e.id).toBeGreaterThan(0)
      expect(e.snippets({ ip: IP, port: 514, proto: e.protos[0]! }).length, e.id).toBeGreaterThan(0)
      expect(e.readsNote.length, e.id).toBeGreaterThan(10)
      // no Vietnamese in the copy users read
      expect(JSON.stringify([e.name, e.intro, e.readsNote, e.steps({ ip: IP, port: 514, proto: e.protos[0]! }), e.snippets({ ip: IP, port: 514, proto: e.protos[0]! }), e.notes]), e.id).not.toMatch(/[ạảãàáâấầẩẫậăắằẳẵặẹẻẽèéêếềểễệỉĩìíịọỏõòóôốồổỗộơớờởỡợụủũùúưứừửữựỳỷỹỵýđ]/i)
    }
    // honesty: only the kinds that have a profile (modules/logs/data/profiles) say parsed; everyone else says stored, and the digest reads them with the generic pattern finder
    expect(ENTRIES.filter((e) => e.reads === 'parsed').map((e) => e.id).sort()).toEqual(['fortigate', 'mikrotik', 'windows'])
    expect(CATALOG.nginx.readsNote).toMatch(/Stored and searchable\./)
    // W3-10 (D-487): a Linux source says its failed logins are read, not "Stored only".
    expect(CATALOG['linux-rsyslog'].logins).toBe(true)
    expect(CATALOG['linux-rsyslog'].readsNote).toMatch(/^Failed logins: 5 failed SSH or PAM logins/)
  })

  it('every snippet that names the box uses the box address and port', () => {
    for (const e of ENTRIES) {
      for (const proto of e.protos) {
        const text = e.snippets({ ip: IP, port: proto === 'tls' ? 6514 : 514, proto }).map((s) => s.code).join('\n') + e.steps({ ip: IP, port: 514, proto }).join('\n')
        expect(text, `${e.id}/${proto}`).toContain(IP)
      }
    }
  })

  it('search matches names, aliases and groups; every word must match', () => {
    expect(searchCatalog('forti').map((e) => e.id)).toEqual(['fortigate'])
    expect(searchCatalog('synology').map((e) => e.id)).toEqual(['synology'])
    expect(searchCatalog('ubuntu').map((e) => e.id)).toContain('linux-rsyslog')
    expect(searchCatalog('windows dns').map((e) => e.id)).toEqual(['windows-dns'])
    expect(searchCatalog('NAS').map((e) => e.id)).toEqual(expect.arrayContaining(['synology', 'qnap']))
    expect(searchCatalog('zzzz-nothing')).toEqual([])
    expect(searchCatalog('')).toHaveLength(ENTRIES.length)
  })

  it('FortiOS: correct modes (TCP is reliable, not legacy-reliable) and TLS adds enc-algorithm', () => {
    expect(code('fortigate')).toBe(['config log syslogd setting', '    set status enable', `    set server "${IP}"`, '    set port 514', '    set mode udp', 'end', 'config log syslogd filter', '    set severity information', 'end'].join('\n'))
    expect(code('fortigate', 'tcp')).toContain('set mode reliable')
    expect(code('fortigate', 'tcp')).not.toContain('legacy-reliable')
    const tls = code('fortigate', 'tls', 6514)
    expect(tls).toContain('set mode reliable')
    expect(tls).toContain('set enc-algorithm high')
    expect(tls).toContain('set port 6514')
  })

  it('MikroTik: action remote then topics firewall, info, critical; UDP only', () => {
    const lines = code('mikrotik').split('\n')
    expect(lines[0]).toBe(`/system logging action add name=vedette target=remote remote=${IP} remote-port=514`)
    expect(lines.slice(1)).toEqual(['/system logging add action=vedette topics=firewall', '/system logging add action=vedette topics=info', '/system logging add action=vedette topics=critical'])
    expect(CATALOG.mikrotik.protos).toEqual(['udp'])
  })

  it('pfSense is UDP only with the IP:port field; OPNsense also does TCP and TLS', () => {
    expect(CATALOG.pfsense.protos).toEqual(['udp'])
    expect(code('pfsense')).toBe(`${IP}:514`)
    expect(CATALOG.opnsense.protos).toEqual(['udp', 'tcp', 'tls'])
  })

  it('Windows: NXLog nxlog.conf with im_msvistalog, xm_syslog to_syslog_bsd, om_udp or om_tcp, restart command; WEF note', () => {
    const conf = CATALOG.windows.snippets({ ip: IP, port: 514, proto: 'udp' })
    expect(conf[0]!.code).toMatch(/Module\s+im_msvistalog/)
    expect(conf[0]!.code).toMatch(/Module\s+om_udp/)
    expect(conf[0]!.code).toMatch(/to_syslog_bsd\(\)/)
    expect(conf[0]!.code).toMatch(new RegExp(`Host\\s+${IP.replace(/\./g, '\\.')}`))
    expect(conf[0]!.code).toContain('Path    eventlog => vedette')
    expect(code('windows', 'tcp')).toMatch(/Module\s+om_tcp/)
    expect(conf[1]!.code).toBe('Restart-Service nxlog')
    expect(CATALOG.windows.notes.join(' ')).toMatch(/Windows Event Forwarding/)
  })

  it('Suricata: eve-log filetype syslog and rsyslog forwarding (UDP or TCP)', () => {
    const s = CATALOG.suricata.snippets({ ip: IP, port: 514, proto: 'udp' })
    expect(s[0]!.code).toContain('filetype: syslog')
    expect(s[1]!.code).toBe(`local5.* action(type="omfwd" target="${IP}" port="514" protocol="udp")`)
    expect(CATALOG.suricata.snippets({ ip: IP, port: 514, proto: 'tcp' })[1]!.code).toContain('protocol="tcp"')
  })

  it('other well-known syntax: Cisco ASA, IOS, Check Point, NetScaler, ESXi, nginx, Wazuh, rsyslog', () => {
    expect(code('cisco-asa')).toContain(`logging host inside ${IP} udp/514`)
    expect(code('cisco-asa', 'tcp')).toContain(`logging host inside ${IP} tcp/514`)
    expect(code('cisco-ios')).toContain(`logging host ${IP} transport udp port 514`)
    expect(code('cisco-switch', 'tcp')).toContain(`logging host ${IP} transport tcp port 514`)
    expect(code('checkpoint')).toContain(`cp_log_export add name vedette target-server ${IP} target-port 514 protocol udp format syslog`)
    expect(code('netscaler')).toContain(`add audit syslogAction vedette ${IP} -serverPort 514 -logLevel ALL`)
    expect(code('netscaler')).toContain('bind system global vedette-policy -priority 100')
    expect(code('esxi')).toContain(`esxcli system syslog config set --loghost='udp://${IP}:514'`)
    expect(code('esxi', 'tls', 6514)).toContain(`ssl://${IP}:6514`)
    expect(code('nginx')).toContain(`access_log syslog:server=${IP}:514,facility=local7,tag=nginx,severity=info combined;`)
    expect(CATALOG.nginx.protos).toEqual(['udp'])
    expect(code('wazuh')).toContain(`<server>${IP}</server>`)
    expect(code('linux-rsyslog')).toContain(`*.* action(type="omfwd" target="${IP}" port="514" protocol="udp")`)
    expect(code('linux-journald')).toContain('ForwardToSyslog=yes')
    expect(code('syslog-ng')).toContain(`network("${IP}" port(514) transport("udp"))`)
    expect(code('juniper-srx')).toContain(`set security log stream vedette host ${IP}`)
  })
})

/** Opens "Add log source", picks a device type from the picker, returns the dialog. */
async function openAdd(pick: RegExp | string) {
  await userEvent.click(await screen.findByRole('button', { name: 'Add log source' }))
  const form = await screen.findByRole('dialog', { name: 'Add log source' })
  await userEvent.click(within(form).getByRole('button', { name: pick }))
  return form
}

describe('logs: the syslog header of a listed line (W1-22, D-485)', () => {
  it('reads RFC 3164 and 5424 like the box (service_test.go TestEventHeaderIsReadForDisplay); a line without a header is all message', () => {
    expect(syslogHeader('<38>Nov 13 14:15:02 laptop-it sshd[2211]: Failed password for invalid user admin from 45.155.205.233 port 51122 ssh2'))
      .toEqual({ host: 'laptop-it', app: 'sshd', message: 'Failed password for invalid user admin from 45.155.205.233 port 51122 ssh2' })
    expect(syslogHeader('<165>1 2026-11-13T07:15:02.000Z fw01 app 77 ID47 - hello')).toEqual({ host: 'fw01', app: 'app', message: 'hello' })
    expect(syslogHeader('type="traffic" srcip=10.0.0.5 action="deny"')).toEqual({ host: null, app: null, message: 'type="traffic" srcip=10.0.0.5 action="deny"' })
    expect(syslogHeader('<34>Nov 11 08:30:15 sshd[1]: hi')).toEqual({ host: null, app: 'sshd', message: 'hi' })
    expect(syslogHeader('<34>Nov 11 08:30:15 sshd[1]: Accepted: key')).toEqual({ host: null, app: 'sshd', message: 'Accepted: key' })
    expect(syslogHeader('<38>Nov 13 14:15:02 lap\u202etop sshd[2]: x')).toEqual({ host: 'laptop', app: 'sshd', message: 'x' })
  })
})

describe('logs: the Logs page (S-LOG-1, S-LOG-2)', () => {
  it('the heading answers the question, sources and digest tables show, no a11y violations', async () => {
    renderApp('/logs')
    expect(await screen.findByRole('heading', { level: 1, name: 'Today: 2 connections and 1 blocked attempt to bad destinations, 3 new log types, 2 spikes.' })).toBeInTheDocument()
    const sources = await screen.findByRole('table', { name: 'Log sources currently received' })
    expect(within(sources).getAllByRole('row')).toHaveLength(5)
    expect(within(sources).getAllByText('Receiving')).toHaveLength(3)
    // Walk 5: a UDP source's TCP lines are kept too, so the column says both; the mock's sources are UDP
    expect(within(sources).getAllByText(/^UDP and TCP \d+$/).length).toBeGreaterThan(0)
    expect(within(sources).queryByText(/^UDP \d+$/)).toBeNull()
    expect(within(sources).getByText('Silent')).toBeInTheDocument()
    expect(screen.getByText(/No new line for over 1 hour/)).toBeInTheDocument()
    expect(await screen.findByRole('table', { name: 'Connections to bad IPs or domains' })).toBeInTheDocument()
    expect(screen.getByRole('table', { name: 'New log types' })).toBeInTheDocument()
    expect(screen.getByRole('table', { name: 'Log types with a spike' })).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('bad connections point to the source device in the inventory', async () => {
    renderApp('/logs')
    const table = await screen.findByRole('table', { name: 'Connections to bad IPs or domains' })
    const nas = assetsStore.get().find((a) => a.ip === '192.168.10.20')!
    expect(within(table).getByRole('link', { name: nas.hostname! })).toHaveAttribute('href', `/devices/${nas.id}`)
    expect(within(table).getByRole('link', { name: 'Look up 185.220.101.47' })).toHaveAttribute('href', '/lookup?q=185.220.101.47')
  })

  it('a subdomain of a name listed with all of its subdomains says the listed name, and Look up goes to it (D-228, D-425)', async () => {
    renderApp('/logs')
    const table = await screen.findByRole('table', { name: 'Connections to bad IPs or domains' })
    expect(within(table).getByText('a7k2q.update-dsm-synology.com')).toBeInTheDocument()
    expect(within(table).getByText('listed as update-dsm-synology.com')).toBeInTheDocument()
    expect(within(table).getByRole('link', { name: 'Look up update-dsm-synology.com' })).toHaveAttribute('href', '/lookup?q=update-dsm-synology.com')
    expect(within(table).queryByRole('link', { name: 'Look up a7k2q.update-dsm-synology.com' })).toBeNull()
  })

  it('a machine that is not in the inventory is said so', async () => {
    assetsStore.update((l) => l.filter((a) => a.ip !== '192.168.10.157'))
    renderApp('/logs')
    const table = await screen.findByRole('table', { name: 'Connections to bad IPs or domains' })
    expect(within(table).getByText('Not in the inventory')).toBeInTheDocument()
  })

  it('"Device setup" for MikroTik shows the RouterOS commands, what Vedette reads, and the UDP note', async () => {
    renderApp('/logs')
    await userEvent.click(await screen.findByRole('button', { name: 'Device setup for RT-BACKUP' }))
    const dialog = await screen.findByRole('dialog', { name: /Set up RT-BACKUP to send logs to the box/ })
    expect(within(dialog).getByText(/\/system logging action add name=vedette target=remote remote=192\.168\.10\.250 remote-port=514/)).toBeInTheDocument()
    expect(within(dialog).getByText(/RouterOS syslog always goes over UDP/)).toBeInTheDocument()
    expect(within(dialog).getByText(/Reads firewall log lines/)).toBeInTheDocument()
    await expectNoA11yViolations(dialog)
  })

  it('add a FortiGate in three clicks: search, validate, then the setup shows the box IP; saved after reload', async () => {
    renderApp('/logs')
    await userEvent.click(await screen.findByRole('button', { name: 'Add log source' }))
    const form = await screen.findByRole('dialog', { name: 'Add log source' })
    await userEvent.type(within(form).getByLabelText('Find your device or software'), 'forti')
    expect(within(form).getByText('1 match')).toBeInTheDocument()
    await userEvent.click(within(form).getByRole('button', { name: /^FortiGate/ }))
    await userEvent.type(within(form).getByLabelText('Name'), 'FW-CN1')
    await userEvent.type(within(form).getByLabelText('IP of the sending device'), '300.1.1.1')
    await userEvent.click(within(form).getByRole('button', { name: 'Add and show setup' }))
    await waitFor(() => expect(within(form).getByLabelText('IP of the sending device')).toHaveAccessibleDescription(/The IP address of the sending device is not valid/))
    expect(within(form).getByLabelText('Name')).toHaveValue('FW-CN1')
    await userEvent.clear(within(form).getByLabelText('IP of the sending device'))
    await userEvent.type(within(form).getByLabelText('IP of the sending device'), '192.168.30.1')
    await userEvent.click(within(form).getByRole('button', { name: 'Add and show setup' }))
    const guide = await screen.findByRole('dialog', { name: /Set up FW-CN1 to send logs to the box/ })
    expect(within(guide).getByText(/set server "192\.168\.10\.250"/)).toBeInTheDocument()
    expect(within(guide).getByText(/set mode udp/)).toBeInTheDocument()
    await userEvent.click(within(guide).getAllByRole('button', { name: 'Close' })[0]!)
    expect((await screen.findAllByText('FW-CN1')).length).toBeGreaterThan(0)
    expect(auditStore.get().some((e) => e.action === 'logs.source_add' && e.target === 'FW-CN1')).toBe(true)
    const res = await getJson('/logs/sources')
    expect((res.sources as { name: string; state: string; kind: string }[]).find((s) => s.name === 'FW-CN1')).toMatchObject({ state: 'never', kind: 'fortigate' })
  })

  it('the picker groups by category, filters as you type, says when nothing matches, and Enter picks a single match', async () => {
    renderApp('/logs')
    await userEvent.click(await screen.findByRole('button', { name: 'Add log source' }))
    const form = await screen.findByRole('dialog', { name: 'Add log source' })
    for (const g of ['Firewalls and routers', 'VPN and remote access', 'Servers and operating systems', 'NAS and virtualisation', 'Security tools', 'Web, proxy, DNS and mail', 'Switches and Wi-Fi', 'Other and generic']) {
      expect(within(form).getByRole('region', { name: g })).toBeInTheDocument()
    }
    const find = within(form).getByLabelText('Find your device or software')
    await userEvent.type(find, 'zzzz')
    expect(within(form).getByText(/Nothing matches "zzzz"/)).toBeInTheDocument()
    await userEvent.clear(find)
    await userEvent.type(find, 'synology{Enter}')
    expect(within(form).getByText('Device type: Synology DSM (Log Center)')).toBeInTheDocument()
    expect(within(form).getByText(/Stored and searchable\./)).toBeInTheDocument()
    await userEvent.click(within(form).getByRole('button', { name: 'Change device type' }))
    expect(within(form).getByLabelText('Find your device or software')).toBeInTheDocument()
  })

  it('walk 5: the generic syslog form offers UDP, TCP and TLS, as its port hint says', async () => {
    renderApp('/logs')
    const form = await openAdd(/Other device \(standard syslog/)
    expect(within(within(form).getByLabelText('Protocol')).getAllByRole('option').map((o) => o.textContent)).toEqual(['UDP', 'TCP', 'TLS'])
  })

  it('protocol options follow the device: MikroTik UDP only, FortiGate UDP/TCP/TLS, each saying what the box keeps; a duplicate IP is refused at the boundary', async () => {
    renderApp('/logs')
    const form = await openAdd(/MikroTik/)
    expect(within(within(form).getByLabelText('Protocol')).getAllByRole('option')).toHaveLength(1)
    // D-443, D-444 (walk 4): the box listens on UDP and TCP whatever the sources; a UDP source takes TCP too, a TCP source no UDP
    expect(within(form).getByLabelText('Protocol')).toHaveAccessibleDescription("The box listens on UDP and TCP and keeps this device's lines from either.")
    await userEvent.type(within(form).getByLabelText('Name'), 'RT-NEW')
    await userEvent.type(within(form).getByLabelText('IP of the sending device'), '192.168.10.1')
    await userEvent.click(within(form).getByRole('button', { name: 'Add and show setup' }))
    await waitFor(() => expect(within(form).getByLabelText('IP of the sending device')).toHaveAccessibleDescription(/There is already a log source with this IP address/))
    await userEvent.click(within(form).getByRole('button', { name: 'Change device type' }))
    await userEvent.click(within(form).getByRole('button', { name: /^FortiGate/ }))
    expect(within(within(form).getByLabelText('Protocol')).getAllByRole('option')).toHaveLength(3)
    await userEvent.selectOptions(within(form).getByLabelText('Protocol'), 'tcp')
    expect(within(form).getByLabelText('Protocol')).toHaveAccessibleDescription('The box listens on UDP and TCP but keeps only TCP from this device: UDP is easy to forge.')
    await userEvent.selectOptions(within(form).getByLabelText('Protocol'), 'tls')
    expect(within(form).getByLabelText('Protocol')).toHaveAccessibleDescription('The box keeps only TLS from this device, on port 6514.')
    expect(within(form).getByLabelText('Port the box listens on')).toHaveValue(6514)
  })

  it('the box certificate of the TLS port is shown with its fingerprint and a download (S-LOG-1, D-434)', async () => {
    renderApp('/logs')
    const card = (await screen.findByRole('heading', { name: 'Box certificate for syslog over TLS' })).closest('div')!
    expect(within(card).getByText(/box's own certificate authority.*port 6514.*Do not pin the server certificate/)).toBeInTheDocument()
    expect(within(card).getByText(/^[0-9a-f]{64}$/)).toBeInTheDocument()
    expect(within(card).getByRole('button', { name: 'Download certificate (.pem)' })).toBeEnabled()
  })

  it('a TLS source can pin the device client certificate: pasted as AB:CD..., stored as lowercase hex; a bad one is refused under the field (D-435)', async () => {
    renderApp('/logs')
    const form = await openAdd(/^FortiGate/)
    expect(within(form).queryByLabelText('Client certificate fingerprint (optional)')).not.toBeInTheDocument() // UDP: no pin
    await userEvent.selectOptions(within(form).getByLabelText('Protocol'), 'tls')
    const field = within(form).getByLabelText('Client certificate fingerprint (optional)')
    await userEvent.type(within(form).getByLabelText('Name'), 'FW-PIN')
    await userEvent.type(within(form).getByLabelText('IP of the sending device'), '192.168.10.77')
    await userEvent.type(field, 'not a fingerprint')
    await userEvent.click(within(form).getByRole('button', { name: 'Add and show setup' }))
    await waitFor(() => expect(field).toHaveAccessibleDescription(/64 hexadecimal characters/))
    await userEvent.clear(field)
    await userEvent.type(field, 'AB:'.repeat(31) + 'AB')
    await userEvent.click(within(form).getByRole('button', { name: 'Add and show setup' }))
    await screen.findByRole('dialog', { name: /Set up FW-PIN to send logs to the box/ })
    const list = (await getJson('/logs/sources')).sources as { name: string; client_cert_sha256: string | null }[]
    expect(list.find((x) => x.name === 'FW-PIN')?.client_cert_sha256).toBe('ab'.repeat(32))
  })

  it('deleting a log source needs confirmation', async () => {
    renderApp('/logs')
    await userEvent.click(await screen.findByRole('button', { name: 'Delete SRV-FILE' }))
    const dlg = await screen.findByRole('dialog', { name: 'Delete log source SRV-FILE?' })
    await userEvent.click(within(dlg).getByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(screen.queryByText('SRV-FILE')).not.toBeInTheDocument())
    expect(auditStore.get().some((e) => e.action === 'logs.source_delete')).toBe(true)
  })

  it('a viewer can read the setup but cannot add, edit or delete', async () => {
    renderApp('/logs', { role: 'viewer' })
    expect(await screen.findByRole('button', { name: 'Add log source' })).toBeDisabled()
    expect(await screen.findByRole('button', { name: 'Edit FW-HQ' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Delete FW-HQ' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Device setup for FW-HQ' })).toBeEnabled()
    expect(screen.getByLabelText('Keep logs for')).toBeDisabled()
    const res = await fetch(`${location.origin}/api/v1/logs/sources`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })
    expect(res.status).toBe(403)
  })

  it('searching events by keyword; says so when no line matches', async () => {
    renderApp('/logs')
    const input = await screen.findByLabelText('Keyword')
    await userEvent.type(input, '185.220.101.47')
    const table = await screen.findByRole('table', { name: 'Log events' })
    await waitFor(() => expect(within(table).getAllByRole('row')).toHaveLength(2))
    expect(within(table).getByText(/dstip=185\.220\.101\.47/)).toBeInTheDocument()
    await userEvent.clear(input)
    await userEvent.type(input, 'no-such-line')
    expect(await screen.findByText(/No matching line/)).toBeInTheDocument()
  })

  it('a keyword search that stopped early says how far back it looked and Search older lines continues it (S-LOG-1, D-441)', async () => {
    const ev = (id: string, ts: string) => ({ id, ts, source_id: 'ls-1', source_name: 'FW-HQ', line: `needle ${id}` })
    let cursor: string | null = 'unset'
    server.use(http.get('*/api/v1/logs/events', ({ request }) => {
      const p = new URL(request.url).searchParams
      if (!p.get('q')) return HttpResponse.json({ events: [], total: 0, next_cursor: null })
      cursor = p.get('cursor')
      return cursor
        ? HttpResponse.json({ events: [ev('le-2', '2026-11-05T08:00:00Z')], total: 1, next_cursor: null })
        : HttpResponse.json({ events: [ev('le-1', '2026-11-11T08:00:00Z')], total: 1, next_cursor: 'c1', searched_back_to: '2026-11-10T08:00:00Z' })
    }))
    renderApp('/logs')
    await userEvent.type(await screen.findByLabelText('Keyword'), 'needle')
    expect(await screen.findByText(/1 matching line found so far, searched back to/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Search older lines' }))
    expect(await screen.findByText('2 matching lines in this time range.')).toBeInTheDocument()
    expect(cursor).toBe('c1')
    expect(screen.queryByRole('button', { name: 'Search older lines' })).not.toBeInTheDocument()
  })

  it('changing the retention period', async () => {
    renderApp('/logs')
    await userEvent.selectOptions(await screen.findByLabelText('Keep logs for'), '90')
    expect(await screen.findByText('Log retention saved.')).toBeInTheDocument()
    expect(((await getJson('/logs/sources')).retention_days)).toBe(90)
  })

  it('shortening the retention asks first: Cancel keeps it, Delete older lines saves; lengthening needs no dialog', async () => {
    renderApp('/logs')
    const select = await screen.findByLabelText('Keep logs for')
    await userEvent.selectOptions(select, '7')
    const dialog = await screen.findByRole('dialog', { name: 'Keep logs for 7 days only?' })
    expect(within(dialog).getByText('Log lines older than 7 days will be deleted at the next cleanup (within about an hour) and cannot be restored.')).toBeInTheDocument()
    await expectNoA11yViolations(dialog)
    expect((await getJson('/logs/sources')).retention_days).toBe(30)
    await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect((await getJson('/logs/sources')).retention_days).toBe(30)
    await userEvent.selectOptions(select, '7')
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Delete older lines' }))
    await waitFor(async () => expect((await getJson('/logs/sources')).retention_days).toBe(7))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    await userEvent.selectOptions(select, '180')
    await waitFor(async () => expect((await getJson('/logs/sources')).retention_days).toBe(180))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('no sources yet: the empty state says what to do and nothing else is shown', async () => {
    server.use(http.get('*/api/v1/logs/sources', () => HttpResponse.json({ box: { ip: '192.168.10.250', hostname: 'vedette-hq' }, sources: [], retention_days: 30 })))
    renderApp('/logs')
    expect(await screen.findByRole('heading', { level: 1, name: 'No device is sending logs to the box yet.' })).toBeInTheDocument()
    expect(screen.getByText('No log sources yet')).toBeInTheDocument()
    expect(screen.queryByRole('table', { name: 'New log types' })).not.toBeInTheDocument()
    expect(screen.queryByLabelText('Keyword')).not.toBeInTheDocument()
  })

  it('no sources yet, but syslog arrives: the sender is named once with every protocol it used, a way to add it and a forgery warning (walk 4, D-443)', async () => {
    server.use(
      http.get('*/api/v1/logs/sources', () => HttpResponse.json({ box: { ip: '192.168.18.141', hostname: 'vedette' }, sources: [], retention_days: 30 })),
      http.get('*/api/v1/logs/unknown-senders', () => HttpResponse.json({ items: [
        { ip: '192.168.18.145', proto: 'tcp', count: 1, last_seen: new Date().toISOString() },
        { ip: '192.168.18.145', proto: 'udp', count: 2, last_seen: new Date(Date.now() - 60e3).toISOString() },
      ] })),
    )
    renderApp('/logs')
    const hint = await screen.findByRole('region', { name: 'Syslog from an address that is not a source' })
    expect(hint).toHaveTextContent('192.168.18.145 sends syslog over TCP and UDP, but no source has this IP, so the box drops its lines (3 times, last')
    expect(within(hint).getAllByRole('listitem')).toHaveLength(1)
    expect(hint).toHaveTextContent('The sender address of a UDP datagram can be forged')
    await userEvent.click(within(hint).getByRole('button', { name: 'Add 192.168.18.145 as a log source' }))
    const form = await screen.findByRole('dialog', { name: 'Add log source' })
    await userEvent.click(within(form).getByRole('button', { name: /^FortiGate/ }))
    expect(within(form).getByLabelText('Protocol')).toHaveValue('udp') // a UDP source takes TCP too (D-444)
  })

  it('the box address is unknown (no LAN range yet): the page says so and the setup shows a clear placeholder', async () => {
    server.use(http.get('*/api/v1/logs/sources', () => HttpResponse.json({
      box: { ip: null, hostname: 'vedette', lan: null, iface: 'eth0' }, retention_days: 30,
      sources: [{ id: 'ls-9', kind: 'nginx', name: 'WEB-1', sender_ip: '10.0.0.5', asset_id: null, asset_name: null, proto: 'udp', port: 514, last_received: null, lines_per_hour: 0, state: 'never', created_at: new Date().toISOString() }],
    })))
    renderApp('/logs')
    expect(await screen.findByText(/add your LAN range first \(Devices, Scope and sensors\)/)).toBeInTheDocument()
    await userEvent.click(await screen.findByRole('button', { name: 'Device setup for WEB-1' }))
    const dialog = await screen.findByRole('dialog', { name: /Set up WEB-1/ })
    expect(within(dialog).getByRole('alert')).toHaveTextContent('Add your LAN range first')
    expect(within(dialog).getByText(/access_log syslog:server=<VEDETTE_BOX_IP>:514/)).toBeInTheDocument()
    expect(dialog).not.toHaveTextContent('192.168.10.250')
  })

  it('a container that cannot see its own address in the declared LAN range says to use the address of the machine, not to add a range (user walk)', async () => {
    server.use(http.get('*/api/v1/logs/sources', () => HttpResponse.json({
      box: { ip: null, hostname: 'vedette', lan: '192.168.50.0/24', iface: 'eth0' }, retention_days: 30,
      sources: [{ id: 'ls-9', kind: 'nginx', name: 'WEB-1', sender_ip: '192.168.50.5', asset_id: null, asset_name: null, proto: 'udp', port: 514, last_received: null, lines_per_hour: 0, state: 'never', created_at: new Date().toISOString() }],
    })))
    renderApp('/logs')
    expect(await screen.findByText(/cannot see its own address in your LAN range 192\.168\.50\.0\/24.*the one you open this page on/)).toBeInTheDocument()
    expect(screen.queryByText(/add your LAN range first/)).not.toBeInTheDocument()
    // no line yet: no size estimate for the retention (QA walk 2026-11-12)
    expect(screen.getByText(/no size estimate yet/)).toBeInTheDocument()
    expect(screen.queryByText(/take about/)).not.toBeInTheDocument()
    await userEvent.click(await screen.findByRole('button', { name: 'Device setup for WEB-1' }))
    const alert = within(await screen.findByRole('dialog', { name: /Set up WEB-1/ })).getByRole('alert')
    expect(alert).toHaveTextContent('Use the address of the machine that runs Vedette')
    expect(alert).not.toHaveTextContent('Add your LAN range first')
  })

  it('Refresh in Log sources refreshes the headline, the digest and the event search too (user walk)', async () => {
    let lines = 0
    server.use(
      http.get('*/api/v1/logs/digest', () => HttpResponse.json({ generated_at: '2026-11-12T01:00:00Z', lines_24h: lines, baseline_days: 7, history_days: 7, new: [], spikes: [], bad_connections: [], ioc_matching: true })),
      http.get('*/api/v1/logs/events', () => HttpResponse.json({ events: [], total: lines, next_cursor: null })),
    )
    renderApp('/logs')
    expect(await screen.findByRole('heading', { level: 1, name: 'No log line received yet.' })).toBeInTheDocument()
    lines = 34
    await userEvent.click(screen.getByRole('button', { name: 'Refresh' }))
    expect(await screen.findByRole('heading', { level: 1, name: /^Today: logs look normal/ })).toBeInTheDocument()
    expect(await screen.findByText(/0 of 34 matching lines/)).toBeInTheDocument()
  })

  it('less than the baseline of logs: the page says it is still learning, not that logs look normal (QA walk)', async () => {
    server.use(http.get('*/api/v1/logs/digest', () => HttpResponse.json({ generated_at: '2026-11-12T01:00:00Z', lines_24h: 34, baseline_days: 7, history_days: 0, new: [], spikes: [], bad_connections: [], ioc_matching: true })))
    renderApp('/logs')
    expect(await screen.findByRole('heading', { level: 1, name: 'Learning what is normal: 0 of 7 days of logs so far.' })).toBeInTheDocument()
    expect(await screen.findByText(/^No new log types yet\. The box is still learning/)).toBeInTheDocument()
    expect(screen.queryByText(/look normal|compared with 7 days ago|compared with the previous/)).not.toBeInTheDocument()
  })

  it('Feeds off: the headline does not count bad connections and the empty list links to Settings, Modules (QA walk)', async () => {
    const item = { id: 'n-1', signature: 'x', source_id: 'ls-1', source_name: 'FW-HQ', count: 1, first_seen: '2026-11-12T00:00:00Z', sample: 'x' }
    server.use(http.get('*/api/v1/logs/digest', () => HttpResponse.json({ generated_at: '2026-11-12T01:00:00Z', lines_24h: 5, baseline_days: 7, history_days: 7, new: [item], spikes: [], bad_connections: [], ioc_matching: false })))
    modulesStore.update((l) => l.map((m) => (m.id === 'feeds' ? { ...m, enabled: false } : m)))
    renderApp('/logs')
    expect(await screen.findByRole('heading', { level: 1, name: 'Today: 1 new log type, 0 spikes.' })).toBeInTheDocument()
    expect(await screen.findByRole('link', { name: 'Open Settings, Modules' })).toHaveAttribute('href', '/settings/modules')
  })

  it('the headline says one connection, and counts a blocked attempt apart (D-227, QA walk 3)', async () => {
    const hit = (id: string, blocked: boolean) => ({ id, ts: '2026-11-12T00:00:00Z', asset_id: null, asset_name: null, src_ip: '192.168.1.50', dest: '185.220.101.47', dest_kind: 'ip', seen_via: 'syslog:FW-HQ', feeds: ['IPsum'], confidence: 0.6, blocked, listed_as: null })
    let hits = [hit('h-1', true)]
    server.use(http.get('*/api/v1/logs/digest', () => HttpResponse.json({ generated_at: '2026-11-12T01:00:00Z', lines_24h: 5, baseline_days: 7, history_days: 7, new: [], spikes: [], bad_connections: hits, ioc_matching: true })))
    renderApp('/logs')
    expect(await screen.findByRole('heading', { level: 1, name: 'Today: 1 blocked attempt to bad destinations, 0 new log types, 0 spikes.' })).toBeInTheDocument()
    hits = [hit('h-1', true), hit('h-2', false)]
    await userEvent.click(screen.getByRole('button', { name: 'Refresh' }))
    expect(await screen.findByRole('heading', { level: 1, name: 'Today: 1 connection and 1 blocked attempt to bad destinations, 0 new log types, 0 spikes.' })).toBeInTheDocument()
  })

  it('syslog from an address that is not a source is named, with a way to add it; a viewer does not see addresses (S-LOG-1, QA walk 3)', async () => {
    server.use(
      http.get('*/api/v1/logs/sources', () => HttpResponse.json({
        box: { ip: null, hostname: 'vedette', lan: '192.168.1.0/24', iface: 'eth0' }, retention_days: 30,
        sources: [{ id: 'ls-1', kind: 'fortigate', name: 'FW-HQ', sender_ip: '192.168.1.1', asset_id: null, asset_name: null, proto: 'udp', port: 514, last_received: null, lines_per_hour: 0, state: 'never', created_at: '2026-11-12T00:00:00Z' },
          { id: 'ls-2', kind: 'cisco-asa', name: 'RT-1', sender_ip: '192.168.1.2', asset_id: null, asset_name: null, proto: 'tcp', port: 514, last_received: null, lines_per_hour: 0, state: 'never', created_at: '2026-11-12T00:00:00Z' }],
      })),
      http.get('*/api/v1/logs/unknown-senders', () => HttpResponse.json({ items: [
        { ip: '172.18.0.1', proto: 'udp', count: 5, last_seen: new Date().toISOString() },
        { ip: '192.168.1.2', proto: 'udp', count: 1, last_seen: new Date().toISOString() }, // a TCP source takes no UDP (D-444)
      ] })),
    )
    const view = renderApp('/logs')
    const hint = await screen.findByRole('region', { name: 'Syslog from an address that is not a source' })
    expect(hint).toHaveTextContent('172.18.0.1 sends syslog over UDP, but no source has this IP, so the box drops its lines (5 times, last')
    expect(hint).toHaveTextContent('192.168.1.2 sends syslog over UDP, but RT-1 is declared with TCP, so the box drops its lines (once, last')
    expect(hint).toHaveTextContent("arrives from the containers' network gateway")
    expect(within(hint).getByRole('button', { name: 'Edit RT-1' })).toBeEnabled()
    await userEvent.click(within(hint).getByRole('button', { name: 'Add 172.18.0.1 as a log source' }))
    const form = await screen.findByRole('dialog', { name: 'Add log source' })
    await userEvent.click(within(form).getByRole('button', { name: /^FortiGate/ }))
    expect(within(form).getByLabelText(/IP of the sending device/)).toHaveValue('172.18.0.1')
    view.unmount()
    renderApp('/logs', { role: 'viewer' })
    expect(await screen.findByRole('table', { name: 'Log sources currently received' })).toBeInTheDocument()
    expect(screen.queryByText(/172\.18\.0\.1/)).not.toBeInTheDocument()
  })

  it('an API error shows the message and a retry button', async () => {
    server.use(http.get('*/api/v1/logs/digest', () => HttpResponse.json({ error: { code: 'x', message: 'The log aggregator has not finished yet.' } }, { status: 503 })))
    renderApp('/logs')
    expect(await screen.findByText('The log aggregator has not finished yet.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument()
  })

  it('an empty list of bad connections says plainly that nothing was found, and says why when Feeds is off', async () => {
    const digest = { generated_at: '2026-11-12T01:00:00Z', lines_24h: 5, baseline_days: 7, history_days: 7, new: [], spikes: [], bad_connections: [], ioc_matching: true }
    server.use(http.get('*/api/v1/logs/digest', () => HttpResponse.json(digest)))
    const first = renderApp('/logs')
    expect(await screen.findByText('None of your devices connected to a listed bad address in the last 24 hours.')).toBeInTheDocument()
    expect(screen.queryByText(/not switched on yet/)).not.toBeInTheDocument()
    expect(screen.queryByText(/The Feeds module is off/)).not.toBeInTheDocument()
    first.unmount()
    modulesStore.update((l) => l.map((m) => (m.id === 'feeds' ? { ...m, enabled: false } : m)))
    renderApp('/logs')
    expect(await screen.findByText(/The Feeds module is off, so no connection can be matched/)).toBeInTheDocument()
    // with Feeds off nothing was matched, so the list must not read as "no device connected" (D-300; QA walk 2026-11-12)
    expect(screen.queryByText(/None of your devices connected/)).not.toBeInTheDocument()
  })

  it('Feeds on but no switched-on feed lists an indicator: the empty list says nothing could be matched (QA walk a)', async () => {
    const digest = { generated_at: '2026-11-12T01:00:00Z', lines_24h: 5, baseline_days: 7, history_days: 7, new: [], spikes: [], bad_connections: [], ioc_matching: false }
    server.use(http.get('*/api/v1/logs/digest', () => HttpResponse.json(digest)))
    renderApp('/logs')
    expect(await screen.findByText(/No switched-on threat feed lists any IP address or domain yet/)).toBeInTheDocument()
    expect(screen.queryByText(/None of your devices connected/)).not.toBeInTheDocument()
  })

  it('the digest shows the hits of the last 24 hours only, newest first, with the device resolved when it is read', async () => {
    const row = (id: string, hours: number, ip: string, dest: string, blocked = false) => ({ id, ts: new Date(Date.now() - hours * 3600e3).toISOString(), src_ip: ip, dest, dest_kind: 'ip' as const, seen_via: 'syslog:FW-HQ', feeds: ['x'], confidence: 0.5, blocked })
    collection<ReturnType<typeof row>[]>('logs_ioc_hits', () => []).set([row('b-old', 30, '192.168.10.20', '203.0.113.99'), row('b-a', 5, '192.168.10.20', '203.0.113.51', true), row('b-b', 1, '192.168.10.20', '203.0.113.50')])
    renderApp('/logs')
    const table = await screen.findByRole('table', { name: 'Connections to bad IPs or domains' })
    expect(within(table).queryByText('203.0.113.99')).not.toBeInTheDocument()
    expect(within(table).getAllByRole('link', { name: /^Look up / }).map((a) => a.textContent)).toEqual(['Look up 203.0.113.50', 'Look up 203.0.113.51'])
    const nas = assetsStore.get().find((a) => a.ip === '192.168.10.20')!
    expect(within(table).getAllByRole('link', { name: nas.hostname! })).toHaveLength(2)
    // D-227: a line the firewall blocked is an attempt, marked Blocked; the one that went through is not
    const [newest, older] = within(table).getAllByRole('row').slice(1)
    expect(within(older!).getByText('Blocked')).toBeInTheDocument()
    expect(within(newest!).queryByText('Blocked')).not.toBeInTheDocument()
  })

  it('logs module off: says where to turn it on', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'logs' ? { ...m, enabled: false } : m)))
    renderApp('/logs')
    expect(await screen.findByText(/module is off/)).toBeInTheDocument()
  })
})

describe('logs: SIEM forwarding (S-LOG-3)', () => {
  it('no a11y violations; an unconfigured form shows a sample record', async () => {
    renderSiem()
    expect(await screen.findByRole('heading', { name: 'Forward to a SIEM' })).toBeInTheDocument()
    expect(screen.getByText(/<131>1 .* finding\.created/)).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('a wrong server is refused, a right one is saved and tested', async () => {
    renderSiem()
    await userEvent.click(await screen.findByRole('button', { name: /^Save$/ }))
    expect(await screen.findByRole('alert')).toHaveTextContent('The SIEM server must be an IP address or a domain name')
    await userEvent.type(screen.getByLabelText('SIEM server'), 'siem.company.com')
    await userEvent.click(screen.getByRole('button', { name: 'Save and send test' }))
    expect((await screen.findAllByText('SIEM settings saved.')).length).toBeGreaterThan(0)
    expect((await screen.findAllByText(/Sent 1 test record to siem\.company\.com:514\/udp/)).length).toBeGreaterThan(0)
    expect(await screen.findByRole('status')).toHaveTextContent('success')
    expect(auditStore.get().some((e) => e.action === 'logs.siem_test')).toBe(true)
  })

  it('an unreachable destination: the error says how to fix it', async () => {
    renderSiem()
    await userEvent.type(await screen.findByLabelText('SIEM server'), 'siem.invalid')
    await userEvent.click(screen.getByRole('button', { name: 'Save and send test' }))
    expect((await screen.findAllByText(/Could not connect to siem\.invalid/)).length).toBeGreaterThan(0)
    expect(await screen.findByRole('status')).toHaveTextContent('failed')
  })

  it('JSON webhook: the signing key keeps only its last 4 characters, the API never returns the full key', async () => {
    renderSiem()
    await userEvent.click(await screen.findByRole('button', { name: 'JSON webhook' }))
    await userEvent.type(screen.getByLabelText('Webhook URL'), 'https://siem.company.com/hooks/vedette')
    await userEvent.type(screen.getByLabelText('Signing key (optional)'), 'a-signing-key-longer-than-16-ABCD')
    expect(screen.getByLabelText('Signing key (optional)')).toHaveAttribute('type', 'password')
    await userEvent.click(screen.getByRole('button', { name: /^Save$/ }))
    expect((await screen.findAllByText('SIEM settings saved.')).length).toBeGreaterThan(0)
    expect(await screen.findByText('Saved, ending in ABCD. Leave empty to keep it.')).toBeInTheDocument()
    const cfg = await getJson('/logs/siem')
    expect(cfg.secret_last4).toBe('ABCD')
    expect(JSON.stringify(cfg)).not.toContain('a-signing-key')
    expect(screen.getByLabelText('Signing key (optional)')).toHaveValue('')
  })

  it('clearing every event type is refused', async () => {
    renderSiem()
    await userEvent.type(await screen.findByLabelText('SIEM server'), '192.168.10.50')
    await userEvent.click(screen.getByRole('checkbox', { name: 'Findings: vulnerabilities matching your devices' }))
    await userEvent.click(screen.getByRole('checkbox', { name: 'Alerts sent' }))
    await userEvent.click(screen.getByRole('button', { name: /^Save$/ }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Choose at least one event type')
  })

  it('an operator cannot change the SIEM settings', async () => {
    renderSiem('operator')
    expect(await screen.findByText('Your account is not allowed to do this.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument()
    const res = await fetch(`${location.origin}/api/v1/logs/siem`)
    expect(res.status).toBe(403)
  })
})

describe('logs: Add log source form matrix (docs/QA.md §2)', () => {
  it('for every one of the device types: only its own protocols are offered, and the port follows the protocol', async () => {
    renderApp('/logs')
    await userEvent.click(await screen.findByRole('button', { name: 'Add log source' }))
    const form = await screen.findByRole('dialog', { name: 'Add log source' })
    const proto = () => within(form).getByLabelText('Protocol') as HTMLSelectElement
    const port = () => within(form).getByLabelText('Port the box listens on') as HTMLInputElement
    const choose = async (name: string) => {
      const b = within(form).getAllByRole('button').find((x) => x.querySelector('span')?.textContent === name)
      expect(b, `device type "${name}" is in the list`).toBeDefined()
      await userEvent.click(b!)
    }
    // a TLS choice first, so a kind without TLS must move it away
    await choose(CATALOG.fortigate.name)
    await userEvent.selectOptions(proto(), 'tls')
    expect(port().value).toBe('6514')
    for (const e of ENTRIES) {
      await userEvent.click(within(form).getByRole('button', { name: 'Change device type' }))
      await choose(e.name)
      const offered = [...proto().options].map((o) => o.value)
      expect(offered, e.name).toEqual(e.protos)
      expect(e.protos, `${e.name}: selected protocol is one it offers`).toContain(proto().value)
      expect(port().value, `${e.name}: port follows the protocol`).toBe(proto().value === 'tls' ? '6514' : '514')
    }
  })

  it('the server refuses a protocol the device type cannot send, and a name or IP that is not valid', async () => {
    const only = ENTRIES.find((e) => !e.protos.includes('tls'))!
    renderSiem()
    const post = (b: unknown) => fetch(`${location.origin}/api/v1/logs/sources`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) })
    expect((await post({ kind: only.id, name: 'TLS-ONLY', sender_ip: '192.168.10.77', proto: 'tls', port: 6514 })).status).toBe(400)
    expect((await post({ kind: only.id, name: 'bad name!', sender_ip: '192.168.10.77', proto: only.protos[0], port: 514 })).status).toBe(400)
    expect((await post({ kind: only.id, name: 'OK-1', sender_ip: '999.1.1.1', proto: only.protos[0], port: 514 })).status).toBe(400)
  })
})

describe('logs: Add log source form matrix (docs/QA.md §2, QA walk 2026-11-12)', () => {
  it('a refused value is told under its own field, which takes focus; fixing the field clears it', async () => {
    renderApp('/logs')
    const form = await openAdd(/^FortiGate/)
    const name = within(form).getByLabelText('Name')
    const NAME_ERR = /may only contain letters without accents/
    fireEvent.change(within(form).getByLabelText('IP of the sending device'), { target: { value: '192.168.10.77' } })
    await eachOption([
      { option: 'FW HQ ă', shown: [NAME_ERR] },
      { option: 'FW-HQ', hidden: [NAME_ERR] },
    ], async (o) => {
      fireEvent.change(name, { target: { value: o } })
      if (o === 'FW HQ ă') { await userEvent.click(within(form).getByRole('button', { name: 'Add and show setup' })); await within(form).findByText(NAME_ERR) }
    }, form)
    fireEvent.change(name, { target: { value: 'FW HQ ă' } })
    await userEvent.click(within(form).getByRole('button', { name: 'Add and show setup' }))
    await waitFor(() => expect(name).toHaveFocus())
    expect(name).toBeInvalid()
    expect(name).toHaveAccessibleDescription(NAME_ERR)
    expect(within(form).queryByRole('alert')).toBeNull()
  })
})
