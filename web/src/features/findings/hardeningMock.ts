// Mock of the box's general hardening (modules/mitigation/hardening.go, INV-8, M2-1) so `make dev` shows the block: the same shape and
// the same kind of configs, written from the sample device's IP and open ports. The box's Go code is the reference; this is sample data.
import type { Asset } from '@/lib/types'
import { collection } from '@/mocks/db'
import { ADMIN_NET_PLACEHOLDER as NET } from './contract'
import type { CompromiseCheck, FindingAsset, FirewallGuide, GeneralHardening, Indicator, KevInfo } from './types'

type Port = GeneralHardening['ports'][number]
type Svc = Asset['services'][number]
interface Family { label: string; port: ((s: Svc) => boolean) | null; checks: Indicator[] }

const web = (s: Svc) => s.name.includes('http') || [80, 443, 8080, 8443].includes(s.port)
const admin = (s: Svc) => web(s) || /ssh|telnet|snmp|winbox/.test(s.name) || [22, 23, 161, 8291, 8728, 8729].includes(s.port)

const LINUX: Indicator[] = [
  { kind: 'log', title: 'Sign-ins', detail: 'Sign-ins at odd hours or from addresses you do not know. The log is /var/log/auth.log (Debian, Ubuntu) or /var/log/secure (Red Hat family), or the journal.', commands: [{ label: 'Last sign-ins', code: 'sudo last -a -n 50' }] },
  { kind: 'process', title: 'Listening programs and programs run from temporary folders', detail: 'Ports you cannot explain, and programs running from /tmp, /var/tmp or /dev/shm.', commands: [{ label: 'Listening ports and their programs', code: 'sudo ss -tulpn' }] },
]
const FAMILIES: Record<string, Family> = {
  windows: { label: 'Windows', port: (s) => [135, 139, 445, 3389, 5985, 5986].includes(s.port), checks: [
    { kind: 'log', title: 'New or changed accounts', detail: 'Security log events 4720, 4722, 4724, 4728, 4732 and 4756 that nobody in your team did, and members of Administrators you do not know.',
      commands: [{ label: 'PowerShell: members of Administrators', code: 'Get-LocalGroupMember -Group Administrators' }] },
    { kind: 'process', title: 'New services, scheduled tasks and listening programs', detail: 'Services installed recently (System log event 7045), scheduled tasks outside Microsoft\'s folder, and programs listening on ports you cannot explain.' },
  ] },
  web: { label: 'Web server', port: web, checks: [
    { kind: 'web', title: 'New script files in the web folders', detail: 'Web shells are small .php, .jsp or .jspx files dropped where the web server serves files.',
      commands: [{ label: 'Script files changed in the last 30 days', code: "sudo find /var/www /srv -type f \\( -name '*.php' -o -name '*.jsp' \\) -mtime -30 -ls 2>/dev/null" }] },
    ...LINUX,
  ] },
  linux: { label: 'Linux', port: (s) => s.name === 'ssh' || s.port === 22, checks: LINUX },
  netdevice: { label: 'Network device', port: admin, checks: [
    { kind: 'file', title: 'Admin accounts', detail: "In the device's admin pages: administrators and VPN users nobody in your team created." },
    { kind: 'log', title: 'Admin sign-ins and configuration changes', detail: "In the device's system log: sign-ins from addresses you do not know. Compare the running configuration with your last backup." },
  ] },
  general: { label: 'General', port: null, checks: [
    { kind: 'file', title: 'Accounts', detail: "In the software's own user list: administrators, users, API keys and tokens nobody in your team created." },
    { kind: 'log', title: 'Sign-ins and changes', detail: "In the software's log: sign-ins at odd hours or from addresses you do not know." },
  ] },
}

function familyOf(k: KevInfo | null, kind: string): Family {
  const vp = `${k?.vendor ?? ''} ${k?.product ?? ''}`.toLowerCase()
  if (vp.startsWith('microsoft')) return FAMILIES.windows!
  if (/wordpress|php|struts|gitlab|magento|atlassian|strapi/.test(vp)) return FAMILIES.web!
  if (/^linux /.test(vp)) return FAMILIES.linux!
  if (/fortinet|cisco|ivanti|palo alto|mikrotik/.test(vp) || ['firewall', 'router', 'switch', 'ap'].includes(kind)) return FAMILIES.netdevice!
  return FAMILIES.general!
}

const OUTBOUND: Indicator = { kind: 'log', title: 'Connections the device started to the internet', detail: "In your firewall's traffic log, look for connections from the device to outside addresses it has no reason to reach: intruders' tools call home." }
const IF_FOUND = [
  'Take the device off the network, but leave it powered on: its memory and temporary files are evidence.',
  'Keep what you found: copy the logs and the files before you change anything.',
  'From a clean computer, change every password and key the device holds or uses, and anywhere they are reused.',
  'Rebuild the device from a known good install or firmware and update it before you connect it again.',
  'Get help: your incident response provider or your national CERT.',
]

/** The address the box sees for this browser (GeneralHardening.viewer): empty, as on a box behind no known address; tests set it. */
export const mockViewer = collection<string>('mit_viewer', () => '')

/** The sample box's own address (the mock's Vedette box), allowed in every config like the box's (r2 M2). */
const BOX = '192.168.10.5'

function guides(cve: string, ip: string, ports: Port[], has: (v: string) => boolean): FirewallGuide[] {
  const tcp = ports.filter((p) => p.proto === 'tcp').map((p) => p.port)
  const all = tcp.length === 0
  const tag = cve.toLowerCase()
  const slug = `${tag}-${ip.replaceAll('.', '-')}`
  const boxNote = ` The Vedette box (${BOX}) is allowed too, so its scans still see the ports.`
  const intro = (all
    ? `Vedette has not seen services of this kind open on ${ip}, so this config blocks every new connection to the device except from your admin network.`
    : `Vedette saw these services open on ${ip}: ${ports.map((p) => `${p.port}/${p.proto}${p.service ? ` (${p.service})` : ''}`).join(', ')}. This config lets only your admin network reach them; the rest of the device is unchanged.`)
    + ' A firewall only filters what passes through it: computers in the same network segment as the device still reach it directly.' + boxNote
  const side = all
    ? 'Everything the device serves (websites, mail, shared folders, printing, remote desktop) stops for computers outside the admin network that reach it through this firewall.'
    : 'Computers outside the admin network can no longer reach these ports of the device through this firewall.'
  const svc = all ? '"ALL"' : `"vedette-${slug}-ports"`
  const box = `vedette-box-${BOX.replaceAll('.', '-')}`
  const policy = (name: string, src: string, action: string, extra: string) =>
    `    edit 0\n        set name "${name}"\n        set srcintf "any"\n        set dstintf "any"\n        set srcaddr ${src}\n        set dstaddr "vedette-${slug}"\n        set action ${action}\n        set service ${svc}\n        set schedule "always"\n${extra}    next\n`
  const fortigate = [
    `config firewall address\n    edit "vedette-admin-net"\n        set subnet ${NET}\n    next\n    edit "${box}"\n        set subnet ${BOX}/32\n    next\n    edit "vedette-${slug}"\n        set subnet ${ip}/32\n    next\nend`,
    all ? '' : `config firewall service custom\n    edit "vedette-${slug}-ports"\n        set tcp-portrange ${tcp.join(' ')}\n    next\nend`,
    `config firewall policy\n${policy(`vedette-${tag}-a`, `"vedette-admin-net" "${box}"`, 'accept', '')}${policy(`vedette-${tag}-d`, '"all"', 'deny', '        set match-vip enable\n        set logtraffic all\n')}end`,
  ].filter(Boolean).join('\n')
  const spec = all ? '' : ` protocol=tcp dst-port=${tcp.join(',')}`
  const comment = `Vedette ${cve}: restrict ${ip}`
  const mt = [
    `/ip firewall filter add chain=forward action=accept dst-address=${ip} src-address-list=vedette-admin${spec} comment="${comment}"`,
    `/ip firewall filter add chain=forward action=drop dst-address=${ip}${all ? ' connection-state=new' : spec} comment="${comment}"`,
  ]
  const entry = (addr: string, what: string) => `    :if ([:len [/ip firewall address-list find list=vedette-admin address="${addr}"]] = 0) do={ /ip firewall address-list add list=vedette-admin address=${addr} comment="${what}" }\n`
  const mikrotik = `{\n${entry(NET, 'Vedette admin network')}${entry(BOX, 'Vedette box')}    :if ([:len [/ip firewall address-list find list=vedette-admin]] = 0) do={ :error "The vedette-admin list is empty: nothing was added." }\n    :local rules [/ip firewall filter find where dynamic=no]\n    :if ([:len $rules] > 0) do={\n${mt.map((r) => `        ${r} place-before=[:pick $rules 0]\n`).join('')}    } else={\n${mt.map((r) => `        ${r}\n`).join('')}    }\n}`
  const table = `vedette_${slug.replaceAll('-', '_')}`
  const drop = all ? `ip daddr ${ip} ct state new drop` : `ip daddr ${ip} tcp dport { ${tcp.join(', ')} } ct state new drop`
  const nft = `sudo nft -f - <<'EOF'\ntable inet ${table} {\n    chain prerouting {\n        type filter hook prerouting priority -150; policy accept;\n        iifname "lo" accept\n        ip daddr ${ip} ip saddr { ${NET}, ${BOX} } accept\n        ${drop}\n    }\n}\nEOF`
  return [
    { vendor: 'fortigate', label: 'FortiGate', detected: has('fortinet'), intro,
      steps: [
        { title: 'FortiGate CLI: allow the admin network to the device\'s ports, deny everyone else', code: fortigate, side_effect: side, note: 'Paste it in the CLI console (the >_ icon at the top of the FortiGate page) or over SSH. FortiGate adds both policies at the bottom of the list.' },
        { title: 'Move both policies to the top, allow first', code: `show firewall policy | grep -f vedette-${slug}\nconfig firewall policy\n    move <ALLOW-ID> before <FIRST-ID>\n    move <DENY-ID> after <ALLOW-ID>\nend`, note: 'Until they are above your other policies they do nothing.' },
      ],
      verify: [{ title: 'Show the policies', code: `show firewall policy | grep -f vedette-${slug}` }],
      undo: [{ title: 'Remove the policies and their objects', code: `config firewall policy\n    delete <ALLOW-ID>\n    delete <DENY-ID>\nend` }] },
    { vendor: 'mikrotik', label: 'MikroTik', detected: has('mikrotik'), intro,
      steps: [{ title: 'RouterOS terminal: allow the admin network, drop everyone else', side_effect: side, code: mikrotik }],
      verify: [{ title: 'Show the rules and their counters', code: `/ip firewall filter print stats where comment="${comment}"` }],
      undo: [{ title: 'Remove the rules', code: `/ip firewall filter remove [find comment="${comment}"]` }] },
    { vendor: 'generic', label: 'Linux (nftables)', detected: false, intro: `${intro} The same config works on a Linux firewall or router and on the device itself when it runs Linux, including services it publishes from Docker or Podman.`,
      steps: [{ title: 'nftables: allow the admin network, drop new connections from everyone else', side_effect: side, code: nft }],
      verify: [{ title: 'Show the table', code: `sudo nft list table inet ${table}` }],
      undo: [{ title: 'Remove the table', code: `sudo nft delete table inet ${table}` }] },
  ]
}

/** The product name that alone says a vendor's family, like the box's familyProduct. */
const FAMILY_PRODUCT: Record<string, string> = { 'Juniper Junos OS': 'Junos', 'Fortinet FortiOS': 'FortiOS', 'MikroTik RouterOS': 'RouterOS', 'Cisco IOS': 'IOS' }

/** GeneralHardening of a sample finding without a confirmed pack (pack and compromise null), like the box's generalHardening. */
export function mockHardening(cve: string, kev: KevInfo | null, view: FindingAsset | null, asset: Asset | undefined, has: (vendor: string) => boolean): GeneralHardening {
  const fam = familyOf(kev, view?.kind ?? '')
  const software = kev?.display || (kev ? `${kev.vendor} ${kev.product}` : 'the software')
  const ip = view && /^\d{1,3}(\.\d{1,3}){3}$/.test(view.ip) ? view.ip : '<IP>'
  const ports: Port[] = fam.port ? (asset?.services ?? []).filter(fam.port).map((s) => ({ port: s.port, proto: s.proto, service: s.name })) : []
  const checks: CompromiseCheck = {
    summary: `General checks for ${fam.label === 'General' || [fam.label, FAMILY_PRODUCT[fam.label]].some((x) => x && software.toLowerCase().includes(x.toLowerCase())) ? software : `${software} (${fam.label})`}: signs any intruder tends to leave. They are not specific to ${cve}: the vendor advisory and the exploited-list entry (links in What to do) name the files, accounts and addresses seen for this CVE.`,
    indicators: [...fam.checks, OUTBOUND], if_found: IF_FOUND,
  }
  return { software, family: fam.label, target: ip, self: false, ports_from: ports.length ? 'seen' : 'all', ports, admin_example: '192.168.1.0/24', box: [BOX], viewer: mockViewer.get(),
    firewall: guides(cve, ip, ports, has), checks }
}
