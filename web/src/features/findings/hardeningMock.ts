// Mock of the box's general hardening (modules/mitigation/hardening.go, INV-8, M2-1) so `make dev` shows the block: the same shape and
// the same kind of configs, written from the sample device's IP and open ports. The box's Go code is the reference; this is sample data.
import type { Asset } from '@/lib/types'
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
  web: { label: 'Web server on Linux', port: web, checks: [
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

function guides(ip: string, ports: Port[], software: string, has: (v: string) => boolean): FirewallGuide[] {
  const tcp = ports.filter((p) => p.proto === 'tcp').map((p) => p.port)
  const all = tcp.length === 0
  const slug = ip.replaceAll('.', '-')
  const intro = all
    ? `Vedette has not seen which port ${software} answers on at ${ip}, so this config blocks every new connection to the device except from your admin network. A firewall only filters what passes through it: computers in the same network segment as the device still reach it directly.`
    : `Vedette saw ${software} answer on ${ports.map((p) => `${p.port}/${p.proto}${p.service ? ` (${p.service})` : ''}`).join(', ')} of ${ip}. This config lets only your admin network reach those ports; the rest of the device is unchanged. A firewall only filters what passes through it: computers in the same network segment as the device still reach it directly.`
  const side = all
    ? 'Everything else the device serves (shared folders, web pages, printing, remote desktop) stops for computers outside the admin network that reach it through this firewall.'
    : 'Computers outside the admin network can no longer reach these ports of the device through this firewall.'
  const svc = all ? '"ALL"' : `"vedette-ports-${slug}"`
  const fortigate = [
    `config firewall address\n    edit "vedette-admin-net"\n        set subnet ${NET}\n    next\n    edit "vedette-host-${slug}"\n        set subnet ${ip}/32\n    next\nend`,
    all ? '' : `config firewall service custom\n    edit "vedette-ports-${slug}"\n        set tcp-portrange ${tcp.join(' ')}\n    next\nend`,
    `config firewall policy\n    edit 0\n        set name "vedette-restrict-${slug}"\n        set srcintf "any"\n        set dstintf "any"\n        set srcaddr "vedette-admin-net"\n        set srcaddr-negate enable\n        set dstaddr "vedette-host-${slug}"\n        set action deny\n        set service ${svc}\n        set schedule "always"\n        set logtraffic all\n    next\nend`,
  ].filter(Boolean).join('\n')
  const match = all ? 'connection-state=new' : `protocol=tcp dst-port=${tcp.join(',')}`
  const rule = all ? 'ct state new drop' : `tcp dport { ${tcp.join(', ')} } drop`
  const table = `vedette_${ip.replaceAll('.', '_')}`
  const chain = (name: string) => `    chain ${name} {\n        type filter hook ${name} priority 0; policy accept;\n${all && name === 'input' ? '        iifname "lo" accept\n' : ''}        ip daddr ${ip} ip saddr != ${NET} ${rule}\n    }\n`
  return [
    { vendor: 'fortigate', label: 'FortiGate', detected: has('fortinet'), intro,
      steps: [
        { title: 'FortiGate CLI: deny the device\'s ports to everyone but the admin network', code: fortigate, side_effect: side, note: 'Paste it in the CLI console (the >_ icon at the top of the FortiGate page) or over SSH. FortiGate adds the policy at the bottom of the list.' },
        { title: 'Move the policy to the top', code: `show firewall policy | grep -f vedette-host-${slug}\nconfig firewall policy\n    move <ID> before <FIRST-ID>\nend`, note: 'The show command prints the policy with its ID. Until it is above your allow policies it does nothing.' },
      ],
      verify: [{ title: 'Show the policy', code: `show firewall policy | grep -f vedette-host-${slug}` }],
      undo: [{ title: 'Remove the policy and its objects', code: `config firewall policy\n    delete <ID>\nend` }] },
    { vendor: 'mikrotik', label: 'MikroTik', detected: has('mikrotik'), intro,
      steps: [{ title: 'RouterOS terminal: drop the ports for everyone but the admin network', side_effect: side,
        code: `/ip firewall address-list add list=vedette-admin address=${NET} comment="Vedette admin network"\n/ip firewall filter add chain=forward action=drop dst-address=${ip} src-address-list=!vedette-admin ${match} place-before=0 comment="Vedette: restrict ${ip}"` }],
      verify: [{ title: 'Show the rules and their counters', code: `/ip firewall filter print stats where comment="Vedette: restrict ${ip}"` }],
      undo: [{ title: 'Remove the rules', code: `/ip firewall filter remove [find comment="Vedette: restrict ${ip}"]` }] },
    { vendor: 'generic', label: 'Linux (nftables)', detected: false, intro: `${intro} The same config works on a Linux firewall or router and on the device itself when it runs Linux.`,
      steps: [{ title: 'nftables: drop the ports for everyone but the admin network', side_effect: side, code: `sudo nft -f - <<'EOF'\ntable inet ${table} {\n${chain('forward')}${chain('input')}}\nEOF` }],
      verify: [{ title: 'Show the table', code: `sudo nft list table inet ${table}` }],
      undo: [{ title: 'Remove the table', code: `sudo nft delete table inet ${table}` }] },
  ]
}

/** GeneralHardening of a sample finding without a confirmed pack (pack and compromise null), like the box's generalHardening. */
export function mockHardening(cve: string, kev: KevInfo | null, view: FindingAsset | null, asset: Asset | undefined, has: (vendor: string) => boolean): GeneralHardening {
  const fam = familyOf(kev, view?.kind ?? '')
  const software = kev?.display || (kev ? `${kev.vendor} ${kev.product}` : 'the software')
  const ip = view && /^\d{1,3}(\.\d{1,3}){3}$/.test(view.ip) ? view.ip : '<IP>'
  const ports: Port[] = fam.port ? (asset?.services ?? []).filter(fam.port).map((s) => ({ port: s.port, proto: s.proto, service: s.name })) : []
  const checks: CompromiseCheck = {
    summary: `General checks for ${software} (${fam.label}): signs any intruder tends to leave. They are not specific to ${cve}: the vendor advisory and the exploited-list entry (links in What to do) name the files, accounts and addresses seen for this CVE.`,
    indicators: [...fam.checks, OUTBOUND], if_found: IF_FOUND,
  }
  return { software, family: fam.label, target: ip, self: false, ports_from: ports.length ? 'seen' : 'all', ports, admin_example: '192.168.1.0/24',
    firewall: guides(ip, ports, software, has), checks }
}
