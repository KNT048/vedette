// Mock of the box's general hardening (modules/mitigation/hardening.go, INV-8): the general "Have I been hit?" checks of the sample
// finding's family, so `make dev` shows the block. The box's Go code is the reference; this is sample data. No firewall config.
import type { CompromiseCheck, FindingAsset, GeneralHardening, Indicator, KevInfo } from './types'

interface Family { label: string; checks: Indicator[] }

const LINUX: Indicator[] = [
  { kind: 'log', title: 'Sign-ins', detail: 'Sign-ins at odd hours or from addresses you do not know. The log is /var/log/auth.log (Debian, Ubuntu) or /var/log/secure (Red Hat family), or the journal.', commands: [{ label: 'Last sign-ins', code: 'sudo last -a -n 50' }] },
  { kind: 'process', title: 'Listening programs and programs run from temporary folders', detail: 'Ports you cannot explain, and programs running from /tmp, /var/tmp or /dev/shm.', commands: [{ label: 'Listening ports and their programs', code: 'sudo ss -tulpn' }] },
]
const FAMILIES: Record<string, Family> = {
  windows: { label: 'Windows', checks: [
    { kind: 'log', title: 'New or changed accounts', detail: 'Security log events 4720, 4722, 4724, 4728, 4732 and 4756 that nobody in your team did, and members of Administrators you do not know.',
      commands: [{ label: 'PowerShell: members of Administrators', code: 'Get-LocalGroupMember -Group Administrators' }] },
    { kind: 'process', title: 'New services, scheduled tasks and listening programs', detail: 'Services installed recently (System log event 7045), scheduled tasks outside Microsoft\'s folder, and programs listening on ports you cannot explain.' },
  ] },
  web: { label: 'Web server', checks: [
    { kind: 'web', title: 'New script files in the web folders', detail: 'Web shells are small .php, .jsp or .jspx files dropped where the web server serves files.',
      commands: [{ label: 'Script files changed in the last 30 days', code: "sudo find /var/www /srv -type f \\( -name '*.php' -o -name '*.jsp' \\) -mtime -30 -ls 2>/dev/null" }] },
    ...LINUX,
  ] },
  linux: { label: 'Linux', checks: LINUX },
  netdevice: { label: 'Network device', checks: [
    { kind: 'file', title: 'Admin accounts', detail: "In the device's admin pages: administrators and VPN users nobody in your team created." },
    { kind: 'log', title: 'Admin sign-ins and configuration changes', detail: "In the device's system log: sign-ins from addresses you do not know. Compare the running configuration with your last backup." },
  ] },
  general: { label: 'General', checks: [
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

/** The product name that alone says a vendor's family, like the box's familyProduct. */
const FAMILY_PRODUCT: Record<string, string> = { 'Juniper Junos OS': 'Junos', 'Fortinet FortiOS': 'FortiOS', 'MikroTik RouterOS': 'RouterOS', 'Cisco IOS': 'IOS' }

/** GeneralHardening of a sample finding without its own compromise signs, like the box's generalHardening. */
export function mockHardening(cve: string, kev: KevInfo | null, view: FindingAsset | null): GeneralHardening {
  const fam = familyOf(kev, view?.kind ?? '')
  const software = kev?.display || (kev ? `${kev.vendor} ${kev.product}` : 'the software')
  const checks: CompromiseCheck = {
    summary: `General checks for ${fam.label === 'General' || [fam.label, FAMILY_PRODUCT[fam.label]].some((x) => x && software.toLowerCase().includes(x.toLowerCase())) ? software : `${software} (${fam.label})`}: signs any intruder tends to leave. They are not specific to ${cve}: the vendor advisory and the exploited-list entry (links in What to do) name the files, accounts and addresses seen for this CVE.`,
    indicators: [...fam.checks, OUTBOUND], if_found: IF_FOUND,
  }
  return { software, family: fam.label, checks }
}
