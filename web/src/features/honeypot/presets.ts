// Trap IP presets and vendors: data, as modules/honeypot/presets.go. A preset fills the services and the vendor of a Trap IP;
// both stay editable. Adding a service later (B3) is a row here and in presets.go, not new screens.
import type { AssetKind } from '@/lib/types'
import type { HpService, OfferedTokenType, TrapPreset, TrapVendor } from './types'

export interface PresetDef { id: TrapPreset; services: HpService[]; vendor: TrapVendor | null; kinds: AssetKind[]; example: string }

export const PRESETS: PresetDef[] = [
  { id: 'file_server', services: ['smb', 'rdp'], vendor: 'dell', kinds: ['server', 'pc'], example: 'FILESRV-OLD' },
  { id: 'nas', services: ['http', 'https', 'smb'], vendor: 'synology', kinds: ['nas'], example: 'NAS-ARCHIVE' },
  { id: 'printer', services: ['http', 'ftp'], vendor: 'hp', kinds: ['printer'], example: 'PRN-FLOOR2' },
  { id: 'camera', services: ['http'], vendor: 'hikvision', kinds: ['camera', 'nvr'], example: 'CAM-STORE-04' },
  { id: 'linux', services: ['ssh', 'ftp'], vendor: 'vmware', kinds: ['server'], example: 'BUILD-SRV-02' },
  { id: 'database', services: ['mssql', 'mysql'], vendor: 'dell', kinds: ['server'], example: 'SQL-OLD-01' },
  { id: 'custom', services: [], vendor: null, kinds: [], example: 'TRAP-01' },
]
export const presetDef = (id: TrapPreset) => PRESETS.find((p) => p.id === id)!

/** The MAC prefix each vendor gives a Trap IP (IEEE OUI; modules/honeypot checks each against the OUI table). */
export const VENDORS: { id: TrapVendor; oui: string }[] = [
  { id: 'dell', oui: 'F8:BC:12' }, { id: 'hp', oui: '3C:D9:2B' }, { id: 'vmware', oui: '00:50:56' }, { id: 'hyperv', oui: '00:15:5D' },
  { id: 'supermicro', oui: '0C:C4:7A' }, { id: 'synology', oui: '00:11:32' }, { id: 'qnap', oui: '24:5E:BE' }, { id: 'brother', oui: '30:05:5C' },
  { id: 'canon', oui: '00:1E:8F' }, { id: 'hikvision', oui: '44:19:B6' }, { id: 'dahua', oui: '3C:EF:8C' }, { id: 'axis', oui: 'AC:CC:8E' },
]

export const SERVICE_PORT: Record<HpService, number> = {
  smb: 445, rdp: 3389, ssh: 22, mssql: 1433, http: 80, https: 443, ftp: 21, telnet: 23, mysql: 3306, mongodb: 27017, redis: 6379, vnc: 5900, git: 9418,
  httpproxy: 8080, tcpbanner: 25, tftp: 69, ntp: 123, sip: 5060,
}
/** The UDP services (the rest are TCP): they answer nothing, they only log. */
export const UDP_SERVICES: HpService[] = ['tftp', 'ntp', 'sip']
/** "445" or "69/udp". */
export const portLabel = (s: HpService) => (UDP_SERVICES.includes(s) ? `${SERVICE_PORT[s]}/udp` : String(SERVICE_PORT[s]))
/** Services where a login names an account, so a fake credential fires on them (Coverage). */
export const LOGIN_SERVICES: HpService[] = ['ssh', 'rdp', 'mssql', 'http', 'https', 'ftp', 'telnet', 'mysql', 'mongodb', 'httpproxy']

// Honey token presets (S-HP-2): a believable token in one click, as Canarytokens offers ready token kinds. A preset fills the
// type, name, file type and place of the form (the place text is token.preset.<id>.plant); every field stays editable. Web only:
// the API gets the fields, never the preset. {year} becomes this year. Custom is the blank form. A credential preset's name is the
// token's label, by role: the box makes the bait account name itself (svc_ + 6 letters).
export type TokenPreset = 'payroll' | 'passwords' | 'bank_accounts' | 'customer_list' | 'network_diagram' | 'vpn_setup' | 'backup_account' | 'old_admin' | 'db_login' | 'nas_admin'
  | 'wiki' | 'router_admin' | 'backup_console' | 'custom'
export interface TokenPresetDef { id: TokenPreset; type: OfferedTokenType; name: string; ext?: 'docx' | 'xlsx' }

export const TOKEN_PRESETS: TokenPresetDef[] = [
  { id: 'payroll', type: 'file', name: 'Payroll-{year}', ext: 'xlsx' },
  { id: 'passwords', type: 'file', name: 'Passwords', ext: 'xlsx' },
  { id: 'bank_accounts', type: 'file', name: 'Bank-accounts-{year}', ext: 'xlsx' },
  { id: 'customer_list', type: 'file', name: 'Customer-list-{year}', ext: 'xlsx' },
  { id: 'network_diagram', type: 'file', name: 'Network-diagram', ext: 'docx' },
  { id: 'vpn_setup', type: 'file', name: 'VPN-setup', ext: 'docx' },
  { id: 'backup_account', type: 'credential', name: 'Backup service account' },
  { id: 'old_admin', type: 'credential', name: 'Old admin account' },
  { id: 'db_login', type: 'credential', name: 'Reporting database login' },
  { id: 'nas_admin', type: 'credential', name: 'NAS admin login' },
  { id: 'wiki', type: 'url', name: 'Wiki admin page' },
  { id: 'router_admin', type: 'url', name: 'Router admin' },
  { id: 'backup_console', type: 'url', name: 'Backup console' },
]
export const tokenPresetName = (p: TokenPresetDef) => p.name.replace('{year}', String(new Date().getFullYear()))
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
/** The token a preset made, whatever year it was made in (Payroll-2025 still counts in 2026); undefined when there is none. The box
 *  refuses a second token of a type with the same name, so type and name find it. */
export function presetToken<T extends { type: string; name: string }>(p: TokenPresetDef, items: T[]): T | undefined {
  const re = new RegExp(`^${p.name.split('{year}').map(escapeRe).join('\\d{4}')}$`, 'i')
  return items.find((k) => k.type === p.type && re.test(k.name))
}

/** The login service to add to a Trap IP of each look so fake accounts can be tried on it: what that machine would really offer. */
export const LOGIN_TO_ADD: Record<TrapPreset, HpService> = {
  file_server: 'rdp', nas: 'http', printer: 'http', camera: 'http', linux: 'ssh', database: 'mssql', custom: 'ssh',
}
/** Looks that may carry a file share: a printer or a camera with SMB would stand out. */
export const SMB_LOOKS: TrapPreset[] = ['file_server', 'nas', 'linux', 'database', 'custom']
