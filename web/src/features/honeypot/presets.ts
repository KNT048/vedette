// Trap IP presets and vendors (D-466): data, as modules/honeypot/presets.go. A preset fills the services and the vendor of a Trap IP;
// both stay editable. Adding a service later (B3) is a row here and in presets.go, not new screens.
import type { AssetKind } from '@/lib/types'
import type { HpService, TrapPreset, TrapVendor } from './types'

export interface PresetDef { id: TrapPreset; services: HpService[]; vendor: TrapVendor | null; kinds: AssetKind[]; example: string }

export const PRESETS: PresetDef[] = [
  { id: 'file_server', services: ['smb', 'rdp'], vendor: 'dell', kinds: ['server', 'pc'], example: 'FILESRV-OLD' },
  { id: 'nas', services: ['http', 'smb'], vendor: 'synology', kinds: ['nas'], example: 'NAS-ARCHIVE' },
  { id: 'printer', services: ['http'], vendor: 'hp', kinds: ['printer'], example: 'PRN-FLOOR2' },
  { id: 'camera', services: ['http'], vendor: 'hikvision', kinds: ['camera', 'nvr'], example: 'CAM-STORE-04' },
  { id: 'linux', services: ['ssh'], vendor: 'vmware', kinds: ['server'], example: 'BUILD-SRV-02' },
  { id: 'database', services: ['mssql'], vendor: 'dell', kinds: ['server'], example: 'SQL-OLD-01' },
  { id: 'custom', services: [], vendor: null, kinds: [], example: 'TRAP-01' },
]
export const presetDef = (id: TrapPreset) => PRESETS.find((p) => p.id === id)!

/** The MAC prefix each vendor gives a Trap IP (IEEE OUI; modules/honeypot checks each against the D-83 table). */
export const VENDORS: { id: TrapVendor; oui: string }[] = [
  { id: 'dell', oui: 'F8:BC:12' }, { id: 'hp', oui: '3C:D9:2B' }, { id: 'vmware', oui: '00:50:56' }, { id: 'hyperv', oui: '00:15:5D' },
  { id: 'supermicro', oui: '0C:C4:7A' }, { id: 'synology', oui: '00:11:32' }, { id: 'qnap', oui: '24:5E:BE' }, { id: 'brother', oui: '30:05:5C' },
  { id: 'canon', oui: '00:1E:8F' }, { id: 'hikvision', oui: '44:19:B6' }, { id: 'dahua', oui: '3C:EF:8C' }, { id: 'axis', oui: 'AC:CC:8E' },
]

export const SERVICE_PORT: Record<HpService, number> = { smb: 445, rdp: 3389, ssh: 22, mssql: 1433, http: 80 }
