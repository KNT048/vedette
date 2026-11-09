// Decoy personalities (S-HP-2, D-50): what the fake machine looks like to a scanner. Ports follow what the real device type opens.
import type { AssetKind } from '@/lib/types'
import type { Personality } from './types'

export interface PersonalityDef { id: Personality; services: { name: string; port: number }[]; kinds: AssetKind[]; namePlaceholder: string }

export const PERSONALITIES: PersonalityDef[] = [
  { id: 'windows_fs', services: [{ name: 'SMB', port: 445 }, { name: 'RDP', port: 3389 }], kinds: ['server', 'pc'], namePlaceholder: 'FILESRV-OLD' },
  { id: 'nas', services: [{ name: 'HTTP login page', port: 80 }, { name: 'SMB', port: 445 }], kinds: ['nas'], namePlaceholder: 'NAS-ARCHIVE' },
  { id: 'printer', services: [{ name: 'HTTP', port: 80 }, { name: 'Raw print', port: 9100 }], kinds: ['printer'], namePlaceholder: 'PRN-FLOOR2' },
  { id: 'camera', services: [{ name: 'HTTP', port: 80 }, { name: 'RTSP', port: 554 }], kinds: ['camera', 'nvr'], namePlaceholder: 'CAM-STORE-04' },
  { id: 'linux', services: [{ name: 'SSH', port: 22 }], kinds: ['server'], namePlaceholder: 'BUILD-SRV-02' },
]
export const personalityDef = (id: Personality) => PERSONALITIES.find((p) => p.id === id)!
