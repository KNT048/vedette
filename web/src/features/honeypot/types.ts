// API types of module honeypot — inferred from the Zod contract (contract.ts), not hand-written.
import type { z } from 'zod'
import type * as C from './contract'

export type HpService = z.infer<typeof C.HpService>
/** In the order of the API (modules/honeypot Services). */
export const HP_SERVICES: HpService[] = ['smb', 'rdp', 'ssh', 'mssql', 'http', 'https', 'ftp', 'telnet', 'mysql', 'mongodb', 'redis', 'vnc', 'git', 'httpproxy', 'tcpbanner', 'tftp', 'ntp', 'sip']

/** off; listening; conflict; starting; stopping; failed: what the box reports (contract.ts TrapState). */
export type Trap = z.infer<typeof C.Trap>
export type TrapState = z.infer<typeof C.TrapState>
export type HpOverview = z.infer<typeof C.HpOverview>
export type Hit = z.infer<typeof C.Hit>
export type HitEvent = z.infer<typeof C.HitEvent>
export type HitDetail = z.infer<typeof C.HitDetail>
export type HitKind = z.infer<typeof C.HitKind>
export type TrapPreset = z.infer<typeof C.TrapPreset>
export type TrapVendor = z.infer<typeof C.TrapVendor>
export type TrapIP = z.infer<typeof C.TrapIP>
export type TrapSuggestion = z.infer<typeof C.TrapSuggestion>
export type TrapIPsResponse = z.infer<typeof C.TrapIPsResponse>
export type TrapIPInput = z.infer<typeof C.TrapIPInput>
export type TokenType = z.infer<typeof C.TokenType>
export const TOKEN_TYPES: TokenType[] = ['file', 'credential', 'url', 'dns']
export type Token = z.infer<typeof C.Token>
export type TokenInput = z.infer<typeof C.TokenInput>
