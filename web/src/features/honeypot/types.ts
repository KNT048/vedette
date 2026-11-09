// API types of module honeypot — inferred from the Zod contract (contract.ts), not hand-written.
import type { z } from 'zod'
import type * as C from './contract'

export type HpService = z.infer<typeof C.HpService>
export const HP_SERVICES: HpService[] = ['smb', 'rdp', 'ssh', 'mssql', 'http']

/** off; listening; conflict = on but the secondary IP clashes with a device in the inventory. */
export type Trap = z.infer<typeof C.Trap>
export type TrapState = Trap['state']
export type HpOverview = z.infer<typeof C.HpOverview>
export type Hit = z.infer<typeof C.Hit>
export type HitEvent = z.infer<typeof C.HitEvent>
export type HitDetail = z.infer<typeof C.HitDetail>
export type HitKind = z.infer<typeof C.HitKind>
export type Personality = z.infer<typeof C.Personality>
export type Decoy = z.infer<typeof C.Decoy>
export type DecoySuggestion = z.infer<typeof C.DecoySuggestion>
export type DecoysResponse = z.infer<typeof C.DecoysResponse>
export type DecoyInput = z.infer<typeof C.DecoyInput>
export type TokenType = z.infer<typeof C.TokenType>
export const TOKEN_TYPES: TokenType[] = ['file', 'credential', 'url', 'dns']
export type Token = z.infer<typeof C.Token>
export type TokenInput = z.infer<typeof C.TokenInput>
