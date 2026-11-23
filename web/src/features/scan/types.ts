// API types of the scan module, derived from the Zod contract (contract.ts), not declared by hand.
import type { z } from 'zod'
import type * as C from './contract'

export type ScanTarget = z.infer<typeof C.ScanTarget>
export type ScanScope = z.infer<typeof C.ScanScope>
/** window.days: 1 = Monday ... 7 = Sunday; rate = requests per second. */
export type ScanConfig = z.infer<typeof C.ScanConfig>
export type ScanConfigResponse = z.infer<typeof C.ScanConfigResponse>
export type RunStatus = z.infer<typeof C.RunStatus>
export type RunResultKind = z.infer<typeof C.RunResultKind>
export type RunResultRow = z.infer<typeof C.RunResultRow>
export type ScanRun = z.infer<typeof C.ScanRun>
export type RunIdentRow = z.infer<typeof C.RunIdentRow>
export type IdentReason = z.infer<typeof C.IdentReason>
export type ProbeEntry = z.infer<typeof C.ProbeEntry>
export type RescanEvent = z.infer<typeof C.RescanEvent>
export type CredTarget = z.infer<typeof C.CredTarget>
