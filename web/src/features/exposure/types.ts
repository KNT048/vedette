// API types of module exposure — inferred from the Zod contract (contract.ts), not hand-written.
import type { z } from 'zod'
import type * as C from './contract'

export const CERT_WARN_DAYS = 30

export type TargetKind = z.infer<typeof C.TargetKind>
export type VerifyMethod = z.infer<typeof C.VerifyMethod>
export type Counts = z.infer<typeof C.Counts>
export type Commitment = z.infer<typeof C.Commitment>
export type Target = z.infer<typeof C.Target>
export type HostRow = z.infer<typeof C.HostRow>
export type PortRow = z.infer<typeof C.PortRow>
export type AdminRow = z.infer<typeof C.AdminRow>
export type CertRow = z.infer<typeof C.CertRow>
export type Snapshot = z.infer<typeof C.Snapshot>
export type SnapshotMeta = z.infer<typeof C.SnapshotMeta>
export type DiffKind = z.infer<typeof C.DiffKind>
export type DiffItem = z.infer<typeof C.DiffItem>
export type DiffChange = z.infer<typeof C.DiffChange>
export type Diff = z.infer<typeof C.Diff>
export type VerifyResult = z.infer<typeof C.VerifyResult>
export type BoxIpRun = z.infer<typeof C.BoxIpRun>
export type BoxIpSettings = z.infer<typeof C.BoxIpSettings>
export type TargetList = z.infer<typeof C.TargetList>
export type BoxIpDetectResult = z.infer<typeof C.BoxIpDetectResult>
