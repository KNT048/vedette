// API types of module exposure — inferred from the Zod contract (contract.ts), not hand-written.
import type { z } from 'zod'
import type * as C from './contract'

export const CERT_WARN_DAYS = 30

export type TargetKind = z.infer<typeof C.TargetKind>
export type VerifyMethod = z.infer<typeof C.VerifyMethod>
export type Counts = z.infer<typeof C.Counts>
export type Commitment = z.infer<typeof C.Commitment>
export type Target = z.infer<typeof C.Target>
export type Gateway = z.infer<typeof C.Gateway>
export type HostRow = z.infer<typeof C.HostRow>
export type HostIp = z.infer<typeof C.HostIp>
export type HostClass = z.infer<typeof C.HostClass>
export type PortRow = z.infer<typeof C.PortRow>
export type AdminRow = z.infer<typeof C.AdminRow>
export type CertRow = z.infer<typeof C.CertRow>
export type ServiceRow = z.infer<typeof C.ServiceRow>
export type CheckRow = z.infer<typeof C.CheckRow>
export type NotCheckedRow = z.infer<typeof C.NotCheckedRow>
export type WebFinding = z.infer<typeof C.WebFinding>
export type VulnRow = z.infer<typeof C.VulnRow>
export type GapRow = z.infer<typeof C.GapRow>
export type TemplateRow = z.infer<typeof C.TemplateRow>
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
export type IgnoredIp = z.infer<typeof C.IgnoredIp>
export type ScanRun = z.infer<typeof C.ScanRun>
export type OutsideView = z.infer<typeof C.OutsideView>
export type Greenbone = z.infer<typeof C.Greenbone>
export type Terms = z.infer<typeof C.Terms>
export type GreenboneResult = z.infer<typeof C.GreenboneResult>

/** The label key of a blocked target: a commitment of an older sentence reads as asked again, not as a missing first scan (D-559). */
export function blockedKey(t: Pick<Target, 'blocked_reason' | 'commitment'>): string {
  return t.blocked_reason === 'no_commitment' && t.commitment ? 'no_commitment_again' : (t.blocked_reason ?? '')
}
