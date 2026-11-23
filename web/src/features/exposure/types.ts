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
export type Appliance = z.infer<typeof C.Appliance>
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
export type QueuedScan = z.infer<typeof C.QueuedScan>
export type OutsideView = z.infer<typeof C.OutsideView>
export type Greenbone = z.infer<typeof C.Greenbone>
export type Terms = z.infer<typeof C.Terms>
export type GreenboneResult = z.infer<typeof C.GreenboneResult>
export type GreenboneRun = z.infer<typeof C.GreenboneRun>

// Target tree: nodes, their rows and their runs.
export type ScopeMode = z.infer<typeof C.ScopeMode>
export type NodeOrigin = z.infer<typeof C.NodeOrigin>
export type TargetRef = z.infer<typeof C.TargetRef>
export type ProofState = z.infer<typeof C.ProofState>
export type ProofCheck = z.infer<typeof C.ProofCheck>
export type Proof = z.infer<typeof C.Proof>
export type DnsProof = z.infer<typeof C.DnsProof>
export type FileProof = z.infer<typeof C.FileProof>
export type Consent = z.infer<typeof C.Consent>
export type RunStatus = z.infer<typeof C.RunStatus>
export type RunTrigger = z.infer<typeof C.RunTrigger>
export type ScanMode = z.infer<typeof C.ScanMode>
export type ScanCounts = z.infer<typeof C.ScanCounts>
export type Scan = z.infer<typeof C.Scan>
export type Severity = z.infer<typeof C.Severity>
export type NodeBlock = z.infer<typeof C.NodeBlock>
export type TargetNode = z.infer<typeof C.TargetNode>
export type TargetTree = z.infer<typeof C.TargetTree>
export type HostSource = z.infer<typeof C.HostSource>
export type Host = z.infer<typeof C.Host>
export type Address = z.infer<typeof C.Address>
export type ServiceIdent = z.infer<typeof C.ServiceIdent>
export type Service = z.infer<typeof C.Service>
export type IssueEngine = z.infer<typeof C.IssueEngine>
export type IssueState = z.infer<typeof C.IssueState>
export type Resolution = z.infer<typeof C.Resolution>
export type Issue = z.infer<typeof C.Issue>
export type IssueCve = z.infer<typeof C.IssueCve>
export type CveSeverity = z.infer<typeof C.CveSeverity>
