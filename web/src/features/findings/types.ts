// Kiểu API module findings — suy ra từ hợp đồng Zod (contract.ts), không khai tay.
import type { z } from 'zod'
import type * as C from './contract'

export type KevInfo = z.infer<typeof C.KevInfo>
/** #825: the CVSS base score with its version and source; null on a row = no score known. */
export type Cvss = z.infer<typeof C.Cvss>
export type FindingAsset = z.infer<typeof C.FindingAsset>
/** Phát hiện + thiết bị + thông tin KEV (đọc từ KEV thật, không phải từ gói khuyến nghị của dự án). */
export type FindingRow = z.infer<typeof C.FindingRow>
/** The update that fixes several open findings of one software on one device. */
export type RowFix = z.infer<typeof C.RowFix>
/** A software without a usable version: one item, not one finding per CVE. */
export type VersionNeeded = z.infer<typeof C.VersionNeeded>
/** #910 phase 1: exploited CVEs of software the box has that it could not check. */
export type UncheckedItem = z.infer<typeof C.UncheckedItem>
export type UncheckedReason = z.infer<typeof C.UncheckedReason>
export type CodeStep = z.infer<typeof C.CodeStep>
export type FirewallVendor = z.infer<typeof C.FirewallVendor>
export type FirewallGuide = z.infer<typeof C.FirewallGuide>
/** Gói giảm thiểu đã xác nhận (DATA_PIPELINE §5b). Chỉ gói status=confirmed mới tới được hộp. */
export type MitigationPack = z.infer<typeof C.MitigationPack>
export type Indicator = z.infer<typeof C.Indicator>
export type CompromiseCheck = z.infer<typeof C.CompromiseCheck>
/** M2-1: the general compromise checks, not a recommendation for the CVE (mitigation INV-8; no firewall config). */
export type GeneralHardening = z.infer<typeof C.GeneralHardening>
export type AiResult = z.infer<typeof C.AiResult>
export type AiAnswer = z.infer<typeof C.AiAnswer>
export type AiAnswerKey = z.infer<typeof C.AiAnswerKey>
export type AppliedEntry = z.infer<typeof C.AppliedEntry>
export type FindingDetail = z.infer<typeof C.FindingDetail>
export type KnownVersion = z.infer<typeof C.KnownVersion>
export type StatusAction = z.infer<typeof C.StatusAction>
export type BulkAction = z.infer<typeof C.BulkAction>
export type ApplyItem = z.infer<typeof C.ApplyItem>
/** Updates to plan: tier 2 and 3 CVEs grouped by the update that fixes them. */
export type Plan = z.infer<typeof C.Plan>
export type PlanItem = z.infer<typeof C.PlanItem>
export type PlanDone = z.infer<typeof C.PlanDone>
export type ToFix = z.infer<typeof C.ToFix>
export type ToFixDevice = z.infer<typeof C.ToFixDevice>
export type ToFixAction = z.infer<typeof C.ToFixAction>
export type PlanCve = z.infer<typeof C.PlanCve>
export type PlanFilter = z.infer<typeof C.PlanFilter>
/** #825: Home's one read: open findings, the few to fix first, the 30-day trend, device and alert counts. */
export type HomeSummary = z.infer<typeof C.HomeSummary>
export type SummaryItem = z.infer<typeof C.SummaryItem>

// The findings model: one status per finding (contract.ts, "The findings model").
export type StatusCode = z.infer<typeof C.StatusCode>
export type OpenStatus = z.infer<typeof C.OpenStatus>
export type Resolution = z.infer<typeof C.Resolution>
export type Via = z.infer<typeof C.Via>
export type Verified = z.infer<typeof C.Verified>
export type Basis = z.infer<typeof C.Basis>
export type FixKind = z.infer<typeof C.FixKind>
export type SeverityBand = z.infer<typeof C.SeverityBand>
export type DeviceStatusCode = z.infer<typeof C.DeviceStatusCode>
export type QuestionKind = z.infer<typeof C.QuestionKind>
export type EventKind = z.infer<typeof C.EventKind>
export type DeviceRef = z.infer<typeof C.DeviceRef>
export type SoftwareRef = z.infer<typeof C.SoftwareRef>
/** The CVSS band and score of a CVE; null where used = "Not scored yet". */
export type CveSeverity = z.infer<typeof C.CveSeverity>
export type Reason = z.infer<typeof C.Reason>
export type Urgency = z.infer<typeof C.Urgency>
export type Verification = z.infer<typeof C.Verification>
export type Handled = z.infer<typeof C.Handled>
export type Reopened = z.infer<typeof C.Reopened>
export type Fix = z.infer<typeof C.Fix>
export type CveRow = z.infer<typeof C.CveRow>
export type SeverityCounts = z.infer<typeof C.SeverityCounts>
export type StatusCounts = z.infer<typeof C.StatusCounts>
/** The device badge; null when the device has nothing open and no question. */
export type DeviceStatus = z.infer<typeof C.DeviceStatus>
export type FixBlock = z.infer<typeof C.FixBlock>
export type DeviceCard = z.infer<typeof C.DeviceCard>
export type DeviceCards = z.infer<typeof C.DeviceCards>
export type FixDevice = z.infer<typeof C.FixDevice>
export type FixCard = z.infer<typeof C.FixCard>
export type FixCards = z.infer<typeof C.FixCards>
export type InputItem = z.infer<typeof C.InputItem>
export type InputList = z.infer<typeof C.InputList>
export type HandledRow = z.infer<typeof C.HandledRow>
export type HandledList = z.infer<typeof C.HandledList>
export type FindingEvent = z.infer<typeof C.FindingEvent>
/** A finding as every place shows it. */
export type View = z.infer<typeof C.View>
export type FirstItem = z.infer<typeof C.FirstItem>
/** Home at a glance. */
export type Overview = z.infer<typeof C.Overview>
