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
export type AppliedEntry = z.infer<typeof C.AppliedEntry>
export type FindingDetail = z.infer<typeof C.FindingDetail>
export type KnownVersion = z.infer<typeof C.KnownVersion>
export type StatusAction = z.infer<typeof C.StatusAction>
export type BulkAction = z.infer<typeof C.BulkAction>
export type ApplyItem = z.infer<typeof C.ApplyItem>
/** Updates to plan: tier 2 and 3 CVEs grouped by the update that fixes them. */
export type Plan = z.infer<typeof C.Plan>
export type PlanItem = z.infer<typeof C.PlanItem>
export type ToFix = z.infer<typeof C.ToFix>
export type ToFixDevice = z.infer<typeof C.ToFixDevice>
export type ToFixAction = z.infer<typeof C.ToFixAction>
export type PlanCve = z.infer<typeof C.PlanCve>
export type PlanFilter = z.infer<typeof C.PlanFilter>
/** #825: Home's one read: open findings, the few to fix first, the 30-day trend, device and alert counts. */
export type HomeSummary = z.infer<typeof C.HomeSummary>
export type SummaryItem = z.infer<typeof C.SummaryItem>
