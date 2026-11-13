// Kiểu API module findings — suy ra từ hợp đồng Zod (contract.ts), không khai tay.
import type { z } from 'zod'
import type * as C from './contract'

export type KevInfo = z.infer<typeof C.KevInfo>
export type FindingAsset = z.infer<typeof C.FindingAsset>
/** Phát hiện + thiết bị + thông tin KEV (đọc từ KEV thật, không phải từ gói khuyến nghị của dự án). */
export type FindingRow = z.infer<typeof C.FindingRow>
/** D-500: a software without a usable version: one item, not one finding per CVE. */
export type VersionNeeded = z.infer<typeof C.VersionNeeded>
export type CodeStep = z.infer<typeof C.CodeStep>
export type FirewallVendor = z.infer<typeof C.FirewallVendor>
export type FirewallGuide = z.infer<typeof C.FirewallGuide>
/** Gói giảm thiểu đã xác nhận (DATA_PIPELINE §5b). Chỉ gói status=confirmed mới tới được hộp. */
export type MitigationPack = z.infer<typeof C.MitigationPack>
export type Indicator = z.infer<typeof C.Indicator>
export type CompromiseCheck = z.infer<typeof C.CompromiseCheck>
export type AiResult = z.infer<typeof C.AiResult>
export type AppliedEntry = z.infer<typeof C.AppliedEntry>
export type FindingDetail = z.infer<typeof C.FindingDetail>
export type StatusAction = z.infer<typeof C.StatusAction>
export type BulkAction = z.infer<typeof C.BulkAction>
export type ApplyItem = z.infer<typeof C.ApplyItem>
