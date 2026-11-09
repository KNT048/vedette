// Kiểu API module reports — suy ra từ hợp đồng Zod (contract.ts), không khai tay.
import type { z } from 'zod'
import type * as C from './contract'

export type FindingRow = z.infer<typeof C.FindingRow>
export type ActionItem = z.infer<typeof C.ActionItem>
export type AiSummary = z.infer<typeof C.AiSummary>
export type WeeklyReport = z.infer<typeof C.WeeklyReport>
export type WeeklyPreview = z.infer<typeof C.WeeklyPreview>
export type Weekday = z.infer<typeof C.Weekday>
export type Schedule = z.infer<typeof C.Schedule>
export type HistoryEntry = z.infer<typeof C.HistoryEntry>
export type DataVolume = z.infer<typeof C.DataVolume>
export type OrgSize = z.infer<typeof C.OrgSize>
export type PdplOrg = z.infer<typeof C.PdplOrg>
export type Measure = z.infer<typeof C.Measure>
export type Obligation = z.infer<typeof C.Obligation>
export type PdplReport = z.infer<typeof C.PdplReport>
export type PdplState = z.infer<typeof C.PdplState>
