// Kiểu API module reports — suy ra từ hợp đồng Zod (contract.ts), không khai tay.
import type { z } from 'zod'
import type * as C from './contract'

export type FindingRow = z.infer<typeof C.FindingRow>
export type TopRisk = z.infer<typeof C.TopRisk>
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

export type OpenStatus = z.infer<typeof C.OpenStatus>
export type HandledStatus = z.infer<typeof C.HandledStatus>
export type FindingStatus = z.infer<typeof C.FindingStatus>
export type CveSeverity = z.infer<typeof C.CveSeverity>
export type Reason = z.infer<typeof C.Reason>
export type Handled = z.infer<typeof C.Handled>
export type DeviceRef = z.infer<typeof C.DeviceRef>
export type ReportFinding = z.infer<typeof C.ReportFinding>
export type HandledItem = z.infer<typeof C.HandledItem>
export type PeriodKind = z.infer<typeof C.PeriodKind>
export type ReportOptions = z.infer<typeof C.ReportOptions>
export type ReportDefinition = z.infer<typeof C.ReportDefinition>
export type ReportDefinitionInput = z.infer<typeof C.ReportDefinitionInput>
export type ReportDocument = z.infer<typeof C.ReportDocument>
export type ExposureTarget = z.infer<typeof C.ExposureTarget>
export type SentReportItem = z.infer<typeof C.SentReportItem>
export type SentReport = z.infer<typeof C.SentReport>
export type Fix = z.infer<typeof C.Fix>
export type Verification = z.infer<typeof C.Verification>
export type ReportSummary = z.infer<typeof C.ReportSummary>
export type ReportHandled = z.infer<typeof C.ReportHandled>
export type ReportOpen = z.infer<typeof C.ReportOpen>
export type ReportNew = z.infer<typeof C.ReportNew>
export type ReportExposure = z.infer<typeof C.ReportExposure>
export type ExposureService = z.infer<typeof C.ExposureService>
export type ReportDetections = z.infer<typeof C.ReportDetections>
export type ReportCoverage = z.infer<typeof C.ReportCoverage>
export type DetectionKind = z.infer<typeof C.DetectionKind>
export type ProofState = z.infer<typeof C.ProofState>
