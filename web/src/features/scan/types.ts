// Kiểu API module scan — suy ra từ hợp đồng Zod (contract.ts), không khai tay.
import type { z } from 'zod'
import type * as C from './contract'

export type ScanTarget = z.infer<typeof C.ScanTarget>
export type ScanScope = z.infer<typeof C.ScanScope>
/** window.days: 1 = Thứ Hai … 7 = Chủ nhật (D-57); rate = yêu cầu mỗi giây. */
export type ScanConfig = z.infer<typeof C.ScanConfig>
export type ScanConfigResponse = z.infer<typeof C.ScanConfigResponse>
export type RunStatus = z.infer<typeof C.RunStatus>
export type RunResultKind = z.infer<typeof C.RunResultKind>
export type RunResultRow = z.infer<typeof C.RunResultRow>
export type ScanRun = z.infer<typeof C.ScanRun>
export type ProbeEntry = z.infer<typeof C.ProbeEntry>
export type RescanEvent = z.infer<typeof C.RescanEvent>
export type CredTarget = z.infer<typeof C.CredTarget>
