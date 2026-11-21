// Types of Settings › Scanning, from the contract (contract.ts, #857).
import type { z } from 'zod'
import type * as C from './contract'

export type EngineId = z.infer<typeof C.EngineId>
export type Engine = z.infer<typeof C.Engine>
export type RunningJob = z.infer<typeof C.RunningJob>
export type Safety = z.infer<typeof C.Safety>
export type SafetyInput = z.infer<typeof C.SafetyInput>
export type SafetySaved = z.infer<typeof C.SafetySaved>
export type ScopeCost = z.infer<typeof C.ScopeCost>
export type ScopeCostInput = z.infer<typeof C.ScopeCostInput>
export type Scanning = z.infer<typeof C.Scanning>
export type HistoryRun = z.infer<typeof C.HistoryRun>
export type Run = z.infer<typeof C.Run>
export type RunDetail = z.infer<typeof C.RunDetail>
export type RunList = z.infer<typeof C.RunList>
export type RunStatus = z.infer<typeof C.RunStatus>
