// Types of Settings › Scanning, from the contract (contract.ts, AI-Trưởng's #857, D-627).
import type { z } from 'zod'
import type * as C from './contract'

export type EngineId = z.infer<typeof C.EngineId>
export type Engine = z.infer<typeof C.Engine>
export type RunningJob = z.infer<typeof C.RunningJob>
export type Safety = z.infer<typeof C.Safety>
export type SafetyInput = z.infer<typeof C.SafetyInput>
export type SafetySaved = z.infer<typeof C.SafetySaved>
export type Scanning = z.infer<typeof C.Scanning>
export type HistoryRun = z.infer<typeof C.HistoryRun>
