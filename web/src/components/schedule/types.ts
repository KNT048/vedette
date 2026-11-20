// The schedule types, inferred from the core contract (one model for every schedule a person can set).
import type { z } from 'zod'
import type * as C from '@/features/core/contract'

export type Schedule = z.infer<typeof C.Schedule>
export type ScheduleRule = z.infer<typeof C.ScheduleRule>
export type ScheduleLimits = z.infer<typeof C.ScheduleLimits>
export type ScheduleSave = z.infer<typeof C.ScheduleSave>
export type SchedulePreview = z.infer<typeof C.SchedulePreview>
export type Freq = ScheduleRule['freq']
export type WindowMode = ScheduleRule['window']
