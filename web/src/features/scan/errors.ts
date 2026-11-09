import { ApiError } from '@/lib/api'

export const errMsg = (e: unknown) => (e instanceof ApiError ? e.message : e instanceof Error ? e.message : String(e))
