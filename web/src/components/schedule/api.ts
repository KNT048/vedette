// The shared schedules API (core/schedule): read, save, run once and the preview of the next start times.
import { useEffect, useState } from 'react'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { Schedule, SchedulePreview, ScheduleRule, ScheduleSave } from './types'

// owner keys are [a-z0-9._-] with one ":" before a subject id: all safe in a path, so the ":" stays as it is
const path = (key: string) => `/schedules/${encodeURIComponent(key).replace(/%3A/gi, ':')}`
export const scheduleQueryKey = (key: string) => ['schedules', key] as const

export const useSchedule = (key: string, enabled = true) => useQuery({ queryKey: scheduleQueryKey(key), queryFn: () => api.get<Schedule>(path(key)), enabled })

export function useSaveSchedule(key: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: ScheduleSave) => api.put<Schedule>(path(key), body),
    onSuccess: (s) => qc.setQueryData(scheduleQueryKey(key), s),
  })
}

export function useRunSchedule(key: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => api.post<{ run_id: string | null }>(`${path(key)}/run`),
    onSuccess: () => void qc.invalidateQueries({ queryKey: scheduleQueryKey(key) }),
  })
}

/** The next three start times of a rule as if it were saved now, asked again 300 ms after the form stops changing. */
export function useSchedulePreview(body: { owner_key: string; rule: ScheduleRule; paused_until: string | null }, enabled: boolean) {
  const json = JSON.stringify(body)
  const [settled, setSettled] = useState(json)
  useEffect(() => {
    const id = setTimeout(() => setSettled(json), 300)
    return () => clearTimeout(id)
  }, [json])
  return useQuery({
    queryKey: ['schedules', 'preview', settled],
    queryFn: () => api.post<SchedulePreview>('/schedules/preview', JSON.parse(settled) as unknown),
    enabled,
    retry: false,
    placeholderData: keepPreviousData,
  })
}
