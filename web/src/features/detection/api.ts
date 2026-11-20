import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { Alert, AlertSort, AlertsResponse, AlertWindow, Overview } from './types'

export const useOverview = () => useQuery({ queryKey: ['detection', 'overview'], queryFn: () => api.get<Overview>('/detection/overview'), refetchInterval: 60_000, refetchIntervalInBackground: false })

export type AlertQuery = { window: AlertWindow; q: string; sort: AlertSort; offset: number; limit: number }
const alertsUrl = (p: AlertQuery) =>
  `/detection/alerts?window=${p.window}&q=${encodeURIComponent(p.q)}&sort=${p.sort}&offset=${p.offset}&limit=${p.limit}`
export const useAlerts = (p: AlertQuery, enabled: boolean) =>
  useQuery({ queryKey: ['detection', 'alerts', p], queryFn: () => api.get<AlertsResponse>(alertsUrl(p)), enabled, placeholderData: keepPreviousData, retry: false })

export const useAlert = (id: string) =>
  useQuery({ queryKey: ['detection', 'alert', id], queryFn: () => api.get<Alert>(`/detection/alerts/${encodeURIComponent(id)}`), retry: false })
