import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import i18n from 'i18next'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import type { AssetKind } from '@/lib/types'
import type {
  AddDeviceInput, AddDeviceResult, AgentKind, AgentsResponse, CatalogResponse, CreateTokenResult, DeviceDetail, DevicesResponse,
  ImportResult, InventorySettings, RegularScan, SampleResult, Sensor, SensorPatch, SensorsResponse, SettingsInput, SettingsSaved, WazuhConnection, WazuhInput, WazuhTestResult,
} from './types'

export const useDevices = () => useQuery({ queryKey: ['inventory', 'devices'], queryFn: () => api.get<DevicesResponse>('/inventory/devices') })
export const useDevice = (id: string) => useQuery({ queryKey: ['inventory', 'device', id], queryFn: () => api.get<DeviceDetail>(`/inventory/devices/${encodeURIComponent(id)}`), retry: false })
/** The contract allows at most 80 characters in `q` (the backend answers 400 above that; the mock clips). A pasted long text is clipped here so suggestions keep working. */
export const CATALOG_Q_MAX = 80
export const catalogPath = (q: string) => `/inventory/catalog?q=${encodeURIComponent(q.trim().slice(0, CATALOG_Q_MAX).trim())}`
export const useCatalog = (q: string) =>
  useQuery({ queryKey: ['inventory', 'catalog', q.trim().slice(0, CATALOG_Q_MAX)], queryFn: () => api.get<CatalogResponse>(catalogPath(q)), placeholderData: (prev) => prev, enabled: q.trim() !== '' })
export const useSettings = (enabled = true) => useQuery({ queryKey: ['inventory', 'settings'], queryFn: () => api.get<InventorySettings>('/inventory/settings'), retry: false, enabled })
// W2-6: while the box is starting the sensor the row is read again every 10 s, so "Starting…" turns into "Reporting" by itself.
export const useSensors = () => useQuery({ queryKey: ['inventory', 'sensors'], queryFn: () => api.get<SensorsResponse>('/inventory/sensors'), retry: false,
  refetchInterval: (q) => (q.state.status !== 'error' && q.state.data?.sensors.some((s) => s.status === 'starting') ? 10_000 : false) })
/** Container-only install (D-387): choose the SPAN card among the cards the sensor reported; the row follows the answer. */
export function useSensorCard(id: string) {
  const qc = useQueryClient()
  return useMutation({ mutationFn: (b: SensorPatch) => api.patch<Sensor>(`/inventory/sensors/${encodeURIComponent(id)}`, b), onSuccess: () => qc.invalidateQueries({ queryKey: ['inventory', 'sensors'] }) })
}
/** `enabled` false while the agent-intake module is off: a module that is off answers 404 (rules/modules.md), so the GUI does not ask. */
export const useAgents = (enabled = true) => useQuery({ queryKey: ['inventory', 'agents'], queryFn: () => api.get<AgentsResponse>('/inventory/agents'), retry: false, enabled })

/** Sau mọi thay đổi thiết bị: làm mới cả danh sách, chi tiết và các trang module khác đọc tài sản (feeds, findings). */
function useInvalidate() {
  const qc = useQueryClient()
  return () => Promise.all([qc.invalidateQueries({ queryKey: ['inventory'] }), qc.invalidateQueries({ queryKey: ['feeds'] }), qc.invalidateQueries({ queryKey: ['findings'] })])
}

export function useAddDevice() {
  const inv = useInvalidate()
  return useMutation({ mutationFn: (b: AddDeviceInput) => api.post<AddDeviceResult>('/inventory/devices', b), onSuccess: inv })
}
export function useImportDevices() {
  const inv = useInvalidate()
  return useMutation({ mutationFn: (b: { filename: string; size: number; sha256: string; text: string }) => api.post<ImportResult>('/inventory/import', b), onSuccess: inv })
}
export function useDeviceAction(id: string) {
  const inv = useInvalidate()
  const base = `/inventory/devices/${encodeURIComponent(id)}`
  return {
    approve: useMutation({ mutationFn: () => api.post(`${base}/approve`), onSuccess: inv }),
    suspicious: useMutation({ mutationFn: (suspicious: boolean) => api.post(`${base}/suspicious`, { suspicious }), onSuccess: inv }),
    remove: useMutation({ mutationFn: () => api.del(base), onSuccess: inv }),
    patch: useMutation({ mutationFn: (b: { kind?: AssetKind; fragile?: boolean; regular_scan?: RegularScan; notes?: string }) => api.patch(base, b), onSuccess: inv }),
    addSoftware: useMutation({ mutationFn: (b: Omit<AddDeviceInput, 'name' | 'ip'>) => api.post<{ kev_cves: number }>(`${base}/software`, b), onSuccess: inv }),
    removeSoftware: useMutation({ mutationFn: (sid: string) => api.del(`${base}/software/${encodeURIComponent(sid)}`), onSuccess: inv }),
    setVersion: useMutation({ mutationFn: (b: { sid: string; version: string }) => api.patch(`${base}/software/${encodeURIComponent(b.sid)}`, { version: b.version }), onSuccess: inv }),
  }
}
export function useNotifyNew() {
  const inv = useInvalidate()
  return useMutation({ mutationFn: (enabled: boolean) => api.put('/inventory/notify-new', { enabled }), onSuccess: inv })
}
export function useSaveSettings() {
  const inv = useInvalidate()
  // Toast ở đây (không ở callback của form): sau khi lưu, làm mới cài đặt đổi `key` của form nên form được dựng lại và callback của nó không bao giờ chạy.
  return useMutation({
    mutationFn: (b: SettingsInput) => api.put<SettingsSaved>('/inventory/settings', b),
    onSuccess: async (r) => {
      toast.success(r.adjusted.length ? i18n.t('inventory:network.savedAdjusted', { list: r.adjusted.map((a) => `${a.from} → ${a.to}`).join(', ') }) : i18n.t('inventory:network.saved'))
      await inv()
    },
  })
}
export function useAgentActions() {
  const inv = useInvalidate()
  return {
    create: useMutation({ mutationFn: (b: { name: string; kind?: AgentKind; expires_in_days?: number }) => api.post<CreateTokenResult>('/inventory/agents/tokens', b), onSuccess: inv }),
    revoke: useMutation({ mutationFn: (id: string) => api.del(`/inventory/agents/tokens/${encodeURIComponent(id)}`), onSuccess: inv }),
    /** Chỉ bản xem thử có mock API. */
    sampleToken: useMutation({ mutationFn: (id: string) => api.post<SampleResult>(`/inventory/agents/tokens/${encodeURIComponent(id)}/sample-data`), onSuccess: inv }),
  }
}
export function useWazuhActions() {
  const inv = useInvalidate()
  return {
    test: useMutation({ mutationFn: (b: WazuhInput) => api.post<WazuhTestResult>('/inventory/agents/wazuh/test', b) }),
    save: useMutation({ mutationFn: (b: WazuhInput) => api.put<WazuhConnection>('/inventory/agents/wazuh', b), onSuccess: inv }),
    disconnect: useMutation({ mutationFn: () => api.del('/inventory/agents/wazuh'), onSuccess: inv }),
    sample: useMutation({ mutationFn: () => api.post<SampleResult>('/inventory/agents/wazuh/sample-data'), onSuccess: inv }),
  }
}
