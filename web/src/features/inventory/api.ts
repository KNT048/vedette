import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import i18n from 'i18next'
import { toast } from 'sonner'
import { api, ApiError } from '@/lib/api'
import type { AssetKind } from '@/lib/types'
import type {
  AddDeviceInput, AddDeviceResult, AgentKind, AgentReport, AgentsResponse, CatalogResponse, CreateTokenResult, DeviceDetail, DevicesResponse, DeviceSourcesView,
  ImportResult, InventorySettings, KeepSeparateInput, MergeChoice, MergeInput, MergePreview, RegularScan, SamePairs, SampleResult, Sensor, SensorPatch, SensorsResponse, SettingsInput, SettingsSaved, SourcesInput, SourcesState, SnmpResponse, SplitInput,
  DeviceSnmp, DeviceSnmpInput, DetectedField, SnmpCheckResult,
  WazuhConnection, WazuhInput, WazuhTestResult,
} from './types'

export const useDevices = () => useQuery({ queryKey: ['inventory', 'devices'], queryFn: () => api.get<DevicesResponse>('/inventory/devices') })
/** The software lines of each device that the Devices search's `software:` words hold (GET /inventory/devices?software=): the
 *  list itself carries no lines, so the server matches them. Read only while the search has such words; the last answer stays while the
 *  next is read, so typing does not empty the list. */
export const useSoftwareMatches = (words: string[]) => useQuery({
  queryKey: ['inventory', 'devices', 'software', words], enabled: words.length > 0, placeholderData: (prev) => prev,
  queryFn: () => api.get<DevicesResponse>(`/inventory/devices?software=${encodeURIComponent(words.join(','))}`),
})
/** The devices a person ignored (the Ignored tab), read only while that tab is open. */
export const useIgnoredDevices = (enabled = true) => useQuery({ queryKey: ['inventory', 'devices', 'ignored'], queryFn: () => api.get<DevicesResponse>('/inventory/devices?ignored=true'), enabled })
export const useDevice = (id: string, enabled = true) => useQuery({ queryKey: ['inventory', 'device', id], queryFn: () => api.get<DeviceDetail>(`/inventory/devices/${encodeURIComponent(id)}`), retry: false, enabled: enabled && id !== '' })
/** The device's three source rows (network scan, SNMP, agent), each decided on the server. `modules` names the state of the modules
 *  behind them, so turning one on or off (from a row or from Settings) reads the rows again. */
export const useDeviceSourceRows = (id: string, modules: string, enabled = true) =>
  useQuery({ queryKey: ['inventory', 'device', id, 'sources', modules], queryFn: () => api.get<DeviceSourcesView>(`/inventory/devices/${encodeURIComponent(id)}/sources`), retry: false, enabled: enabled && id !== '' })
/** The contract allows at most 80 characters in `q` (the backend answers 400 above that; the mock clips). A pasted long text is clipped here so suggestions keep working. */
export const CATALOG_Q_MAX = 80
export const catalogPath = (q: string) => `/inventory/catalog?q=${encodeURIComponent(q.trim().slice(0, CATALOG_Q_MAX).trim())}`
export const useCatalog = (q: string) =>
  useQuery({ queryKey: ['inventory', 'catalog', q.trim().slice(0, CATALOG_Q_MAX)], queryFn: () => api.get<CatalogResponse>(catalogPath(q)), placeholderData: (prev) => prev, enabled: q.trim() !== '' })
export const useSettings = (enabled = true) => useQuery({ queryKey: ['inventory', 'settings'], queryFn: () => api.get<InventorySettings>('/inventory/settings'), retry: false, enabled })
// While the box is starting the sensor the row is read again every 10 s, so "Starting…" turns into "Reporting" by itself.
export const useSensors = () => useQuery({ queryKey: ['inventory', 'sensors'], queryFn: () => api.get<SensorsResponse>('/inventory/sensors'), retry: false,
  refetchInterval: (q) => (q.state.status !== 'error' && q.state.data?.sensors.some((s) => s.status === 'starting') ? 10_000 : false) })
/** Container-only install: choose the SPAN card among the cards the sensor reported; the row follows the answer. */
export function useSensorCard(id: string) {
  const qc = useQueryClient()
  return useMutation({ mutationFn: (b: SensorPatch) => api.patch<Sensor>(`/inventory/sensors/${encodeURIComponent(id)}`, b), onSuccess: () => qc.invalidateQueries({ queryKey: ['inventory', 'sensors'] }) })
}
/** `enabled` false while the agent-intake module is off: a module that is off answers 404, so the GUI does not ask. */
export const useAgents = (enabled = true) => useQuery({ queryKey: ['inventory', 'agents'], queryFn: () => api.get<AgentsResponse>('/inventory/agents'), retry: false, enabled })

/** "I updated it" for agent-read software (S-MIT-1, agent-intake INV-23): which agent of this box reads the device and the open ask.
 *  `enabled` false while agent-intake is off (its routes answer 404). */
const reportPath = (id: string) => `/inventory/agents/devices/${encodeURIComponent(id)}/report`
export const useAgentReport = (id: string, enabled = true) =>
  useQuery({ queryKey: ['inventory', 'agent-report', id], queryFn: () => api.get<AgentReport>(reportPath(id)), retry: false, enabled, staleTime: 30_000 })
/** Ask the device's osquery agent to send its software now; the answer is the device's new state (every row of it shows the open ask). */
export function useAskReport(id: string) {
  const qc = useQueryClient()
  return useMutation({ mutationFn: () => api.post<AgentReport>(reportPath(id)), onSuccess: (r) => qc.setQueryData(['inventory', 'agent-report', id], r) })
}

/** `enabled` false while sensor-active is off (its SNMP routes answer 404 then), so the GUI does not ask. */
export const useSnmp = (enabled = true) => useQuery({ queryKey: ['inventory', 'snmp'], queryFn: () => api.get<SnmpResponse>('/inventory/snmp'), retry: false, enabled })
/** Dismiss every SNMP notice (what the box changed by itself); the list is read again. */
export function useDismissSnmpNotices() {
  const qc = useQueryClient()
  return useMutation({ mutationFn: () => api.post('/inventory/snmp/notices/dismiss'), onSuccess: () => qc.invalidateQueries({ queryKey: ['inventory', 'snmp'] }) })
}

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
/** Approve every given device, one after the other (one POST each); it stops at the first failure and says how many it did. */
export function useApproveAll() {
  const inv = useInvalidate()
  return useMutation({
    mutationFn: async (ids: string[]) => {
      let done = 0
      try {
        for (const id of ids) {
          await api.post(`/inventory/devices/${encodeURIComponent(id)}/approve`)
          done++
        }
      } catch (e) {
        throw Object.assign(e instanceof Error ? e : new Error(String(e)), { done })
      }
      return done
    },
    onSettled: inv,
  })
}
export function useDeviceAction(id: string) {
  const inv = useInvalidate()
  const base = `/inventory/devices/${encodeURIComponent(id)}`
  return {
    approve: useMutation({ mutationFn: () => api.post(`${base}/approve`), onSuccess: inv }),
    suspicious: useMutation({ mutationFn: (suspicious: boolean) => api.post(`${base}/suspicious`, { suspicious }), onSuccess: inv }),
    /** Ignore (known, not watched) or stop ignoring (back to To review). */
    ignore: useMutation({ mutationFn: (ignored: boolean) => api.post(`${base}/ignore`, { ignored }), onSuccess: inv }),
    remove: useMutation({ mutationFn: () => api.del(base), onSuccess: inv }),
    /** A trusted source reads another value than the one a person entered (INV-47): use the detected one, or keep the entered one. */
    useDetected: useMutation({ mutationFn: (b: { field: DetectedField; detected: string }) => api.post(`${base}/differs/${b.field}/use`, { detected: b.detected }), onSuccess: inv }),
    keepEntered: useMutation({ mutationFn: (b: { field: DetectedField; detected: string }) => api.post(`${base}/differs/${b.field}/keep`, { detected: b.detected }), onSuccess: inv }),
    patch: useMutation({ mutationFn: (b: { name?: string; kind?: AssetKind; fragile?: boolean; regular_scan?: RegularScan; notes?: string; os?: string }) => api.patch(base, b), onSuccess: inv }),
    addSoftware: useMutation({ mutationFn: (b: Omit<AddDeviceInput, 'name' | 'ip'>) => api.post<{ kev_cves: number }>(`${base}/software`, b), onSuccess: inv }),
    removeSoftware: useMutation({ mutationFn: (sid: string) => api.del(`${base}/software/${encodeURIComponent(sid)}`), onSuccess: inv }),
    setVersion: useMutation({ mutationFn: (b: { sid: string; version: string }) => api.patch(`${base}/software/${encodeURIComponent(b.sid)}`, { version: b.version }), onSuccess: inv }),
    /** INV-41: the package release (and/or version) of a row; on a row a sensor or agent reported this is a person's correction. */
    correct: useMutation({ mutationFn: ({ sid, ...b }: { sid: string; version?: string; pkg_version?: string }) => api.patch(`${base}/software/${encodeURIComponent(sid)}`, b), onSuccess: inv }),
    /** INV-41 (6): the person says a row a scan, SNMP or an agent reported is not installed (its findings close); Clear = removeSoftware on the correction. */
    notInstalled: useMutation({ mutationFn: (sid: string) => api.patch(`${base}/software/${encodeURIComponent(sid)}`, { not_installed: true }), onSuccess: inv }),
  }
}
/** Turn the network scan or the SNMP reads of one device on or off (admin); the answer is both, the default resolved. */
export function useDeviceSources(id: string) {
  const inv = useInvalidate()
  return useMutation({
    mutationFn: (b: SourcesInput) => api.put<SourcesState>(`/inventory/devices/${encodeURIComponent(id)}/sources`, b), onSuccess: inv,
  })
}
/** #829: every pair of devices that may be one machine; one cached read for the To review hints and the `possible:same` filter. */
export const usePossibleSame = () => useQuery({ queryKey: ['inventory', 'possible-same'], queryFn: () => api.get<SamePairs>('/inventory/possible-same'), retry: false })
/** What merging `from` into `into` would do (admin): both sides, what moves, the fields that differ and the refusal; nothing
 *  changes. Read again whenever the kept device or the devices change. */
export const useMergePreview = (into: string, from: string[], enabled = true) => useQuery({
  queryKey: ['inventory', 'merge-preview', into, from.join(',')], retry: false, enabled: enabled && !!into && from.length > 0,
  // the last answer stays while the next is read (another device kept), so the dialog does not empty under the person's choice
  placeholderData: (prev) => prev,
  queryFn: () => api.get<MergePreview>(`/inventory/devices/${encodeURIComponent(into)}/merge-preview?from=${encodeURIComponent(from.join(','))}`),
})
/** #829: Merge (every device of `from` joins `into` and is gone, in one step) and Keep separate, admin only. After a merge the
 *  devices that went are not read again (their page would answer 404 while it navigates away); every other inventory, feeds and
 *  findings query is. */
export function useSameDevice() {
  const qc = useQueryClient()
  const refresh = (gone: string[] = []) => Promise.all([
    // not the devices that went (their page would answer 404) nor the merge preview (the dialog closes)
    qc.invalidateQueries({ queryKey: ['inventory'], predicate: (q) => q.queryKey[1] !== 'merge-preview' && !(q.queryKey[1] === 'device' && gone.includes(String(q.queryKey[2]))) }),
    qc.invalidateQueries({ queryKey: ['feeds'] }), qc.invalidateQueries({ queryKey: ['findings'] }),
  ])
  return {
    merge: useMutation({
      mutationFn: ({ into, from, fields }: { into: string; from: string[]; fields?: MergeChoice }) =>
        api.post<{ id: string }>(`/inventory/devices/${encodeURIComponent(into)}/merge`, (fields ? { from, fields } : { from }) satisfies MergeInput),
      onSuccess: (_r, v) => {
        for (const f of v.from) qc.removeQueries({ queryKey: ['inventory', 'device', f], exact: true, type: 'inactive' })
        return refresh(v.from)
      },
      // #876 r1: a device gone meanwhile (404) or devices the box now tells apart (409): read the devices, the preview and the pairs
      // again, so nothing offers what no longer exists (the dialog keeps the words).
      onError: (e, v) => {
        if (!(e instanceof ApiError) || (e.status !== 404 && e.status !== 409)) return
        for (const id of [v.into, ...v.from]) void qc.invalidateQueries({ queryKey: ['inventory', 'device', id], exact: true })
        void qc.invalidateQueries({ queryKey: ['inventory', 'merge-preview'] })
        void qc.invalidateQueries({ queryKey: ['inventory', 'devices'], exact: true })
        void qc.invalidateQueries({ queryKey: ['inventory', 'possible-same'], exact: true })
      },
    }),
    keepSeparate: useMutation({
      mutationFn: ({ id, other }: { id: string } & KeepSeparateInput) => api.post(`/inventory/devices/${encodeURIComponent(id)}/keep-separate`, { other } satisfies KeepSeparateInput),
      onSuccess: () => refresh(),
    }),
  }
}
/** Split one address off a device (admin): that interface becomes a device of its own; the answer is the new device. */
export function useSplitAddress(id: string) {
  const inv = useInvalidate()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (address: string) => api.post<{ id: string }>(`/inventory/devices/${encodeURIComponent(id)}/split`, { address } satisfies SplitInput),
    onSuccess: inv,
    // an address gone meanwhile (404) or one that may no longer be split (409): read the device again, so the list is the box's
    onError: (e) => { if (e instanceof ApiError && (e.status === 404 || e.status === 409)) void qc.invalidateQueries({ queryKey: ['inventory', 'device', id], exact: true }) },
  })
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
    // review #860 r2 L2: the block changed since the page loaded (another admin, an inline add): read it again, so the form shows
    // the current values and its version; the toast outlives the form, which is built again on the new values
    onError: async (e) => {
      if (e instanceof ApiError && e.code === 'safety_changed') {
        toast.error(i18n.t('inventory:network.changedElsewhere'))
        await inv()
      }
    },
  })
}
/** Add one range to the scan scope without sending the whole block (#860, append-only): the ranges and confirmation the dialog showed
 *  go back with it, so a change made meanwhile is a 409 scope_changed instead of being overwritten. */
export function useAddScopeRange() {
  const inv = useInvalidate()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (b: { range: string; confirm: boolean; shown_ranges: string[]; shown_confirmed_at: string | null }) => api.post('/scanning/safety/ranges', b),
    onSettled: async () => { await Promise.all([inv(), qc.invalidateQueries({ queryKey: ['scanning'] })]) },
  })
}
export function useAgentActions() {
  const inv = useInvalidate()
  return {
    create: useMutation({ mutationFn: (b: { name: string; kind?: AgentKind; expires_in_days?: number; device_id?: string }) => api.post<CreateTokenResult>('/inventory/agents/tokens', b), onSuccess: inv }),
    /** Every token no machine enrolled with goes; tokens with machines stay. */
    removeUnused: useMutation({ mutationFn: () => api.post<{ removed: number }>('/inventory/agents/tokens/remove-unused'), onSuccess: inv }),
    revoke: useMutation({ mutationFn: (id: string) => api.del(`/inventory/agents/tokens/${encodeURIComponent(id)}`), onSuccess: inv }),
    /** One stale agent record goes (the token and the other machines stay); the device page reads the report again. */
    removeNode: useMutation({ mutationFn: (id: string) => api.del(`/inventory/agents/nodes/${encodeURIComponent(id)}`), onSuccess: inv }),
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
/** one device's SNMP (set up per device; admin). `enabled` false while sensor-active is off (its routes answer 404 then). */
export const useDeviceSnmp = (id: string, enabled = true) =>
  useQuery({ queryKey: ['inventory', 'snmp', 'device', id], queryFn: () => api.get<DeviceSnmp>(`/inventory/snmp/devices/${encodeURIComponent(id)}`), retry: false, enabled })

/** set up or edit, copy from another device, remove, Check now. A check that gets an answer records it on the device, so it
 *  refreshes devices too. */
export function useDeviceSnmpActions(id: string) {
  const qc = useQueryClient()
  const inv = () => qc.invalidateQueries({ queryKey: ['inventory'] })
  const path = `/inventory/snmp/devices/${encodeURIComponent(id)}`
  return {
    save: useMutation({ mutationFn: (b: DeviceSnmpInput) => api.put<DeviceSnmp>(path, b), onSuccess: inv }),
    remove: useMutation({ mutationFn: () => api.del(path), onSuccess: inv }),
    check: useMutation({ mutationFn: () => api.post<SnmpCheckResult>(`${path}/check`, {}), onSuccess: inv }),
  }
}

