import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '@/lib/api'
import type { InstallKind, ModuleId } from '@/lib/modules'
import type { Role } from '@/lib/session'
import type {
  Account, AdminUser, AuditQuery, AuditResult, AuthOptions, GeneralSettings, McpState, McpTokenCreated, OidcConfig, OidcSave, PrivacyState, SetupModule, SetupPayload, SetupStatus, TotpStart, EmailCodeSent,
  UpdateChannel, UpdatesState, MaintenanceWindow, OsRebootBody, OsRun, OsState,
  BoxBackups, RestoreRun,
  NetworkState, IfaceRole, ManagementBody, SpanConfig, SpanStatus, NtpConfig, Connector, ConnectorInput, ConnectorTestResult,
} from './types'

const qs = (q: Partial<AuditQuery>) => {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(q)) if (v) p.set(k, v)
  const s = p.toString()
  return s ? `?${s}` : ''
}

// ---- cài đặt ban đầu ----
export const useSetupModules = () => useQuery({ queryKey: ['core', 'setup-modules'], queryFn: () => api.get<{ modules: SetupModule[]; install: InstallKind; lan: string | null }>('/core/setup/modules'), retry: false })
export const useSetupStatus = () => useQuery({ queryKey: ['setup'], queryFn: () => api.get<SetupStatus>('/setup') })
export function useSubmitSetup() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (p: SetupPayload) => api.post<{ ok: true }>('/core/setup', p),
    onSuccess: async () => { qc.removeQueries({ queryKey: ['me'] }); await qc.invalidateQueries() },
  })
}

// ---- đăng nhập ----
export const useAuthOptions = () => useQuery({ queryKey: ['core', 'auth-options'], queryFn: () => api.get<AuthOptions>('/core/auth-options'), retry: false })

// ---- chung ----
export const useGeneral = () => useQuery({ queryKey: ['core', 'general'], queryFn: () => api.get<GeneralSettings>('/core/general') })
export function useSaveGeneral() {
  const qc = useQueryClient()
  return useMutation({ mutationFn: (v: GeneralSettings) => api.put<GeneralSettings>('/core/general', v), onSuccess: () => { void qc.invalidateQueries({ queryKey: ['core', 'general'] }); void qc.invalidateQueries({ queryKey: ['me'] }) } })
}

// ---- module ----
export type ToggleResult = { kind: 'ok'; affected: ModuleId[] } | { kind: 'missing'; missing: ModuleId[] }
async function patchModule(id: ModuleId, enabled: boolean, withDependencies: boolean): Promise<ToggleResult> {
  try {
    const r = await api.patch<{ affected?: ModuleId[] }>(`/modules/${id}`, { enabled, with_dependencies: withDependencies })
    return { kind: 'ok', affected: r.affected ?? [] }
  } catch (e) {
    if (e instanceof ApiError && e.status === 409 && e.code === 'missing_dependencies') return { kind: 'missing', missing: (e.details.missing as ModuleId[] | undefined) ?? [] }
    throw e
  }
}
export function useToggleModule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (v: { id: ModuleId; enabled: boolean; withDependencies?: boolean }) => patchModule(v.id, v.enabled, v.withDependencies === true),
    onSuccess: async (r, v) => {
      if (r.kind !== 'ok') return
      await qc.invalidateQueries({ queryKey: ['modules'] }) // so the MCP page sees the module off before its cached answer is dropped
      // off, every /core/mcp path is 404 (D-230): drop the cached answer instead of refetching it
      if (v.id === 'mcp-server' && !v.enabled) qc.removeQueries({ queryKey: ['core', 'mcp'] })
      else void qc.invalidateQueries({ queryKey: ['core', 'mcp'] })
    },
  })
}

// ---- tài khoản ----
export const useAccount = (enabled = true) => useQuery({ queryKey: ['core', 'account'], queryFn: () => api.get<Account>('/core/account'), enabled })
export function useAccountMutations() {
  const qc = useQueryClient()
  const refresh = () => { void qc.invalidateQueries({ queryKey: ['core', 'account'] }); void qc.invalidateQueries({ queryKey: ['me'] }) }
  return {
    rename: useMutation({ mutationFn: (name: string) => api.patch('/core/account', { name }), onSuccess: refresh }),
    password: useMutation({ mutationFn: (v: { current: string; next: string }) => api.post('/core/account/password', v) }),
    start2fa: useMutation({ mutationFn: (password: string) => api.post<TotpStart>('/core/account/2fa/start', { password }) }),
    startEmail2fa: useMutation({ mutationFn: (password: string) => api.post<EmailCodeSent>('/core/account/2fa/email/start', { password }) }),
    confirmEmail2fa: useMutation({ mutationFn: (code: string) => api.post('/core/account/2fa/email/confirm', { code }), onSuccess: refresh }),
    confirm2fa: useMutation({ mutationFn: (code: string) => api.post('/core/account/2fa/confirm', { code }), onSuccess: refresh }),
    disable2fa: useMutation({ mutationFn: (password: string) => api.post('/core/account/2fa/disable', { password }), onSuccess: refresh }),
    revoke: useMutation({ mutationFn: (id: string) => api.del(`/core/account/sessions/${id}`), onSuccess: refresh }),
    revokeOthers: useMutation({ mutationFn: () => api.post('/core/account/sessions/revoke-others'), onSuccess: refresh }),
  }
}

// ---- người dùng, OIDC ----
export const useUsers = (enabled = true) => useQuery({ queryKey: ['core', 'users'], queryFn: () => api.get<{ items: AdminUser[] }>('/core/users'), enabled })
export function useUserMutations() {
  const qc = useQueryClient()
  const refresh = () => { void qc.invalidateQueries({ queryKey: ['core', 'users'] }) }
  return {
    create: useMutation({ mutationFn: (v: { name: string; email: string; role: Role }) => api.post<{ user: AdminUser; temp_password: string }>('/core/users', v), onSuccess: refresh }),
    patch: useMutation({ mutationFn: (v: { id: string; role?: Role; disabled?: boolean }) => api.patch<{ user: AdminUser }>(`/core/users/${v.id}`, { role: v.role, disabled: v.disabled }), onSuccess: refresh }),
    reset: useMutation({ mutationFn: (id: string) => api.post<{ temp_password: string }>(`/core/users/${id}/reset-password`) }),
    reset2fa: useMutation({ mutationFn: (id: string) => api.post(`/core/users/${id}/2fa/reset`), onSuccess: refresh }),
  }
}
export const useOidc = (enabled = true) => useQuery({ queryKey: ['core', 'oidc'], queryFn: () => api.get<OidcConfig>('/core/oidc'), enabled })
export function useOidcMutations() {
  const qc = useQueryClient()
  return {
    save: useMutation({ mutationFn: (v: OidcSave) => api.put<OidcConfig>('/core/oidc', v), onSuccess: () => { void qc.invalidateQueries({ queryKey: ['core', 'oidc'] }); void qc.invalidateQueries({ queryKey: ['core', 'auth-options'] }) } }),
    test: useMutation({ mutationFn: () => api.post<{ ok: true; endpoints: Record<string, string> }>('/core/oidc/test') }),
  }
}

// ---- audit ----
export const useAudit = (q: AuditQuery) => useQuery({ queryKey: ['core', 'audit', q], queryFn: () => api.get<AuditResult>(`/core/audit${qs(q)}`), placeholderData: keepPreviousData })
export const auditExportPath = (q: AuditQuery) => `/core/audit/export${qs(q)}`

// ---- cập nhật ----
/** Hỏi lại mỗi giây khi phần mềm đang cập nhật hay quay lại (D-340); vẫn hỏi khi một lần hỏi lỗi lúc Vedette khởi động lại. */
export const useUpdates = () => useQuery({
  queryKey: ['core', 'updates'], queryFn: () => api.get<UpdatesState>('/core/updates'),
  refetchInterval: (q) => (q.state.data?.run?.status === 'running' ? 1000 : false), refetchIntervalInBackground: true,
})
/** The every-page banner of D-386: the same data, read again every 10 minutes (an open tab learns of a withdrawal the periodic check stored), never at the 1 s pace of a run (only the Updates page follows a run). */
export const useUpdatesBanner = () => useQuery({ queryKey: ['core', 'updates'], queryFn: () => api.get<UpdatesState>('/core/updates'), staleTime: 60_000, refetchInterval: 10 * 60_000 })
export function useUpdateMutations() {
  const qc = useQueryClient()
  // Cancel a poll already on its way first: an older answer arriving after this one would hide a run that just started.
  const set = async (d: UpdatesState) => { await qc.cancelQueries({ queryKey: ['core', 'updates'] }); qc.setQueryData(['core', 'updates'], d); void qc.invalidateQueries({ queryKey: ['core', 'privacy'] }) }
  return {
    refresh: () => qc.fetchQuery({ queryKey: ['core', 'updates'], queryFn: () => api.get<UpdatesState>('/core/updates'), staleTime: 0 }),
    settings: useMutation({ mutationFn: (v: { channel?: UpdateChannel; mode?: 'auto' | 'manual' }) => api.patch<UpdatesState>('/core/updates', v), onSuccess: set }),
    // A failed check is stored (last_check_error, D-392): read the state again so the page says so.
    check: useMutation({ mutationFn: () => api.post<UpdatesState & { applied: number }>('/core/updates/check'), onSuccess: set, onError: () => void qc.invalidateQueries({ queryKey: ['core', 'updates'] }) }),
    apply: useMutation({ mutationFn: (component: string) => api.post<UpdatesState>('/core/updates/apply', { component }), onSuccess: set }),
    rollback: useMutation({ mutationFn: (v: { component: string; confirm_data_loss?: boolean }) => api.post<UpdatesState>('/core/updates/rollback', v), onSuccess: set }),
    importBundle: useMutation({ mutationFn: (v: { name: string; size: number; sha256: string; content: string }) => api.post<{ applied: number; state: UpdatesState }>('/core/updates/bundle', v), onSuccess: (r) => set(r.state) }),
  }
}

// ---- hệ điều hành của hộp (D-53) ----
// D-381: the pages that use the endpoints of vedette-host mount them only on the appliance (useInstallKind); on a container-only
// install they could only answer 409 not_appliance.
export const useOsState = () => useQuery({ queryKey: ['core', 'os'], queryFn: () => api.get<OsState>('/core/updates/os') })
/** Lần chạy hiện tại hoặc gần nhất; tự hỏi lại mỗi 0,5 giây khi đang chạy để có log trực tiếp. */
export const useOsRun = () => useQuery({
  queryKey: ['core', 'os-run'], queryFn: () => api.get<OsRun | null>('/core/updates/os/run'),
  refetchInterval: (q) => (q.state.data?.status === 'running' ? 500 : false),
})
export function useOsMutations() {
  const qc = useQueryClient()
  const setOs = (d: OsState) => { qc.setQueryData(['core', 'os'], d); void qc.invalidateQueries({ queryKey: ['core', 'updates'] }) }
  return {
    check: useMutation({ mutationFn: () => api.post<OsState>('/core/updates/os/check'), onSuccess: setOs }),
    install: useMutation({ mutationFn: (scope: 'security' | 'all') => api.post<OsRun>('/core/updates/os/install', { scope }), onSuccess: (r) => { qc.setQueryData(['core', 'os-run'], r); void qc.invalidateQueries({ queryKey: ['core', 'os'] }) } }),
    settings: useMutation({ mutationFn: (v: { auto_security?: boolean; window?: MaintenanceWindow }) => api.patch<OsState>('/core/updates/os/settings', v), onSuccess: setOs }),
    reboot: useMutation({ mutationFn: (v: OsRebootBody) => api.post<OsState>('/core/updates/os/reboot', v), onSuccess: setOs }),
    cancelReboot: useMutation({ mutationFn: () => api.del<OsState>('/core/updates/os/reboot'), onSuccess: setOs }),
  }
}

// ---- quyền riêng tư ----
export const usePrivacy = () => useQuery({ queryKey: ['core', 'privacy'], queryFn: () => api.get<PrivacyState>('/core/privacy') })
export function useSavePrivacy() {
  const qc = useQueryClient()
  return useMutation({ mutationFn: (v: { telemetry?: boolean; update_check?: boolean }) => api.patch<PrivacyState>('/core/privacy', v), onSuccess: (d) => { qc.setQueryData(['core', 'privacy'], d); void qc.invalidateQueries({ queryKey: ['core', 'updates'] }) } })
}

// ---- kết nối tới thiết bị (D-93) ----
/** Every change refreshes the list and the Privacy page: flow 12 is on while a connection is enabled. */
function useConnectionWrite<A, R = unknown>(fn: (a: A) => Promise<R>) {
  const qc = useQueryClient()
  return useMutation({ mutationFn: fn, onSettled: () => { void qc.invalidateQueries({ queryKey: ['core', 'connections'] }); void qc.invalidateQueries({ queryKey: ['core', 'privacy'] }); void qc.invalidateQueries({ queryKey: ['response'] }) } })
}
export const useConnections = () => useQuery({ queryKey: ['core', 'connections'], queryFn: () => api.get<{ items: Connector[] }>('/core/connections') })
export const useSaveConnection = () => useConnectionWrite(({ id, ...b }: ConnectorInput & { id?: string }) => (id ? api.put<Connector>(`/core/connections/${encodeURIComponent(id)}`, b) : api.post<Connector>('/core/connections', b)))
export const useRemoveConnection = () => useConnectionWrite((id: string) => api.del(`/core/connections/${encodeURIComponent(id)}`))
export const useTestConnection = () => useConnectionWrite((id: string) => api.post<ConnectorTestResult>(`/core/connections/${encodeURIComponent(id)}/test`))

// ---- MCP ----
/** Only while the mcp-server module is on: off, every /core/mcp path is 404 (D-230). The switch is useToggleModule. */
export const useMcp = (enabled: boolean) => useQuery({ queryKey: ['core', 'mcp'], queryFn: () => api.get<McpState>('/core/mcp'), enabled })
export function useMcpMutations() {
  const qc = useQueryClient()
  const refresh = () => { void qc.invalidateQueries({ queryKey: ['core', 'mcp'] }) }
  return {
    create: useMutation({ mutationFn: (v: { name: string; scopes: string[] }) => api.post<McpTokenCreated>('/core/mcp/tokens', v), onSuccess: refresh }),
    revoke: useMutation({ mutationFn: (id: string) => api.del(`/core/mcp/tokens/${id}`), onSuccess: refresh }),
  }
}

// ---- dữ liệu ----
// ---- cài đặt ban đầu: ghi vào module thật sau khi tạo quản trị ----
/** Module kiểm kê: dải LAN + xác nhận phạm vi (giữ nguyên các trường còn lại của cài đặt hiện có). */
export async function saveInventoryScope(lan: string[], scopeConfirmed: boolean) {
  const cur = await api.get<Record<string, unknown>>('/inventory/settings')
  return api.put<{ scope_confirmed_at: string | null }>('/inventory/settings', { ...cur, lan_ranges: lan, active: { ...(cur.active as object), enabled: scopeConfirmed }, scope_confirmed: scopeConfirmed })
}

// ---- khôi phục sao lưu trên hộp (S-CORE-1, D-377) ----
export const useBoxBackups = () => useQuery({ queryKey: ['core', 'backups'], queryFn: () => api.get<BoxBackups>('/core/data/backups'), retry: false })
/** Polled while a restore runs: Vedette restarts during it, so a failed poll is retried, not shown. */
export const useRestoreRun = () => useQuery({ queryKey: ['core', 'restore-run'], queryFn: () => api.get<RestoreRun | null>('/core/data/restore/run'), refetchInterval: (q) => (q.state.data?.status === 'running' ? 3000 : false) })
export const useRestore = () => {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (v: { backup_id: string; confirm_data_loss: true; password: string; code?: string }) => api.post<RestoreRun>('/core/data/restore', v),
    onSuccess: (r) => { qc.setQueryData(['core', 'restore-run'], r); void qc.invalidateQueries({ queryKey: ['core', 'backups'] }) },
  })
}
export const usePurge = () => useMutation({ mutationFn: (v: { confirm: string; password: string; code?: string }) => api.post<{ ok: true; removed: Record<string, number>; kept: string[] }>('/core/data/purge', v) })

// ---- mạng của hộp (D-56) ----
export const useNetwork = (enabled: boolean) => useQuery({ queryKey: ['core', 'network'], queryFn: () => api.get<NetworkState>('/core/network'), enabled, refetchInterval: (q) => (q.state.data?.pending ? 10000 : false) })
/** Polled while the page is open: the point of the card is to watch traffic arrive. */
export const useSpanStatus = () => useQuery({ queryKey: ['core', 'network', 'span-status'], queryFn: () => api.get<SpanStatus>('/core/network/span/status'), refetchInterval: 5000 })
export function useNetworkActions() {
  const qc = useQueryClient()
  const done = (d: NetworkState) => { qc.setQueryData(['core', 'network'], d); void qc.invalidateQueries({ queryKey: ['core', 'network', 'span-status'] }); void qc.invalidateQueries({ queryKey: ['inventory'] }); void qc.invalidateQueries({ queryKey: ['core', 'privacy'] }) }
  return {
    roles: useMutation({ mutationFn: (roles: Record<string, IfaceRole>) => api.put<NetworkState>('/core/network/interfaces', { roles }), onSuccess: done }),
    management: useMutation({ mutationFn: (b: ManagementBody) => api.put<NetworkState>('/core/network/management', b), onSuccess: done }),
    confirm: useMutation({ mutationFn: () => api.post<NetworkState>('/core/network/management/confirm'), onSuccess: done }),
    revert: useMutation({ mutationFn: () => api.post<NetworkState>('/core/network/management/revert'), onSuccess: done }),
    span: useMutation({ mutationFn: (b: SpanConfig) => api.put<NetworkState>('/core/network/span', b), onSuccess: done }),
    ntp: useMutation({ mutationFn: (b: NtpConfig) => api.put<NetworkState>('/core/network/ntp', b), onSuccess: done }),
  }
}
