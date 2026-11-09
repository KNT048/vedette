import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '@/lib/api'
import type { ModuleId } from '@/lib/modules'
import type { Role } from '@/lib/session'
import type {
  Account, AdminUser, AuditQuery, AuditResult, AuthOptions, GeneralSettings, McpState, McpTokenCreated, OidcConfig, PrivacyState, SetupModule, SetupPayload, SetupStatus, TotpStart, EmailCodeSent,
  UpdateChannel, UpdatesState, MaintenanceWindow, OsRebootBody, OsRun, OsState,
  NetworkState, IfaceRole, ManagementBody, SpanConfig, SpanStatus, NtpConfig,
} from './types'

const qs = (q: Partial<AuditQuery>) => {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(q)) if (v) p.set(k, v)
  const s = p.toString()
  return s ? `?${s}` : ''
}

// ---- cài đặt ban đầu ----
export const useSetupModules = () => useQuery({ queryKey: ['core', 'setup-modules'], queryFn: () => api.get<{ modules: SetupModule[] }>('/core/setup/modules'), retry: false })
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
    onSuccess: (r) => { if (r.kind === 'ok') { void qc.invalidateQueries({ queryKey: ['modules'] }); void qc.invalidateQueries({ queryKey: ['core', 'mcp'] }) } },
  })
}

// ---- tài khoản ----
export const useAccount = () => useQuery({ queryKey: ['core', 'account'], queryFn: () => api.get<Account>('/core/account') })
export function useAccountMutations() {
  const qc = useQueryClient()
  const refresh = () => { void qc.invalidateQueries({ queryKey: ['core', 'account'] }); void qc.invalidateQueries({ queryKey: ['me'] }) }
  return {
    rename: useMutation({ mutationFn: (name: string) => api.patch('/core/account', { name }), onSuccess: refresh }),
    password: useMutation({ mutationFn: (v: { current: string; next: string }) => api.post('/core/account/password', v) }),
    start2fa: useMutation({ mutationFn: () => api.post<TotpStart>('/core/account/2fa/start') }),
    startEmail2fa: useMutation({ mutationFn: () => api.post<EmailCodeSent>('/core/account/2fa/email/start') }),
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
export const useOidc = () => useQuery({ queryKey: ['core', 'oidc'], queryFn: () => api.get<OidcConfig>('/core/oidc') })
export function useOidcMutations() {
  const qc = useQueryClient()
  return {
    save: useMutation({ mutationFn: (v: Omit<OidcConfig, 'secret_last4'> & { client_secret: string }) => api.put<OidcConfig>('/core/oidc', v), onSuccess: () => { void qc.invalidateQueries({ queryKey: ['core', 'oidc'] }); void qc.invalidateQueries({ queryKey: ['core', 'auth-options'] }) } }),
    test: useMutation({ mutationFn: () => api.post<{ ok: true; endpoints: Record<string, string> }>('/core/oidc/test') }),
  }
}

// ---- audit ----
export const useAudit = (q: AuditQuery) => useQuery({ queryKey: ['core', 'audit', q], queryFn: () => api.get<AuditResult>(`/core/audit${qs(q)}`), placeholderData: keepPreviousData })
export const auditExportPath = (q: AuditQuery) => `/core/audit/export${qs(q)}`

// ---- cập nhật ----
export const useUpdates = () => useQuery({ queryKey: ['core', 'updates'], queryFn: () => api.get<UpdatesState>('/core/updates') })
export function useUpdateMutations() {
  const qc = useQueryClient()
  const set = (d: UpdatesState) => { qc.setQueryData(['core', 'updates'], d); void qc.invalidateQueries({ queryKey: ['core', 'privacy'] }) }
  return {
    settings: useMutation({ mutationFn: (v: { channel?: UpdateChannel; mode?: 'auto' | 'manual' }) => api.patch<UpdatesState>('/core/updates', v), onSuccess: set }),
    check: useMutation({ mutationFn: () => api.post<UpdatesState & { applied: number }>('/core/updates/check'), onSuccess: set }),
    apply: useMutation({ mutationFn: (component: string) => api.post<UpdatesState>('/core/updates/apply', { component }), onSuccess: set }),
    rollback: useMutation({ mutationFn: (component: string) => api.post<UpdatesState>('/core/updates/rollback', { component }), onSuccess: set }),
    importBundle: useMutation({ mutationFn: (v: { name: string; size: number; sha256: string; content: string }) => api.post<{ applied: number; state: UpdatesState }>('/core/updates/bundle', v), onSuccess: (r) => set(r.state) }),
  }
}

// ---- hệ điều hành của hộp (D-53) ----
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

// ---- MCP ----
export const useMcp = () => useQuery({ queryKey: ['core', 'mcp'], queryFn: () => api.get<McpState>('/core/mcp') })
export function useMcpMutations() {
  const qc = useQueryClient()
  const refresh = () => { void qc.invalidateQueries({ queryKey: ['core', 'mcp'] }) }
  return {
    toggle: useMutation({ mutationFn: (enabled: boolean) => api.patch<McpState>('/core/mcp', { enabled }), onSuccess: () => { refresh(); void qc.invalidateQueries({ queryKey: ['modules'] }) } }),
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
/** Module thông báo: PUT /notify/channels/:type, bật kênh với mức tối thiểu Trung bình. */
export const saveNotifyChannel = (type: string, fields: Record<string, string>, secret: string) =>
  api.put(`/notify/channels/${type}`, { enabled: true, fields, secret: secret || undefined, min_severity: 'medium' })

export const usePurge = () => useMutation({ mutationFn: (confirm: string) => api.post<{ ok: true; removed: Record<string, number> }>('/core/data/purge', { confirm }) })

// ---- mạng của hộp (D-56) ----
export const useNetwork = () => useQuery({ queryKey: ['core', 'network'], queryFn: () => api.get<NetworkState>('/core/network'), refetchInterval: (q) => (q.state.data?.pending ? 2000 : false) })
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
