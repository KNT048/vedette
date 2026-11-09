import { useQuery } from '@tanstack/react-query'
import { api } from './api'

export type ModuleId =
  | 'core' | 'feeds' | 'inventory' | 'notify' | 'sensor-passive' | 'sensor-active' | 'findings' | 'mitigation' | 'exposure' | 'scan'
  | 'scan-credentialed' | 'honeypot' | 'logs' | 'agent-intake' | 'ai' | 'reports' | 'mcp-server' | 'auth-oidc' | 'response'

export interface ModuleState {
  id: ModuleId
  enabled: boolean
  tier: 'core' | 'standard' | 'optional'
  depends: ModuleId[]
  enabled_at: string | null
}

export function useModules() {
  return useQuery({ queryKey: ['modules'], queryFn: () => api.get<{ modules: ModuleState[] }>('/modules'), staleTime: 30_000 })
}

/** true/false khi đã biết; undefined khi đang tải. */
export function useModuleEnabled(id: ModuleId): boolean | undefined {
  const { data } = useModules()
  return data?.modules.find((m) => m.id === id)?.enabled
}
