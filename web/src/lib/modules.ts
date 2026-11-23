import { useQuery } from '@tanstack/react-query'
import { api } from './api'

export type ModuleId =
  | 'core' | 'feeds' | 'inventory' | 'notify' | 'sensor-passive' | 'sensor-active' | 'findings' | 'mitigation' | 'exposure' | 'scan'
  | 'scan-credentialed' | 'honeypot' | 'logs' | 'ids' | 'agent-intake' | 'ai' | 'reports' | 'mcp-server' | 'auth-oidc' | 'response'

/** appliance: install.sh with the system helper vedette-host; container: container-only install, no helper. */
export type InstallKind = 'appliance' | 'container'

export interface ModuleState {
  id: ModuleId
  enabled: boolean
  tier: 'core' | 'standard' | 'optional'
  depends: ModuleId[]
  enabled_at: string | null
  /** false: this install cannot run the module (honeypot on a container-only install). */
  available: boolean
}

export function useModules() {
  return useQuery({ queryKey: ['modules'], queryFn: () => api.get<{ modules: ModuleState[]; install: InstallKind }>('/modules'), staleTime: 30_000 })
}

/** true/false when known; undefined while loading. */
export function useModuleEnabled(id: ModuleId): boolean | undefined {
  const { data } = useModules()
  return data?.modules.find((m) => m.id === id)?.enabled
}

/** false when this install cannot run the module, for example the honeypot on a container-only install; undefined while loading. */
export function useModuleAvailable(id: ModuleId): boolean | undefined {
  return useModules().data?.modules.find((m) => m.id === id)?.available
}

/** The install kind from GET /modules, the one source the GUI reads; undefined while loading. */
export function useInstallKind(): InstallKind | undefined {
  return useModules().data?.install
}
