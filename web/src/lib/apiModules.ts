// Request → module id, the same boundaries as core/server/modules.go (ModuleOf). The drift test
// (apiModules.test.ts) checks this against api/route-modules.json, which a Go test keeps equal to the
// Go table. Used by main.tsx to decide which modules go to the real backend (VITE_API_REAL).
const prefixOverrides: ReadonlyArray<readonly [string, string]> = [
  ['/findings', 'findings'],
  ['/scans', 'scan'],
  ['/scans/credentialed', 'scan-credentialed'],
  ['/core/oidc', 'auth-oidc'],
  ['/auth/oidc', 'auth-oidc'],
  ['/core/mcp', 'mcp-server'],
  ['/install', 'agent-intake'],
  ['/intake', 'agent-intake'],
  ['/inventory/agents', 'agent-intake'],
  ['/inventory/sensors', 'sensor-passive'],
  ['/core/network', 'host'],
  ['/auth', 'core'],
  ['/me', 'core'],
  ['/modules', 'core'],
  ['/setup', 'core'],
]

/** Module that owns a path below /api/v1 (query string ignored; concrete ids or {id} placeholders). */
export function moduleOf(path: string): string {
  const p = path.split('?')[0]!
  if (/^\/findings\/[^/]+\/(applied|ai)$/.test(p)) return 'mitigation'
  let best = p.split('/')[1] ?? ''
  let bestLen = 0
  for (const [prefix, mod] of prefixOverrides) {
    if (prefix.length > bestLen && (p === prefix || p.startsWith(`${prefix}/`))) {
      best = mod
      bestLen = prefix.length
    }
  }
  return best
}

/** Modules served by the real backend: `VITE_API_REAL` = `all` or comma-separated ids. `VITE_API_MOCK=off` means `all`. */
export function realModules(real: string | undefined, mockFlag?: string): (id: string) => boolean {
  if (mockFlag === 'off') return () => true
  const list = (real ?? '').split(',').map((s) => s.trim()).filter(Boolean)
  if (list.includes('all')) return () => true
  const set = new Set(list)
  return (id) => set.has(id)
}
