// The v1 promise covers the v1 modules only. Two other groups ship in the same build:
// - Preview (#818): off by default, labelled "Preview" on their nav entry, their row in Settings → Modules and their page header.
// - After v1 (#819): while POST_V1_IN_UI is false the GUI does not offer them: no nav entry, no row in Settings → Modules, no
//   Settings section, no setup wizard choice, no switch elsewhere. A box that already has one on still sees it, read-only, with
//   one line and the way out (turn it off; once off it is hidden), as SPAN_IN_UI does. No route, API, mock or backend
//   code is removed. The switch POST_V1_IN_UI lives in ./postV1 (so a test can flip it); post-v1: set it true and recheck the
//   stories of these modules.
import { createContext } from 'react'
import type { ModuleId } from './modules'
import { useModules } from './modules'
import { CREDENTIALED_IN_UI } from './credentialed'
import { POST_V1_IN_UI } from './postV1'

export const PREVIEW_MODULES: readonly ModuleId[] = ['scan', 'honeypot', 'logs', 'ai', 'reports']
export const POST_V1_MODULES: readonly ModuleId[] = ['response', 'mcp-server', 'auth-oidc', 'scan-credentialed']

/** true: the GUI does not offer this module in this build. scan-credentialed keeps its own switch: it has no
 *  backend yet, so it stays hidden after v1 until that is built. */
export const notOffered = (id: ModuleId) => (id === 'scan-credentialed' ? !CREDENTIALED_IN_UI : !POST_V1_IN_UI && POST_V1_MODULES.includes(id))

/** v1 or preview: shown as usual. hidden: not offered and off, so absent everywhere. leaving: not offered but on here, so shown
 *  read-only with the way out. `enabled` undefined (still loading) counts as off, so a hidden module never flashes in. */
export type Scope = 'v1' | 'preview' | 'hidden' | 'leaving'

export function scopeOf(id: ModuleId, enabled: boolean | undefined): Scope {
  if (notOffered(id)) return enabled ? 'leaving' : 'hidden'
  return PREVIEW_MODULES.includes(id) ? 'preview' : 'v1'
}

/** The scope of one module on this box, from GET /modules. */
export function useScope(id: ModuleId): Scope {
  return scopeOf(id, useModules().data?.modules.find((m) => m.id === id)?.enabled)
}

/** The module of the page being shown: set by Layout (from the nav entry of the path) and by a Settings section, read by
 *  PageHeader, so a page of a preview module gets its badge and line without the page knowing about it (#818). */
export const PageModule = createContext<ModuleId | null>(null)
