// The contract between the app shell and the FE modules (docs/FRONTEND.md §7). Each features/<m>/index.tsx exports `feature`.
// The shell gathers them with import.meta.glob: adding a module does NOT need a change to any file in src/app.
import type { ComponentType, ReactNode } from 'react'
import type { RouteObject } from 'react-router'
import type { LucideIcon } from 'lucide-react'
import type { ModuleId } from '@/lib/modules'
import type { Role } from '@/lib/session'

export type NavGroup = 'monitor' | 'assets' | 'detect' | 'assist'

export interface NavItem {
  to: string
  label: string // i18n key in the form "ns:key"
  icon: LucideIcon
  module: ModuleId // module off → hidden from the sidebar (the route still shows ModuleOff)
  group: NavGroup
  order: number
  end?: boolean
}

export interface SettingsSection {
  id: string // path /settings/<id>
  label: string // khoá i18n "ns:key"
  module: ModuleId
  /** The module whose own switch this section holds while the section stays under `module` (MCP under core): the
   *  section is hidden with that module when the GUI does not offer it. */
  switchOf?: ModuleId
  minRole: Role
  order: number
  element: ReactNode
}

export interface Feature {
  id: string
  routes: RouteObject[] // children of the signed-in layout
  publicRoutes?: RouteObject[] // outside the layout, no sign-in needed (sign-in, initial setup)
  nav?: NavItem[]
  settings?: SettingsSection[]
  /** A plug-in point for UI on another module's page (for example the AI attaches a panel to the CVE page). */
  slots?: Record<string, ComponentType<Record<string, unknown>>>
}

const mods = import.meta.glob<{ feature: Feature }>('../features/*/index.tsx', { eager: true })
export const features: Feature[] = Object.values(mods).map((m) => m.feature)
export const navItems = features.flatMap((f) => f.nav ?? []).sort((a, b) => a.order - b.order)
export const settingsSections = features.flatMap((f) => f.settings ?? []).sort((a, b) => a.order - b.order)

/** Every component registered for a slot, in module order. */
export function slotComponents(name: string) {
  return features.flatMap((f) => (f.slots?.[name] ? [f.slots[name]] : []))
}
