// The contract between the app shell and the FE modules (docs/FRONTEND.md §7). Each features/<m>/index.tsx exports `feature`.
// The shell gathers them with import.meta.glob: adding a module does NOT need a change to any file in src/app.
import type { ComponentType, ReactNode } from 'react'
import type { RouteObject } from 'react-router'
import type { LucideIcon } from 'lucide-react'
import type { ModuleId } from '@/lib/modules'
import type { Role } from '@/lib/session'
import { loadNamespaces, nsOfKey } from '@/lib/i18n'

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
  /** Locale namespaces the routes need, loaded with the route chunk. Default: the feature's own id. */
  namespaces?: string[]
  routes: RouteObject[] // children of the signed-in layout
  publicRoutes?: RouteObject[] // outside the layout, no sign-in needed (sign-in, initial setup)
  nav?: NavItem[]
  settings?: SettingsSection[]
  /** UI plug-in points on another module's page (for example the AI panel on the CVE page). */
  slots?: Record<string, ComponentType<Record<string, unknown>>>
}

const mods = import.meta.glob<{ feature: Feature }>('../features/*/index.tsx', { eager: true })

/** A route's chunk and its feature's locale namespaces load together, so the page renders with its words and never shows a key. */
function withNamespaces(routes: RouteObject[] | undefined, ns: string[]): RouteObject[] | undefined {
  return routes?.map((r) => {
    const { lazy, children } = r
    return {
      ...r,
      ...(typeof lazy === 'function' ? { lazy: () => Promise.all([lazy(), loadNamespaces(ns)]).then(([m]) => m) } : {}),
      ...(children ? { children: withNamespaces(children, ns) } : {}),
    } as RouteObject
  })
}
export const features: Feature[] = Object.values(mods).map((m) => {
  const f = m.feature
  const ns = f.namespaces ?? [f.id]
  return { ...f, routes: withNamespaces(f.routes, ns) ?? [], publicRoutes: withNamespaces(f.publicRoutes, ns) }
})
export const navItems = features.flatMap((f) => f.nav ?? []).sort((a, b) => a.order - b.order)
export const settingsSections = features.flatMap((f) => f.settings ?? []).sort((a, b) => a.order - b.order)

/** Every component registered for a slot, in module order. */
export function slotComponents(name: string) {
  return features.flatMap((f) => (f.slots?.[name] ? [f.slots[name]] : []))
}

/** The namespaces the shell itself reads labels from (sidebar entries, settings tabs, the page title): every feature that has an entry. */
export const shellNamespaces: string[] = [...new Set([...navItems.map((n) => n.label), ...settingsSections.map((s) => s.label)].map(nsOfKey).filter((n): n is string => !!n))]
