// Hợp đồng giữa khung ứng dụng và module FE (docs/FRONTEND.md §7). Mỗi features/<m>/index.tsx export `feature`.
// Khung tự gom bằng import.meta.glob — thêm module KHÔNG cần sửa file trong src/app.
import type { ComponentType, ReactNode } from 'react'
import type { RouteObject } from 'react-router'
import type { LucideIcon } from 'lucide-react'
import type { ModuleId } from '@/lib/modules'
import type { Role } from '@/lib/session'
import { loadNamespaces, nsOfKey } from '@/lib/i18n'

export type NavGroup = 'monitor' | 'assets' | 'detect' | 'assist'

export interface NavItem {
  to: string
  label: string // khoá i18n dạng "ns:key"
  icon: LucideIcon
  module: ModuleId // module tắt → ẩn khỏi thanh bên (route vẫn hiện ModuleOff)
  group: NavGroup
  order: number
  end?: boolean
}

export interface SettingsSection {
  id: string // đường dẫn /settings/<id>
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
  routes: RouteObject[] // con của layout đã đăng nhập
  publicRoutes?: RouteObject[] // ngoài layout, không cần đăng nhập (đăng nhập, cài đặt ban đầu)
  nav?: NavItem[]
  settings?: SettingsSection[]
  /** Điểm cắm UI vào trang của module khác (ví dụ AI gắn khung vào trang CVE). */
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

/** Mọi component đã đăng ký cho một slot, theo thứ tự module. */
export function slotComponents(name: string) {
  return features.flatMap((f) => (f.slots?.[name] ? [f.slots[name]] : []))
}

/** The namespaces the shell itself reads labels from (sidebar entries, settings tabs, the page title): every feature that has an entry. */
export const shellNamespaces: string[] = [...new Set([...navItems.map((n) => n.label), ...settingsSections.map((s) => s.label)].map(nsOfKey).filter((n): n is string => !!n))]
