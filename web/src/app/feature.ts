// Hợp đồng giữa khung ứng dụng và module FE (docs/FRONTEND.md §7). Mỗi features/<m>/index.tsx export `feature`.
// Khung tự gom bằng import.meta.glob — thêm module KHÔNG cần sửa file trong src/app.
import type { ComponentType, ReactNode } from 'react'
import type { RouteObject } from 'react-router'
import type { LucideIcon } from 'lucide-react'
import type { ModuleId } from '@/lib/modules'
import type { Role } from '@/lib/session'

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
  minRole: Role
  order: number
  element: ReactNode
}

export interface Feature {
  id: string
  routes: RouteObject[] // con của layout đã đăng nhập
  publicRoutes?: RouteObject[] // ngoài layout, không cần đăng nhập (đăng nhập, cài đặt ban đầu)
  nav?: NavItem[]
  settings?: SettingsSection[]
  /** Điểm cắm UI vào trang của module khác (ví dụ AI gắn khung vào trang CVE). Tên slot: xem docs/plans/…-fe-spec.md §Slot. */
  slots?: Record<string, ComponentType<Record<string, unknown>>>
}

const mods = import.meta.glob<{ feature: Feature }>('../features/*/index.tsx', { eager: true })
export const features: Feature[] = Object.values(mods).map((m) => m.feature)
export const navItems = features.flatMap((f) => f.nav ?? []).sort((a, b) => a.order - b.order)
export const settingsSections = features.flatMap((f) => f.settings ?? []).sort((a, b) => a.order - b.order)

/** Mọi component đã đăng ký cho một slot, theo thứ tự module. */
export function slotComponents(name: string) {
  return features.flatMap((f) => (f.slots?.[name] ? [f.slots[name]] : []))
}
