// Gói module chọn lúc cài đặt ban đầu (spec A6 bước 3). FE và mock dùng chung để không lệch nhau.
import type { ModuleId } from '@/lib/modules'
import type { BundleId } from './types'

const SMB: ModuleId[] = ['core', 'feeds', 'inventory', 'notify', 'sensor-passive', 'mitigation', 'honeypot', 'reports']
const MID: ModuleId[] = [...SMB, 'sensor-active', 'scan', 'exposure', 'logs', 'ai']

export const BUNDLES: Record<Exclude<BundleId, 'custom'>, ModuleId[]> = { smb: SMB, mid: MID }

export interface ModuleDef { id: ModuleId; tier: 'core' | 'standard' | 'optional'; depends: ModuleId[] }

/** Chọn thêm `id` thì kéo theo các module nó cần (hiện rõ trên giao diện, không bật ngầm). */
export function closure(id: ModuleId, all: ModuleDef[], picked: Set<ModuleId>): Set<ModuleId> {
  const next = new Set(picked)
  const visit = (m: ModuleId) => {
    if (next.has(m)) return
    next.add(m)
    all.find((x) => x.id === m)?.depends.forEach(visit)
  }
  visit(id)
  return next
}

/** Bỏ `id` thì bỏ cả module phụ thuộc vào nó. */
export function without(id: ModuleId, all: ModuleDef[], picked: Set<ModuleId>): Set<ModuleId> {
  const next = new Set(picked)
  const drop = (m: ModuleId) => {
    if (!next.delete(m)) return
    all.filter((x) => x.depends.includes(m)).forEach((x) => drop(x.id))
  }
  drop(id)
  return next
}
