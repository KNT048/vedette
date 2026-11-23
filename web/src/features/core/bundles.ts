// Module bundles chosen at initial setup (spec A6 step 3). The FE and the mock share this so they do not drift apart.
import type { ModuleId } from '@/lib/modules'
import type { BundleId } from './types'

// v1 modules only: a bundle never turns on a preview module (scan, honeypot, logs, ai,
// reports; the customer turns each on from its own row) and never offers a post-v1 one. modules/core/handlers_setup.go has the
// same lists (TestBundlesMatchTheWebList).
const SMB: ModuleId[] = ['core', 'feeds', 'inventory', 'notify', 'sensor-passive', 'findings', 'mitigation']
const MID: ModuleId[] = [...SMB, 'sensor-active', 'exposure']

export const BUNDLES: Record<Exclude<BundleId, 'custom'>, ModuleId[]> = { smb: SMB, mid: MID }

export interface ModuleDef { id: ModuleId; tier: 'core' | 'standard' | 'optional'; depends: ModuleId[] }

/** Choosing `id` also pulls in the modules it needs (shown plainly in the UI, never turned on silently). */
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

/** Removing `id` removes the modules that depend on it too. */
export function without(id: ModuleId, all: ModuleDef[], picked: Set<ModuleId>): Set<ModuleId> {
  const next = new Set(picked)
  const drop = (m: ModuleId) => {
    if (!next.delete(m)) return
    all.filter((x) => x.depends.includes(m)).forEach((x) => drop(x.id))
  }
  drop(id)
  return next
}
