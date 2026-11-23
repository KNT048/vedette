// Two-level device types: one single list, content/devicetypes/types.json, which Go embeds from the same file. The zod contract, OpenAPI
// and the display labels all read from here, nothing is copied by hand.
import data from '../../../content/devicetypes/types.json'

export interface DeviceType { id: string; label: string; category: string; acts_as: string; aliases: string[]; no_auto_isolate?: boolean }
export interface DeviceCategory { id: string; label: string }

export const DEVICE_TYPES: readonly DeviceType[] = data.types
export const DEVICE_CATEGORIES: readonly DeviceCategory[] = data.categories
/** Every type id, in the order of the file (group by group). */
export const TYPE_IDS = data.types.map((t) => t.id) as [string, ...string[]]
/** The 13 types that behaviour depends on (fragile by default, never touch the gateway, honeypot...); each type "behaves like" one of these. */
export const BEHAVIOUR_KINDS = ['firewall', 'router', 'switch', 'ap', 'nas', 'server', 'pc', 'printer', 'camera', 'nvr', 'iot', 'web', 'unknown'] as const

const BY_ID = new Map(DEVICE_TYPES.map((t) => [t.id, t]))
const CAT_BY_ID = new Map(DEVICE_CATEGORIES.map((c) => [c.id, c]))

/** The human-readable label of a type; an unknown id gives the id itself. */
export const kindLabel = (id: string): string => BY_ID.get(id)?.label ?? id
/** The group of a type; an unknown id belongs to "unknown". */
export const categoryOf = (id: string): string => BY_ID.get(id)?.category ?? 'unknown'
export const categoryLabel = (id: string): string => CAT_BY_ID.get(id)?.label ?? id
/** The type that behaviour treats the id as. */
export const actsAs = (id: string): string => BY_ID.get(id)?.acts_as ?? 'unknown'
/** A response rule by type (device_type, naming only the 13 types) covers a device of type id: the id is one of the named types, or the type it behaves
 * like is in the list and that type is not marked no_auto_isolate; a no_auto_isolate type (PBX, OT, medical, power) is never
 * auto-isolated by a device_type rule (review #714). Like devicetypes.MatchesKind in Go. */
export const matchesKind = (kinds: string[], id: string): boolean => {
  if (kinds.includes(id)) return true
  const t = BY_ID.get(id)
  return !!t && !t.no_auto_isolate && kinds.includes(t.acts_as)
}
/** The types by group, in display order: for a type picker with optgroup. */
export const TYPES_BY_CATEGORY: readonly { category: DeviceCategory; types: DeviceType[] }[] =
  DEVICE_CATEGORIES.map((c) => ({ category: c, types: DEVICE_TYPES.filter((t) => t.category === c.id) }))

const fold = (s: string) => s.toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/đ/g, 'd').replace(/[^a-z0-9]+/g, ' ').trim()
const BY_NAME = new Map<string, string>()
for (const t of DEVICE_TYPES) BY_NAME.set(fold(t.id), t.id)
for (const t of DEVICE_TYPES) if (!BY_NAME.has(fold(t.label))) BY_NAME.set(fold(t.label), t.id)
for (const t of DEVICE_TYPES) for (const a of t.aliases) if (!BY_NAME.has(fold(a))) BY_NAME.set(fold(a), t.id)
/** The type the user typed: an id, label or alias, ignoring case/diacritics (like devicetypes.Lookup in Go). */
export const lookupType = (name: string): string | undefined => BY_NAME.get(fold(name))
