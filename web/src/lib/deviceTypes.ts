// Loại thiết bị hai cấp (D-511): một danh sách duy nhất, content/devicetypes/types.json, Go nhúng cùng tệp này. Hợp đồng zod, OpenAPI
// và nhãn hiển thị đều đọc từ đây, không chép tay.
import data from '../../../content/devicetypes/types.json'

export interface DeviceType { id: string; label: string; category: string; acts_as: string; aliases: string[] }
export interface DeviceCategory { id: string; label: string }

export const DEVICE_TYPES: readonly DeviceType[] = data.types
export const DEVICE_CATEGORIES: readonly DeviceCategory[] = data.categories
/** Mọi id loại, theo thứ tự của tệp (nhóm theo nhóm). */
export const TYPE_IDS = data.types.map((t) => t.id) as [string, ...string[]]
/** 13 loại mà hành vi dựa vào (mong manh mặc định, không đụng gateway, honeypot…); mỗi loại "hành xử như" một trong số này. */
export const BEHAVIOUR_KINDS = ['firewall', 'router', 'switch', 'ap', 'nas', 'server', 'pc', 'printer', 'camera', 'nvr', 'iot', 'web', 'unknown'] as const

const BY_ID = new Map(DEVICE_TYPES.map((t) => [t.id, t]))
const CAT_BY_ID = new Map(DEVICE_CATEGORIES.map((c) => [c.id, c]))

/** Nhãn người đọc của một loại; id lạ thì chính id. */
export const kindLabel = (id: string): string => BY_ID.get(id)?.label ?? id
/** Nhóm của một loại; id lạ thuộc "unknown". */
export const categoryOf = (id: string): string => BY_ID.get(id)?.category ?? 'unknown'
export const categoryLabel = (id: string): string => CAT_BY_ID.get(id)?.label ?? id
/** Loại mà hành vi coi id là (D-511). */
export const actsAs = (id: string): string => BY_ID.get(id)?.acts_as ?? 'unknown'
/** Các loại theo nhóm, theo thứ tự hiển thị: cho ô chọn loại có optgroup. */
export const TYPES_BY_CATEGORY: readonly { category: DeviceCategory; types: DeviceType[] }[] =
  DEVICE_CATEGORIES.map((c) => ({ category: c, types: DEVICE_TYPES.filter((t) => t.category === c.id) }))

const fold = (s: string) => s.toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/đ/g, 'd').replace(/[^a-z0-9]+/g, ' ').trim()
const BY_NAME = new Map<string, string>()
for (const t of DEVICE_TYPES) BY_NAME.set(fold(t.id), t.id)
for (const t of DEVICE_TYPES) if (!BY_NAME.has(fold(t.label))) BY_NAME.set(fold(t.label), t.id)
for (const t of DEVICE_TYPES) for (const a of t.aliases) if (!BY_NAME.has(fold(a))) BY_NAME.set(fold(a), t.id)
/** Loại người gõ: id, nhãn hay bí danh, không phân biệt hoa thường/dấu (như devicetypes.Lookup của Go). */
export const lookupType = (name: string): string | undefined => BY_NAME.get(fold(name))
