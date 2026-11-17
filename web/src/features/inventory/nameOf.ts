import i18n from '@/lib/i18n'
import type { Asset } from '@/lib/types'

type Named = Pick<Asset, 'hostname' | 'vendor' | 'model' | 'ip'> & { name?: Asset['name']; origin?: Asset['origin']; software?: { display: string }[] }

/** The name a person gave the device in Vedette, trimmed; '' when none. */
const userName = (a: Named) => a.name?.trim() ?? ''

const hasIp = (a: Named) => !!a.ip && a.ip !== '—'

/** Một luật đặt tên cho mọi module, đúng như `inventory.DisplayName` của backend (findings, scans, báo cáo, mock của chúng):
 *  tên người đặt trong Vedette (`name`) luôn thắng khi có; rồi tên máy (tên người gõ lúc khai tay cũng là tên máy); thiết bị khai tay thì theo sản phẩm đầu tiên, không có IP thì "<sản phẩm> (no device)",
 *  không bao giờ là hàng trống tên; thiết bị phát hiện thì hãng + model; rồi IP. '' khi không biết gì. */
export function displayName(a: Named): string {
  if (userName(a)) return userName(a)
  if (a.hostname) return a.hostname
  // The backend lists software by display name (ORDER BY display): the first of them, whatever order this array has.
  const product = a.origin === 'manual' ? a.software?.map((s) => s.display.trim()).filter(Boolean).sort()[0] : undefined
  if (product) return hasIp(a) ? product : i18n.t('inventory:noDevice', { product })
  // A maker or model read from a person's declared OS row (software_id) is not the observations' (inventory INV-45): the backend's
  // naming rule leaves it out, and so does this one, so a device has one name on every page.
  const hw = [a.vendor, a.model].filter((o) => o && !o.software_id).map((o) => o!.value).filter(Boolean).join(' ')
  return hw || (hasIp(a) ? a.ip : '')
}

/** Tên trên trang Devices: như `displayName`, nhưng thiết bị chỉ biết IP thì kèm loại ("Router 192.168.1.1"), không biết gì thì loại. */
export function nameOf(a: Named, fallback: string) {
  if (userName(a)) return userName(a) // a person's name is shown as typed, even when it is the IP
  const name = displayName(a)
  return name && name === a.ip ? `${fallback} ${a.ip}` : name || fallback
}

/** A product someone said they run, with no address and no name (the add form's software path, CSV, the weekly "I have this"):
 *  declared software, not a device; nothing scans it, it is matched against exploited CVEs by its product. */
export const declaredSoftwareOnly = (a: Named) => a.origin === 'manual' && !a.hostname && !hasIp(a)

/** Characters a name in Vedette cannot hold (as the backend's userName, #929): < >, C0 and C1 controls, bidi marks,
 *  overrides and isolates, zero-width characters, the soft hyphen, word joiners and U+FEFF. They would show the name reversed or blank. */
const BAD_NAME = /[<>\u0000-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/
/** Whether a trimmed name in Vedette is refused: more than 64 characters or a character of BAD_NAME. '' (none) is fine. */
export const badUserName = (s: string) => [...s].length > 64 || BAD_NAME.test(s)
