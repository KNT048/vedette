import i18n from '@/lib/i18n'
import type { Asset } from '@/lib/types'

type Named = Pick<Asset, 'hostname' | 'vendor' | 'model' | 'ip'> & { origin?: Asset['origin']; software?: { display: string }[] }

const hasIp = (a: Named) => !!a.ip && a.ip !== '—'

/** Một luật đặt tên cho mọi module (D-471), đúng như `inventory.DisplayName` của backend (findings, scans, báo cáo, mock của chúng):
 *  tên máy (tên người gõ cũng là tên máy); thiết bị khai tay thì theo sản phẩm đầu tiên, không có IP thì "<sản phẩm> (no device)",
 *  không bao giờ là hàng trống tên; thiết bị phát hiện thì hãng + model; rồi IP. '' khi không biết gì. */
export function displayName(a: Named): string {
  if (a.hostname) return a.hostname
  // The backend lists software by display name (ORDER BY display): the first of them, whatever order this array has.
  const product = a.origin === 'manual' ? a.software?.map((s) => s.display.trim()).filter(Boolean).sort()[0] : undefined
  if (product) return hasIp(a) ? product : i18n.t('inventory:noDevice', { product })
  const hw = [a.vendor?.value, a.model?.value].filter(Boolean).join(' ')
  return hw || (hasIp(a) ? a.ip : '')
}

/** Tên trên trang Devices: như `displayName`, nhưng thiết bị chỉ biết IP thì kèm loại ("Router 192.168.1.1"), không biết gì thì loại. */
export function nameOf(a: Named, fallback: string) {
  const name = displayName(a)
  return name && name === a.ip ? `${fallback} ${a.ip}` : name || fallback
}
