import type { Asset } from '@/lib/types'

/** Tên để hiển thị: tên máy, nếu chưa có thì hãng + model, nếu chưa có nữa thì IP. */
export function nameOf(a: Pick<Asset, 'hostname' | 'vendor' | 'model' | 'ip'>, fallback: string) {
  if (a.hostname) return a.hostname
  const hw = [a.vendor?.value, a.model?.value].filter(Boolean).join(' ')
  return hw || (a.ip && a.ip !== '—' ? `${fallback} ${a.ip}` : fallback)
}
