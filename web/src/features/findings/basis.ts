import type { Finding } from '@/lib/types'
import type { FindingRow } from './types'

/** Khoá i18n cho "cơ sở" của phát hiện: quét xác nhận / theo phiên bản / chỉ khớp sản phẩm. */
export const basisKey = (b: Finding['basis']) => `basis.${b}`
export const isOpen = (s: FindingRow['status']) => s === 'confirmed' || s === 'suspected'
/** Tên thiết bị như trang Devices (D-484): `name` do API cấp; không bao giờ là id nội bộ. */
export const deviceName = (a: { name: string } | null, fallback: string) => a?.name || fallback
/** Thiết bị khai tay hoặc chỉ thấy qua LLDP không có IP; API ghi "—". */
export const hasIp = (a: { ip: string } | null) => !!a && !!a.ip && a.ip !== '—'

const SEVERITY = ['info', 'low', 'medium', 'high', 'critical'] as const
const CERTAINTY: Record<Finding['basis'], number> = { scan: 2, version: 1, product: 0 }
/** Thứ tự rủi ro thật (D-484): độ chắc chắn trước (quét > phiên bản > chỉ sản phẩm), rồi mức nghiêm trọng. */
export const riskRank = (f: Pick<Finding, 'basis' | 'severity'>) => CERTAINTY[f.basis] * 10 + SEVERITY.indexOf(f.severity)
/** Chỉ khớp tên sản phẩm, chưa biết phiên bản: mức nghiêm trọng hiện mờ, "Unverified" (D-484). */
export const unverified = (f: Pick<Finding, 'basis'>) => f.basis === 'product'

export type CvssBand = 'none' | 'low' | 'medium' | 'high' | 'critical'
/** FIRST's qualitative bands, the same in CVSS v3.1 and v4.0 (#825): 0.0 None, 0.1–3.9 Low, 4.0–6.9 Medium, 7.0–8.9 High, 9.0–10.0 Critical. */
export function cvssBand(score: number): CvssBand {
  if (score === 0) return 'none'
  if (score < 4) return 'low'
  if (score < 7) return 'medium'
  if (score < 9) return 'high'
  return 'critical'
}
