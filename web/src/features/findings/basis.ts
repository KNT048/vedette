import type { Finding } from '@/lib/types'

/** Khoá i18n cho "cơ sở" của phát hiện: quét xác nhận / theo phiên bản / chỉ khớp sản phẩm. */
export const basisKey = (b: Finding['basis']) => `basis.${b}`
export const isOpen = (s: Finding['status']) => s === 'confirmed' || s === 'suspected'
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
