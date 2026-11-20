import type { Finding } from '@/lib/types'
import type { FindingRow } from './types'

/** Khoá i18n cho "cơ sở" của phát hiện: quét xác nhận / theo phiên bản / chỉ khớp sản phẩm. */
export const basisKey = (b: Finding['basis']) => `basis.${b}`
/** The basis as the page says it: a version match the device itself stated (its SNMP answer or its agent) is confirmed by it. */
export const basisLabel = (f: Pick<Finding, 'basis' | 'evidence'>) => (f.basis === 'version' && f.evidence?.source ? 'basis.device' : basisKey(f.basis))
export const isOpen = (s: FindingRow['status']) => s === 'confirmed' || s === 'suspected'
/** Tên thiết bị như trang Devices: `name` do API cấp; không bao giờ là id nội bộ. */
export const deviceName = (a: { name: string } | null, fallback: string) => a?.name || fallback
/** Thiết bị khai tay hoặc chỉ thấy qua LLDP không có IP; API ghi "—". */
export const hasIp = (a: { ip: string } | null) => !!a && !!a.ip && a.ip !== '—'

const SEVERITY = ['info', 'low', 'medium', 'high', 'critical'] as const
const CERTAINTY: Record<Finding['basis'], number> = { scan: 2, person: 2, version: 1, product: 0 }
/** Thứ tự rủi ro thật: độ chắc chắn trước (quét, người hoặc phiên bản thiết bị tự báo xác nhận > phiên bản > chỉ sản phẩm), rồi mức nghiêm trọng. */
export const riskRank = (f: Pick<Finding, 'basis' | 'severity'> & { evidence?: Finding['evidence'] }) =>
  (f.basis === 'version' && f.evidence?.source ? 2 : CERTAINTY[f.basis]) * 10 + SEVERITY.indexOf(f.severity)
/** Chỉ khớp tên sản phẩm, chưa biết phiên bản: mức nghiêm trọng hiện mờ, "Unverified". */
export const unverified = (f: Pick<Finding, 'basis'>) => f.basis === 'product'
