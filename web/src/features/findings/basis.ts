import type { Finding } from '@/lib/types'

/** Khoá i18n cho "cơ sở" của phát hiện: quét xác nhận / theo phiên bản / chỉ khớp sản phẩm. */
export const basisKey = (b: Finding['basis']) => `basis.${b}`
export const isOpen = (s: Finding['status']) => s === 'confirmed' || s === 'suspected'
export const deviceName = (a: { hostname: string | null; ip: string } | null, fallback: string) => a?.hostname ?? a?.ip ?? fallback
