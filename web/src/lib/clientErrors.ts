// Vòng đệm 20 lỗi phía trình duyệt gần nhất cho gói chẩn đoán báo lỗi (D-42, S-CORE-5). Chỉ giữ trong bộ nhớ, không gửi đi đâu.
// Xoá email và địa chỉ IP khỏi thông điệp trước khi lưu: gói chẩn đoán không được chứa chúng.
export interface ClientError { at: string; kind: 'error' | 'unhandledrejection'; message: string }

const MAX = 20
const buf: ClientError[] = []
let installed = false

export function redact(s: string): string {
  return s
    .replace(/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g, '[email]')
    .replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, '[ip]')
    .replace(/\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b/gi, '[ip]')
}

function push(kind: ClientError['kind'], raw: unknown) {
  const msg = raw instanceof Error ? `${raw.name}: ${raw.message}` : String(raw)
  buf.push({ at: new Date().toISOString(), kind, message: redact(msg).slice(0, 300) })
  if (buf.length > MAX) buf.shift()
}

/** Gọi một lần ở main.tsx. */
export function installClientErrors() {
  if (installed) return
  installed = true
  window.addEventListener('error', (e) => push('error', e.error ?? e.message))
  window.addEventListener('unhandledrejection', (e) => push('unhandledrejection', e.reason))
}

/** Dùng cho lỗi trang (RouteError) mà trình duyệt không báo qua sự kiện. */
export const recordClientError = (e: unknown) => push('error', e)
export const getClientErrors = (): ClientError[] => [...buf]
