// Client API duy nhất của SPA. M1: MSW trả lời (src/mocks); M2: backend Go cùng hợp đồng (D-18).
export class ApiError extends Error {
  readonly status: number
  readonly code: string
  /** Trường thêm trong `error` của phản hồi (ví dụ `missing` khi bật module thiếu phụ thuộc). */
  readonly details: Record<string, unknown>
  constructor(status: number, code: string, message: string, details: Record<string, unknown> = {}) {
    super(message)
    this.status = status
    this.code = code
    this.details = details
  }
}

/** Sản phẩm chỉ có tiếng Anh (D-28); vẫn gửi header để máy chủ sinh văn bản đúng ngôn ngữ. */
const lang = () => 'en'

/** Double-submit CSRF (API_CONVENTIONS 7.2): the server sets cookie `__Host-vedette_csrf`, state-changing calls echo it in a header. The mock ignores it. */
function csrfToken(): string | null {
  const m = document.cookie.match(/(?:^|;\s*)__Host-vedette_csrf=([^;]*)/)
  return m ? decodeURIComponent(m[1]!) : null
}

async function request<T>(method: string, path: string, body?: unknown, file?: { blob: Blob; headers: Record<string, string> }): Promise<T> {
  const csrf = method === 'GET' ? null : csrfToken()
  const res = await fetch(`${location.origin}/api/v1${path}`, {
    method,
    credentials: 'same-origin',
    headers: {
      Accept: 'application/json', 'Accept-Language': lang(), ...(csrf ? { 'X-CSRF-Token': csrf } : {}),
      ...(file ? { 'Content-Type': 'application/octet-stream', ...file.headers } : body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    body: file ? file.blob : body === undefined ? undefined : JSON.stringify(body),
  })
  if (res.status === 204) return undefined as T
  const data: unknown = await res.json().catch(() => null)
  if (!res.ok) {
    const err = (data as { error?: { code?: string; message?: string } & Record<string, unknown> } | null)?.error
    const { code, message, ...details } = err ?? {}
    throw new ApiError(res.status, code ?? 'http_error', message ?? `HTTP ${res.status}`, details)
  }
  return data as T
}

export const api = {
  get: <T>(path: string) => request<T>('GET', path),
  post: <T>(path: string, body?: unknown) => request<T>('POST', path, body ?? {}),
  put: <T>(path: string, body: unknown) => request<T>('PUT', path, body),
  patch: <T>(path: string, body: unknown) => request<T>('PATCH', path, body),
  del: <T>(path: string) => request<T>('DELETE', path),
  /** POST a file as the body itself (`application/octet-stream`, D-518), with headers the operation reads. */
  upload: <T>(path: string, blob: Blob, headers: Record<string, string> = {}) => request<T>('POST', path, undefined, { blob, headers }),
}

/** File name the box sends in Content-Disposition (plain `filename=` or RFC 5987 `filename*=`), cleaned of path parts and control characters; `fallback` when absent or empty. */
export function dispositionName(header: string | null, fallback: string): string {
  const clean = (v: string) => {
    // eslint-disable-next-line no-control-regex
    const base = v.replace(/[\u0000-\u001f\u007f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, '').split(/[\\/]/).pop()?.trim() ?? ''
    return base && base !== '.' && base !== '..' ? base : ''
  }
  if (!header) return fallback
  const star = /filename\*\s*=\s*(?:[^']*)'[^']*'("?)([^";]*)\1/i.exec(header)
  if (star?.[2]) {
    let v = star[2]
    try { v = decodeURIComponent(v) } catch { /* keep as sent */ }
    const n = clean(v)
    if (n) return n
  }
  const plain = /filename\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^";]*))/i.exec(header)
  const n = clean((plain?.[1]?.replace(/\\(["\\])/g, '$1') ?? plain?.[2] ?? ''))
  return n || fallback
}

/** Tải file (CSV/JSON/rule pack) từ API mock hoặc thật mà không rời trình duyệt. Tên file: do hộp gửi (Content-Disposition), không có thì `filename`. */
export async function download(path: string, filename: string, body?: unknown) {
  // With a body it is a POST (a download behind a password, like the decryption key): JSON and the CSRF header as every POST.
  const csrf = body === undefined ? null : csrfToken()
  const res = await fetch(`${location.origin}/api/v1${path}`, body === undefined ? { credentials: 'same-origin' } : {
    method: 'POST', credentials: 'same-origin', body: JSON.stringify(body),
    headers: { 'Content-Type': 'application/json', 'Accept-Language': lang(), ...(csrf ? { 'X-CSRF-Token': csrf } : {}) },
  })
  if (!res.ok) {
    // The box's own sentence (error.message of the JSON body) when it sent one, not just the status.
    const data: unknown = await res.json().catch(() => null)
    const err = (data as { error?: { code?: string; message?: string } } | null)?.error
    throw new ApiError(res.status, err?.code ?? 'download_failed', err?.message ?? `HTTP ${res.status}`)
  }
  const name = dispositionName(res.headers.get('Content-Disposition'), filename)
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  URL.revokeObjectURL(url)
  return name
}
