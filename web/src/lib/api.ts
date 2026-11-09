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

/** Double-submit CSRF (API_CONVENTIONS 7.2): the server sets cookie `vedette_csrf`, state-changing calls echo it in a header. The mock ignores it. */
function csrfToken(): string | null {
  const m = document.cookie.match(/(?:^|;\s*)vedette_csrf=([^;]*)/)
  return m ? decodeURIComponent(m[1]!) : null
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const csrf = method === 'GET' ? null : csrfToken()
  const res = await fetch(`${location.origin}/api/v1${path}`, {
    method,
    credentials: 'same-origin',
    headers: { Accept: 'application/json', 'Accept-Language': lang(), ...(csrf ? { 'X-CSRF-Token': csrf } : {}), ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
    body: body === undefined ? undefined : JSON.stringify(body),
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
}

/** Tải file (CSV/JSON/rule pack) từ API mock hoặc thật mà không rời trình duyệt. */
export async function download(path: string, filename: string) {
  const res = await fetch(`${location.origin}/api/v1${path}`, { credentials: 'same-origin' })
  if (!res.ok) throw new ApiError(res.status, 'download_failed', `HTTP ${res.status}`)
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}
