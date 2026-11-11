// Tiện ích chung cho handler mock: lỗi chuẩn {error:{code,message}}, kiểm tra quyền, validate ở biên (SYS-2).
import { HttpResponse } from 'msw'
import { sessionStore, usersStore, type User } from './stores'
import { realSessionOn, realUser } from './realSession'
import type { Role } from '@/lib/session'

export const API = '*/api/v1'

/** `extra` is spread into `error` next to `code` and `message`, so `field` (D-73) or any other detail reaches the client. */
export function fail(status: number, code: string, message: string, extra: Record<string, unknown> = {}) {
  return HttpResponse.json({ error: { code, message, ...extra } }, { status })
}

const rank: Record<Role, number> = { viewer: 0, operator: 1, admin: 2 }

/** Người đang đăng nhập: phiên của mock, hoặc (khi core chạy thật trong `make dev-api`) người dùng của backend thật (`mocks/realSession.ts`). */
export function currentUser(): User | undefined {
  if (realSessionOn()) return realUser()
  const s = sessionStore.get()
  return s.userId ? usersStore.get().find((x) => x.id === s.userId) : undefined
}

/** Trả về lỗi 401/403 nếu thiếu quyền, hoặc null nếu được phép. `allowLimited`: cho cả phiên đang bị giới hạn vì mật khẩu tạm (D-180). */
export function guard(min: Role, allowLimited = false) {
  const u = currentUser()
  if (!u) return fail(401, 'unauthenticated', 'Your session has ended. Sign in again.')
  if (rank[u.role] < rank[min]) return fail(403, 'forbidden', 'Your account is not allowed to do this.')
  // D-180 (after the role, like the server): a session opened with an administrator-set password may only read /me, change the password and sign out (those pass allowLimited).
  if (u.temp_password_expires_at && !allowLimited) return fail(403, 'password_change_required', 'Choose a new password before you continue.')
  return null
}

export async function body<T>(req: Request): Promise<Partial<T>> {
  try { return (await req.json()) as Partial<T> } catch { return {} }
}

export const NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/
export const IPV4_RE = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/
export const CIDR_RE = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}\/([0-9]|[12]\d|3[0-2])$/
export const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i
export const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

/** Ghi nhật ký kiểm toán cho mọi mutation (SYS-3). Module core hiển thị ở Cài đặt → Nhật ký. */
export { audit } from './stores'

/** Sản phẩm chỉ có tiếng Anh (D-28). Giữ chữ ký để mã cũ chạy; viết mới thì dùng chuỗi tiếng Anh trực tiếp. */
export const langOf = (_req: Request): 'en' => 'en'
/** @deprecated D-28: dùng chuỗi tiếng Anh trực tiếp. Trả về bản tiếng Anh. */
export const msg = (_req: Request, _vi: string, en: string) => en
