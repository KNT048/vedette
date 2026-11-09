// Mã đăng nhập hai bước qua email (D-35), phía mock. Backend thật sinh/kiểm cùng quy tắc: 6 số, hết hạn 10 phút,
// dùng 1 lần, 5 lần nhập sai huỷ mã, gửi lại sau 60 giây, tối đa 5 lần gửi mỗi giờ cho mỗi người dùng.
import { HttpResponse } from 'msw'
import { collection } from '@/mocks/db'
import { fail } from '@/mocks/http'

export const CODE_TTL_MS = 10 * 60_000
export const MAX_TRIES = 5
export const RESEND_S = 60
export const MAX_SENDS_PER_HOUR = 5

interface Pending { code: string; expires: number; tries: number; sent_at: number }
interface Slot { pending: Pending | null; sends: number[] }
export const emailCodes = collection<Record<string, Slot>>('core_email_codes', () => ({}))

/** a•••@acme.example: chỉ chữ đầu và tên miền, đủ để người dùng nhận ra hộp thư của mình. */
export const maskEmail = (email: string) => { const [local = '', domain = ''] = email.split('@'); return `${local.slice(0, 1)}•••@${domain}` }

const randomCode = () => String(crypto.getRandomValues(new Uint32Array(1))[0]! % 1_000_000).padStart(6, '0')
const tooSoon = (wait: number) => HttpResponse.json({ error: { code: 'resend_too_soon', message: `Wait ${wait} seconds before asking for a new code.`, retry_after: wait } }, { status: 429 })

export type Issued = { code: string; resend_after: number } | { error: Response }

/** Gửi mã mới. `reuseFresh`: lúc đăng nhập, nếu mã vừa gửi chưa đầy 60 giây thì giữ mã đó (tải lại trang không tốn lượt gửi). */
export function issueCode(userId: string, reuseFresh = false): Issued {
  const all = emailCodes.get()
  const now = Date.now()
  const sends = (all[userId]?.sends ?? []).filter((t) => now - t < 3_600_000)
  const p = all[userId]?.pending
  if (p && now - p.sent_at < RESEND_S * 1000) {
    const wait = Math.ceil((RESEND_S * 1000 - (now - p.sent_at)) / 1000)
    if (reuseFresh && now < p.expires) return { code: p.code, resend_after: wait }
    return { error: tooSoon(wait) }
  }
  if (sends.length >= MAX_SENDS_PER_HOUR) return { error: fail(429, 'too_many_codes', 'Too many codes were sent in the last hour. Try again later.') }
  const code = randomCode()
  emailCodes.set({ ...all, [userId]: { pending: { code, expires: now + CODE_TTL_MS, tries: 0, sent_at: now }, sends: [...sends, now] } })
  return { code, resend_after: RESEND_S }
}

export function clearCode(userId: string) {
  const all = emailCodes.get()
  const slot = all[userId]
  if (slot) emailCodes.set({ ...all, [userId]: { ...slot, pending: null } })
}

/** null = mã đúng (và đã dùng hết); còn lại là phản hồi lỗi. */
export function checkCode(userId: string, input: string): Response | null {
  const all = emailCodes.get()
  const p = all[userId]?.pending
  if (!p) return fail(400, 'no_code', 'No code is waiting. Ask for a new code.')
  if (Date.now() > p.expires) { clearCode(userId); return fail(400, 'code_expired', 'This code has expired. Ask for a new code.') }
  if (!/^\d{6}$/.test(input)) return fail(400, 'invalid_code', 'The code is 6 digits.')
  if (input !== p.code) {
    const tries = p.tries + 1
    if (tries >= MAX_TRIES) { clearCode(userId); return fail(400, 'too_many_tries', 'Too many wrong codes. Ask for a new code.') }
    emailCodes.set({ ...all, [userId]: { ...all[userId]!, pending: { ...p, tries } } })
    const left = MAX_TRIES - tries
    return fail(400, 'wrong_code', `Wrong code. ${left} ${left === 1 ? 'try' : 'tries'} left.`)
  }
  clearCode(userId)
  return null
}

/** Phản hồi thành công của "gửi mã": preview_code chỉ có trong bản xem thử (mock), backend thật không bao giờ gửi. */
export const sentBody = (email: string, i: { code: string; resend_after: number }) => ({ sent_to: maskEmail(email), resend_after: i.resend_after, preview_code: i.code })
