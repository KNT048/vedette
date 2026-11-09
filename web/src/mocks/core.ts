// Handler lõi: phiên đăng nhập, người dùng hiện tại, trạng thái module, trạng thái cài đặt ban đầu.
// Các handler còn lại của module core (người dùng, cập nhật, quyền riêng tư…) ở features/core/mocks.ts.
import { http, HttpResponse } from 'msw'
import { API, body, fail, guard, currentUser, audit } from './http'
import { emailChannelReady, modulesStore, orgStore, sessionStore, twofaMethodOf, usersStore } from './stores'
import { dataMode } from './db'
import type { ModuleId } from '@/lib/modules'
import { collection } from './db'
import { verifyTotp } from '@/features/core/totp'
import { checkCode, issueCode, sentBody } from '@/features/core/emailCode'

// Cùng bảng với features/core/mocks.ts (khoá TOTP đã xác nhận của từng người dùng).
const totpSecrets = collection<Record<string, string>>('core_totp', () => ({}))

const EMAIL_UNAVAILABLE = 'Two-step email codes cannot be sent right now. Ask an administrator to turn the email channel back on, or to reset your two-step sign-in.'

export const coreHandlers = [
  http.get(`${API}/me`, () => {
    const u = currentUser()
    if (!u) return fail(401, 'unauthenticated', 'Not signed in.')
    return HttpResponse.json({ id: u.id, name: u.name, email: u.email, role: u.role, org: orgStore.get().name, twofa: u.twofa, twofa_method: twofaMethodOf(u) })
  }),

  http.get(`${API}/setup`, () => HttpResponse.json({ complete: orgStore.get().setup_complete, org: orgStore.get().name, data_mode: dataMode() })),

  http.post(`${API}/auth/login`, async ({ request }) => {
    const b = await body<{ email: string; password: string; code: string }>(request)
    const email = String(b.email ?? '').trim().toLowerCase()
    const u = usersStore.get().find((x) => x.email === email && !x.disabled)
    if (!u || u.password !== b.password) return fail(400, 'invalid_credentials', 'Wrong email or password.')
    // Xác thực hai lớp: đúng mật khẩu nhưng thiếu mã → 401 để trang đăng nhập hỏi mã; mã sai → 400.
    if (u.twofa) {
      const code = String(b.code ?? '').replace(/\s/g, '')
      if (twofaMethodOf(u) === 'email') {
        // Không bao giờ lùi về "chỉ mật khẩu": kênh email không gửi được thì từ chối đăng nhập (D-35).
        if (!emailChannelReady()) {
          audit('auth.login_failed', u.email, 'email channel unavailable for two-step code')
          return fail(503, 'twofa_email_unavailable', EMAIL_UNAVAILABLE)
        }
        if (!code) {
          const sent = issueCode(u.id, true)
          if ('error' in sent) return sent.error
          return HttpResponse.json({ error: { code: 'twofa_required', message: 'We sent a 6-digit code to your sign-in email. Enter it to finish signing in.', method: 'email', sent_to: sentBody(u.email, sent).sent_to, resend_after: sent.resend_after, preview_code: sent.code } }, { status: 401 })
        }
        const bad = checkCode(u.id, code)
        if (bad) { audit('auth.login_failed', u.email, 'wrong two-step code'); return bad }
      } else {
        if (!code) return HttpResponse.json({ error: { code: 'twofa_required', message: 'This account has two-step sign-in on. Enter the 6-digit code from your authenticator app.', method: 'app' } }, { status: 401 })
        const secret = totpSecrets.get()[u.id]
        if (!/^\d{6}$/.test(code) || !secret || !(await verifyTotp(secret, code))) {
          audit('auth.login_failed', u.email, 'wrong two-step code')
          return fail(400, 'invalid_code', 'Wrong code. Check the time on your phone and enter a new code.')
        }
      }
    }
    sessionStore.set({ userId: u.id })
    usersStore.update((l) => l.map((x) => (x.id === u.id ? { ...x, last_login: new Date().toISOString() } : x)))
    audit('auth.login', u.email)
    return HttpResponse.json({ ok: true })
  }),

  // Gửi lại mã email ở bước hai: gửi cả mật khẩu để người lạ không thể bắt hộp thư người khác nhận mã.
  http.post(`${API}/auth/login/resend-code`, async ({ request }) => {
    const b = await body<{ email: string; password: string }>(request)
    const u = usersStore.get().find((x) => x.email === String(b.email ?? '').trim().toLowerCase() && !x.disabled)
    if (!u || u.password !== b.password) return fail(400, 'invalid_credentials', 'Wrong email or password.')
    if (twofaMethodOf(u) !== 'email') return fail(409, 'not_email_method', 'This account does not use email codes.')
    if (!emailChannelReady()) return fail(503, 'twofa_email_unavailable', EMAIL_UNAVAILABLE)
    const sent = issueCode(u.id)
    if ('error' in sent) return sent.error
    audit('auth.code_resend', u.email)
    return HttpResponse.json(sentBody(u.email, sent))
  }),

  http.post(`${API}/auth/logout`, () => {
    audit('auth.logout', currentUser()?.email ?? '-')
    sessionStore.set({ userId: null })
    return new HttpResponse(null, { status: 204 })
  }),

  http.get(`${API}/modules`, () => {
    const denied = guard('viewer')
    if (denied) return denied
    return HttpResponse.json({ modules: modulesStore.get() })
  }),

  // S-CORE-1: bật module thiếu phụ thuộc → 409 kèm danh sách, UI hỏi bật kèm (rule modules.md: không tự bật ngầm).
  http.patch(`${API}/modules/:id`, async ({ params, request }) => {
    const denied = guard('admin')
    if (denied) return denied
    const id = params.id as ModuleId
    const b = await body<{ enabled: boolean; with_dependencies: boolean }>(request)
    const all = modulesStore.get()
    const mod = all.find((m) => m.id === id)
    if (!mod) return fail(404, 'not_found', 'No such module.')
    if (mod.tier === 'core') return fail(400, 'core_module', 'Core modules are always on.')
    const enabled = b.enabled === true
    const now = new Date().toISOString()
    if (enabled) {
      const missing = mod.depends.filter((d) => !all.find((m) => m.id === d)?.enabled)
      if (missing.length && !b.with_dependencies) return HttpResponse.json({ error: { code: 'missing_dependencies', message: 'Turn on the modules it depends on first.', missing } }, { status: 409 })
      modulesStore.set(all.map((m) => (m.id === id || missing.includes(m.id) ? { ...m, enabled: true, enabled_at: now } : m)))
    } else {
      const dependents = all.filter((m) => m.enabled && m.depends.includes(id)).map((m) => m.id)
      modulesStore.set(all.map((m) => (m.id === id ? { ...m, enabled: false } : m)))
      audit('module.disable', id, dependents.length ? `affected: ${dependents.join(', ')}` : undefined)
      return HttpResponse.json({ modules: modulesStore.get(), affected: dependents })
    }
    audit('module.enable', id)
    return HttpResponse.json({ modules: modulesStore.get(), affected: [] })
  }),
]
