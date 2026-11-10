// Mock API module core (S-CORE-1..4, S-MCP-1, cài đặt ban đầu). Handler lõi (đăng nhập, /me, /modules) ở src/mocks/core.ts.
import { http, HttpResponse } from 'msw'
import { logExportHandlers } from './logExport'
import { API, audit, body, currentUser, fail, guard, EMAIL_RE } from '@/mocks/http'
import { aiConfigStore, assetsStore, auditStore, emailChannelReady, findingsStore, isOn, modulesStore, orgStore, sessionStore, twofaMethodOf, usersStore, type User } from '@/mocks/stores'
import { collection, dataMode, daysAgo, newId, nowIso, resetMockDb, setDataMode } from '@/mocks/db'
import type { Role } from '@/lib/session'
import type { ModuleId } from '@/lib/modules'
import { BUNDLES } from './bundles'
import { inventorySettingsStore } from '@/features/inventory/mocks'
import { osHandlers } from './osMock'
import { networkHandlers } from './networkMock'
import { connectionsHandlers } from './connectionsMock'
import { connectorsStore } from '@/mocks/connectors'
import { networkStore } from '@/mocks/network'
import { newSecret, verifyTotp } from './totp'
import { checkCode, clearCode, issueCode, maskEmail, sentBody } from './emailCode'
import { CIDR_RE, compareVersion, fromBase64, isPrivateCidr, MIN_PASSWORD, TIMEZONES } from './util'
import type { AccountSession, AdminUser, Advisory, AuditQuery, AuditRow, ManagedPackage, McpToken, OidcConfig, PrivacyFlow, SetupPayload, UpdateAvailable, UpdateChannel, UpdateComponent, UpdateHistory, UpdatesState } from './types'

const ROLES: Role[] = ['viewer', 'operator', 'admin']
const hex = (n: number) => [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, '0')).join('')
const adminOf = (u: User): AdminUser => ({ id: u.id, name: u.name, email: u.email, role: u.role, twofa: u.twofa, twofa_method: twofaMethodOf(u), disabled: !!u.disabled, created_at: u.created_at, last_login: u.last_login })
/** Mã cài đặt một lần (D-75): hộp thật in nó vào nhật ký lúc khởi động khi chưa có quản trị viên; mock dùng một mã cố định. */
export const MOCK_SETUP_CODE = 'setup-code-demo'
const tempPassword = () => `${hex(3)}-${hex(3)}-${hex(3)}-${hex(2)}`

// ---------- Cài đặt ban đầu ----------
const setupHandlers = [
  // Công khai, chỉ id/tầng/phụ thuộc (không lộ module nào đang bật) để bước chọn gói vẽ được danh sách.
  http.get(`${API}/core/setup/modules`, () => HttpResponse.json({ modules: modulesStore.get().map(({ id, tier, depends }) => ({ id, tier, depends })) })),

  http.post(`${API}/core/setup`, async ({ request }) => {
    if (orgStore.get().setup_complete) return fail(409, 'already_setup', 'This box is already set up. Sign in with the administrator account.')
    const b = await body<SetupPayload>(request)
    if (b.sample === true) {
      // Bản xem thử: mọi bảng về dữ liệu mẫu nguyên bản, đăng nhập luôn quản trị mẫu.
      resetMockDb()
      setDataMode('sample')
      orgStore.update((o) => ({ ...o, setup_complete: true }))
      sessionStore.set({ userId: 'u-admin' })
      audit('core.setup', 'sample')
      return HttpResponse.json({ ok: true })
    }
    // D-75: creating the first administrator needs the code the box printed in its log. It is judged before the
    // other fields, so a wrong code learns nothing about them. The sample path above creates no account.
    if (String(b.setup_code ?? '').trim() !== MOCK_SETUP_CODE) return fail(403, 'invalid_setup_code', 'The setup code is missing or wrong. Find it in the box\'s log: it is printed there each time Vedette starts while setup is open.')
    const org = String(b.org ?? '').trim()
    if (org.length < 2 || org.length > 80) return fail(400, 'invalid_org', 'The organization name is 2 to 80 characters.')
    const a = b.admin ?? { name: '', email: '', password: '' }
    const name = String(a.name ?? '').trim()
    const email = String(a.email ?? '').trim().toLowerCase()
    if (!name || name.length > 80) return fail(400, 'invalid_name', 'Enter the administrator\'s name (at most 80 characters).')
    if (!EMAIL_RE.test(email)) return fail(400, 'invalid_email', 'The email is not valid, for example name@company.com.')
    if (String(a.password ?? '').length < MIN_PASSWORD) return fail(400, 'weak_password', `The password needs at least ${MIN_PASSWORD} characters. A long sentence is easier to remember than random characters.`)
    const lan = (b.lan ?? []).map((x) => String(x).trim()).filter(Boolean)
    if (lan.length < 1 || lan.length > 16) return fail(400, 'invalid_lan', 'Enter 1 to 16 LAN ranges, for example 192.168.10.0/24.')
    const badLan = lan.find((x) => !CIDR_RE.test(x))
    if (badLan) return fail(400, 'invalid_lan', `The range "${badLan}" is not valid. Write it like 192.168.10.0/24.`)
    const pub = lan.find((x) => !isPrivateCidr(x))
    if (pub) return fail(400, 'public_range', `${pub} is not a private range (10.x, 172.16-31.x, 192.168.x). Add public addresses later under External exposure.`)
    let enable: ModuleId[]
    const all = modulesStore.get() // danh sách module mặc định; kiểm tra xong mới dọn kho (lỗi thì không mất gì)
    if (b.bundle === 'smb' || b.bundle === 'mid') enable = BUNDLES[b.bundle]
    else if (b.bundle === 'custom') {
      enable = (b.modules ?? []) as ModuleId[]
      const unknown = enable.find((m) => !all.some((x) => x.id === m))
      if (unknown) return fail(400, 'invalid_module', `No module "${unknown}".`)
      if (!enable.includes('core')) enable = ['core', ...enable]
      for (const id of enable) {
        const lacking = all.find((x) => x.id === id)?.depends.filter((d) => !enable.includes(d)) ?? []
        if (lacking.length) return fail(400, 'missing_dependencies', `Module ${id} also needs: ${lacking.join(', ')}.`)
      }
    } else return fail(400, 'invalid_bundle', 'Choose a module bundle: small, medium or custom.')

    // Cài thật: xoá sạch rồi vào chế độ 'clean' để MỌI module bắt đầu rỗng (không tài khoản, thiết bị, cảnh báo mẫu).
    resetMockDb()
    setDataMode('clean')
    const user: User = { id: newId('u'), name, email, role: 'admin', password: String(a.password), twofa: false, created_at: nowIso(), last_login: nowIso() }
    usersStore.set([user])
    orgStore.update((o) => ({ ...o, name: org, setup_complete: true }))
    modulesStore.set(all.map((m) => ({ ...m, enabled: m.tier === 'core' || enable.includes(m.id), enabled_at: m.tier === 'core' || enable.includes(m.id) ? nowIso() : null })))
    // The LAN ranges asked for here are the ranges of Devices → Scope and sensors (and what Scan reads); the commitment ticked here is that page's commitment.
    inventorySettingsStore.update((st) => ({ ...st, lan_ranges: [...new Set(lan)], scope_confirmed_at: b.commitment ? nowIso() : null, scope_confirmed_by: b.commitment ? email : null }))
    sessionStore.set({ userId: user.id })
    // Same rows, same order as the backend: the administrator, the sign-in, then the setup itself.
    audit('user.create', email, 'role admin')
    audit('auth.login', email)
    audit('core.setup', org, `bundle ${b.bundle}, ${lan.length} ranges${b.commitment ? ', active-scan commitment confirmed' : ''}`)
    return HttpResponse.json({ ok: true })
  }),
]

// ---------- Chung ----------
const generalHandlers = [
  http.get(`${API}/core/general`, () => {
    const denied = guard('viewer')
    if (denied) return denied
    const o = orgStore.get()
    return HttpResponse.json({ name: o.name, timezone: o.timezone })
  }),
  http.put(`${API}/core/general`, async ({ request }) => {
    const denied = guard('admin')
    if (denied) return denied
    const b = await body<{ name: string; timezone: string }>(request)
    const name = String(b.name ?? '').trim()
    if (name.length < 2 || name.length > 80) return fail(400, 'invalid_org', 'The organization name is 2 to 80 characters.')
    if (!TIMEZONES.includes(String(b.timezone))) return fail(400, 'invalid_timezone', 'The time zone is not in the list.')
    orgStore.update((o) => ({ ...o, name, timezone: b.timezone as string }))
    audit('core.general', name, `time zone ${b.timezone}`)
    return HttpResponse.json({ name, timezone: b.timezone })
  }),
]

// ---------- Tài khoản của tôi ----------
const sessionsStore = collection<Record<string, AccountSession[]>>('core_sessions_list', () => ({}))
const totpSecrets = collection<Record<string, string>>('core_totp', () => ({}))
const totpPending = collection<Record<string, string>>('core_totp_pending', () => ({}))

function sessionsOf(userId: string): AccountSession[] {
  const all = sessionsStore.get()
  if (!all[userId]) {
    // Cài sạch: chỉ có phiên đang dùng (không phiên "Firefox trên Windows" mẫu).
    all[userId] = dataMode() === 'clean'
      ? [{ id: newId('s'), device: 'This browser', ip: '127.0.0.1', started_at: nowIso(), last_seen: nowIso(), current: true }]
      : [
        { id: newId('s'), device: 'This browser', ip: '192.168.10.35', started_at: nowIso(), last_seen: nowIso(), current: true },
        { id: newId('s'), device: 'Firefox on Windows', ip: '192.168.10.61', started_at: daysAgo(2), last_seen: daysAgo(1, 3), current: false },
      ]
    sessionsStore.set(all)
  }
  return all[userId]
}

const accountHandlers = [
  http.get(`${API}/core/account`, () => {
    const denied = guard('viewer')
    if (denied) return denied
    const u = currentUser()!
    const reason = !isOn('notify') ? 'module_off' : !emailChannelReady() ? 'channel_not_ready' : null
    return HttpResponse.json({ user: { id: u.id, name: u.name, email: u.email, role: u.role, twofa: u.twofa, twofa_method: twofaMethodOf(u), created_at: u.created_at, last_login: u.last_login }, twofa_email: { available: reason === null, reason, sent_to: maskEmail(u.email) }, sessions: sessionsOf(u.id) })
  }),
  http.patch(`${API}/core/account`, async ({ request }) => {
    const denied = guard('viewer')
    if (denied) return denied
    const u = currentUser()!
    const b = await body<{ name: string }>(request)
    const name = String(b.name ?? '').trim()
    if (!name || name.length > 80) return fail(400, 'invalid_name', 'Enter a display name (at most 80 characters).')
    usersStore.update((l) => l.map((x) => (x.id === u.id ? { ...x, name } : x)))
    audit('account.profile', u.email, 'display name changed')
    return HttpResponse.json({ ok: true })
  }),
  http.post(`${API}/core/account/password`, async ({ request }) => {
    const denied = guard('viewer')
    if (denied) return denied
    const u = currentUser()!
    const b = await body<{ current: string; next: string }>(request)
    if (b.current !== u.password) return fail(400, 'wrong_password', 'The current password is wrong.')
    const next = String(b.next ?? '')
    if (next.length < MIN_PASSWORD) return fail(400, 'weak_password', `The new password needs at least ${MIN_PASSWORD} characters.`)
    if (next === u.password) return fail(400, 'same_password', 'The new password must differ from the current one.')
    usersStore.update((l) => l.map((x) => (x.id === u.id ? { ...x, password: next } : x)))
    audit('account.password', u.email)
    return HttpResponse.json({ ok: true })
  }),
  http.post(`${API}/core/account/2fa/start`, async ({ request }) => {
    const denied = guard('viewer')
    if (denied) return denied
    const u = currentUser()!
    // D-76: turning two-step on needs the current password, like turning it off.
    if ((await body<{ password: string }>(request)).password !== u.password) return fail(400, 'wrong_password', 'Wrong password. The password is needed to turn on two-factor authentication.')
    if (u.twofa) return fail(409, 'already_on', 'Two-step sign-in is already on. Turn it off first to set up the other method.')
    const secret = newSecret()
    totpPending.update((p) => ({ ...p, [u.id]: secret }))
    const otpauth = `otpauth://totp/Vedette:${encodeURIComponent(u.email)}?secret=${secret}&issuer=Vedette&algorithm=SHA1&digits=6&period=30`
    return HttpResponse.json({ secret, otpauth })
  }),
  http.post(`${API}/core/account/2fa/confirm`, async ({ request }) => {
    const denied = guard('viewer')
    if (denied) return denied
    const u = currentUser()!
    const secret = totpPending.get()[u.id]
    if (!secret) return fail(409, 'no_pending', 'No key is waiting for confirmation. Click "Turn on two-factor authentication" to create one.')
    const code = String((await body<{ code: string }>(request)).code ?? '').replace(/\s/g, '')
    if (!/^\d{6}$/.test(code)) return fail(400, 'invalid_code', 'The code is 6 digits from your authenticator app.')
    if (!(await verifyTotp(secret, code))) return fail(400, 'wrong_code', 'Wrong code. Check the time on your phone and enter a new code.')
    totpSecrets.update((s) => ({ ...s, [u.id]: secret }))
    totpPending.update((p) => { const n = { ...p }; delete n[u.id]; return n })
    usersStore.update((l) => l.map((x) => (x.id === u.id ? { ...x, twofa: true, twofa_method: 'app' } : x)))
    audit('account.2fa_on', u.email, 'authenticator app')
    return HttpResponse.json({ ok: true })
  }),
  http.post(`${API}/core/account/2fa/email/start`, async ({ request }) => {
    const denied = guard('viewer')
    if (denied) return denied
    const u = currentUser()!
    if ((await body<{ password: string }>(request)).password !== u.password) return fail(400, 'wrong_password', 'Wrong password. The password is needed to turn on two-factor authentication.')
    if (u.twofa) return fail(409, 'already_on', 'Two-step sign-in is already on. Turn it off first to set up the other method.')
    if (!emailChannelReady()) return fail(409, 'email_channel_not_ready', 'Email codes need the email alert channel. An administrator has to set it up and turn it on first.')
    const sent = issueCode(u.id)
    if ('error' in sent) return sent.error
    return HttpResponse.json(sentBody(u.email, sent))
  }),
  http.post(`${API}/core/account/2fa/email/confirm`, async ({ request }) => {
    const denied = guard('viewer')
    if (denied) return denied
    const u = currentUser()!
    if (u.twofa) return fail(409, 'already_on', 'Two-step sign-in is already on. Turn it off first to set up the other method.')
    if (!emailChannelReady()) return fail(409, 'email_channel_not_ready', 'Email codes need the email alert channel. An administrator has to set it up and turn it on first.')
    const code = String((await body<{ code: string }>(request)).code ?? '').replace(/\s/g, '')
    const bad = checkCode(u.id, code)
    if (bad) return bad
    usersStore.update((l) => l.map((x) => (x.id === u.id ? { ...x, twofa: true, twofa_method: 'email' } : x)))
    audit('account.2fa_on', u.email, 'email code')
    return HttpResponse.json({ ok: true })
  }),
  http.post(`${API}/core/account/2fa/disable`, async ({ request }) => {
    const denied = guard('viewer')
    if (denied) return denied
    const u = currentUser()!
    const b = await body<{ password: string }>(request)
    if (b.password !== u.password) return fail(400, 'wrong_password', 'Wrong password. The password is needed to turn off two-factor authentication.')
    totpSecrets.update((s) => { const n = { ...s }; delete n[u.id]; return n })
    usersStore.update((l) => l.map((x) => (x.id === u.id ? { ...x, twofa: false, twofa_method: null } : x)))
    clearCode(u.id)
    audit('account.2fa_off', u.email)
    return HttpResponse.json({ ok: true })
  }),
  http.delete(`${API}/core/account/sessions/:id`, ({ params }) => {
    const denied = guard('viewer')
    if (denied) return denied
    const u = currentUser()!
    const list = sessionsOf(u.id)
    const s = list.find((x) => x.id === params.id)
    if (!s) return fail(404, 'not_found', 'No such session.')
    if (s.current) return fail(400, 'current_session', 'This is the session you are using. Use "Sign out" in the account menu.')
    sessionsStore.update((all) => ({ ...all, [u.id]: list.filter((x) => x.id !== s.id) }))
    audit('account.session_revoke', u.email, s.device)
    return new HttpResponse(null, { status: 204 })
  }),
  http.post(`${API}/core/account/sessions/revoke-others`, () => {
    const denied = guard('viewer')
    if (denied) return denied
    const u = currentUser()!
    const list = sessionsOf(u.id)
    sessionsStore.update((all) => ({ ...all, [u.id]: list.filter((x) => x.current) }))
    audit('account.session_revoke', u.email, 'all other sessions')
    return HttpResponse.json({ ok: true, revoked: list.filter((x) => !x.current).length })
  }),
]

// ---------- Người dùng, OIDC ----------
const oidcStore = collection<{ issuer: string; client_id: string; secret: string; default_role: Role; role_map: { group: string; role: Role }[] }>('oidc_config', () => ({ issuer: '', client_id: '', secret: '', default_role: 'viewer', role_map: [] }))
const oidcView = (): OidcConfig => { const c = oidcStore.get(); return { issuer: c.issuer, client_id: c.client_id, secret_last4: c.secret ? c.secret.slice(-4) : null, default_role: c.default_role, role_map: c.role_map } }
const activeAdmins = (l: User[]) => l.filter((x) => x.role === 'admin' && !x.disabled).length

const usersHandlers = [
  http.get(`${API}/core/users`, () => {
    const denied = guard('admin')
    if (denied) return denied
    return HttpResponse.json({ items: usersStore.get().map(adminOf) })
  }),
  http.post(`${API}/core/users`, async ({ request }) => {
    const denied = guard('admin')
    if (denied) return denied
    const b = await body<{ name: string; email: string; role: Role }>(request)
    const name = String(b.name ?? '').trim()
    const email = String(b.email ?? '').trim().toLowerCase()
    if (!name || name.length > 80) return fail(400, 'invalid_name', 'Enter the user\'s name (at most 80 characters).')
    if (!EMAIL_RE.test(email)) return fail(400, 'invalid_email', 'The email is not valid, for example name@company.com.')
    if (!ROLES.includes(b.role as Role)) return fail(400, 'invalid_role', 'Choose a role: view only, operator or administrator.')
    if (usersStore.get().some((x) => x.email === email)) return fail(409, 'duplicate', 'This email already has an account.')
    const temp = tempPassword()
    const u: User = { id: newId('u'), name, email, role: b.role as Role, password: temp, twofa: false, created_at: nowIso(), last_login: null }
    usersStore.update((l) => [...l, u])
    audit('user.create', email, `vai ${u.role}`)
    return HttpResponse.json({ user: adminOf(u), temp_password: temp }, { status: 201 })
  }),
  http.patch(`${API}/core/users/:id`, async ({ params, request }) => {
    const denied = guard('admin')
    if (denied) return denied
    const me = currentUser()!
    const list = usersStore.get()
    const target = list.find((x) => x.id === params.id)
    if (!target) return fail(404, 'not_found', 'No such user.')
    const b = await body<{ role: Role; disabled: boolean }>(request)
    const next: User = { ...target }
    if (b.role !== undefined) {
      if (!ROLES.includes(b.role)) return fail(400, 'invalid_role', 'Choose a role: view only, operator or administrator.')
      next.role = b.role
    }
    if (b.disabled !== undefined) {
      if (b.disabled && target.id === me.id) return fail(400, 'self_disable', 'You cannot disable the account you are using. Ask another administrator.')
      next.disabled = b.disabled === true
    }
    const after = list.map((x) => (x.id === target.id ? next : x))
    if (activeAdmins(after) < 1) return fail(400, 'last_admin', 'At least one active administrator must remain. Add another administrator first.')
    usersStore.set(after)
    if (next.role !== target.role) audit('user.role', target.email, `${target.role} sang ${next.role}`)
    if (!!next.disabled !== !!target.disabled) audit(next.disabled ? 'user.disable' : 'user.enable', target.email)
    return HttpResponse.json({ user: adminOf(next) })
  }),
  http.post(`${API}/core/users/:id/2fa/reset`, ({ params }) => {
    const denied = guard('admin')
    if (denied) return denied
    const me = currentUser()!
    const target = usersStore.get().find((x) => x.id === params.id)
    if (!target) return fail(404, 'not_found', 'No such user.')
    if (target.id === me.id) return fail(400, 'self_reset', 'You cannot reset your own two-step sign-in here. Use My account instead.')
    const was = twofaMethodOf(target)
    if (!was) return fail(409, 'not_on', 'Two-step sign-in is already off for this user.')
    totpSecrets.update((s) => { const n = { ...s }; delete n[target.id]; return n })
    totpPending.update((p) => { const n = { ...p }; delete n[target.id]; return n })
    clearCode(target.id)
    usersStore.update((l) => l.map((x) => (x.id === target.id ? { ...x, twofa: false, twofa_method: null } : x)))
    audit('user.2fa_reset', target.email, `was ${was === 'app' ? 'authenticator app' : 'email code'}`)
    return HttpResponse.json({ ok: true })
  }),
  http.post(`${API}/core/users/:id/reset-password`, ({ params }) => {
    const denied = guard('admin')
    if (denied) return denied
    const target = usersStore.get().find((x) => x.id === params.id)
    if (!target) return fail(404, 'not_found', 'No such user.')
    const temp = tempPassword()
    usersStore.update((l) => l.map((x) => (x.id === target.id ? { ...x, password: temp } : x)))
    sessionsStore.update((all) => { const n = { ...all }; delete n[target.id]; return n })
    audit('user.reset_password', target.email)
    return HttpResponse.json({ temp_password: temp })
  }),

  http.get(`${API}/core/oidc`, () => {
    const denied = guard('admin')
    if (denied) return denied
    return HttpResponse.json(oidcView())
  }),
  http.put(`${API}/core/oidc`, async ({ request }) => {
    const denied = guard('admin')
    if (denied) return denied
    const b = await body<{ issuer: string; client_id: string; client_secret: string; default_role: Role; role_map: { group: string; role: Role }[] }>(request)
    const cur = oidcStore.get()
    let issuer = String(b.issuer ?? '').trim().replace(/\/+$/, '')
    try { if (new URL(issuer).protocol !== 'https:') throw new Error('x') } catch { issuer = '' }
    if (!issuer) return fail(400, 'invalid_issuer', 'The issuer must be an https address, for example https://sso.example.com/realms/main.')
    const clientId = String(b.client_id ?? '').trim()
    if (!clientId || clientId.length > 200) return fail(400, 'invalid_client', 'Enter the Client ID (at most 200 characters).')
    const secret = b.client_secret ? String(b.client_secret) : cur.secret
    if (secret.length < 8) return fail(400, 'invalid_secret', 'Enter the Client secret (at least 8 characters).')
    if (!ROLES.includes(b.default_role as Role)) return fail(400, 'invalid_role', 'Choose a default role.')
    const map = (b.role_map ?? []).filter((m) => String(m.group ?? '').trim())
    if (map.length > 10) return fail(400, 'too_many', 'At most 10 role mapping rows.')
    if (map.some((m) => !ROLES.includes(m.role))) return fail(400, 'invalid_role', 'One mapping row has an invalid role.')
    oidcStore.set({ issuer, client_id: clientId, secret, default_role: b.default_role as Role, role_map: map.map((m) => ({ group: m.group.trim(), role: m.role })) })
    audit('oidc.update', issuer)
    return HttpResponse.json(oidcView())
  }),
  http.post(`${API}/core/oidc/test`, () => {
    const denied = guard('admin')
    if (denied) return denied
    const c = oidcStore.get()
    if (!c.issuer) return fail(400, 'not_configured', 'Save the OIDC configuration before testing.')
    const host = new URL(c.issuer).hostname
    audit('oidc.test', c.issuer)
    if (host.includes('invalid') || host.endsWith('.local')) return fail(502, 'discovery_failed', `Cannot read ${c.issuer}/.well-known/openid-configuration. Check the issuer and the network path from the box to the IdP.`)
    return HttpResponse.json({ ok: true, endpoints: { authorization: `${c.issuer}/protocol/openid-connect/auth`, token: `${c.issuer}/protocol/openid-connect/token`, jwks: `${c.issuer}/protocol/openid-connect/certs` } })
  }),

  // Công khai: trang đăng nhập hỏi để biết có nút SSO không.
  http.get(`${API}/core/auth-options`, () => HttpResponse.json({ oidc: isOn('auth-oidc') && !!oidcStore.get().issuer })),
  // Mock cho vòng chuyển hướng IdP: đăng nhập thẳng bằng một tài khoản SSO mẫu với vai mặc định. Bản thật dùng authorization code + PKCE.
  http.post(`${API}/core/sso/login`, () => {
    if (!isOn('auth-oidc') || !oidcStore.get().issuer) return fail(400, 'oidc_off', 'SSO sign-in is not enabled. Ask an administrator to enable it under Settings, Users.')
    const cfg = oidcStore.get()
    const email = 'sso.user@acme.example'
    let u = usersStore.get().find((x) => x.email === email)
    if (u?.disabled) return fail(403, 'disabled', 'This account has been disabled.')
    if (!u) {
      u = { id: newId('u'), name: 'SSO user', email, role: cfg.default_role, password: tempPassword(), twofa: false, created_at: nowIso(), last_login: nowIso() }
      usersStore.update((l) => [...l, u as User])
    }
    sessionStore.set({ userId: u.id })
    audit('auth.login', email, 'SSO')
    return HttpResponse.json({ ok: true })
  }),
]

// ---------- Nhật ký kiểm toán ----------
function filterAudit(q: Partial<AuditQuery>): AuditRow[] {
  const text = (q.q ?? '').trim().toLowerCase()
  const from = q.from ? new Date(`${q.from}T00:00:00`).getTime() : -Infinity
  const to = q.to ? new Date(`${q.to}T23:59:59.999`).getTime() : Infinity
  return auditStore.get().map(({ prev_hash: _p, hash: _h, detail, ...r }): AuditRow => (detail === null ? r : { ...r, detail })).filter((r) => {
    const t = new Date(r.ts).getTime()
    if (t < from || t > to) return false
    if (q.user && r.user !== q.user) return false
    if (q.group && r.action.split('.')[0] !== q.group) return false
    if (text && !`${r.action} ${r.target} ${r.detail ?? ''} ${r.user}`.toLowerCase().includes(text)) return false
    return true
  })
}
const qOf = (url: string): Partial<AuditQuery> => { const p = new URL(url).searchParams; return { q: p.get('q') ?? '', user: p.get('user') ?? '', group: p.get('group') ?? '', from: p.get('from') ?? '', to: p.get('to') ?? '' } }
/** Ô CSV bắt đầu bằng = + - @ bị Excel hiểu là công thức: thêm dấu nháy để thành chữ. */
const csvCell = (v: string) => { const s = /^[=+\-@\t\r]/.test(v) ? `'${v}` : v; return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s }

const auditHandlers = [
  http.get(`${API}/core/audit`, ({ request }) => {
    const denied = guard('admin')
    if (denied) return denied
    const all = auditStore.get()
    const rows = filterAudit(qOf(request.url))
    return HttpResponse.json({ items: rows.slice(0, 200), total: rows.length, users: [...new Set(all.map((r) => r.user))].sort(), groups: [...new Set(all.map((r) => r.action.split('.')[0] ?? ''))].sort() })
  }),
  http.get(`${API}/core/audit/export`, ({ request }) => {
    const denied = guard('admin')
    if (denied) return denied
    const rows = filterAudit(qOf(request.url))
    const csv = ['time,user,action,target,detail', ...rows.map((r) => [r.ts, r.user, r.action, r.target, r.detail ?? ''].map(csvCell).join(','))].join('\r\n')
    return new HttpResponse(`﻿${csv}\r\n`, { headers: { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename=vedette-audit.csv' } })
  }),
]

// ---------- Cập nhật ----------
const CATALOG: UpdateAvailable[] = [
  { component: 'software', version: '0.9.4', channel: 'stable', size_kb: 18200, note: 'Fixes a hang when receiving oversized syslog packets (VSA-2026-003).' },
  { component: 'software', version: '0.10.0-beta.1', channel: 'beta', size_kb: 19100, note: 'Preview: new settings interface.' },
  { component: 'data', version: '20261106.12', channel: 'stable', size_kb: 640, note: 'Exploited-vulnerability data, 12-hour update.' },
  { component: 'pack-mitigation', version: '2026.11.06', channel: 'stable', size_kb: 410, note: 'Adds mitigation guidance for Ivanti Connect Secure.' },
  { component: 'pack-parsers', version: '1.4.1', channel: 'stable', size_kb: 96, note: 'Fixes how FortiGate 7.4 logs are read.' },
]
const comp = (id: string, kind: UpdateComponent['kind'], version: string, previous: string | null, ago: number): UpdateComponent => ({ id, kind, version, previous, installed_at: daysAgo(ago), signature: 'valid' })
const updStore = collection<{ channel: UpdateChannel; mode: 'auto' | 'manual'; components: UpdateComponent[]; history: UpdateHistory[]; last_check: string }>('core_updates', () => ({
  channel: 'stable',
  mode: 'manual',
  last_check: daysAgo(0, 2),
  components: [comp('software', 'software', '0.9.3', '0.9.2', 9), comp('data', 'data', '20261106.08', '20261106.04', 0), comp('pack-mitigation', 'content', '2026.11.04', '2026.10.28', 2), comp('pack-nuclei', 'content', '2026.11.05', '2026.11.01', 1), comp('pack-parsers', 'content', '1.4.0', '1.3.2', 14)],
  history: [
    { id: 'h8', ts: daysAgo(0, 4), component: 'data', from: '20261106.04', to: '20261106.08', action: 'update', user: 'system' },
    { id: 'h7', ts: daysAgo(1), component: 'pack-nuclei', from: '2026.11.01', to: '2026.11.05', action: 'update', user: 'system' },
    { id: 'h6', ts: daysAgo(2), component: 'pack-mitigation', from: '2026.10.28', to: '2026.11.04', action: 'update', user: 'admin@acme.example' },
    { id: 'h5', ts: daysAgo(9), component: 'software', from: '0.9.2', to: '0.9.3', action: 'update', user: 'admin@acme.example' },
    { id: 'h4', ts: daysAgo(14), component: 'pack-parsers', from: '1.3.2', to: '1.4.0', action: 'update', user: 'system' },
  ],
}), () => ({
  // Cài sạch: bản vừa cài, chưa có lịch sử cập nhật và chưa có "bản trước" để quay về.
  channel: 'stable',
  mode: 'manual',
  last_check: nowIso(),
  components: [comp('software', 'software', '0.9.3', null, 0), comp('data', 'data', '20261106.08', null, 0), comp('pack-mitigation', 'content', '2026.11.04', null, 0), comp('pack-nuclei', 'content', '2026.11.05', null, 0), comp('pack-parsers', 'content', '1.4.0', null, 0)],
  history: [],
}))
const privacyStore = collection<{ install_id: string; telemetry: boolean; last_sent: string | null; update_check: boolean }>('core_privacy', () => ({ install_id: `ins-${hex(8)}`, telemetry: false, last_sent: daysAgo(0, 0.7), update_check: true }),
  () => ({ install_id: `ins-${hex(8)}`, telemetry: false, last_sent: null, update_check: true }))

const ADVISORIES: Omit<Advisory, 'status'>[] = [
  { id: 'VSA-2026-003', title: 'Receiving an oversized syslog packet can stop the log receiver', severity: 'high', published: '2026-11-03', fixed_in: '0.9.4', summary: 'Someone on the same network sends an unusually long UDP 514 packet and the log receiver process stops. No data can be read. Update to 0.9.4, or only allow the IPs of your log-sending devices.' },
  { id: 'VSA-2026-002', title: 'The YAML library can use a lot of memory', severity: 'medium', published: '2026-10-12', fixed_in: '0.9.2', summary: 'A configuration file entered by an administrator can make the process use all memory. Fixed in 0.9.2.' },
]

/** Phiên bản phần mềm đang chạy. */
export const softwareVersion = () => updStore.get().components.find((c) => c.id === 'software')!.version

/** Gói do Vedette ghim và cập nhật cùng bản phát hành (D-53); không gói nào tự lấy từ kho hệ điều hành. */
function managedOf(components: UpdateComponent[], available: UpdateAvailable[]): ManagedPackage[] {
  const nuclei = components.find((c) => c.id === 'pack-nuclei')?.version ?? '–'
  const pending = available.some((a) => a.component === 'pack-nuclei')
  return [
    { id: 'nmap', name: 'nmap', version: '7.95', status: 'ok' },
    { id: 'opencanary', name: 'OpenCanary', version: '0.9.4', status: 'ok' },
    { id: 'osquery', name: 'osquery mirror files', version: '5.12.1', status: 'ok' },
    { id: 'nuclei', name: 'nuclei templates', version: nuclei, status: pending ? 'update_pending' : 'ok' },
  ]
}

function updView(): UpdatesState {
  const s = updStore.get()
  const p = privacyStore.get()
  const sw = s.components.find((c) => c.id === 'software')!.version
  const available = CATALOG.filter((a) => {
    if (a.channel === 'beta' && s.channel !== 'beta') return false
    const cur = s.components.find((c) => c.id === a.component)
    return !cur || compareVersion(a.version, cur.version) > 0
  })
  // chỉ giữ bản mới nhất cho mỗi thành phần
  const latest = available.filter((a) => !available.some((b) => b.component === a.component && compareVersion(b.version, a.version) > 0))
  return { channel: s.channel, mode: s.mode, check_enabled: p.update_check, last_check: s.last_check, components: s.components, available: latest, history: s.history.slice(0, 20), advisories: ADVISORIES.map((a) => ({ ...a, status: compareVersion(sw, a.fixed_in) < 0 ? 'affected' : 'fixed' })), managed: managedOf(s.components, latest) }
}

function applyOne(component: string, version: string, action: UpdateHistory['action'], user: string) {
  updStore.update((s) => {
    const cur = s.components.find((c) => c.id === component)
    if (!cur) return s
    const entry: UpdateHistory = { id: newId('h'), ts: nowIso(), component, from: cur.version, to: version, action, user }
    return { ...s, components: s.components.map((c) => (c.id === component ? { ...c, previous: c.version, version, installed_at: nowIso(), signature: 'valid' } : c)), history: [entry, ...s.history].slice(0, 100) }
  })
}

/** Chữ ký mô phỏng (FNV-1a). Bản thật: minisign/cosign (UPDATES.md §1). */
export function mockSign(text: string): string {
  let h = 0x811c9dc5
  for (let i = 0; i < text.length; i++) { h ^= text.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0 }
  return `mock-sig-${h.toString(16).padStart(8, '0')}`
}

const updatesHandlers = [
  ...osHandlers({
    updateCheckOn: () => privacyStore.get().update_check,
    addHistory: (e) => updStore.update((s) => ({ ...s, history: [e, ...s.history].slice(0, 100) })),
  }),
  http.get(`${API}/core/updates`, () => {
    const denied = guard('viewer')
    if (denied) return denied
    return HttpResponse.json(updView())
  }),
  http.patch(`${API}/core/updates`, async ({ request }) => {
    const denied = guard('admin')
    if (denied) return denied
    const b = await body<{ channel: UpdateChannel; mode: 'auto' | 'manual' }>(request)
    if (b.channel !== undefined && b.channel !== 'stable' && b.channel !== 'beta') return fail(400, 'invalid_channel', 'The channel is stable or beta.')
    if (b.mode !== undefined && b.mode !== 'auto' && b.mode !== 'manual') return fail(400, 'invalid_mode', 'The mode is automatic or manual.')
    updStore.update((s) => ({ ...s, channel: b.channel ?? s.channel, mode: b.mode ?? s.mode }))
    audit('update.settings', 'updates', `channel ${b.channel ?? '-'}, mode ${b.mode ?? '-'}`)
    return HttpResponse.json(updView())
  }),
  http.post(`${API}/core/updates/check`, () => {
    const denied = guard('operator')
    if (denied) return denied
    if (!privacyStore.get().update_check) return fail(409, 'check_off', 'Update checks are off under Privacy. Turn them on or import an offline bundle.')
    updStore.update((s) => ({ ...s, last_check: nowIso() }))
    let applied = 0
    if (updStore.get().mode === 'auto') for (const a of updView().available) { applyOne(a.component, a.version, 'update', 'system'); applied++ }
    audit('update.check', 'updates', applied ? `auto-installed ${applied}` : undefined)
    return HttpResponse.json({ ...updView(), applied })
  }),
  http.post(`${API}/core/updates/apply`, async ({ request }) => {
    const denied = guard('admin')
    if (denied) return denied
    const b = await body<{ component: string }>(request)
    const a = updView().available.find((x) => x.component === b.component)
    if (!a) return fail(404, 'no_update', 'There is no new version of this component. Click "Check now".')
    applyOne(a.component, a.version, 'update', currentUser()!.email)
    audit('update.apply', a.component, `to ${a.version}`)
    return HttpResponse.json(updView())
  }),
  http.post(`${API}/core/updates/rollback`, async ({ request }) => {
    const denied = guard('admin')
    if (denied) return denied
    const b = await body<{ component: string }>(request)
    const cur = updStore.get().components.find((c) => c.id === b.component)
    if (!cur) return fail(404, 'not_found', 'No such component.')
    if (!cur.previous) return fail(409, 'no_previous', 'No previous version to go back to.')
    const prev = cur.previous
    updStore.update((s) => ({
      ...s,
      mode: 'manual',
      components: s.components.map((c) => (c.id === cur.id ? { ...c, version: prev, previous: null, installed_at: nowIso() } : c)),
      history: [{ id: newId('h'), ts: nowIso(), component: cur.id, from: cur.version, to: prev, action: 'rollback' as const, user: currentUser()!.email }, ...s.history].slice(0, 100),
    }))
    audit('update.rollback', cur.id, `${cur.version} back to ${prev}`)
    return HttpResponse.json(updView())
  }),
  http.get(`${API}/core/updates/bundle`, () => {
    const denied = guard('operator')
    if (denied) return denied
    const items = CATALOG.filter((a) => a.channel === 'stable' || updStore.get().channel === 'beta').map((a) => ({ component: a.component, version: a.version, channel: a.channel }))
    const created_at = nowIso()
    const bundle = { format: 'vedette-bundle/1', created_at, items, signature: mockSign(JSON.stringify(items) + created_at) }
    audit('update.bundle_export', 'bundle', `${items.length} items`)
    return new HttpResponse(JSON.stringify(bundle, null, 2), { headers: { 'Content-Type': 'application/json', 'Content-Disposition': 'attachment; filename=vedette-bundle.json' } })
  }),
  http.post(`${API}/core/updates/bundle`, async ({ request }) => {
    const denied = guard('admin')
    if (denied) return denied
    const b = await body<{ name: string; size: number; sha256: string; content: string }>(request)
    if (!b.content) return fail(400, 'empty', 'No bundle file chosen.')
    if (Number(b.size) > 5 * 1024 * 1024) return fail(400, 'too_large', 'The file is larger than 5 MB. A real bundle is smaller; check the file.')
    let bundle: { format?: string; created_at?: string; items?: { component: string; version: string }[]; signature?: string }
    try { bundle = JSON.parse(fromBase64(String(b.content))) as typeof bundle } catch { return fail(400, 'not_bundle', 'The file is not a Vedette bundle (content cannot be read).') }
    if (bundle.format !== 'vedette-bundle/1' || !Array.isArray(bundle.items)) return fail(400, 'not_bundle', 'The file is not a Vedette bundle (wrong format).')
    if (bundle.signature !== mockSign(JSON.stringify(bundle.items) + (bundle.created_at ?? ''))) {
      audit('update.bundle_import', String(b.name ?? 'bundle'), 'rejected: invalid signature')
      return fail(400, 'bad_signature', 'Invalid signature. The bundle was modified or not signed by the project. The box does not install unsigned packages.')
    }
    let applied = 0
    for (const it of bundle.items) {
      const cur = updStore.get().components.find((c) => c.id === it.component)
      if (cur && compareVersion(it.version, cur.version) > 0) { applyOne(it.component, it.version, 'bundle', currentUser()!.email); applied++ }
    }
    audit('update.bundle_import', String(b.name ?? 'bundle'), `installed ${applied}`)
    return HttpResponse.json({ applied, state: updView() })
  }),
]

// ---------- Quyền riêng tư ----------
function telemetryPayload() {
  const clean = dataMode() === 'clean'
  const counts: Record<string, number> = {}
  for (const a of assetsStore.get()) for (const s of a.software) {
    const k = `${s.vendor}:${s.product}:${s.version ?? 'unknown'}`.toLowerCase().replace(/\s+/g, '-')
    counts[k] = (counts[k] ?? 0) + 1
  }
  const hour = new Date(); hour.setMinutes(0, 0, 0)
  return {
    schema: 1,
    install_id: privacyStore.get().install_id,
    country: 'VN',
    version: updStore.get().components.find((c) => c.id === 'software')!.version,
    hour: hour.toISOString(),
    // Cài sạch: hộp chưa ghi nhận gì nên mọi số đếm là 0 (bản mẫu hiện số minh hoạ).
    honeypot_touches: clean ? { smb: 0, rdp: 0, ssh: 0 } : { smb: 0, rdp: 2, ssh: 1 },
    ioc_connections: clean ? 0 : 3,
    cve_matches: clean ? {} : { 'CVE-2022-27593': 1 }, // counts of matches between devices and exploited vulnerabilities, by CVE (there is no IDS, D-43)
    // A product found on one device only is left out (PRIVACY.md flow 2): a rare product must not identify a small company.
    device_counts: Object.fromEntries(Object.entries(counts).filter(([, n]) => n >= 2).sort(([a], [b]) => a.localeCompare(b))),
  }
}

/** Flow 10: time requests leave the LAN unless every NTP server is an internal address. Host names count as public (cannot tell from here). */
function ntpPublic() {
  const n = networkStore.get().ntp
  return n.mode === 'default' || n.servers.some((x) => !isPrivateCidr(`${x}/32`))
}

function privacyView() {
  const p = privacyStore.get()
  const ai = aiConfigStore.get().configured && isOn('ai')
  const flows: PrivacyFlow[] = [
    { id: 1, state: 'on', control: 'reason' },
    { id: 2, state: p.telemetry ? 'on' : 'off', control: 'switch' },
    { id: 3, state: ai ? 'on' : 'off', control: 'reason', configured: ai },
    { id: 4, state: 'conditional', control: 'reason' },
    { id: 5, state: 'conditional', control: 'reason' },
    { id: 6, state: p.update_check ? 'on' : 'off', control: 'switch' },
    { id: 7, state: 'conditional', control: 'reason' },
    { id: 8, state: isOn('ai') ? 'conditional' : 'off', control: 'reason' },
    { id: 9, state: isOn('exposure') ? 'on' : 'off', control: 'reason' },
    { id: 10, state: ntpPublic() ? 'on' : 'off', control: 'reason' },
    { id: 11, state: isOn('auth-oidc') && !!oidcStore.get().issuer ? 'conditional' : 'off', control: 'reason' },
    { id: 12, state: connectorsStore.get().some((c) => c.enabled && c.kind !== 'mcp-stdio') ? 'on' : 'off', control: 'reason' },
  ]
  return { flows, telemetry: { enabled: p.telemetry, last_sent: p.last_sent, payload: telemetryPayload() }, update_check: p.update_check }
}

const privacyHandlers = [
  http.get(`${API}/core/privacy`, () => {
    const denied = guard('viewer')
    if (denied) return denied
    return HttpResponse.json(privacyView())
  }),
  http.patch(`${API}/core/privacy`, async ({ request }) => {
    const denied = guard('admin')
    if (denied) return denied
    const b = await body<{ telemetry: boolean; update_check: boolean }>(request)
    if (b.telemetry !== undefined && typeof b.telemetry !== 'boolean') return fail(400, 'invalid', 'The switch value must be on or off.')
    if (b.update_check !== undefined && typeof b.update_check !== 'boolean') return fail(400, 'invalid', 'The switch value must be on or off.')
    // D-154: nothing sends the anonymous signal, so it cannot be turned on (the backend answers the same).
    if (b.telemetry === true) return fail(400, 'telemetry_unavailable', 'This version of Vedette does not send an anonymous signal, so it cannot be turned on.')
    privacyStore.update((p) => ({ ...p, telemetry: b.telemetry ?? p.telemetry, update_check: b.update_check ?? p.update_check }))
    if (b.telemetry !== undefined) audit('privacy.telemetry', 'anonymous signal', b.telemetry ? 'on' : 'off')
    if (b.update_check !== undefined) audit('privacy.update_check', 'update check', b.update_check ? 'on' : 'off')
    return HttpResponse.json(privacyView())
  }),
]

// ---------- MCP ----------
const MCP_SCOPES = ['assets', 'findings', 'feeds']
const MCP_TOOLS = [
  { name: 'list_assets', scope: 'assets' }, { name: 'get_asset', scope: 'assets' },
  { name: 'list_findings', scope: 'findings' }, { name: 'get_finding', scope: 'findings' },
  { name: 'lookup_cve', scope: 'feeds' }, { name: 'lookup_ioc', scope: 'feeds' }, { name: 'hot_vulnerabilities', scope: 'feeds' },
]
const mcpTokens = collection<(McpToken & { secret_hash: string })[]>('mcp_tokens', () => [])
const mcpView = () => ({ enabled: isOn('mcp-server'), bind: '127.0.0.1', port: 8765, endpoint: 'http://127.0.0.1:8765/mcp', tokens: mcpTokens.get().map(({ secret_hash: _h, ...t }) => t), tools: MCP_TOOLS, scopes: MCP_SCOPES })

const mcpHandlers = [
  http.get(`${API}/core/mcp`, () => {
    const denied = guard('admin')
    if (denied) return denied
    return HttpResponse.json(mcpView())
  }),
  http.patch(`${API}/core/mcp`, async ({ request }) => {
    const denied = guard('admin')
    if (denied) return denied
    const b = await body<{ enabled: boolean }>(request)
    if (typeof b.enabled !== 'boolean') return fail(400, 'invalid', 'The value must be on or off.')
    modulesStore.update((l) => l.map((m) => (m.id === 'mcp-server' ? { ...m, enabled: b.enabled as boolean, enabled_at: b.enabled ? nowIso() : m.enabled_at } : m)))
    audit(b.enabled ? 'module.enable' : 'module.disable', 'mcp-server')
    return HttpResponse.json(mcpView())
  }),
  http.post(`${API}/core/mcp/tokens`, async ({ request }) => {
    const denied = guard('admin')
    if (denied) return denied
    if (!isOn('mcp-server')) return fail(409, 'module_off', 'Turn on the MCP server before creating a token.')
    const b = await body<{ name: string; scopes: string[] }>(request)
    const name = String(b.name ?? '').trim()
    if (!/^[\p{L}\p{N} _.'-]{1,64}$/u.test(name)) return fail(400, 'invalid_name', 'The token name is 1 to 64 characters: letters, digits, spaces, apostrophes, dashes.')
    const scopes = [...new Set(b.scopes ?? [])]
    if (!scopes.length || scopes.some((s) => !MCP_SCOPES.includes(s))) return fail(400, 'invalid_scopes', 'Choose at least one read scope: devices, findings or vulnerability feeds.')
    const secret = `vmcp_${hex(16)}`
    const item: McpToken & { secret_hash: string } = { id: newId('t'), name, scopes, last4: secret.slice(-4), created_at: nowIso(), last_used: null, secret_hash: `h:${secret.length}` }
    mcpTokens.update((l) => [...l, item])
    audit('mcp.token_create', name, scopes.join(','))
    const { secret_hash: _h, ...pub } = item
    return HttpResponse.json({ token: secret, item: pub }, { status: 201 })
  }),
  http.delete(`${API}/core/mcp/tokens/:id`, ({ params }) => {
    const denied = guard('admin')
    if (denied) return denied
    const t = mcpTokens.get().find((x) => x.id === params.id)
    if (!t) return fail(404, 'not_found', 'No such token.')
    mcpTokens.update((l) => l.filter((x) => x.id !== t.id))
    audit('mcp.token_revoke', t.name)
    return new HttpResponse(null, { status: 204 })
  }),
]

// ---------- Dữ liệu ----------
const download = (name: string, data: unknown) => new HttpResponse(JSON.stringify(data, null, 2), { headers: { 'Content-Type': 'application/json', 'Content-Disposition': `attachment; filename=${name}` } })
const stamp = () => new Date().toISOString().slice(0, 10)

// Wrong passwords for the purge since the last good one: the real limiter is the one of the sign-in (5 tries), D-76.
const PURGE_MAX_TRIES = 5
const purgeTries = collection<{ n: number }>('core_purge_tries', () => ({ n: 0 }))

const dataHandlers = [
  http.get(`${API}/core/data/backup`, () => {
    const denied = guard('admin')
    if (denied) return denied
    audit('data.backup', 'backup')
    // Không đưa mật khẩu và khoá vào bản sao lưu mock (SYS-4).
    return download(`vedette-backup-${stamp()}.json`, { format: 'vedette-backup/1', created_at: nowIso(), org: orgStore.get(), modules: modulesStore.get(), users: usersStore.get().map(adminOf), assets: assetsStore.get(), findings: findingsStore.get(), audit: auditStore.get() })
  }),
  http.get(`${API}/core/data/export`, () => {
    const denied = guard('admin')
    if (denied) return denied
    audit('data.export', 'JSON export')
    return download(`vedette-export-${stamp()}.json`, { format: 'vedette-export/1', exported_at: nowIso(), assets: assetsStore.get(), findings: findingsStore.get(), audit: auditStore.get() })
  }),
  // Xoá toàn bộ: mọi bảng của mọi module về trạng thái chưa cài đặt (bản thật: vedette data purge). Phiên kết thúc, lần tải sau mở /setup.
  http.post(`${API}/core/data/purge`, async ({ request }) => {
    const denied = guard('admin')
    if (denied) return denied
    const b = await body<{ confirm: string; password?: string; code?: string }>(request)
    if (String(b.confirm ?? '') !== orgStore.get().name) return fail(400, 'confirm_mismatch', 'The organization name does not match. Type it exactly to confirm deletion.')
    // D-154 step-up, like the other sensitive routes (D-76, D-98): the current password, counted against a limit, then a fresh two-step code when it is on.
    const u = currentUser()!
    if (purgeTries.get().n >= PURGE_MAX_TRIES) return HttpResponse.json({ error: { code: 'rate_limited', message: 'Too many tries. Wait a few minutes and try again.', retry_after: 300 } }, { status: 429, headers: { 'Retry-After': '300' } })
    if (String(b.password ?? '') !== u.password) {
      purgeTries.update((x) => ({ n: x.n + 1 }))
      return fail(400, 'wrong_password', 'Wrong password. The password is needed to delete all data.')
    }
    if (u.twofa) {
      const code = String(b.code ?? '').replace(/\s/g, '')
      if (u.twofa_method === 'email') {
        if (!code) {
          const sent = issueCode(u.id, true)
          if ('error' in sent) return sent.error
          return HttpResponse.json({ error: { code: 'code_required', message: 'Type the 6-digit code we emailed you to delete all data.', method: 'email', sent_to: maskEmail(u.email), resend_after: sent.resend_after } }, { status: 400 })
        }
        const bad = checkCode(u.id, code)
        if (bad) return bad
      } else {
        if (!code) return HttpResponse.json({ error: { code: 'code_required', message: 'Type the 6-digit code from your authenticator app to delete all data.', method: 'app' } }, { status: 400 })
        if (!/^\d{6}$/.test(code)) return fail(400, 'invalid_code', 'The code is 6 digits from your authenticator app.')
        if (!(await verifyTotp(totpSecrets.get()[u.id] ?? '', code))) return fail(400, 'wrong_code', 'Wrong code. Check the time on your phone and enter a new code.')
      }
    }
    purgeTries.set({ n: 0 })
    const removed = { assets: assetsStore.get().length, findings: findingsStore.get().length, audit: auditStore.get().length }
    resetMockDb()
    return HttpResponse.json({ ok: true, removed, kept: [] })
  }),
]

export const handlers = [...logExportHandlers, ...setupHandlers, ...generalHandlers, ...accountHandlers, ...usersHandlers, ...auditHandlers, ...updatesHandlers, ...privacyHandlers, ...networkHandlers, ...connectionsHandlers, ...mcpHandlers, ...dataHandlers]
