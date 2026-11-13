// Mock API module core (S-CORE-1..4, S-MCP-1, cài đặt ban đầu). Handler lõi (đăng nhập, /me, /modules) ở src/mocks/core.ts.
import { http, HttpResponse } from 'msw'
import { logExportHandlers } from './logExport'
import { API, audit, body, currentUser, fail, guard, EMAIL_RE } from '@/mocks/http'
import { aiConfigStore, assetsStore, auditStore, emailChannelReady, findingsStore, installStore, isOn, moduleAvailable, modulesStore, orgStore, sessionStore, tempExpiry, twofaMethodOf, usersStore, type User } from '@/mocks/stores'
import { collection, dataMode, daysAgo, newId, nowIso, peek, resetMockDb, setDataMode } from '@/mocks/db'
import type { Role } from '@/lib/session'
import type { ModuleId } from '@/lib/modules'
import { BUNDLES } from './bundles'
import { inventorySettingsStore } from '@/features/inventory/mocks'
import { cidrRange, overlapping } from '@/features/inventory/validate'
import { osHandlers } from './osMock'
import { networkHandlers } from './networkMock'
import { connectionsHandlers } from './connectionsMock'
import { connectorsStore } from '@/mocks/connectors'
import { newSecret, verifyTotp } from './totp'
import { checkCode, clearCode, issueCode, maskEmail, sentBody } from './emailCode'
import { CIDR_RE, compareVersion, fromBase64, GUESSABLE_PASSWORD, guessablePassword, isPrivateCidr, LOCAL_RANGE_NAMES, MIN_PASSWORD, validTimeZone } from './util'
import type { AccountSession, AdminUser, BoxBackup, RestoreRun, Advisory, AuditQuery, AuditRow, ManagedPackage, McpToken, OidcConfig, PrivacyFlow, SetupPayload, UpdateAvailable, UpdateChannel, UpdateComponent, UpdateHistory, UpdateCheckError, UpdateRun, UpdatesState } from './types'

const ROLES: Role[] = ['viewer', 'operator', 'admin']
const hex = (n: number) => [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, '0')).join('')
const adminOf = (u: User): AdminUser => ({ id: u.id, name: u.name, email: u.email, role: u.role, twofa: u.twofa, twofa_method: twofaMethodOf(u), disabled: !!u.disabled, created_at: u.created_at, last_login: u.last_login, sso: !!u.sso })
const ssoOnly = () => fail(409, 'sso_user', 'This account signs in through SSO. Its password, two-step sign-in and role come from the identity provider.')
/** Mã cài đặt một lần (D-75): hộp thật in nó vào nhật ký lúc khởi động khi chưa có quản trị viên; mock dùng một mã cố định. */
export const MOCK_SETUP_CODE = 'setup-code-demo'
const tempPassword = () => `${hex(3)}-${hex(3)}-${hex(3)}-${hex(2)}`

// ---------- Cài đặt ban đầu ----------
const setupHandlers = [
  // Công khai, chỉ id/tầng/phụ thuộc (không lộ module nào đang bật) để bước chọn gói vẽ được danh sách.
  http.get(`${API}/core/setup/modules`, () => HttpResponse.json({ modules: modulesStore.get().map(({ id, tier, depends }) => ({ id, tier, depends, available: moduleAvailable(id) })), install: installStore.get().kind, lan: installStore.get().kind === 'appliance' && !orgStore.get().setup_complete ? '192.168.10.0/24' : null })),

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
    if (guessablePassword(String(a.password), email)) return fail(400, 'weak_password', GUESSABLE_PASSWORD)
    const lan = (b.lan ?? []).map((x) => String(x).trim()).filter(Boolean)
    if (lan.length < 1 || lan.length > 16) return fail(400, 'invalid_lan', 'Enter 1 to 16 LAN ranges, for example 192.168.10.0/24.')
    const badLan = lan.find((x) => !CIDR_RE.test(x))
    if (badLan) return fail(400, 'invalid_lan', `The range "${badLan}" is not valid. Write it like 192.168.10.0/24.`)
    const pub = lan.find((x) => !isPrivateCidr(x))
    if (pub) return fail(400, 'public_range', `${pub} is not a private range (${LOCAL_RANGE_NAMES}). Add public addresses later under External exposure.`)
    // The ranges become the scope of Devices → Scope and sensors (below), so they obey that page's rule too (inventory INV-6, #350).
    const uniqueLan = [...new Set(lan.map((r) => cidrRange(r).network))] // host bits cleared first, as the backend does
    const clash = uniqueLan.map((r) => [r, overlapping(r, uniqueLan)] as const).find(([, o]) => o)
    if (clash) return fail(400, 'overlap_range', `Range ${clash[0]} overlaps ${clash[1]}. Keep the larger range and drop the smaller one.`)
    let enable: ModuleId[]
    const all = modulesStore.get() // danh sách module mặc định; kiểm tra xong mới dọn kho (lỗi thì không mất gì)
    // D-381: a bundle leaves out what this install cannot run; a custom choice naming it is refused.
    if (b.bundle === 'smb' || b.bundle === 'mid') enable = BUNDLES[b.bundle].filter(moduleAvailable)
    else if (b.bundle === 'custom') {
      enable = (b.modules ?? []) as ModuleId[]
      const unknown = enable.find((m) => !all.some((x) => x.id === m))
      if (unknown) return fail(400, 'invalid_module', `No module "${unknown}".`)
      const notHere = enable.find((m) => !moduleAvailable(m))
      if (notHere) return fail(409, 'not_appliance', `Module ${notHere} needs vedette-host, which only the appliance install has. This is a container-only install, so it cannot run here.`)
      if (!enable.includes('core')) enable = ['core', ...enable]
      for (const id of enable) {
        const lacking = all.find((x) => x.id === id)?.depends.filter((d) => !enable.includes(d)) ?? []
        if (lacking.length) return fail(400, 'missing_dependencies', `Module ${id} also needs: ${lacking.join(', ')}.`)
      }
    } else return fail(400, 'invalid_bundle', 'Choose a module bundle: smb, mid or custom.')

    // Cài thật: xoá sạch rồi vào chế độ 'clean' để MỌI module bắt đầu rỗng (không tài khoản, thiết bị, cảnh báo mẫu).
    const install = installStore.get() // the install kind is the box, not its data
    resetMockDb()
    installStore.set(install)
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
    if (!validTimeZone(String(b.timezone))) return fail(400, 'invalid_timezone', 'The time zone is not in the list.')
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
    // Cài sạch: chỉ có phiên đang dùng (không phiên "Firefox trên Windows" mẫu). Device is the raw User-Agent, as the box stores it.
    const firefoxWindows = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0'
    all[userId] = dataMode() === 'clean'
      ? [{ id: newId('s'), device: navigator.userAgent, ip: '127.0.0.1', started_at: nowIso(), last_seen: nowIso(), current: true }]
      : [
        { id: newId('s'), device: navigator.userAgent, ip: '192.168.10.35', started_at: nowIso(), last_seen: nowIso(), current: true },
        { id: newId('s'), device: firefoxWindows, ip: '192.168.10.61', started_at: daysAgo(2), last_seen: daysAgo(1, 3), current: false },
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
    return HttpResponse.json({ user: { id: u.id, name: u.name, email: u.email, role: u.role, twofa: u.twofa, twofa_method: twofaMethodOf(u), created_at: u.created_at, last_login: u.last_login, sso: !!u.sso }, twofa_email: { available: reason === null, reason, sent_to: maskEmail(u.email) }, sessions: sessionsOf(u.id) })
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
    const denied = guard('viewer', true)
    if (denied) return denied
    if (currentUser()!.sso) return ssoOnly()
    const u = currentUser()!
    const b = await body<{ current: string; next: string }>(request)
    if (b.current !== u.password) return fail(400, 'wrong_password', 'The current password is wrong.')
    const next = String(b.next ?? '')
    if (next.length < MIN_PASSWORD) return fail(400, 'weak_password', `The new password needs at least ${MIN_PASSWORD} characters.`)
    if (guessablePassword(next, u.email)) return fail(400, 'weak_password', GUESSABLE_PASSWORD)
    if (next === u.password) return fail(400, 'same_password', 'The new password must differ from the current one.')
    usersStore.update((l) => l.map((x) => (x.id === u.id ? { ...x, password: next, temp_password_expires_at: null } : x)))
    audit('account.password', u.email, u.temp_password_expires_at ? 'temporary password replaced' : undefined)
    return HttpResponse.json({ ok: true })
  }),
  http.post(`${API}/core/account/2fa/start`, async ({ request }) => {
    const denied = guard('viewer')
    if (denied) return denied
    if (currentUser()!.sso) return ssoOnly()
    const u = currentUser()!
    // D-76: turning two-step on needs the current password, like turning it off.
    if ((await body<{ password: string }>(request)).password !== u.password) return fail(400, 'wrong_password', 'Wrong password. The password is needed to turn on two-step sign-in.')
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
    if (!secret) return fail(409, 'no_pending', 'No key is waiting for confirmation. Choose "Set up authenticator app" again to get a new one.')
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
    if (currentUser()!.sso) return ssoOnly()
    const u = currentUser()!
    if ((await body<{ password: string }>(request)).password !== u.password) return fail(400, 'wrong_password', 'Wrong password. The password is needed to turn on two-step sign-in.')
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
    if (b.password !== u.password) return fail(400, 'wrong_password', 'Wrong password. The password is needed to turn off two-step sign-in.')
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
interface OidcStored { issuer: string; client_id: string; secret: string; scopes: string; groups_claim: string; default_role: Role | null; role_map: { group: string; role: Role }[]; /** D-194 (5): pinned when an administrator saves, from the address they used */ redirect_uri?: string; /** D-378 */ ca_pem?: string }
const oidcStore = collection<OidcStored>('oidc_config', () => ({ issuer: '', client_id: '', secret: '', scopes: 'openid email profile', groups_claim: 'groups', default_role: null, role_map: [] }))
const oidcView = (): OidcConfig => {
  const c = oidcStore.get()
  return {
    issuer: c.issuer, client_id: c.client_id, secret_last4: c.secret ? c.secret.slice(-4) : null, scopes: c.scopes ?? 'openid email profile', groups_claim: c.groups_claim ?? 'groups',
    default_role: c.default_role ?? null, role_map: c.role_map, redirect_uri: c.redirect_uri || `${location.origin}/sso/callback`, sso_users: usersStore.get().filter((u) => u.sso).length,
    ca_pem: c.ca_pem ?? '', ca_certs: caBlocks(c.ca_pem ?? '').map((_, i) => ({ subject: `Mock internal CA ${i + 1}`, expires_at: MOCK_CA_EXPIRES })),
  }
}
// D-378: the mock cannot read X.509, so it checks the shape only (PEM CERTIFICATE blocks, nothing else, 1 to 5, at most 64 KB) and
// names each block "Mock internal CA n". The box parses each certificate and refuses a non-CA or an expired one.
const MOCK_CA_EXPIRES = '2030-01-01T00:00:00.000Z'
const caBlocks = (pemText: string) => pemText.match(/-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----/g) ?? []
function caError(raw: string): string | null {
  const text = raw.trim()
  if (!text) return null
  const blocks = caBlocks(text)
  if (raw.length > 64 * 1024) return 'The CA certificate text is larger than 64 KB.'
  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(text)) return 'The CA certificate text holds a PRIVATE KEY block; only certificates are accepted (never a private key).'
  if (!blocks.length || blocks.join('').replace(/\s/g, '') !== text.replace(/\s/g, '')) return 'The CA certificate text is not PEM, or has text outside the PEM blocks. Paste the PEM of the CA that signed the identity provider\'s certificate (-----BEGIN CERTIFICATE-----).'
  if (blocks.length > 5) return 'The CA certificate text holds more than 5 certificates.'
  return null
}
// Luồng đăng nhập SSO đang chờ gọi lại (D-194): state, binding, hạn 10 phút, dùng một lần. Bản thật chỉ giữ SHA-256 của hai giá trị.
const oidcFlows = collection<{ state: string; binding: string; expires: number; issuer: string; client_id: string }[]>('oidc_flow', () => [])
// Người dùng ở IdP mẫu: mock không có IdP thật, nên bước đăng nhập ở IdP được bỏ qua và trả về ngay một mã.
export const MOCK_IDP_USER: { sub: string; email: string; email_verified?: boolean; name: string; groups: string[] } = { sub: 'mock-sub-1', email: 'sso.user@acme.example', email_verified: true, name: 'SSO user', groups: ['vedette-operators', 'staff'] }
/** D-195: vai cao nhất trong các dòng khớp nhóm; không khớp dòng nào → vai mặc định (null = không có quyền). */
export function ssoRole(groups: string[], c: Pick<OidcStored, 'role_map' | 'default_role'>): Role | null {
  const hits = c.role_map.filter((m) => groups.includes(m.group)).map((m) => m.role)
  if (!hits.length) return c.default_role ?? null
  return hits.reduce((a, b) => (ROLES.indexOf(b) > ROLES.indexOf(a) ? b : a))
}
// RFC 6749 §3.3 scope-token; tên claim chỉ chữ, số và _ . : / -
const SCOPE_RE = /^[\x21\x23-\x5B\x5D-\x7E]{1,64}$/
const CLAIM_RE = /^[A-Za-z0-9_.:/-]{1,64}$/
const randomToken = () => Array.from(crypto.getRandomValues(new Uint8Array(32)), (b) => b.toString(16).padStart(2, '0')).join('')
const OIDC_OFF = 'SSO sign-in is not set up. Sign in with your email and password, or ask an administrator.'
// D-196: đường vào dự phòng là quản trị viên dùng mật khẩu, nên chỉ họ được tính.
const activeAdmins = (l: User[]) => l.filter((x) => x.role === 'admin' && !x.disabled && !x.sso).length

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
    const u: User = { id: newId('u'), name, email, role: b.role as Role, password: temp, temp_password_expires_at: tempExpiry(), twofa: false, created_at: nowIso(), last_login: null }
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
    if (b.role !== undefined && b.role !== target.role) {
      if (target.sso) return ssoOnly()
      if (!ROLES.includes(b.role)) return fail(400, 'invalid_role', 'Choose a role: view only, operator or administrator.')
      next.role = b.role
    }
    if (b.disabled !== undefined) {
      if (b.disabled && target.id === me.id) return fail(400, 'self_disable', 'You cannot disable the account you are using. Ask another administrator.')
      next.disabled = b.disabled === true
    }
    const after = list.map((x) => (x.id === target.id ? next : x))
    if (activeAdmins(after) < 1 && activeAdmins(after) < activeAdmins(list)) return fail(400, 'last_admin', 'At least one active administrator who signs in with a password must remain, so the box stays reachable when the identity provider is down. Add another administrator first.')
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
    if (target.sso) return ssoOnly()
    const temp = tempPassword()
    usersStore.update((l) => l.map((x) => (x.id === target.id ? { ...x, password: temp, temp_password_expires_at: tempExpiry() } : x)))
    sessionsStore.update((all) => { const n = { ...all }; delete n[target.id]; return n })
    audit('user.password_reset', target.email)
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
    const b = await body<Partial<OidcStored> & { client_secret?: string }>(request)
    const cur = oidcStore.get()
    let issuer = String(b.issuer ?? '').trim().replace(/\/+$/, '')
    try { if (new URL(issuer).protocol !== 'https:') throw new Error('x') } catch { issuer = '' }
    if (!issuer) return fail(400, 'invalid_issuer', 'The issuer must be an https address, for example https://sso.example.com/realms/main.')
    const clientId = String(b.client_id ?? '').trim()
    if (!clientId || clientId.length > 200) return fail(400, 'invalid_client', 'Enter the Client ID (at most 200 characters).')
    const secret = b.client_secret ? String(b.client_secret) : cur.secret
    if (secret.length < 8) return fail(400, 'invalid_secret', 'Enter the Client secret (at least 8 characters).')
    const scopes = String(b.scopes ?? '').trim().split(/\s+/).filter(Boolean)
    if (!scopes.includes('openid') || scopes.length > 10 || !scopes.every((x) => SCOPE_RE.test(x))) return fail(400, 'invalid_scopes', 'Scopes are words separated by spaces, at most 10, and must include openid.')
    const claim = String(b.groups_claim ?? '').trim()
    if (!CLAIM_RE.test(claim)) return fail(400, 'invalid_claim', 'Enter the name of the groups claim, for example groups (letters, digits and _ . : / -, at most 64).')
    if (b.default_role !== null && !ROLES.includes(b.default_role as Role)) return fail(400, 'invalid_role', 'Choose a default role, or No access.')
    const map = (b.role_map ?? []).filter((m) => String(m.group ?? '').trim())
    if (map.length > 10) return fail(400, 'too_many', 'At most 10 role mapping rows.')
    if (map.some((m) => !ROLES.includes(m.role) || m.group.trim().length > 256)) return fail(400, 'invalid_role', 'One mapping row has an invalid role or a group name longer than 256 characters.')
    const ca = b.ca_pem === undefined ? (cur.ca_pem ?? '') : String(b.ca_pem)
    const caErr = caError(ca)
    if (caErr) return fail(400, 'invalid_ca', caErr)
    // D-378 (INV-3): a new CA needs the secret again, like a new issuer; removing it does not.
    if (ca.trim() && caBlocks(ca).join('') !== caBlocks(cur.ca_pem ?? '').join('') && !b.client_secret) return fail(400, 'invalid_secret', 'The issuer, Client ID or CA changed: enter the Client secret again.')
    oidcStore.set({ issuer, client_id: clientId, secret, scopes: [...new Set(scopes)].join(' '), groups_claim: claim, default_role: (b.default_role ?? null) as Role | null, role_map: map.map((m) => ({ group: m.group.trim(), role: m.role })), redirect_uri: `${location.origin}/sso/callback`, ca_pem: caBlocks(ca).map((x) => `${x}\n`).join('') })
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
    // D-378: an issuer under .internal stands for an IdP behind a private CA; it works once a CA is saved.
    if (host.endsWith('.internal') && !c.ca_pem) return fail(502, 'discovery_failed', `Cannot read ${c.issuer}/.well-known/openid-configuration: the box does not trust the identity provider's certificate (an internal CA? paste it under Identity provider CA certificate). Check the issuer and the network path from the box to the identity provider.`)
    return HttpResponse.json({ ok: true, endpoints: { authorization: `${c.issuer}/protocol/openid-connect/auth`, token: `${c.issuer}/protocol/openid-connect/token`, jwks: `${c.issuer}/protocol/openid-connect/certs` } })
  }),

  // Công khai: trang đăng nhập hỏi để biết có nút SSO không.
  http.get(`${API}/core/auth-options`, () => HttpResponse.json({ oidc: isOn('auth-oidc') && !!oidcStore.get().issuer })),
  // D-194: bắt đầu đăng nhập SSO. Bản thật trả điểm authorization của IdP; mock bỏ qua IdP và đưa thẳng về trang gọi lại kèm một mã.
  // Module tắt: không có route (404, SYS-5); bật mà chưa có issuer: 400 oidc_off.
  http.post(`${API}/auth/oidc/start`, () => {
    if (!isOn('auth-oidc')) return fail(404, 'not_found', 'Not found.')
    const cfg = oidcStore.get()
    if (!cfg.issuer) return fail(400, 'oidc_off', OIDC_OFF)
    // D-194 (5): SSO runs only at the address the administrator registered at the identity provider.
    const at = new URL(oidcView().redirect_uri).origin
    if (at !== location.origin) return fail(409, 'sso_wrong_address', `SSO sign-in works at ${at}. Open Vedette there to sign in with SSO.`, { address: at })
    const state = randomToken()
    const binding = randomToken()
    const now = Date.now()
    oidcFlows.update((l) => [...l.filter((f) => f.expires > now).slice(-999), { state, binding, expires: now + 10 * 60_000, issuer: cfg.issuer, client_id: cfg.client_id }])
    return HttpResponse.json({ authorize_url: `${location.origin}/sso/callback?code=mock-${randomToken().slice(0, 16)}&state=${state}`, binding })
  }),
  // D-194, D-195: gọi lại. Luồng dùng một lần và gắn với issuer/client lúc bắt đầu; vai theo nhóm; không nối vào tài khoản mật khẩu.
  // Bản thật giới hạn theo địa chỉ như start; mock không đếm. Chỉ ghi kiểm toán khi luồng có thật (không để người lạ làm đầy nhật ký).
  http.post(`${API}/auth/oidc/callback`, async ({ request }) => {
    if (!isOn('auth-oidc')) return fail(404, 'not_found', 'Not found.')
    const cfg = oidcStore.get()
    if (!cfg.issuer) return fail(400, 'oidc_off', OIDC_OFF)
    const b = await body<{ code?: string; state?: string; binding?: string }>(request)
    const refuse = (reason: string, status: number, code: string, msg: string, who = cfg.issuer) => { audit('auth.login_failed', who, `SSO: ${reason}`); return fail(status, code, msg) }
    const flow = oidcFlows.get().find((f) => f.state === b.state)
    oidcFlows.update((l) => l.filter((f) => f.state !== b.state)) // dùng một lần, kể cả khi binding sai
    if (!flow) return fail(400, 'sso_expired', 'This sign-in has expired or was already used. Start again from the sign-in page.')
    if (flow.expires < Date.now() || flow.issuer !== cfg.issuer || flow.client_id !== cfg.client_id) return refuse('state', 400, 'sso_expired', 'This sign-in has expired or was already used. Start again from the sign-in page.')
    if (flow.binding !== b.binding) return refuse('binding', 400, 'sso_expired', 'This sign-in was started in another tab or browser. Start again from the sign-in page.')
    if (!b.code) return refuse('token', 400, 'sso_failed', 'The identity provider\'s answer could not be verified. Ask an administrator to check the SSO settings; the audit log has the reason.')
    const idp = MOCK_IDP_USER
    const email = idp.email.toLowerCase()
    const list = usersStore.get()
    let u = list.find((x) => x.sso?.iss === cfg.issuer && x.sso.sub === idp.sub)
    const role = ssoRole(idp.groups, cfg)
    // D-196 (4): leaving the groups ends the person's sessions at once, not at the next sign-in only.
    const endSessions = (id: string) => { sessionsStore.update((all) => { const n = { ...all }; delete n[id]; return n }); if (sessionStore.get().userId === id) sessionStore.set({ userId: null }) }
    if (!role) {
      if (u) endSessions(u.id)
      return refuse('no_access', 403, 'no_access', 'Your company account is not in a group that may use Vedette. Ask an administrator.', email)
    }
    if (!u && idp.email_verified === false) return refuse('email_unverified', 403, 'email_unverified', 'Your identity provider says this email address is not verified. Verify it there, or ask an administrator.', email)
    let relinked = false
    if (!u) {
      const same = list.find((x) => x.email.toLowerCase() === email)
      // Tài khoản mật khẩu, tài khoản SSO cùng issuer khác sub, hay email chưa xác minh: không nối. Tài khoản SSO của issuer cũ + email đã xác minh: gắn lại.
      if (same && (!same.sso || same.sso.iss === cfg.issuer || idp.email_verified !== true)) return refuse('email_in_use', 409, 'email_in_use', `A Vedette account already uses ${email} and does not belong to this SSO identity. Use another email at the identity provider, or ask an administrator.`, email)
      if (same) { u = { ...same, sso: { iss: cfg.issuer, sub: idp.sub } }; relinked = true }
    }
    if (u?.disabled) return refuse('disabled', 403, 'disabled', 'This account has been disabled. Ask an administrator.', email)
    if (!u) {
      u = { id: newId('u'), name: idp.name, email, role, password: '', twofa: false, created_at: nowIso(), last_login: null, sso: { iss: cfg.issuer, sub: idp.sub } }
      usersStore.update((l) => [...l, u as User])
      audit('user.create', email, 'SSO')
    } else {
      if (relinked) audit('user.sso_relink', email, cfg.issuer)
      if (u.role !== role) { audit('user.role', email, `${u.role} sang ${role} (SSO groups)`); endSessions(u.id) }
    }
    // D-195 (6): email and name stay as they were at creation; only the role follows the groups.
    const signed: User = { ...u, role, last_login: nowIso() }
    usersStore.update((l) => l.map((x) => (x.id === signed.id ? signed : x)))
    sessionStore.set({ userId: signed.id })
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
    if (q.actor === 'people' && isSystemActor(r.user)) return false
    if (q.group && r.action.split('.')[0] !== q.group) return false
    if (text && !`${r.action} ${r.target} ${r.detail ?? ''} ${r.user}`.toLowerCase().includes(text)) return false
    return true
  })
}
const qOf = (url: string): Partial<AuditQuery> => { const p = new URL(url).searchParams; return { q: p.get('q') ?? '', user: p.get('user') ?? '', group: p.get('group') ?? '', from: p.get('from') ?? '', to: p.get('to') ?? '', actor: p.get('actor') === 'people' ? 'people' : '' } }
/** D-416: an automatic line is written by the box itself: user "system" or "system:<part>" (a person, the console and an MCP token are not). */
const isSystemActor = (user: string) => user === 'system' || user.startsWith('system:')
/** D-416: ids of devices (a-…) and findings (f-…) in a line's target or detail. */
const AUDIT_ID_RE = /\b[af]-[a-z0-9]{1,64}\b/g
/** D-416: the display names of the devices and findings named in these rows; a device is its host name, else its IP; a finding is "<CVE> on <device>". */
function auditNames(rows: AuditRow[]): Record<string, string> {
  const ids = new Set(rows.flatMap((r) => `${r.target} ${r.detail ?? ''}`.match(AUDIT_ID_RE) ?? []))
  if (!ids.size) return {}
  const assets = new Map(assetsStore.get().map((a) => [a.id, a.hostname || a.ip]))
  const out: Record<string, string> = {}
  for (const f of findingsStore.get()) if (ids.has(f.id)) out[f.id] = assets.has(f.asset_id) ? `${f.cve} on ${assets.get(f.asset_id)}` : f.cve
  for (const [id, name] of assets) if (ids.has(id) && name) out[id] = name
  return out
}
/** Ô CSV bắt đầu bằng = + - @ bị Excel hiểu là công thức: thêm dấu nháy để thành chữ. */
const csvCell = (v: string) => { const s = /^[=+\-@\t\r]/.test(v) ? `'${v}` : v; return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s }

const auditHandlers = [
  http.get(`${API}/core/audit`, ({ request }) => {
    const denied = guard('admin')
    if (denied) return denied
    const all = auditStore.get()
    const rows = filterAudit(qOf(request.url))
    const items = rows.slice(0, 200)
    return HttpResponse.json({ items, total: rows.length, users: [...new Set(all.map((r) => r.user))].sort(), groups: [...new Set(all.map((r) => r.action.split('.')[0] ?? ''))].sort(), names: auditNames(items) })
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
/** Trình trợ giúp `vedette-host` mà mỗi bản phát hành mang theo (manifest `host.version`, D-316). */
const HOST_IN: Record<string, string> = { '0.9.4': '0.9.4', '0.10.0-beta.1': '0.10.0-beta.1' }
/** Bản phát hành khai `rollback.safe=false` (đổi DB): rollback khỏi bản này khôi phục DB trước cập nhật (D-104, D-340). */
const RESTORES_DATA = new Set(['0.9.4'])
const comp = (id: string, kind: UpdateComponent['kind'], version: string, previous: string | null, ago: number): UpdateComponent => ({ id, kind, version, previous, installed_at: daysAgo(ago), signature: 'valid', rollback_restores_data: false })
const updStore = collection<{ channel: UpdateChannel; mode: 'auto' | 'manual'; components: UpdateComponent[]; history: UpdateHistory[]; last_check: string | null; last_check_error?: UpdateCheckError | null; run?: UpdateRun | null }>('core_updates', () => ({
  channel: 'stable',
  mode: 'manual',
  last_check: daysAgo(0, 2),
  components: [comp('software', 'software', '0.9.3', '0.9.2', 9), comp('host', 'software', '0.9.3', null, 9), comp('data', 'data', '20261106.08', '20261106.04', 0), comp('pack-mitigation', 'content', '2026.11.04', '2026.10.28', 2), comp('pack-nuclei', 'content', '2026.11.05', '2026.11.01', 1), comp('pack-parsers', 'content', '1.4.0', '1.3.2', 14)],
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
  last_check: null,
  components: [comp('software', 'software', '0.9.3', null, 0), comp('host', 'software', '0.9.3', null, 0), comp('data', 'data', '20261106.08', null, 0), comp('pack-mitigation', 'content', '2026.11.04', null, 0), comp('pack-nuclei', 'content', '2026.11.05', null, 0), comp('pack-parsers', 'content', '1.4.0', null, 0)],
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

/** Mỗi bước của một lần chạy mô phỏng (D-340); bản thật: kéo image tới 45 phút, rồi khởi động lại. */
export const RUN_STEP_MS = import.meta.env.MODE === 'test' ? 300 : 1500
const runSteps = (action: UpdateRun['action'], restore: boolean): UpdateRun['steps'] => (action === 'update' ? ['download', 'restart', 'start'] : restore ? ['start', 'restore', 'restart'] : ['start', 'restart'])

/**
 * How the system helper step of the next software update ends (S-CORE-2 criterion D-316); code null = it succeeds. Only tests and
 * e2e set it (no button: on a real box the host decides). `version` stands in for the helper version of the release; without it
 * downgrade_not_allowed uses 0.9.2 and test_version_refused `<release>-test.1`.
 */
export type HostOutcome = 'self_update_unhealthy' | 'install_failed' | 'signature_invalid' | 'checksum_mismatch' | 'downgrade_not_allowed' | 'test_version_refused' | 'dependencies_unavailable' | 'dpkg_locked' | 'rollback_failed' | 'self_update_interrupted' | 'host_too_old' | 'current_package_missing' | 'host_download_failed'
/**
 * How the next update check ends (S-CORE-2 criterion D-392); null = it succeeds. Only tests and e2e set it (no button: on a
 * real box the network decides). The sentences are core's own (modules/core/updates_check.go checkFailure), never remote text.
 */
export const CHECK_FAILURES: Record<UpdateCheckError['code'], { status: number; message: string }> = {
  update_source_unreachable: { status: 503, message: 'Could not reach the update source (github.com): it did not answer in time. Try again later; if it keeps happening, check that the box can reach github.com over HTTPS.' },
  // Only a record kept by an older version (D-540): a check of a source that publishes no release now succeeds with nothing offered.
  update_not_published: { status: 502, message: 'No release found yet: the release source answered, but no update information is published there. This is not a network problem and nothing needs fixing on the box.' },
  update_check_failed: { status: 502, message: "The update information did not pass Vedette's signature checks, so nothing new is offered and nothing was installed. The details are in the box log." },
}
export const checkScenario = collection<{ code: UpdateCheckError['code'] | null }>('core_updates_check_scenario', () => ({ code: null }))
export const hostScenario = collection<{ code: HostOutcome | null; version: string | null }>('core_updates_host_scenario', () => ({ code: null, version: null }))
/** The words core sends for each code (the story's sentences; slice 5 maps the host codes to these, core CONTRACT INV-21). */
export function hostError(code: HostOutcome, v: string, running: string, release: string): string {
  switch (code) {
    case 'self_update_unhealthy': case 'install_failed': return `The new system helper ${v} did not start correctly, so the box went back to ${running} by itself. Nothing else was changed.`
    case 'signature_invalid': return 'The system helper in this update is not signed by the Vedette release key. Nothing was installed.'
    case 'checksum_mismatch': return 'The downloaded system helper does not match the signed release. Nothing was installed.'
    case 'downgrade_not_allowed': return `System helper ${v} is older than the one running (${running}). The helper is never taken back by an update.`
    case 'test_version_refused': return `${v} is a test build. It is never installed on a real box.`
    case 'dependencies_unavailable': return "The new system helper needs operating system packages that the box's package sources do not offer. Nothing was installed."
    case 'dpkg_locked': return 'The box is installing operating system packages. Try again in a few minutes.'
    case 'rollback_failed': case 'self_update_interrupted': return 'The system helper update stopped half way and could not be undone. Vedette keeps running; follow the runbook section "vedette-host self-update stopped half way".'
    case 'host_too_old': return `This box's system helper (${running}) is too old to update itself. Run install.sh of release ${release} on the box (it upgrades the helper and keeps your data), then apply again.`
    case 'current_package_missing': return `Updating the system helper to ${v} failed: the box has no copy of the running helper to go back to, so it was not updated. Run install.sh of release ${release} on the box (it keeps your data), then apply again.`
    case 'host_download_failed': return `Updating the system helper to ${v} failed: its package could not be downloaded. Check that the box can reach github.com over HTTPS, then apply again.`
  }
}
const hostRow = () => updStore.get().components.find((c) => c.id === 'host')
/** The helper version a software release brings when the run must update it first: above the running one, or forced by a scenario. */
function hostTarget(release: string): string | undefined {
  const cur = hostRow()
  const sc = hostScenario.get()
  // the two version refusals need an older or a test build to make sense; the others keep the release's own helper
  const v = sc.version ?? (sc.code === 'downgrade_not_allowed' ? '0.9.2' : sc.code === 'test_version_refused' ? `${release}-test.1` : HOST_IN[release])
  if (!cur || !v) return undefined // container-only install, or a release without a helper
  return compareVersion(v, cur.version) > 0 || sc.code ? v : undefined
}
/** End of the host step: the helper is on the new version (history row `host`), or the run ends before any image changes. */
function settleHost(run: UpdateRun, to: string): boolean {
  const cur = hostRow()!
  const { code } = hostScenario.get()
  if (!code) {
    updStore.update((s) => ({ ...s, components: s.components.map((c) => (c.id === 'host' ? { ...c, version: to, installed_at: nowIso() } : c)), history: [{ id: newId('h'), ts: nowIso(), component: 'host', from: cur.version, to, action: 'update' as const, user: run.user }, ...s.history].slice(0, 100) }))
    return true
  }
  const reverted = code === 'self_update_unhealthy' || code === 'install_failed'
  updStore.update((s) => ({ ...s, run: { ...run, status: reverted ? 'reverted' : 'failed', step: null, finished_at: nowIso(), error: hostError(code, to, cur.version, run.to) } }))
  return false
}

/** Đưa lần chạy phần mềm đang chạy tới bước đúng với thời gian đã trôi; xong thì đổi phiên bản và ghi lịch sử. */
function tickRun() {
  const run = updStore.get().run
  if (!run || run.status !== 'running') return
  const steps = run.steps
  const i = Math.floor((Date.now() - Date.parse(run.started_at)) / RUN_STEP_MS)
  const host = steps[0] === 'host' && i >= 1 ? hostTarget(run.to) : undefined
  if (host && !settleHost(run, host)) return
  if (i < steps.length) {
    if (run.step !== steps[i]) updStore.update((s) => ({ ...s, run: { ...run, step: steps[i]! } }))
    return
  }
  if (run.action === 'update') applyOne(run.component, run.to, 'update', run.user)
  else rollbackOne(run.component, run.user)
  updStore.update((s) => ({ ...s, run: { ...run, status: 'done', step: null, finished_at: nowIso() } }))
}

function startRun(action: UpdateRun['action'], component: string, from: string, to: string, user: string, restore = false) {
  const host = action === 'update' && component === 'software' ? hostTarget(to) : undefined // a rollback never takes the helper back
  const steps: UpdateRun['steps'] = host ? ['host', ...runSteps(action, restore)] : runSteps(action, restore)
  const run: UpdateRun = { id: newId('ur'), action, component, from, to, status: 'running', steps, step: steps[0]!, started_at: nowIso(), finished_at: null, user, error: null }
  // criterion (h): a helper without host.self_update stops the run before any host call, nothing installed
  if (host && hostScenario.get().code === 'host_too_old') Object.assign(run, { status: 'failed', step: null, finished_at: run.started_at, error: hostError('host_too_old', host, hostRow()!.version, to) })
  updStore.update((s) => ({ ...s, run }))
}

/**
 * The stored index as far as D-386 needs it: its revocations and its expires_at. The mock check stores a fresh index
 * (expires in 14 days), like the box; tests put a revocation of the running release or an expired index here.
 */
export const updIndex = collection<{ expires_at: string; revoked: { kind: 'release' | 'image_digest' | 'key' | 'advisory_only'; id: string; reason: string; since: string; action: NonNullable<UpdatesState['running_revoked']>['action'] }[] }>('core_updates_index', () => ({ expires_at: new Date(Date.now() + 7 * 864e5).toISOString(), revoked: [] }))
const WARNS = new Set(['block_install_and_warn', 'rollback_if_possible'])
/** D-386: a release revocation of the running version (the mock has no image digests); one with a warning action first. */
function runningRevoked(running: string): UpdatesState['running_revoked'] {
  const hits = updIndex.get().revoked.filter((r) => r.kind === 'release' && r.id === running)
  const r = hits.find((x) => WARNS.has(x.action)) ?? hits[0]
  return r ? { version: running, reason: r.reason, since: r.since, action: r.action } : null
}
const staleSince = (): string | null => { const e = updIndex.get().expires_at; return Date.parse(e) < Date.now() ? e : null }

/** The images of a mock release by digest (manifest images[], S-CORE-9 G4): fixed per service and version, like a real manifest. */
const releaseImages = (version: string) => ['core', 'sensor', 'honeypot', 'scan'].map((service) => ({
  service, digest: `sha256:${[...`${service}@${version}`].map((c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join('').padEnd(64, '0').slice(0, 64)}`,
}))

function updView(): UpdatesState {
  tickRun()
  const s = updStore.get()
  const p = privacyStore.get()
  const sw = s.components.find((c) => c.id === 'software')!.version
  const available = CATALOG.filter((a) => {
    if (a.channel === 'beta' && s.channel !== 'beta') return false
    const cur = s.components.find((c) => c.id === a.component)
    return !cur || compareVersion(a.version, cur.version) > 0
  })
  // A container-only install has no system helper: no host row, no host_version (D-381, S-CORE-2 D-316 (g)).
  const container = installStore.get().kind === 'container'
  // chỉ giữ bản mới nhất cho mỗi thành phần
  const latest = available.filter((a) => !available.some((b) => b.component === a.component && compareVersion(b.version, a.version) > 0)).map((a) => {
    if (a.component !== 'software') return a
    const host = container ? undefined : hostTarget(a.version)
    return { ...a, images: releaseImages(a.version), ...(host ? { host_version: host } : {}) }
  })
  return { channel: s.channel, mode: s.mode, check_enabled: p.update_check, last_check: s.last_check, last_check_error: s.last_check_error ?? null, components: container ? s.components.filter((c) => c.id !== 'host') : s.components, available: latest, history: s.history.slice(0, 20), advisories: ADVISORIES.map((a) => ({ ...a, status: compareVersion(sw, a.fixed_in) < 0 ? 'affected' : 'fixed' })), managed: managedOf(s.components, latest), running_revoked: runningRevoked(sw), stale_since: staleSince(), run: s.run && (s.run.status === 'running' || Date.now() - Date.parse(s.run.finished_at ?? s.run.started_at) < 864e5) ? s.run : null }
}

function applyOne(component: string, version: string, action: UpdateHistory['action'], user: string) {
  updStore.update((s) => {
    const cur = s.components.find((c) => c.id === component)
    if (!cur) return s
    const entry: UpdateHistory = { id: newId('h'), ts: nowIso(), component, from: cur.version, to: version, action, user }
    return { ...s, components: s.components.map((c) => (c.id === component ? { ...c, previous: c.version, version, installed_at: nowIso(), signature: 'valid', rollback_restores_data: component === 'software' && RESTORES_DATA.has(version) } : c)), history: [entry, ...s.history].slice(0, 100) }
  })
}

function rollbackOne(component: string, user: string) {
  updStore.update((s) => {
    const cur = s.components.find((c) => c.id === component)
    if (!cur?.previous) return s
    const prev = cur.previous
    return {
      ...s,
      mode: 'manual',
      components: s.components.map((c) => (c.id === cur.id ? { ...c, version: prev, previous: null, installed_at: nowIso(), rollback_restores_data: false } : c)),
      history: [{ id: newId('h'), ts: nowIso(), component: cur.id, from: cur.version, to: prev, action: 'rollback' as const, user }, ...s.history].slice(0, 100),
    }
  })
}

const softwareBusy = () => updStore.get().run?.status === 'running'
const busy = () => fail(409, 'busy', 'An update or rollback of the software is already running. Wait for it to finish.')

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
    if (!privacyStore.get().update_check) return fail(409, 'check_off', 'Update checks are off under Privacy. Turn them on to look for Vedette releases.')
    const failed = checkScenario.get().code
    if (failed) {
      const f = CHECK_FAILURES[failed]
      updStore.update((s) => ({ ...s, last_check_error: { at: nowIso(), code: failed, message: f.message } })) // last_check stays: it moves only on a good check
      audit('update.check', 'updates', `failed: ${failed}`)
      return fail(f.status, failed, f.message)
    }
    updStore.update((s) => ({ ...s, last_check: nowIso(), last_check_error: null }))
    updIndex.update((x) => ({ ...x, expires_at: new Date(Date.now() + 14 * 864e5).toISOString() })) // a fresh signed index
    let applied = 0
    if (updStore.get().mode === 'auto') {
      for (const a of updView().available) {
        const cur = updStore.get().components.find((c) => c.id === a.component)
        if (a.component !== 'software') { applyOne(a.component, a.version, 'update', 'system'); applied++ } // the software reports at the end of its run, not here
        else if (cur && !softwareBusy()) startRun('update', a.component, cur.version, a.version, 'system')
      }
    }
    audit('update.check', 'updates', applied ? `auto-installed ${applied}` : undefined)
    return HttpResponse.json({ ...updView(), applied })
  }),
  http.post(`${API}/core/updates/apply`, async ({ request }) => {
    const denied = guard('admin')
    if (denied) return denied
    const b = await body<{ component: string }>(request)
    const v = updView()
    if (b.component === 'software' && softwareBusy()) return busy()
    const a = v.available.find((x) => x.component === b.component)
    if (!a) return fail(404, 'no_update', 'There is no new version of this component. Click "Check now".')
    const cur = v.components.find((c) => c.id === a.component)
    if (a.component === 'software' && cur) startRun('update', a.component, cur.version, a.version, currentUser()!.email)
    else applyOne(a.component, a.version, 'update', currentUser()!.email)
    audit('update.apply', a.component, `to ${a.version}`)
    return HttpResponse.json(updView())
  }),
  http.post(`${API}/core/updates/rollback`, async ({ request }) => {
    const denied = guard('admin')
    if (denied) return denied
    const b = await body<{ component: string; confirm_data_loss?: boolean }>(request)
    if (b.confirm_data_loss !== undefined && typeof b.confirm_data_loss !== 'boolean') return fail(400, 'invalid_body', 'confirm_data_loss is true or false.')
    updView()
    if (b.component === 'software' && softwareBusy()) return busy()
    const cur = updStore.get().components.find((c) => c.id === b.component)
    if (!cur) return fail(404, 'not_found', 'No such component.')
    if (!cur.previous) return fail(409, 'no_previous', 'No previous version to go back to.')
    if (cur.rollback_restores_data && b.confirm_data_loss !== true) return fail(409, 'confirm_required', 'This rollback also puts back the database from before the update, so data written since then is lost. Confirm to go on.')
    const prev = cur.previous
    if (cur.id === 'software') startRun('rollback', cur.id, cur.version, prev, currentUser()!.email, cur.rollback_restores_data)
    else rollbackOne(cur.id, currentUser()!.email)
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
    updView()
    if (softwareBusy() && bundle.items.some((it) => it.component === 'software')) return busy()
    let applied = 0
    for (const it of bundle.items) {
      const cur = updStore.get().components.find((c) => c.id === it.component)
      if (!cur || compareVersion(it.version, cur.version) <= 0) continue
      if (it.component === 'software') startRun('update', it.component, cur.version, it.version, currentUser()!.email) // the same run as Apply (D-340)
      else { applyOne(it.component, it.version, 'bundle', currentUser()!.email); applied++ }
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
    // on (D-166 (4)): the distribution's own chrony sources stay whatever is entered; off on a container-only install, which sets no time source (S-CORE-4)
    { id: 10, state: installStore.get().kind === 'container' ? 'off' : 'on', control: 'reason' },
    { id: 11, state: isOn('auth-oidc') && !!oidcStore.get().issuer ? 'conditional' : 'off', control: 'reason' },
    { id: 12, state: connectorsStore.get().some((c) => c.enabled && c.kind !== 'mcp-stdio') ? 'on' : 'off', control: 'reason' },
    { id: 13, state: isOn('mcp-server') ? 'conditional' : 'off', control: 'reason' },
    // the Wazuh connection the inventory mock keeps (Inventory → Agents): on while one is saved and the module is on (D-309)
    { id: 14, state: isOn('agent-intake') && peek<unknown>('intake_wazuh') ? 'on' : 'off', control: 'reason' },
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
const mcpView = () => ({ enabled: isOn('mcp-server'), bind: '127.0.0.1', port: 8765, endpoint: 'http://127.0.0.1:8765/mcp', listening: true, listen_error: null, tokens: mcpTokens.get().map(({ secret_hash: _h, ...t }) => t), tools: MCP_TOOLS, scopes: MCP_SCOPES })

// The mcp-server module owns /core/mcp*: while it is off every path answers 404 like the real server, after the role check (D-230).
// The switch is PATCH /modules/mcp-server (the module toggle), as for single sign-on.
const MCP_MAX_TOKENS = 10
/** Like the server: signed in first, then 404 while the module is off, then the admin role. */
function mcpGate() {
  const anon = guard('viewer')
  if (anon) return anon
  if (!isOn('mcp-server')) return fail(404, 'not_found', 'Not found.')
  return guard('admin')
}
const mcpHandlers = [
  http.get(`${API}/core/mcp`, () => {
    const denied = mcpGate()
    if (denied) return denied
    return HttpResponse.json(mcpView())
  }),
  http.post(`${API}/core/mcp/tokens`, async ({ request }) => {
    const denied = mcpGate()
    if (denied) return denied
    const b = await body<{ name: string; scopes: string[] }>(request)
    const name = String(b.name ?? '').trim()
    if (!/^[\p{L}\p{N} _.'-]{1,64}$/u.test(name)) return fail(400, 'invalid_name', 'The token name is 1 to 64 characters: letters, digits, spaces, apostrophes, dashes.')
    const asked = Array.isArray(b.scopes) ? b.scopes : []
    const scopes = MCP_SCOPES.filter((x) => asked.includes(x))
    if (!scopes.length || asked.some((x) => !MCP_SCOPES.includes(x))) return fail(400, 'invalid_scopes', 'Choose at least one read scope: devices, findings or vulnerability feeds.')
    if (mcpTokens.get().length >= MCP_MAX_TOKENS) return fail(400, 'too_many', `A box holds up to ${MCP_MAX_TOKENS} MCP tokens. Revoke one you no longer use.`)
    const secret = `vmcp_${hex(16)}`
    const item: McpToken & { secret_hash: string } = { id: newId('t'), name, scopes, last4: secret.slice(-4), created_at: nowIso(), last_used: null, secret_hash: `h:${secret.length}` }
    mcpTokens.update((l) => [...l, item])
    audit('mcp.token_create', name, `scopes ${scopes.join(',')}, last 4 ${item.last4}`)
    const { secret_hash: _h, ...pub } = item
    return HttpResponse.json({ token: secret, item: pub }, { status: 201 })
  }),
  http.delete(`${API}/core/mcp/tokens/:id`, ({ params }) => {
    const denied = mcpGate()
    if (denied) return denied
    const t = mcpTokens.get().find((x) => x.id === params.id)
    if (!t) return fail(404, 'not_found', 'No such token.')
    mcpTokens.update((l) => l.filter((x) => x.id !== t.id))
    audit('mcp.token_revoke', t.name, `last 4 ${t.last4}`)
    return new HttpResponse(null, { status: 204 })
  }),
]

// ---------- Dữ liệu ----------
const download = (name: string, data: unknown) => new HttpResponse(JSON.stringify(data, null, 2), { headers: { 'Content-Type': 'application/json', 'Content-Disposition': `attachment; filename=${name}` } })
const stamp = () => new Date().toISOString().slice(0, 10)

// Wrong passwords for the purge since the last good one: the real limiter is the one of the sign-in (5 tries), D-76.
const PURGE_MAX_TRIES = 5
const purgeTries = collection<{ n: number }>('core_purge_tries', () => ({ n: 0 }))

// Bản sao lưu trình hỗ trợ giữ trên hộp (host-api §6.11) và lần khôi phục gần nhất (D-377). Mock: khôi phục xong ngay, không khởi động lại.
const boxBackupsStore = collection<BoxBackup[]>('core_box_backups', () => [
  { id: 'b3c1a7e0d2f94b5e8a6c0d1e2f3a4b5c', kind: 'pre_os_update', created_at: daysAgo(1), size: 48_300_000, includes_key: true },
  { id: 'a9e2c4f6b8d0e1f2a3b4c5d6e7f8a9b0', kind: 'pre_update', created_at: daysAgo(6), size: 47_100_000, includes_key: true },
  { id: '0f1e2d3c4b5a69788796a5b4c3d2e1f0', kind: 'manual', created_at: daysAgo(12), size: 45_900_000, includes_key: false },
  { id: '3c4d5e6f708192a3b4c5d6e7f8091021', kind: 'pre_restore', created_at: daysAgo(9), size: 45_100_000, includes_key: true },
  { id: '2b3c4d5e6f708192a3b4c5d6e7f80910', kind: 'pre_restore', created_at: daysAgo(15), size: 44_800_000, includes_key: true },
  { id: '1a2b3c4d5e6f708192a3b4c5d6e7f809', kind: 'pre_restore', created_at: daysAgo(20), size: 44_200_000, includes_key: true },
])
const restoreRunStore = collection<{ run: RestoreRun | null }>('core_restore_run', () => ({ run: null }))

// D-154 step-up, like the other sensitive routes (D-76, D-98): the current password, counted against a limit, then a fresh
// two-step code when it is on. Shared by Delete all data and Restore (D-377); null = passed.
async function stepUp(b: { password?: string; code?: string }, what: string): Promise<Response | null> {
    const u = currentUser()!
    if (purgeTries.get().n >= PURGE_MAX_TRIES) return HttpResponse.json({ error: { code: 'rate_limited', message: 'Too many tries. Wait a few minutes and try again.', retry_after: 300 } }, { status: 429, headers: { 'Retry-After': '300' } })
    if (String(b.password ?? '') !== u.password) {
      purgeTries.update((x) => ({ n: x.n + 1 }))
      return fail(400, 'wrong_password', `Wrong password. The password is needed to ${what}.`)
    }
    if (u.twofa) {
      const code = String(b.code ?? '').replace(/\s/g, '')
      if (u.twofa_method === 'email') {
        if (!code) {
          const sent = issueCode(u.id, true)
          if ('error' in sent) return sent.error
          return HttpResponse.json({ error: { code: 'code_required', message: `Type the 6-digit code we emailed you to ${what}.`, method: 'email', sent_to: maskEmail(u.email), resend_after: sent.resend_after } }, { status: 400 })
        }
        const bad = checkCode(u.id, code)
        if (bad) return bad
      } else {
        if (!code) return HttpResponse.json({ error: { code: 'code_required', message: `Type the 6-digit code from your authenticator app to ${what}.`, method: 'app' } }, { status: 400 })
        if (!/^\d{6}$/.test(code)) return fail(400, 'invalid_code', 'The code is 6 digits from your authenticator app.')
        if (!(await verifyTotp(totpSecrets.get()[u.id] ?? '', code))) return fail(400, 'wrong_code', 'Wrong code. Check the time on your phone and enter a new code.')
      }
    }
    purgeTries.set({ n: 0 })
    return null
}

const dataHandlers = [
  http.get(`${API}/core/data/backup`, () => {
    const denied = guard('admin')
    if (denied) return denied
    audit('data.backup', 'backup')
    // Không đưa mật khẩu và khoá vào bản sao lưu mock (SYS-4).
    return download(`vedette-backup-${stamp()}.tar.gz`, { format: 'vedette-backup/1', created_at: nowIso(), org: orgStore.get(), modules: modulesStore.get(), users: usersStore.get().map(adminOf), assets: assetsStore.get(), findings: findingsStore.get(), audit: auditStore.get() })
  }),
  http.get(`${API}/core/data/backups`, () => {
    const denied = guard('admin')
    if (denied) return denied
    return HttpResponse.json({ backups: [...boxBackupsStore.get()].sort((x, y) => y.created_at.localeCompare(x.created_at)) })
  }),
  http.get(`${API}/core/data/restore/run`, () => {
    const denied = guard('admin')
    if (denied) return denied
    return HttpResponse.json(restoreRunStore.get().run)
  }),
  http.post(`${API}/core/data/restore`, async ({ request }) => {
    const denied = guard('admin')
    if (denied) return denied
    const b = await body<{ backup_id?: string; confirm_data_loss?: boolean; password?: string; code?: string }>(request)
    const src = boxBackupsStore.get().find((x) => x.id === b.backup_id)
    if (!src) return fail(404, 'backup_unknown', 'This backup is no longer on the box. Reload the list.')
    if (b.confirm_data_loss !== true) return fail(409, 'confirm_required', 'Restoring replaces everything written since the backup. Confirm to go on.')
    if (restoreRunStore.get().run?.status === 'running') return fail(409, 'busy', 'A restore is already running. Wait for it to finish.')
    const stepped = await stepUp(b, 'restore a backup')
    if (stepped) return stepped
    const at = nowIso()
    const pre: BoxBackup = { id: crypto.randomUUID().replace(/-/g, ''), kind: 'pre_restore', created_at: at, size: src.size, includes_key: true }
    boxBackupsStore.update((l) => [pre, ...l])
    const run: RestoreRun = { id: newId('restore'), backup_id: src.id, backup_created_at: src.created_at, status: 'done', started_at: at, finished_at: at, user: currentUser()!.email, pre_restore_backup_id: pre.id, error: null }
    restoreRunStore.set({ run })
    audit('data.restore', src.created_at)
    return HttpResponse.json(run, { status: 202 })
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
    const stepped = await stepUp(b, 'delete all data')
    if (stepped) return stepped
    purgeTries.set({ n: 0 })
    const removed = { assets: assetsStore.get().length, findings: findingsStore.get().length, audit: auditStore.get().length }
    resetMockDb()
    return HttpResponse.json({ ok: true, removed, kept: ['honeypot_log'] })
  }),
]

export const handlers = [...logExportHandlers, ...setupHandlers, ...generalHandlers, ...accountHandlers, ...usersHandlers, ...auditHandlers, ...updatesHandlers, ...privacyHandlers, ...networkHandlers, ...connectionsHandlers, ...mcpHandlers, ...dataHandlers]
