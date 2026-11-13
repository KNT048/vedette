import { describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { eachOption } from '@/test/formMatrix'
import { toast } from 'sonner'
import { server } from '@/test/server'
import { assetsStore, auditStore, modulesStore, orgStore, sessionStore, usersStore } from '@/mocks/stores'
import { encode } from 'uqr'
import { newSecret, totpAt } from './totp'
import { collection } from '@/mocks/db'
import { MOCK_SETUP_CODE } from './mocks'
import { emailCodes } from './emailCode'
import { CHECK_FAILURES, checkScenario, mockSign, MOCK_IDP_USER } from './mocks'
import { saveSsoFlow, takeSsoFlow } from './ssoFlow'
import type { Role } from '@/lib/session'
import { nav, compareVersion, toBase64 } from './util'

const setModule = (id: string, enabled: boolean) => modulesStore.update((l) => l.map((m) => (m.id === id ? { ...m, enabled } : m)))
const user = () => userEvent.setup()

const NOHASH = { prev_hash: '0'.repeat(64), hash: '0'.repeat(64) } // rows written straight into the store, the chain is not under test here

describe('core: cài đặt ban đầu', () => {
  it('đi hết 4 bước, tạo quản trị, đặt setup_complete và vào trang chủ', async () => {
    const u = user()
    renderApp('/setup', { role: null, setupComplete: false })
    expect(await screen.findByRole('heading', { level: 2, name: 'Organization and administrator account' })).toBeInTheDocument()
    await expectNoA11yViolations()
    // lỗi ở bước 1: mật khẩu ngắn
    await u.type(screen.getByLabelText('Organization name'), 'ABC Company')
    await u.type(screen.getByLabelText('Administrator name'), 'Lan')
    await u.type(screen.getByLabelText('Sign-in email'), 'lan@abc.vn')
    await u.type(screen.getByLabelText('Password'), 'ngan')
    await u.type(screen.getByLabelText('Repeat password'), 'ngan')
    await u.click(screen.getByRole('button', { name: 'Continue' }))
    expect(await screen.findByText(/The password needs at least 12 characters, it has 4 so far/)).toBeInTheDocument()
    // D-75: the one-time setup code from the box's log is asked for on the first step
    expect(screen.getByText("Enter the setup code from the box's log.")).toBeInTheDocument()
    await u.type(screen.getByLabelText('Setup code'), MOCK_SETUP_CODE)
    await u.clear(screen.getByLabelText('Password'))
    await u.clear(screen.getByLabelText('Repeat password'))
    await u.type(screen.getByLabelText('Password'), 'mot-cau-mat-khau-dai')
    await u.type(screen.getByLabelText('Repeat password'), 'mot-cau-mat-khau-dai')
    await u.click(screen.getByRole('button', { name: 'Continue' }))
    // bước 2
    expect(await screen.findByRole('heading', { level: 2, name: 'Network to watch' })).toBeInTheDocument()
    await u.type(screen.getByLabelText('Range 1'), '192.168.10.0/33')
    await u.click(screen.getByRole('button', { name: 'Continue' }))
    expect(await screen.findByText(/"192.168.10.0\/33" is not a valid range/)).toBeInTheDocument()
    await u.clear(screen.getByLabelText('Range 1'))
    // địa chỉ trần thiếu tiền tố: báo lỗi, không tự đoán /24 (kien: có thể là /25)
    await u.type(screen.getByLabelText('Range 1'), '192.168.10.0')
    await u.click(screen.getByRole('button', { name: 'Continue' }))
    expect(await screen.findByText(/"192.168.10.0" has no prefix length/)).toBeInTheDocument()
    expect(screen.getByLabelText('Range 1')).toHaveValue('192.168.10.0')
    await u.clear(screen.getByLabelText('Range 1'))
    await u.type(screen.getByLabelText('Range 1'), '192.168.10.0/24')
    await u.click(screen.getByRole('button', { name: 'Add range' }))
    await u.type(screen.getByLabelText('Range 2'), '10.20.0.0/16')
    await u.click(screen.getByRole('button', { name: 'Add range' }))
    await u.type(screen.getByLabelText('Range 3'), '10.20.0.0/16')
    await u.click(screen.getByRole('button', { name: 'Continue' }))
    expect(await screen.findByText(/10.20.0.0\/16 is listed twice/)).toBeInTheDocument()
    await u.click(screen.getByRole('button', { name: 'Remove range 3' }))
    expect(screen.getByText(/Vedette is provided as is under the Apache-2.0 license/)).toBeInTheDocument()
    await u.click(screen.getByRole('checkbox', { name: /I confirm these ranges belong to my company/ }))
    await u.click(screen.getByRole('button', { name: 'Continue' }))
    // bước 3: tuỳ chọn, chọn module kéo theo phụ thuộc
    expect(await screen.findByRole('heading', { level: 2, name: 'Choose a module bundle' })).toBeInTheDocument()
    await u.click(screen.getByRole('radio', { name: /Custom/ }))
    await u.click(await screen.findByRole('checkbox', { name: /^Vulnerability scan/ }))
    expect(screen.getByRole('checkbox', { name: /^Inventory/ })).toBeChecked()
    expect(screen.getByRole('checkbox', { name: /^Vulnerability feeds/ })).toBeChecked()
    await u.click(screen.getByRole('button', { name: 'Continue' }))
    // bước 4: bỏ qua kênh
    expect(await screen.findByRole('heading', { level: 2, name: 'Where alerts go' })).toBeInTheDocument()
    await u.click(screen.getByRole('button', { name: 'Skip and finish' }))
    expect(await screen.findByRole('heading', { level: 1, name: /^Today/ })).toBeInTheDocument()
    expect(orgStore.get().setup_complete).toBe(true)
    expect(orgStore.get().name).toBe('ABC Company')
    expect(usersStore.get().map((x) => x.email)).toEqual(['lan@abc.vn'])
    expect(assetsStore.get()).toHaveLength(0)
    expect(modulesStore.get().find((m) => m.id === 'scan')!.enabled).toBe(true)
    expect(modulesStore.get().find((m) => m.id === 'agent-intake')!.enabled).toBe(false)
    // phạm vi quét được ghi vào module kiểm kê thật
    const inv = (await (await fetch(`${location.origin}/api/v1/inventory/settings`)).json()) as { lan_ranges: string[]; scope_confirmed_at: string | null; scope_confirmed_by: string | null; active: { enabled: boolean } }
    expect(inv.lan_ranges).toEqual(['192.168.10.0/24', '10.20.0.0/16'])
    expect(inv.scope_confirmed_by).toBe('lan@abc.vn')
    expect(inv.active.enabled).toBe(true)
    expect(auditStore.get().some((a) => a.action === 'core.setup' && a.detail?.includes('commitment confirmed'))).toBe(true)
  })

  it('bước kênh lưu qua module thông báo; token sai báo lỗi và thử lại được', async () => {
    const u = user()
    renderApp('/setup', { role: null, setupComplete: false })
    await u.type(await screen.findByLabelText('Setup code'), MOCK_SETUP_CODE)
    await u.type(screen.getByLabelText('Organization name'), 'XYZ Company')
    await u.type(screen.getByLabelText('Administrator name'), 'Nam')
    await u.type(screen.getByLabelText('Sign-in email'), 'nam@xyz.vn')
    await u.type(screen.getByLabelText('Password'), 'mot-cau-mat-khau-dai')
    await u.type(screen.getByLabelText('Repeat password'), 'mot-cau-mat-khau-dai')
    await u.click(screen.getByRole('button', { name: 'Continue' }))
    await u.type(await screen.findByLabelText('Range 1'), '8.8.8.0/24')
    await u.click(screen.getByRole('button', { name: 'Continue' }))
    expect(await screen.findByText(/8.8.8.0\/24 is not a private range/)).toBeInTheDocument()
    await u.clear(screen.getByLabelText('Range 1'))
    await u.type(screen.getByLabelText('Range 1'), '10.0.0.0/0')
    await u.click(screen.getByRole('button', { name: 'Continue' }))
    expect(await screen.findByText(/0.0.0.0\/0 is not a private range/)).toBeInTheDocument()
    await u.clear(screen.getByLabelText('Range 1'))
    await u.type(screen.getByLabelText('Range 1'), '10.0.0.0/24')
    await u.click(screen.getByRole('button', { name: 'Continue' }))
    await u.click(await screen.findByRole('button', { name: 'Continue' }))
    await u.click(await screen.findByRole('button', { name: 'Finish setup' }))
    expect((await screen.findAllByText('Fill this in.')).length).toBe(2)
    await u.type(screen.getByLabelText('Chat ID to send to'), '-1001234567890')
    await u.type(screen.getByLabelText('Bot token'), 'token-sai')
    await u.click(screen.getByRole('button', { name: 'Finish setup' }))
    expect(await screen.findByText(/The account was created but the channel was not saved/)).toBeInTheDocument()
    expect(orgStore.get().setup_complete).toBe(true)
    await u.clear(screen.getByLabelText('Bot token'))
    await u.type(screen.getByLabelText('Bot token'), '123456789:EXAMPLE_not_a_real_token_0000000000')
    await u.click(screen.getByRole('button', { name: 'Finish setup' }))
    expect(await screen.findByRole('heading', { level: 1, name: /^Today/ })).toBeInTheDocument()
    const ch = (await (await fetch(`${location.origin}/api/v1/notify/channels`)).json()) as { channels: { type: string; configured: boolean; enabled: boolean; fields: Record<string, string>; secret_last4: string }[] }
    const tg = ch.channels.find((c) => c.type === 'telegram')!
    expect(tg).toMatchObject({ configured: true, enabled: true, secret_last4: '0000' })
    expect(tg.fields.chat_id).toBe('-1001234567890')
    const inv = (await (await fetch(`${location.origin}/api/v1/inventory/settings`)).json()) as { lan_ranges: string[]; active: { enabled: boolean } }
    expect(inv.lan_ranges).toEqual(['10.0.0.0/24'])
    expect(inv.active.enabled).toBe(false) // không tick xác nhận: chỉ nghe thụ động
  })

  it('D-75: a wrong setup code sends you back to the first step with the error on the code field; nothing is created', async () => {
    const u = user()
    renderApp('/setup', { role: null, setupComplete: false })
    await u.type(await screen.findByLabelText('Setup code'), 'not-the-code')
    await u.type(screen.getByLabelText('Organization name'), 'XYZ Company')
    await u.type(screen.getByLabelText('Administrator name'), 'Nam')
    await u.type(screen.getByLabelText('Sign-in email'), 'nam@xyz.vn')
    await u.type(screen.getByLabelText('Password'), 'mot-cau-mat-khau-dai')
    await u.type(screen.getByLabelText('Repeat password'), 'mot-cau-mat-khau-dai')
    await u.click(screen.getByRole('button', { name: 'Continue' }))
    await u.type(await screen.findByLabelText('Range 1'), '10.0.0.0/24')
    await u.click(screen.getByRole('button', { name: 'Continue' }))
    await u.click(await screen.findByRole('button', { name: 'Continue' }))
    await u.click(await screen.findByRole('button', { name: 'Skip and finish' }))
    expect(await screen.findByRole('heading', { level: 2, name: 'Organization and administrator account' })).toBeInTheDocument()
    expect(screen.getByText(/The setup code is missing or wrong/)).toBeInTheDocument()
    expect(screen.getByLabelText('Setup code')).toHaveAttribute('aria-invalid', 'true')
    expect(screen.getByLabelText('Setup code')).toHaveValue('not-the-code')
    expect(orgStore.get().setup_complete).toBe(false)
    expect(usersStore.get().some((x) => x.email === 'nam@xyz.vn')).toBe(false)
    // fixing the code is enough: the other fields were kept
    await u.clear(screen.getByLabelText('Setup code'))
    await u.type(screen.getByLabelText('Setup code'), MOCK_SETUP_CODE)
    await u.click(screen.getByRole('button', { name: 'Continue' }))
    await u.click(await screen.findByRole('button', { name: 'Continue' }))
    await u.click(await screen.findByRole('button', { name: 'Continue' }))
    await u.click(await screen.findByRole('button', { name: 'Skip and finish' }))
    expect(await screen.findByRole('heading', { level: 1, name: /^Today/ })).toBeInTheDocument()
    expect(orgStore.get().setup_complete).toBe(true)
  })

  it('D-75 API: the code is judged before every other field and never needed for the sample path', async () => {
    orgStore.update((o) => ({ ...o, setup_complete: false }))
    const post = (b: object) => fetch(`${location.origin}/api/v1/core/setup`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) })
    for (const body of [{}, { setup_code: '' }, { setup_code: 'wrong' }, { setup_code: 'wrong', org: '' }]) {
      const r = await post(body)
      expect(r.status).toBe(403)
      expect(((await r.json()) as { error: { code: string } }).error.code).toBe('invalid_setup_code')
    }
    const bad = await post({ setup_code: MOCK_SETUP_CODE, org: '' })
    expect(((await bad.json()) as { error: { code: string } }).error.code).toBe('invalid_org')
    expect(orgStore.get().setup_complete).toBe(false)
  })

  it('sample data signs in the sample administrator at once', async () => {
    const u = user()
    renderApp('/setup', { role: null, setupComplete: false })
    await u.click(await screen.findByRole('button', { name: 'Use sample data' }))
    expect(await screen.findByRole('heading', { level: 1, name: /^Today/ })).toBeInTheDocument()
    expect(orgStore.get().setup_complete).toBe(true)
    expect(usersStore.get().find((x) => x.id === sessionStore.get().userId)?.email).toBe('admin@acme.example')
  })

  it('the release build (VITE_API_MOCK=off) shows no Use sample data in setup (D-369)', async () => {
    vi.stubEnv('VITE_API_MOCK', 'off')
    try {
      renderApp('/setup', { role: null, setupComplete: false })
      await screen.findByRole('heading', { level: 1 })
      expect(screen.queryByRole('button', { name: 'Use sample data' })).not.toBeInTheDocument()
    } finally { vi.unstubAllEnvs() }
  })

  it('the LAN range typed in setup is stored where Devices → Scope keeps ranges, and the commitment with it', async () => {
    orgStore.update((o) => ({ ...o, setup_complete: false }))
    const res = await fetch(`${location.origin}/api/v1/core/setup`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ setup_code: MOCK_SETUP_CODE, org: 'ABC Company', admin: { name: 'Lan', email: 'lan@abc.vn', password: 'mat-khau-dai-123' }, lan: ['192.168.18.0/24', '10.1.0.0/16'], bundle: 'smb', commitment: true }) })
    expect(res.status).toBe(200)
    const st = (await (await fetch(`${location.origin}/api/v1/inventory/settings`)).json()) as { lan_ranges: string[]; scope_confirmed_at: string | null; scope_confirmed_by: string | null }
    expect(st.lan_ranges).toEqual(['192.168.18.0/24', '10.1.0.0/16'])
    expect(st).toMatchObject({ scope_confirmed_by: 'lan@abc.vn' })
    expect(st.scope_confirmed_at).not.toBeNull()
    const scan = (await (await fetch(`${location.origin}/api/v1/scans/config`)).json()) as { scope: { networks: string[] } }
    expect(scan.scope.networks).toEqual(['192.168.18.0/24', '10.1.0.0/16'])
  })

  it('setup refuses overlapping LAN ranges like Devices → Scope does, and nothing is set up (#350)', async () => {
    orgStore.update((o) => ({ ...o, setup_complete: false }))
    const res = await fetch(`${location.origin}/api/v1/core/setup`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ setup_code: MOCK_SETUP_CODE, org: 'ABC Company', admin: { name: 'Lan', email: 'lan@abc.vn', password: 'mat-khau-dai-123' }, lan: ['192.168.0.0/16', '192.168.18.0/24'], bundle: 'smb', commitment: true }) })
    expect(res.status).toBe(400)
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe('overlap_range')
    expect(orgStore.get().setup_complete).toBe(false)
    const same = await fetch(`${location.origin}/api/v1/core/setup`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ setup_code: MOCK_SETUP_CODE, org: 'ABC Company', admin: { name: 'Lan', email: 'lan@abc.vn', password: 'mat-khau-dai-123' }, lan: ['192.168.18.0/24', '192.168.18.7/24'], bundle: 'smb', commitment: true }) })
    expect(same.status).toBe(200) // the same network written twice is not an overlap
  })

  it('setup writes the same audit rows as the backend, oldest first: the administrator, the sign-in, the setup', async () => {
    orgStore.update((o) => ({ ...o, setup_complete: false }))
    const res = await fetch(`${location.origin}/api/v1/core/setup`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ setup_code: MOCK_SETUP_CODE, org: 'ABC Company', admin: { name: 'Lan', email: 'lan@abc.vn', password: 'mat-khau-dai-123' }, lan: ['192.168.18.0/24'], bundle: 'smb', commitment: true }) })
    expect(res.status).toBe(200)
    const rows = [...auditStore.get()].reverse()
    expect(rows.map((r) => [r.user, r.action, r.target])).toEqual([
      ['lan@abc.vn', 'user.create', 'lan@abc.vn'],
      ['lan@abc.vn', 'auth.login', 'lan@abc.vn'],
      ['lan@abc.vn', 'core.setup', 'ABC Company'],
    ])
  })

  it('đã cài xong thì /setup chuyển về đăng nhập', async () => {
    renderApp('/setup', { role: null })
    expect(await screen.findByRole('button', { name: 'Sign in' })).toBeInTheDocument()
  })
})

describe('core: khung Cài đặt và vai', () => {
  it('/settings chuyển tới mục đầu tiên, a11y sạch', async () => {
    renderApp('/settings')
    expect(await screen.findByRole('heading', { level: 1, name: /Sample Company box/ })).toBeInTheDocument()
    const nav = screen.getByRole('navigation', { name: 'Settings sections' })
    for (const n of ['General', 'Modules', 'Users', 'Connections', 'Audit log', 'Updates', 'Privacy', 'MCP server', 'Data']) expect(within(nav).getByRole('link', { name: n })).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('chỉ xem: menu ẩn mục cần quản trị, URL trực tiếp báo cần quyền', async () => {
    renderApp('/settings/users', { role: 'viewer' })
    expect(await screen.findByText('Users needs a higher role')).toBeInTheDocument()
    const nav = screen.getByRole('navigation', { name: 'Settings sections' })
    expect(within(nav).queryByRole('link', { name: 'User' })).toBeNull()
    expect(within(nav).getByRole('link', { name: 'Privacy' })).toBeInTheDocument()
  })

  it('chỉ xem: mục Chung chỉ đọc, nút Lưu tắt kèm lý do', async () => {
    renderApp('/settings/general', { role: 'viewer' })
    expect(await screen.findByLabelText('Organization name')).toBeDisabled()
    expect(screen.getByRole('note')).toHaveTextContent('Changing it needs the Admin role')
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
  })

  it('mục không tồn tại: thông báo thân thiện', async () => {
    renderApp('/settings/khong-co')
    expect(await screen.findByText('No such settings section')).toBeInTheDocument()
  })

  it('lưu cài đặt chung và ghi nhật ký', async () => {
    const u = user()
    renderApp('/settings/general')
    const name = await screen.findByLabelText('Organization name')
    await u.clear(name)
    await u.type(name, 'New Company')
    await u.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('Saved')).toBeInTheDocument()
    expect(orgStore.get().name).toBe('New Company')
    expect(auditStore.get()[0]!.action).toBe('core.general')
  })

  it('lỗi API hiện thông báo và nút thử lại', async () => {
    server.use(http.get('*/api/v1/core/general', () => HttpResponse.json({ error: { code: 'x', message: 'The settings server is not responding.' } }, { status: 503 })))
    renderApp('/settings/general')
    expect(await screen.findByText('The settings server is not responding.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument()
  })
})

describe('core: module (S-CORE-1)', () => {
  it('bật module thiếu phụ thuộc: hộp thoại "bật kèm"', async () => {
    const u = user()
    setModule('scan', false)
    renderApp('/settings/modules')
    await u.click(await screen.findByRole('switch', { name: 'Turn on module Credentialed scan' }))
    const dlg = await screen.findByRole('dialog', { name: 'Turn on the required modules too?' })
    expect(within(dlg).getByText('Vulnerability scan')).toBeInTheDocument()
    expect(modulesStore.get().find((m) => m.id === 'scan-credentialed')!.enabled).toBe(false)
    await u.click(within(dlg).getByRole('button', { name: 'Turn on together' }))
    await waitFor(() => expect(modulesStore.get().find((m) => m.id === 'scan-credentialed')!.enabled).toBe(true))
    expect(modulesStore.get().find((m) => m.id === 'scan')!.enabled).toBe(true)
  })

  it('tắt module: liệt kê module bị ảnh hưởng và nói dữ liệu được giữ', async () => {
    const u = user()
    renderApp('/settings/modules')
    await u.click(await screen.findByRole('switch', { name: 'Turn off module Inventory' }))
    const dlg = await screen.findByRole('dialog', { name: 'Turn off Inventory?' })
    expect(within(dlg).getByText(/The module's data is kept/)).toBeInTheDocument()
    expect(within(dlg).getByText('Passive sensor')).toBeInTheDocument()
    await u.click(within(dlg).getByRole('button', { name: 'Turn off' }))
    await waitFor(() => expect(modulesStore.get().find((m) => m.id === 'inventory')!.enabled).toBe(false))
    expect(assetsStore.get().length).toBeGreaterThan(0)
  })

  it('vai chỉ xem không bật tắt được, module lõi bị khoá', async () => {
    renderApp('/settings/modules', { role: 'viewer' })
    expect(await screen.findByRole('switch', { name: 'Turn off module Inventory' })).toBeDisabled()
    expect(screen.getByRole('switch', { name: 'Turn off module Core' })).toBeDisabled()
    await expectNoA11yViolations()
  })
})

describe('core: quyền riêng tư (S-CORE-4)', () => {
  it('flow 1 lists the host of a custom feed that is on, host only, read from /feeds/sources', async () => {
    const f = { id: 'cf-1', builtin: false, name: 'Partner list', kind: 'ioc', format: 'json', url: 'https://intel.partner.example:8443/feed.json?token=s3cret', default_url: null, enabled: true, interval_hours: 24, auth: { type: 'none' }, parser: null, last_fetch: null, records: null, status: 'never', error: null, license: null, answered_by: null }
    server.use(http.get('*/api/v1/feeds/sources', () => HttpResponse.json({ items: [f] })))
    renderApp('/settings/privacy')
    await screen.findByRole('table', { name: 'Data flows that leave the box' })
    expect((await screen.findAllByText('Your own feeds right now: intel.partner.example.')).length).toBeGreaterThan(0)
    expect(document.body.textContent).not.toContain('s3cret')
  })
  it('hiện đủ 14 luồng; tín hiệu ẩn danh ghi "không gửi", không công tắc, không payload (D-82, D-153)', async () => {
    renderApp('/settings/privacy')
    const table = await screen.findByRole('table', { name: 'Data flows that leave the box' })
    expect(within(table).getAllByRole('row')).toHaveLength(15)
    for (const n of ['MCP server, read by tools you connect', 'Pull feeds directly from their sources', 'Anonymous signal', 'AI assistant', 'Data sources that need a key', 'Notifications', 'Update check', 'Forwarding to a SIEM', 'News about a CVE', 'External exposure', 'Time sync', 'Single sign-on', 'Connections you add']) expect(within(table).getAllByText(new RegExp(n)).length).toBeGreaterThan(0)
    expect(screen.queryByRole('switch', { name: 'Send anonymous signal' })).toBeNull()
    expect(document.querySelector('pre code')).toBeNull()
    expect(screen.getByText(/Anonymous signal: not sent\. The box sends nothing to the Vedette project\./)).toBeInTheDocument()
    const row = within(table).getByText(/2\. Anonymous signal/).closest('tr')!
    expect(within(row).getAllByText('Not sent').length).toBeGreaterThan(0)
    expect(document.body.textContent).not.toMatch(/\bIDS\b|ids_matches/i) // there is no IDS on the box (D-43)
    await expectNoA11yViolations()
  })

  it('the anonymous signal cannot be turned on: 400 telemetry_unavailable, and it reads as off (D-154)', async () => {
    renderApp('/settings/privacy')
    await screen.findByRole('heading', { level: 1 })
    const on = await fetch(`${location.origin}/api/v1/core/privacy`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ telemetry: true }) })
    expect(on.status).toBe(400)
    expect(((await on.json()) as { error: { code: string } }).error.code).toBe('telemetry_unavailable')
    const off = await fetch(`${location.origin}/api/v1/core/privacy`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ telemetry: false }) })
    expect(off.status).toBe(200)
    const got = (await (await fetch(`${location.origin}/api/v1/core/privacy`)).json()) as { telemetry: { enabled: boolean } }
    expect(got.telemetry.enabled).toBe(false)
  })

  it.each([true, false])('the title never says a signal is sent, whatever telemetry.enabled is (%s)', async (enabled) => {
    await fetch(`${location.origin}/api/v1/core/privacy`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ telemetry: enabled }) }) // true is refused (400): the title does not depend on it
    renderApp('/settings/privacy')
    const h1 = await screen.findByRole('heading', { level: 1 })
    expect(h1).toHaveTextContent('The box connects out only for the flows listed below')
    expect(h1.textContent).not.toMatch(/sends an anonymous signal/i)
    expect(screen.queryByRole('switch', { name: 'Send anonymous signal' })).toBeNull()
    expect(screen.queryByText(/Sending every hour/)).toBeNull()
  })

  it('luồng 8 và 9 theo trạng thái module', async () => {
    setModule('exposure', false)
    renderApp('/settings/privacy')
    const table = await screen.findByRole('table', { name: 'Data flows that leave the box' })
    const row = within(table).getByText(/9\. External exposure/).closest('tr')!
    expect(within(row).getByText('Off')).toBeInTheDocument()
  })

  it('vai chỉ xem xem được nhưng công tắc kiểm tra cập nhật tắt', async () => {
    renderApp('/settings/privacy', { role: 'viewer' })
    expect(await screen.findByRole('switch', { name: 'Automatic update check' })).toBeDisabled()
  })
})

describe('core: dữ liệu', () => {
  it('khôi phục bản sao lưu trên hộp: cần "I understand", bản dữ liệu hiện tại được giữ thành Before restore (D-377)', async () => {
    const u = user()
    renderApp('/settings/data')
    const before = await screen.findAllByRole('button', { name: 'Restore' })
    const preBefore = screen.getAllByText('Before restore').length
    await u.click(before[0]!)
    const dlg = await screen.findByRole('dialog', { name: /Restore the backup from/ })
    within(dlg).getByText(/Everything written since then is replaced/)
    within(dlg).getByText(/keeps a copy of the data it has now/)
    const confirm = within(dlg).getByRole('button', { name: 'Restore' })
    expect(confirm).toBeDisabled()
    within(dlg).getByText(/keeps the last 3 Before restore copies/)
    within(dlg).getByText(/so the oldest Before restore copy, from/)
    await u.click(within(dlg).getByLabelText(/I understand/))
    expect(confirm).toBeDisabled()
    await u.type(within(dlg).getByLabelText('Your current password'), 'wrong')
    await u.click(confirm)
    await within(dlg).findByText(/Wrong password/)
    await u.clear(within(dlg).getByLabelText('Your current password'))
    await u.type(within(dlg).getByLabelText('Your current password'), 'vedette-demo')
    await u.click(confirm)
    await screen.findByText(/The data from before the restore is kept as a backup/)
    await waitFor(() => expect(screen.getAllByText('Before restore')).toHaveLength(preBefore + 1))
    expect(await screen.findAllByRole('button', { name: 'Restore' })).toHaveLength(before.length + 1)
  })

  it('khôi phục không có confirm_data_loss: 409 confirm_required, không gì đổi (D-377)', async () => {
    renderApp('/settings/data')
    await screen.findAllByRole('button', { name: 'Restore' })
    const r = await fetch(`${location.origin}/api/v1/core/data/backups`).then((x) => x.json()) as { backups: { id: string }[] }
    const res = await fetch(`${location.origin}/api/v1/core/data/restore`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ backup_id: r.backups[0]!.id }) })
    expect(res.status).toBe(409)
    expect((await res.json() as { error: { code: string } }).error.code).toBe('confirm_required')
  })

  it('xoá toàn bộ dữ liệu: gõ đúng tên, hộp về trạng thái chưa cài đặt', async () => {
    const u = user()
    const spy = vi.spyOn(nav, 'toSetup').mockImplementation(() => {})
    renderApp('/settings/data')
    await u.click(await screen.findByRole('button', { name: 'Delete all data' }))
    const dlg = await screen.findByRole('dialog', { name: 'Delete all data on the box?' })
    const confirm = within(dlg).getByRole('button', { name: 'Delete everything' })
    expect(confirm).toBeDisabled()
    await u.type(within(dlg).getByLabelText(/Type the organization name/), 'Sample')
    expect(confirm).toBeDisabled()
    await u.type(within(dlg).getByLabelText(/Type the organization name/), ' Company')
    expect(confirm).toBeDisabled() // the password is needed too (D-154)
    expect(within(dlg).queryByLabelText('Two-step code')).toBeNull() // no two-step on this account
    await u.type(within(dlg).getByLabelText('Your current password'), 'vedette-demo')
    expect(confirm).toBeEnabled()
    // what is deleted and what is kept, said exactly
    expect(within(dlg).getByText(/Deleted: all data, users and backups.*decryption key is replaced/)).toBeInTheDocument()
    expect(within(dlg).getByText(/Kept: the TLS certificate, the system journal.*network settings/)).toBeInTheDocument()
    await u.click(confirm)
    await u.click(within(await screen.findByRole('dialog', { name: 'All data deleted' })).getByRole('button', { name: 'Continue to setup' })) // the mock box has a honeypot: what stays is said before leaving
    await waitFor(() => expect(spy).toHaveBeenCalledTimes(1))
    expect(orgStore.get().setup_complete).toBe(false)
    expect(sessionStore.get().userId).toBeNull()
    spy.mockRestore()
  })

  it('mật khẩu sai bị từ chối, 5 lần sai bị chặn, không xoá gì', async () => {
    const u = user()
    const spy = vi.spyOn(nav, 'toSetup').mockImplementation(() => {})
    renderApp('/settings/data')
    await u.click(await screen.findByRole('button', { name: 'Delete all data' }))
    const dlg = await screen.findByRole('dialog', { name: 'Delete all data on the box?' })
    await u.type(within(dlg).getByLabelText(/Type the organization name/), 'Sample Company')
    await u.type(within(dlg).getByLabelText('Your current password'), 'not-the-password')
    await u.click(within(dlg).getByRole('button', { name: 'Delete everything' }))
    expect(await within(dlg).findByText(/The password is needed to delete all data/)).toBeInTheDocument()
    for (let i = 0; i < 4; i++) await u.click(within(dlg).getByRole('button', { name: 'Delete everything' }))
    await u.clear(within(dlg).getByLabelText('Your current password'))
    await u.type(within(dlg).getByLabelText('Your current password'), 'vedette-demo') // the right one, but the limit is reached
    await u.click(within(dlg).getByRole('button', { name: 'Delete everything' }))
    expect(await within(dlg).findByText(/Too many tries/)).toBeInTheDocument()
    expect(spy).not.toHaveBeenCalled()
    expect(assetsStore.get().length).toBeGreaterThan(0)
    spy.mockRestore()
  })

  it('có hai bước: ô mã hiện ra, thiếu hay sai mã bị từ chối, đúng mã mới xoá', async () => {
    const u = user()
    const secret = newSecret()
    collection<Record<string, string>>('core_totp', () => ({})).update((s) => ({ ...s, 'u-admin': secret }))
    usersStore.update((l) => l.map((x) => (x.id === 'u-admin' ? { ...x, twofa: true, twofa_method: 'app' } : x)))
    const spy = vi.spyOn(nav, 'toSetup').mockImplementation(() => {})
    renderApp('/settings/data')
    await u.click(await screen.findByRole('button', { name: 'Delete all data' }))
    const dlg = await screen.findByRole('dialog', { name: 'Delete all data on the box?' })
    await u.type(within(dlg).getByLabelText(/Type the organization name/), 'Sample Company')
    await u.type(within(dlg).getByLabelText('Your current password'), 'vedette-demo')
    expect(within(dlg).getByText('The 6-digit code from your authenticator app.')).toBeInTheDocument()
    await u.click(within(dlg).getByRole('button', { name: 'Delete everything' }))
    expect(await within(dlg).findByText(/Enter the 6-digit code|Type the 6-digit code/)).toBeInTheDocument()
    await u.type(within(dlg).getByLabelText('Two-step code'), '000000')
    await u.click(within(dlg).getByRole('button', { name: 'Delete everything' }))
    expect(await within(dlg).findByText(/Wrong code/)).toBeInTheDocument()
    expect(spy).not.toHaveBeenCalled()
    await u.clear(within(dlg).getByLabelText('Two-step code'))
    await u.type(within(dlg).getByLabelText('Two-step code'), await totpAt(secret, Date.now()))
    await u.click(within(dlg).getByRole('button', { name: 'Delete everything' }))
    await u.click(within(await screen.findByRole('dialog', { name: 'All data deleted' })).getByRole('button', { name: 'Continue to setup' })) // the mock box has a honeypot: what stays is said before leaving
    await waitFor(() => expect(spy).toHaveBeenCalledTimes(1))
    spy.mockRestore()
  })

  it('nói rõ cái gì chưa xoá được (kept) trước khi rời trang', async () => {
    const u = user()
    const spy = vi.spyOn(nav, 'toSetup').mockImplementation(() => {})
    server.use(http.post(`${location.origin}/api/v1/core/data/purge`, () => HttpResponse.json({ ok: true, removed: {}, kept: ['host_backups'] })))
    renderApp('/settings/data')
    await u.click(await screen.findByRole('button', { name: 'Delete all data' }))
    const dlg = await screen.findByRole('dialog', { name: 'Delete all data on the box?' })
    await u.type(within(dlg).getByLabelText(/Type the organization name/), 'Sample Company')
    await u.type(within(dlg).getByLabelText('Your current password'), 'vedette-demo')
    await u.click(within(dlg).getByRole('button', { name: 'Delete everything' }))
    const done = await screen.findByRole('dialog', { name: 'All data deleted' })
    expect(within(done).getByText(/set up without the helper/)).toBeInTheDocument()
    expect(spy).not.toHaveBeenCalled() // the page waits for the administrator
    await u.click(within(done).getByRole('button', { name: 'Continue to setup' }))
    expect(spy).toHaveBeenCalledTimes(1)
    spy.mockRestore()
  })

  it('server từ chối khi tên không khớp', async () => {
    renderApp('/settings/data')
    await screen.findByRole('button', { name: 'Delete all data' })
    const res = await fetch(`${location.origin}/api/v1/core/data/purge`, { method: 'POST', body: JSON.stringify({ confirm: 'sai', password: 'vedette-demo' }) })
    expect(res.status).toBe(400)
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe('confirm_mismatch')
    expect(assetsStore.get().length).toBeGreaterThan(0)
  })

  it('the release build (VITE_API_MOCK=off) does not offer to restore sample data a real box does not have (issue #244)', async () => {
    vi.stubEnv('VITE_API_MOCK', 'off')
    try {
      renderApp('/settings/data')
      await screen.findByRole('button', { name: 'Download backup' })
      expect(screen.queryByRole('button', { name: 'Restore sample data' })).not.toBeInTheDocument()
      expect(screen.queryByText(/Trial build only/)).not.toBeInTheDocument()
    } finally { vi.unstubAllEnvs() }
  })

  it('khôi phục dữ liệu mẫu gọi reset rồi tải lại', async () => {
    const u = user()
    const spy = vi.spyOn(nav, 'reload').mockImplementation(() => {})
    renderApp('/settings/data')
    await u.click(await screen.findByRole('button', { name: 'Restore sample data' }))
    await u.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Restore and reload' }))
    expect(spy).toHaveBeenCalledTimes(1)
    spy.mockRestore()
  })

  it('vai chỉ xem bị chặn ở mục Dữ liệu', async () => {
    renderApp('/settings/data', { role: 'viewer' })
    expect(await screen.findByText('Data needs a higher role')).toBeInTheDocument()
  })
})

describe('core: đăng nhập hai lớp', () => {
  it('đúng mật khẩu nhưng thiếu mã: trang đăng nhập hỏi mã; mã sai bị từ chối; mã đúng vào được', async () => {
    const u = user()
    const secret = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
    localStorage.clear()
    // bật 2FA bằng khoá cố định qua API thật của mock
    sessionStore.set({ userId: 'u-admin' })
    const st = (await (await fetch(`${location.origin}/api/v1/core/account/2fa/start`, { method: 'POST', body: JSON.stringify({ password: 'vedette-demo' }) })).json()) as { secret: string }
    const ok = await fetch(`${location.origin}/api/v1/core/account/2fa/confirm`, { method: 'POST', body: JSON.stringify({ code: await totpAt(st.secret, Date.now()) }) })
    expect(ok.status).toBe(200)
    expect(secret).toBeTruthy()
    renderApp('/login', { role: null })
    await u.type(await screen.findByLabelText('Email'), 'admin@acme.example')
    await u.type(screen.getByLabelText('Password'), 'vedette-demo')
    await u.click(screen.getByRole('button', { name: 'Sign in' }))
    const code = await screen.findByLabelText('6-digit code')
    expect(sessionStore.get().userId).toBeNull()
    await u.type(code, '000000')
    await u.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByText(/Wrong code/)).toBeInTheDocument()
    expect(sessionStore.get().userId).toBeNull()
    await u.clear(code)
    await u.type(code, await totpAt(st.secret, Date.now()))
    await u.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByRole('heading', { level: 1, name: /^Today/ })).toBeInTheDocument()
    expect(sessionStore.get().userId).toBe('u-admin')
  })

  it('API: thiếu mã 401 twofa_required, mã sai 400 invalid_code', async () => {
    usersStore.update((l) => l.map((x) => (x.id === 'u-op' ? { ...x, twofa: true } : x)))
    const login = (extra: object) => fetch(`${location.origin}/api/v1/auth/login`, { method: 'POST', body: JSON.stringify({ email: 'it@acme.example', password: 'vedette-demo', ...extra }) })
    const a = await login({})
    expect(a.status).toBe(401)
    expect(((await a.json()) as { error: { code: string } }).error.code).toBe('twofa_required')
    const b = await login({ code: '123456' })
    expect(b.status).toBe(400)
    expect(((await b.json()) as { error: { code: string } }).error.code).toBe('invalid_code')
    expect(sessionStore.get().userId).toBeNull()
  })
})

describe('core: người dùng, OIDC, nhật ký (S-CORE-3)', () => {
  it('thêm người dùng cho mật khẩu tạm một lần', async () => {
    const u = user()
    renderApp('/settings/users')
    await u.click(await screen.findByRole('button', { name: 'Add user' }))
    await u.type(screen.getByLabelText('Display name'), 'Hoa')
    await u.type(screen.getByLabelText('Sign-in email'), 'hana@acme.example')
    await u.selectOptions(screen.getByLabelText('Role'), 'operator')
    await u.click(screen.getByRole('button', { name: 'Create account' }))
    expect(await screen.findByRole('dialog', { name: 'Account created' })).toBeInTheDocument()
    expect(document.querySelector('pre code')!.textContent).toMatch(/^[0-9a-f]{6}-/)
    expect(usersStore.get().find((x) => x.email === 'hana@acme.example')?.role).toBe('operator')
  })

  it('không hạ vai quản trị cuối cùng', async () => {
    const u = user()
    renderApp('/settings/users')
    await u.selectOptions((await screen.findAllByLabelText('Role of Admin'))[0]!, 'viewer')
    expect((await screen.findAllByText(/who signs in with a password must remain/))[0]).toBeInTheDocument()
    expect(usersStore.get().find((x) => x.id === 'u-admin')!.role).toBe('admin')
  })

  it('đổi vai và vô hiệu người dùng', async () => {
    const u = user()
    renderApp('/settings/users')
    await u.selectOptions((await screen.findAllByLabelText('Role of IT Operator'))[0]!, 'viewer')
    await waitFor(() => expect(usersStore.get().find((x) => x.id === 'u-op')!.role).toBe('viewer'))
    await u.click(screen.getAllByRole('button', { name: 'Disable Director' })[0]!)
    await waitFor(() => expect(usersStore.get().find((x) => x.id === 'u-view')!.disabled).toBe(true))
  })

  it('OIDC: lưu trống báo cả ba ô một lần (QA b8)', async () => {
    const u = user()
    renderApp('/settings/users')
    await u.click(await screen.findByRole('button', { name: 'Turn on SSO sign-in' }))
    await u.click(await screen.findByRole('button', { name: 'Save' }))
    expect(await screen.findByText('Enter the issuer address.')).toBeInTheDocument()
    expect(screen.getByText('Enter the Client ID.')).toBeInTheDocument()
    expect(screen.getByText('Enter the Client secret.')).toBeInTheDocument()
  })

  it('OIDC: bật, lưu, thử, và nút SSO hiện ở trang đăng nhập', async () => {
    const u = user()
    renderApp('/settings/users')
    await u.click(await screen.findByRole('button', { name: 'Turn on SSO sign-in' }))
    await u.type(await screen.findByLabelText('Issuer'), 'http://sso.acme.example')
    await u.type(screen.getByLabelText('Client ID'), 'vedette')
    await u.type(screen.getByLabelText('Client secret'), 'bi-mat-rat-dai')
    // D-194 (5): the redirect address is the SPA callback page, not an API path
    expect(screen.getByText(`${location.origin}/sso/callback`)).toBeInTheDocument()
    // D-195: no access by default
    expect((screen.getByLabelText('People in none of these groups') as HTMLSelectElement).value).toBe('none')
    await u.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText(/The issuer must be an https address/)).toBeInTheDocument()
    await u.clear(screen.getByLabelText('Issuer'))
    await u.type(screen.getByLabelText('Issuer'), 'https://sso.acme.example/realms/main')
    await u.clear(screen.getByLabelText('Scopes'))
    await u.type(screen.getByLabelText('Scopes'), 'email profile')
    await u.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText(/Scopes are words separated by spaces/)).toBeInTheDocument()
    expect(screen.getByLabelText('Scopes')).toHaveAttribute('aria-invalid', 'true') // the error sits under its own field
    expect(screen.getByLabelText('Issuer')).toHaveAttribute('aria-invalid', 'false')
    await u.type(screen.getByLabelText('Scopes'), ' openid groups')
    await u.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText(/ending in/)).toBeInTheDocument()
    await u.click(screen.getByRole('button', { name: 'Test connection' }))
    expect(await screen.findByText('Read the identity provider\'s OIDC configuration.')).toBeInTheDocument()
    expect(within(screen.getByRole('region', { name: 'Endpoints read from the identity provider' })).getByText('Signing keys')).toBeInTheDocument()
    expect(auditStore.get().map((r) => r.action)).toEqual(expect.arrayContaining(['oidc.update', 'oidc.test']))
    await expectNoA11yViolations()
  })

  // D-378: an IdP behind a private CA (the mock stands for one with an issuer under .internal).
  it('OIDC: CA nội bộ của IdP: dán, kiểm, hiện hạn, gỡ (D-378)', async () => {
    const u = user()
    const pem = '-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIBATAKBggqhkjOPQQDAjAUMRIwEAYDVQQDEwlBY21lIFJvb3Q=\n-----END CERTIFICATE-----\n'
    renderApp('/settings/users')
    await u.click(await screen.findByRole('button', { name: 'Turn on SSO sign-in' }))
    await u.type(await screen.findByLabelText('Issuer'), 'https://sso.acme.internal/realms/main')
    await u.type(screen.getByLabelText('Client ID'), 'vedette')
    await u.type(screen.getByLabelText('Client secret'), 'bi-mat-rat-dai')
    await u.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText(/ending in/)).toBeInTheDocument()
    await u.click(screen.getByRole('button', { name: 'Test connection' }))
    expect(await screen.findByText(/does not trust the identity provider's certificate/)).toBeInTheDocument()
    const ca = screen.getByLabelText('Identity provider CA certificate (optional)')
    await u.click(ca)
    await u.paste('-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----')
    await u.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText(/only certificates are accepted/)).toBeInTheDocument()
    expect(ca).toHaveAttribute('aria-invalid', 'true')
    await u.clear(ca)
    await u.paste(pem)
    await u.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText(/CA changed: enter the Client secret again/)).toBeInTheDocument() // INV-3: a new CA needs the secret
    expect(screen.getByLabelText('Client secret')).toHaveAttribute('aria-invalid', 'true')
    await u.type(screen.getByLabelText('Client secret'), 'bi-mat-rat-dai')
    await u.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText(/Saved: Mock internal CA 1, expires/)).toBeInTheDocument()
    await u.click(screen.getByRole('button', { name: 'Test connection' }))
    expect(await screen.findByRole('region', { name: 'Endpoints read from the identity provider' })).toBeInTheDocument()
    await u.click(screen.getByRole('button', { name: 'Remove CA certificate' }))
    await u.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(screen.queryByText(/Saved: Mock internal CA/)).toBeNull())
    expect(screen.getByLabelText('Identity provider CA certificate (optional)')).toHaveValue('')
    await expectNoA11yViolations()
  })

  it('trang đăng nhập có nút SSO khi auth-oidc bật và đã cấu hình', async () => {
    setModule('auth-oidc', true)
    const r = await fetch(`${location.origin}/api/v1/core/auth-options`)
    expect(((await r.json()) as { oidc: boolean }).oidc).toBe(false) // bật nhưng chưa cấu hình issuer
    renderApp('/login', { role: null })
    expect(await screen.findByRole('button', { name: 'Sign in' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Sign in with SSO' })).toBeNull()
  })
})

// D-194, D-195, D-196: the SSO round trip on the mock. The mock skips the identity provider: its authorization address is the
// callback page itself, with a code. The identity there is MOCK_IDP_USER (groups vedette-operators and staff).
describe('core: đăng nhập SSO (S-CORE-3, D-194..D-196)', () => {
  const ISSUER = 'https://sso.acme.example'
  async function configure(map: { group: string; role: Role }[], default_role: Role | null = null) {
    setModule('auth-oidc', true)
    sessionStore.set({ userId: 'u-admin' })
    const put = await fetch(`${location.origin}/api/v1/core/oidc`, { method: 'PUT', body: JSON.stringify({ issuer: ISSUER, client_id: 'v', client_secret: 'bi-mat-rat-dai', scopes: 'openid email profile', groups_claim: 'groups', default_role, role_map: map }) })
    expect(put.status).toBe(200)
    sessionStore.set({ userId: null })
  }
  /** What the sign-in page does: start, keep the binding in this tab; returns the callback path the IdP would send back. */
  async function start(): Promise<string> {
    const r = await fetch(`${location.origin}/api/v1/auth/oidc/start`, { method: 'POST' })
    const b = (await r.json()) as { authorize_url: string; binding: string }
    saveSsoFlow({ binding: b.binding, next: '/account' })
    const url = new URL(b.authorize_url)
    return url.pathname + url.search
  }
  const ssoUser = () => usersStore.get().find((x) => x.email === MOCK_IDP_USER.email)

  it('nút SSO bắt đầu luồng và giữ binding trong tab này', async () => {
    const u = user()
    await configure([{ group: 'vedette-operators', role: 'operator' }])
    const assign = vi.fn()
    vi.stubGlobal('location', { ...window.location, origin: location.origin, assign })
    try {
      renderApp('/login?next=%2Faccount', { role: null })
      await u.click(await screen.findByRole('button', { name: 'Sign in with SSO' }))
      await waitFor(() => expect(assign).toHaveBeenCalledOnce())
    } finally { vi.unstubAllGlobals() }
    expect(String(assign.mock.calls[0]![0])).toMatch(/\/sso\/callback\?code=mock-[0-9a-f]+&state=[0-9a-f]{64}$/)
    expect(takeSsoFlow()).toEqual({ binding: expect.stringMatching(/^[0-9a-f]{64}$/), next: '/account' })
  })

  it('lần đầu: tạo tài khoản SSO với vai cao nhất của nhóm, vào trang đang định vào', async () => {
    await configure([{ group: 'staff', role: 'viewer' }, { group: 'vedette-operators', role: 'operator' }, { group: 'other', role: 'admin' }])
    renderApp(await start(), { role: null })
    expect(await screen.findByText(/Your password and two-step sign-in are set at your identity provider/)).toBeInTheDocument()
    expect(ssoUser()).toMatchObject({ role: 'operator', sso: { iss: ISSUER, sub: MOCK_IDP_USER.sub }, password: '' })
    expect(sessionStore.get().userId).toBe(ssoUser()!.id)
    const rows = auditStore.get().map((r) => `${r.action} ${r.detail ?? ''}`)
    expect(rows).toEqual(expect.arrayContaining(['user.create SSO', 'auth.login SSO']))
    // D-195 (5), D-196 (1): no password, no Vedette two-step sign-in
    expect(screen.queryByRole('button', { name: 'Change password' })).toBeNull()
    const login = await fetch(`${location.origin}/api/v1/auth/login`, { method: 'POST', body: JSON.stringify({ email: MOCK_IDP_USER.email, password: '' }) })
    expect(login.status).toBe(400)
  })

  it('vai đồng bộ theo nhóm ở mỗi lần đăng nhập', async () => {
    await configure([{ group: 'vedette-operators', role: 'operator' }])
    renderApp(await start(), { role: null })
    await screen.findByText(/Your password and two-step sign-in are set at your identity provider/)
    await configure([{ group: 'vedette-operators', role: 'viewer' }])
    renderApp(await start(), { role: null })
    await waitFor(() => expect(ssoUser()?.role).toBe('viewer'))
    expect(auditStore.get().some((r) => r.action === 'user.role' && r.detail?.includes('SSO groups'))).toBe(true)
  })

  it('không nhóm nào khớp và vai mặc định là No access → từ chối, không tạo tài khoản', async () => {
    await configure([{ group: 'vedette-admins', role: 'admin' }])
    renderApp(await start(), { role: null })
    expect(await screen.findByRole('alert')).toHaveTextContent('Your company account is not in a group that may use Vedette')
    expect(screen.getByRole('link', { name: 'Back to sign in' })).toHaveAttribute('href', '/login')
    expect(ssoUser()).toBeUndefined()
    expect(auditStore.get().some((r) => r.action === 'auth.login_failed' && r.detail === 'SSO: no_access')).toBe(true)
    await expectNoA11yViolations()
  })

  it('vai mặc định cho người không thuộc nhóm nào khi quản trị viên chọn', async () => {
    await configure([], 'viewer')
    renderApp(await start(), { role: null })
    await screen.findByText(/Your password and two-step sign-in are set at your identity provider/)
    expect(ssoUser()?.role).toBe('viewer')
  })

  it('liên kết gọi lại mở ở tab khác (không có binding) hay dùng lại → từ chối', async () => {
    await configure([{ group: 'vedette-operators', role: 'operator' }])
    const path = await start()
    const kept = takeSsoFlow()! // another tab: nothing kept here
    renderApp(path, { role: null })
    expect(await screen.findByRole('alert')).toHaveTextContent('started in another tab')
    expect(ssoUser()).toBeUndefined()
    // the state was spent by that try: even the right binding no longer helps
    const state = new URLSearchParams(path.split('?')[1]).get('state')
    const again = await fetch(`${location.origin}/api/v1/auth/oidc/callback`, { method: 'POST', body: JSON.stringify({ code: 'x', state, binding: kept.binding }) })
    expect(again.status).toBe(400)
    expect(((await again.json()) as { error: { code: string } }).error.code).toBe('sso_expired')
  })

  it('IdP trả lỗi → hiện mã lỗi, không gọi hộp', async () => {
    const calls: string[] = []
    const seen = ({ request }: { request: Request }) => { calls.push(new URL(request.url).pathname) }
    server.events.on('request:start', seen)
    try {
      renderApp('/sso/callback?error=access_denied&state=x', { role: null })
      expect(await screen.findByRole('alert')).toHaveTextContent('Your identity provider did not sign you in (access_denied). Try again')
    } finally { server.events.removeListener('request:start', seen) }
    expect(calls).not.toContain('/api/v1/auth/oidc/callback')
  })

  it('module tắt: không có route SSO (404); địa chỉ khác địa chỉ đã đăng ký → 409 sso_wrong_address', async () => {
    const r = await fetch(`${location.origin}/api/v1/auth/oidc/start`, { method: 'POST' })
    expect(r.status).toBe(404)
    await configure([{ group: 'vedette-operators', role: 'operator' }])
    // the administrator saved from another address: that is the one registered at the identity provider
    collection<{ redirect_uri?: string }>('oidc_config', () => ({})).update((c) => ({ ...c, redirect_uri: 'https://vedette.acme.example/sso/callback' }))
    const w = await fetch(`${location.origin}/api/v1/auth/oidc/start`, { method: 'POST' })
    expect(w.status).toBe(409)
    expect(((await w.json()) as { error: { code: string; message: string } }).error).toMatchObject({ code: 'sso_wrong_address', message: expect.stringContaining('https://vedette.acme.example') })
  })

  it('luồng gắn với issuer/client lúc bắt đầu: đổi cấu hình giữa chừng → hết hạn', async () => {
    await configure([{ group: 'vedette-operators', role: 'operator' }])
    const path = await start()
    sessionStore.set({ userId: 'u-admin' })
    await fetch(`${location.origin}/api/v1/core/oidc`, { method: 'PUT', body: JSON.stringify({ issuer: 'https://other.acme.example', client_id: 'v', client_secret: '', scopes: 'openid', groups_claim: 'groups', default_role: null, role_map: [{ group: 'vedette-operators', role: 'operator' }] }) })
    sessionStore.set({ userId: null })
    renderApp(path, { role: null })
    expect(await screen.findByRole('alert')).toHaveTextContent('expired or was already used')
    expect(ssoUser()).toBeUndefined()
  })

  it('rời nhóm → từ chối và kết thúc phiên đang có của người đó', async () => {
    await configure([{ group: 'vedette-operators', role: 'operator' }])
    renderApp(await start(), { role: null })
    await screen.findByText(/Your password and two-step sign-in are set at your identity provider/)
    const id = ssoUser()!.id
    expect(sessionStore.get().userId).toBe(id)
    await configure([])
    sessionStore.set({ userId: id })
    renderApp(await start(), { role: null })
    expect(await screen.findByRole('alert')).toHaveTextContent('not in a group')
    expect(sessionStore.get().userId).toBeNull()
  })

  it('đổi IdP: tài khoản SSO cũ được gắn lại chỉ khi email đã xác minh', async () => {
    usersStore.update((l) => [...l, { id: 'u-old', name: 'Old', email: MOCK_IDP_USER.email, role: 'viewer', password: '', twofa: false, created_at: '2026-10-01T02:00:00Z', last_login: null, sso: { iss: 'https://old-idp.acme.example', sub: 'old-sub' } }])
    await configure([{ group: 'vedette-operators', role: 'operator' }])
    MOCK_IDP_USER.email_verified = undefined // the new IdP does not say (Entra)
    try {
      renderApp(await start(), { role: null })
      expect(await screen.findByRole('alert')).toHaveTextContent('does not belong to this SSO identity')
      expect(usersStore.get().find((x) => x.id === 'u-old')?.sso?.iss).toBe('https://old-idp.acme.example')
    } finally { MOCK_IDP_USER.email_verified = true }
    renderApp(await start(), { role: null })
    await screen.findByText(/Your password and two-step sign-in are set at your identity provider/)
    expect(usersStore.get().find((x) => x.id === 'u-old')).toMatchObject({ role: 'operator', sso: { iss: ISSUER, sub: MOCK_IDP_USER.sub } })
    expect(auditStore.get().some((r) => r.action === 'user.sso_relink')).toBe(true)
  })

  it('email đã thuộc tài khoản mật khẩu → không nối (D-195 (3))', async () => {
    usersStore.update((l) => [...l, { id: 'u-pw', name: 'Same', email: MOCK_IDP_USER.email, role: 'admin', password: 'x'.repeat(12), twofa: false, created_at: '2026-10-01T02:00:00Z', last_login: null }])
    await configure([{ group: 'vedette-operators', role: 'operator' }])
    renderApp(await start(), { role: null })
    expect(await screen.findByRole('alert')).toHaveTextContent('does not belong to this SSO identity')
    expect(usersStore.get().find((x) => x.id === 'u-pw')).toMatchObject({ role: 'admin' })
    expect(usersStore.get().find((x) => x.id === 'u-pw')?.sso).toBeUndefined()
    expect(sessionStore.get().userId).toBeNull()
  })

  it('tài khoản SSO bị vô hiệu → từ chối dù IdP cho qua', async () => {
    await configure([{ group: 'vedette-operators', role: 'operator' }])
    usersStore.update((l) => [...l, { id: 'u-sso', name: 'S', email: MOCK_IDP_USER.email, role: 'operator', password: '', twofa: false, created_at: '2026-10-01T02:00:00Z', last_login: null, disabled: true, sso: { iss: ISSUER, sub: MOCK_IDP_USER.sub } }])
    renderApp(await start(), { role: null })
    expect(await screen.findByRole('alert')).toHaveTextContent('This account has been disabled')
  })

  it('Users: tài khoản SSO không đổi vai, không đặt lại mật khẩu; quản trị viên mật khẩu cuối cùng được giữ', async () => {
    const u = user()
    usersStore.update((l) => [...l, { id: 'u-sso', name: 'Sso Admin', email: MOCK_IDP_USER.email, role: 'admin', password: '', twofa: false, created_at: '2026-10-01T02:00:00Z', last_login: null, sso: { iss: ISSUER, sub: MOCK_IDP_USER.sub } }])
    renderApp('/settings/users')
    expect((await screen.findAllByText('Through SSO'))[0]).toBeInTheDocument()
    expect(screen.getAllByText('Set by SSO groups')[0]).toBeInTheDocument()
    expect(screen.queryAllByLabelText('Role of Sso Admin')).toHaveLength(0)
    expect(screen.queryAllByRole('button', { name: 'Reset password of Sso Admin' })).toHaveLength(0)
    const patch = await fetch(`${location.origin}/api/v1/core/users/u-sso`, { method: 'PATCH', body: JSON.stringify({ role: 'viewer' }) })
    expect(patch.status).toBe(409)
    // D-196 (3): the SSO admin does not count; the only password admin stays
    await u.selectOptions((await screen.findAllByLabelText('Role of Admin'))[0]!, 'viewer')
    expect((await screen.findAllByText(/who signs in with a password must remain/))[0]).toBeInTheDocument()
  })

  it('tắt SSO: hộp thoại nói số người chỉ đăng nhập bằng SSO', async () => {
    const u = user()
    await configure([{ group: 'vedette-operators', role: 'operator' }])
    usersStore.update((l) => [...l, { id: 'u-sso', name: 'S', email: MOCK_IDP_USER.email, role: 'operator', password: '', twofa: false, created_at: '2026-10-01T02:00:00Z', last_login: null, sso: { iss: ISSUER, sub: MOCK_IDP_USER.sub } }])
    renderApp('/settings/users')
    await u.click(await screen.findByRole('button', { name: 'Turn off SSO' }))
    const dialog = await screen.findByRole('dialog', { name: 'Turn off SSO sign-in?' })
    expect(dialog).toHaveTextContent('1 person signs in only through SSO')
    await u.click(within(dialog).getByRole('button', { name: 'Turn off SSO' }))
    await waitFor(() => expect(modulesStore.get().find((m) => m.id === 'auth-oidc')?.enabled).toBe(false))
  })
})

describe('core: nhật ký (S-CORE-3)', () => {
  it('nhật ký lọc được theo chữ và nhóm', async () => {
    const u = user()
    auditStore.set([
      { id: 'a1', ts: new Date().toISOString(), user: 'admin@acme.example', action: 'module.enable', target: 'scan', detail: null, ...NOHASH },
      { id: 'a2', ts: new Date().toISOString(), user: 'it@acme.example', action: 'user.create', target: 'hana@acme.example', detail: null, ...NOHASH },
    ])
    renderApp('/settings/audit')
    expect(await screen.findByText('2 log lines match the filters', { exact: false })).toBeInTheDocument()
    await u.selectOptions(screen.getByLabelText('Kind of action'), 'user')
    expect(await screen.findByRole('heading', { level: 1, name: /^1 log lines/ })).toBeInTheDocument()
    const table = screen.getByRole('table', { name: 'Audit log' })
    expect(within(table).getByText('Create user')).toBeInTheDocument()
    await u.type(screen.getByLabelText('Search text'), 'khong-co-gi')
    expect((await screen.findAllByText(/No line matches the filters/)).length).toBeGreaterThan(0)
    await expectNoA11yViolations()
  })

  it('xuất CSV chống công thức và đúng dấu ngoặc', async () => {
    renderApp('/settings/audit')
    await screen.findByRole('table', { name: 'Audit log' })
    auditStore.set([{ id: 'x', ts: '2026-11-06T01:00:00.000Z', user: 'a@b.vn', action: 'data.export', target: '=HYPERLINK("x")', detail: 'yes, comma', ...NOHASH }])
    const res = await fetch(`${location.origin}/api/v1/core/audit/export`)
    const text = await res.text()
    expect(res.headers.get('Content-Disposition')).toContain('vedette-audit.csv')
    expect(text).toContain(`"'=HYPERLINK(""x"")"`)
    expect(text).toContain('"yes, comma"')
  })
})

describe('core: cập nhật (S-CORE-2)', () => {
  it('cảnh báo khuyến cáo, cập nhật phần mềm rồi khuyến cáo hết', async () => {
    const u = user()
    renderApp('/settings/updates')
    expect(await screen.findByRole('alert')).toHaveTextContent('1 known vulnerabilities')
    await u.click(screen.getByRole('button', { name: 'Update Vedette software' }))
    // D-340: the software update is a run with steps; Apply and Rollback wait for it, the toast comes at its end
    expect(await screen.findByRole('heading', { name: 'Updating Vedette software to 0.9.4' })).toBeInTheDocument()
    expect(screen.getByText(/^Step 1 of 4: update the system helper/)).toBeInTheDocument() // D-316: the release brings a newer helper
    expect(screen.getByRole('button', { name: /^Back to .*Vedette software/i })).toBeDisabled()
    expect(await screen.findByText(/switched to the new build/, undefined, { timeout: 8000 })).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByRole('alert')).toBeNull())
    expect(screen.getByRole('table', { name: 'Versions in use' })).toHaveTextContent('0.9.4')
  })

  it('rollback that restores the database: warns, needs the box ticked, then goes back (D-340)', async () => {
    const u = user()
    renderApp('/settings/updates')
    await u.click(await screen.findByRole('button', { name: 'Update Vedette software' }))
    expect(await screen.findByRole('heading', { name: 'Vedette software updated to 0.9.4' }, { timeout: 8000 })).toBeInTheDocument() // not a toast: one of the test before may still show
    await u.click(await screen.findByRole('button', { name: /^Back to 0\.9\.3/ }))
    const dlg = await screen.findByRole('dialog')
    expect(dlg).toHaveTextContent('Data written since the update is lost.')
    const go = within(dlg).getByRole('button', { name: 'Roll back' })
    expect(go).toBeDisabled()
    await u.click(within(dlg).getByRole('checkbox', { name: 'I understand that data written since the update is lost.' }))
    expect(go).toBeEnabled()
    await u.click(go)
    expect(await screen.findByText('Vedette software rolled back.', undefined, { timeout: 8000 })).toBeInTheDocument()
    expect(within(screen.getByRole('table', { name: 'Versions in use' })).getByText('0.9.3')).toBeInTheDocument()
  })

  it('a rollback that restores the database without confirm_data_loss is refused with 409 confirm_required', async () => {
    const u = user()
    renderApp('/settings/updates')
    await u.click(await screen.findByRole('button', { name: 'Update Vedette software' }))
    expect(await screen.findByRole('heading', { name: 'Vedette software updated to 0.9.4' }, { timeout: 8000 })).toBeInTheDocument() // not a toast: one of the test before may still show
    const r = await fetch(`${location.origin}/api/v1/core/updates/rollback`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ component: 'software' }) })
    expect(r.status).toBe(409)
    expect(((await r.json()) as { error: { code: string } }).error.code).toBe('confirm_required')
  })

  it('a run that went back shows why and no success toast (D-340)', async () => {
    const success = vi.spyOn(toast, 'success')
    const run = { id: 'ur1', action: 'update', component: 'software', from: '0.9.3', to: '0.9.4', status: 'reverted', steps: ['download', 'restart', 'start'], step: null, started_at: '2026-11-12T08:00:00Z', finished_at: '2026-11-12T08:09:00Z', user: 'admin@acme.example', error: 'core did not pass its health check, so the box went back to 0.9.3.' }
    server.use(http.get('*/api/v1/core/updates', () => HttpResponse.json({ channel: 'stable', mode: 'manual', check_enabled: true, last_check: '2026-11-12T08:00:00Z', components: [], available: [], history: [], advisories: [], managed: [], run })))
    renderApp('/settings/updates')
    expect(await screen.findByRole('heading', { name: 'Update to 0.9.4 did not start; back on 0.9.3' })).toBeInTheDocument()
    expect(screen.getByText('Went back')).toBeInTheDocument()
    expect(screen.getByText(/did not pass its health check/)).toBeInTheDocument()
    expect(screen.queryByRole('alert')).toBeNull() // an old end is not announced on every visit
    expect(success).not.toHaveBeenCalled()
    success.mockRestore()
  })

  it('while Vedette restarts a read fails: the page stays and says it reconnects, then one toast at the end (D-340)', async () => {
    toast.dismiss() // toasts of the tests before still show for a few seconds
    const u = user()
    renderApp('/settings/updates')
    await u.click(await screen.findByRole('button', { name: 'Update Vedette software' }))
    expect(await screen.findByRole('heading', { name: 'Updating Vedette software to 0.9.4' })).toBeInTheDocument()
    server.use(http.get('*/api/v1/core/updates', () => HttpResponse.error(), { once: true }))
    expect(await screen.findByText('Reconnecting to Vedette…', undefined, { timeout: 4000 })).toBeInTheDocument()
    expect(screen.getByRole('table', { name: 'Versions in use' })).toBeInTheDocument()
    expect(await screen.findByRole('heading', { name: 'Vedette software updated to 0.9.4' }, { timeout: 8000 })).toBeInTheDocument()
    expect(await screen.findAllByText(/switched to the new build/)).toHaveLength(1)
    expect(screen.getAllByRole('button', { name: 'Reload' })).toHaveLength(2) // in the toast and in the panel
  })

  it('a second software run, or a bundle with the software, is refused with 409 busy while one runs; packs still update', async () => {
    const u = user()
    renderApp('/settings/updates')
    await u.click(await screen.findByRole('button', { name: 'Update Vedette software' }))
    expect(await screen.findByRole('heading', { name: 'Updating Vedette software to 0.9.4' })).toBeInTheDocument()
    const post = (path: string, b: unknown) => fetch(`${location.origin}/api/v1/core/updates/${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) })
    const again = await post('apply', { component: 'software' })
    expect(again.status).toBe(409)
    expect(((await again.json()) as { error: { code: string } }).error.code).toBe('busy')
    const items = [{ component: 'software', version: '0.9.4', channel: 'stable' }]
    const created_at = '2026-11-06T00:00:00Z'
    const content = toBase64(JSON.stringify({ format: 'vedette-bundle/1', created_at, items, signature: mockSign(JSON.stringify(items) + created_at) }))
    expect((await post('bundle', { name: 'b.json', size: 10, sha256: '0'.repeat(64), content })).status).toBe(409)
    expect(screen.getByRole('button', { name: 'Import bundle' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Update Log parser pack' })).toBeEnabled()
  })

  it('rollback hỏi xác nhận và chuyển sang cập nhật tay', async () => {
    const u = user()
    renderApp('/settings/updates')
    await u.click(await screen.findByRole('button', { name: /^Back to .*Vedette software/i }))
    const dlg = await screen.findByRole('dialog')
    expect(dlg).toHaveTextContent('0.9.3')
    expect(dlg).not.toHaveTextContent('Data written since the update is lost.')
    await u.click(within(dlg).getByRole('button', { name: 'Roll back' }))
    expect(await screen.findByText('Vedette software rolled back.', undefined, { timeout: 8000 })).toBeInTheDocument()
    const table = screen.getByRole('table', { name: 'Versions in use' })
    expect(within(table).getByText('0.9.2')).toBeInTheDocument()
  })

  it('đổi kênh và chế độ; chế độ tự động tự cài khi kiểm tra', async () => {
    const u = user()
    renderApp('/settings/updates')
    await u.click(await screen.findByRole('button', { name: 'Automatic' }))
    await u.click(screen.getByRole('button', { name: 'Check for Vedette releases' }))
    expect(await screen.findByText(/Installed \d+ new items automatically/)).toBeInTheDocument()
  })

  it('a failed check says so under the settings with the reason, and a good check clears it (D-392)', async () => {
    const u = user()
    checkScenario.set({ code: 'update_source_unreachable' })
    renderApp('/settings/updates')
    await u.click(await screen.findByRole('button', { name: 'Check for Vedette releases' }))
    // One status line (D-407): the failure with its reason, then the last good check, which stays.
    expect(await screen.findByText(/^Last check failed .+: Vedette could not download the update information from GitHub\..* Last successful check /)).toBeInTheDocument()
    expect(screen.queryByText(/^Last checked |^Never checked/)).toBeNull()
    checkScenario.set({ code: null })
    await u.click(screen.getByRole('button', { name: 'Check for Vedette releases' }))
    await waitFor(() => expect(screen.queryByText(/^Last check failed/)).toBeNull())
  })

  it('a build with no release: one status line that does not blame the network, no empty tables, the version in the sidebar (D-407)', async () => {
    sessionStore.set({ userId: 'u-admin' })
    const s = await (await fetch(`${location.origin}/api/v1/core/updates`)).json()
    const e = { at: new Date(Date.now() - 6 * 60_000).toISOString(), code: 'update_not_published', message: CHECK_FAILURES.update_not_published.message }
    server.use(http.get('*/api/v1/core/updates', () => HttpResponse.json({ ...s, last_check: null, last_check_error: e, managed: [], advisories: [] })))
    renderApp('/settings/updates')
    expect(await screen.findByText(/^Last check failed 6 minutes ago: No release found for this version yet/)).toBeInTheDocument()
    expect(screen.queryByText(/Never checked|reach github\.com/)).toBeNull()
    expect(screen.queryByText('No rows.')).toBeNull()
    expect(screen.getByText(/^None listed\. This list comes from the signed release information/)).toBeInTheDocument()
    expect(screen.getByText(/^None known yet\. Advisories arrive with the signed update information/)).toBeInTheDocument()
    const running = s.components.find((c: { id: string }) => c.id === 'software').version
    expect(screen.getAllByRole('link', { name: `Vedette ${running}` })[0]).toHaveAttribute('href', '/settings/updates')
  })

  it('bundle offline: chữ ký sai bị từ chối, chữ ký đúng được cài', async () => {
    const u = user()
    renderApp('/settings/updates')
    const input = await screen.findByLabelText('Bundle file')
    const items = [{ component: 'pack-parsers', version: '1.4.1', channel: 'stable' }]
    const created_at = '2026-11-06T00:00:00Z'
    const bad = JSON.stringify({ format: 'vedette-bundle/1', created_at, items, signature: 'mock-sig-00000000' })
    await u.upload(input, new File([bad], 'bad.json', { type: 'application/json' }))
    expect(await screen.findByText(/Invalid signature/)).toBeInTheDocument()
    const good = JSON.stringify({ format: 'vedette-bundle/1', created_at, items, signature: mockSign(JSON.stringify(items) + created_at) })
    await u.upload(input, new File([good], 'good.json', { type: 'application/json' }))
    expect(await screen.findByText('Bundle imported, 1 new items installed.')).toBeInTheDocument()
  })

  it('chỉ xem: không cập nhật được', async () => {
    renderApp('/settings/updates', { role: 'viewer' })
    expect(await screen.findByRole('button', { name: 'Update Vedette software' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Check for Vedette releases' })).toBeDisabled()
    await expectNoA11yViolations()
  })

  it('so sánh phiên bản', () => {
    expect(compareVersion('0.9.4', '0.10.0-beta.1')).toBe(-1)
    expect(compareVersion('0.10.0', '0.10.0-beta.1')).toBe(1)
    expect(compareVersion('20261106.08', '20261106.12')).toBe(-1)
    expect(toBase64('á')).toBe('w6E=')
  })
})

describe('core: MCP (S-MCP-1)', () => {
  it('bật, tạo token chỉ hiện một lần, thu hồi', async () => {
    const u = user()
    renderApp('/settings/mcp')
    expect(await screen.findByRole('heading', { level: 1, name: 'MCP server is off' })).toBeInTheDocument()
    await u.click(screen.getByRole('switch', { name: 'Turn on MCP server' }))
    expect(await screen.findByText('127.0.0.1:8765')).toBeInTheDocument()
    await u.click(screen.getByRole('button', { name: 'Create token' }))
    expect(await screen.findByText('Name the token so you know which one to revoke later.')).toBeInTheDocument()
    await u.type(screen.getByLabelText('Token name'), 'Claude Desktop')
    await u.click(screen.getByRole('button', { name: 'Create token' }))
    const dlg = await screen.findByRole('dialog', { name: 'Token Claude Desktop created' })
    expect(document.querySelector('[role=dialog] pre code')!.textContent).toMatch(/^vmcp_[0-9a-f]{32}$/)
    await u.click(within(dlg).getByRole('button', { name: 'I have copied it' }))
    const row = (await screen.findByText('Claude Desktop', { selector: 'span' })).closest('tr')!
    expect(row.textContent).not.toMatch(/vmcp_/)
    await u.click(within(row).getByRole('button', { name: 'Revoke token Claude Desktop' }))
    const ask = await screen.findByRole('dialog', { name: 'Revoke token Claude Desktop?' })
    await u.click(within(ask).getByRole('button', { name: 'Cancel' }))
    expect(within(row).getByText('Claude Desktop')).toBeInTheDocument()
    await u.click(within(row).getByRole('button', { name: 'Revoke token Claude Desktop' }))
    await u.click(within(await screen.findByRole('dialog', { name: 'Revoke token Claude Desktop?' })).getByRole('button', { name: 'Revoke' }))
    expect(await screen.findByText('No tokens yet. Create one so an outside tool can connect.')).toBeInTheDocument()
    expect(screen.getByRole('table', { name: 'Tools the MCP server offers' })).toBeInTheDocument()
    await expectNoA11yViolations()
  })
  it('the switch is the module (D-230): off, no /core/mcp path answers and the page asks for none', async () => {
    const u = user()
    setModule('mcp-server', true)
    renderApp('/settings/mcp')
    expect(await screen.findByRole('heading', { level: 1, name: 'MCP server is on, read-only, 0 tokens' })).toBeInTheDocument()
    const real = globalThis.fetch
    const asked: string[] = []
    const spy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => { asked.push(String(input instanceof Request ? input.url : input)); return real(input, init) })
    await u.click(screen.getByRole('switch', { name: 'Turn off MCP server' }))
    expect(await screen.findByRole('heading', { level: 1, name: 'MCP server is off' })).toBeInTheDocument()
    expect(await screen.findByRole('switch', { name: 'Turn on MCP server' })).toBeInTheDocument()
    expect(asked.filter((x) => x.endsWith('/api/v1/core/mcp'))).toEqual([]) // no 404 call once it is off
    spy.mockRestore()
    expect(modulesStore.get().find((m) => m.id === 'mcp-server')?.enabled).toBe(false)
    expect(screen.queryByText('127.0.0.1:8765')).not.toBeInTheDocument()
    expect((await call('/core/mcp', 'GET')).status).toBe(404)
    expect((await call('/core/mcp/tokens', 'POST', { name: 'x', scopes: ['feeds'] })).status).toBe(404)
    expect((await call('/core/mcp/tokens/t-1', 'DELETE')).status).toBe(404)
  })
  it('a port another program holds is said plainly, so no token goes to it (D-230)', async () => {
    setModule('mcp-server', true)
    server.use(http.get('*/api/v1/core/mcp', () => HttpResponse.json({ enabled: true, bind: '127.0.0.1', port: 8765, endpoint: 'http://127.0.0.1:8765/mcp', listening: false,
      listen_error: 'The port 127.0.0.1:8765 could not be opened: another program may hold it. Vedette tries again every 15 seconds.', tokens: [], tools: [], scopes: ['assets'] })))
    renderApp('/settings/mcp')
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('could not be opened')
    expect(alert).toHaveTextContent('Do not give a token to this address')
  })
  it('refuses what the server refuses: bad name, unknown scope, an 11th token', async () => {
    setModule('mcp-server', true)
    renderApp('/settings/mcp') // signs the admin in
    await screen.findByRole('heading', { level: 1, name: 'MCP server is on, read-only, 0 tokens' })
    const create = (b: object) => call('/core/mcp/tokens', 'POST', b)
    expect(await errCode(await create({ name: '<b>', scopes: ['feeds'] }))).toBe('invalid_name')
    expect(await errCode(await create({ name: 'ok', scopes: ['feeds', 'secrets'] }))).toBe('invalid_scopes')
    expect(await errCode(await create({ name: 'ok', scopes: [] }))).toBe('invalid_scopes')
    for (let i = 0; i < 10; i++) expect((await create({ name: `t${i}`, scopes: ['feeds'] })).status).toBe(201)
    expect(await errCode(await create({ name: 'eleven', scopes: ['feeds'] }))).toBe('too_many')
  })
})

describe('core: tài khoản', () => {
  it('đổi mật khẩu: sai mật khẩu cũ, rồi thành công', async () => {
    const u = user()
    renderApp('/account')
    await u.type(await screen.findByLabelText('Current password'), 'sai-roi')
    await u.type(screen.getByLabelText('New password'), 'mat-khau-moi-rat-dai')
    await u.type(screen.getByLabelText('Repeat new password'), 'mat-khau-moi-rat-dai')
    await u.click(screen.getByRole('button', { name: 'Change password' }))
    expect(await screen.findByText('The current password is wrong.')).toBeInTheDocument()
    await u.clear(screen.getByLabelText('Current password'))
    await u.type(screen.getByLabelText('Current password'), 'vedette-demo')
    await u.click(screen.getByRole('button', { name: 'Change password' }))
    expect(await screen.findByText('Password changed.')).toBeInTheDocument()
    expect(usersStore.get().find((x) => x.id === 'u-admin')!.password).toBe('mat-khau-moi-rat-dai')
  })

  it('bật 2FA bằng mã TOTP thật, sai mã bị từ chối, rồi tắt bằng mật khẩu', async () => {
    const u = user()
    renderApp('/account')
    const start = await screen.findByRole('button', { name: 'Set up authenticator app' })
    // D-76: the current password comes first; without it neither method can be started
    expect(start).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Set up email code' })).toBeDisabled()
    await u.type(screen.getByLabelText('Your current password'), 'wrong password here')
    await u.click(start)
    expect(await screen.findByText(/The password is needed to turn on two-step sign-in/)).toBeInTheDocument()
    expect(screen.queryByRole('img', { name: 'QR code for your authenticator app' })).not.toBeInTheDocument()
    await u.clear(screen.getByLabelText('Your current password'))
    await u.type(screen.getByLabelText('Your current password'), 'vedette-demo')
    await u.click(start)
    const key = (await screen.findByText(/^[A-Z2-7]{32}$/)).textContent!
    const otpauth = screen.getByText(/^otpauth:\/\/totp\/Vedette:/).textContent!
    // QR drawn locally: black modules on white with a 4-module quiet zone, own accessible name
    const qr = screen.getByRole('img', { name: 'QR code for your authenticator app' })
    const size = encode(otpauth, { ecc: 'M', border: 0 }).size
    expect(qr.getAttribute('viewBox')).toBe(`0 0 ${size + 8} ${size + 8}`)
    expect(qr.querySelector('rect')).toHaveAttribute('fill', '#fff')
    const d = qr.querySelector('path')!.getAttribute('d')!
    const xs = [...d.matchAll(/M(\d+) (\d+)h/g)].map((m) => [Number(m[1]), Number(m[2])] as const)
    expect(xs.length).toBeGreaterThan(100)
    expect(Math.min(...xs.map(([x]) => x))).toBeGreaterThanOrEqual(4)
    expect(Math.max(...xs.map(([x, y]) => Math.max(x, y)))).toBeLessThanOrEqual(size + 3)
    expect(screen.getByText('Scan this QR code with your authenticator app, or enter the key by hand.')).toBeInTheDocument()
    await u.type(screen.getByLabelText('6-digit code'), '000000')
    await u.click(screen.getByRole('button', { name: 'Confirm and turn on' }))
    expect(await screen.findByText(/Wrong code/)).toBeInTheDocument()
    await u.clear(screen.getByLabelText('6-digit code'))
    await u.type(screen.getByLabelText('6-digit code'), await totpAt(key, Date.now()))
    await u.click(screen.getByRole('button', { name: 'Confirm and turn on' }))
    expect(await screen.findByText('Two-step sign-in is on.')).toBeInTheDocument()
    expect(usersStore.get().find((x) => x.id === 'u-admin')!.twofa).toBe(true)
    await u.click(screen.getByRole('button', { name: 'Turn off two-step sign-in' }))
    await u.type(screen.getByLabelText('Current password', { selector: '#twofa-off-pw' }), 'vedette-demo')
    await u.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Turn off' }))
    await waitFor(() => expect(usersStore.get().find((x) => x.id === 'u-admin')!.twofa).toBe(false))
  })

  it('kết thúc phiên khác, a11y sạch', async () => {
    const u = user()
    renderApp('/account', { role: 'viewer' })
    await u.click(await screen.findByRole('button', { name: 'End session Firefox on Windows at 192.168.10.61' }))
    expect(await screen.findByText('Session ended.')).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('walk 2026-11-12: short device label with the raw text as tooltip; a guessable new password is refused under New password (D-389)', async () => {
    const u = user()
    renderApp('/account')
    const label = await screen.findByText('Firefox on Windows')
    expect(label).toHaveAttribute('title', expect.stringMatching(/^Mozilla\/5\.0 \(Windows NT 10\.0/))
    await u.type(screen.getByLabelText('Current password'), 'vedette-demo')
    await u.type(screen.getByLabelText('New password'), 'password1234')
    await u.type(screen.getByLabelText('Repeat new password'), 'password1234')
    await u.click(screen.getByRole('button', { name: 'Change password' }))
    expect(await screen.findByText(/^This password is too easy to guess/)).toBeInTheDocument()
    expect(screen.getByLabelText('New password')).toHaveAttribute('aria-invalid', 'true')
    expect(usersStore.get().find((x) => x.id === 'u-admin')!.password).toBe('vedette-demo')
  })

  it('two-step on: an administrator sees the box-console reset with their email, another user is told to ask an administrator (D-389)', async () => {
    usersStore.update((l) => l.map((x) => (x.id === 'u-admin' || x.id === 'u-op' ? { ...x, twofa: true, twofa_method: 'app' } : x)))
    const { unmount } = renderApp('/account')
    expect(await screen.findByText("docker exec vedette-core /vedette reset-admin 'admin@acme.example'")).toBeInTheDocument()
    unmount()
    renderApp('/account', { role: 'operator' })
    expect(await screen.findByText(/Ask an administrator to turn two-step sign-in off for you/)).toBeInTheDocument()
    expect(screen.queryByText(/reset-admin/)).not.toBeInTheDocument()
  })
})

// ---------- D-35: hai kiểu đăng nhập hai bước ----------
const call = (path: string, method = 'POST', body: object = {}) => fetch(`${location.origin}/api/v1${path}`, { method, body: method === 'GET' ? undefined : JSON.stringify(body) })
const errCode = async (r: Response) => ((await r.json()) as { error: { code: string } }).error.code
const setUser = (id: string, patch: object) => usersStore.update((l) => l.map((x) => (x.id === id ? { ...x, ...patch } : x)))
const slot = (id: string) => emailCodes.get()[id]!
const ageCode = (id: string, ms: number) => emailCodes.update((all) => ({ ...all, [id]: { ...all[id]!, pending: all[id]!.pending && { ...all[id]!.pending!, sent_at: all[id]!.pending!.sent_at - ms, expires: all[id]!.pending!.expires - ms }, sends: all[id]!.sends } }))
const startEmail = (password = 'vedette-demo') => call('/core/account/2fa/email/start', 'POST', { password })
const startApp = (password = 'vedette-demo') => call('/core/account/2fa/start', 'POST', { password })
const loginAs = (email: string, extra: object = {}) => call('/auth/login', 'POST', { email, password: 'vedette-demo', ...extra })

describe('core: turning two-step on needs the current password (D-76)', () => {
  it('both start calls refuse a wrong or missing password and create nothing', async () => {
    sessionStore.set({ userId: 'u-admin' })
    for (const body of [{}, { password: '' }, { password: 'wrong' }]) {
      expect(await errCode(await call('/core/account/2fa/start', 'POST', body))).toBe('wrong_password')
      expect(await errCode(await call('/core/account/2fa/email/start', 'POST', body))).toBe('wrong_password')
    }
    expect(emailCodes.get()['u-admin']).toBeUndefined() // no code was issued
    expect(await errCode(await call('/core/account/2fa/confirm', 'POST', { code: '123456' }))).toBe('no_pending') // no key was made
    expect((await startApp()).status).toBe(200)
    expect((await startEmail()).status).toBe(200)
  })
})

describe('core: two-step sign-in, email code method (D-35)', () => {
  it('account: both methods are offered; email is enabled when the email channel is on', async () => {
    const u = user()
    renderApp('/account')
    expect(await screen.findByRole('button', { name: 'Set up authenticator app' })).toBeDisabled() // until the password is typed (D-76)
    await u.type(screen.getByLabelText('Your current password'), 'vedette-demo')
    expect(screen.getByRole('button', { name: 'Set up authenticator app' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Set up email code' })).toBeEnabled()
    expect(screen.getByText(/emails a 6-digit code to your sign-in address, a•••@acme\.example/)).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('account: email option is disabled with the reason when the channel is removed; admins get a link, others are told to ask', async () => {
    sessionStore.set({ userId: 'u-admin' })
    expect((await call('/notify/channels/email', 'DELETE')).status).toBe(204)
    const { unmount } = renderApp('/account')
    const btn = await screen.findByRole('button', { name: 'Set up email code' })
    expect(btn).toBeDisabled()
    await user().type(screen.getByLabelText('Your current password'), 'vedette-demo')
    expect(btn).toBeDisabled() // the password alone does not enable it: the channel is missing
    expect(screen.getByText(/the email alert channel, which is not set up or is turned off/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Open alert channels' })).toHaveAttribute('href', '/settings/channels')
    expect((await startEmail()).status).toBe(409)
    expect(screen.getByRole('button', { name: 'Set up authenticator app' })).toBeEnabled()
    unmount()
    renderApp('/account', { role: 'viewer' })
    expect(await screen.findByText(/Ask an administrator to set up the email channel\./)).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Open alert channels' })).not.toBeInTheDocument()
  })

  it('account: Notifications module off is a separate reason', async () => {
    setModule('notify', false)
    renderApp('/account')
    expect(await screen.findByRole('button', { name: 'Set up email code' })).toBeDisabled()
    expect(screen.getByText('Email codes need the Notifications module, which is off.')).toBeInTheDocument()
  })

  it('setup: code goes to the masked sign-in email, wrong tries are counted, 5 wrong cancel the code, the right code turns it on', async () => {
    const u = user()
    renderApp('/account')
    await u.type(await screen.findByLabelText('Your current password'), 'vedette-demo')
    await u.click(await screen.findByRole('button', { name: 'Set up email code' }))
    expect(await screen.findByText(/We sent a 6-digit code to a•••@acme\.example/)).toBeInTheDocument()
    const code = slot('u-admin').pending!.code
    expect(code).toMatch(/^\d{6}$/)
    expect(screen.getByTestId('preview-code')).toHaveTextContent(`Preview build: the email would contain ${code}`)
    expect(screen.getByRole('button', { name: /^Send a new code in \d+ s$/ })).toBeDisabled()
    const wrong = code === '000000' ? '111111' : '000000'
    const field = screen.getByLabelText('6-digit code')
    await u.type(field, wrong)
    await u.click(screen.getByRole('button', { name: 'Confirm and turn on' }))
    expect(await screen.findByText('Wrong code. 4 tries left.')).toBeInTheDocument()
    expect(usersStore.get().find((x) => x.id === 'u-admin')!.twofa).toBe(false)
    for (const left of [3, 2, 1]) {
      await u.click(screen.getByRole('button', { name: 'Confirm and turn on' }))
      expect(await screen.findByText(`Wrong code. ${left} ${left === 1 ? 'try' : 'tries'} left.`)).toBeInTheDocument()
    }
    await u.click(screen.getByRole('button', { name: 'Confirm and turn on' }))
    expect(await screen.findByText('Too many wrong codes. Ask for a new code.')).toBeInTheDocument()
    // the cancelled code no longer works even when typed correctly
    await u.clear(field)
    await u.type(field, code)
    await u.click(screen.getByRole('button', { name: 'Confirm and turn on' }))
    expect(await screen.findByText('No code is waiting. Ask for a new code.')).toBeInTheDocument()
    // a new code after the cooldown works
    ageCode('u-admin', 61_000)
    expect((await startEmail()).status).toBe(200)
    const fresh = slot('u-admin').pending!.code
    await u.clear(field)
    await u.type(field, fresh)
    await u.click(screen.getByRole('button', { name: 'Confirm and turn on' }))
    expect((await screen.findAllByText('Two-step sign-in is on.')).length).toBeGreaterThan(0)
    const me = usersStore.get().find((x) => x.id === 'u-admin')!
    expect(me).toMatchObject({ twofa: true, twofa_method: 'email' })
    expect(await screen.findByText('On: Email code')).toBeInTheDocument()
    expect(auditStore.get().some((r) => r.action === 'account.2fa_on' && r.detail === 'email code')).toBe(true)
    // switching: a second method cannot be started while one is on
    expect((await startApp()).status).toBe(409)
    expect((await startEmail()).status).toBe(409)
  })

  it('codes: expire after 10 minutes, single use, 60 s resend wait, 5 sends per hour', async () => {
    sessionStore.set({ userId: 'u-admin' })
    expect((await startEmail()).status).toBe(200)
    const first = slot('u-admin').pending!
    expect(first.expires - first.sent_at).toBe(10 * 60_000)
    const soon = await startEmail()
    expect(soon.status).toBe(429)
    const body = (await soon.json()) as { error: { code: string; message: string; retry_after: number } }
    expect(body.error).toMatchObject({ code: 'resend_too_soon' })
    expect(body.error.retry_after).toBeGreaterThan(0)
    expect(body.error.message).toMatch(/^Wait \d+ seconds before asking for a new code\.$/)
    // expiry
    ageCode('u-admin', 10 * 60_000 + 1)
    const late = await call('/core/account/2fa/email/confirm', 'POST', { code: first.code })
    expect(late.status).toBe(400)
    expect(await late.json()).toMatchObject({ error: { code: 'code_expired', message: 'This code has expired. Ask for a new code.' } })
    // 5 sends per hour: sends 2..5 pass (aging only the cooldown), the 6th is refused
    for (let i = 0; i < 4; i += 1) { ageCode('u-admin', 61_000); expect((await startEmail()).status).toBe(200) }
    ageCode('u-admin', 61_000)
    const many = await startEmail()
    expect(many.status).toBe(429)
    expect(await many.json()).toMatchObject({ error: { code: 'too_many_codes', message: 'Too many codes were sent in the last hour. Try again later.' } })
  })

  it('login: an email-method user gets a code sent, the page says where, preview note, resend with cooldown; wrong code refused; right code signs in; code is single use', async () => {
    const u = user()
    setUser('u-op', { twofa: true, twofa_method: 'email' })
    renderApp('/login', { role: null })
    await u.type(await screen.findByLabelText('Email'), 'it@acme.example')
    await u.type(screen.getByLabelText('Password'), 'vedette-demo')
    await u.click(screen.getByRole('button', { name: 'Sign in' }))
    const field = await screen.findByLabelText('6-digit code')
    expect(field).toHaveAttribute('autocomplete', 'one-time-code')
    expect(field).toHaveFocus()
    expect(screen.getByText('We sent a 6-digit code to i•••@acme.example. It expires in 10 minutes.')).toBeInTheDocument()
    const code = slot('u-op').pending!.code
    expect(screen.getByTestId('preview-code')).toHaveTextContent(code)
    expect(await screen.findByRole('button', { name: /^Send a new code in \d+ s$/ })).toBeDisabled()
    expect(sessionStore.get().userId).toBeNull()
    // wrong code
    await u.type(field, code === '000000' ? '111111' : '000000')
    await u.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByText('Wrong code. 4 tries left.')).toBeInTheDocument()
    expect(sessionStore.get().userId).toBeNull()
    // resend after the 60 s wait (the page countdown follows the clock)
    ageCode('u-op', 61_000)
    vi.useFakeTimers({ toFake: ['Date'], now: Date.now() })
    try { vi.setSystemTime(Date.now() + 61_000) } catch { /* ignore */ }
    await waitFor(() => expect(screen.getByRole('button', { name: 'Send a new code' })).toBeEnabled(), { timeout: 3000 })
    await u.click(screen.getByRole('button', { name: 'Send a new code' }))
    expect(await screen.findByText('A new code was sent to i•••@acme.example.')).toBeInTheDocument()
    vi.useRealTimers()
    const fresh = slot('u-op').pending!.code
    await waitFor(() => expect(screen.getByTestId('preview-code')).toHaveTextContent(fresh))
    await u.type(screen.getByLabelText('6-digit code'), fresh)
    await u.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByRole('heading', { level: 1, name: /^Today/ })).toBeInTheDocument()
    expect(sessionStore.get().userId).toBe('u-op')
    // single use: the same code does nothing the second time
    sessionStore.set({ userId: null })
    const again = await loginAs('it@acme.example', { code: fresh })
    expect(again.status).toBe(400)
    expect(await errCode(again)).toBe('no_code')
    expect(sessionStore.get().userId).toBeNull()
  })

  it('login API: 401 twofa_required carries method and masked sent_to; app users get method app and no code is sent', async () => {
    setUser('u-op', { twofa: true, twofa_method: 'email' })
    setUser('u-view', { twofa: true })
    const a = await loginAs('it@acme.example')
    expect(a.status).toBe(401)
    expect(((await a.json()) as { error: Record<string, unknown> }).error).toMatchObject({ code: 'twofa_required', method: 'email', sent_to: 'i•••@acme.example', resend_after: 60 })
    // reloading the page and signing in again within 60 s keeps the code instead of spending another send
    const code = slot('u-op').pending!.code
    const b = await loginAs('it@acme.example')
    expect(b.status).toBe(401)
    expect(slot('u-op').pending!.code).toBe(code)
    expect(slot('u-op').sends).toHaveLength(1)
    const c = await loginAs('director@acme.example')
    expect(c.status).toBe(401)
    const cb = ((await c.json()) as { error: Record<string, unknown> }).error
    expect(cb).toMatchObject({ code: 'twofa_required', method: 'app' })
    expect(cb.sent_to).toBeUndefined()
    expect(emailCodes.get()['u-view']).toBeUndefined()
  })

  it('login API: resend needs the password, obeys the 60 s wait, and only works for email users', async () => {
    setUser('u-op', { twofa: true, twofa_method: 'email' })
    await loginAs('it@acme.example')
    const soon = await call('/auth/login/resend-code', 'POST', { email: 'it@acme.example', password: 'vedette-demo' })
    expect(soon.status).toBe(429)
    expect(await errCode(soon)).toBe('resend_too_soon')
    expect(await errCode(await call('/auth/login/resend-code', 'POST', { email: 'it@acme.example', password: 'wrong' }))).toBe('invalid_credentials')
    expect(await errCode(await call('/auth/login/resend-code', 'POST', { email: 'director@acme.example', password: 'vedette-demo' }))).toBe('not_email_method')
    ageCode('u-op', 61_000)
    const ok = await call('/auth/login/resend-code', 'POST', { email: 'it@acme.example', password: 'vedette-demo' })
    expect(ok.status).toBe(200)
    expect(await ok.json()).toMatchObject({ sent_to: 'i•••@acme.example', resend_after: 60 })
  })

  it('login: when the email channel is off an email-method user is refused (never password-only), with a clear message', async () => {
    const u = user()
    setUser('u-op', { twofa: true, twofa_method: 'email' })
    sessionStore.set({ userId: 'u-admin' })
    await call('/notify/channels/email', 'DELETE')
    sessionStore.set({ userId: null })
    const r = await loginAs('it@acme.example')
    expect(r.status).toBe(503)
    expect(await errCode(r)).toBe('twofa_email_unavailable')
    expect(sessionStore.get().userId).toBeNull()
    renderApp('/login', { role: null })
    await u.type(await screen.findByLabelText('Email'), 'it@acme.example')
    await u.type(screen.getByLabelText('Password'), 'vedette-demo')
    await u.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByText('Two-step email codes cannot be sent right now. Ask an administrator to turn the email channel back on, or to reset your two-step sign-in.')).toBeInTheDocument()
    expect(sessionStore.get().userId).toBeNull()
    expect(screen.queryByLabelText('6-digit code')).not.toBeInTheDocument()
  })

  it('login: after 10 wrong passwords the page says how long to wait, and the right password waits too (S-CORE-3)', async () => {
    const u = user()
    for (let i = 0; i < 10; i++) {
      const r = await fetch(`${location.origin}/api/v1/auth/login`, { method: 'POST', body: JSON.stringify({ email: 'it@acme.example', password: `wrong password ${i}` }) })
      expect(r.status).toBe(400)
    }
    renderApp('/login', { role: null })
    await u.type(await screen.findByLabelText('Email'), 'it@acme.example')
    await u.type(screen.getByLabelText('Password'), 'vedette-demo')
    await u.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByText(/^Too many failed sign-in attempts\. Try again in \d+ seconds\.$/)).toBeInTheDocument()
    expect(sessionStore.get().userId).toBeNull()
  })

  it('login: an authenticator-app user still sees the authenticator copy and no resend button', async () => {
    const u = user()
    setUser('u-op', { twofa: true })
    renderApp('/login', { role: null })
    await u.type(await screen.findByLabelText('Email'), 'it@acme.example')
    await u.type(screen.getByLabelText('Password'), 'vedette-demo')
    await u.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByText(/Get the code from your authenticator app/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Send a new code/ })).not.toBeInTheDocument()
    expect(screen.queryByTestId('preview-code')).not.toBeInTheDocument()
  })

  it('turning two-step off (with the password) works for the email method too', async () => {
    const u = user()
    setUser('u-admin', { twofa: true, twofa_method: 'email' })
    renderApp('/account')
    expect(await screen.findByText(/Vedette emails to a•••@acme\.example/)).toBeInTheDocument()
    await u.click(screen.getByRole('button', { name: 'Turn off two-step sign-in' }))
    await u.type(screen.getByLabelText('Current password', { selector: '#twofa-off-pw' }), 'vedette-demo')
    await u.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Turn off' }))
    await waitFor(() => expect(usersStore.get().find((x) => x.id === 'u-admin')).toMatchObject({ twofa: false, twofa_method: null }))
  })
})

describe('core: admin reset of two-step sign-in (D-35)', () => {
  it('users list shows the method; reset asks first, turns it off and writes an audit entry', async () => {
    const u = user()
    setUser('u-op', { twofa: true, twofa_method: 'email' })
    setUser('u-view', { twofa: true })
    renderApp('/settings/users')
    const row = (await screen.findByRole('table', { name: 'Users' })).querySelectorAll('tbody tr')
    const text = [...row].map((r) => r.textContent ?? '').join('|')
    expect(text).toContain('Email code')
    expect(text).toContain('Authenticator app')
    expect(screen.queryByRole('button', { name: 'Reset two-step sign-in of Director' })).toBeInTheDocument()
    await u.click(screen.getByRole('button', { name: 'Reset two-step sign-in of IT Operator' }))
    const dlg = await screen.findByRole('dialog', { name: 'Reset two-step sign-in for IT Operator?' })
    expect(usersStore.get().find((x) => x.id === 'u-op')!.twofa).toBe(true)
    await u.click(within(dlg).getByRole('button', { name: 'Reset two-step sign-in' }))
    await waitFor(() => expect(usersStore.get().find((x) => x.id === 'u-op')).toMatchObject({ twofa: false, twofa_method: null }))
    const entry = auditStore.get().find((r) => r.action === 'user.2fa_reset')!
    expect(entry).toMatchObject({ user: 'admin@acme.example', target: 'it@acme.example', detail: 'was email code' })
    expect(await screen.findByText('Two-step sign-in was reset.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Reset two-step sign-in of IT Operator' })).not.toBeInTheDocument()
    // the reset user signs in with the password alone again
    expect((await loginAs('it@acme.example')).status).toBe(200)
  })

  it('an administrator cannot reset their own; non-admins are refused; users without two-step have no reset', async () => {
    setUser('u-admin', { twofa: true })
    renderApp('/settings/users')
    const own = await screen.findByRole('button', { name: 'Reset two-step sign-in of Admin' })
    expect(own).toBeDisabled()
    expect(screen.queryByRole('button', { name: 'Reset two-step sign-in of IT Operator' })).not.toBeInTheDocument()
    const self = await call('/core/users/u-admin/2fa/reset')
    expect(self.status).toBe(400)
    expect(await errCode(self)).toBe('self_reset')
    expect(await errCode(await call('/core/users/u-op/2fa/reset'))).toBe('not_on')
    sessionStore.set({ userId: 'u-op' })
    expect((await call('/core/users/u-view/2fa/reset')).status).toBe(403)
  })
})

describe('core: turning off Notifications warns about email-code users (D-35)', () => {
  it('the module dialog says how many users will be locked out; no warning when there are none', async () => {
    const u = user()
    renderApp('/settings/modules')
    await u.click(await screen.findByRole('switch', { name: 'Turn off module Notifications' }))
    const none = await screen.findByRole('dialog', { name: 'Turn off Notifications?' })
    expect(within(none).queryByText(/sign in with email codes/)).not.toBeInTheDocument()
    await u.click(within(none).getByRole('button', { name: 'Cancel' }))
    setUser('u-op', { twofa: true, twofa_method: 'email' })
    setUser('u-view', { twofa: true, twofa_method: 'email' })
    await u.click(screen.getByRole('switch', { name: 'Turn off module Notifications' }))
    const dlg = await screen.findByRole('dialog', { name: 'Turn off Notifications?' })
    expect(await within(dlg).findByText(/2 users sign in with email codes\. They will not be able to sign in until the email channel is back on or an administrator resets their two-step sign-in\./)).toBeInTheDocument()
  })
})

describe('core: operating system of the box (S-CORE-7, D-53)', () => {
  const BASE = `${location.origin}/api/v1/core/updates/os`
  const post = (path: string, body?: unknown) => fetch(`${BASE}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) })
  const patch = (body: unknown) => fetch(`${BASE}/settings`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  const T = { timeout: 8000 }
  const asAdmin = () => sessionStore.set({ userId: 'u-admin' })
  const osSection = () => within(document.getElementById('os') ?? document.body)

  it('shows the operating system part even when the software part is not built yet (501, issue #230)', async () => {
    server.use(http.get('*/api/v1/core/updates', () => HttpResponse.json({ error: { code: 'not_implemented', message: 'Not built yet.' } }, { status: 501 })))
    renderApp('/settings/updates')
    expect(await screen.findByRole('heading', { level: 1, name: 'Ubuntu 24.04.3 LTS: 5 security updates waiting' }, T)).toBeInTheDocument()
    expect(osSection().getByRole('button', { name: 'Check now' })).toBeInTheDocument()
    expect(await screen.findByText('Not built yet.')).toBeInTheDocument()
  })

  it('a box that has not checked yet shows its message and Check now, which loads the page (issue #231)', async () => {
    collection<{ on: boolean }>('core_os_never_checked', () => ({ on: false })).set({ on: true })
    asAdmin()
    const r = await fetch(BASE)
    expect([r.status, (await r.json()).os]).toEqual([200, null]) // not a 409 in the console on every open (D-407)
    const u = user()
    renderApp('/settings/updates')
    expect(await screen.findByText('The box has not looked for operating system updates yet. Click Check now.', undefined, T)).toBeInTheDocument()
    await u.click(osSection().getByRole('button', { name: 'Check now' }))
    expect(await screen.findByRole('heading', { level: 1, name: /Ubuntu 24.04.3 LTS/ }, T)).toBeInTheDocument()
    expect(osSection().getByRole('table', { name: 'Pending operating system updates' })).toBeInTheDocument()
  })

  it('says "1 security update" in the singular (issue #240)', async () => {
    asAdmin()
    const os = await (await fetch(BASE)).json()
    server.use(http.get('*/api/v1/core/updates/os', () => HttpResponse.json({ ...os, pending: os.pending.slice(0, 1).map((p: object) => ({ ...p, security: true })) })))
    renderApp('/settings/updates')
    expect(await screen.findByRole('heading', { level: 1, name: /: 1 security update waiting$/ }, T)).toBeInTheDocument()
  })

  it('a container-only install: the 409 is titled for what it is and the page still numbers 1, 2, 3 (issues #239, #241)', async () => {
    server.use(http.get('*/api/v1/core/updates/os', () => HttpResponse.json({ error: { code: 'not_appliance', message: 'This install has no operating system helper (container-only install).' } }, { status: 409 })))
    renderApp('/settings/updates')
    expect(await screen.findByText('Not available on this install', undefined, T)).toBeInTheDocument()
    expect(screen.queryByText('Invalid request')).not.toBeInTheDocument()
    expect(screen.getByText('This install has no operating system helper (container-only install).')).toBeInTheDocument()
    expect(osSection().getByRole('heading', { level: 2, name: 'Operating system of this box' })).toBeInTheDocument()
    const nums = Array.from(document.querySelectorAll('span[aria-hidden="true"]')).map((n) => n.textContent).filter((x) => /^[123]$/.test(x ?? ''))
    expect(nums).toEqual(['1', '2', '3'])
  })

  it('a failed install says Failed with the reason and no success toast (issue #238)', async () => {
    collection<{ on: boolean }>('core_os_install_fails', () => ({ on: false })).set({ on: true })
    const u = user()
    renderApp('/settings/updates')
    await u.click(await screen.findByRole('button', { name: /^Install security updates/ }, T))
    const log = await screen.findByRole('log', { name: 'apt output' })
    expect(await within(log.parentElement!).findByText('Failed', undefined, { timeout: 8000 })).toBeInTheDocument()
    expect(within(log.parentElement!).getByRole('alert')).toHaveTextContent(/package manager failed/)
    expect(log).toHaveTextContent('run failed: apt_failed')
    expect(within(log.parentElement!).queryByText('Finished')).not.toBeInTheDocument()
    expect(screen.queryByText(/^Finished: /)).not.toBeInTheDocument()
    toast.dismiss()
  })

  it('shows the release, kernel, support end, auto updates, pending packages with security and CVEs, and guidance for a release upgrade', async () => {
    renderApp('/settings/updates')
    expect(await screen.findByRole('heading', { level: 1, name: 'Ubuntu 24.04.3 LTS: 5 security updates waiting' }, T)).toBeInTheDocument()
    const os = osSection()
    expect(await os.findByText('6.8.0-71-generic')).toBeInTheDocument()
    expect(os.getByText('Until May 2029')).toBeInTheDocument()
    expect(os.getByText('Supported')).toBeInTheDocument()
    expect(os.getByRole('switch', { name: 'Automatic security updates' })).toBeChecked()
    const table = os.getByRole('table', { name: 'Pending operating system updates' })
    for (const n of ['openssh-server', 'openssl', 'linux-image-6.8.0-87-generic', 'libc6', 'curl', 'tzdata']) expect(within(table).getByText(n)).toBeInTheDocument()
    expect(within(table).getByText('CVE-2025-26465')).toBeInTheDocument()
    expect(within(table).getAllByText('Yes')).toHaveLength(5)
    // release upgrade: guidance only, no button that does it
    expect(os.getByText('Release upgrade to Ubuntu 26.04 LTS is available')).toBeInTheDocument()
    expect(os.getByText(/sudo do-release-upgrade/)).toBeInTheDocument()
    expect(os.queryByRole('button', { name: /upgrade/i })).toBeNull()
    expect(os.getByText(/vedette-host, runs a fixed list of apt commands/)).toBeInTheDocument()
    // block 2
    const managed = screen.getByRole('table', { name: 'Packages managed by Vedette' })
    for (const n of ['nmap', 'OpenCanary', 'osquery mirror files', 'nuclei templates']) expect(within(managed).getByText(n)).toBeInTheDocument()
    expect(within(managed).getAllByText('Updated together with Vedette releases').length).toBeGreaterThan(0)
    await expectNoA11yViolations()
  })

  it('Debian 12: standard support has ended, LTS runs to June 2028', async () => {
    const debian = { os: { distro: 'debian', name: 'Debian GNU/Linux 12 (bookworm)', release: '12', kernel: '6.1.0-37-amd64', support_end: '2026-06-10', extended_end: '2028-06-30', booted_at: new Date().toISOString(), last_check: new Date().toISOString(), mirrors: ['deb.debian.org', 'security.debian.org'] }, pending: [], reboot_required: false, reboot_reasons: [], reboot_scheduled_at: null, auto_security: false, window: { mode: 'always', days: [7], from: '02:00', to: '05:00' }, release_upgrade: { to: 'Debian 13 (trixie)', steps: ['Take a snapshot.'] }, busy: false }
    server.use(http.get('*/api/v1/core/updates/os', () => HttpResponse.json(debian)))
    renderApp('/settings/updates')
    const os = osSection
    expect(await screen.findByRole('heading', { level: 1, name: 'Debian GNU/Linux 12 (bookworm): no security updates waiting' }, T)).toBeInTheDocument()
    expect(os().getByText('Standard support ended')).toBeInTheDocument()
    expect(os().getByText('Extended (LTS) support until June 2028')).toBeInTheDocument()
    expect(os().getByText('Release upgrade to Debian 13 (trixie) is available')).toBeInTheDocument()
    expect(os().getByRole('switch', { name: 'Automatic security updates' })).not.toBeChecked()
    expect(os().getByText('Nothing waiting. The operating system is up to date.')).toBeInTheDocument()
  })

  it('install security updates: live log, backup, health check, reboot required, then the security rows are gone; a second run is refused meanwhile', async () => {
    const u = user()
    renderApp('/settings/updates')
    await u.click(await screen.findByRole('button', { name: /^Install security updates/ }, T))
    expect(await screen.findByText('Install started. Watch the progress below.')).toBeInTheDocument()
    const log = await screen.findByRole('log', { name: 'apt output' })
    expect(await within(log.parentElement!).findByText('Running')).toBeInTheDocument()
    // a second run while the first is going: refused with a clear message, nothing started
    const second = await post('/install', { scope: 'all' })
    expect(second.status).toBe(409)
    expect((await second.json()).error.message).toMatch(/already in progress/)
    expect(await within(log.parentElement!).findByText('Finished', undefined, { timeout: 8000 })).toBeInTheDocument()
    expect(log).toHaveTextContent('pre-update backup of the Vedette database: vedette-pre-update-')
    expect(log).toHaveTextContent('Unpacking openssh-server')
    expect(log).toHaveTextContent('archive.ubuntu.com')
    const panel = log.parentElement!
    expect(within(panel).getByText('5 packages, 5 security')).toBeInTheDocument()
    expect(within(panel).getByText(/^vedette-pre-update-.*\.db\.gz \(4\.2 MB\)$/)).toBeInTheDocument()
    for (const n of ['vedette-api', 'database', 'sensor', 'web interface']) expect(within(panel).getByText(n)).toBeInTheDocument()
    await waitFor(() => expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('Ubuntu 24.04.3 LTS: no security updates waiting'), T)
    const os = osSection()
    expect(os.getAllByText('Reboot required').length).toBeGreaterThan(0)
    expect(os.getByText(/Needed by: linux-image-6.8.0-87-generic .*libc6/)).toBeInTheDocument()
    const table = os.getByRole('table', { name: 'Pending operating system updates' })
    expect(within(table).queryByText('openssl')).toBeNull()
    expect(within(table).getByText('tzdata')).toBeInTheDocument()
    expect(auditStore.get().some((a) => a.action === 'os.install' && a.target === 'security')).toBe(true)
    expect(auditStore.get().some((a) => a.action === 'os.install_done')).toBe(true)
    // nothing to install now
    const again = await post('/install', { scope: 'security' })
    expect(again.status).toBe(409)
    expect((await again.json()).error.code).toBe('nothing_to_install')
  })

  it('reboot now asks first, then clears the reboot-required state; the update history gets the run', async () => {
    const u = user()
    asAdmin()
    await post('/install', { scope: 'security' })
    renderApp('/settings/updates')
    await waitFor(() => expect(osSection().getByText('Reboot required')).toBeInTheDocument(), T)
    await u.click(osSection().getByRole('button', { name: 'Reboot now' }))
    const dlg = await screen.findByRole('dialog', { name: 'Reboot the box now?' })
    await u.click(within(dlg).getByRole('button', { name: 'Reboot now' }))
    await waitFor(() => expect(osSection().getByText('No reboot needed')).toBeInTheDocument(), T)
    expect(osSection().getByText('6.8.0-87-generic')).toBeInTheDocument()
    const hist = screen.getByRole('table', { name: 'Update history' })
    expect(within(hist).getByText('Operating system')).toBeInTheDocument()
  })

  it('viewer sees everything read-only: every action is disabled with the reason', async () => {
    renderApp('/settings/updates', { role: 'viewer' })
    const os = osSection
    await screen.findByRole('heading', { level: 1, name: /security updates waiting/ }, T)
    for (const n of [/^Install security updates/, 'Install all updates', 'Reboot now', 'Schedule reboot', 'Check now']) expect(os().getByRole('button', { name: n })).toBeDisabled()
    expect(os().getByRole('switch', { name: 'Automatic security updates' })).toBeDisabled()
    expect(os().getByRole('button', { name: 'Save window' })).toBeDisabled()
    expect(os().getByRole('button', { name: 'Install all updates' })).toHaveAttribute('title', expect.stringMatching(/admin/i))
    expect((await post('/install', { scope: 'security' })).status).toBe(403)
    await expectNoA11yViolations()
  })

  it('operator can check but not install, reboot or change settings', async () => {
    sessionStore.set({ userId: 'u-op' })
    expect((await post('/check')).status).toBe(200)
    for (const r of [post('/install', { scope: 'all' }), post('/reboot', { when: 'now' }), patch({ auto_security: false })]) expect((await r).status).toBe(403)
  })

  it('check now refreshes the time; refused when update checks are off under Privacy', async () => {
    const u = user()
    renderApp('/settings/updates')
    await u.click(await screen.findByRole('button', { name: 'Check now' }, T))
    expect(await screen.findByText('Checked the package mirrors.', undefined, T)).toBeInTheDocument()
    asAdmin()
    await fetch(`${location.origin}/api/v1/core/privacy`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ update_check: false }) })
    const r = await post('/check')
    expect(r.status).toBe(409)
    expect((await r.json()).error.code).toBe('check_off')
  })

  it('automatic security updates switch is saved and audited', async () => {
    const u = user()
    renderApp('/settings/updates')
    await screen.findByRole('button', { name: 'Check now' }, T)
    const sw = await osSection().findByRole('switch', { name: 'Automatic security updates' }, T)
    await u.click(sw)
    expect(await screen.findByText('Automatic security updates are off.')).toBeInTheDocument()
    await waitFor(() => expect(osSection().getByRole('switch', { name: 'Automatic security updates' })).not.toBeChecked())
    expect(auditStore.get().some((a) => a.action === 'os.settings')).toBe(true)
  })

  describe('form matrix: maintenance window', () => {
    it('every mode shows only its own fields and rejects bad input', async () => {
      const u = user()
      renderApp('/settings/updates')
      await screen.findByRole('button', { name: 'Save window' }, T)
      const os = osSection()
      const group = () => os.getByRole('group', { name: 'Window mode' })
      const dayFields = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday', 'From', 'until']
      await eachOption([
        { option: 'Only in a window', shown: dayFields, hidden: [/any time of day/] },
        { option: 'Any time', shown: [/any time of day/], hidden: dayFields },
        { option: 'Only in a window', shown: dayFields, hidden: [/any time of day/] }, // going back restores the fields
      ], async (o) => { await u.click(within(group()).getByRole('button', { name: o })) }, document.getElementById('os')!)
      // the saved days survive the round trip
      expect(os.getByLabelText('Sunday')).toBeChecked()
      expect(os.getByLabelText('Monday')).not.toBeChecked()
      // no days: error, Save locked; same start and end: error
      await u.click(os.getByLabelText('Sunday'))
      expect(os.getByRole('alert')).toHaveTextContent('Pick at least one day.')
      expect(os.getByRole('button', { name: 'Save window' })).toBeDisabled()
      await u.click(os.getByLabelText('Monday'))
      fireEvent.change(os.getByLabelText('until'), { target: { value: '02:00' } })
      expect(os.getByRole('alert')).toHaveTextContent('The start and the end are the same')
      fireEvent.change(os.getByLabelText('until'), { target: { value: '04:00' } })
      await u.click(os.getByRole('button', { name: 'Save window' }))
      expect(await screen.findByText('Maintenance window saved.')).toBeInTheDocument()
      expect(await os.findByText('Mon, 02:00 to 04:00')).toBeInTheDocument()
      // the server checks too
      asAdmin()
      expect((await patch({ window: { mode: 'window', days: [], from: '02:00', to: '04:00' } })).status).toBe(400)
      expect((await patch({ window: { mode: 'window', days: [1], from: '02:00', to: '02:00' } })).status).toBe(400)
      expect((await patch({ window: { mode: 'window', days: [8], from: '02:00', to: '04:00' } })).status).toBe(400)
      expect((await patch({ window: { mode: 'weekly', days: [1], from: '02:00', to: '04:00' } })).status).toBe(400)
      expect((await patch({ window: { mode: 'window', days: [1], from: '25:00', to: '04:00' } })).status).toBe(400)
    })
  })

  it('saving a window warns first and says so when it cancelled the scheduled reboot (QA b3)', async () => {
    const u = user()
    renderApp('/settings/updates')
    await screen.findByRole('button', { name: 'Check now' }, T)
    const os = osSection()
    await u.click(await os.findByRole('button', { name: 'Schedule reboot' }, T))
    const d = within(await screen.findByRole('dialog', { name: 'Schedule a reboot' }))
    await u.click(d.getByRole('radio', { name: 'At the start of the next maintenance window' }))
    await u.click(d.getByRole('button', { name: /^Schedule/ }))
    await os.findByText(/Reboot scheduled for/)
    await u.click(os.getByLabelText('Sunday'))
    await u.click(os.getByLabelText('Monday'))
    expect(os.getByText(/saving cancels the reboot/)).toBeInTheDocument()
    await u.click(os.getByRole('button', { name: 'Save window' }))
    expect(await screen.findByText(/it was cancelled\. Schedule it again/)).toBeInTheDocument()
    toast.dismiss()
  })

  describe('form matrix: schedule a reboot', () => {
    const open = async (u: ReturnType<typeof user>) => {
      await screen.findByRole('button', { name: 'Check now' }, T)
      await u.click(await osSection().findByRole('button', { name: 'Schedule reboot' }, T))
      return screen.findByRole('dialog', { name: 'Schedule a reboot' })
    }

    it('with a maintenance window: both choices usable, the time field only for "a time I choose"', async () => {
      const u = user()
      renderApp('/settings/updates')
      const dlg = await open(u)
      const d = within(dlg)
      expect(d.getByRole('radio', { name: 'At the start of the next maintenance window' })).toBeEnabled()
      await eachOption([
        { option: 'At a time I choose', shown: ['Time', /inside the maintenance window/], hidden: [/no maintenance window yet/] },
        { option: 'At the start of the next maintenance window', hidden: ['Time'] },
        { option: 'At a time I choose', shown: ['Time'] },
      ], async (o) => { await u.click(d.getByRole('radio', { name: o })) }, dlg)
      expect(d.getByLabelText('Time')).toHaveValue('') // going back does not keep an earlier value
      // outside the window (window is Sunday 02:00 to 05:00, so 12:00 is outside)
      await u.type(d.getByLabelText('Time'), '12:00')
      await u.click(d.getByRole('button', { name: 'Schedule reboot' }))
      expect(await screen.findByText(/12:00 is outside the maintenance window/)).toBeInTheDocument()
      fireEvent.change(d.getByLabelText('Time'), { target: { value: '03:30' } })
      await u.click(d.getByRole('button', { name: 'Schedule reboot' }))
      expect(await screen.findByText('Reboot scheduled.')).toBeInTheDocument()
      const note = await osSection().findByText(/^Reboot scheduled for /)
      expect(note).toBeInTheDocument()
      const when = await (await fetch(BASE)).json()
      expect(new Date(when.reboot_scheduled_at).getDay()).toBe(0) // a Sunday
      expect(new Date(when.reboot_scheduled_at).getHours()).toBe(3)
      // cancel
      await u.click(osSection().getByRole('button', { name: 'Cancel reboot' }))
      await waitFor(() => expect(osSection().queryByText(/^Reboot scheduled for /)).toBeNull())
    })

    it('without a window ("any time"): the window choice is locked with the reason, any time is accepted, and the server refuses "window"', async () => {
      const u = user()
      asAdmin()
      expect((await patch({ window: { mode: 'always', days: [7], from: '02:00', to: '05:00' } })).status).toBe(200)
      renderApp('/settings/updates')
      const dlg = await open(u)
      const d = within(dlg)
      await eachOption([
        { option: 'At a time I choose', shown: ['Time', /next time this clock time comes/], hidden: [/inside the maintenance window/], locked: ['At the start of the next maintenance window'] },
      ], async (o) => { await u.click(d.getByRole('radio', { name: o })) }, dlg)
      expect(d.getByText(/There is no maintenance window yet/)).toBeInTheDocument()
      expect((await post('/reboot', { when: 'window' })).status).toBe(400)
      fireEvent.change(d.getByLabelText('Time'), { target: { value: '12:00' } })
      await u.click(d.getByRole('button', { name: 'Schedule reboot' }))
      expect((await screen.findAllByText('Reboot scheduled.')).length).toBeGreaterThan(0)
    })

    it('server side: bad time, wrong choice, window shrinking drops a schedule that no longer fits', async () => {
      asAdmin()
      expect((await post('/reboot', { when: 'custom', at: '7pm' })).status).toBe(400)
      expect((await post('/reboot', { when: 'soon' })).status).toBe(400)
      expect((await post('/reboot', { when: 'window' })).status).toBe(200)
      expect((await (await fetch(BASE)).json()).reboot_scheduled_at).not.toBeNull()
      await patch({ window: { mode: 'window', days: [3], from: '10:00', to: '11:00' } })
      expect((await (await fetch(BASE)).json()).reboot_scheduled_at).toBeNull()
      expect((await fetch(`${BASE}/reboot`, { method: 'DELETE' })).status).toBe(409)
    })
  })

  it('privacy flow 6 names the distribution mirrors and the local mirror option', async () => {
    renderApp('/settings/privacy')
    const row = (await screen.findByText(/^6\. Update checks/)).closest('tr')!
    for (const h of ['archive.ubuntu.com', 'security.ubuntu.com', 'deb.debian.org', 'security.debian.org', 'local mirror']) expect(row).toHaveTextContent(h)
  })

  it('privacy flow 6 says the scan image build contacts deb.debian.org from inside the build container, ignoring the local mirror (D-147)', async () => {
    renderApp('/settings/privacy')
    const row = (await screen.findByText(/^6\. Update checks/)).closest('tr')!
    expect(row).toHaveTextContent('builds the `scan` image on the box')
    expect(row).toHaveTextContent(/at install on every box \(whether or not active scanning is turned on\) and again whenever the `scan` image is pulled or updated/)
    expect(row).toHaveTextContent(/There is no setting that skips the `scan` image build/)
    expect(row).toHaveTextContent(/installs without active scanning/)
    expect(row).toHaveTextContent(/nmap from the Debian package repository/)
    expect(row).toHaveTextContent(/it contacts Debian's `deb\.debian\.org` from inside the build container, also on an Ubuntu box/)
    expect(row).toHaveTextContent(/does not apply to it/)
  })
})

describe('core: two-step setup form matrix (docs/QA.md §2)', () => {
  it('app and email each show only their own setup steps, and Cancel returns to the choice from either', async () => {
    const u = user()
    renderApp('/account')
    const APP = 'Set up authenticator app', EMAIL = 'Set up email code'
    const QR = 'QR code for your authenticator app', RESEND = /^Send a new code/
    await u.type(await screen.findByLabelText('Your current password'), 'vedette-demo')
    await eachOption([
      { option: 'choice', shown: [APP, EMAIL], hidden: [QR, RESEND, '6-digit code'] },
      { option: 'app', shown: [QR, '6-digit code', 'Confirm and turn on'], hidden: [RESEND, APP, EMAIL, /We sent a 6-digit code/] },
      { option: 'choice', shown: [APP, EMAIL], hidden: [QR, '6-digit code'] },
      { option: 'email', shown: [/We sent a 6-digit code/, RESEND, '6-digit code'], hidden: [QR, 'Manual key', APP, EMAIL] },
      { option: 'choice', shown: [APP, EMAIL], hidden: [RESEND, /We sent a 6-digit code/] },
    ], async (o) => {
      if (o === 'choice') {
        const cancel = screen.queryByRole('button', { name: 'Cancel' })
        if (cancel) await u.click(cancel)
        await screen.findByRole('button', { name: APP })
      } else await u.click(await screen.findByRole('button', { name: o === 'app' ? APP : EMAIL }))
      if (o === 'email') await screen.findByText(/We sent a 6-digit code/)
      if (o === 'app') await screen.findByRole('img', { name: QR })
    })
  })
})
