// D-180 (S-CORE-3): a password an administrator sets must be changed at first sign-in. Also the day format of the log download (D-132).
import { describe, expect, it } from 'vitest'
import { fireEvent, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp } from '@/test/render'
import { server } from '@/test/server'
import { api, ApiError } from '@/lib/api'
import { auditStore, sessionStore, tempExpiry, usersStore } from '@/mocks/stores'
import { logsExportQuery } from './logCategories'

const TEMP = 'ab12cd-34ef56-789abc-0d'
const addTempUser = (expires = tempExpiry()) => usersStore.update((l) => [...l, { id: 'u-new', name: 'Hana', email: 'hana@acme.example', role: 'operator', password: TEMP, temp_password_expires_at: expires, twofa: false, created_at: '2026-11-01T00:00:00Z', last_login: null }])
const post = (path: string, body: object) => fetch(`${location.origin}/api/v1${path}`, { method: 'POST', body: JSON.stringify(body) })

describe('first sign-in with an administrator-set password (D-180)', () => {
  it('create and reset mark the password temporary, for 72 hours', async () => {
    sessionStore.set({ userId: 'u-admin' })
    const made = (await (await post('/core/users', { name: 'Kim', email: 'kim@acme.example', role: 'viewer' })).json()) as { user: { id: string } }
    const row = () => usersStore.get().find((x) => x.id === made.user.id)!
    const hours = (iso: string) => Math.round((Date.parse(iso) - Date.now()) / 3_600_000)
    expect(hours(row().temp_password_expires_at!)).toBe(72)
    usersStore.update((l) => l.map((x) => (x.id === 'u-op' ? { ...x, temp_password_expires_at: null } : x)))
    expect((await post('/core/users/u-op/reset-password', {})).status).toBe(200)
    expect(hours(usersStore.get().find((x) => x.id === 'u-op')!.temp_password_expires_at!)).toBe(72)
    expect(auditStore.get().some((r) => r.action === 'user.password_reset')).toBe(true)
  })

  it('a limited session reads /me and may change the password, everything else is 403 password_change_required', async () => {
    addTempUser()
    sessionStore.set({ userId: 'u-new' })
    const me = await api.get<{ password_change_required: boolean }>('/me')
    expect(me.password_change_required).toBe(true)
    for (const path of ['/core/account', '/modules', '/core/general']) {
      const e = await api.get(path).catch((x: unknown) => x)
      expect(e, path).toBeInstanceOf(ApiError)
      expect(e).toMatchObject({ status: 403, code: 'password_change_required' })
    }
    expect((await post('/core/account/password', { current: TEMP, next: TEMP })).status).toBe(400) // same_password
    expect((await post('/core/account/password', { current: TEMP, next: 'a-brand-new-long-password' })).status).toBe(200)
    expect((await api.get<{ password_change_required: boolean }>('/me')).password_change_required).toBe(false)
    expect(await api.get('/modules')).toBeTruthy()
    expect(auditStore.get().find((r) => r.action === 'account.password')?.detail).toBe('temporary password replaced')
  })

  it('an expired temporary password cannot sign in', async () => {
    addTempUser(new Date(Date.now() - 1000).toISOString())
    const r = await post('/auth/login', { email: 'hana@acme.example', password: TEMP })
    expect(r.status).toBe(400)
    expect(((await r.json()) as { error: { code: string; message: string } }).error).toMatchObject({ code: 'temp_password_expired', message: 'This temporary password has expired. Ask an administrator for a new one.' })
    expect(sessionStore.get().userId).toBeNull()
  })

  it('sign-in lands on Choose a new password, then on the page the user was going to', async () => {
    const u = userEvent.setup()
    addTempUser()
    renderApp('/login?next=%2Faccount', { role: null })
    await u.type(await screen.findByLabelText('Email'), 'hana@acme.example')
    await u.type(screen.getByLabelText('Password'), TEMP)
    await u.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByRole('heading', { level: 1, name: 'Choose a new password' })).toBeInTheDocument()
    // the same checks as My account → Change password, plus: not the temporary password
    await u.type(screen.getByLabelText('Temporary password'), TEMP)
    await u.type(screen.getByLabelText('New password'), 'short')
    await u.type(screen.getByLabelText('Repeat new password'), 'short')
    await u.click(screen.getByRole('button', { name: 'Save and continue' }))
    expect(await screen.findByText('The new password needs at least 12 characters.')).toBeInTheDocument()
    await u.clear(screen.getByLabelText('New password'))
    await u.type(screen.getByLabelText('New password'), TEMP)
    await u.click(screen.getByRole('button', { name: 'Save and continue' }))
    expect(await screen.findByText('The new password must differ from the temporary one.')).toBeInTheDocument()
    await u.clear(screen.getByLabelText('New password'))
    await u.type(screen.getByLabelText('New password'), 'a-brand-new-long-password')
    await u.type(screen.getByLabelText('Repeat new password'), 'another-long-password-x')
    await u.click(screen.getByRole('button', { name: 'Save and continue' }))
    expect(await screen.findByText('The two entries do not match.')).toBeInTheDocument()
    await u.clear(screen.getByLabelText('Repeat new password'))
    await u.type(screen.getByLabelText('Repeat new password'), 'a-brand-new-long-password')
    await u.click(screen.getByRole('button', { name: 'Save and continue' }))
    await waitFor(() => expect(usersStore.get().find((x) => x.id === 'u-new')!.temp_password_expires_at).toBeNull())
    expect(await screen.findByRole('heading', { name: 'Where you are signed in' })).toBeInTheDocument() // /account
    expect(usersStore.get().find((x) => x.id === 'u-new')!.password).toBe('a-brand-new-long-password')
  })

  it('a limited user who opens any page is sent to Choose a new password', async () => {
    addTempUser()
    renderApp('/devices', { role: null })
    sessionStore.set({ userId: 'u-new' })
    expect(await screen.findByRole('heading', { level: 1, name: 'Choose a new password' })).toBeInTheDocument()
  })
})

describe('Download logs sends the days as YYYY-MM-DD (D-132)', () => {
  it('the request has the picked days as they are, not a time', () => {
    const q = new URLSearchParams(logsExportQuery(['audit', 'alerts'], 'csv', '2026-11-05', '2026-11-09'))
    expect(q.get('from')).toBe('2026-11-05')
    expect(q.get('to')).toBe('2026-11-09')
    expect(q.get('categories')).toBe('audit,alerts')
    expect(q.get('format')).toBe('csv')
    const open = new URLSearchParams(logsExportQuery(['audit'], 'json', '', ''))
    expect(open.has('from') || open.has('to')).toBe(false)
  })

  it('the Data page requests the picked days and the box accepts them', async () => {
    let seen: URL | null = null
    server.use(http.get('*/api/v1/core/logs/export', ({ request }) => { seen = new URL(request.url); return new HttpResponse('{}', { headers: { 'Content-Type': 'application/json' } }) }))
    renderApp('/settings/data')
    fireEvent.change(await screen.findByLabelText('From'), { target: { value: '2026-11-05' } })
    fireEvent.change(screen.getByLabelText('To'), { target: { value: '2026-11-09' } })
    fireEvent.click(screen.getByRole('button', { name: /Download logs/ }))
    await waitFor(() => expect(seen).not.toBeNull())
    expect(seen!.searchParams.get('from')).toBe('2026-11-05')
    expect(seen!.searchParams.get('to')).toBe('2026-11-09')
  })
})
