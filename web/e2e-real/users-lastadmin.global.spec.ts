// Last-admin protection (S-CORE-3, core INV on users). The rule is about the whole box ("at least one active administrator must remain"),
// and the other specs leave throwaway administrators behind (auth.spec.ts), so this one runs in the global project, alone: it disables
// every other active administrator, checks that the one that is left cannot demote or disable itself, and enables the others again.
import { expect, request, test } from '@playwright/test'
import { ACCOUNTS, api, authFile, box } from './box'
import { h1, noErrors } from './ui'
import { collectErrors } from '../e2e/helpers'

test.use({ storageState: authFile('admin'), actionTimeout: 10_000 })

interface Listed { id: string; email: string; name: string; role: string; disabled?: boolean }

test('the only active administrator can neither demote nor disable itself', async ({ page }) => {
  test.setTimeout(120_000)
  const errors = collectErrors(page)
  const admin = await request.newContext({ baseURL: box().base_url, storageState: authFile('admin') })
  const users = (await api<{ items: Listed[] }>(admin, 'GET', '/core/users')).body.items
  const me = users.find((u) => u.email === ACCOUNTS.admin.email)!
  const others = users.filter((u) => u.role === 'admin' && !u.disabled && u.id !== me.id)
  const stopped: string[] = []
  try {
    for (const u of others) {
      const r = await api(admin, 'PATCH', `/core/users/${u.id}`, { disabled: true })
      expect(r.status, `disable ${u.email}: ${JSON.stringify(r.body)}`).toBe(200) // not the last one while this one is active
      stopped.push(u.id)
    }
    const active = (await api<{ items: Listed[] }>(admin, 'GET', '/core/users')).body.items.filter((u) => u.role === 'admin' && !u.disabled)
    expect(active.map((u) => u.email), 'the box has exactly one active administrator now').toEqual([ACCOUNTS.admin.email])

    // the server refuses, with a reason a person can read
    const demote = await api<{ error: { code: string; message: string } }>(admin, 'PATCH', `/core/users/${me.id}`, { role: 'viewer' })
    expect(demote.status).toBe(400)
    expect(demote.body).toMatchObject({ error: { code: 'last_admin', message: expect.stringContaining('At least one active administrator must remain') } })
    const off = await api<{ error: { code: string } }>(admin, 'PATCH', `/core/users/${me.id}`, { disabled: true })
    expect(off.status).toBe(400)
    expect(['last_admin', 'self_disable']).toContain(off.body.error.code)
    expect((await api<{ role: string }>(admin, 'GET', '/me')).body.role, 'still an administrator').toBe('admin')

    // and so does the page: Disable is off for yourself, the role list snaps back with the reason
    await page.goto('/settings/users')
    await expect(h1(page)).toContainText('active users')
    await page.getByRole('textbox', { name: 'Find a user' }).fill(me.name)
    await expect(page.getByRole('button', { name: `Disable ${me.name}` })).toBeDisabled()
    await page.getByRole('combobox', { name: `Role of ${me.name}` }).selectOption('viewer')
    await expect(page.locator('[data-sonner-toast]').filter({ hasText: /At least one active administrator must remain/ }).first()).toBeVisible()
    await expect(page.getByRole('combobox', { name: `Role of ${me.name}` })).toHaveValue('admin')
    await page.reload()
    await expect(page.getByRole('combobox', { name: `Role of ${me.name}` })).toHaveValue('admin')
    noErrors(errors, /status of 40\d/)
  } finally {
    for (const id of stopped) await api(admin, 'PATCH', `/core/users/${id}`, { disabled: false })
    await admin.dispose()
  }
})
