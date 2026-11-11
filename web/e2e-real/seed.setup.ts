// Seeds the accounts of the run (D-172): an operator and a viewer next to the administrator the wizard made, each created the way a person
// does (temporary password, then a password change), and one storageState file per role for the specs of the parallel project.
import { mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { expect, request, test } from '@playwright/test'
import { ACCOUNTS, api, authFile, box, createUser, login, password, type Role } from './box'

test('accounts and one storageState per role', async () => {
  const ctx = async () => request.newContext({ baseURL: box().base_url })
  const signedIn = async (role: Role) => {
    const c = await ctx()
    const r = await login(c, ACCOUNTS[role].email, password())
    expect(r.status, `sign-in of the ${role}: ${JSON.stringify(r.body)}`).toBe(200)
    mkdirSync(dirname(authFile(role)), { recursive: true, mode: 0o700 })
    await c.storageState({ path: authFile(role) })
    return c
  }

  const admin = await signedIn('admin')
  // The wizard's mid-size bundle leaves `response` off (D-41, it acts on the customer's devices). The routes check visits its page, so the
  // seed turns the module on; the switch that lets it act on devices is a separate one and stays off.
  // Public-IP auto-detect would call checkip/icanhazip/ifconfig.me during the run: turn it off right after the wizard (no internet dependence).
  const noAuto = await api(admin, 'PUT', '/exposure/box-ip/settings', { auto: false, interval_min: 60 })
  expect(noAuto.status, `exposure auto-detect off: ${JSON.stringify(noAuto.body)}`).toBe(200)
  const on = await api(admin, 'PATCH', '/modules/response', { enabled: true, with_dependencies: true })
  expect(on.status, `enable response: ${JSON.stringify(on.body)}`).toBe(200)
  for (const role of ['operator', 'viewer'] as const) {
    const tmp = await ctx()
    await createUser(admin, tmp, { ...ACCOUNTS[role], role })
    await tmp.dispose()
    const c = await signedIn(role)
    const me = await api<{ email: string; role: string }>(c, 'GET', '/me')
    expect(me.status).toBe(200)
    expect(me.body).toMatchObject({ email: ACCOUNTS[role].email, role })
    await c.dispose()
  }
  const me = await api<{ email: string; role: string }>(admin, 'GET', '/me')
  expect(me.body).toMatchObject({ email: ACCOUNTS.admin.email, role: 'admin' })
  await admin.dispose()
})
