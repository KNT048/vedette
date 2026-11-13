// The notify module on the real backend, on a box with no internet: what needs no change to box-wide state (S-NOT-1, S-NOT-2 page and role gate, S-ALERT-3 list, notify INV-1 read side, INV-11).
// Everything that saves, edits or deletes a channel, the quiet hours and the history of a real send is in notify.global.spec.ts (one channel per type: that state is box-wide).
// Steps from e2e/qa/notify.spec.ts. This file only reads, or sends a request that is refused before it can change anything (the tests say which).
import { expect, request, test } from '@playwright/test'
import { api, authFile, box } from './box'
import { as, chanRow, destText, getChannels, getHistory, historyMeta, NAME, quietSummary, SEV, statusText, TYPES, watch5xx, type Channels, type Incident } from './notify-shared'
import { expectAccessible, h1, noErrors, noVietnamese } from './ui'
import { collectErrors, shot } from '../e2e/helpers'

test.use({ actionTimeout: 10_000 })

const NOT_FOUND = { error: { code: 'not_found' } }
const FORBIDDEN = { error: { code: 'forbidden' } }
const PUT_EMAIL = { enabled: false, fields: { host: 'smtp.e2e.test', port: '587', security: 'starttls', username: 'alerts@e2e.test', from: 'alerts@e2e.test', to: 'it@e2e.test' }, secret: 'e2e-smtp-password-0123', min_severity: 'medium' }

test.describe('Alert channels with what the box really holds (S-NOT-1, S-NOT-2)', () => {
  test.use({ storageState: authFile('admin') })

  test('the page shows the six channels, the rules and the history exactly as the API has them: accessible, English only, no 5xx, no script error', async ({ page }) => {
    const errors = collectErrors(page)
    const server = watch5xx(page)
    const c = await as('admin')
    let d: Channels
    let h: Awaited<ReturnType<typeof getHistory>>
    try { d = await getChannels(c); h = await getHistory(c) } finally { await c.dispose() }
    expect(d.channels.map((x) => x.type)).toEqual(TYPES)

    await page.goto('/settings/channels')
    await expect(h1(page)).toHaveText('Alert channels')
    await expect(page.getByText('Choose where Vedette sends alerts. With no channel on, alerts only appear in the app.')).toBeVisible()
    await expect(page.getByText('Alert content (device names, CVE IDs) leaves the box only to the channels you turn on here and nowhere else. A channel that is off sends no data.')).toBeVisible()
    await expect(page.getByRole('table', { name: 'Alert channels' })).toBeVisible()
    for (const ch of d.channels) {
      const row = chanRow(page, ch)
      await expect(row, `row of ${ch.type}`).toHaveCount(1)
      await expect(row).toContainText(NAME[ch.type])
      await expect(row).toContainText(statusText(ch))
      if (ch.configured) {
        await expect(row).toContainText(destText(ch))
        await expect(row).toContainText(`${SEV[ch.min_severity]} and above`)
        await expect(row.getByRole('button', { name: `Send test ${NAME[ch.type]}`, exact: true })).toBeVisible()
        await expect(row.getByRole('button', { name: `Remove channel ${NAME[ch.type]}`, exact: true })).toBeVisible()
      } else {
        await expect(row.getByRole('button', { name: `Send test ${NAME[ch.type]}` })).toHaveCount(0) // nothing to test until it is saved
      }
    }
    // the rules show the saved values
    await expect(page.getByLabel('From', { exact: true })).toHaveValue(d.quiet.from)
    await expect(page.getByLabel('Until', { exact: true })).toHaveValue(d.quiet.to)
    await expect(page.getByRole('switch', { name: 'Turn on quiet hours' })).toBeChecked({ checked: d.quiet.enabled })
    await expect(page.getByLabel('Still send Critical right away', { exact: true })).toBeChecked({ checked: d.quiet.allow_critical })
    await expect(page.getByRole('switch', { name: 'Group messages for the same product' })).toBeChecked({ checked: d.grouping.enabled })
    await expect(page.getByLabel('Grouping window', { exact: true })).toHaveValue(String(d.grouping.window_min))
    const summary = quietSummary(d.quiet)
    if (summary) await expect(page.getByText(summary, { exact: true })).toBeVisible()
    else await expect(page.getByText(/^Quiet from /)).toHaveCount(0)
    // the history: the empty state or the table with one row per message, and the line about vulnerabilities that matched nothing
    await expect(page.getByText(historyMeta(h.suppressed), { exact: true })).toBeVisible()
    if (h.items.length === 0) {
      await expect(page.getByText('Nothing sent yet')).toBeVisible()
      await expect(page.getByRole('table', { name: 'Sent messages' })).toHaveCount(0)
    } else {
      await expect(page.getByRole('table', { name: 'Sent messages' }).getByRole('row')).toHaveCount(h.items.length + 1)
    }
    await expect(page.locator('main')).not.toContainText(/undefined|NaN|\[object|1970/)
    await expectAccessible(page, 'alert channels')
    await noVietnamese(page, 'alert channels')
    await shot(page, 'real', 'notify-channels')
    expect(server).toEqual([])
    noErrors(errors)
  })

  test('every dialog opens and closes with Escape, shows its own fields in English, and an unsaved edit changes nothing on the box', async ({ page }) => {
    const errors = collectErrors(page)
    const c = await as('admin')
    try {
      const before = await getChannels(c)
      await page.goto('/settings/channels')
      await expect(h1(page)).toHaveText('Alert channels')
      const fields: Record<string, string[]> = {
        telegram: ['Chat ID', 'Bot token'], slack: ['Channel label (optional)', 'Incoming Webhook URL'], zalo: ['OA ID', 'Recipient ID (user_id)', 'App ID', 'Secret key', 'Refresh token', 'Access token (optional)'],
        'zalo-personal': ['Recipient (user or group ID)'], email: ['SMTP server', 'Port', 'Encryption', 'Username', 'Send from', 'Send to', 'SMTP password'], webhook: ['Webhook URL', 'Signing key'],
      }
      for (const ch of before.channels) {
        await chanRow(page, ch).getByRole('button', { name: `${ch.configured ? 'Edit' : 'Set up'} ${NAME[ch.type]}`, exact: true }).click()
        const dlg = page.getByRole('dialog', { name: `Channel ${NAME[ch.type]}` })
        await expect(dlg).toBeVisible()
        for (const f of fields[ch.type]!) await expect(dlg.getByLabel(f, { exact: true }), `${ch.type}: ${f}`).toBeVisible()
        const approvals = dlg.getByRole('switch', { name: 'Approve actions from this channel' })
        if (ch.type === 'zalo' || ch.type === 'webhook') {
          await expect(approvals).toHaveCount(0)
          await expect(dlg.getByText('This channel cannot take approvals. Messages sent here carry a link that opens Vedette, where an operator or administrator approves.')).toBeVisible()
        } else {
          await expect(approvals).toHaveCount(1)
        }
        if (ch.type === 'zalo-personal') await expect(dlg.getByText("Unofficial: uses Zalo's personal web protocol, not an official API. Zalo may lock the account. Use a dedicated account, not your personal one.")).toBeVisible()
        await expectAccessible(page, `${ch.type} dialog`)
        await noVietnamese(page, `${ch.type} dialog`)
        await page.keyboard.press('Escape')
        await expect(dlg).toHaveCount(0)
      }
      expect(await getChannels(c), 'opening and closing dialogs changed the box').toEqual(before)
    } finally { await c.dispose() }
    noErrors(errors)
  })
})

test.describe('Incidents on a box where nothing has happened yet (S-ALERT-3)', () => {
  test.use({ storageState: authFile('viewer') })

  test('the list says what the API says; an unknown incident is a 404 the page explains, never a script error', async ({ page }) => {
    const errors = collectErrors(page)
    const server = watch5xx(page)
    const c = await as('viewer')
    let list: Incident[]
    let notFoundText = ''
    try {
      const r = await api<{ incidents: Incident[] }>(c, 'GET', '/notify/incidents')
      expect(r.status).toBe(200)
      list = r.body.incidents
      expect(Array.isArray(list)).toBe(true)
      const missing = await api<{ error: { message: string } }>(c, 'GET', '/notify/incidents/does-not-exist')
      expect(missing).toMatchObject({ status: 404, body: NOT_FOUND })
      notFoundText = missing.body.error.message
    } finally { await c.dispose() }
    const fresh = list.filter((i) => i.status === 'new').length
    const open = list.filter((i) => i.status !== 'resolved').length

    await page.goto('/incidents')
    await expect(h1(page)).toHaveText(fresh === 0 ? 'No new incidents' : `${fresh} new incident${fresh === 1 ? '' : 's'}`)
    if (open === 0) {
      await expect(page.getByText('No open incidents')).toBeVisible()
      await expect(page.getByRole('table', { name: 'Incidents' })).toHaveCount(0)
      await expect(page.getByRole('link', { name: 'Set up alert channels' })).toHaveAttribute('href', '/settings/channels')
    } else {
      await expect(page.getByRole('table', { name: 'Incidents' }).getByRole('row')).toHaveCount(open + 1)
    }
    await page.getByRole('button', { name: 'All', exact: true }).click() // the other filter: an empty box says "No incidents yet", a box with only resolved ones lists them
    if (list.length === 0) await expect(page.getByText('No incidents yet')).toBeVisible()
    else await expect(page.getByRole('table', { name: 'Incidents' }).getByRole('row')).toHaveCount(list.length + 1)
    await expect(page.locator('main')).not.toContainText(/undefined|NaN|\[object|1970/)
    await expectAccessible(page, 'incidents')
    await noVietnamese(page, 'incidents')

    await page.goto('/incidents/does-not-exist')
    await expect(page.getByRole('alert').first()).toContainText('Not found')
    await expect(page.getByRole('alert').first()).toContainText(notFoundText)
    await noVietnamese(page, 'incident not found')
    expect(server).toEqual([])
    noErrors(errors, /status of 404/)
  })

  test('an old alert link and a finding that was never notified are answered honestly', async () => {
    const c = await as('viewer')
    try {
      expect(await api(c, 'GET', '/notify/alerts/does-not-exist/target')).toMatchObject({ status: 404, body: NOT_FOUND })
      expect(await api(c, 'GET', '/notify/findings/does-not-exist/notices')).toEqual({ status: 200, body: { sends: [] } })
    } finally { await c.dispose() }
  })
})

test.describe('roles (notify: Endpoints owned)', () => {
  for (const role of ['viewer', 'operator'] as const) {
    test(`the API refuses what a ${role} may not do with 403 forbidden, changes nothing, and lets through what the role allows`, async () => {
      const c = await as(role)
      const admin = await as('admin')
      try {
        const before = await getChannels(admin)
        const historyBefore = await getHistory(admin)
        // admin-only: channels, rules, test send, history (a request that is refused before the handler cannot change anything, so a valid body is safe here)
        for (const [method, path, body] of [
          ['GET', '/notify/channels', undefined], ['GET', '/notify/history', undefined],
          ['PUT', '/notify/channels/email', PUT_EMAIL], ['DELETE', '/notify/channels/email', undefined], ['POST', '/notify/channels/email/test', undefined],
          ['PUT', '/notify/rules', { quiet: { enabled: true, from: '01:00', to: '02:00', allow_critical: false }, grouping: { enabled: false, window_min: 15 } }],
        ] as const) {
          expect(await api(c, method, path, body), `${role}: ${method} ${path}`).toMatchObject({ status: 403, body: FORBIDDEN })
        }
        if (role === 'viewer') { // operator-only: acknowledge an incident, send a message again
          expect(await api(c, 'PATCH', '/notify/incidents/does-not-exist', { status: 'acknowledged' }), 'viewer: PATCH incident').toMatchObject({ status: 403, body: FORBIDDEN })
          expect(await api(c, 'POST', '/notify/history/does-not-exist/resend'), 'viewer: resend').toMatchObject({ status: 403, body: FORBIDDEN })
        } else { // the operator passes the role gate and meets the 404 of an id that is not there
          expect(await api(c, 'PATCH', '/notify/incidents/does-not-exist', { status: 'acknowledged' }), 'operator: PATCH incident').toMatchObject({ status: 404, body: NOT_FOUND })
          expect(await api(c, 'POST', '/notify/history/does-not-exist/resend'), 'operator: resend').toMatchObject({ status: 404, body: NOT_FOUND })
        }
        expect((await api(c, 'GET', '/notify/incidents')).status).toBe(200)
        expect(await getChannels(admin), 'a refused call changed the channels').toEqual(before)
        expect(await getHistory(admin), 'a refused call changed the history').toEqual(historyBefore)
      } finally { await Promise.all([c.dispose(), admin.dispose()]) }
    })

    test(`a ${role} who opens Alert channels is told it needs a higher role, with no control to change a channel`, async ({ browser }) => {
      const context = await browser.newContext({ baseURL: box().base_url, storageState: authFile(role), locale: 'vi-VN' })
      try {
        const page = await context.newPage()
        const errors = collectErrors(page)
        const server = watch5xx(page)
        await page.goto('/settings/channels')
        await expect(page.getByText('Alert channels needs a higher role')).toBeVisible()
        await expect(page.getByText('Only the Admin role can open this section. Ask an administrator if you need access.')).toBeVisible()
        await expect(page.getByRole('button', { name: /^(Set up|Edit) / })).toHaveCount(0)
        await expect(page.getByRole('table', { name: 'Alert channels' })).toHaveCount(0)
        await noVietnamese(page, `${role} channels`)
        expect(server).toEqual([])
        noErrors(errors, /status of 403/)
      } finally { await context.close() }
    })
  }

  test('someone who is not signed in gets 401 unauthenticated on every route', async () => {
    const c = await request.newContext({ baseURL: box().base_url })
    try {
      for (const [method, path] of [['GET', '/notify/channels'], ['GET', '/notify/history'], ['GET', '/notify/incidents']] as const) {
        const r = await c.fetch(`/api/v1${path}`, { method, failOnStatusCode: false })
        expect(r.status(), `${method} ${path}`).toBe(401)
        expect(await r.json(), `${method} ${path}`).toMatchObject({ error: { code: 'unauthenticated' } })
      }
    } finally { await c.dispose() }
  })

  test('a channel type that does not exist is refused by the schema before any handler (PRE-3)', async () => {
    const admin = await as('admin')
    try {
      expect(await api(admin, 'PUT', '/notify/channels/fax', PUT_EMAIL)).toMatchObject({ status: 400, body: { error: { code: 'invalid' } } })
      expect(await api(admin, 'DELETE', '/notify/channels/fax')).toMatchObject({ status: 400, body: { error: { code: 'invalid' } } })
      expect(await api(admin, 'POST', '/notify/channels/fax/test')).toMatchObject({ status: 400, body: { error: { code: 'invalid' } } })
    } finally { await admin.dispose() }
  })
})
