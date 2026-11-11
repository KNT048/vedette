// The notify module on the real backend, on a box with no internet: everything that changes a channel or the rules (S-NOT-1, S-NOT-2, notify INV-1, INV-7, INV-8, INV-11, D-86, S-ALERT-1 delivery record).
// Global project: a channel is one row per type on the box and the rules are one set, so these tests run one at a time and give the box back as they found it
// (afterEach deletes every channel they saved and puts the rules back, and checks both). Steps from e2e/qa/notify.spec.ts.
// No test reaches the internet: Telegram, Slack and Zalo channels are only ever saved TURNED OFF and never sent a test (their addresses are fixed on the internet); a webhook
// cannot point at loopback (D-86), so the webhook is only saved, turned off. The one real send is an email channel to a closed port on loopback (INV-8 allows an internal SMTP host).
// What this file cannot prove (a delivered message, a Telegram button press, the delivery of an approval request to a channel) needs a seam: see .ai/deferred/feat-e2e-real-notify.md.
// Approval DELIVERY is not covered: only the validation of approver lists is (INV-7).
import { expect, test, type Page } from '@playwright/test'
import { ACCOUNTS, api, authFile } from './box'
import { as, auditHasNo, auditIds, chanRow, closedPort, ERR_UNREACHABLE, getChannels, getHistory, historyMeta, newAudit, ownAddress, quietSummary, refused, TYPES, testedText, watch5xx, type Ch, type ChannelType, type Hist, type Rules } from './notify-shared'
import { seed, startFeedServer, stopFeedServer, sweep as sweepDevices } from './findings-seed'
import { expectAccessible, noErrors, noVietnamese } from './ui'
import { collectErrors, shot } from '../e2e/helpers'

test.use({ storageState: authFile('admin'), actionTimeout: 10_000 })

// Secrets of the tests: made up, long enough for their channel's checks, each with its own last 4 characters so a test can tell whose it is.
const TG_API = '123456789:EXAMPLEnotARealTokenForE2eTests0000TG01'
const TG_GUI = '987654321:EXAMPLEnotARealTokenForGuiRun00000gui1'
const SLACK_HOOK = 'https://hooks.slack.com/services/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01'
// Built at run time: literals in Slack's token shapes are blocked by GitHub push protection.
const SLACK_APP = ['xapp', '1', 'A0E2E0001', '0000000001', 'notarealapptoken0001'].join('-')
const SLACK_BOT = ['xoxb', '0000000001', '0000000002', 'notarealbottoken0002'].join('-')
const ZALO_TOKEN = 'zalo-e2e-not-a-real-token-ZL01'
const WEBHOOK_KEY = 'e2e-webhook-signing-key-WH01'
const SMTP_PASSWORD = 'e2e-smtp-password-not-real-SM01'
const last4 = (s: string) => s.slice(-4)
const generatedKeys: string[] = [] // keys the form made at random: also never to come back
/** No response of the box holds all but the last 4 characters of any secret of this file (INV-1). */
function noSecretIn(text: string, what: string) {
  for (const sec of [TG_API, TG_GUI, SLACK_HOOK, SLACK_APP, SLACK_BOT, ZALO_TOKEN, WEBHOOK_KEY, SMTP_PASSWORD, ...generatedKeys]) expect(text, `${what} holds a secret`).not.toContain(sec.slice(0, -4))
}
/** `api` that also checks the body of the answer for a secret. */
async function call<T = any>(...a: Parameters<typeof api>) {
  const r = await api<T>(...a)
  noSecretIn(JSON.stringify(r.body), `${a[1]} ${a[2]}`)
  return r
}

/** What the box says by default (CONTRACT: defaultQuiet, defaultGrouping), checked once before the tests and put back after every one. */
const DEFAULT_RULES: Rules = { quiet: { enabled: false, from: '22:00', to: '06:30', allow_critical: true }, grouping: { enabled: true, window_min: 60 } }

test.beforeAll(async () => {
  const c = await as('admin')
  try {
    const d = await getChannels(c)
    expect(d.channels.filter((x) => x.configured).map((x) => x.type), 'this file needs a box with no channel saved').toEqual([])
    expect({ quiet: d.quiet, grouping: d.grouping }, 'this file needs the default quiet hours and grouping').toEqual(DEFAULT_RULES)
    expect(d.email_code_users, 'this file needs a box where nobody signs in with email codes').toBe(0)
  } finally { await c.dispose() }
})
/** Gives the box back: every channel a test saved is deleted (status checked), the rules are the defaults again, and both are read back. */
test.afterEach(async () => {
  const c = await as('admin')
  try {
    for (const ch of (await getChannels(c)).channels.filter((x) => x.configured)) {
      expect((await call(c, 'DELETE', `/notify/channels/${ch.type}`)).status, `cleanup of the ${ch.type} channel`).toBe(204)
    }
    expect((await call(c, 'PUT', '/notify/rules', DEFAULT_RULES)).status, 'cleanup of the rules').toBe(200)
    const after = await getChannels(c)
    expect(after.channels.filter((x) => x.configured), 'channels left behind').toEqual([])
    expect({ quiet: after.quiet, grouping: after.grouping }, 'rules left behind').toEqual(DEFAULT_RULES)
  } finally { await c.dispose() }
})

const toast = (page: Page, text: string) => expect(page.locator('[data-sonner-toast]').filter({ hasText: text }).first()).toBeVisible()
const dialog = (page: Page) => page.getByRole('dialog')
const saveBtn = (d: ReturnType<typeof dialog>) => d.getByRole('button', { name: 'Save', exact: true })
const sw = (d: ReturnType<typeof dialog>) => d.getByRole('switch', { name: 'Turn this channel on' })
const putOf = (page: Page, type: ChannelType) => page.waitForResponse((r) => r.url().endsWith(`/api/v1/notify/channels/${type}`) && r.request().method() === 'PUT')
const alertOf = (d: ReturnType<typeof dialog>, text: string) => expect(d.getByRole('alert')).toHaveText(text)
const channel = async (type: ChannelType): Promise<Ch> => {
  const c = await as('admin')
  try { return (await getChannels(c)).channels.find((x) => x.type === type)! } finally { await c.dispose() }
}
/** A Save in the open dialog that the box accepts: waits for the PUT and returns its body. */
async function saveOk(page: Page, d: ReturnType<typeof dialog>, type: ChannelType) {
  const [res] = await Promise.all([putOf(page, type), saveBtn(d).click()])
  const text = await res.text()
  expect(res.status(), `PUT ${type}: ${text}`).toBe(200)
  noSecretIn(text, `PUT ${type}`)
  return JSON.parse(text) as Ch
}
/** A Save in the open dialog that the box refuses: the dialog stays open and says why at the top. */
async function saveRefused(page: Page, d: ReturnType<typeof dialog>, type: ChannelType, code: string, message: string) {
  const [res] = await Promise.all([putOf(page, type), saveBtn(d).click()])
  expect(res.status(), `PUT ${type}`).toBe(400)
  const text = await res.text()
  noSecretIn(text, `refused PUT ${type}`)
  expect(JSON.parse(text)).toMatchObject({ error: { code, message } })
  await alertOf(d, message)
}
/** Nothing of the secret is shown by the page, the API or the audit log (INV-1, SYS-4): only its last 4 characters. */
async function noEcho(page: Page, secret: string) {
  const c = await as('admin')
  try {
    const all = JSON.stringify(await getChannels(c))
    expect(all, 'the secret is in GET /notify/channels').not.toContain(secret)
    expect(all, 'most of the secret is in GET /notify/channels').not.toContain(secret.slice(0, -4))
    await auditHasNo(c, secret)
  } finally { await c.dispose() }
  expect(await page.locator('body').innerText(), 'the secret is on the page').not.toContain(secret.slice(0, -4))
}
const users = async () => {
  const c = await as('admin')
  try {
    const r = await call<{ items: { id: string; name: string; email: string; role: string; disabled?: boolean }[] }>(c, 'GET', '/core/users')
    expect(r.status).toBe(200)
    return r.body.items
  } finally { await c.dispose() }
}

test.describe('channels through the form: add, refusals, edit, remove (S-NOT-1, S-NOT-2, INV-1)', () => {
  test('Telegram: each refusal at the form says what to fix, the key is saved but never shown again, an edit keeps it, Cancel keeps the channel, Remove deletes it and its key', async ({ page }) => {
    const errors = collectErrors(page)
    const server = watch5xx(page)
    const c = await as('admin')
    try {
      const before = await auditIds(c)
      await page.goto('/settings/channels')
      await chanRow(page, { type: 'telegram', configured: false }).getByRole('button', { name: 'Set up Telegram', exact: true }).click()
      const d = page.getByRole('dialog', { name: 'Channel Telegram' })
      await expect(d.getByText('Message @BotFather, send /newbot and paste the token you get (like 123456789:AAH…). The token is the bot\'s password: share it with nobody. To send to a group, add the bot to the group first.')).toBeVisible()
      await expectAccessible(page, 'telegram dialog')
      await sw(d).click() // never turned on: no test of this file may send to the internet
      await expect(sw(d)).not.toBeChecked()
      await d.getByLabel('Chat ID', { exact: true }).fill('abc')
      await saveRefused(page, d, 'telegram', 'secret_required', 'Enter the bot token.')
      await d.getByLabel('Bot token', { exact: true }).fill('not-a-token')
      await saveRefused(page, d, 'telegram', 'bad_token', 'A bot token looks like 123456789:AAH… and comes from @BotFather. Copy it again without extra spaces.')
      await d.getByLabel('Bot token', { exact: true }).fill(TG_GUI)
      await saveRefused(page, d, 'telegram', 'bad_chat_id', 'Chat ID is a number (groups look like -1001234567890) or a public @channel_name.')
      await expect(d.getByLabel('Chat ID', { exact: true }), 'the form keeps what was typed').toHaveValue('abc')
      expect((await channel('telegram')).configured, 'a refused save saved something').toBe(false)

      await d.getByLabel('Chat ID', { exact: true }).fill('-1001234567890')
      const saved = await saveOk(page, d, 'telegram')
      expect(saved).toMatchObject({ type: 'telegram', configured: true, enabled: false, fields: { chat_id: '-1001234567890' }, secret_last4: last4(TG_GUI), min_severity: 'medium', last_test: null, approvals: false, approvers: [] })
      await toast(page, 'Channel Telegram saved.')
      await expect(dialog(page)).toHaveCount(0)
      const now = await channel('telegram')
      expect(now).toEqual(saved)
      const row = chanRow(page, now)
      await expect(row).toContainText('Chat -1001234567890')
      await expect(row).toContainText('Off')
      await expect(row).toContainText('Medium and above')
      await expect(row).toContainText('Not tested')
      await noEcho(page, TG_GUI)

      // edit: the key is not typed again and stays; the severity changes
      await row.getByRole('button', { name: 'Edit Telegram', exact: true }).click()
      const e = dialog(page)
      await expect(e.getByText(`Saved, ending in ${last4(TG_GUI)}. Leave empty to keep it.`)).toBeVisible()
      await expect(e.getByLabel('Bot token', { exact: true })).toHaveValue('')
      await expect(e.getByLabel('Chat ID', { exact: true })).toHaveValue('-1001234567890')
      await e.getByLabel('Send from severity', { exact: true }).selectOption('high')
      const edited = await saveOk(page, e, 'telegram')
      expect(edited).toMatchObject({ configured: true, enabled: false, secret_last4: last4(TG_GUI), min_severity: 'high', fields: { chat_id: '-1001234567890' } })
      await expect(chanRow(page, edited)).toContainText('High and above')

      // remove: Cancel keeps it, Delete removes it and its key
      await chanRow(page, edited).getByRole('button', { name: 'Remove channel Telegram', exact: true }).click()
      const r = page.getByRole('dialog', { name: 'Remove channel Telegram?' })
      await expect(r).toContainText("Deletes this channel's settings and saved key. Future alerts will not be sent through it.")
      await r.getByRole('button', { name: 'Cancel', exact: true }).click()
      await expect(dialog(page)).toHaveCount(0)
      expect((await channel('telegram')).configured, 'Cancel removed the channel').toBe(true)
      await chanRow(page, edited).getByRole('button', { name: 'Remove channel Telegram', exact: true }).click()
      const [gone] = await Promise.all([page.waitForResponse((x) => x.url().endsWith('/api/v1/notify/channels/telegram') && x.request().method() === 'DELETE'), page.getByRole('dialog').getByRole('button', { name: 'Delete', exact: true }).click()])
      expect(gone.status()).toBe(204)
      await toast(page, 'Channel Telegram and its saved key were removed.')
      expect(await channel('telegram')).toMatchObject({ configured: false, enabled: false, fields: {}, secret_last4: null, min_severity: 'medium', last_test: null, approvals: false, approvers: [] })
      await expect(chanRow(page, { type: 'telegram', configured: false })).toContainText('Not set up')
      await noEcho(page, TG_GUI)

      // every save and the remove are in the audit log, by the administrator, with no secret
      expect(await newAudit(c, before)).toEqual([
        `notify.channel_remove|telegram|configuration and saved key deleted|${ACCOUNTS.admin.email}`,
        `notify.channel_save|telegram|off|${ACCOUNTS.admin.email}`,
        `notify.channel_save|telegram|off|${ACCOUNTS.admin.email}`,
      ])
      await noVietnamese(page, 'telegram')
    } finally { await c.dispose() }
    expect(server).toEqual([])
    noErrors(errors, /status of 400/)
  })

  test('Email: refusals one field at a time, the encryption sets the port, an unreachable server fails the test with a plain sentence that is kept as the last test, edit, remove (INV-8, INV-11)', async ({ page }) => {
    test.setTimeout(120_000)
    const errors = collectErrors(page)
    const server = watch5xx(page)
    const port = await closedPort()
    const c = await as('admin')
    try {
      const before = await auditIds(c)
      await page.goto('/settings/channels')
      await chanRow(page, { type: 'email', configured: false }).getByRole('button', { name: 'Set up Email', exact: true }).click()
      const d = page.getByRole('dialog', { name: 'Channel Email' })
      await expect(d.getByLabel('Port', { exact: true })).toHaveValue('587')
      await expect(d.getByLabel('Encryption', { exact: true })).toHaveValue('starttls')
      await saveRefused(page, d, 'email', 'bad_to', 'Enter between 1 and 20 recipient emails, separated by commas.')
      await d.getByLabel('Send to', { exact: true }).fill('it@e2e.test, not-an-email')
      await saveRefused(page, d, 'email', 'bad_to', 'A recipient email is not valid. Separate several recipients with commas.')
      await d.getByLabel('Send to', { exact: true }).fill('it@e2e.test; boss@e2e.test')
      await saveRefused(page, d, 'email', 'bad_host', 'The SMTP server must be a domain name or an IP address, for example smtp.company.com.')
      await d.getByLabel('SMTP server', { exact: true }).fill('smtp.e2e.test')
      await d.getByLabel('Encryption', { exact: true }).selectOption('ssl')
      await expect(d.getByLabel('Port', { exact: true })).toHaveValue('465')
      await d.getByLabel('Encryption', { exact: true }).selectOption('starttls')
      await expect(d.getByLabel('Port', { exact: true })).toHaveValue('587')
      await d.getByLabel('Port', { exact: true }).fill('465')
      await saveRefused(page, d, 'email', 'port_mismatch', 'Port 465 uses SSL/TLS, not STARTTLS. Choose SSL/TLS, or change the port to 587 for STARTTLS.')
      await d.getByLabel('Port', { exact: true }).fill('587')
      await saveRefused(page, d, 'email', 'bad_username', 'Enter the SMTP username (usually the email address).')
      await d.getByLabel('Username', { exact: true }).fill('alerts@e2e.test')
      await saveRefused(page, d, 'email', 'secret_required', 'Enter the SMTP password. This channel has no saved key yet.')
      await d.getByLabel('Encryption', { exact: true }).selectOption('none')
      await saveRefused(page, d, 'email', 'bad_security', 'Unencrypted SMTP is only allowed for a server on your internal network. Choose STARTTLS or SSL/TLS.')
      await d.getByLabel('SMTP server', { exact: true }).fill('127.0.0.1')
      await d.getByLabel('Port', { exact: true }).fill(String(port))
      await saveRefused(page, d, 'email', 'bad_from', 'The sender email is not valid, for example alerts@company.com.')
      expect((await channel('email')).configured, 'a refused save saved something').toBe(false)

      await d.getByLabel('Send from', { exact: true }).fill('alerts@e2e.test')
      const [saved, tested] = await Promise.all([
        putOf(page, 'email'),
        page.waitForResponse((r) => r.url().endsWith('/api/v1/notify/channels/email/test') && r.request().method() === 'POST', { timeout: 60_000 }),
        d.getByRole('button', { name: 'Save and send test', exact: true }).click(),
      ])
      expect(saved.status()).toBe(200)
      expect(tested.status()).toBe(200)
      const testedText0 = await tested.text()
      noSecretIn(testedText0, 'test of email')
      const result = JSON.parse(testedText0) as { at: string; ok: boolean; detail: string }
      expect(result).toMatchObject({ ok: false, detail: ERR_UNREACHABLE })
      expect(Number.isNaN(Date.parse(result.at)), 'the time of the test is a date').toBe(false)
      await toast(page, ERR_UNREACHABLE)
      const now = await channel('email')
      expect(now).toMatchObject({ configured: true, enabled: true, secret_last4: null, min_severity: 'medium', last_test: result, approvals: false,
        fields: { host: '127.0.0.1', port: String(port), security: 'none', username: 'alerts@e2e.test', from: 'alerts@e2e.test', to: 'it@e2e.test, boss@e2e.test' } })
      const row = chanRow(page, now)
      await expect(row).toContainText('On')
      await expect(row).toContainText('it@e2e.test, boss@e2e.test')
      await expect(row.getByTitle(ERR_UNREACHABLE, { exact: true })).toHaveText(testedText(result))

      // edit: saving again is a new configuration, so the last test is cleared (POST-3)
      await row.getByRole('button', { name: 'Edit Email', exact: true }).click()
      const e = dialog(page)
      await expect(e.getByLabel('SMTP password', { exact: true }), 'the saved password is not put back in the form').toHaveValue('')
      await e.getByLabel('Send to', { exact: true }).fill('ops@e2e.test')
      const edited = await saveOk(page, e, 'email')
      expect(edited).toMatchObject({ enabled: true, last_test: null, fields: { to: 'ops@e2e.test' } })
      await expect(chanRow(page, edited)).toContainText('ops@e2e.test')
      await expect(chanRow(page, edited)).toContainText('Not tested')

      // the Send test button of the row gives the same answer, and the row keeps it
      const [again] = await Promise.all([page.waitForResponse((r) => r.url().endsWith('/api/v1/notify/channels/email/test') && r.request().method() === 'POST', { timeout: 60_000 }), chanRow(page, edited).getByRole('button', { name: 'Send test Email', exact: true }).click()])
      const againBody = (await again.json()) as { at: string; ok: boolean; detail: string }
      expect(againBody).toMatchObject({ ok: false, detail: ERR_UNREACHABLE })
      await expect(chanRow(page, edited).getByTitle(ERR_UNREACHABLE, { exact: true })).toHaveText(testedText(againBody))

      // remove: nobody signs in with email codes on this box, so the dialog has no warning about them
      await chanRow(page, edited).getByRole('button', { name: 'Remove channel Email', exact: true }).click()
      await expect(dialog(page)).not.toContainText('sign in with email codes')
      const [gone] = await Promise.all([page.waitForResponse((x) => x.url().endsWith('/api/v1/notify/channels/email') && x.request().method() === 'DELETE'), dialog(page).getByRole('button', { name: 'Delete', exact: true }).click()])
      expect(gone.status()).toBe(204)
      await toast(page, 'Channel Email and its saved key were removed.')
      expect((await channel('email')).configured).toBe(false)

      const A = ACCOUNTS.admin.email
      expect(await newAudit(c, before)).toEqual([
        `notify.channel_remove|email|configuration and saved key deleted|${A}`,
        `notify.channel_save|email|on|${A}`,
        `notify.channel_save|email|on|${A}`,
        `notify.channel_test|email|failed|${A}`,
        `notify.channel_test|email|failed|${A}`,
      ])
      await noVietnamese(page, 'email')
    } finally { await c.dispose() }
    expect(server).toEqual([])
    noErrors(errors, /status of 400/)
  })

  test('Webhook: refusals at the form, an address on this machine is refused in the form too (D-86), the generated key is saved but only its last 4 characters come back', async ({ page }) => {
    const errors = collectErrors(page)
    const server = watch5xx(page)
    const c = await as('admin')
    const BAD = 'The webhook URL must start with https:// (or http:// on an internal network). Example: https://hooks.company.com/vedette.'
    const BLOCKED = 'The webhook cannot point at this machine, a link-local or multicast address, or an unspecified address.'
    try {
      const before = await auditIds(c)
      await page.goto('/settings/channels')
      await chanRow(page, { type: 'webhook', configured: false }).getByRole('button', { name: 'Set up Webhook', exact: true }).click()
      const d = page.getByRole('dialog', { name: 'Channel Webhook' })
      await expect(d.getByRole('switch', { name: 'Approve actions from this channel' })).toHaveCount(0)
      await sw(d).click()
      const url = d.getByLabel('Webhook URL', { exact: true })
      const key = d.getByLabel('Signing key', { exact: true })
      await url.fill('not a url')
      await saveRefused(page, d, 'webhook', 'bad_url', BAD)
      await url.fill('http://127.0.0.1:8444/hook')
      await saveRefused(page, d, 'webhook', 'bad_url', BLOCKED)
      await url.fill('http://hooks.e2e.invalid/vedette')
      await saveRefused(page, d, 'webhook', 'bad_url', 'Plain http:// is only allowed for hosts on your internal network. Use https:// for this address.')
      await url.fill('https://hooks.e2e.invalid/vedette')
      await saveRefused(page, d, 'webhook', 'secret_required', 'Enter the webhook signing key.')
      await key.fill('abc')
      await saveRefused(page, d, 'webhook', 'bad_secret', 'The signing key needs at least 16 characters. Press Generate if you want a random one.')
      await d.getByRole('button', { name: 'Generate random', exact: true }).click()
      const generated = await key.inputValue()
      generatedKeys.push(generated)
      expect(generated, 'a random key is 24 bytes in hex').toMatch(/^[0-9a-f]{48}$/)
      expect((await channel('webhook')).configured, 'a refused save saved something').toBe(false)
      const saved = await saveOk(page, d, 'webhook')
      expect(saved).toMatchObject({ type: 'webhook', configured: true, enabled: false, fields: { url: 'https://hooks.e2e.invalid/vedette' }, secret_last4: last4(generated), min_severity: 'medium', approvals: false, approvers: [] })
      await toast(page, 'Channel Webhook saved.')
      await expect(chanRow(page, saved)).toContainText('https://hooks.e2e.invalid/vedette')
      await noEcho(page, generated)

      // an edit to an address on this machine is refused too, and the saved channel stays as it was
      await chanRow(page, saved).getByRole('button', { name: 'Edit Webhook', exact: true }).click()
      const e = dialog(page)
      await expect(e.getByLabel('Signing key', { exact: true }), 'the saved key is not put back in the form').toHaveValue('')
      await e.getByLabel('Webhook URL', { exact: true }).fill('https://localhost/hook')
      await saveRefused(page, e, 'webhook', 'bad_url', BLOCKED)
      expect(await channel('webhook')).toEqual(saved)
      await page.keyboard.press('Escape')

      expect(await newAudit(c, before), 'only the one accepted save is in the audit log').toEqual([`notify.channel_save|webhook|off|${ACCOUNTS.admin.email}`])
      await noVietnamese(page, 'webhook')
    } finally { await c.dispose() }
    expect(server).toEqual([])
    noErrors(errors, /status of 400/)
  })

  test('Slack: the webhook URL must be a Slack one, the label has a limit, the URL is the secret (S-NOT-2)', async ({ page }) => {
    const errors = collectErrors(page)
    const server = watch5xx(page)
    await page.goto('/settings/channels')
    await chanRow(page, { type: 'slack', configured: false }).getByRole('button', { name: 'Set up Slack', exact: true }).click()
    const d = page.getByRole('dialog', { name: 'Channel Slack' })
    await sw(d).click()
    const hook = d.getByLabel('Incoming Webhook URL', { exact: true })
    await saveRefused(page, d, 'slack', 'secret_required', 'Enter the Incoming Webhook URL.')
    await hook.fill('https://example.com/services/T0E2E0001/B0E2E0001/notahook')
    await saveRefused(page, d, 'slack', 'bad_webhook', 'A Slack Incoming Webhook URL starts with https://hooks.slack.com/services/. Copy it again from your Slack app.')
    await hook.fill(SLACK_HOOK)
    await d.getByLabel('Channel label (optional)', { exact: true }).fill('x'.repeat(81))
    await saveRefused(page, d, 'slack', 'bad_label', 'The channel label can be at most 80 characters.')
    // the channel ID and the two Socket Mode tokens belong to approvals only
    await expect(d.getByLabel('Channel ID', { exact: true })).toHaveCount(0)
    await d.getByRole('switch', { name: 'Approve actions from this channel' }).click()
    await expect(d.getByLabel('Channel ID', { exact: true })).toBeVisible()
    await expect(d.getByLabel('App-level token (xapp-…)', { exact: true })).toBeVisible()
    await expect(d.getByLabel('Bot token (xoxb-…)', { exact: true })).toBeVisible()
    await d.getByRole('switch', { name: 'Approve actions from this channel' }).click()
    await expect(d.getByLabel('Channel ID', { exact: true })).toHaveCount(0)
    await d.getByLabel('Channel label (optional)', { exact: true }).fill('#it-alerts-e2e')
    const saved = await saveOk(page, d, 'slack')
    expect(saved).toMatchObject({ type: 'slack', configured: true, enabled: false, fields: { label: '#it-alerts-e2e' }, secret_last4: last4(SLACK_HOOK), approvals: false })
    await expect(chanRow(page, saved)).toContainText('#it-alerts-e2e')
    await noEcho(page, SLACK_HOOK)
    await chanRow(page, saved).getByRole('button', { name: 'Edit Slack', exact: true }).click()
    await expect(dialog(page).getByLabel('Incoming Webhook URL', { exact: true }), 'the saved URL is not put back in the form').toHaveValue('')
    await page.keyboard.press('Escape')
    expect(server).toEqual([])
    noErrors(errors, /status of 400/)
  })

  test('Zalo OA: OA ID, recipient and token are each refused at their own check (S-NOT-1)', async ({ page }) => {
    const errors = collectErrors(page)
    const server = watch5xx(page)
    await page.goto('/settings/channels')
    await chanRow(page, { type: 'zalo', configured: false }).getByRole('button', { name: 'Set up Zalo OA', exact: true }).click()
    const d = page.getByRole('dialog', { name: 'Channel Zalo OA' })
    await sw(d).click()
    await d.getByLabel('OA ID', { exact: true }).fill('12345')
    await saveRefused(page, d, 'zalo', 'bad_oa_id', 'OA ID is a string of digits, shown in the Official Account management page.')
    await d.getByLabel('OA ID', { exact: true }).fill('1234567890')
    await saveRefused(page, d, 'zalo', 'bad_user_id', 'The Zalo recipient ID (user_id) is the number of a person who followed or messaged the OA.')
    await d.getByLabel('Recipient ID (user_id)', { exact: true }).fill('2468013579')
    await saveRefused(page, d, 'zalo', 'secret_required', 'Enter the access token. This channel has no saved key yet.')
    await d.getByLabel('Access token', { exact: true }).fill('short')
    await saveRefused(page, d, 'zalo', 'bad_token', 'The Zalo access token is too short. Copy the whole string from Zalo Developers.')
    await d.getByLabel('Access token', { exact: true }).fill(ZALO_TOKEN)
    const saved = await saveOk(page, d, 'zalo')
    expect(saved).toMatchObject({ type: 'zalo', configured: true, enabled: false, fields: { oa_id: '1234567890', user_id: '2468013579' }, secret_last4: last4(ZALO_TOKEN) })
    await expect(chanRow(page, saved)).toContainText('OA 1234567890, recipient 2468013579')
    await noEcho(page, ZALO_TOKEN)
    await chanRow(page, saved).getByRole('button', { name: 'Edit Zalo OA', exact: true }).click()
    await expect(dialog(page).getByLabel('Access token', { exact: true }), 'the saved token is not put back in the form').toHaveValue('')
    await page.keyboard.press('Escape')
    expect(server).toEqual([])
    noErrors(errors, /status of 400/)
  })

  test('Zalo personal: the unofficial-account warning is always shown, and a recipient and a session are both required', async ({ page }) => {
    const errors = collectErrors(page)
    await page.goto('/settings/channels')
    await chanRow(page, { type: 'zalo-personal', configured: false }).getByRole('button', { name: 'Set up Zalo personal', exact: true }).click()
    const d = page.getByRole('dialog', { name: 'Channel Zalo personal' })
    await expect(d.getByText("Unofficial: uses Zalo's personal web protocol, not an official API. Zalo may lock the account. Use a dedicated account, not your personal one.")).toBeVisible()
    await expect(d.getByText('Not signed in yet.')).toBeVisible()
    await sw(d).click()
    await saveRefused(page, d, 'zalo-personal', 'bad_user_id', 'The recipient is the numeric Zalo ID of a user or a group (6 to 25 digits).')
    await d.getByLabel('Recipient (user or group ID)', { exact: true }).fill('8412345678901')
    await saveRefused(page, d, 'zalo-personal', 'secret_required', 'Scan the QR code with the Zalo app first. This channel has no saved session yet.')
    expect((await channel('zalo-personal')).configured).toBe(false)
    noErrors(errors, /status of 400/)
  })

  // The GUI's "I scanned it" makes a placeholder string and the box refuses it (400 bad_secret): the backend loginQR is not built, and paste-cookies vs a loginQR port is
  // undecided (.ai/deferred/feat-notify-module.md:9, D-171(2)). The body is the real flow: it becomes the test once the backend exists.
  test.fixme('Zalo personal: sign in by QR in the form and save the channel (backend loginQR not built: .ai/deferred/feat-notify-module.md:9)', async ({ page }) => {
    await page.goto('/settings/channels')
    await chanRow(page, { type: 'zalo-personal', configured: false }).getByRole('button', { name: 'Set up Zalo personal', exact: true }).click()
    const d = page.getByRole('dialog', { name: 'Channel Zalo personal' })
    await sw(d).click() // never turned on: no test of this file may send to the internet
    await d.getByRole('button', { name: 'Show QR code', exact: true }).click()
    await d.getByRole('button', { name: 'I scanned it', exact: true }).click()
    await d.getByLabel('Recipient (user or group ID)', { exact: true }).fill('8412345678901')
    await saveBtn(d).click()
    await toast(page, 'Channel Zalo personal saved.')
  })
})

test.describe('the box refuses what D-86 forbids, and keeps the rest (INV-8)', () => {
  const BAD = 'The webhook URL must start with https:// (or http:// on an internal network). Example: https://hooks.company.com/vedette.'
  const BLOCKED = 'The webhook cannot point at this machine, a link-local or multicast address, or an unspecified address.'
  const INSECURE = 'Plain http:// is only allowed for hosts on your internal network. Use https:// for this address.'
  const body = (url: string) => ({ enabled: false, fields: { url }, secret: WEBHOOK_KEY, min_severity: 'medium' })

  test('a webhook to loopback, link-local, multicast, unspecified, to a name that means loopback, or to a disguised number is 400 bad_url and nothing is saved; a private http address and a public https name are accepted', async () => {
    const c = await as('admin')
    try {
      const before = await auditIds(c)
      const cases: [string, string][] = [
        ['http://127.0.0.1:9/x', BLOCKED], ['https://127.0.0.1/x', BLOCKED], ['http://localhost/x', BLOCKED], ['https://hooks.localhost/x', BLOCKED],
        ['https://[::1]/x', BLOCKED], ['https://169.254.169.254/latest/meta-data', BLOCKED], ['https://[fe80::1]/x', BLOCKED], ['https://0.0.0.0/x', BLOCKED], ['https://224.0.0.1/x', BLOCKED],
        ['https://[::ffff:127.0.0.1]/x', BLOCKED], ['https://LOCALHOST/x', BLOCKED], ['https://127.1/x', BAD], ['https://0177.0.0.1/x', BAD], ['https://2130706433/x', BAD], ['https://0x7f.1/x', BAD], ['https://user:pw@hooks.e2e.invalid/x', BAD], ['ftp://hooks.e2e.invalid/x', BAD], ['', BAD],
        ['http://hooks.e2e.invalid/x', INSECURE],
      ]
      for (const [url, message] of cases) {
        expect(await call(c, 'PUT', '/notify/channels/webhook', body(url)), `PUT webhook ${JSON.stringify(url)}`).toMatchObject(refused(400, 'bad_url', message))
      }
      expect((await getChannels(c)).channels.find((x) => x.type === 'webhook')!.configured, 'a refused address was saved').toBe(false)
      expect(await newAudit(c, before), 'a refusal wrote an audit row').toEqual([])
      // an internal SIEM on plain http (RFC 1918) and a public https name are fine: saved (turned off, so nothing is ever sent)
      const ok1 = await call<Ch>(c, 'PUT', '/notify/channels/webhook', body('http://10.99.99.99:9/hook'))
      expect(ok1, 'private http').toMatchObject({ status: 200, body: { configured: true, fields: { url: 'http://10.99.99.99:9/hook' }, secret_last4: last4(WEBHOOK_KEY) } })
      const ok2 = await call<Ch>(c, 'PUT', '/notify/channels/webhook', body('https://hooks.e2e.invalid/hook'))
      expect(ok2, 'public https').toMatchObject({ status: 200, body: { configured: true, fields: { url: 'https://hooks.e2e.invalid/hook' } } })
      await auditHasNo(c, WEBHOOK_KEY)
    } finally { await c.dispose() }
  })

  test('a webhook to this machine\'s own address is refused, which is what stops the box calling itself', async () => {
    const own = ownAddress()
    if (process.env.CI) expect(own, 'CI machine has no network address besides loopback').toBeDefined()
    else test.skip(!own, 'this machine has no network address besides loopback')
    const c = await as('admin')
    try {
      expect(await call(c, 'PUT', '/notify/channels/webhook', body(`https://${own}/hook`)), `PUT webhook ${own}`).toMatchObject(refused(400, 'bad_url', BLOCKED))
      expect(await call(c, 'PUT', '/notify/channels/webhook', body(`https://${own}:8444/hook`)), `PUT webhook ${own}:8444`).toMatchObject(refused(400, 'bad_url', BLOCKED))
      expect((await getChannels(c)).channels.find((x) => x.type === 'webhook')!.configured).toBe(false)
    } finally { await c.dispose() }
  })

  test('the API refuses what the form refuses, with the same codes, for every kind; a minimum severity of Info is refused by the schema (400 invalid)', async () => {
    const c = await as('admin')
    try {
      const m = 'medium'
      const put = (type: ChannelType, b: unknown) => api(c, 'PUT', `/notify/channels/${type}`, b)
      expect(await put('telegram', { enabled: false, fields: { chat_id: '-1001234567890' }, secret: 'nope', min_severity: m })).toMatchObject(refused(400, 'bad_token'))
      expect(await put('slack', { enabled: false, fields: {}, secret: 'https://hooks.slack.com/services/a/b', min_severity: m })).toMatchObject(refused(400, 'bad_webhook'))
      expect(await put('zalo', { enabled: false, fields: { oa_id: '1234567890', user_id: '2468013579' }, secret: ZALO_TOKEN + ' x', min_severity: m })).toMatchObject(refused(400, 'bad_token', 'The Zalo access token has a character that is not allowed. Copy it again without spaces.'))
      expect(await put('email', { enabled: false, fields: { host: 'smtp.e2e.test', port: 'abc', security: 'starttls', username: 'a@e2e.test', from: 'a@e2e.test', to: 'it@e2e.test' }, secret: SMTP_PASSWORD, min_severity: m })).toMatchObject(refused(400, 'bad_port', 'The SMTP port is a number from 1 to 65535 (usually 587 or 465).'))
      expect(await put('email', { enabled: false, fields: { host: 'smtp.e2e.test', port: '0', security: 'starttls', username: 'a@e2e.test', from: 'a@e2e.test', to: 'it@e2e.test' }, secret: SMTP_PASSWORD, min_severity: m })).toMatchObject(refused(400, 'bad_port', 'The SMTP port is a number from 1 to 65535 (usually 587 or 465).'))
      expect(await put('email', { enabled: false, fields: { host: 'smtp.e2e.test', port: '587', security: 'starttls', username: 'a@e2e.test', from: 'not-an-email', to: 'it@e2e.test' }, secret: SMTP_PASSWORD, min_severity: m })).toMatchObject(refused(400, 'bad_from'))
      expect(await put('email', { enabled: false, fields: { host: 'smtp.e2e.test', port: '587', security: 'ssl', username: 'a@e2e.test', from: 'a@e2e.test', to: 'it@e2e.test' }, secret: SMTP_PASSWORD, min_severity: m })).toMatchObject(refused(400, 'port_mismatch', 'Port 587 uses STARTTLS, not SSL/TLS. Choose STARTTLS, or change the port to 465 for SSL/TLS.'))
      expect(await put('zalo-personal', { enabled: false, fields: { user_id: '8412345678901' }, secret: 'zl-session-0123456789abcdef', min_severity: m })).toMatchObject(refused(400, 'bad_secret', 'The saved Zalo session is not usable. Sign in to Zalo again.'))
      expect(await put('telegram', { enabled: false, fields: { chat_id: '-1001234567890' }, secret: TG_API, min_severity: 'info' })).toMatchObject(refused(400, 'invalid', 'The field "min_severity" is missing or has a value that is not allowed. Fix it and try again.'))
      expect((await getChannels(c)).channels.filter((x) => x.configured), 'a refused save saved something').toEqual([])
    } finally { await c.dispose() }
  })

  test('a test needs a saved configuration: every kind answers 400 not_configured, and sends nothing (INV-11)', async () => {
    const c = await as('admin')
    try {
      const before = await auditIds(c)
      for (const type of TYPES) {
        expect(await call(c, 'POST', `/notify/channels/${type}/test`), `test of ${type}`).toMatchObject(refused(400, 'not_configured', 'This channel has no saved configuration. Enter and save it before sending a test.'))
      }
      expect(await newAudit(c, before), 'a refused test wrote an audit row').toEqual([])
    } finally { await c.dispose() }
  })

  test('a message cannot be sent again through a channel that is not set up: 409 channel_not_ready (INV-11)', async () => {
    // There is no history row to point at on a box where nothing was sent, so the id is one that does not exist: 404. The 409 is proved with a real row in the delivery test below.
    const c = await as('admin')
    try {
      expect(await call(c, 'POST', '/notify/history/does-not-exist/resend')).toMatchObject(refused(404, 'not_found', 'No such message in the history.'))
    } finally { await c.dispose() }
  })
})

test.describe('approver lists (INV-7 validation)', () => {
  const TG = { enabled: false, fields: { chat_id: '-1001234567890' }, secret: TG_API, min_severity: 'medium' }
  const chat = (c: Awaited<ReturnType<typeof as>>, type: ChannelType, b: unknown) => api(c, 'PUT', `/notify/channels/${type}`, b)

  test('the API refuses an approver list that cannot work: empty, a public @name, a viewer, a stranger, twice, a bad address; webhook and Zalo OA take none', async () => {
    const c = await as('admin')
    try {
      const all = await users()
      const op = all.find((u) => u.email === ACCOUNTS.operator.email)!
      const viewer = all.find((u) => u.email === ACCOUNTS.viewer.email)!
      const ok = { user_id: op.id, address: '123456789' }
      const T = (over: object) => ({ ...TG, approvals: true, ...over })
      expect(await chat(c, 'telegram', T({ approvers: [] }))).toMatchObject(refused(400, 'approvers_required', 'Add at least one approver, or turn off "Approve actions from this channel".'))
      expect(await chat(c, 'telegram', T({ fields: { chat_id: '@alerts_e2e' }, approvers: [ok] }))).toMatchObject(refused(400, 'bad_chat_id',
        'To approve actions in Telegram, Chat ID must be the number of the chat (groups look like -1001234567890), not a public @channel_name: anyone can join a public channel, and a name that is given up can be taken by someone else.'))
      expect(await chat(c, 'telegram', T({ approvers: [{ user_id: viewer.id, address: '123456789' }] }))).toMatchObject(refused(400, 'viewer_not_allowed', `${viewer.email} is a viewer. Only operators and administrators can approve actions.`))
      expect(await chat(c, 'telegram', T({ approvers: [{ user_id: 'u-does-not-exist', address: '123456789' }] }))).toMatchObject(refused(400, 'no_such_user', 'One of the approvers does not exist or is disabled.'))
      expect(await chat(c, 'telegram', T({ approvers: [ok, ok] }))).toMatchObject(refused(400, 'duplicate_user', `${op.email} is listed twice.`))
      expect(await chat(c, 'telegram', T({ approvers: [{ user_id: op.id, address: 'abc' }] }))).toMatchObject(refused(400, 'bad_approver_address', `${op.email}: A Telegram user ID is a number of 5 to 15 digits. A bot such as @userinfobot can show it.`))
      expect(await chat(c, 'email', { enabled: false, fields: { host: 'smtp.e2e.test', port: '587', security: 'starttls', username: 'a@e2e.test', from: 'a@e2e.test', to: 'it@e2e.test' }, secret: SMTP_PASSWORD, min_severity: 'medium', approvals: true, approvers: [{ user_id: op.id, address: 'someone-else@e2e.test' }] }))
        .toMatchObject(refused(400, 'bad_approver_address', `${op.email}: the approval link goes to the sign-in email of the user, ${op.email}.`))
      for (const [type, fields] of [['webhook', { url: 'https://hooks.e2e.invalid/x' }], ['zalo', { oa_id: '1234567890', user_id: '2468013579' }]] as const) {
        expect(await chat(c, type, { enabled: false, fields, secret: type === 'webhook' ? WEBHOOK_KEY : ZALO_TOKEN, min_severity: 'medium', approvals: true, approvers: [ok] }), type).toMatchObject(refused(400, 'approvals_unsupported', 'This channel cannot take approvals. It sends a link that opens Vedette instead.'))
      }
      expect((await getChannels(c)).channels.filter((x) => x.configured), 'a refused save saved something').toEqual([])
    } finally { await c.dispose() }
  })

  test('Slack approvals need a channel ID and both Socket Mode tokens; the tokens come back as their last 4 characters only (INV-1, INV-7)', async () => {
    const c = await as('admin')
    try {
      const op = (await users()).find((u) => u.email === ACCOUNTS.operator.email)!
      const before = await auditIds(c)
      const S = (over: object) => ({ enabled: false, fields: { label: '', channel_id: 'C04ABCDEF12' }, secret: SLACK_HOOK, min_severity: 'medium', approvals: true, approvers: [{ user_id: op.id, address: 'U04ABCD1234' }], app_token: SLACK_APP, bot_token: SLACK_BOT, ...over })
      expect(await chat(c, 'slack', S({ fields: { label: '', channel_id: 'abc' } }))).toMatchObject(refused(400, 'bad_channel_id', 'A Slack channel ID looks like C04ABCDEF12. Open the channel details in Slack and copy the ID at the bottom.'))
      expect(await chat(c, 'slack', S({ app_token: 'xapp-bad' }))).toMatchObject(refused(400, 'bad_app_token', 'The app-level token starts with xapp- and needs the connections:write scope. Copy it again from Basic Information.'))
      expect(await chat(c, 'slack', S({ bot_token: 'xoxb-bad' }))).toMatchObject(refused(400, 'bad_bot_token', 'The bot token starts with xoxb-. Copy it from OAuth & Permissions after installing the app.'))
      expect(await chat(c, 'slack', S({ app_token: '' }))).toMatchObject(refused(400, 'secret_required', 'Enter the app-level token (xapp-…). Approving in Slack needs Socket Mode.'))
      expect(await chat(c, 'slack', S({ bot_token: '' }))).toMatchObject(refused(400, 'secret_required', 'Enter the bot token (xoxb-…). Approving in Slack needs it to read button presses and reply.'))
      expect(await chat(c, 'slack', S({ approvers: [{ user_id: op.id, address: 'not-a-member' }] }))).toMatchObject(refused(400, 'bad_approver_address', `${op.email}: A Slack member ID looks like U04ABCD1234 (Profile, More, Copy member ID).`))
      const ok = await chat(c, 'slack', S({}))
      expect(ok, JSON.stringify(ok.body)).toMatchObject({ status: 200, body: { configured: true, enabled: false, approvals: true, secret_last4: last4(SLACK_HOOK), fields: { channel_id: 'C04ABCDEF12' },
        approvers: [{ user_id: op.id, address: 'U04ABCD1234' }], approval_last4: { app_token: last4(SLACK_APP), bot_token: last4(SLACK_BOT) } } })
      const text = JSON.stringify(await getChannels(c))
      for (const s of [SLACK_HOOK, SLACK_APP, SLACK_BOT]) {
        expect(text, 'a secret is in GET /notify/channels').not.toContain(s.slice(0, -4))
        await auditHasNo(c, s)
      }
      expect(await newAudit(c, before)).toEqual([`notify.channel_save|slack|off, approvals on (1 approver)|${ACCOUNTS.admin.email}`])
      // a second save without the tokens keeps the saved ones (blank = keep)
      const keep = await chat(c, 'slack', S({ app_token: '', bot_token: '', secret: '' }))
      expect(keep, JSON.stringify(keep.body)).toMatchObject({ status: 200, body: { secret_last4: last4(SLACK_HOOK), approval_last4: { app_token: last4(SLACK_APP), bot_token: last4(SLACK_BOT) } } })
    } finally { await c.dispose() }
  })

  test('Telegram in the form: the approver list offers only operators and administrators, an empty list is refused, a valid one is saved and shown as a chip', async ({ page }) => {
    const errors = collectErrors(page)
    const server = watch5xx(page)
    const c = await as('admin')
    try {
      const all = await users()
      const op = all.find((u) => u.email === ACCOUNTS.operator.email)!
      const saved = await chat(c, 'telegram', { ...TG, approvals: true, approvers: [{ user_id: op.id, address: '123456789' }] })
      expect(saved).toMatchObject({ status: 200, body: { approvals: true, approvers: [{ user_id: op.id, address: '123456789' }] } })
      const before = await auditIds(c)

      await page.goto('/settings/channels')
      await expect(chanRow(page, { type: 'telegram', configured: true })).toContainText('Approvals')
      await chanRow(page, { type: 'telegram', configured: true }).getByRole('button', { name: 'Edit Telegram', exact: true }).click()
      const d = dialog(page)
      await expect(d.getByLabel('Bot token', { exact: true }), 'the saved token is not put back in the form').toHaveValue('')
      await expect(d.getByRole('switch', { name: 'Approve actions from this channel' })).toBeChecked()
      const list = d.getByRole('group', { name: 'Who can approve' })
      await expect(list).toContainText(op.name)
      await expect(list.getByLabel('Telegram user ID', { exact: true })).toHaveValue('123456789')

      // remove the only approver: refused
      await list.getByRole('button', { name: `Remove ${op.email}`, exact: true }).click()
      await expect(list).toContainText('No approvers yet. Add at least one operator or administrator.')
      await saveRefused(page, d, 'telegram', 'approvers_required', 'Add at least one approver, or turn off "Approve actions from this channel".')
      // the picker lists exactly the active operators and administrators, and nobody who is a viewer
      const eligible = all.filter((u) => !u.disabled && u.role !== 'viewer')
      const picker = list.getByLabel('Add approver', { exact: true })
      await expect(picker.locator('option')).toHaveText(eligible.map((u) => `${u.name} (${u.email})`))
      for (const v of all.filter((u) => u.role === 'viewer')) await expect(picker.locator('option').filter({ hasText: v.email })).toHaveCount(0)
      await picker.selectOption(op.id)
      await list.getByRole('button', { name: 'Add', exact: true }).click()
      await list.getByLabel('Telegram user ID', { exact: true }).fill('5551234')
      const again = await saveOk(page, d, 'telegram')
      expect(again).toMatchObject({ approvals: true, approvers: [{ user_id: op.id, address: '5551234' }] })
      expect(await newAudit(c, before)).toEqual([`notify.channel_save|telegram|off, approvals on (1 approver)|${ACCOUNTS.admin.email}`])
      await noVietnamese(page, 'telegram approvals')
    } finally { await c.dispose() }
    expect(server).toEqual([])
    noErrors(errors, /status of 400/)
  })
})

test.describe('quiet hours and grouping (S-NOT-1, INV-3, INV-5)', () => {
  test('the form explains the hours, refuses equal times, saves, keeps the values after a reload, and writes an audit row', async ({ page }) => {
    const errors = collectErrors(page)
    const server = watch5xx(page)
    const c = await as('admin')
    try {
      const before = await auditIds(c)
      await page.goto('/settings/channels')
      const from = page.getByLabel('From', { exact: true }), until = page.getByLabel('Until', { exact: true })
      const on = page.getByRole('switch', { name: 'Turn on quiet hours' })
      const group = page.getByRole('switch', { name: 'Group messages for the same product' })
      const crit = page.getByLabel('Still send Critical right away', { exact: true })
      const saveRules = page.getByRole('button', { name: 'Save quiet hours and grouping', exact: true })
      await expect(on).not.toBeChecked() // the defaults
      await from.fill('23:00'); await until.fill('06:15')
      await expect(page.getByText(/^Quiet from /)).toHaveCount(0) // off: no summary yet
      await on.click()
      await expect(page.getByText(quietSummary({ enabled: true, from: '23:00', to: '06:15', allow_critical: true })!, { exact: true })).toBeVisible()
      await until.fill('23:00')
      await expect(page.getByText(/^Quiet from /)).toHaveCount(0)
      const [bad] = await Promise.all([page.waitForResponse((r) => r.url().endsWith('/api/v1/notify/rules') && r.request().method() === 'PUT'), saveRules.click()])
      expect(bad.status()).toBe(400)
      expect(await bad.json()).toMatchObject({ error: { code: 'bad_quiet', message: 'The start and end times must not be the same.' } })
      await expect(page.getByRole('alert').filter({ hasText: 'The start and end times must not be the same.' })).toBeVisible()
      await until.fill('23:30')
      await expect(page.getByText(quietSummary({ enabled: true, from: '23:00', to: '23:30', allow_critical: true })!, { exact: true })).toBeVisible()
      await crit.click()
      await group.click()
      await page.getByLabel('Grouping window', { exact: true }).selectOption('240')
      const [ok] = await Promise.all([page.waitForResponse((r) => r.url().endsWith('/api/v1/notify/rules') && r.request().method() === 'PUT'), saveRules.click()])
      expect(ok.status()).toBe(200)
      await toast(page, 'Quiet hours and grouping saved.')
      const want: Rules = { quiet: { enabled: true, from: '23:00', to: '23:30', allow_critical: false }, grouping: { enabled: false, window_min: 240 } }
      expect(await ok.json()).toEqual(want)
      const d = await getChannels(c)
      expect({ quiet: d.quiet, grouping: d.grouping }).toEqual(want)

      await page.reload()
      await expect(from).toHaveValue('23:00')
      await expect(until).toHaveValue('23:30')
      await expect(on).toBeChecked()
      await expect(crit).not.toBeChecked()
      await expect(group).not.toBeChecked()
      await expect(page.getByLabel('Grouping window', { exact: true })).toHaveValue('240')
      expect(await newAudit(c, before)).toEqual([`notify.rules_save|quiet hours and grouping||${ACCOUNTS.admin.email}`])
      await noVietnamese(page, 'rules')
    } finally { await c.dispose() }
    expect(server).toEqual([])
    noErrors(errors, /status of 400/)
  })

  test('the API refuses equal times (400 bad_quiet) and keeps what was saved', async () => {
    const c = await as('admin')
    try {
      const rules: Rules = { quiet: { enabled: true, from: '08:00', to: '08:00', allow_critical: true }, grouping: { enabled: true, window_min: 15 } }
      expect(await call(c, 'PUT', '/notify/rules', rules)).toMatchObject(refused(400, 'bad_quiet', 'The start and end times must not be the same.'))
      const d = await getChannels(c)
      expect({ quiet: d.quiet, grouping: d.grouping }, 'a refused save changed the rules').toEqual(DEFAULT_RULES)
    } finally { await c.dispose() }
  })
})

test.describe('a real send that fails: the record in History, the finding and the audit log (S-ALERT-1, S-NOT-1, INV-6, INV-11)', () => {
  test.beforeAll(startFeedServer)
  test.afterAll(stopFeedServer)
  test.afterEach(sweepDevices)

  test('a finding on a declared device is queued for an email channel whose server refuses the connection: one failed row with the plain reason, on the finding, in History, sent again by an operator and from the page', async ({ page }) => {
    test.setTimeout(240_000)
    const errors = collectErrors(page)
    const server = watch5xx(page)
    const port = await closedPort()
    const c = await as('admin'), op = await as('operator'), viewer = await as('viewer')
    try {
      // nothing held back: quiet hours are off and grouping would wait an hour for a vulnerability that is not Critical
      const noGroup: Rules = { quiet: DEFAULT_RULES.quiet, grouping: { enabled: false, window_min: 60 } }
      expect((await call(c, 'PUT', '/notify/rules', noGroup)).status).toBe(200)
      const mail = await call<Ch>(c, 'PUT', '/notify/channels/email', { enabled: true, fields: { host: '127.0.0.1', port: String(port), security: 'none', username: '', from: 'alerts@e2e.test', to: 'it@e2e.test' }, min_severity: 'low' })
      expect(mail.status, JSON.stringify(mail.body)).toBe(200)
      const audit = await auditIds(c)

      const s = await seed()
      const mine = (h: { items: Hist[] }) => h.items.filter((i) => i.link.endsWith(`/findings/${s.findingId}`))
      await expect.poll(async () => mine(await getHistory(c)).length, { message: 'the vulnerability notice was attempted (the deliver job runs every 15 s)', timeout: 75_000, intervals: [2_000] }).toBe(1)
      const row = mine(await getHistory(c))[0]!
      expect(row).toMatchObject({ kind: 'vuln', channel: 'email', to: 'it@e2e.test', ok: false, error: ERR_UNREACHABLE })
      expect(row.what.length, 'what was sent is named').toBeGreaterThan(0)

      // the finding says who was told and that it failed; a viewer may read it
      const notices = await call(viewer, 'GET', `/notify/findings/${s.findingId}/notices`)
      expect(notices).toEqual({ status: 200, body: { sends: [{ id: row.id, channel: 'email', to: 'it@e2e.test', at: row.at, ok: false, error: ERR_UNREACHABLE }] } })
      await page.goto(`/findings/${s.findingId}`)
      await expect(page.locator('#notified')).toContainText(`Notified: Email (failed: ${ERR_UNREACHABLE})`)

      // an operator sends it again: the channel is on, so it is tried and fails the same way, as a new row; a viewer may not
      expect(await call(viewer, 'POST', `/notify/history/${row.id}/resend`)).toMatchObject({ status: 403, body: { error: { code: 'forbidden' } } })
      const resent = await call<Hist>(op, 'POST', `/notify/history/${row.id}/resend`)
      expect(resent).toMatchObject({ status: 200, body: { channel: 'email', to: 'it@e2e.test', ok: false, error: ERR_UNREACHABLE, kind: 'vuln', what: row.what, link: row.link } })
      expect(resent.body.id).not.toBe(row.id)
      expect(mine(await getHistory(c)).map((i) => i.id).sort()).toEqual([row.id, resent.body.id].sort())

      // History in the page: both rows, the reason, the kind; Send again from the page adds a third and shows the reason
      await page.goto('/settings/channels')
      const meta = page.getByText(/^Vedette only alerts for products you own\./)
      await expect.poll(async () => (await meta.innerText()) === historyMeta((await getHistory(c)).suppressed), { message: 'the line over History says what the API says now' }).toBe(true)
      const table = page.getByRole('table', { name: 'Sent messages' })
      const rows = table.getByRole('row').filter({ hasText: row.what })
      await expect(rows).toHaveCount(2)
      for (const text of ['Email', 'it@e2e.test', 'Vulnerability', 'Failed', ERR_UNREACHABLE]) await expect(rows.first()).toContainText(text)
      await expect(rows.first().getByRole('link', { name: row.what, exact: true })).toBeVisible()
      const [res] = await Promise.all([page.waitForResponse((r) => /\/api\/v1\/notify\/history\/[^/]+\/resend$/.test(r.url())), rows.first().getByRole('button', { name: 'Send again via Email', exact: true }).click()])
      expect(res.status()).toBe(200)
      expect(await res.json()).toMatchObject({ ok: false, error: ERR_UNREACHABLE, what: row.what })
      await toast(page, ERR_UNREACHABLE)
      await expect(rows).toHaveCount(3)
      expect(mine(await getHistory(c))).toHaveLength(3)

      const A = ACCOUNTS.operator.email, B = ACCOUNTS.admin.email
      const log = await newAudit(c, audit)
      expect(log.filter((l) => l.startsWith('notify.resend|')).map((l) => l.split('|').slice(2).join('|')).sort(), 'one resend by the operator, one by the administrator').toEqual([`email|${B}`, `email|${A}`].sort())
      await expectAccessible(page, 'history with rows')
      await noVietnamese(page, 'history with rows')
      await shot(page, 'real', 'notify-history')
    } finally { await Promise.all([c.dispose(), op.dispose(), viewer.dispose()]) }
    expect(server).toEqual([])
    noErrors(errors)
  })

  test('a message cannot be sent again once its channel is gone: 409 channel_not_ready (INV-11)', async () => {
    test.setTimeout(240_000)
    const port = await closedPort()
    const c = await as('admin')
    try {
      expect((await call(c, 'PUT', '/notify/rules', { quiet: DEFAULT_RULES.quiet, grouping: { enabled: false, window_min: 60 } })).status).toBe(200)
      expect((await call(c, 'PUT', '/notify/channels/email', { enabled: true, fields: { host: '127.0.0.1', port: String(port), security: 'none', username: '', from: 'alerts@e2e.test', to: 'it@e2e.test' }, min_severity: 'low' })).status).toBe(200)
      const s = await seed()
      let row: Hist | undefined
      await expect.poll(async () => { row = (await getHistory(c)).items.find((i) => i.link.endsWith(`/findings/${s.findingId}`)); return row?.ok }, { timeout: 75_000, intervals: [2_000] }).toBe(false)
      expect((await call(c, 'DELETE', '/notify/channels/email')).status).toBe(204)
      expect(await call(c, 'POST', `/notify/history/${row!.id}/resend`)).toMatchObject(refused(409, 'channel_not_ready', 'This channel is not set up or is turned off. An administrator can turn it on in Settings, Alert channels.'))
      expect(await call(c, 'POST', '/notify/channels/email/test')).toMatchObject(refused(400, 'not_configured'))
    } finally { await c.dispose() }
  })
})
