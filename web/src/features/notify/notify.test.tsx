import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClientProvider } from '@tanstack/react-query'
import { http, HttpResponse } from 'msw'
import { MemoryRouter } from 'react-router'
import { Toaster } from 'sonner'
import { makeQueryClient } from '@/app/App'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { server } from '@/test/server'
import { eachOption } from '@/test/formMatrix'
import { auditStore, installStore, modulesStore, orgStore, sessionStore, usersStore } from '@/mocks/stores'
import type { Role } from '@/lib/session'
import ChannelsSettings from './ChannelsSettings'
import { forbiddenHost, ownHost } from './types'

const USER: Record<Role, string> = { admin: 'u-admin', operator: 'u-op', viewer: 'u-view' }
function renderChannels(role: Role = 'admin') {
  orgStore.update((o) => ({ ...o, setup_complete: true }))
  sessionStore.set({ userId: USER[role] })
  return render(<MemoryRouter><QueryClientProvider client={makeQueryClient()}><ChannelsSettings /><Toaster /></QueryClientProvider></MemoryRouter>)
}
const getJson = async (path: string) => (await fetch(`${location.origin}/api/v1${path}`)).json() as Promise<Record<string, unknown>>
/** Button is disabled until the role is known: wait until it is enabled, then press. */
async function press(name: string | RegExp) {
  await waitFor(() => expect(screen.getByRole('button', { name })).toBeEnabled())
  await userEvent.click(screen.getByRole('button', { name }))
}
const TOKEN = '8123456789:AAHnewTokenForVedette_1234567890abcdefXY7z'

describe('notify: incidents (S-ALERT-3, D-52)', () => {
  it('the heading counts new incidents; the list has trap, bad address and log anomaly, no vulnerabilities; no a11y violations', async () => {
    renderApp('/incidents')
    expect(await screen.findByRole('heading', { level: 1, name: '3 new incidents' })).toBeInTheDocument()
    const table = await screen.findByRole('table', { name: 'Incidents' })
    expect(within(table).getAllByRole('row')).toHaveLength(5)
    expect(within(table).getByRole('link', { name: 'PC-HR-01 touched the SMB trap on FILESRV-OLD' })).toHaveAttribute('href', '/incidents/al-4')
    expect(within(table).getByRole('link', { name: 'PC-HR-01' })).toHaveAttribute('href', '/devices/a-pc07')
    expect(within(table).getByText('Internal trap touched')).toBeInTheDocument()
    expect(within(table).getByText('Connection to a known-bad address')).toBeInTheDocument()
    expect(within(table).getByText('Log anomaly')).toBeInTheDocument()
    expect(within(table).getByText('14×')).toBeInTheDocument()
    expect(within(table).getByText('Email failed')).toBeInTheDocument()
    expect(within(table).getAllByText(/^Telegram \d\d:\d\d$/).length).toBeGreaterThan(0)
    expect(screen.queryByText('QNAP Photo Station')).not.toBeInTheDocument()
    expect(within(table).queryByText(/Vulnerabilit/)).not.toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('every row has a Respond link carrying the incident id', async () => {
    renderApp('/incidents')
    const table = await screen.findByRole('table', { name: 'Incidents' })
    expect(within(table).getByRole('link', { name: 'Respond to PC-HR-01 touched the SMB trap on FILESRV-OLD' })).toHaveAttribute('href', '/response?incident=al-4')
  })

  it('the All filter also shows resolved and acknowledged incidents; the kind filter narrows', async () => {
    renderApp('/incidents')
    await screen.findByRole('table', { name: 'Incidents' })
    expect(screen.queryByText(/192\.168\.10\.157 touched/)).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /^All$/ }))
    expect(await screen.findByText('192.168.10.157 touched the RDP trap on FILESRV-OLD')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Trap touches' }))
    expect(within(screen.getByRole('table', { name: 'Incidents' })).getAllByRole('row')).toHaveLength(3)
  })

  it('a blocked connection (D-227) is said as an attempt in the list and the detail (walk 3)', async () => {
    const one = { id: 'in-a', kind: 'bad_address', attempt: true, link: '/logs', title: '192.168.1.50 tried to reach 185.220.101.47 (blocked by FW-HQ), which a threat feed lists', devices: [], severity: 'high', what: 'w', action: 'a',
      first_seen: '2026-11-12T08:00:00.000Z', last_seen: '2026-11-12T08:00:00.000Z', count: 1, status: 'new', handled_by: null, handled_at: null, note: null, sends: [] }
    server.use(http.get('*/api/v1/notify/incidents', () => HttpResponse.json({ incidents: [one] })),
      http.get('*/api/v1/notify/incidents/in-a', () => HttpResponse.json({ incident: one, previews: [] })))
    renderApp('/incidents')
    const table = await screen.findByRole('table', { name: 'Incidents' })
    expect(within(table).getByText('Attempt to reach a known-bad address')).toBeInTheDocument()
    expect(within(table).queryByText('Connection to a known-bad address')).toBeNull()
    await userEvent.click(within(table).getByRole('link', { name: one.title }))
    expect(await screen.findByRole('heading', { level: 1, name: one.title })).toBeInTheDocument()
    expect(screen.getByText('Attempt to reach a known-bad address')).toBeInTheDocument()
  })

  it('container-only: no "Trap touches" filter, since the honeypot cannot run on this install (D-381, walk 3)', async () => {
    installStore.set({ kind: 'container' })
    try {
      renderApp('/incidents')
      await screen.findByRole('table', { name: 'Incidents' })
      expect(await screen.findByRole('button', { name: 'Bad addresses' })).toBeInTheDocument()
      await waitFor(() => expect(screen.queryByRole('button', { name: 'Trap touches' })).toBeNull())
    } finally { installStore.set({ kind: 'appliance' }) }
  })

  it('detail: what happened, first and last seen, count, who responded; message text per channel; Respond link', async () => {
    renderApp('/incidents/al-4')
    expect(await screen.findByRole('heading', { level: 1, name: 'PC-HR-01 touched the SMB trap on FILESRV-OLD' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Respond' })).toHaveAttribute('href', '/response?incident=al-4')
    expect(screen.getByRole('link', { name: 'Open trap touch' })).toHaveAttribute('href', '/honeypot/hits/hit-seed-1')
    expect(screen.getByRole('link', { name: 'PC-HR-01' })).toHaveAttribute('href', '/devices/a-pc07')
    expect(screen.getByText('Times seen')).toBeInTheDocument()
    expect(screen.getByText('3×')).toBeInTheDocument()
    const tg = await screen.findByRole('figure', { name: 'Telegram' })
    expect(tg).toHaveTextContent('Critical: PC-HR-01 touched the SMB trap on FILESRV-OLD')
    expect(tg).toHaveTextContent('Device: PC-HR-01 (192.168.10.107)')
    expect(tg).toHaveTextContent('What to do first: Take the machine off the network')
    expect(tg).toHaveTextContent('https://192.168.10.250/incidents/al-4')
    expect(screen.queryByText('Vulnerability IDs')).not.toBeInTheDocument()
    expect(within(screen.getByRole('table', { name: 'Delivery log of the incident' })).getAllByText('Sent')).toHaveLength(1)
    await expectNoA11yViolations()
  })

  it('bad-address detail shows the failed email with the reason', async () => {
    renderApp('/incidents/al-6')
    expect(await screen.findByRole('link', { name: 'Open related logs' })).toHaveAttribute('href', '/logs')
    expect(within(screen.getByRole('table', { name: 'Delivery log of the incident' })).getByText(/The SMTP server rejected the login/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('tab', { name: 'Email' }))
    expect(await screen.findByRole('figure', { name: 'Email' })).toHaveTextContent('Subject: [Vedette] High: PC-SALES-02 connected to 185.220.101.47')
  })

  it('acknowledge, then resolve with a note, then reopen', async () => {
    renderApp('/incidents/al-4', { role: 'operator' })
    await press('Acknowledge')
    expect(await screen.findByText(/Acknowledged by it@acme\.example/)).toBeInTheDocument()
    await userEvent.type(await screen.findByLabelText('Note (optional)'), 'Machine is clean')
    await press('Resolve')
    expect(await screen.findByText(/Resolved by it@acme\.example/)).toBeInTheDocument()
    expect(screen.getByText(/Note: Machine is clean/)).toBeInTheDocument()
    expect(auditStore.get().some((e) => e.action === 'notify.incident_status' && e.detail?.includes('resolved'))).toBe(true)
    await userEvent.click(screen.getByRole('button', { name: 'Reopen' }))
    expect(await screen.findByRole('button', { name: 'Acknowledge' })).toBeInTheDocument()
  })

  it('a viewer can read but not acknowledge or resolve', async () => {
    renderApp('/incidents/al-4', { role: 'viewer' })
    expect(await screen.findByRole('button', { name: 'Acknowledge' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Resolve' })).toBeDisabled()
    const res = await fetch(`${location.origin}/api/v1/notify/incidents/al-4`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ status: 'resolved' }) })
    expect(res.status).toBe(403)
  })

  it('a viewer does not ask for the alert channels (403 in the console)', async () => {
    const real = globalThis.fetch
    const asked: string[] = []
    const spy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => { asked.push(String(input instanceof Request ? input.url : input)); return real(input, init) })
    renderApp('/incidents', { role: 'viewer' })
    await screen.findByRole('heading', { level: 1 })
    expect(asked.filter((x) => x.includes('/notify/channels'))).toEqual([])
    spy.mockRestore()
  })

  it('an unknown incident says so', async () => {
    renderApp('/incidents/al-zzz')
    expect(await screen.findByText(/No such incident/)).toBeInTheDocument()
  })

  it('no open incidents: the empty state shows what to do, and the channel link only while no channel is on', async () => {
    const channels = (enabled: boolean) => http.get('*/api/v1/notify/channels', () => HttpResponse.json({ channels: [{ type: 'webhook', configured: enabled, enabled, fields: {} }], quiet: {}, grouping: {}, email_code_users: 0 }))
    server.use(http.get('*/api/v1/notify/incidents', () => HttpResponse.json({ incidents: [] })), channels(false))
    const view = renderApp('/incidents')
    expect(await screen.findByRole('heading', { level: 1, name: 'No new incidents' })).toBeInTheDocument()
    expect(await screen.findByRole('link', { name: 'Set up alert channels' })).toHaveAttribute('href', '/settings/channels')
    view.unmount()
    server.use(channels(true))
    renderApp('/incidents')
    expect(await screen.findByRole('heading', { level: 1, name: 'No new incidents' })).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByRole('link', { name: 'Set up alert channels' })).toBeNull())
  })

  it('container-only: the empty state does not promise trap touches (the honeypot cannot run there)', async () => {
    server.use(http.get('*/api/v1/notify/incidents', () => HttpResponse.json({ incidents: [] })))
    installStore.set({ kind: 'container' })
    try {
      renderApp('/incidents')
      expect(await screen.findByText(/^When a machine connects to a known-bad address/)).toBeInTheDocument()
      expect(screen.queryByText(/When a trap is touched/)).toBeNull()
    } finally { installStore.set({ kind: 'appliance' }) }
  })

  it('an API error shows the message and a retry button', async () => {
    server.use(http.get('*/api/v1/notify/incidents', () => HttpResponse.json({ error: { code: 'x', message: 'The incident list could not be read.' } }, { status: 500 })))
    renderApp('/incidents')
    expect(await screen.findByText('The incident list could not be read.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument()
  })

  it('notify module off: says where to turn it on', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'notify' ? { ...m, enabled: false } : m)))
    renderApp('/incidents')
    expect(await screen.findByText(/module is off/)).toBeInTheDocument()
  })

  it('the incident list holds no vulnerability kind', async () => {
    const res = await getJsonAfterLogin('/notify/incidents')
    for (const i of res.incidents as { kind: string }[]) expect(['trap', 'bad_address', 'log_anomaly', 'unknown_device']).toContain(i.kind)
  })
})

describe('notify: old /alerts links (D-52)', () => {
  it('/alerts goes to /incidents', async () => {
    renderApp('/alerts')
    expect(await screen.findByRole('table', { name: 'Incidents' })).toBeInTheDocument()
  })
  it('/alerts/:id of an incident goes to the incident', async () => {
    renderApp('/alerts/al-4')
    expect(await screen.findByRole('heading', { level: 1, name: /touched the SMB trap/ })).toBeInTheDocument()
  })
  it('/alerts/:id of an old vulnerability alert goes to the finding', async () => {
    const res = await getJsonAfterLogin('/notify/alerts/al-1/target')
    expect(res.to).toBe('/findings/f-1')
  })
})

describe('notify: vulnerability notices on the finding (S-ALERT-1)', () => {
  it('the finding shows where it was sent and a failure with its reason', async () => {
    renderApp('/findings/f-2')
    expect(await screen.findByText(/Notified: Telegram \d\d:\d\d, Email \(failed: The SMTP server rejected the login/)).toBeInTheDocument()
  })
  it('a finding that was never notified shows no panel', async () => {
    const res = await getJsonAfterLogin('/notify/findings/f-zzz/notices')
    expect(res.sends).toEqual([])
  })
})

describe('notify: delivery history (S-NOT-1, D-52)', () => {
  it('Settings, Alert channels lists every message of every kind, with the meta line', async () => {
    renderChannels()
    const table = await screen.findByRole('table', { name: 'Sent messages' })
    expect(within(table).getAllByText('Incident').length).toBeGreaterThan(0)
    expect(within(table).getAllByText('Vulnerability').length).toBeGreaterThan(0)
    expect(within(table).getByText('Approval request')).toBeInTheDocument()
    expect(screen.getByText(/Vedette only alerts for products you own/)).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('Send again repeats a failed message and adds a row', async () => {
    renderChannels()
    const table = await screen.findByRole('table', { name: 'Sent messages' })
    const before = within(table).getAllByRole('row').length
    const btn = within(table).getAllByRole('button', { name: 'Send again via Email' })[0]!
    await waitFor(() => expect(btn).toBeEnabled())
    await userEvent.click(btn)
    await waitFor(() => expect(within(screen.getByRole('table', { name: 'Sent messages' })).getAllByRole('row').length).toBe(before + 1))
    expect(auditStore.get().some((e) => e.action === 'notify.resend')).toBe(true)
  })

  it('nothing skipped (a box with no device, walk 2): the meta line says only what the count proves, and that the first download is not counted (walk 3)', async () => {
    server.use(http.get('*/api/v1/notify/history', () => HttpResponse.json({ items: [], suppressed: { count: 0, days: 7 } })))
    renderChannels()
    expect(await screen.findByText('Vedette only alerts for products you own. In the last 7 days no new vulnerability was skipped for matching none of your devices. The first download of the vulnerability lists is not counted.')).toBeInTheDocument()
    expect(screen.queryByText(/already has a notice/)).toBeNull()
  })
})

describe('notify: retention is published (D-160, D-215)', () => {
  it('the Incidents page and the History screen say history and resolved incidents are kept for 1 year', async () => {
    const inc = renderApp('/incidents')
    expect(await screen.findByText(/History and resolved incidents are kept for 1 year\./)).toBeInTheDocument()
    inc.unmount()
    renderChannels() // the History screen is a section of Settings, Alert channels
    expect(await screen.findByText(/History and resolved incidents are kept for 1 year\./)).toBeInTheDocument()
  })
})

describe('notify: alert channels (S-NOT-1)', () => {
  it('lists 6 channels with their status, no a11y violations', async () => {
    renderChannels()
    const table = await screen.findByRole('table', { name: 'Alert channels' })
    expect(within(table).getAllByRole('row')).toHaveLength(7)
    expect(within(table).getAllByText('On')).toHaveLength(3)
    expect(within(table).getAllByText('Not set up')).toHaveLength(3)
    expect(screen.getByText(/leaves the box only to the channels you turn on here/)).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('the API never returns a full secret, only the last 4 characters', async () => {
    renderChannels()
    await screen.findByRole('table', { name: 'Alert channels' })
    const res = await getJson('/notify/channels')
    const tg = (res.channels as { type: string; secret_last4: string }[]).find((c) => c.type === 'telegram')!
    expect(tg.secret_last4).toBe('0000')
    expect(JSON.stringify(res)).not.toContain('EXAMPLE_not_a_real')
    expect(JSON.stringify(res)).not.toContain('MatKhauMau')
  })

  it('set up Telegram: a wrong token is refused, a right one is saved with only the last 4 characters shown, then a test is sent', async () => {
    renderChannels()
    await press('Edit Telegram')
    const dlg = await screen.findByRole('dialog', { name: 'Channel Telegram' })
    const secret = within(dlg).getByLabelText('Bot token')
    expect(secret).toHaveAttribute('type', 'password')
    expect(within(dlg).getByText('Saved, ending in 0000. Leave empty to keep it.')).toBeInTheDocument()
    await userEvent.type(secret, 'not-a-token')
    await userEvent.click(within(dlg).getByRole('button', { name: /^Save$/ }))
    await waitFor(() => expect(secret).toHaveAccessibleDescription(/A bot token looks like 123456789:AAH/))
    await userEvent.clear(secret)
    await userEvent.type(secret, TOKEN)
    await userEvent.click(within(dlg).getByRole('button', { name: /^Save$/ }))
    expect((await screen.findAllByText('Channel Telegram saved.')).length).toBeGreaterThan(0)
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    const tg = ((await getJson('/notify/channels')).channels as { type: string; secret_last4: string }[]).find((c) => c.type === 'telegram')!
    expect(tg.secret_last4).toBe(TOKEN.slice(-4))
    await userEvent.click(screen.getByRole('button', { name: 'Send test Telegram' }))
    expect((await screen.findAllByText(/Telegram received the test message/)).length).toBeGreaterThan(0)
    expect(auditStore.get().some((e) => e.action === 'notify.channel_test' && e.target === 'telegram')).toBe(true)
  })

  it('Zalo OA: the access token is required on first save, a full form can be turned on', async () => {
    renderChannels()
    await press('Set up Zalo OA')
    const dlg = await screen.findByRole('dialog', { name: 'Channel Zalo OA' })
    await userEvent.type(within(dlg).getByLabelText('OA ID'), '12345')
    await userEvent.click(within(dlg).getByRole('button', { name: /^Save$/ }))
    await waitFor(() => expect(within(dlg).getByLabelText('OA ID')).toHaveAccessibleDescription(/OA ID is a string of digits/))
    await userEvent.clear(within(dlg).getByLabelText('OA ID'))
    await userEvent.type(within(dlg).getByLabelText('OA ID'), '1234567890')
    await userEvent.click(within(dlg).getByRole('button', { name: /^Save$/ }))
    await waitFor(() => expect(within(dlg).getByLabelText('Recipient ID (user_id)')).toHaveAccessibleDescription(/Zalo recipient ID \(user_id\)/))
    await userEvent.type(within(dlg).getByLabelText('Recipient ID (user_id)'), '2468013579')
    await userEvent.click(within(dlg).getByRole('button', { name: /^Save$/ }))
    await waitFor(() => expect(within(dlg).getByLabelText('Access token')).toHaveAccessibleDescription(/Enter the access token/))
    expect(within(dlg).queryByRole('alert')).toBeNull()
    await userEvent.type(within(dlg).getByLabelText('Access token'), 'zalo-access-token-0123456789-abcdef')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Save and send test' }))
    expect((await screen.findAllByText(/Zalo OA 1234567890 sent the test message to recipient 2468013579/)).length).toBeGreaterThan(0)
    const z = ((await getJson('/notify/channels')).channels as { type: string; configured: boolean; secret_last4: string }[]).find((c) => c.type === 'zalo')!
    expect(z).toMatchObject({ configured: true, secret_last4: 'cdef' })
  })

  it('SMTP email: recipients are checked at the boundary', async () => {
    renderChannels()
    await press('Edit Email')
    const dlg = await screen.findByRole('dialog', { name: 'Channel Email' })
    const to = within(dlg).getByLabelText('Send to')
    await userEvent.clear(to)
    await userEvent.type(to, 'it@acme.example, not-an-email')
    await userEvent.click(within(dlg).getByRole('button', { name: /^Save$/ }))
    await waitFor(() => expect(to).toHaveAccessibleDescription('not-an-email is not a valid email address. Separate several recipients with commas.'))
    expect(to).toHaveAttribute('aria-invalid', 'true')
  })

  it('SMTP email: the server cannot be Vedette itself (in a container 127.0.0.1 is Vedette), as for a webhook (walk 3, D-446)', async () => {
    renderChannels()
    await press('Edit Email')
    const dlg = await screen.findByRole('dialog', { name: 'Channel Email' })
    const host = within(dlg).getByLabelText('SMTP server')
    await userEvent.clear(host)
    await userEvent.type(host, '127.0.0.1')
    await userEvent.click(within(dlg).getByRole('button', { name: /^Save$/ }))
    await waitFor(() => expect(host).toHaveAccessibleDescription(/^That address is Vedette itself: .* enter the machine's LAN address and that program's port\.$/))
  })

  it('server refusals of the other types show under the field the code names; a code that fits several fields stays at the top (deferred walk 2)', async () => {
    renderChannels()
    await press('Edit Telegram')
    const tg = await screen.findByRole('dialog', { name: 'Channel Telegram' })
    const chat = within(tg).getByLabelText('Chat ID')
    await userEvent.clear(chat)
    await userEvent.type(chat, 'abc')
    await userEvent.click(within(tg).getByRole('button', { name: /^Save$/ }))
    await waitFor(() => expect(chat).toHaveAccessibleDescription(/Chat ID is a number/)) // bad_chat_id
    expect(chat).toHaveAttribute('aria-invalid', 'true')
    expect(within(tg).queryByRole('alert')).toBeNull()
    await userEvent.type(chat, '1')
    expect(chat).not.toHaveAttribute('aria-invalid')
    await userEvent.click(within(tg).getByRole('button', { name: 'Cancel' }))
    // Slack secret_required can be the webhook URL or either app token: the message says which, at the top
    const APP = 'Enter the app-level token (xapp-…). Approving in Slack needs Socket Mode.'
    server.use(http.put('*/api/v1/notify/channels/slack', () => HttpResponse.json({ error: { code: 'secret_required', message: APP } }, { status: 400 })))
    await press('Edit Slack')
    const sl = await screen.findByRole('dialog', { name: 'Channel Slack' })
    await userEvent.click(within(sl).getByRole('button', { name: /^Save$/ }))
    expect(await within(sl).findByRole('alert')).toHaveTextContent(APP)
    expect(within(sl).getByLabelText('Incoming Webhook URL')).not.toHaveAttribute('aria-invalid')
  })

  it('webhook: a saved URL the box cannot read (400 url_unreadable) shows under the URL, not the signing key', async () => {
    // only the box answers it (a sealed URL that cannot be opened): the mock keeps the URL in clear
    const MSG = 'The saved webhook URL cannot be read. Enter it again and save.'
    server.use(http.put('*/api/v1/notify/channels/webhook', () => HttpResponse.json({ error: { code: 'url_unreadable', message: MSG } }, { status: 400 })))
    renderChannels()
    await press('Set up Webhook')
    const dlg = await screen.findByRole('dialog', { name: 'Channel Webhook' })
    const url = within(dlg).getByLabelText('Webhook URL')
    await userEvent.type(url, 'https://hooks.company.example/vedette')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Generate random' }))
    await userEvent.click(within(dlg).getByRole('button', { name: /^Save$/ }))
    await waitFor(() => expect(url).toHaveAccessibleDescription(MSG))
    expect(url).toHaveAttribute('aria-invalid', 'true')
    expect(within(dlg).getByLabelText('Signing key')).not.toHaveAttribute('aria-invalid')
    expect(within(dlg).queryByRole('alert')).toBeNull()
  })

  it('SMTP email: the port follows the encryption; leaving SSL/TLS drops 465 for 587 (QA walk b)', async () => {
    renderChannels()
    await press('Edit Email')
    const dlg = await screen.findByRole('dialog', { name: 'Channel Email' })
    const enc = within(dlg).getByLabelText('Encryption')
    const port = within(dlg).getByLabelText('Port')
    await userEvent.selectOptions(enc, 'ssl')
    expect(port).toHaveValue(465)
    await userEvent.selectOptions(enc, 'none')
    expect(port).toHaveValue(587)
    await userEvent.clear(port)
    await userEvent.type(port, '2525')
    await userEvent.selectOptions(enc, 'ssl')
    expect(port).toHaveValue(2525)
  })

  it('webhook: generate a random key and save; an unreachable host makes the test fail with advice', async () => {
    renderChannels()
    await press('Set up Webhook')
    const dlg = await screen.findByRole('dialog', { name: 'Channel Webhook' })
    await userEvent.type(within(dlg).getByLabelText('Webhook URL'), 'https://hooks.khong-co.invalid/vedette')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Generate random' }))
    expect((within(dlg).getByLabelText('Signing key') as HTMLInputElement).value).toMatch(/^[0-9a-f]{48}$/)
    await userEvent.click(within(dlg).getByRole('button', { name: 'Save and send test' }))
    expect((await screen.findAllByText(/Could not connect to hooks\.khong-co\.invalid/)).length).toBeGreaterThan(0)
    await press('Send test Webhook')
    expect(await screen.findByText(/Tested .*: failed/)).toBeInTheDocument()
  })

  it('webhook (walk 2): the help names both signed headers; a bad URL and a short key show at once, each under its field, before anything is sent', async () => {
    let puts = 0
    server.use(http.put('*/api/v1/notify/channels/webhook', () => { puts++ })) // counts, then falls through to the mock
    renderChannels()
    await press('Set up Webhook')
    const dlg = await screen.findByRole('dialog', { name: 'Channel Webhook' })
    const url = within(dlg).getByLabelText('Webhook URL')
    const key = within(dlg).getByLabelText('Signing key')
    expect(key).toHaveAccessibleDescription(/X-Vedette-Timestamp .*X-Vedette-Signature \(sha256=<hex>\)\. The hex is HMAC-SHA256 with this key over the timestamp, a dot and the raw body/)
    await userEvent.click(url)
    await userEvent.paste('http://example.com/hook')
    await userEvent.click(key)
    await userEvent.paste('short')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Save' }))
    expect(url).toHaveAttribute('aria-invalid', 'true')
    expect(url).toHaveAccessibleDescription('Plain http:// is only allowed for hosts on your internal network. Use https:// for this address.')
    expect(key).toHaveAttribute('aria-invalid', 'true')
    expect(key).toHaveAccessibleDescription('The signing key needs at least 16 characters. Press Generate random if you want a random one.')
    expect(within(dlg).queryByRole('alert')).toBeNull()
    expect(puts).toBe(0)
    await userEvent.type(url, 's', { initialSelectionStart: 4, initialSelectionEnd: 4 }) // http -> https
    expect(url).not.toHaveAttribute('aria-invalid')
    expect(key).toHaveAttribute('aria-invalid', 'true')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Generate random' }))
    expect(key).not.toHaveAttribute('aria-invalid')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Save' }))
    expect((await screen.findAllByText('Channel Webhook saved.')).length).toBeGreaterThan(0)
    expect(puts).toBe(1)
  })

  it('webhook: a URL the box refuses (bad_url) shows under the URL field, not at the top', async () => {
    const BLOCKED = "That address is Vedette itself: loopback, Vedette's own container, or one of its ports (8443, 8444, 8765, 514, 6514) on the machine that runs it. For another program on that machine, enter the machine's LAN address and that program's port."
    server.use(http.put('*/api/v1/notify/channels/webhook', () => HttpResponse.json({ error: { code: 'bad_url', message: BLOCKED } }, { status: 400 })))
    renderChannels()
    await press('Set up Webhook')
    const dlg = await screen.findByRole('dialog', { name: 'Channel Webhook' })
    const url = within(dlg).getByLabelText('Webhook URL')
    await userEvent.click(url)
    await userEvent.paste('http://127.0.0.1/h')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Generate random' }))
    await userEvent.click(within(dlg).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(url).toHaveAccessibleDescription(BLOCKED))
    expect(url).toHaveAttribute('aria-invalid', 'true')
    expect(within(dlg).queryByRole('alert')).toBeNull()
  })

  it('webhook (walk 3 G13): a link-local / cloud metadata URL over http gets the precise sentence, not the http rule, before anything is sent', async () => {
    let puts = 0
    server.use(http.put('*/api/v1/notify/channels/webhook', () => { puts++ }))
    renderChannels()
    await press('Set up Webhook')
    const dlg = await screen.findByRole('dialog', { name: 'Channel Webhook' })
    const url = within(dlg).getByLabelText('Webhook URL')
    await userEvent.click(url)
    await userEvent.paste('http://169.254.169.254/latest')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Generate random' }))
    await userEvent.click(within(dlg).getByRole('button', { name: 'Save' }))
    expect(url).toHaveAccessibleDescription('The webhook cannot point at a link-local or multicast address, a cloud metadata service, or an unspecified address.')
    expect(puts).toBe(0)
  })

  it('Send test (walk 3 G13): while the box waits for the far end, the row says the test is running', async () => {
    let answer!: () => void
    const held = new Promise<void>((r) => { answer = r })
    server.use(http.post('*/api/v1/notify/channels/telegram/test', async () => {
      await held
      return HttpResponse.json({ at: new Date().toISOString(), ok: false, detail: 'The server did not answer in time.' })
    }))
    renderChannels()
    await press('Send test Telegram')
    expect(await within(screen.getByRole('table', { name: 'Alert channels' })).findByText('Sending test…')).toBeInTheDocument()
    answer()
    await waitFor(() => expect(screen.queryByText('Sending test…')).toBeNull())
  })

  it('Send test (walk 3 G13): a failed last test is shown as text with the reason and an "on but failed" hint', async () => {
    renderChannels()
    await press('Set up Webhook')
    const dlg = await screen.findByRole('dialog', { name: 'Channel Webhook' })
    await userEvent.type(within(dlg).getByLabelText('Webhook URL'), 'https://hooks.khong-co.invalid/vedette')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Generate random' }))
    await userEvent.click(within(dlg).getByRole('button', { name: 'Save and send test' }))
    const table = screen.getByRole('table', { name: 'Alert channels' })
    expect(await within(table).findByText(/Could not connect to hooks\.khong-co\.invalid/)).toBeVisible()
    expect(within(table).getByText(/The channel is on, but its last test failed/)).toBeInTheDocument()
  })

  it('narrow screen (walk 3 G13): each channel is a card with its Set up / Edit / Send test / Remove buttons in it', async () => {
    vi.stubGlobal('matchMedia', (q: string) => ({ matches: q.includes('max-width'), media: q, addEventListener: () => {}, removeEventListener: () => {} }))
    try {
      renderChannels()
      const list = await screen.findByRole('list', { name: 'Alert channels' })
      expect(screen.queryByRole('table', { name: 'Alert channels' })).toBeNull()
      expect(within(list).getByRole('button', { name: 'Set up Webhook' })).toBeInTheDocument()
      expect(within(list).getByRole('button', { name: 'Send test Telegram' })).toBeInTheDocument()
      expect(within(list).getByRole('button', { name: 'Remove channel Telegram' })).toBeInTheDocument()
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('webhook URL is a secret (SYS-4): only scheme://host/… and its last 4 characters come back, and an empty URL keeps it', async () => {
    const first = renderChannels()
    await screen.findByRole('table')
    const put = (b: unknown) => fetch(`${location.origin}/api/v1/notify/channels/webhook`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) })
    const token = ['tok', 'path', '7f3a9c'].join('-')
    const base = { enabled: true, min_severity: 'low', secret: 'abcdefgh-1234567890' }
    const saved = await (await put({ ...base, fields: { url: `https://hooks.acme.example/vedette/${token}?key=9f8e` } })).json() as { fields: Record<string, string> }
    expect(saved.fields.url).toBe('https://hooks.acme.example/…9f8e')
    const webhook = async () => ((await getJson('/notify/channels')).channels as { type: string; fields: Record<string, string> }[]).find((c) => c.type === 'webhook')!
    expect(JSON.stringify(await webhook())).not.toContain(token)
    // an empty URL, or the masked one the API showed, keeps the saved one; nothing else is saved
    expect((await put({ ...base, secret: undefined, fields: { url: '' } })).status).toBe(200)
    expect((await put({ ...base, secret: undefined, fields: { url: saved.fields.url } })).status).toBe(200)
    expect((await webhook()).fields.url).toBe('https://hooks.acme.example/…9f8e')
    // the dialog starts with an empty URL field and says what is saved
    first.unmount()
    renderChannels()
    await press('Edit Webhook')
    const dlg = await screen.findByRole('dialog', { name: 'Channel Webhook' })
    expect(within(dlg).getByLabelText('Webhook URL')).toHaveValue('')
    expect(within(dlg).getByText(/Saved: https:\/\/hooks\.acme\.example\/…9f8e\./)).toBeInTheDocument()
    expect(dlg.textContent).not.toContain(token)
  })

  it('removing a channel also deletes its saved key', async () => {
    renderChannels()
    await press('Remove channel Email')
    const dlg = await screen.findByRole('dialog', { name: 'Remove channel Email?' })
    await userEvent.click(within(dlg).getByRole('button', { name: 'Delete' }))
    await waitFor(async () => {
      const em = ((await getJson('/notify/channels')).channels as { type: string; configured: boolean; secret_last4: string | null }[]).find((c) => c.type === 'email')!
      expect(em).toMatchObject({ configured: false, secret_last4: null })
    })
  })

  it('two-step email codes: the channels API counts the users; turning the email channel off or removing it warns first', async () => {
    const setCodeUsers = (ids: string[]) => usersStore.update((l) => l.map((x) => (ids.includes(x.id) ? { ...x, twofa: true, twofa_method: 'email' as const } : x)))
    expect((await getJsonAfterLogin('/notify/channels')).email_code_users).toBe(0)
    setCodeUsers(['u-op', 'u-view'])
    expect((await getJsonAfterLogin('/notify/channels')).email_code_users).toBe(2)
    renderChannels()
    // turn the email channel off in the edit dialog: a confirm names the count; "Keep editing" changes nothing
    await press('Edit Email')
    const dlg = await screen.findByRole('dialog', { name: 'Channel Email' })
    await userEvent.click(within(dlg).getByRole('switch', { name: 'Turn this channel on' }))
    await userEvent.click(within(dlg).getByRole('button', { name: /^Save$/ }))
    const warn = await screen.findByRole('dialog', { name: 'Turn off the email channel?' })
    expect(warn).toHaveTextContent('2 users sign in with email codes. They will not be able to sign in until this channel is back on or an administrator resets their two-step sign-in.')
    await userEvent.click(within(warn).getByRole('button', { name: 'Keep editing' }))
    expect(((await getJson('/notify/channels')).channels as { type: string; enabled: boolean }[]).find((c) => c.type === 'email')!.enabled).toBe(true)
    await userEvent.click(within(dlg).getByRole('button', { name: /^Save$/ }))
    await userEvent.click(within(await screen.findByRole('dialog', { name: 'Turn off the email channel?' })).getByRole('button', { name: 'Turn off anyway' }))
    await waitFor(async () => expect(((await getJson('/notify/channels')).channels as { type: string; enabled: boolean }[]).find((c) => c.type === 'email')!.enabled).toBe(false))
  })

  it('removing the email channel names the affected user (singular); no warning when nobody uses email codes', async () => {
    renderChannels()
    await press('Remove channel Email')
    const none = await screen.findByRole('dialog', { name: 'Remove channel Email?' })
    expect(within(none).queryByRole('alert')).not.toBeInTheDocument()
  })

  it('removing the email channel with one email-code user shows the warning in the dialog', async () => {
    usersStore.update((l) => l.map((x) => (x.id === 'u-op' ? { ...x, twofa: true, twofa_method: 'email' as const } : x)))
    renderChannels()
    await press('Remove channel Email')
    const dlg = await screen.findByRole('dialog', { name: 'Remove channel Email?' })
    expect(within(dlg).getByRole('alert')).toHaveTextContent('1 user signs in with email codes. They will not be able to sign in until this channel is back on or an administrator resets their two-step sign-in.')
  })

  it('save quiet hours and grouping; identical times are refused', async () => {
    renderChannels()
    await screen.findByRole('table', { name: 'Alert channels' })
    await waitFor(() => expect(screen.getByLabelText('Until')).toBeEnabled())
    const to = screen.getByLabelText('Until')
    await userEvent.clear(to)
    await userEvent.type(to, '22:00')
    await userEvent.click(screen.getByRole('button', { name: 'Save quiet hours and grouping' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('The start and end times must not be the same')
    await userEvent.clear(to)
    await userEvent.type(to, '07:00')
    await userEvent.selectOptions(screen.getByLabelText('Grouping window'), '240')
    await userEvent.click(screen.getByRole('button', { name: 'Save quiet hours and grouping' }))
    expect((await screen.findAllByText('Quiet hours and grouping saved.')).length).toBeGreaterThan(0)
    const res = await getJson('/notify/channels')
    expect(res.quiet).toMatchObject({ from: '22:00', to: '07:00', allow_critical: true })
    expect(res.grouping).toMatchObject({ window_min: 240 })
  })

  it('an operator cannot read channel settings (admins only)', async () => {
    renderChannels('operator')
    expect(await screen.findByText('Your account is not allowed to do this.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Set up|Edit/ })).not.toBeInTheDocument()
  })

  it('an API error shows the message and a retry button', async () => {
    server.use(http.get('*/api/v1/notify/channels', () => HttpResponse.json({ error: { code: 'x', message: 'The channel settings could not be read.' } }, { status: 500 })))
    renderChannels()
    expect(await screen.findByText('The channel settings could not be read.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument()
  })
})

async function getJsonAfterLogin(path: string) {
  sessionStore.set({ userId: 'u-admin' })
  return getJson(path)
}

describe('notify: forbidden webhook hosts match the box (forbiddenAddr after Unmap; G13 review L1, L5)', () => {
  it('only IP literals and localhost names are judged; an IPv4-mapped IPv6 loopback is forbidden too', () => {
    const host = (u: string) => new URL(u).hostname
    for (const u of ['https://127.0.0.1/x', 'http://169.254.169.254/latest', 'https://0.0.0.0/', 'https://224.0.0.251/', 'https://[::1]/', 'https://[::]/', 'https://[fe80::1]/', 'https://[ff02::1]/', 'http://[::ffff:127.0.0.1]/', 'https://[::ffff:169.254.1.1]/', 'https://localhost/', 'https://app.localhost./',
      'https://100.100.100.200/latest', 'https://192.0.0.192/', 'https://[fd00:ec2::254]/', 'https://[fd20:ce::254]/', 'http://metadata.google.internal/x', 'https://METADATA.goog/', 'https://[::ffff:100.100.100.200]/'])
      expect(forbiddenHost(host(u)), u).toBe(true)
    for (const u of ['https://224.alerts.example.com/hook', 'https://127.corp.example/x', 'https://169.254.example.net/', 'https://8.8.8.8/', 'https://10.0.0.5/', 'https://[2001:db8::1]/', 'https://[::ffff:10.0.0.1]/', 'https://hooks.company.com/', 'https://100.100.100.201/', 'https://[fd00:ec2::253]/', 'https://metadata.company.com/'])
      expect(forbiddenHost(host(u)), u).toBe(false)
    // D-446: the page names Vedette itself apart (loopback, localhost names); everything else forbidden gets the other sentence
    for (const u of ['https://127.0.0.1/x', 'https://127.8.9.10/x', 'https://[::1]/', 'http://[::ffff:127.0.0.1]/', 'https://localhost/', 'https://app.localhost./']) expect(ownHost(host(u)), u).toBe(true)
    for (const u of ['http://169.254.169.254/latest', 'https://[::]/', 'https://[::ffff:169.254.1.1]/', 'https://10.0.0.5/', 'https://127.corp.example/x']) expect(ownHost(host(u)), u).toBe(false)
  })
})

describe('notify: channel form matrix (docs/QA.md §2)', () => {
  const ALL = ['Chat ID', 'Bot token', 'OA ID', 'Access token', 'Recipient ID (user_id)', 'SMTP server', 'Port', 'Encryption', 'Username', 'Send from', 'Send to', 'SMTP password', 'Webhook URL', 'Signing key', 'Channel label (optional)', 'Incoming Webhook URL', 'Channel ID', 'App-level token (xapp-…)', 'Bot token (xoxb-…)', 'Recipient (user or group ID)']
  const only = (...keep: string[]) => ALL.filter((x) => !keep.includes(x))
  const APPROVE = 'Approve actions from this channel'
  const LINK_ONLY = /This channel cannot take approvals/

  it('each channel type shows only its own fields, and approvals only where the channel can take them', async () => {
    renderChannels()
    await screen.findByRole('table')
    const open = async (type: string) => {
      const prev = screen.queryByRole('dialog')
      if (prev) { await userEvent.click(within(prev).getByRole('button', { name: 'Cancel' })); await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull()) }
      await press(new RegExp(`^(Set up|Edit) ${type}$`))
      await screen.findByRole('dialog')
    }
    await eachOption([
      { option: 'Telegram', shown: ['Chat ID', 'Bot token', APPROVE], hidden: [...only('Chat ID', 'Bot token'), LINK_ONLY] },
      { option: 'Slack', shown: ['Channel label (optional)', 'Incoming Webhook URL', APPROVE], hidden: [...only('Channel label (optional)', 'Incoming Webhook URL', 'Channel ID', 'App-level token (xapp-…)', 'Bot token (xoxb-…)'), LINK_ONLY] },
      { option: 'Zalo OA', shown: ['OA ID', 'Access token', 'Recipient ID (user_id)', LINK_ONLY], hidden: [...only('OA ID', 'Access token', 'Recipient ID (user_id)'), APPROVE] },
      { option: 'Zalo personal', shown: ['Zalo sign-in', 'Or find by invite link, phone number or ID', APPROVE, /Unofficial channel/], hidden: [...only(), LINK_ONLY, 'Bot token', 'I scanned it'] },
      { option: 'Email', shown: ['SMTP server', 'Port', 'Encryption', 'Username', 'Send from', 'Send to', 'SMTP password', APPROVE], hidden: [...only('SMTP server', 'Port', 'Encryption', 'Username', 'Send from', 'Send to', 'SMTP password'), LINK_ONLY] },
      { option: 'Webhook', shown: ['Webhook URL', 'Signing key', 'Generate random', LINK_ONLY], hidden: [...only('Webhook URL', 'Signing key'), APPROVE] },
      { option: 'Telegram', shown: ['Chat ID', 'Bot token'], hidden: [...only('Chat ID', 'Bot token')] }, // going back restores the same fields
    ], open)
  })

  it('Slack: the channel ID and app tokens appear only with approvals; turning approvals off sends none of them', async () => {
    renderChannels()
    await screen.findByRole('table')
    await press(/^Edit Slack$/)
    const dlg = await screen.findByRole('dialog')
    expect(within(dlg).getByLabelText('Channel ID')).toHaveValue('C04VEDETTE1')
    await userEvent.click(within(dlg).getByRole('switch', { name: 'Approve actions from this channel' }))
    expect(within(dlg).queryByLabelText('Channel ID')).toBeNull()
    expect(within(dlg).queryByLabelText('App-level token (xapp-…)')).toBeNull()
    await userEvent.click(within(dlg).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    const slack = (await getJson('/notify/channels') as { channels: { type: string; approvals: boolean; fields: Record<string, string> }[] }).channels.find((c) => c.type === 'slack')!
    expect(slack.approvals).toBe(false)
    expect(slack.fields.channel_id).toBeUndefined()
  })

  it('the server refuses approvals on a channel that only sends a link, and a viewer as approver', async () => {
    renderChannels()
    await screen.findByRole('table')
    const put = (type: string, b: unknown) => fetch(`${location.origin}/api/v1/notify/channels/${type}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) })
    const base = { enabled: true, min_severity: 'high', approvals: true, approvers: [{ user_id: 'u-admin', address: 'x' }] }
    expect((await put('webhook', { ...base, fields: { url: 'https://hooks.example.com/x' }, secret: 'abcdefgh-1234' })).status).toBe(400)
    expect((await put('zalo', { ...base, fields: { oa_id: '1234567890', user_id: '987654' }, secret: 'abcdefgh-1234' })).status).toBe(400)
    expect((await put('telegram', { ...base, fields: { chat_id: '-100123' }, approvers: [{ user_id: 'u-view', address: '123456' }] })).status).toBe(400)
  })

  it('Zalo personal: an approver is a Zalo user ID, never a phone number, and one address is one approver (S-NOT-1, D-242)', async () => {
    renderChannels()
    await screen.findByRole('table')
    const put = (approvers: unknown) => fetch(`${location.origin}/api/v1/notify/channels/zalo-personal`, { method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: true, min_severity: 'high', fields: { user_id: '8412345678901' }, secret: 'zl-session', approvals: true, approvers }) })
    for (const phone of ['0912345678', '84912345678', '+84912345678']) {
      const res = await put([{ user_id: 'u-op', address: phone }])
      expect(res.status).toBe(400)
      const body = await res.json() as { error: { code: string; message: string } }
      expect(body.error.code).toBe('bad_approver_address')
      expect(body.error.message).toBe("it@acme.example: Enter the approver's Zalo user ID, not a phone number: a reply in Zalo carries the sender's user ID, never the phone number, so a phone number would never match. The user ID is the long number of the Zalo account, for example 2938475610293847561.")
    }
    const dup = await put([{ user_id: 'u-op', address: '2938475610293847561' }, { user_id: 'u-admin', address: ' 2938475610293847561 ' }])
    expect(dup.status).toBe(400)
    expect((await dup.json() as { error: { code: string; message: string } }).error).toEqual({ code: 'duplicate_address',
      message: 'admin@acme.example: 2938475610293847561 is already the address of it@acme.example. One address can belong to one approver only.' })
    expect((await put([{ user_id: 'u-op', address: '2938475610293847561' }, { user_id: 'u-admin', address: '3847561029384756102' }])).status).toBe(200)
  })

  it('Telegram: approvals need a numeric chat ID; a public @name is refused and the message says why (S-NOT-1)', async () => {
    renderChannels()
    await screen.findByRole('table')
    const put = (b: unknown) => fetch(`${location.origin}/api/v1/notify/channels/telegram`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) })
    const base = { enabled: true, min_severity: 'high', approvals: true, approvers: [{ user_id: 'u-admin', address: '123456789' }] }
    const res = await put({ ...base, fields: { chat_id: '@vedette_alerts' } })
    expect(res.status).toBe(400)
    const body = await res.json() as { error: { code: string; message: string } }
    expect(body.error.code).toBe('bad_chat_id')
    expect(body.error.message).toBe('To approve actions in Telegram, Chat ID must be the number of the chat (groups look like -1001234567890), not a public @channel_name: anyone can join a public channel, and a name that is given up can be taken by someone else.')
    expect((await put({ ...base, fields: { chat_id: '-1001234567890' } })).status).toBe(200)
    expect((await put({ ...base, approvals: false, approvers: [], fields: { chat_id: '@vedette_alerts' } })).status).toBe(200) // a @name is fine for alerts only
  })

  it('Zalo personal: a real QR sign-in, the recipient picked from the groups, approvers by friend or phone, Waiting then Linked (S-NOT-1, S-RESP-2, D-447)', async () => {
    renderChannels()
    await screen.findByRole('table')
    await press(/^Set up Zalo personal$/)
    const dlg = await screen.findByRole('dialog')
    expect(within(dlg).getByRole('note')).toHaveTextContent('Unofficial channel: Zalo may lock the account it signs in with')
    expect(within(dlg).getByText(/Sign in to pick from the account's groups/)).toBeInTheDocument()
    await userEvent.click(within(dlg).getByRole('button', { name: 'Sign in with a QR code' }))
    expect(await within(dlg).findByRole('img', { name: 'QR code to sign in to Zalo' })).toBeInTheDocument()
    expect(await within(dlg).findByText(/Signed in as Vedette Box\. Press Save/, undefined, { timeout: 5000 })).toBeInTheDocument()
    expect(within(dlg).queryByRole('img', { name: 'QR code to sign in to Zalo' })).toBeNull()
    const pick = await within(dlg).findByLabelText('Group or friend')
    await waitFor(() => expect(within(pick).getByRole('option', { name: 'Night shift (12 members)' })).toBeInTheDocument())
    await userEvent.selectOptions(pick, '8000000002')
    expect(within(dlg).getByText('Alerts go to the group Night shift (ID 8000000002).')).toBeInTheDocument()
    // An invite link resolves to its group; the account is not a member, which the dialog says.
    await userEvent.type(within(dlg).getByLabelText('Or find by invite link, phone number or ID'), 'https://zalo.me/g/rowukgvsyq24kacrh4ii')
    await userEvent.click(within(dlg).getAllByRole('button', { name: 'Find' })[0]!)
    expect(await within(dlg).findByText('Alerts go to the group Support group (ID 8000000009).')).toBeInTheDocument()
    expect(within(dlg).getByText(/not a member of Support group/)).toBeInTheDocument()
    await userEvent.type(within(dlg).getByLabelText('Or find by invite link, phone number or ID'), 'hello')
    await userEvent.click(within(dlg).getAllByRole('button', { name: 'Find' })[0]!)
    expect(await within(dlg).findByText(/Enter a group invite link/)).toBeInTheDocument()
    expect(within(dlg).getByLabelText('Or find by invite link, phone number or ID')).toHaveAttribute('aria-invalid', 'true')
    await userEvent.selectOptions(within(dlg).getByLabelText('Group or friend'), '8000000002')
    await userEvent.click(within(dlg).getByRole('switch', { name: APPROVE_LABEL }))
    await userEvent.click(within(dlg).getByRole('button', { name: 'Add' }))
    await userEvent.click(within(dlg).getByRole('button', { name: 'Add' }))
    const friends = within(dlg).getAllByLabelText('Zalo friend')
    expect(friends).toHaveLength(2)
    await userEvent.selectOptions(friends[0]!, '2938475610293847561')
    const phones = within(dlg).getAllByLabelText('Or find by phone number')
    await userEvent.type(phones[1]!, '0912 345 678')
    await userEvent.click(within(dlg).getAllByRole('button', { name: 'Find' })[2]!)
    expect(await within(dlg).findByText('Zalo: Hoa Le (ID 4756102938475610293)')).toBeInTheDocument()
    expect(within(dlg).getAllByText('Save to send this person a code on Zalo.')).toHaveLength(2)
    await userEvent.click(within(dlg).getByRole('button', { name: 'Save' }))
    // The dialog stays open: each approver waits for the reply to the code, then shows Linked.
    expect(await within(dlg).findAllByText(/Waiting for (Minh Tran|Hoa Le) to reply/)).toHaveLength(2)
    expect(within(dlg).getAllByRole('button', { name: 'Send again' })).toHaveLength(2)
    expect(await within(dlg).findAllByText('Linked', undefined, { timeout: 5000 })).toHaveLength(2)
    const z = (await getJson('/notify/channels') as { channels: { type: string; approvals: boolean; fields: Record<string, string>; approvers: { address: string; name?: string }[] }[] }).channels.find((c) => c.type === 'zalo-personal')!
    expect(z.fields).toEqual({ user_id: '8000000002', group: 'true', name: 'Night shift', account: 'Vedette Box' })
    expect(z.approvers.map((a) => [a.address, a.name])).toEqual([['2938475610293847561', 'Minh Tran'], ['4756102938475610293', 'Hoa Le']])
  })

  it('Zalo personal: saving with a sign-in that ended is refused, and finding needs a session (S-NOT-1, D-447)', async () => {
    renderChannels()
    await screen.findByRole('table')
    const res = await fetch(`${location.origin}/api/v1/notify/channels/zalo-personal`, { method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: true, min_severity: 'high', fields: { user_id: '8000000002' }, zalo_login: true }) })
    expect(res.status).toBe(400)
    expect((await res.json() as { error: { code: string } }).error.code).toBe('login_required')
    await fetch(`${location.origin}/api/v1/notify/channels/zalo-personal`, { method: 'DELETE' })
    const find = await fetch(`${location.origin}/api/v1/notify/zalo/resolve`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query: '0912345678' }) })
    expect(find.status).toBe(409)
  })
})
const APPROVE_LABEL = 'Approve actions from this channel'
