// S-NOT-1 criterion D-462: the setup wizard has no alert channel step, so Home reminds an administrator until a channel is on.
import { describe, expect, it } from 'vitest'
import { cleanup, screen, waitFor } from '@testing-library/react'
import { renderApp } from '@/test/render'
import { modulesStore, sessionStore } from '@/mocks/stores'
import { server } from '@/test/server'

const TITLE = 'No alert channel yet'
const prompt = () => screen.queryByText(TITLE)
const call = (path: string, method: string, body?: object) =>
  fetch(`${location.origin}/api/v1${path}`, { method, headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined })
const telegram = (enabled: boolean) => call('/notify/channels/telegram', 'PUT', { enabled, fields: { chat_id: '-1001234567890' }, secret: '123456789:EXAMPLE_not_a_real_token_0000000000', min_severity: 'medium' })
/** The sample box has Telegram, Slack and email on: remove them so no channel is set up. */
async function removeAll() {
  sessionStore.set({ userId: 'u-admin' }) // the channel API is for administrators; renderApp sets the session it renders with
  for (const type of ['telegram', 'slack', 'email']) expect((await call(`/notify/channels/${type}`, 'DELETE')).status).toBe(204)
}
/** Renders Home and resolves once the mock has answered GET <path>, so the reminder had its chance to show. */
async function renderHomeAndWaitFor(path: string, role?: 'operator') {
  let read = false
  const seen = ({ request }: { request: Request }) => { if (new URL(request.url).pathname.endsWith(path)) read = true }
  server.events.on('response:mocked', seen)
  renderApp('/', role ? { role } : {})
  await waitFor(() => expect(read).toBe(true))
  server.events.removeListener('response:mocked', seen)
  expect(await screen.findByRole('heading', { level: 1 })).toBeInTheDocument()
}

describe('alert channel reminder on Home (D-462)', () => {
  it('no channel: an administrator sees it with a link to Settings, Alert channels; it is gone once a channel is on', async () => {
    await removeAll()
    renderApp('/')
    expect(await screen.findByText(TITLE)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Set up an alert channel' })).toHaveAttribute('href', '/settings/channels')
    expect(screen.getByText(/Switch off Notifications in Settings, Modules/)).toBeInTheDocument()
    cleanup()
    expect((await telegram(true)).status).toBe(200)
    await renderHomeAndWaitFor('/notify/channels')
    expect(prompt()).toBeNull()
  })

  it('a channel that is saved but switched off does not count', async () => {
    await removeAll()
    expect((await telegram(false)).status).toBe(200)
    renderApp('/')
    expect(await screen.findByText(TITLE)).toBeInTheDocument()
  })

  it('not shown when a channel is on (the sample box)', async () => {
    await renderHomeAndWaitFor('/notify/channels')
    expect(prompt()).toBeNull()
  })

  it('not shown to an operator (only administrators read channels), and the channels are not asked for', async () => {
    await removeAll()
    let asked = false
    const seen = ({ request }: { request: Request }) => { if (new URL(request.url).pathname.endsWith('/notify/channels')) asked = true }
    server.events.on('response:mocked', seen)
    await renderHomeAndWaitFor('/modules', 'operator')
    server.events.removeListener('response:mocked', seen)
    expect(asked).toBe(false)
    expect(prompt()).toBeNull()
  })

  it('not shown while the Notifications module is off', async () => {
    await removeAll()
    modulesStore.update((l) => l.map((m) => (m.id === 'notify' ? { ...m, enabled: false } : m)))
    await renderHomeAndWaitFor('/modules')
    expect(prompt()).toBeNull()
  })
})
