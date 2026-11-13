// S-NOT-1 criterion D-462: the setup wizard has no alert channel step, so Home reminds an administrator until a channel is on.
import { describe, expect, it } from 'vitest'
import { act, cleanup, screen, waitFor } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
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

/**
 * Renders Home and resolves once the mock has answered every GET in `paths` and React has rendered what they returned,
 * so the reminder had its chance to show. Returns the paths that were asked for (to check /notify/channels was not).
 */
async function renderHome(paths: string[], role?: 'operator') {
  const asked = new Set<string>()
  const seen = ({ request }: { request: Request }) => { asked.add(new URL(request.url).pathname.replace(/^\/api\/v1/, '')) }
  server.events.on('response:mocked', seen)
  try {
    renderApp('/', role ? { role } : {})
    await waitFor(() => { for (const p of paths) expect(asked.has(p), p).toBe(true) })
    expect(await screen.findByRole('heading', { level: 1 })).toBeInTheDocument()
    await act(async () => {}) // let the queries that just resolved render, and any request they start begin
    return asked
  } finally { server.events.removeListener('response:mocked', seen) }
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
    await renderHome(['/me', '/modules', '/notify/channels'])
    expect(prompt()).toBeNull()
  })

  it('a channel that is saved but switched off does not count', async () => {
    await removeAll()
    expect((await telegram(false)).status).toBe(200)
    renderApp('/')
    expect(await screen.findByText(TITLE)).toBeInTheDocument()
  })

  it('not shown when a channel is on (the sample box)', async () => {
    await renderHome(['/me', '/modules', '/notify/channels'])
    expect(prompt()).toBeNull()
  })

  it('not shown to an operator (only administrators read channels), and the channels are not asked for', async () => {
    await removeAll()
    const asked = await renderHome(['/me', '/modules'], 'operator')
    expect(asked.has('/notify/channels')).toBe(false)
    expect(prompt()).toBeNull()
  })

  it('not shown while the Notifications module is off, and the channels are not asked for', async () => {
    await removeAll()
    modulesStore.update((l) => l.map((m) => (m.id === 'notify' ? { ...m, enabled: false } : m)))
    const asked = await renderHome(['/me', '/modules'])
    expect(asked.has('/notify/channels')).toBe(false)
    expect(prompt()).toBeNull()
  })

  for (const status of [403, 500]) {
    it(`not shown, and Home still works, when reading the channels fails (${status})`, async () => {
      server.use(http.get('*/api/v1/notify/channels', () => HttpResponse.json({ error: { code: status === 403 ? 'forbidden' : 'internal', message: 'No.' } }, { status })))
      await renderHome(['/me', '/modules', '/notify/channels'])
      expect(prompt()).toBeNull()
      expect(screen.getByRole('search')).toBeInTheDocument() // the rest of Home rendered
    })
  }
})
