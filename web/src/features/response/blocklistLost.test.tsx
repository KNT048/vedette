// #847 (J7 #812): after a backup restored without its decryption key, the box cannot read the block list token. The Block list tab
// shows the box's sentence (the firewall keeps its address) and keeps Regenerate token reachable; Regenerate shows the new address.
import { describe, expect, it, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp } from '@/test/render'
import { server } from '@/test/server'

// D-624 (#819, #841): AI response is hidden in the v1 GUI (POST_V1_IN_UI false) but its screens are kept; run them as offered,
// as response.test.tsx does.
const postV1 = vi.hoisted(() => ({ POST_V1_IN_UI: true }))
vi.mock('@/lib/postV1', () => postV1)

const LOST = 'The block list address could not be read on this box (it was restored without the decryption key, or the box key changed). Your firewall keeps using its current address. Press Regenerate token to make a new one, then paste it into the firewall.'
const T = { timeout: 5000 }

describe('Block list after a restore without the decryption key', () => {
  it('secret_lost: the sentence shows, and Regenerate token makes a new address', async () => {
    let regenerated = false
    const view = { url: 'https://box.example:8443/api/v1/response/blocklist/0123456789abcdef0123456789abcdef.txt', token_last4: 'cdef', entries: [], last_fetch: null }
    server.use(
      http.get('*/api/v1/response/blocklist', () => (regenerated ? HttpResponse.json(view) : HttpResponse.json({ error: { code: 'secret_lost', message: LOST } }, { status: 409 }))),
      http.post('*/api/v1/response/blocklist/token', () => { regenerated = true; return HttpResponse.json(view) }),
    )
    const user = userEvent.setup()
    renderApp('/response#blocklist')
    expect(await screen.findByText(LOST, undefined, T)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Regenerate token' }))
    const dialog = await screen.findByRole('dialog', { name: 'Regenerate the token?' }, T)
    await user.click(within(dialog).getByRole('button', { name: 'Regenerate token' }))
    expect(await screen.findByText(view.url, undefined, T)).toBeInTheDocument()
    expect(screen.queryByText(LOST)).not.toBeInTheDocument()
  })
})
