// J7 (#812): after a backup restored without its decryption key, the box refuses an account whose two-step key or SSO client
// secret was lost with its own error; the sign-in page shows that sentence (who fixes it and where), not a generic failure.
import { describe, expect, it } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp } from '@/test/render'
import { server } from '@/test/server'

const TWOFA_LOST = 'Your two-step sign-in key could not be read on this box (it was restored without the decryption key, or the box key changed). Ask an administrator to reset your two-step sign-in in Settings, Users, then sign in and set it up again.'
const SSO_LOST = 'SSO sign-in cannot be used: the SSO client secret could not be read on this box (it was restored without the decryption key, or the box key changed). An administrator signs in with a password and enters the client secret again in Settings, Users, SSO sign-in.'

describe('sign-in after a restore without the decryption key', () => {
  it('twofa_reset_required: the sentence shows under the password, no code is asked for', async () => {
    server.use(http.post('*/api/v1/auth/login', () => HttpResponse.json({ error: { code: 'twofa_reset_required', message: TWOFA_LOST } }, { status: 403 })))
    const u = userEvent.setup()
    renderApp('/login', { role: null })
    await u.type(await screen.findByLabelText('Email'), 'ann@acme.example')
    await u.type(screen.getByLabelText('Password'), 'the-right-password')
    await u.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByText(TWOFA_LOST)).toBeInTheDocument()
    expect(screen.queryByLabelText(/code/i)).not.toBeInTheDocument()
  })

  it('sso_secret_lost: the sentence shows under Sign in with SSO', async () => {
    server.use(
      http.get('*/api/v1/core/auth-options', () => HttpResponse.json({ oidc: true })),
      http.post('*/api/v1/auth/oidc/start', () => HttpResponse.json({ error: { code: 'sso_secret_lost', message: SSO_LOST } }, { status: 409 })),
    )
    const u = userEvent.setup()
    renderApp('/login', { role: null })
    await u.click(await screen.findByRole('button', { name: 'Sign in with SSO' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(SSO_LOST)
  })
})
