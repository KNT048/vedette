// #847 (#812): after a backup restored without its decryption key, the box cannot open the saved SIEM signing key. The SIEM page says
// forwarding is stopped and opens on the key field; Save with the field blank shows the box's sentence; the key typed again clears it.
import { describe, expect, it } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClientProvider } from '@tanstack/react-query'
import { http, HttpResponse } from 'msw'
import { Toaster } from 'sonner'
import { makeQueryClient } from '@/app/App'
import { server } from '@/test/server'
import { orgStore, sessionStore } from '@/mocks/stores'
import SiemSettings from './SiemSettings'

const LOST = 'The saved signing key of the SIEM webhook was not restored (the backup was restored without its decryption key, or the box key changed). Enter the signing key again (the one your SIEM checks, or press Generate random and put the new key in the SIEM) and press Save. Nothing is sent to the SIEM until then.'
const T = { timeout: 5000 }

describe('SIEM forwarding after a restore without the decryption key', () => {
  it('secret_lost: the state shows, the key field has focus, a blank Save is refused, the key typed again resumes forwarding', async () => {
    let lost = true
    const cfg = () => ({ enabled: true, format: 'json', host: '', port: 514, proto: 'udp', url: 'https://siem.company.com/hooks/vedette', secret_last4: '1234', secret_lost: lost, events: ['alerts'], last_test: null })
    server.use(
      http.get('*/api/v1/logs/siem', () => HttpResponse.json(cfg())),
      http.put('*/api/v1/logs/siem', async ({ request }) => {
        const b = (await request.json()) as { secret?: string }
        if (!b.secret) return HttpResponse.json({ error: { code: 'secret_lost', message: LOST } }, { status: 409 })
        lost = false
        return HttpResponse.json(cfg())
      }),
    )
    orgStore.update((o) => ({ ...o, setup_complete: true }))
    sessionStore.set({ userId: 'u-admin' })
    const user = userEvent.setup()
    render(<QueryClientProvider client={makeQueryClient()}><SiemSettings /><Toaster /></QueryClientProvider>)
    expect(await screen.findByText('Forwarding is stopped: the saved signing key was not restored', undefined, T)).toBeInTheDocument()
    const field = screen.getByLabelText('Signing key (optional)')
    await waitFor(() => expect(field).toHaveFocus(), T) // once the role is known and the form is enabled
    expect(field).toHaveAccessibleDescription(/was not restored with the backup/)

    field.blur()
    await user.click(screen.getByRole('button', { name: /^Save$/ }))
    expect(await screen.findByRole('alert', undefined, T)).toHaveTextContent(LOST)
    expect(field).toHaveFocus()

    await user.type(field, 'a-signing-key-longer-than-16-ABCD')
    await user.click(screen.getByRole('button', { name: /^Save$/ }))
    await waitFor(() => expect(screen.queryByText('Forwarding is stopped: the saved signing key was not restored')).not.toBeInTheDocument(), T)
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('a working syslog setup with a lost webhook key: nothing is stopped; switching to JSON asks for the key', async () => {
    server.use(http.get('*/api/v1/logs/siem', () => HttpResponse.json({ enabled: true, format: 'syslog', host: '192.168.10.50', port: 514, proto: 'udp', url: '', secret_last4: '1234', secret_lost: true, events: ['alerts'], last_test: null })))
    orgStore.update((o) => ({ ...o, setup_complete: true }))
    sessionStore.set({ userId: 'u-admin' })
    const user = userEvent.setup()
    render(<QueryClientProvider client={makeQueryClient()}><SiemSettings /><Toaster /></QueryClientProvider>)
    await waitFor(() => expect(screen.getByLabelText('SIEM server')).toBeEnabled(), T)
    expect(screen.queryByText('Forwarding is stopped: the saved signing key was not restored')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'JSON webhook' }))
    expect(await screen.findByText('The saved signing key was not restored')).toBeInTheDocument()
    expect(screen.queryByText('Forwarding is stopped: the saved signing key was not restored')).not.toBeInTheDocument()
  })
})
