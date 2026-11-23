// #847 (#812): after a backup restored without its decryption key, the box cannot open a profile's saved API key. The profile is
// listed with the state and an action to enter the key right there; Test answers secret_lost and opens Edit on the key field; Save with
// the key blank is refused; the key typed again makes the profile usable.
import { describe, expect, it } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router'
import { http, HttpResponse } from 'msw'
import { Toaster } from 'sonner'
import { makeQueryClient } from '@/app/App'
import { server } from '@/test/server'
import { aiConfigStore, sessionStore } from '@/mocks/stores'
import { renderApp } from '@/test/render'
import AiSettings from './AiSettings'

const LOST = 'The saved API key of the AI profile "Claude" was not restored (the backup was restored without its decryption key, or the box key changed). Open Edit, enter the key again and save, then test it. Nothing was sent.'
const T = { timeout: 5000 }

describe('AI profiles after a restore without the decryption key', () => {
  it('key_lost: listed with the state; Test opens Edit on the key; a blank Save is refused; the key typed again fixes it', async () => {
    let lost = true
    const profile = () => ({ id: 'p-claude', name: 'Claude', kind: 'anthropic', api_style: 'anthropic', base_url: 'https://api.anthropic.com', model: 'claude-haiku-5-5', key_last4: lost ? '1111' : '2222', key_lost: lost, location: 'cloud', monthly_budget: 6_000_000, usable: !lost, used_month: 0, last_test: null })
    let saved: Record<string, unknown> | null = null
    server.use(
      http.get('*/api/v1/ai/profiles', () => HttpResponse.json({ items: [profile()] })),
      http.post('*/api/v1/ai/profiles/test', () => HttpResponse.json({ error: { code: 'secret_lost', message: LOST } }, { status: 409 })),
      http.put('*/api/v1/ai/profiles/:id', async ({ request }) => {
        saved = (await request.json()) as Record<string, unknown>
        if (!saved.api_key) return HttpResponse.json({ error: { code: 'secret_lost', message: LOST } }, { status: 409 })
        lost = false
        return HttpResponse.json(profile())
      }),
    )
    sessionStore.set({ userId: 'u-admin' })
    const qc = makeQueryClient()
    const user = userEvent.setup()
    render(<QueryClientProvider client={qc}><MemoryRouter><AiSettings /></MemoryRouter><Toaster /></QueryClientProvider>)
    await waitFor(() => expect(qc.getQueryData(['me'])).toBeTruthy(), T)
    expect(await screen.findByText('Claude: the saved API key was not restored', undefined, T)).toBeInTheDocument()
    expect(screen.getAllByText('Key not restored: enter it again').length).toBeGreaterThan(0)
    // the only profile is lost: the routing table stays, with its own line (not "add a profile")
    expect(await screen.findByText(/No job can run: the saved key of every profile was not restored/, undefined, T)).toBeInTheDocument()
    expect(screen.getByRole('table', { name: 'AI job routing' })).toBeInTheDocument()
    expect(screen.queryByText('No usable profile to assign')).not.toBeInTheDocument()

    // Test: the box says the key was not restored, and Edit opens on the key field
    await user.click(await screen.findByRole('button', { name: 'Test connection for Claude' }))
    let dlg = await screen.findByRole('dialog', { name: 'Edit Claude' }, T)
    expect(screen.getByText(`Claude: ${LOST}`)).toBeInTheDocument()
    const key = within(dlg).getByLabelText('API key')
    await waitFor(() => expect(key).toHaveFocus())
    expect(key).toHaveAccessibleDescription(/was not restored with the backup/)
    // a blank Save is refused on the field, nothing is sent
    await user.click(within(dlg).getByRole('button', { name: 'Save' }))
    expect(await within(dlg).findByText('The saved key was not restored with the backup. Enter the key again.')).toBeInTheDocument()
    expect(saved).toBeNull()
    await user.click(within(dlg).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())

    // the state's own action opens the same dialog; the key typed again makes the profile usable
    await user.click(screen.getByRole('button', { name: 'Enter the key' }))
    dlg = await screen.findByRole('dialog', { name: 'Edit Claude' }, T)
    await user.type(within(dlg).getByLabelText('API key'), 'new-secret-key-2222')
    await user.click(within(dlg).getByRole('checkbox', { name: /I understand/ }))
    await user.click(within(dlg).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull(), T)
    expect(saved).toMatchObject({ id: 'p-claude', api_key: 'new-secret-key-2222' })
    await waitFor(() => expect(screen.queryByText('Claude: the saved API key was not restored')).not.toBeInTheDocument(), T)
    expect(screen.queryByText(`Claude: ${LOST}`)).not.toBeInTheDocument() // the failed Test of the old key is gone too
  })
})

// #875: with every key lost the box reads "not configured", but the profiles (and their tasks) are still there. The AI panels
// send the customer to the lost profile's key, never to "Add AI profile" (a duplicate that leaves the lost one assigned).
describe('AI panels after a restore without the decryption key', () => {
  const lostProfiles = () => {
    aiConfigStore.update((c) => ({ ...c, configured: false }))
    server.use(http.get('*/api/v1/ai/profiles', () => HttpResponse.json({ items: [
      { id: 'p-claude', name: 'Claude', kind: 'anthropic', api_style: 'anthropic', base_url: 'https://api.anthropic.com', model: 'claude-haiku-5-5', key_last4: '1111', key_lost: true, location: 'cloud', monthly_budget: 6_000_000, usable: false, used_month: 0, last_test: null },
    ] })))
  }

  it('an administrator is sent to enter the key again, not to add a profile', async () => {
    lostProfiles()
    renderApp('/assistant')
    expect(await screen.findByRole('heading', { level: 1, name: /The AI key was not restored/ }, T)).toBeInTheDocument()
    expect(await screen.findByText('The AI key was not restored', undefined, T)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Enter the key again in Settings, AI assistant' })).toHaveAttribute('href', '/settings/ai#ai-profiles')
    expect(screen.queryByRole('button', { name: 'Add AI profile' })).toBeNull()
    expect(screen.queryByText('No AI profile yet')).toBeNull()
  })

  it('the CVE panel says the same; an operator is told to ask an administrator', async () => {
    lostProfiles()
    renderApp('/cve/CVE-2022-27593', { role: 'operator' })
    expect((await screen.findAllByText('The AI key was not restored', undefined, T)).length).toBe(1)
    expect(screen.getAllByText('Ask an administrator to enter the AI key again.')).toHaveLength(1)
    expect(screen.queryByRole('button', { name: 'Add AI profile' })).toBeNull()
    expect(screen.getByRole('button', { name: 'Ask my AI' })).toBeDisabled()
  })
})
