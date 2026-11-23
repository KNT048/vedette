import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp } from '@/test/render'
import { server } from '@/test/server'
import { assetsStore, modulesStore, sessionStore } from '@/mocks/stores'
import { ensureBox } from './mocks'

// An enrollment token is made by one click on "Create install command", never by opening a dialog or choosing a system.
vi.setConfig({ testTimeout: 30_000 })
beforeEach(() => ensureBox())

const T = { timeout: 5000 }
const enableModule = (id: string, enabled: boolean) => modulesStore.update((l) => l.map((m) => (m.id === id ? { ...m, enabled } : m)))
const tokens = async () => {
  sessionStore.set({ userId: 'u-admin' })
  const r = await fetch(`${location.origin}/api/v1/inventory/agents`)
  return ((await r.json()) as { tokens: { id: string; name: string; hosts: number; device_id: string | null }[] }).tokens
}
const setOs = (id: string, os: string | null) => assetsStore.update((l) => l.map((a) => (a.id === id ? { ...a, os: os ? { value: os, source: 'nmap', confidence: 1, seen_at: new Date().toISOString() } : null } : a)))
const command = (dlg: HTMLElement) => within(dlg).getByText(/^vdt_osquery_/).textContent

describe('Install dialogs make a token on the click only', () => {
  it('device page: opening the dialog and picking a system make none; one click makes one and the command stays', async () => {
    enableModule('agent-intake', true)
    setOs('a-srvad', null)
    const user = userEvent.setup()
    const before = (await tokens()).length
    renderApp('/devices/a-srvad', { role: 'admin' })
    const list = await screen.findByRole('list', { name: 'Sources' }, T)
    await user.click(await within(list).findByRole('button', { name: 'Create agent token' }, T))
    const dlg = await screen.findByRole('dialog', undefined, T)
    await user.click(await within(dlg).findByRole('button', { name: 'Linux' }, T))
    await user.click(within(dlg).getByRole('button', { name: 'Windows' }))
    await user.click(within(dlg).getByRole('button', { name: 'Linux' }))
    expect(await tokens()).toHaveLength(before)
    await user.click(await within(dlg).findByRole('button', { name: 'Create install command' }, T))
    await within(dlg).findByText(/^vdt_osquery_/, undefined, T)
    const made = await tokens()
    expect(made).toHaveLength(before + 1)
    expect(made.at(-1)!.name).toMatch(/\S/)
    expect(made.at(-1)!.device_id).toBe('a-srvad') // made for this device: its row offers Show setup
    const first = command(dlg)
    await user.click(within(dlg).getByRole('button', { name: 'Windows' })) // switching the system re-renders: the same token, no new one
    expect(command(dlg)).toBe(first)
    expect(within(dlg).queryByRole('button', { name: 'Create install command' })).toBeNull()
    expect(await tokens()).toHaveLength(before + 1)
  })

  it('Add a device > osquery: picking a system makes none; one click makes one', async () => {
    enableModule('agent-intake', true)
    const user = userEvent.setup()
    const before = (await tokens()).length
    renderApp('/devices?add=osquery', { role: 'admin' })
    const dlg = await screen.findByRole('dialog', { name: 'Add a device' }, T)
    await user.click(await within(dlg).findByRole('button', { name: 'Linux' }, T))
    expect(await tokens()).toHaveLength(before)
    await user.click(await within(dlg).findByRole('button', { name: 'Create install command' }, T))
    await within(dlg).findByText(/^vdt_osquery_/, undefined, T)
    expect(await tokens()).toHaveLength(before + 1)
  })

  it('Settings > Agents and tokens: opening the dialog makes none; one click makes one named "osquery install <date>"', async () => {
    enableModule('agent-intake', true)
    const user = userEvent.setup()
    const before = (await tokens()).length
    renderApp('/devices/setup?tab=agents', { role: 'admin' })
    await user.click(await screen.findByRole('button', { name: 'Create agent token' }, T))
    const dlg = await screen.findByRole('dialog', undefined, T)
    expect(await tokens()).toHaveLength(before)
    await user.click(await within(dlg).findByRole('button', { name: 'Create install command' }, T))
    await screen.findByRole('dialog', { name: /^Token for osquery install \d{4}-\d{2}-\d{2}$/ }, T)
    const made = await tokens()
    expect(made).toHaveLength(before + 1)
    expect(made.at(-1)!.name).toMatch(/^osquery install \d{4}-\d{2}-\d{2}$/)
  })
})

describe('Agents and tokens list', () => {
  it('shows who made each token and when, and Remove unused tokens removes tokens without machines, not ones with machines or made in the last hour', async () => {
    enableModule('agent-intake', true)
    const user = userEvent.setup()
    sessionStore.set({ userId: 'u-admin' })
    await fetch(`${location.origin}/api/v1/inventory/agents/tokens`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: 'just made' }) })
    renderApp('/devices/setup?tab=agents', { role: 'admin' })
    const table = await screen.findByRole('table', { name: 'Enrollment tokens' }, T)
    for (const h of ['Made by', '^Made$', 'Expires', 'Last data received', 'Machines enrolled']) expect(within(table).getByRole('columnheader', { name: new RegExp(h) })).toBeInTheDocument()
    expect(within(table).getByText('osquery install (never run)')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Remove unused tokens' }))
    await waitFor(() => expect(within(table).queryByText('osquery install (never run)')).toBeNull(), T)
    expect(within(table).getByText('just made')).toBeInTheDocument() // made in the last hour: its command may still be on screen
    expect(within(table).getByText('osquery on SRV-AD and SRV-FILE')).toBeInTheDocument() // it has machines: it stays
    expect((await tokens()).map((t) => t.name).sort()).toEqual(['just made', 'osquery on SRV-AD and SRV-FILE'])
  })

  it('at the limit the error says so in words and Remove unused tokens is offered right there', async () => {
    enableModule('agent-intake', true)
    const user = userEvent.setup()
    server.use(http.post('*/api/v1/inventory/agents/tokens', () => HttpResponse.json({ error: { code: 'too_many_tokens', message: 'There are already 500 enrollment tokens, the most there can be. Use Remove unused tokens or revoke a token you no longer need, then create the install command again.' } }, { status: 409 })))
    renderApp('/devices/setup?tab=agents', { role: 'admin' })
    await user.click(await screen.findByRole('button', { name: 'Create agent token' }, T))
    const dlg = await screen.findByRole('dialog', undefined, T)
    await user.click(await within(dlg).findByRole('button', { name: 'Create install command' }, T))
    expect(await within(dlg).findByText(/already 500 enrollment tokens/, undefined, T)).toBeInTheDocument()
    await user.click(within(dlg).getByRole('button', { name: 'Remove unused tokens' }))
    await waitFor(() => expect(within(dlg).queryByText(/already 500 enrollment tokens/)).toBeNull(), T)
    expect(within(dlg).getByRole('button', { name: 'Create install command' })).toBeInTheDocument()
  })
})
