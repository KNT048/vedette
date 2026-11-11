// Harness AI (S-AI-7): bộ máy hook, "Ask your data" áp hook, và vài thao tác trên giao diện.
import { describe, expect, it } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router'
import { Toaster } from 'sonner'
import { makeQueryClient } from '@/app/App'
import { server } from '@/test/server'
import { eachOption } from '@/test/formMatrix'
import { sessionStore } from '@/mocks/stores'
import AiSettings from './AiSettings'
import { activeDefs, builtinHookState, customHooksStore, knowledgeStore, runHooks } from './harness'
import type { AskResult } from './types'

void server
const api = (path: string, init?: RequestInit) => fetch(`${location.origin}/api/v1${path}`, { headers: { 'Content-Type': 'application/json' }, ...init })
const post = (path: string, b: unknown) => api(path, { method: 'POST', body: JSON.stringify(b) })
const ask = async (question: string) => (await (await post('/ai/ask', { question })).json()) as AskResult
const asAdmin = () => sessionStore.set({ userId: 'u-admin' })

describe('hook engine', () => {
  it('masks email and phone, refuses ID numbers, masks a name next to an account', () => {
    const d = activeDefs()
    const m = runHooks('Mail an.nguyen@example.com or call 0912 345 678 about account Nguyen Van An', 'before_ai', d)
    expect(m.outcome).toBe('masked')
    expect(m.text).not.toMatch(/example\.com|0912|Nguyen/)
    expect(m.hits.map((h) => h.action)).toEqual(['mask', 'mask', 'mask'])
    expect(runHooks('CCCD 079123456789 owns this laptop', 'before_ai', d).outcome).toBe('blocked')
    expect(runHooks('Which machines still expose RDP on 192.168.10.5?', 'before_ai', d).outcome).toBe('pass')
  })

  it('security-only refuses off-topic work; turning it off lets it through', () => {
    expect(runHooks('Write a poem about my firewall', 'before_ai', activeDefs()).outcome).toBe('blocked')
    builtinHookState.set({ 'security-only': false })
    expect(runHooks('Write a poem about my firewall', 'before_ai', activeDefs()).outcome).toBe('pass')
  })

  it('custom hooks run at their own stage; a disabled hook does nothing', () => {
    customHooksStore.set([{ id: 'h', name: 'Falcon', when: 'after_ai', match: { type: 'keywords', pattern: 'project falcon' }, action: 'block', message: 'No code names.', enabled: true }])
    expect(runHooks('about Project Falcon', 'before_ai', activeDefs()).outcome).toBe('pass')
    expect(runHooks('about Project Falcon', 'after_ai', activeDefs()).outcome).toBe('blocked')
    customHooksStore.update((l) => l.map((x) => ({ ...x, enabled: false })))
    expect(runHooks('about Project Falcon', 'after_ai', activeDefs()).outcome).toBe('pass')
  })
})

describe('ask your data applies hooks', () => {
  it('masks an email or phone before the AI sees it and names the hook', async () => {
    asAdmin()
    const r = await ask('Which machines still expose RDP? Reply to an.nguyen@example.com')
    expect(r.question).not.toContain('example.com')
    expect(r.hooks.some((h) => h.id === 'block-pii' && h.action === 'mask')).toBe(true)
    expect(r.model).not.toBe('')
  })
  it('blocks an ID number: no AI call, no tokens, a clear message', async () => {
    asAdmin()
    const r = await ask('Whose laptop is this? ID 079123456789')
    expect(r.tokens).toEqual({ input: 0, output: 0 })
    expect(r.answer[0]).toMatch(/ID number/)
    expect(r.question).not.toContain('079123456789')
    expect(r.hooks[0]).toMatchObject({ id: 'block-pii', action: 'block' })
  })
  it('refuses an off-topic request only while "Security work only" is on', async () => {
    asAdmin()
    const r = await ask('write a poem')
    expect(r.hooks[0]).toMatchObject({ id: 'security-only', action: 'block' })
    expect(r.answer[0]).toMatch(/only helps with the security/)
    await api('/ai/hooks/builtin/security-only', { method: 'PUT', body: JSON.stringify({ enabled: false }) })
    expect((await ask('write a poem')).hooks).toEqual([])
  })
  it('the locked hook cannot be turned off', async () => {
    asAdmin()
    const res = await api('/ai/hooks/builtin/write-approval', { method: 'PUT', body: JSON.stringify({ enabled: false }) })
    expect(res.status).toBe(400)
  })
  it('rejects a broken regex', async () => {
    asAdmin()
    const bad = await post('/ai/hooks', { name: 'x', when: 'before_ai', match: { type: 'regex', pattern: '(' }, action: 'block', message: 'No.', enabled: true })
    expect(bad.status).toBe(400)
  })
})

describe('Settings, AI assistant tabs', () => {
  function renderAt(url: string) {
    asAdmin()
    const qc = makeQueryClient()
    return render(<QueryClientProvider client={qc}><MemoryRouter initialEntries={[url]}><AiSettings /></MemoryRouter><Toaster /></QueryClientProvider>)
  }
  it('opens a tab from ?tab= and shows built-in rules read-only plus a custom rule', async () => {
    renderAt('/settings/ai?tab=rules')
    expect(await screen.findByText("Only help with the security of this company's network.")).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Rules' })).toHaveAttribute('aria-pressed', 'true')
    expect(await screen.findByText(/Name every device by its hostname/)).toBeInTheDocument()
  })
  it('the Connections tab only points to Settings → Connections (D-93)', async () => {
    renderAt('/settings/ai?tab=connections')
    const link = await screen.findByRole('link', { name: 'Settings → Connections' })
    expect(link).toHaveAttribute('href', '/settings/connections')
    expect(screen.queryByRole('button', { name: 'Add connection' })).toBeNull()
  })
  it('hooks tab: built-in "Write tools need approval" is locked on; a sample with an email is masked', async () => {
    renderAt('/settings/ai?tab=hooks')
    const locked = await screen.findByRole('switch', { name: 'Hook enabled: Write tools need approval' })
    expect(locked).toBeDisabled()
    expect(locked).toBeChecked()
    await userEvent.type(screen.getByLabelText('Sample text'), 'mail me at an@example.com')
    await userEvent.click(screen.getByRole('button', { name: 'Test' }))
    expect(await screen.findByText('Masked')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByText(/mail me at \[masked\]/)).toBeInTheDocument())
  })
  it('knowledge tab warns when the index profile is a cloud profile', async () => {
    renderAt('/settings/ai?tab=knowledge')
    const sel = await screen.findByLabelText('AI profile that builds the index')
    await userEvent.selectOptions(sel, 'p-haiku')
    expect(await screen.findByText(/leaves your network and goes to api\.anthropic\.com/)).toBeInTheDocument()
  })
  it('knowledge tab: a PDF is picked and uploaded; another type is refused on the page (S-AI-7, INV-10)', async () => {
    renderAt('/settings/ai?tab=knowledge')
    await userEvent.selectOptions(await screen.findByLabelText('AI profile that builds the index'), 'p-haiku')
    await waitFor(() => expect(screen.getByRole('button', { name: 'Upload document' })).toBeEnabled())
    const input = screen.getByTestId('kb-file')
    await userEvent.upload(input, new File(['%PDF-1.4\n%fake but named right\n'], 'runbook.pdf', { type: 'application/pdf' }), { applyAccept: false })
    await waitFor(() => expect(knowledgeStore.get().some((d) => d.name === 'runbook.pdf')).toBe(true))
    expect(screen.queryByText(/cannot be added/)).toBeNull()
    await userEvent.upload(input, new File(['x'], 'photo.png', { type: 'image/png' }), { applyAccept: false })
    expect(await screen.findByText(/photo\.png cannot be added/)).toBeInTheDocument()
  })
})

describe('Hooks form: form matrix (docs/QA.md §2)', () => {
  function renderTab(tab: string) {
    asAdmin()
    return render(<QueryClientProvider client={makeQueryClient()}><MemoryRouter initialEntries={[`/settings/ai?tab=${tab}`]}><AiSettings /></MemoryRouter><Toaster /></QueryClientProvider>)
  }
  it('a hook: keywords and regex have their own hint and an empty pattern; the pattern does not carry over; each action explains itself', async () => {
    renderTab('hooks')
    await userEvent.click((await screen.findAllByRole('button', { name: 'Add hook' }))[0]!)
    const dlg = await screen.findByRole('dialog', { name: 'Add hook' })
    const type = within(dlg).getByLabelText('Match by')
    await userEvent.type(within(dlg).getByLabelText('Keywords'), 'project falcon, salary')
    await eachOption([
      { option: 'Regex', shown: ['Regular expression', /For example: password/], hidden: [/Separate words with commas/] },
      { option: 'Keywords', shown: ['Keywords', /Separate words with commas/], hidden: ['Regular expression'] },
    ], async (o) => { await userEvent.selectOptions(type, within(type).getByRole('option', { name: o })) }, dlg)
    expect(within(dlg).getByLabelText('Keywords')).toHaveValue('')
    expect(within(dlg).queryByLabelText('Regular expression')).toBeNull()
    const action = within(dlg).getByLabelText('What it does')
    for (const [o, hint] of [['Block', /not sent or the answer/], ['Mask', /replaced with \[masked\]/], ['Require approval', /waits until a person approves/]] as const) {
      await userEvent.selectOptions(action, within(action).getByRole('option', { name: o }))
      expect(within(dlg).getByText(hint)).toBeInTheDocument()
    }
    // the server refuses a regex that does not compile, and keywords that are only separators
    expect((await post('/ai/hooks', { name: 'x', when: 'before_ai', match: { type: 'keywords', pattern: ' , ' }, action: 'block', message: 'No.', enabled: true })).status).toBe(400)
  })
})
