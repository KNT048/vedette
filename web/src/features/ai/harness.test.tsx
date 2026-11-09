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
import { activeDefs, builtinHookState, customHooksStore, runHooks } from './harness'
import type { AskResult, Connector } from './types'

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
  it('rejects a broken regex and a connection with no allow-list or shell characters', async () => {
    asAdmin()
    const bad = await post('/ai/hooks', { name: 'x', when: 'before_ai', match: { type: 'regex', pattern: '(' }, action: 'block', message: 'No.', enabled: true })
    expect(bad.status).toBe(400)
    const base = { name: 'Srv', kind: 'mcp-stdio', target: 'npx tool', auth_type: 'none', allow: ['api.example.com'], enabled: true }
    expect((await post('/ai/connections', { ...base, allow: [] })).status).toBe(400)
    expect((await post('/ai/connections', { ...base, target: 'npx tool; rm -rf /' })).status).toBe(400)
    const ok = await post('/ai/connections', { ...base, auth_type: 'token', secret: 'supersecret-1234' })
    const c = (await ok.json()) as Connector
    expect(c.auth).toEqual({ type: 'token', last4: '1234' })
    expect(JSON.stringify(c)).not.toContain('supersecret')
    expect(c.tools.some((t) => t.access === 'write')).toBe(true)
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
})

describe('Connections and Hooks forms: form matrix (docs/QA.md §2)', () => {
  function renderTab(tab: string) {
    asAdmin()
    return render(<QueryClientProvider client={makeQueryClient()}><MemoryRouter initialEntries={[`/settings/ai?tab=${tab}`]}><AiSettings /></MemoryRouter><Toaster /></QueryClientProvider>)
  }
  const TARGETS = ['Base address (URL)', 'SSH server (host or host:port)', 'Device address (URL, or host:port for NETCONF)', 'Platform address (URL)', 'MCP server address (URL)', 'Command that starts the MCP server']
  const others = (keep: string) => TARGETS.filter((x) => x !== keep)
  const usable = (sign: HTMLElement) => within(sign).getAllByRole('option').filter((o) => !(o as HTMLOptionElement).disabled).map((o) => o.textContent)

  it('every connection kind shows its own address, offers only the sign-ins it can use, and carries nothing over from the last kind', async () => {
    renderTab('connections')
    await userEvent.click(await screen.findByRole('button', { name: 'Add connection' }))
    const dlg = await screen.findByRole('dialog', { name: 'Add connection' })
    const kind = within(dlg).getByLabelText('Kind')
    const sign = within(dlg).getByLabelText('Sign-in')
    const pick = async (o: string) => { await userEvent.selectOptions(kind, within(kind).getByRole('option', { name: o })) }
    // Generic kinds only (D-58): no field asks which brand a device is.
    await eachOption([
      { option: 'HTTP API', shown: [TARGETS[0]!], hidden: [...others(TARGETS[0]!), 'Secret'] }, // starts with no sign-in, so no secret field
      { option: 'SSH / CLI', shown: [TARGETS[1]!, 'Secret'], hidden: [...others(TARGETS[1]!)] },
      { option: 'NETCONF / RESTCONF', shown: [TARGETS[2]!, 'Secret'], hidden: [...others(TARGETS[2]!)] },
      { option: 'Automation platform (Ansible AWX/Tower, n8n...)', shown: [TARGETS[3]!, 'Secret'], hidden: [...others(TARGETS[3]!)] },
      { option: 'MCP server (URL)', shown: [TARGETS[4]!], hidden: [...others(TARGETS[4]!)] },
      { option: 'MCP server (command)', shown: [TARGETS[5]!], hidden: [...others(TARGETS[5]!), 'Secret'] },
      { option: 'HTTP API', shown: [TARGETS[0]!], hidden: [...others(TARGETS[0]!), 'Secret'] },
    ], pick, dlg)
    expect(within(dlg).queryByLabelText(/Which device API/)).toBeNull()
    expect(within(kind).getAllByRole('option').map((o) => o.textContent)).toEqual(['HTTP API', 'SSH / CLI', 'NETCONF / RESTCONF', 'Automation platform (Ansible AWX/Tower, n8n...)', 'MCP server (URL)', 'MCP server (command)'])

    // sign-ins the kind cannot use are locked and the server refuses them too
    await pick('SSH / CLI'); expect(usable(sign)).toEqual(['User and password', 'SSH key'])
    await pick('NETCONF / RESTCONF'); expect(usable(sign)).toEqual(['API token', 'User and password'])
    await pick('Automation platform (Ansible AWX/Tower, n8n...)'); expect(usable(sign)).toEqual(['API token', 'User and password'])
    await pick('MCP server (command)'); expect(usable(sign)).toEqual(['No sign-in', 'API token'])
    await pick('HTTP API'); expect(usable(sign)).toEqual(['No sign-in', 'API token', 'User and password'])
    const base = { name: 'Srv', kind: 'ssh', target: '192.168.10.30:22', auth_type: 'token', secret: 'supersecret-1234', allow: ['uname -a'], enabled: true }
    expect((await post('/ai/connections', base)).status).toBe(400)
    expect((await post('/ai/connections', { ...base, kind: 'netconf-restconf', target: 'https://192.168.10.1', auth_type: 'ssh-key', allow: ['https://192.168.10.1/'] })).status).toBe(400)
    expect((await post('/ai/connections', { ...base, kind: 'device-api', target: 'https://192.168.10.1', auth_type: 'token', allow: ['https://192.168.10.1/'] })).status).toBe(400) // no brand-specific kind exists any more
    expect((await post('/ai/connections', { ...base, auth_type: 'ssh-key' })).status).toBe(200)

    // nothing typed for a kind survives a change of kind: address, allow-list and secret restart
    await pick('NETCONF / RESTCONF')
    await userEvent.type(within(dlg).getByLabelText('Allow-list (one per line)'), 'https://192.168.10.1/restconf/')
    await userEvent.type(within(dlg).getByLabelText('Secret'), 'token-for-the-api')
    await userEvent.clear(within(dlg).getByLabelText(TARGETS[2]!)); await userEvent.type(within(dlg).getByLabelText(TARGETS[2]!), 'https://10.0.0.1')
    await pick('SSH / CLI')
    expect(within(dlg).getByLabelText(TARGETS[1]!)).toHaveValue('192.168.10.30:22')
    expect(within(dlg).getByLabelText('Allow-list (one per line)')).toHaveValue('')
    expect(within(dlg).getByLabelText('Secret')).toHaveValue('')
    expect(within(dlg).getByLabelText('Sign-in')).toHaveValue('ssh-key')
  })

  it('each generic kind offers generic tools, a way to write only through an approved action, and no brand', async () => {
    asAdmin()
    const mk = (kind: string, target: string, auth_type: string, allow: string[]) => post('/ai/connections', { name: `k-${kind}`, kind, target, auth_type, secret: auth_type === 'none' ? undefined : 'a-long-enough-secret', allow, enabled: true })
    const made = await Promise.all([
      mk('http', 'https://192.168.10.1', 'token', ['https://192.168.10.1/api/']),
      mk('ssh', '192.168.10.2:22', 'ssh-key', ['uname -a']),
      mk('netconf-restconf', 'https://192.168.10.3', 'basic', ['https://192.168.10.3/restconf/']),
      mk('automation', 'https://automation.example.local', 'token', ['https://automation.example.local/api/']),
      mk('mcp-http', 'https://mcp.example.local/mcp', 'none', ['mcp.example.local']),
    ].map(async (p) => { const r = await p; return { status: r.status, json: (await r.json()) as { tools: { name: string; access: string; enabled: boolean }[] } } }))
    for (const r of made) expect(r.status, JSON.stringify(r.json)).toBe(200)
    const tools = made.map((r) => r.json.tools.map((t) => `${t.name}:${t.access}`))
    expect(tools[0]).toEqual(['fetch_url:read', 'send_request:write'])
    expect(tools[1]).toEqual(['run_allowed_command:read', 'run_approved_command:write'])
    expect(tools[2]).toEqual(['get_config:read', 'apply_config:write'])
    expect(tools[3]).toEqual(['list_jobs:read', 'launch_job:write'])
    // every write tool starts off: an administrator turns it on (D-41, D-51)
    for (const r of made) for (const t of r.json.tools) if (t.access === 'write') expect((t as { enabled: boolean }).enabled, t.name).toBe(false)
    expect(JSON.stringify(made.map((r) => r.json))).not.toMatch(/vendor|fortinet|mikrotik|pfsense/i)
  })

  it('editing a connection and returning to its saved kind restores its saved values; another kind starts clean and needs a new secret', async () => {
    renderTab('connections')
    await userEvent.click(await screen.findByRole('button', { name: 'Edit Core switch' }).catch(() => screen.findAllByRole('button', { name: /^Edit / }).then((l) => l[0]!)))
    const dlg = await screen.findByRole('dialog')
    const kind = within(dlg).getByLabelText('Kind')
    const saved = (within(dlg).getByLabelText(/^(Device address|SSH server|Base address)/) as HTMLInputElement).value
    const savedKind = (kind as HTMLSelectElement).value
    await userEvent.selectOptions(kind, savedKind === 'http' ? 'mcp-stdio' : 'http')
    expect((within(dlg).getByLabelText(/^(Device address|SSH server|Base address|MCP|Command)/) as HTMLInputElement).value).not.toBe(saved)
    expect(within(dlg).queryByText(/Saved, ending/)).toBeNull() // the saved secret belongs to the old kind
    await userEvent.selectOptions(kind, savedKind)
    expect((within(dlg).getByLabelText(/^(Device address|SSH server|Base address)/) as HTMLInputElement).value).toBe(saved)
  })

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
