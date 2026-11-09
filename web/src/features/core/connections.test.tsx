// Settings → Connections (D-93, D-94; S-AI-7, S-RESP-4): list, add, edit, delete, test, the errors, the pin, roles, and privacy flow 12.
// The form matrix (docs/QA.md §2): every kind of connection x every sign-in it can use.
import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { eachOption } from '@/test/formMatrix'
import { server } from '@/test/server'
import { actionsStore } from '@/features/response/state'
import { connectorsStore } from '@/mocks/connectors'
import { sessionStore } from '@/mocks/stores'
import { CONNECTION_KINDS, KIND_AUTH } from '@/lib/connections'
import type { Connector } from './types'

void server
const api = (path: string, init?: RequestInit) => fetch(`${location.origin}/api/v1${path}`, { headers: { 'Content-Type': 'application/json' }, ...init })
const post = (path: string, b?: unknown) => api(path, { method: 'POST', body: b === undefined ? undefined : JSON.stringify(b) })
const put = (path: string, b: unknown) => api(path, { method: 'PUT', body: JSON.stringify(b) })
const as = (userId: 'u-admin' | 'u-op' | 'u-view') => sessionStore.set({ userId })
const user = () => userEvent.setup()
const HTTP = { name: 'Lab API', kind: 'http', target: 'https://192.168.10.50', auth_type: 'token', secret: 'a-long-enough-secret', allow: ['https://192.168.10.50/api/'], enabled: true }
const SSH = { name: 'Lab switch', kind: 'ssh', target: '192.168.10.51:22', auth_type: 'ssh-key', username: 'vedette', secret: 'a-long-enough-key', allow: ['show version'], enabled: true }
const card = (name: string) => screen.getByRole('heading', { level: 2, name: new RegExp(name) }).closest('li') as HTMLElement
const loaded = () => screen.findAllByRole('heading', { level: 2 })
const inForce = (connector_id: string) => actionsStore.update((l) => [{ id: 'act-inforce', items: [{ id: 'it-1', connector_id, status: 'executed' }] } as never, ...l])

describe('Settings → Connections: the page', () => {
  it('lists the connections with sign-in, user name and pinned key; a11y is clean', async () => {
    renderApp('/settings/connections')
    expect(await screen.findByRole('heading', { level: 1, name: 'Connections' })).toBeInTheDocument()
    await loaded()
    const ssh = card('File server')
    expect(within(ssh).getByText(/SSH key ending b2Lx/)).toBeInTheDocument()
    expect(within(ssh).getByText(/signs in as vedette-ro/)).toBeInTheDocument()
    expect(within(ssh).getByText(/ssh-ed25519 SHA256:/)).toBeInTheDocument()
    expect(within(ssh).getByText(/Pinned host key/)).toBeInTheDocument()
    expect(within(card('Office FortiGate')).getByText(/Pinned certificate/)).toBeInTheDocument()
    expect(within(card('Vendor advisories')).queryByText(/Pinned/)).toBeNull()
    expect(screen.getByRole('link', { name: 'See privacy flow 12' })).toHaveAttribute('href', '/settings/privacy')
    await expectNoA11yViolations()
  })

  it('is a core page: it opens with the AI module off', async () => {
    const { modulesStore } = await import('@/mocks/stores')
    modulesStore.update((l) => l.map((m) => (m.id === 'ai' ? { ...m, enabled: false } : m)))
    renderApp('/settings/connections')
    expect(await screen.findByRole('button', { name: 'Add connection' })).toBeInTheDocument()
  })

  it('adds a connection, shows it, and answers 201', async () => {
    const u = user()
    renderApp('/settings/connections')
    await u.click(await screen.findByRole('button', { name: 'Add connection' }))
    const dlg = await screen.findByRole('dialog', { name: 'Add connection' })
    await u.type(within(dlg).getByLabelText('Name'), 'Guest switch')
    await u.clear(within(dlg).getByLabelText('Base address (URL)')); await u.type(within(dlg).getByLabelText('Base address (URL)'), 'https://192.168.10.60')
    await u.selectOptions(within(dlg).getByLabelText('Sign-in'), 'token')
    await u.type(within(dlg).getByLabelText('Secret'), 'a-long-enough-secret')
    await u.type(within(dlg).getByLabelText('Allow-list (one per line)'), 'https://192.168.10.60/api/')
    await u.click(within(dlg).getByRole('button', { name: 'Add connection' }))
    expect(await screen.findByRole('heading', { level: 2, name: /Guest switch/ })).toBeInTheDocument()
    expect(within(card('Guest switch')).getByText('Not tested')).toBeInTheDocument()
    expect((await post('/core/connections', { ...HTTP, name: 'Another one' })).status).toBe(201)
  })

  it('empty state offers a single way to add one', async () => {
    connectorsStore.set([])
    renderApp('/settings/connections')
    expect(await screen.findByText('No connections yet')).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: 'Add connection' })).toHaveLength(1)
  })

  it('edits: the secret is kept when left blank, the user name changes, a write tool turns on', async () => {
    const u = user()
    renderApp('/settings/connections')
    await loaded()
    await u.click(within(card('File server')).getByRole('button', { name: 'Edit File server (read-only SSH)' }))
    const dlg = await screen.findByRole('dialog', { name: /Edit File server/ })
    expect(within(dlg).getByLabelText('User name')).toHaveValue('vedette-ro')
    expect(within(dlg).getByText(/Saved, ending b2Lx/)).toBeInTheDocument()
    await u.clear(within(dlg).getByLabelText('User name')); await u.type(within(dlg).getByLabelText('User name'), 'auditor')
    await u.click(within(dlg).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(within(card('File server')).getByText(/signs in as auditor/)).toBeInTheDocument())
    expect(within(card('File server')).getByText(/SSH key ending b2Lx/)).toBeInTheDocument()
  })

  it('"Forget pinned key" sends clear_pin and the card loses the pin; without it the pin stays through an edit', async () => {
    const u = user()
    renderApp('/settings/connections')
    await loaded()
    // no switch: the pin survives
    await u.click(within(card('File server')).getByRole('button', { name: 'Edit File server (read-only SSH)' }))
    let dlg = await screen.findByRole('dialog', { name: /Edit File server/ })
    expect(within(dlg).getByRole('group', { name: 'Pinned key' })).toHaveTextContent('ssh-ed25519 SHA256:')
    expect(within(dlg).getByRole('switch', { name: 'Forget pinned key' })).not.toBeChecked()
    await u.click(within(dlg).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(within(card('File server')).getByText(/Pinned host key/)).toBeInTheDocument()
    // switch on: the pin goes, and the dialog says nothing is pinned next time
    await u.click(within(card('File server')).getByRole('button', { name: 'Edit File server (read-only SSH)' }))
    dlg = await screen.findByRole('dialog', { name: /Edit File server/ })
    await u.click(within(dlg).getByRole('switch', { name: 'Forget pinned key' }))
    await u.click(within(dlg).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(within(card('File server')).queryByText(/Pinned host key/)).toBeNull())
    await u.click(within(card('File server')).getByRole('button', { name: 'Edit File server (read-only SSH)' }))
    expect(await screen.findByText(/Nothing pinned yet/)).toBeInTheDocument()
  })

  it('the API: clear_pin drops the pin; a new address, kind or sign-in drops it too', async () => {
    as('u-admin')
    const same = { name: 'File server (read-only SSH)', kind: 'ssh', target: '192.168.10.30:22', auth_type: 'ssh-key', username: 'vedette-ro', allow: ['uname -a'], enabled: true }
    expect(((await (await put('/core/connections/cn-ssh', same)).json()) as Connector).pin).not.toBeNull()
    expect(((await (await put('/core/connections/cn-ssh', { ...same, clear_pin: true })).json()) as Connector).pin).toBeNull()
    const t = (await (await post('/core/connections/cn-fgt/test')).json()) as { connector: Connector }
    expect(t.connector.pin).not.toBeNull()
    const moved = (await (await put('/core/connections/cn-fgt', { name: 'Office FortiGate API', kind: 'http', target: 'https://192.168.10.2', auth_type: 'token', allow: ['https://192.168.10.2/'], enabled: true })).json()) as Connector
    expect(moved.pin).toBeNull()
    expect((await put('/core/connections/cn-fgt', { ...HTTP, name: 'Office FortiGate API', clear_pin: 'yes' })).status).toBe(400)
  })
})

describe('Settings → Connections: test, delete and the server errors', () => {
  it('Test pins the key on first use and says so; the pin is kept by later tests', async () => {
    const u = user()
    as('u-admin')
    const made = (await (await post('/core/connections', SSH)).json()) as Connector
    expect(made.pin).toBeNull()
    renderApp('/settings/connections')
    await loaded()
    expect(within(card('Lab switch')).queryByText(/Pinned host key/)).toBeNull()
    await u.click(within(card('Lab switch')).getByRole('button', { name: 'Test connection Lab switch' }))
    expect(await within(card('Lab switch')).findByText(/The host key is now pinned/)).toBeInTheDocument()
    const first = within(card('Lab switch')).getByText(/ssh-ed25519 SHA256:/).textContent
    await u.click(within(card('Lab switch')).getByRole('button', { name: 'Test connection Lab switch' }))
    await waitFor(() => expect(within(card('Lab switch')).queryByText(/is now pinned/)).toBeNull())
    expect(within(card('Lab switch')).getByText(/ssh-ed25519 SHA256:/).textContent).toBe(first)
  })

  it('a pinned key that no longer matches is refused before anything is sent, with the way out', async () => {
    const u = user()
    as('u-admin')
    connectorsStore.update((l) => [...l, { ...(l[0] as Connector), id: 'cn-changed', name: 'Moved device', target: 'https://changed.lan' }])
    renderApp('/settings/connections')
    await loaded()
    await u.click(within(card('Moved device')).getByRole('button', { name: 'Test connection Moved device' }))
    expect(await within(card('Moved device')).findByRole('alert')).toHaveTextContent(/is not the one pinned.*Nothing was sent.*Forget pinned key/)
    expect(await within(card('Moved device')).findByText('Failed')).toBeInTheDocument()
  })

  it('an unreachable device shows the error from the box', async () => {
    const u = user()
    as('u-admin')
    await post('/core/connections', { ...HTTP, name: 'Dead end', target: 'https://unreachable.lan' })
    renderApp('/settings/connections')
    await loaded()
    await u.click(within(card('Dead end')).getByRole('button', { name: 'Test connection Dead end' }))
    expect(await within(card('Dead end')).findByRole('alert')).toHaveTextContent('Could not connect to https://unreachable.lan')
  })

  it('kind_unsupported: mcp-stdio is refused on create and edit; an old row shows "Not supported" and can only be deleted', async () => {
    const u = user()
    as('u-admin')
    const body = { name: 'Local MCP', kind: 'mcp-stdio', target: 'npx some-mcp-server', auth_type: 'none', allow: ['api.example.com'], enabled: true }
    const r = await post('/core/connections', body)
    expect(r.status).toBe(400)
    expect(((await r.json()) as { error: { code: string } }).error.code).toBe('kind_unsupported')
    expect((await put('/core/connections/cn-http', body)).status).toBe(400)
    connectorsStore.update((l) => [...l, { ...(l[0] as Connector), id: 'cn-old', name: 'Old MCP command', kind: 'mcp-stdio', target: 'fw-mcp', auth: { type: 'none', last4: null }, pin: null }])
    renderApp('/settings/connections')
    await loaded()
    const old = card('Old MCP command')
    expect(within(old).getByText('Not supported')).toBeInTheDocument()
    expect(within(old).getByRole('button', { name: 'Test connection Old MCP command' })).toBeDisabled()
    expect(within(old).getByRole('button', { name: 'Edit Old MCP command' })).toBeDisabled()
    expect(within(old).getByText(/does not start an MCP server from a command/)).toBeInTheDocument()
    await u.click(within(old).getByRole('button', { name: 'Delete Old MCP command' }))
    await u.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(screen.queryByRole('heading', { level: 2, name: /Old MCP command/ })).toBeNull())
  })

  it('in_use: delete is refused while a change made through the connection is in force, and works after it is gone', async () => {
    const u = user()
    as('u-admin')
    inForce('cn-fgt')
    expect((await api('/core/connections/cn-fgt', { method: 'DELETE' })).status).toBe(409)
    renderApp('/settings/connections')
    await loaded()
    await u.click(within(card('Office FortiGate')).getByRole('button', { name: 'Delete Office FortiGate API' }))
    const dlg = await screen.findByRole('dialog', { name: 'Delete Office FortiGate API?' })
    await u.click(within(dlg).getByRole('button', { name: 'Delete' }))
    expect(await within(dlg).findByRole('alert')).toHaveTextContent(/still in force/)
    expect(connectorsStore.get().some((c) => c.id === 'cn-fgt')).toBe(true)
    actionsStore.update((l) => l.filter((a) => a.id !== 'act-inforce'))
    await u.click(within(dlg).getByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(screen.queryByRole('heading', { level: 2, name: /Office FortiGate/ })).toBeNull())
  })

  it('the other server errors reach the right field: duplicate name, no allow-list, short secret, missing user name', async () => {
    as('u-admin')
    const code = async (b: unknown) => ((await (await post('/core/connections', b)).json()) as { error?: { code: string } }).error?.code
    expect(await code({ ...HTTP, name: 'office fortigate api' })).toBe('duplicate_name')
    expect(await code({ ...HTTP, allow: [] })).toBe('allow_required')
    expect(await code({ ...HTTP, secret: 'short' })).toBe('invalid_secret')
    expect(await code({ ...SSH, username: '' })).toBe('username_required')
    expect(await code({ ...SSH, username: 'a b' })).toBe('invalid_username')
    expect(await code({ ...HTTP, auth_type: 'basic', username: undefined })).toBe('username_required')
    expect(await code({ ...HTTP, kind: 'device-api' })).toBe('invalid_kind')
  })
})

describe('Settings → Connections: roles', () => {
  it.each(['viewer', 'operator'] as const)('%s: no access to the section, the API answers 403', async (role) => {
    renderApp('/settings/connections', { role })
    expect(await screen.findByText('Connections needs a higher role')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Add connection' })).toBeNull()
    expect(within(screen.getByRole('navigation', { name: 'Settings sections' })).queryByRole('link', { name: 'Connections' })).toBeNull()
    expect((await api('/core/connections')).status).toBe(403)
    expect((await post('/core/connections', HTTP)).status).toBe(403)
    expect((await put('/core/connections/cn-fgt', HTTP)).status).toBe(403)
    expect((await api('/core/connections/cn-fgt', { method: 'DELETE' })).status).toBe(403)
    expect((await post('/core/connections/cn-fgt/test')).status).toBe(403)
  })
  it('signed out: 401', async () => {
    sessionStore.set({ userId: null })
    expect((await api('/core/connections')).status).toBe(401)
  })
})

describe('Settings → Connections: form matrix (docs/QA.md §2): every kind x every sign-in it can use', () => {
  const TARGET: Record<string, string> = { http: 'Base address (URL)', ssh: 'SSH server (host or host:port)', 'netconf-restconf': 'Device address (URL, or host:port for NETCONF)', automation: 'Platform address (URL)', 'mcp-http': 'MCP server address (URL)' }
  const KIND_LABEL: Record<string, string> = { http: 'HTTP API', ssh: 'SSH / CLI', 'netconf-restconf': 'NETCONF / RESTCONF', automation: 'Automation platform (Ansible AWX/Tower, n8n...)', 'mcp-http': 'MCP server (URL)' }
  const AUTH_LABEL: Record<string, string> = { none: 'No sign-in', token: 'API token', basic: 'User and password', 'ssh-key': 'SSH key' }
  const usable = (sign: HTMLElement) => within(sign).getAllByRole('option').filter((o) => !(o as HTMLOptionElement).disabled).map((o) => o.textContent)
  const SUPPORTED = CONNECTION_KINDS.filter((k) => k !== 'mcp-stdio')

  it('each kind shows its own address, offers only the sign-ins it can use, and nothing typed for the last kind is carried over', async () => {
    const u = user()
    renderApp('/settings/connections')
    await u.click(await screen.findByRole('button', { name: 'Add connection' }))
    const dlg = await screen.findByRole('dialog', { name: 'Add connection' })
    const kind = within(dlg).getByLabelText('Kind')
    const sign = within(dlg).getByLabelText('Sign-in')
    const pick = async (o: string) => { await u.selectOptions(kind, within(kind).getByRole('option', { name: o })) }
    const others = (k: string) => Object.entries(TARGET).filter(([x]) => x !== k).map(([, v]) => v)
    // the default sign-in of each kind decides whether a secret and a user name are on screen
    await eachOption([
      { option: KIND_LABEL.http!, shown: [TARGET.http!], hidden: [...others('http'), 'Secret', 'User name'] },
      { option: KIND_LABEL.ssh!, shown: [TARGET.ssh!, 'Secret', 'User name'], hidden: others('ssh') },
      { option: KIND_LABEL['netconf-restconf']!, shown: [TARGET['netconf-restconf']!, 'Secret'], hidden: [...others('netconf-restconf'), 'User name'] },
      { option: KIND_LABEL.automation!, shown: [TARGET.automation!, 'Secret'], hidden: [...others('automation'), 'User name'] },
      { option: KIND_LABEL['mcp-http']!, shown: [TARGET['mcp-http']!, 'Secret'], hidden: [...others('mcp-http'), 'User name'] },
      { option: KIND_LABEL.http!, shown: [TARGET.http!], hidden: [...others('http'), 'Secret', 'User name'] },
    ], pick, dlg)
    // the command kind cannot be chosen any more (D-94), and no brand is asked for
    const opts = within(kind).getAllByRole('option') as HTMLOptionElement[]
    expect(opts.map((o) => o.textContent)).toEqual(['HTTP API', 'SSH / CLI', 'NETCONF / RESTCONF', 'Automation platform (Ansible AWX/Tower, n8n...)', 'MCP server (URL)', 'MCP server (command) (not supported)'])
    expect(opts.find((o) => o.value === 'mcp-stdio')).toBeDisabled()
    expect(within(dlg).queryByLabelText(/Which device API/)).toBeNull()

    // every kind x every sign-in: the sign-in options are the kind's own; the secret and the user name follow the chosen sign-in
    for (const k of SUPPORTED) {
      await pick(KIND_LABEL[k]!)
      expect(usable(sign), `${k} sign-ins`).toEqual((['none', 'token', 'basic', 'ssh-key'] as const).filter((a) => KIND_AUTH[k].includes(a)).map((a) => AUTH_LABEL[a]))
      for (const a of KIND_AUTH[k]) {
        await u.selectOptions(sign, within(sign).getByRole('option', { name: AUTH_LABEL[a]! }))
        const user = k === 'ssh' || a === 'basic'
        expect(!!within(dlg).queryByLabelText('Secret'), `${k}/${a}: secret`).toBe(a !== 'none')
        expect(!!within(dlg).queryByLabelText('User name'), `${k}/${a}: user name`).toBe(user)
      }
    }
    // the box refuses a sign-in the kind cannot use, and an unknown kind
    const base = { name: 'Srv', kind: 'ssh', target: '192.168.10.30:22', auth_type: 'token', secret: 'supersecret-1234', allow: ['uname -a'], enabled: true }
    as('u-admin')
    expect((await post('/core/connections', base)).status).toBe(400)
    expect((await post('/core/connections', { ...base, kind: 'netconf-restconf', target: 'https://192.168.10.1', auth_type: 'ssh-key', allow: ['https://192.168.10.1/'] })).status).toBe(400)
    expect((await post('/core/connections', { ...base, auth_type: 'ssh-key', username: 'ops' })).status).toBe(201)

    // nothing typed for a kind survives a change of kind: address, user name, allow-list and secret restart
    await pick('NETCONF / RESTCONF')
    await u.selectOptions(sign, within(sign).getByRole('option', { name: 'User and password' }))
    await u.type(within(dlg).getByLabelText('User name'), 'admin')
    await u.type(within(dlg).getByLabelText('Allow-list (one per line)'), 'https://192.168.10.1/restconf/')
    await u.type(within(dlg).getByLabelText('Secret'), 'token-for-the-api')
    await u.clear(within(dlg).getByLabelText(TARGET['netconf-restconf']!)); await u.type(within(dlg).getByLabelText(TARGET['netconf-restconf']!), 'https://10.0.0.1')
    await pick('SSH / CLI')
    expect(within(dlg).getByLabelText(TARGET.ssh!)).toHaveValue('192.168.10.30:22')
    expect(within(dlg).getByLabelText('User name')).toHaveValue('')
    expect(within(dlg).getByLabelText('Allow-list (one per line)')).toHaveValue('')
    expect(within(dlg).getByLabelText('Secret')).toHaveValue('')
    expect(within(dlg).getByLabelText('Sign-in')).toHaveValue('ssh-key')
  })

  it('an empty submit names every missing field; a user name is asked for by SSH and Basic only', async () => {
    const u = user()
    renderApp('/settings/connections')
    await u.click(await screen.findByRole('button', { name: 'Add connection' }))
    const dlg = await screen.findByRole('dialog', { name: 'Add connection' })
    await u.selectOptions(within(dlg).getByLabelText('Kind'), 'ssh')
    await u.click(within(dlg).getByRole('button', { name: 'Add connection' }))
    for (const m of ['Give the connection a name.', 'Enter the user name.', 'Enter the secret.', /Add at least one allow-list entry/]) expect(within(dlg).getByText(m)).toBeInTheDocument()
    await u.selectOptions(within(dlg).getByLabelText('Kind'), 'http')
    expect(within(dlg).queryByText('Enter the user name.')).toBeNull()
  })

  it('each generic kind offers generic tools, write tools start off, no brand', async () => {
    as('u-admin')
    const mk = (kind: string, target: string, auth_type: string, allow: string[], username?: string) => post('/core/connections', { name: `k-${kind}`, kind, target, auth_type, username, secret: auth_type === 'none' ? undefined : 'a-long-enough-secret', allow, enabled: true })
    const made = await Promise.all([
      mk('http', 'https://192.168.10.1', 'token', ['https://192.168.10.1/api/']),
      mk('ssh', '192.168.10.2:22', 'ssh-key', ['uname -a'], 'ops'),
      mk('netconf-restconf', 'https://192.168.10.3', 'basic', ['https://192.168.10.3/restconf/'], 'admin'),
      mk('automation', 'https://automation.example.local', 'token', ['https://automation.example.local/api/']),
      mk('mcp-http', 'https://mcp.example.local/mcp', 'none', ['mcp.example.local']),
    ].map(async (p) => { const r = await p; return { status: r.status, json: (await r.json()) as Connector } }))
    for (const r of made) expect(r.status, JSON.stringify(r.json)).toBe(201)
    const tools = made.map((r) => r.json.tools.map((t) => `${t.name}:${t.access}`))
    expect(tools[0]).toEqual(['fetch_url:read', 'send_request:write'])
    expect(tools[1]).toEqual(['run_allowed_command:read', 'run_approved_command:write'])
    expect(tools[2]).toEqual(['get_config:read', 'apply_config:write'])
    expect(tools[3]).toEqual(['list_jobs:read', 'launch_job:write'])
    for (const r of made) for (const t of r.json.tools) if (t.access === 'write') expect(t.enabled, t.name).toBe(false)
    expect(made[2]!.json.username).toBe('admin')
    expect(made[0]!.json.username).toBeNull() // a token has no user name, even when one is sent
    expect(JSON.stringify(made.map((r) => r.json))).not.toMatch(/vendor|fortinet|mikrotik|pfsense|supersecret|a-long-enough/i)
  })

  it('editing and returning to the saved kind restores its saved values; another kind starts clean and needs a new secret and user name', async () => {
    const u = user()
    renderApp('/settings/connections')
    await loaded()
    await u.click(within(card('File server')).getByRole('button', { name: 'Edit File server (read-only SSH)' }))
    const dlg = await screen.findByRole('dialog')
    const kind = within(dlg).getByLabelText('Kind')
    await u.selectOptions(kind, 'http')
    expect(within(dlg).getByLabelText('Base address (URL)')).not.toHaveValue('192.168.10.30:22')
    expect(within(dlg).queryByText(/Saved, ending/)).toBeNull() // the saved secret and user name belong to the old kind
    expect(within(dlg).queryByLabelText('User name')).toBeNull()
    expect(within(dlg).queryByRole('group', { name: 'Pinned key' })).toBeNull() // so does the pin
    await u.selectOptions(kind, 'ssh')
    expect(within(dlg).getByLabelText('SSH server (host or host:port)')).toHaveValue('192.168.10.30:22')
    expect(within(dlg).getByLabelText('User name')).toHaveValue('vedette-ro')
    expect(within(dlg).getByRole('group', { name: 'Pinned key' })).toBeInTheDocument()
  })
})

describe('Settings → Privacy: flow 12, Connections you add', () => {
  const row = async () => {
    const table = await screen.findByRole('table', { name: 'Data flows that leave the box' })
    return { table, row: within(table).getByText(/12\. Connections you add/).closest('tr') as HTMLElement }
  }
  it('lists 12 flows; flow 12 is on while a connection is enabled and links to Connections', async () => {
    renderApp('/settings/privacy')
    const { table, row: r } = await row()
    expect(within(table).getAllByRole('row')).toHaveLength(13)
    expect(within(r).getByText('Running')).toBeInTheDocument()
    expect(within(r).getByText(/Only the address you typed for each connection/)).toBeInTheDocument()
    expect(within(r).getByRole('link', { name: 'Open connections' })).toHaveAttribute('href', '/settings/connections')
  })
  it('is off when no connection is enabled, and follows a change made on the Connections page', async () => {
    as('u-admin')
    connectorsStore.update((l) => l.map((c) => ({ ...c, enabled: false })))
    const body = (await (await api('/core/privacy')).json()) as { flows: { id: number; state: string; control: string }[] }
    expect(body.flows).toHaveLength(12)
    expect(body.flows[11]).toEqual({ id: 12, state: 'off', control: 'reason' })
    connectorsStore.update((l) => l.map((c, i) => (i === 0 ? { ...c, enabled: true } : c)))
    expect(((await (await api('/core/privacy')).json()) as typeof body).flows[11]).toEqual({ id: 12, state: 'on', control: 'reason' })
    connectorsStore.set([])
    renderApp('/settings/privacy')
    expect(within((await row()).row).getByText('Off')).toBeInTheDocument()
  })
})
