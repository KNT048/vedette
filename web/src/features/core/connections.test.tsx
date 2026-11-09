// Settings → Connections (D-93, D-94; S-AI-7, S-RESP-4): list, add, edit, delete, test, the errors, the pin, roles, and privacy flow 12.
// The form matrix (docs/QA.md §2): every kind of connection x every sign-in it can use.
import { describe, expect, it } from 'vitest'
import { http } from 'msw'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { eachOption } from '@/test/formMatrix'
import { server } from '@/test/server'
import { actionsStore } from '@/features/response/state'
import { connectorsStore } from '@/mocks/connectors'
import { API } from '@/mocks/http'
import { networkStore } from '@/mocks/network'
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
    expect(within(ssh).getByText(/SSH key SHA256:/)).toBeInTheDocument()
    expect(within(ssh).queryByText(/ending/)).toBeNull()
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
    expect(within(dlg).getByText(/Saved, SHA256:/)).toBeInTheDocument()
    await u.clear(within(dlg).getByLabelText('User name')); await u.type(within(dlg).getByLabelText('User name'), 'auditor')
    await u.click(within(dlg).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(within(card('File server')).getByText(/signs in as auditor/)).toBeInTheDocument())
    expect(within(card('File server')).getByText(/SSH key SHA256:/)).toBeInTheDocument()
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

  it('the API: clear_pin drops the pin; another host or kind drops it too', async () => {
    as('u-admin')
    const same = { name: 'File server (read-only SSH)', kind: 'ssh', target: '192.168.10.30:22', auth_type: 'ssh-key', username: 'vedette-ro', allow: ['uname -a'], enabled: true }
    expect(((await (await put('/core/connections/cn-ssh', same)).json()) as Connector).pin).not.toBeNull()
    expect(((await (await put('/core/connections/cn-ssh', { ...same, clear_pin: true })).json()) as Connector).pin).toBeNull()
    const t = (await (await post('/core/connections/cn-fgt/test')).json()) as { connector: Connector }
    expect(t.connector.pin).not.toBeNull()
    const moved = (await (await put('/core/connections/cn-fgt', { name: 'Office FortiGate API', kind: 'http', target: 'https://192.168.10.2', auth_type: 'token', secret: 'a-new-token-1234', allow: ['https://192.168.10.2/'], enabled: true })).json()) as Connector
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
    await post('/core/connections', { ...HTTP, name: 'Dead end', target: 'https://unreachable.lan', allow: ['https://unreachable.lan/'] })
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
    connectorsStore.update((l) => [...l, { ...(l[0] as Connector), id: 'cn-old', name: 'Old MCP command', kind: 'mcp-stdio', target: 'fw-mcp', auth: { type: 'none', last4: null, key_fingerprint: null }, pin: null }])
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
    expect(await code({ ...SSH, username: 'a b' })).toBe('invalid')
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
  const TARGET: Record<string, string> = { http: 'Base address (URL)', ssh: 'SSH server (host or host:port)', 'netconf-restconf': 'Device address (URL)', automation: 'Platform address (URL)', 'mcp-http': 'MCP server address (URL)' }
  const KIND_LABEL: Record<string, string> = { http: 'HTTP API', ssh: 'SSH / CLI', 'netconf-restconf': 'NETCONF / RESTCONF', automation: 'Automation platform', 'mcp-http': 'MCP server (URL)' }
  const AUTH_LABEL: Record<string, string> = { none: 'No sign-in', token: 'API token', basic: 'User and password', 'ssh-key': 'SSH key' }
  const KEY = 'Private key (OpenSSH or PEM, no passphrase)'
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
      { option: KIND_LABEL.ssh!, shown: [TARGET.ssh!, KEY, 'User name'], hidden: [...others('ssh'), 'Secret'] },
      { option: KIND_LABEL['netconf-restconf']!, shown: [TARGET['netconf-restconf']!, 'Secret'], hidden: [...others('netconf-restconf'), 'User name'] },
      { option: KIND_LABEL.automation!, shown: [TARGET.automation!, 'Secret'], hidden: [...others('automation'), 'User name'] },
      { option: KIND_LABEL['mcp-http']!, shown: [TARGET['mcp-http']!, 'Secret'], hidden: [...others('mcp-http'), 'User name'] },
      { option: KIND_LABEL.http!, shown: [TARGET.http!], hidden: [...others('http'), 'Secret', 'User name'] },
    ], pick, dlg)
    // the command kind cannot be chosen any more (D-94), and no brand is asked for
    const opts = within(kind).getAllByRole('option') as HTMLOptionElement[]
    expect(opts.map((o) => o.textContent)).toEqual(['HTTP API', 'SSH / CLI', 'NETCONF / RESTCONF', 'Automation platform', 'MCP server (URL)', 'MCP server (command) (not supported)'])
    expect(opts.find((o) => o.value === 'mcp-stdio')).toBeDisabled()
    expect(within(dlg).queryByLabelText(/Which device API/)).toBeNull()

    // every kind x every sign-in: the sign-in options are the kind's own; the secret and the user name follow the chosen sign-in
    for (const k of SUPPORTED) {
      await pick(KIND_LABEL[k]!)
      expect(usable(sign), `${k} sign-ins`).toEqual((['none', 'token', 'basic', 'ssh-key'] as const).filter((a) => KIND_AUTH[k].includes(a)).map((a) => AUTH_LABEL[a]))
      for (const a of KIND_AUTH[k]) {
        await u.selectOptions(sign, within(sign).getByRole('option', { name: AUTH_LABEL[a]! }))
        const user = k === 'ssh' || a === 'basic'
        expect(!!within(dlg).queryByLabelText(/^(Secret|Private key)/), `${k}/${a}: secret`).toBe(a !== 'none')
        expect(!!within(dlg).queryByLabelText(KEY), `${k}/${a}: key box`).toBe(a === 'ssh-key')
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
    expect(within(dlg).getByLabelText(TARGET.ssh!)).toHaveValue('') // no sample address is ever put in the field
    expect(within(dlg).getByLabelText('User name')).toHaveValue('')
    expect(within(dlg).getByLabelText('Allow-list (one per line)')).toHaveValue('')
    expect(within(dlg).getByLabelText(KEY)).toHaveValue('')
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
      mk('mcp-http', 'https://mcp.example.local/mcp', 'none', ['https://mcp.example.local/mcp']),
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

// ---- Independent QA of 13b-1 (D-94, D-73, PRIVACY flow 12): what the mock must refuse so the real box and the mock answer alike ----
type Err = { error?: { code: string; message: string; field?: string } }
const answer = async (r: Promise<Response>) => { const res = await r; return { status: res.status, body: (await res.json().catch(() => ({}))) as Err & Record<string, unknown> } }
const create = (b: unknown) => answer(post('/core/connections', b))
const OPENSSH_NONE = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQAAACBkZXZpY2Uta2V5\n-----END OPENSSH PRIVATE KEY-----\n'

describe('Connections: D-94 address policy and HTTPS only', () => {
  it('every HTTP kind refuses an http:// target: 400 invalid_target on the field target, with the reason', async () => {
    as('u-admin')
    for (const kind of ['http', 'netconf-restconf', 'automation', 'mcp-http']) {
      const r = await create({ ...HTTP, name: `plain ${kind}`, kind, target: 'http://192.168.10.50', allow: ['http://192.168.10.50/'] })
      expect(r.status, `${kind} http:// target`).toBe(400)
      expect(r.body.error).toMatchObject({ code: 'invalid_target', field: 'target', message: 'The address must start with https://. Vedette sends sign-in details and changes only over HTTPS.' })
    }
  })

  it('loopback, link-local (metadata), multicast, unspecified, localhost, numeric host names and the box itself are refused at save, as typed and after normalisation', async () => {
    as('u-admin')
    const mgmt = networkStore.get().mgmt.address!
    const urls = ['https://localhost', 'https://LOCALHOST.', 'https://api.localhost', 'https://127.0.0.1', 'https://127.1.2.3', 'https://[::1]', 'https://169.254.169.254', 'https://[fe80::1]', 'https://[ff02::1]', 'https://224.0.0.1', 'https://239.255.255.250', 'https://0.0.0.0', 'https://[::]', 'https://2130706433', 'https://0x7f.1', 'https://192.168.010.001', `https://${mgmt}`]
    for (const [i, target] of urls.entries()) {
      const r = await create({ ...HTTP, name: `bad ${i}`, target, allow: [`${target}/`] })
      expect(r.status, `${target} was accepted: ${JSON.stringify(r.body).slice(0, 120)}`).toBe(400)
      expect(r.body.error?.field, target).toBe('target')
      expect(r.body.error?.message, target).toMatch(/^Vedette never connects to .+\. Enter the address of the device or service itself\.$/)
    }
    expect((await create({ ...HTTP, name: 'box', target: `https://${mgmt}`, allow: [`https://${mgmt}/`] })).body.error?.message).toContain('the box itself')
    expect((await create({ ...HTTP, name: 'lo', target: 'https://127.0.0.1', allow: ['https://127.0.0.1/'] })).body.error?.message).toContain('a loopback address')
    for (const [i, target] of ['localhost:22', '127.0.0.1:22', '169.254.169.254:22', '224.0.0.1:22', '0.0.0.0:22', '2130706433:22', '0x7f.1:22', `${mgmt}:22`].entries()) {
      const r = await create({ ...SSH, name: `bad ssh ${i}`, target })
      expect(r.status, `ssh ${target} was accepted`).toBe(400)
      expect(r.body.error).toMatchObject({ code: 'invalid_target', field: 'target' })
    }
    expect((await create({ ...HTTP, name: 'ok lan', target: 'https://10.1.2.3', allow: ['https://10.1.2.3/'] })).status).toBe(201) // a private range is fine
    expect((await create({ ...HTTP, name: 'ok cloud', target: 'https://mcp.cloud.example.com', allow: ['https://mcp.cloud.example.com/'] })).status).toBe(201) // so is a public name the admin typed
  })

  it('HTTP kinds: an allow-list entry outside the target can never be used and is refused (400 invalid_allow, field allow)', async () => {
    as('u-admin')
    const r = await create({ ...HTTP, allow: ['https://192.168.10.50/api/', 'https://evil.example.com/'] })
    expect(r.status).toBe(400)
    expect(r.body.error).toMatchObject({ code: 'invalid_allow', field: 'allow', message: 'Each allow-list entry must be an address under https://192.168.10.50, for example https://192.168.10.50/api/.' })
    expect((await create({ ...HTTP, allow: ['https://192.168.10.50.evil.example/'] })).status, 'a longer host name is not under the target').toBe(400)
    expect((await create({ ...HTTP, target: 'https://192.168.10.50/api', allow: ['https://192.168.10.50/other/'] })).status, 'another path is not under the target path').toBe(400)
    expect((await create({ ...HTTP, name: 'under path', target: 'https://192.168.10.50/api', allow: ['https://192.168.10.50/api/v2/'] })).status).toBe(201)
    expect((await create({ ...SSH, name: 'ssh commands', allow: ['uname -a'] })).status, 'SSH allow-lists hold commands, not addresses').toBe(201)
    const seed = connectorsStore.get().find((c) => c.id === 'cn-http')!
    expect(seed.allow.every((a) => a.startsWith(`${seed.target}/`)), 'the sample connection obeys its own rule').toBe(true)
  })
})

describe('Connections: SSH keys', () => {
  it('a private key protected by a passphrase is refused at save (400 invalid_secret, field secret)', async () => {
    as('u-admin')
    const openssh = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBxyzAB12\n-----END OPENSSH PRIVATE KEY-----\n'
    const pem = '-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123456789ABCDEF\n\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n'
    const pkcs8 = '-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQI\n-----END ENCRYPTED PRIVATE KEY-----\n'
    for (const [i, secret] of [openssh, pem, pkcs8].entries()) {
      const r = await create({ ...SSH, name: `enc ${i}`, secret })
      expect(r.status, `passphrase key ${i} was accepted`).toBe(400)
      expect(r.body.error).toMatchObject({ code: 'invalid_secret', field: 'secret', message: 'This private key is protected by a passphrase, which Vedette cannot type. Save a copy without one and paste that.' })
    }
    expect((await create({ ...SSH, name: 'plain key', secret: OPENSSH_NONE })).status).toBe(201)
  })

  it('a pasted private key goes into a monospace textarea with its line breaks, and reaches the API unchanged', async () => {
    const u = userEvent.setup()
    let sent: { secret?: string } = {}
    server.use(http.post(`${API}/core/connections`, async ({ request }) => { sent = (await request.clone().json()) as typeof sent })) // reads the body, then lets the mock answer
    renderApp('/settings/connections')
    await u.click(await screen.findByRole('button', { name: 'Add connection' }))
    const dlg = await screen.findByRole('dialog', { name: 'Add connection' })
    await u.selectOptions(within(dlg).getByLabelText('Kind'), 'ssh')
    const key = within(dlg).getByLabelText('Private key (OpenSSH or PEM, no passphrase)') as HTMLTextAreaElement
    expect(key.tagName, 'a one-line input strips the line breaks and Go then finds no PEM block').toBe('TEXTAREA')
    expect(key).toHaveAttribute('spellcheck', 'false'); expect(key).toHaveAttribute('autocomplete', 'off'); expect(key.className).toContain('font-mono')
    await u.type(within(dlg).getByLabelText('Name'), 'Key switch')
    await u.type(within(dlg).getByLabelText(/SSH server/), '192.168.10.44:22')
    await u.type(within(dlg).getByLabelText('User name'), 'ops')
    await u.click(key); await u.paste(OPENSSH_NONE)
    expect(key.value).toContain('\n-----END OPENSSH PRIVATE KEY-----')
    await u.type(within(dlg).getByLabelText('Allow-list (one per line)'), 'show version')
    await u.click(within(dlg).getByRole('button', { name: 'Add connection' }))
    await screen.findByRole('heading', { level: 2, name: /Key switch/ })
    expect(sent.secret).toBe(OPENSSH_NONE)
  })

  it('an SSH key is shown by its fingerprint (SHA256:...), never as "ending ----"; last4 stays null', async () => {
    as('u-admin')
    const r = await create({ ...SSH, name: 'key id', secret: OPENSSH_NONE })
    expect(r.status).toBe(201)
    const auth = (r.body as unknown as Connector).auth
    expect(auth.last4).toBeNull()
    expect(auth.key_fingerprint).toMatch(/^SHA256:[A-Za-z0-9+/]{43}$/)
    expect(((await (await put(`/core/connections/${(r.body as unknown as Connector).id}`, { ...SSH, secret: undefined, name: 'key id' })).json()) as Connector).auth.key_fingerprint, 'a blank key on edit keeps the saved key').toBe(auth.key_fingerprint)
    renderApp('/settings/connections')
    await loaded()
    expect(within(card('key id')).getByText(/^SSH key SHA256:/)).toBeInTheDocument()
    expect(JSON.stringify(r.body)).not.toContain('b3BlbnNz')
  })
})

describe('Connections: MCP tools (D-94 (3), D-93 (4))', () => {
  const MCP = { ...HTTP, name: 'Cloud MCP', kind: 'mcp-http', target: 'https://mcp.example.com/mcp', auth_type: 'none', secret: undefined, allow: ['https://mcp.example.com/mcp'] }
  it('every tool found on the server starts as write and off; the input can mark one read; other kinds refuse an access (400 invalid_tool_access)', async () => {
    as('u-admin')
    const r = await create(MCP)
    expect(r.status).toBe(201)
    const made = r.body as unknown as Connector
    expect(made.tools.length).toBeGreaterThan(0)
    for (const t of made.tools) expect(`${t.name}:${t.access}:${t.enabled ? 'on' : 'off'}`).toBe(`${t.name}:write:off`)
    const first = made.tools[0]!.name
    const p = await answer(put(`/core/connections/${made.id}`, { ...MCP, tools: [{ name: first, enabled: true, access: 'read' }] }))
    expect(p.status).toBe(200)
    const tools = (p.body as unknown as Connector).tools
    expect(tools.find((t) => t.name === first)).toMatchObject({ access: 'read', enabled: true })
    expect(tools.filter((t) => t.name !== first).every((t) => t.access === 'write' && !t.enabled)).toBe(true)
    const other = await answer(put('/core/connections/cn-fgt', { name: 'Office FortiGate API', kind: 'http', target: 'https://192.168.10.1', auth_type: 'token', allow: ['https://192.168.10.1/api/v2/'], enabled: true, tools: [{ name: 'get_virtual_ips', enabled: true, access: 'write' }] }))
    expect(other.status).toBe(400)
    expect(other.body.error).toMatchObject({ code: 'invalid_tool_access', field: 'tools', message: 'Only tools of an MCP server can be marked read or write; the built-in tools of this kind are fixed.' })
  })

  it('the card gives every MCP tool a Read/Write choice that defaults to Write and is saved', async () => {
    const u = userEvent.setup()
    as('u-admin')
    await create(MCP)
    renderApp('/settings/connections')
    await loaded()
    const c = card('Cloud MCP')
    const pick = within(c).getByLabelText('Access of list_resources on Cloud MCP') as HTMLSelectElement
    expect(pick.value).toBe('write')
    await u.selectOptions(pick, 'read')
    await waitFor(() => expect((within(card('Cloud MCP')).getByLabelText('Access of list_resources on Cloud MCP') as HTMLSelectElement).value).toBe('read'))
    expect((within(card('Cloud MCP')).getByLabelText('Access of search_docs on Cloud MCP') as HTMLSelectElement).value).toBe('write')
    expect(within(card('File server')).queryByLabelText(/^Access of/), 'built-in tools are fixed, no choice').toBeNull()
  })
})

describe('Connections: the pin is the identity of the server (D-94)', () => {
  const ssh = () => connectorsStore.get().find((c) => c.id === 'cn-ssh')!
  const sshBody = (over: Record<string, unknown> = {}) => ({ name: ssh().name, kind: 'ssh', target: ssh().target, auth_type: 'ssh-key', username: ssh().username, allow: ssh().allow, enabled: true, ...over })
  it('changing only the sign-in method keeps the pin', async () => {
    as('u-admin')
    const r = await answer(put('/core/connections/cn-ssh', sshBody({ auth_type: 'basic', secret: 'a-new-password-1234' })))
    expect(r.status).toBe(200)
    expect((r.body as unknown as Connector).pin, 'the host key does not belong to the way of signing in').not.toBeNull()
  })
  it('a trailing slash or a path does not change the server; another host or port does, and then the secret must be entered again (400 secret_required)', async () => {
    as('u-admin')
    const fgt = { name: 'Office FortiGate API', kind: 'http', auth_type: 'token', allow: ['https://192.168.10.1/'], enabled: true }
    expect(((await (await put('/core/connections/cn-fgt', { ...fgt, target: 'https://192.168.10.1/' })).json()) as Connector).pin, 'trailing slash').not.toBeNull()
    expect(((await (await put('/core/connections/cn-fgt', { ...fgt, target: 'https://192.168.10.1/api/v2' })).json()) as Connector).pin, 'a path').not.toBeNull()
    for (const target of ['https://192.168.10.1:8443', 'https://192.168.10.2']) {
      const r = await answer(put('/core/connections/cn-fgt', { ...fgt, target, allow: [`${target}/`] }))
      expect(r.status, target).toBe(400)
      expect(r.body.error).toMatchObject({ code: 'secret_required', field: 'secret', message: 'Enter the secret again: the address changed, and a saved secret is only sent to the address it was saved for.' })
    }
    const moved = await answer(put('/core/connections/cn-fgt', { ...fgt, target: 'https://192.168.10.2', allow: ['https://192.168.10.2/'], secret: 'a-token-for-the-new-one' }))
    expect(moved.status).toBe(200)
    expect((moved.body as unknown as Connector).pin).toBeNull()
    const ssh2 = await answer(put('/core/connections/cn-ssh', sshBody({ target: '192.168.10.31:22' })))
    expect(ssh2.body.error?.code, 'SSH host change also needs the key again').toBe('secret_required')
    expect((await answer(put('/core/connections/cn-ssh', sshBody({ target: '192.168.10.30' })))).status, 'port 22 is the default, so the same server').toBe(200)
  })
})

describe('Connections: D-73 the mock answers like the generated backend', () => {
  it('a user name that breaks the schema pattern is 400 invalid on the field username; a missing one is username_required; clear_pin that is not a boolean names its field', async () => {
    as('u-admin')
    const msg = 'The user name is 1 to 64 characters, with no spaces, colons or control characters.'
    for (const username of ['u'.repeat(65), 'lan admin', 'a:b', 'tab\tname', 'zero\u200bwidth']) {
      const r = await create({ ...SSH, name: `u ${username.length}`, username })
      expect(r.status, username).toBe(400)
      expect(r.body.error, username).toMatchObject({ code: 'invalid', field: 'username', message: msg })
    }
    expect((await create({ ...SSH, username: '' })).body.error).toMatchObject({ code: 'username_required', field: 'username' })
    const pin = await answer(put('/core/connections/cn-ssh', { ...SSH, clear_pin: 'yes' }))
    expect(pin.body.error).toMatchObject({ code: 'invalid', field: 'clear_pin' })
  })
})

describe('Connections: a connection that is off sends nothing (PRIVACY flow 12)', () => {
  it('Test on a disabled connection answers 409 connection_off and does not touch it; the Test button is disabled', async () => {
    const u = userEvent.setup()
    as('u-admin')
    connectorsStore.update((l) => l.map((c) => ({ ...c, enabled: false })))
    const flows = ((await (await api('/core/privacy')).json()) as { flows: { id: number; state: string }[] }).flows
    expect(flows.find((f) => f.id === 12)?.state).toBe('off')
    const before = connectorsStore.get().find((c) => c.id === 'cn-ssh')!.last_test
    const r = await answer(post('/core/connections/cn-ssh/test'))
    expect(r.status).toBe(409)
    expect(r.body.error).toMatchObject({ code: 'connection_off', message: 'This connection is turned off, so nothing is sent to it. Turn it on, then test it.' })
    expect(connectorsStore.get().find((c) => c.id === 'cn-ssh')!.last_test).toBe(before)
    renderApp('/settings/connections')
    await loaded()
    expect(within(card('File server')).getByRole('button', { name: 'Test connection File server (read-only SSH)' })).toBeDisabled()
    await u.click(within(card('File server')).getByRole('switch', { name: 'Connection enabled: File server (read-only SSH)' }))
    await waitFor(() => expect(within(card('File server')).getByRole('button', { name: 'Test connection File server (read-only SSH)' })).toBeEnabled())
  })

  it('an old mcp-stdio row can still be turned off, nothing else about it changes, and it never counts for flow 12', async () => {
    as('u-admin')
    connectorsStore.set([{ ...connectorsStore.get()[0]!, id: 'cn-old', name: 'Old MCP', kind: 'mcp-stdio', target: 'fw-mcp', auth: { type: 'none', last4: null, key_fingerprint: null }, pin: null, enabled: true }])
    expect(((await (await api('/core/privacy')).json()) as { flows: { id: number; state: string }[] }).flows[11]!.state, 'an unsupported row sends nothing').toBe('off')
    const off = await answer(put('/core/connections/cn-old', { name: 'Old MCP', kind: 'mcp-stdio', target: 'fw-mcp', auth_type: 'none', allow: ['x'], enabled: false }))
    expect(off.status).toBe(200)
    expect(connectorsStore.get()[0]).toMatchObject({ enabled: false, target: 'fw-mcp', name: 'Old MCP' })
    expect((await answer(put('/core/connections/cn-old', { name: 'Old MCP', kind: 'mcp-stdio', target: 'fw-mcp', auth_type: 'none', allow: ['x'], enabled: true }))).body.error?.code).toBe('kind_unsupported')
  })
})

describe('Connections: the dialog', () => {
  const open = async () => {
    const u = userEvent.setup()
    renderApp('/settings/connections')
    await u.click(await screen.findByRole('button', { name: 'Add connection' }))
    return { u, dlg: await screen.findByRole('dialog', { name: 'Add connection' }) }
  }
  it('a new connection starts with an empty address and the same default sign-in the kind gets when you switch to it', async () => {
    const { u, dlg } = await open()
    expect(within(dlg).getByLabelText('Base address (URL)')).toHaveValue('')
    expect(within(dlg).getByLabelText('Sign-in')).toHaveValue('none')
    await u.selectOptions(within(dlg).getByLabelText('Kind'), 'ssh'); await u.selectOptions(within(dlg).getByLabelText('Kind'), 'http')
    expect(within(dlg).getByLabelText('Sign-in'), 'same default on first open and when switching back').toHaveValue('none')
    expect(within(dlg).getByText(/For example https:\/\/192\.168\.10\.1/)).toBeInTheDocument() // the example lives in the hint only
    await u.click(within(dlg).getByRole('button', { name: 'Add connection' }))
    expect(within(dlg).getByText('Enter where to connect.')).toBeInTheDocument()
    expect(within(dlg).getByLabelText('Name'), 'focus goes to the first wrong field').toHaveFocus()
  })

  it('a server error lands on its field: marked invalid, described by the message, focused; the footer alert stays away', async () => {
    const { u, dlg } = await open()
    await u.type(within(dlg).getByLabelText('Name'), 'Core switch')
    await u.selectOptions(within(dlg).getByLabelText('Kind'), 'ssh')
    await u.type(within(dlg).getByLabelText(/SSH server/), '192.168.10.40:22')
    await u.type(within(dlg).getByLabelText('User name'), 'lan admin')
    await u.type(within(dlg).getByLabelText('Private key (OpenSSH or PEM, no passphrase)'), 'a-long-enough-key')
    await u.type(within(dlg).getByLabelText('Allow-list (one per line)'), 'show vlan brief')
    await u.click(within(dlg).getByRole('button', { name: 'Add connection' }))
    await within(dlg).findByText(/no spaces, colons or control characters/)
    const field = within(dlg).getByLabelText('User name')
    expect(field).toHaveAttribute('aria-invalid', 'true')
    expect(field).toHaveAccessibleDescription(/no spaces, colons or control characters/)
    await waitFor(() => expect(field).toHaveFocus())
    expect(within(dlg).queryByRole('alert')).toBeNull()
  })

  it.each([
    ['target', 'http://192.168.10.50', /must start with https/, 'Base address (URL)'],
    ['allow', 'https://elsewhere.example/', /under https:\/\/192\.168\.10\.50/, 'Allow-list (one per line)'],
    ['name', 'File server (read-only SSH)', /already has this name/, 'Name'],
  ])('an error about the %s is shown under the %s field', async (_f, value, msg, label) => {
    const { u, dlg } = await open()
    await u.type(within(dlg).getByLabelText('Name'), 'Fresh API')
    await u.type(within(dlg).getByLabelText('Base address (URL)'), 'https://192.168.10.50')
    await u.type(within(dlg).getByLabelText('Allow-list (one per line)'), 'https://192.168.10.50/api/')
    const f = within(dlg).getByLabelText(label)
    await u.clear(f); await u.type(f, value)
    if (label === 'Allow-list (one per line)') { /* typed above */ }
    await u.click(within(dlg).getByRole('button', { name: 'Add connection' }))
    await within(dlg).findByText(msg)
    expect(within(dlg).getByLabelText(label)).toHaveAttribute('aria-invalid', 'true')
    expect(within(dlg).queryByRole('alert')).toBeNull()
  })

  it('RESTCONF is HTTPS only: the address label is "Device address (URL)" and the hint says so', async () => {
    const { u, dlg } = await open()
    await u.selectOptions(within(dlg).getByLabelText('Kind'), 'netconf-restconf')
    expect(dlg.querySelector('label[for="cn-target"]')?.textContent).toBe('Device address (URL)')
    expect(within(dlg).getByText(/RESTCONF over HTTPS only/)).toBeInTheDocument()
    expect((await create({ ...HTTP, kind: 'netconf-restconf', target: '192.168.10.2:830', allow: ['192.168.10.2'] })).status).toBe(400)
  })

  it('the automation kind label has no product names; they are in its hint (D-58)', async () => {
    const { u, dlg } = await open()
    expect(within(within(dlg).getByLabelText('Kind')).getByRole('option', { name: 'Automation platform' })).toBeInTheDocument()
    await u.selectOptions(within(dlg).getByLabelText('Kind'), 'automation')
    expect(within(dlg).getByText(/such as Ansible AWX or n8n/)).toBeInTheDocument()
  })

  it('the dialog says what the secret is for, and an edit that moves the address asks for the secret again', async () => {
    const { u, dlg } = await open()
    expect(within(dlg).getByText('The secret is stored encrypted on this box and used only to sign in to the address below.')).toBeInTheDocument()
    await u.click(within(dlg).getByRole('button', { name: 'Cancel' }))
    await u.click(within(card('Office FortiGate')).getByRole('button', { name: 'Edit Office FortiGate API' }))
    const edit = await screen.findByRole('dialog', { name: /Edit Office/ })
    expect(within(edit).getByText(/Saved, ending k9Qe/)).toBeInTheDocument()
    const target = within(edit).getByLabelText('Base address (URL)')
    await u.clear(target); await u.type(target, 'https://192.168.10.9')
    expect(within(edit).queryByText(/Saved, ending/), 'a saved secret is not kept for another address').toBeNull()
    expect(within(edit).queryByRole('group', { name: 'Pinned key' }), 'the pin belongs to the old server').toBeNull()
    await u.clear(within(edit).getByLabelText('Allow-list (one per line)')); await u.type(within(edit).getByLabelText('Allow-list (one per line)'), 'https://192.168.10.9/api/')
    await u.click(within(edit).getByRole('button', { name: 'Save' }))
    expect(await within(edit).findByText('Enter the secret again: the address changed.')).toBeInTheDocument()
  })

  it('the old test result disappears after the connection is edited', async () => {
    const u = userEvent.setup()
    renderApp('/settings/connections')
    await loaded()
    await u.click(within(card('File server')).getByRole('button', { name: 'Test connection File server (read-only SSH)' }))
    expect(await within(card('File server')).findByRole('status')).toBeInTheDocument()
    await u.click(within(card('File server')).getByRole('button', { name: 'Edit File server (read-only SSH)' }))
    await u.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(within(card('File server')).queryByRole('status')).toBeNull()
  })

  it('the pin_mismatch message tells how to forget the pin', async () => {
    as('u-admin')
    connectorsStore.update((l) => [...l, { ...(l[0] as Connector), id: 'cn-changed', name: 'Moved device', target: 'https://changed.lan' }])
    const r = await answer(post('/core/connections/cn-changed/test'))
    expect(r.status).toBe(502)
    expect(r.body.error).toMatchObject({ code: 'pin_mismatch' })
    expect(r.body.error?.message).toContain('turn on "Forget pinned key"')
  })

  it('no string is glued together in the code: the moved-tab sentence and the option suffixes come from i18n', async () => {
    const { dlg } = await open()
    expect(within(within(dlg).getByLabelText('Kind')).getByRole('option', { name: 'MCP server (command) (not supported)' })).toBeDisabled()
    expect(within(within(dlg).getByLabelText('Sign-in')).getByRole('option', { name: 'SSH key (not for this kind)' })).toBeDisabled()
  })
})
