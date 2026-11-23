// S-CORE-1: what the v1 GUI shows of the preview modules and of the modules left out of v1.
import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp, expectNoA11yViolations, mainNavLink } from '@/test/render'
import { modulesStore, sessionStore } from '@/mocks/stores'
import { server } from '@/test/server'
import { MOCK_SETUP_CODE } from './mocks'
import { saveSsoFlow } from './ssoFlow'

const setModule = (id: string, enabled: boolean) => modulesStore.update((l) => l.map((m) => (m.id === id ? { ...m, enabled } : m)))
const mainNav = () => screen.getByRole('navigation', { name: 'Main navigation' })
const settingsNav = () => screen.getByRole('navigation', { name: 'Settings sections' })
const LEAVING = 'This feature is not part of this release. Its settings are kept and shown read-only.'
const BADGE = 'Not in this release'

describe('preview modules (#818)', () => {
  it('a preview module that is on has a Preview badge in the nav, on its Settings → Modules row and on its page header; a v1 module has none', async () => {
    renderApp('/honeypot')
    const traps = await within(await screen.findByRole('navigation', { name: 'Main navigation' })).findByRole('link', { name: 'Internal traps Preview' })
    expect(within(traps).getByText('Preview')).toBeInTheDocument()
    expect(await mainNavLink(/^Devices( \d+ to review)?$/)).toBeInTheDocument() // v1: no Preview badge in its name (a count may follow)
    const header = (await screen.findByRole('heading', { level: 1 })).closest('header')!
    expect(within(header).getByText('Preview')).toBeInTheDocument()
    expect(within(header).queryByText(/v1/)).toBeNull() // the badge only: no release-planning words
  })

  it('Settings → Modules: the preview row has the badge, a v1 row has none', async () => {
    renderApp('/settings/modules')
    const traps = (await screen.findByRole('switch', { name: 'Turn off module Internal traps' })).closest('tr')!
    expect(within(traps).getByText('Preview')).toBeInTheDocument()
    expect(within(traps).queryByText(/v1/)).toBeNull()
    const devices = screen.getByRole('switch', { name: 'Turn off module Inventory' }).closest('tr')!
    expect(within(devices).queryByText('Preview')).toBeNull()
    expect(within(screen.getByRole('switch', { name: /module Vulnerability scan$/ }).closest('tr')!).getByText('Preview')).toBeInTheDocument()
    await expectNoA11yViolations()
  })
})

describe('modules that are not part of this release', () => {
  it('off: absent from the nav, Settings → Modules, the Settings menu, Users (SSO) and Incidents (Respond); a direct link says it is not available', async () => {
    setModule('response', false) // mcp-server, auth-oidc and scan-credentialed are off in the mock already
    const u = userEvent.setup()
    renderApp('/settings/modules')
    await screen.findByRole('switch', { name: 'Turn off module Internal traps' })
    for (const n of ['AI response', 'MCP server', 'SSO sign-in', 'Credentialed scan']) expect(screen.queryByText(n)).toBeNull()
    expect(within(mainNav()).queryByRole('link', { name: /Response/ })).toBeNull()
    expect(within(settingsNav()).queryByRole('link', { name: /AI response/ })).toBeNull()
    expect(within(settingsNav()).queryByRole('link', { name: 'MCP server' })).toBeNull()

    await u.click(within(settingsNav()).getByRole('link', { name: 'Users' }))
    expect(await screen.findByRole('heading', { level: 1, name: /user/i })).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'SSO sign-in (OIDC)' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Turn on SSO sign-in' })).toBeNull()
  })

  it('off: opening its Settings path says it is not available, with no link to turn it on', async () => {
    renderApp('/settings/mcp')
    expect(await screen.findByText('MCP server is not available in this release')).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 1, name: 'MCP server' })).toBeInTheDocument() // the page has its h1
    expect(screen.queryByRole('link', { name: 'Open module settings' })).toBeNull()
    expect(screen.queryByRole('switch', { name: 'MCP server' })).toBeNull()
  })

  it('off: Incidents has no Respond column', async () => {
    setModule('response', false)
    renderApp('/incidents')
    await screen.findByRole('heading', { level: 1 })
    await waitFor(() => expect(screen.getAllByRole('columnheader').length).toBeGreaterThan(2))
    expect(screen.queryByRole('columnheader', { name: 'Respond' })).toBeNull()
    expect(screen.queryByRole('link', { name: /^Respond/ })).toBeNull()
  })

  it('on (a box that turned it on earlier): shown read-only with its note; the only action is turning it off, then it is gone', async () => {
    const u = userEvent.setup()
    renderApp('/settings/modules') // response is on in the mock
    const row = (await screen.findByRole('switch', { name: 'Turn off module AI response' })).closest('tr')!
    expect(within(row).getByText(BADGE)).toBeInTheDocument()
    expect(within(row).getByText(LEAVING)).toBeInTheDocument()
    const nav = await mainNavLink(`Response ${BADGE}`)
    expect(nav).toHaveAttribute('href', '/response')
    expect(within(settingsNav()).getByRole('link', { name: 'AI response (high risk)' })).toBeInTheDocument()

    await u.click(within(row).getByRole('switch', { name: 'Turn off module AI response' }))
    const dlg = await screen.findByRole('dialog', { name: 'Turn off AI response?' })
    await u.click(within(dlg).getByRole('button', { name: 'Turn off' }))
    await waitFor(() => expect(screen.queryByRole('switch', { name: /module AI response$/ })).toBeNull())
    expect(modulesStore.get().find((m) => m.id === 'response')!.enabled).toBe(false)
    await waitFor(() => expect(within(mainNav()).queryByRole('link', { name: /Response/ })).toBeNull())
    expect(within(settingsNav()).queryByRole('link', { name: /AI response/ })).toBeNull()
  })

  it('on: its page header carries the note and the way to Settings → Modules', async () => {
    renderApp('/response')
    const header = (await screen.findByRole('heading', { level: 1 })).closest('header')!
    expect(within(header).getByText(BADGE)).toBeInTheDocument()
    expect(within(header).getByText(LEAVING)).toBeInTheDocument()
    expect(within(header).getByRole('link', { name: 'Turn off in Settings, Modules' })).toHaveAttribute('href', '/settings/modules#module-response') // its own switch
  })

  it('on: MCP server keeps only its off switch; SSO shows its settings without fields and only Turn off SSO', async () => {
    setModule('mcp-server', true)
    setModule('auth-oidc', true)
    const u = userEvent.setup()
    renderApp('/settings/mcp')
    expect(await screen.findByRole('switch', { name: 'Turn off MCP server' })).toBeEnabled()
    expect(screen.getByText(LEAVING)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Create token' })).toBeNull()

    await u.click(within(settingsNav()).getByRole('link', { name: 'Users' }))
    expect(await screen.findByRole('heading', { name: 'SSO sign-in (OIDC)' })).toBeInTheDocument()
    expect(await screen.findByRole('button', { name: 'Turn off SSO' })).toBeEnabled()
    expect(screen.getByText(LEAVING)).toBeInTheDocument()
    expect(screen.queryByLabelText('Issuer')).toBeNull()
    expect(screen.queryByRole('button', { name: 'Save' })).toBeNull()
    await u.click(screen.getByRole('button', { name: 'Turn off SSO' }))
    const dlg = await screen.findByRole('dialog')
    await u.click(within(dlg).getByRole('button', { name: 'Turn off SSO' }))
    await waitFor(() => expect(modulesStore.get().find((m) => m.id === 'auth-oidc')!.enabled).toBe(false))
    await waitFor(() => expect(screen.queryByRole('heading', { name: 'SSO sign-in (OIDC)' })).toBeNull())
  })
})

describe('setup bundles turn on v1 modules only', () => {
  it('the bundle step lists only v1 modules; the custom list labels preview modules and offers no hidden one; Small business leaves every preview module off', async () => {
    const u = userEvent.setup()
    renderApp('/setup', { role: null, setupComplete: false })
    await u.click(await screen.findByRole('checkbox', { name: 'I have read, understood and agree to the terms of use' }))
    await u.click(screen.getByRole('button', { name: 'Continue' }))
    await u.type(await screen.findByLabelText('Setup code'), MOCK_SETUP_CODE)
    await u.type(screen.getByLabelText('Organization name'), 'ABC Company')
    await u.type(screen.getByLabelText('Administrator name'), 'Lan')
    await u.type(screen.getByLabelText('Sign-in email'), 'lan@abc.example')
    await u.type(screen.getByLabelText('Password'), 'a long enough sentence')
    await u.type(screen.getByLabelText('Repeat password'), 'a long enough sentence')
    await u.click(screen.getByRole('button', { name: 'Continue' }))
    const range = await screen.findByLabelText('Range 1')
    await u.clear(range) // the box's own network may be offered there
    await u.type(range, '192.168.10.0/24')
    await u.click(screen.getByRole('checkbox', { name: /I confirm these ranges belong to my company/ }))
    await u.click(screen.getByRole('button', { name: 'Continue' }))
    const small = (await screen.findByRole('radio', { name: /Small business/ })).closest('div')!
    const mid = screen.getByRole('radio', { name: /Mid-size business/ }).closest('div')!
    for (const box of [small, mid]) for (const name of [/Internal traps/, /Reports/, /Vulnerability scan/, /Logs/, /AI assistant/]) expect(within(box).queryByText(name)).toBeNull()
    expect(within(mid).getByText(/External exposure/)).toBeInTheDocument()
    await u.click(screen.getByRole('radio', { name: /Custom/ }))
    expect(await screen.findByRole('checkbox', { name: /^Internal traps Preview/ })).not.toBeChecked()
    for (const hidden of [/AI response/, /MCP server/, /SSO sign-in/, /Credentialed scan/]) expect(screen.queryByRole('checkbox', { name: hidden })).toBeNull()
    await u.click(screen.getByRole('radio', { name: /Small business/ }))
    await u.click(screen.getByRole('button', { name: 'Finish setup' }))
    expect(await screen.findByRole('heading', { level: 1, name: /^Today/ })).toBeInTheDocument()
    const on = new Set(modulesStore.get().filter((m) => m.enabled).map((m) => m.id))
    expect([...on].sort()).toEqual(['core', 'feeds', 'findings', 'inventory', 'mitigation', 'notify', 'sensor-passive'])
  })
})

describe('more entry points of those modules', () => {
  const APPROVE = 'Approve actions from this channel'

  it('channel Approvals: a channel without them has no section; one with them can turn them off, not change its approvers', async () => {
    const u = userEvent.setup()
    renderApp('/settings/channels') // response on in the mock: shown, not offered
    await u.click(await screen.findByRole('button', { name: 'Edit Telegram' }))
    let d = await screen.findByRole('dialog')
    expect(within(d).queryByRole('switch', { name: APPROVE })).toBeNull()
    await u.click(within(d).getByRole('button', { name: 'Cancel' }))
    await u.click(screen.getByRole('button', { name: 'Edit Slack' }))
    d = await screen.findByRole('dialog')
    const sw = within(d).getByRole('switch', { name: APPROVE })
    expect(sw).toBeChecked()
    expect(sw).toBeEnabled()
    expect(within(d).getByRole('button', { name: 'Add' }).matches(':disabled')).toBe(true)
    await u.click(sw)
    expect(sw).not.toBeChecked()
    expect(sw).toBeDisabled() // off again; cannot be turned back on here
  })

  it('trap hits: no Respond while the response module is hidden', async () => {
    setModule('response', false)
    renderApp('/honeypot?tab=hits')
    await screen.findByRole('table', { name: /hit/i })
    expect(screen.queryByRole('columnheader', { name: 'Respond' })).toBeNull()
    expect(screen.queryByRole('link', { name: /^Respond/ })).toBeNull()
  })

  it('a Settings section of a preview module carries the Preview badge', async () => {
    renderApp('/settings/ai')
    const header = (await screen.findByRole('heading', { level: 1 })).closest('header')!
    expect(within(header).getByText('Preview')).toBeInTheDocument()
    expect(within(header).queryByText(/v1/)).toBeNull() // the badge only: no release-planning words
  })

  it('turning off a module this build does not offer says it is hidden once off, and SSO names the people who only sign in through it', async () => {
    setModule('auth-oidc', true)
    const u = userEvent.setup()
    renderApp('/settings/modules')
    await u.click(await screen.findByRole('switch', { name: 'Turn off module SSO sign-in' }))
    const dlg = await screen.findByRole('dialog', { name: 'Turn off SSO sign-in?' })
    expect(within(dlg).queryByText(/Turn it back on any time/)).toBeNull()
    expect(within(dlg).getByText(/cannot be turned on again here/, { selector: '[hidden], [hidden] *' })).toBeInTheDocument()
  })
})

describe('every entry point is gone, and old links land on a plain page', () => {
  const NOT_AVAILABLE = 'AI response is not available in this release'

  it('a box with AI response on: its own nav entry stays, but Incidents has no Respond', async () => {
    renderApp('/incidents') // response is on in the mock
    await screen.findByRole('heading', { level: 1 })
    await waitFor(() => expect(screen.getAllByRole('columnheader').length).toBeGreaterThan(2))
    expect(screen.queryByRole('columnheader', { name: 'Respond' })).toBeNull()
    expect(screen.queryByRole('link', { name: /^Respond/ })).toBeNull()
    expect(await mainNavLink(`Response ${BADGE}`)).toHaveAttribute('href', '/response')
  })

  it('a box with AI response on: the incident page has no Respond button', async () => {
    renderApp('/incidents/al-4')
    expect(await screen.findByRole('heading', { level: 1 })).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Respond' })).toBeNull()
  })

  it('a box with AI response on: trap hits have no Respond link', async () => {
    renderApp('/honeypot?tab=hits')
    await screen.findByRole('table', { name: /hit/i })
    expect(screen.queryByRole('columnheader', { name: 'Respond' })).toBeNull()
    expect(screen.queryByRole('link', { name: /^Respond/ })).toBeNull()
  })

  it('a box with AI response on: the finding page shows no response plan and does not ask for one', async () => {
    const asked: string[] = []
    let modules = false
    server.events.on('response:mocked', ({ request }) => {
      const path = new URL(request.url).pathname
      if (path.endsWith('/modules')) modules = true
      if (path.includes('/response/')) asked.push(path)
    })
    try {
      renderApp('/findings/f-1')
      expect(await screen.findByRole('heading', { level: 1 })).toBeInTheDocument()
      await waitFor(() => expect(modules).toBe(true))
      expect(screen.queryByRole('heading', { name: 'Response plan' })).toBeNull()
      expect(asked).toEqual([])
    } finally { server.events.removeAllListeners() }
  })

  it('off: the AI task routing has no response plan row', async () => {
    setModule('response', false)
    renderApp('/settings/ai')
    const table = await screen.findByRole('table', { name: 'AI job routing' })
    expect(within(table).getByLabelText('Primary profile for Log summaries')).toBeInTheDocument()
    expect(within(table).queryByLabelText('Primary profile for Response plans')).toBeNull()
  })

  it('off: the log download has no response log', async () => {
    setModule('response', false)
    renderApp('/settings/data')
    expect(await screen.findByRole('checkbox', { name: 'Audit log' })).toBeChecked()
    expect(screen.queryByRole('checkbox', { name: 'Response log' })).toBeNull()
  })

  it.each([
    ['/response', 'the response page'],
    ['/response?incident=al-4', 'an old Respond link of an incident'],
    ['/settings/response', 'its Settings section'],
    ['/link/telegram?c=abc', 'a chat approver confirm link'],
  ])('off: %s (%s) shows the not-available page with no way to turn it on', async (path) => {
    setModule('response', false)
    renderApp(path)
    expect(await screen.findByText(NOT_AVAILABLE)).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 1 })).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Open module settings' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Confirm ownership' })).toBeNull()
    expect(screen.queryByRole('region', { name: 'Respond to this incident' })).toBeNull()
  })

  it('the credentialed scan has no tab; its old link opens the first tab', async () => {
    renderApp('/settings/scanning?tab=credentialed')
    expect(await screen.findByRole('tab', { name: 'Engines', selected: true })).toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: 'Credentialed scan' })).toBeNull()
  })

  it('SSO configured and on: the sign-in page keeps its SSO button and the sign-in completes', async () => {
    setModule('auth-oidc', true)
    sessionStore.set({ userId: 'u-admin' })
    const put = await fetch(`${location.origin}/api/v1/core/oidc`, { method: 'PUT', body: JSON.stringify({ issuer: 'https://sso.acme.example', client_id: 'v', client_secret: 'a-long-client-secret', scopes: 'openid email profile', groups_claim: 'groups', default_role: null, role_map: [{ group: 'vedette-operators', role: 'operator' }] }) })
    expect(put.status).toBe(200)
    sessionStore.set({ userId: null })
    const { unmount } = renderApp('/login', { role: null })
    expect(await screen.findByRole('button', { name: 'Sign in with SSO' })).toBeEnabled()
    unmount()
    // what the button starts; the mock identity provider sends the browser straight back to the callback
    const r = await fetch(`${location.origin}/api/v1/auth/oidc/start`, { method: 'POST' })
    expect(r.status).toBe(200)
    const b = (await r.json()) as { authorize_url: string; binding: string }
    saveSsoFlow({ binding: b.binding, next: '/account?tab=sign-in' })
    const back = new URL(b.authorize_url)
    renderApp(back.pathname + back.search, { role: null })
    expect(await screen.findByText(/Your password and two-step sign-in are set at your identity provider/)).toBeInTheDocument()
  })
})
