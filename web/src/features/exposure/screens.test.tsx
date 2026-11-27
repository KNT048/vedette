// The exposure screens on the target tree: the tree with whose proof covers what, add and edit in dialogs, rows with first
// and last seen, issue handling in the shared vocabulary, the names of a chosen scope, and a scan stopped through its run.
import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { sessionStore, usersStore } from '@/mocks/stores'
import { exposureTreeRowsStore, exposureTreeStore } from './mocks'
import { TERMS_VERSION } from './contract'

const tree = () => screen.findByRole('table', { name: 'Targets' })
const rowOf = async (table: HTMLElement, text: string) => (await within(table).findByRole('link', { name: text })).closest('tr')!

describe('exposure screens: a replaced IP of the box', () => {
  it('the Ownership tab of an IP the box no longer uses since a new address came says it was replaced, by what and when', async () => {
    try {
      localStorage.setItem('vedette-mock-egress', '198.51.100.9')
      sessionStore.set({ userId: 'u-admin' })
      await fetch(`${location.origin}/api/v1/exposure/box-ip/verify`, { method: 'POST' })
      renderApp('/exposure/xt-14?tab=ownership')
      expect(await screen.findByText(/^Replaced by 198\.51\.100\.9 on .+: no longer scanned unless the box goes out through it again\.$/)).toBeInTheDocument()
    } finally { localStorage.removeItem('vedette-mock-egress') }
  })
})

describe('exposure screens: the target tree', () => {
  it('a name under a domain sits under it and says whose proof covers it; the counts open the target; axe clean', async () => {
    renderApp('/exposure')
    const table = await tree()
    const names = within(table).getAllByRole('row').slice(1).map((r) => within(r).getAllByRole('link')[0]!.textContent)
    expect(names).toEqual(['198.51.100.2', '198.51.100.3', 'example.com', 'git.example.com', 'shop.example.net'])
    const git = await rowOf(table, 'git.example.com')
    expect(git).toHaveTextContent('under example.com')
    expect(git).toHaveTextContent('Covered')
    expect(git).toHaveTextContent('by the proof of example.com')
    expect(within(git).getByRole('link', { name: '2 open issues on git.example.com' })).toHaveAttribute('href', '/exposure/xt-12?tab=issues')
    expect(await rowOf(table, 'shop.example.net')).toHaveTextContent('Needs ownership proof')
    await expectNoA11yViolations()
  })

  it('Add target is a dialog: a name under a proven domain is said to be covered, and the scope chosen is sent', async () => {
    renderApp('/exposure')
    await userEvent.click(await screen.findByRole('button', { name: 'Add target' }))
    const dialog = await screen.findByRole('dialog', { name: 'Add a target' })
    await userEvent.type(within(dialog).getByRole('textbox', { name: 'Domain' }), 'api.example.com')
    expect(within(dialog).getByRole('status')).toHaveTextContent('It goes under example.com, whose ownership proof covers it')
    await userEvent.click(within(dialog).getByRole('radio', { name: /Only api\.example\.com/ }))
    await userEvent.click(within(dialog).getByRole('button', { name: 'Add' }))
    // covered by its parent: no proof to do, so the page opens on its issues, with its place in the tree
    expect(await screen.findByRole('heading', { name: 'api.example.com is ready for its first scan' })).toBeInTheDocument()
    expect(screen.getByText('This name only')).toBeInTheDocument()
    expect(screen.getAllByRole('link', { name: 'example.com' }).map((a) => a.getAttribute('href'))).toEqual(['/exposure/xt-11', '/exposure/xt-11'])
    expect(screen.getByText('Covered')).toBeInTheDocument()
  })
})

describe('exposure screens: a target page', () => {
  it('a target without proof opens on Ownership with its TXT record; Scan now says why it is locked', async () => {
    renderApp('/exposure/xt-13')
    expect(await screen.findByRole('tab', { name: /Ownership/, selected: true })).toBeInTheDocument()
    expect(screen.getByTestId('proof-host')).toHaveTextContent('@ (that is example.net)')
    expect(screen.getByText('vedette-verify=0f3b6c2d9a8e7145')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Scan now' })).toBeDisabled()
    expect(screen.getByText(/Cannot scan yet: shop\.example\.net has no ownership proof/)).toBeInTheDocument()
  })

  it('services and names are rows with first and last seen; a name that is its own target links there', async () => {
    renderApp('/exposure/xt-11?tab=services')
    const services = await screen.findByRole('table', { name: 'Services of example.com' })
    expect(within(services).getAllByRole('row')).toHaveLength(4)
    expect(within(services).getByText('198.51.100.21:25/tcp').closest('tr')).toHaveTextContent('Certificate for mail.example.com')
    await userEvent.click(screen.getByRole('button', { name: 'No longer seen (1)' }))
    expect(within(await screen.findByRole('table', { name: 'Services of example.com' })).getByText('198.51.100.22:443/tcp')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('tab', { name: 'Names' }))
    const names = await screen.findByRole('table', { name: 'Names under example.com' })
    const git = within(names).getByText('git.example.com', { selector: 'span' }).closest('tr')!
    expect(within(git).getByRole('link', { name: 'git.example.com' })).toHaveAttribute('href', '/exposure/xt-12')
    expect(git).toHaveTextContent('Scanned as its own target')
    expect(within(names).getByText('vpn.example.com').closest('tr')).toHaveTextContent(/\d{1,2} \w{3,4} 2026 – \d{1,2} \w{3,4} 2026/)
  })

  it('an open service the last scans could not reach says since when, with what happens to it; one they reached does not', async () => {
    exposureTreeRowsStore.update((r) => ({ ...r, services: { ...r.services, 'xt-11': (r.services['xt-11'] ?? []).map((s) =>
      s.id === 'xs-11-3' ? { ...s, not_reached_since: '2026-11-03T08:00:00.000Z' } : { ...s, not_reached_since: null }) } }))
    renderApp('/exposure/xt-11?tab=services')
    const services = await screen.findByRole('table', { name: 'Services of example.com' })
    const smtp = within(services).getByText('198.51.100.21:25/tcp').closest('tr')!
    expect(smtp).toHaveTextContent('Not reached since 3 Nov 2026')
    expect(within(smtp).getByRole('button', { name: /Not reached since 3 Nov 2026/ })).toHaveAccessibleDescription(/^The last scans could not reach this port from the box\./)
    const https = within(services).getByText('198.51.100.20:443/tcp').closest('tr')!
    expect(https).not.toHaveTextContent('Not reached')
    expect(within(services).getAllByText(/^Not reached since/)).toHaveLength(1)
  })

  it('with the scope "names I choose", picked names are added to the choice', async () => {
    renderApp('/exposure/xt-13?tab=names')
    const names = await screen.findByRole('table', { name: 'Names under shop.example.net' })
    expect(screen.getByText(/shop\.example\.net and 1 chosen name are scanned/)).toBeInTheDocument()
    expect(within(names).getByText('staging.shop.example.net').closest('tr')).toHaveTextContent('Not in scope')
    await userEvent.click(within(names).getByRole('checkbox', { name: 'Select staging.shop.example.net' }))
    await userEvent.click(screen.getByRole('button', { name: 'Scan this name' }))
    await waitFor(() => expect(screen.getByText(/shop\.example\.net and 2 chosen names are scanned/)).toBeInTheDocument())
  })

  it('Edit is a dialog: turning a target off locks Scan now with the reason', async () => {
    renderApp('/exposure/xt-12')
    await userEvent.click(await screen.findByRole('button', { name: 'Edit' }))
    const dialog = await screen.findByRole('dialog', { name: 'Edit git.example.com' })
    await userEvent.click(within(dialog).getByRole('switch', { name: 'Scan this target' }))
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save' }))
    expect(await screen.findByRole('heading', { name: 'git.example.com is turned off: nothing scans it' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Scan now' })).toBeDisabled()
  })

  it('Scan now: the Scans tab reads Scanning while the run is live, and the running scan is its first row', async () => {
    renderApp('/exposure/xt-12', { role: 'operator' })
    await userEvent.click(await screen.findByRole('button', { name: 'Scan now' }))
    const tab = await screen.findByRole('tab', { name: 'Scanning' })
    expect(screen.queryByText(/Surface scan started/)).toBeNull() // no "Running … Open the run" block above the tabs
    await userEvent.click(tab)
    expect(await screen.findByText('Running')).toBeInTheDocument()
    expect(screen.getAllByRole('link').some((l) => /^\/runs\/run-/.test(l.getAttribute('href') ?? ''))).toBe(true)
  })

  it("an administrator's first Scan now asks in a dialog with the sentence it records and the scope; without two-step the server's refusal says what to do", async () => {
    usersStore.update((l) => l.map((u) => (u.id === 'u-admin' ? { ...u, twofa: false } : u)))
    renderApp('/exposure/xt-15?tab=ownership')
    // the mock finds the proof file at this check: the page then offers the first scan, which asks before it records the sentence
    await userEvent.click(await screen.findByRole('button', { name: 'Check' }))
    await userEvent.click(await screen.findByRole('button', { name: 'Scan now' }))
    const dialog = await screen.findByRole('dialog', { name: 'Confirm and scan 198.51.100.3' })
    expect(dialog).toHaveTextContent('my company owns 198.51.100.3')
    expect(dialog).toHaveAccessibleDescription(/non-intrusive/)
    await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('dialog')).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Scan now' }))
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Confirm and scan' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Turn on two-step sign-in for your account before the first scan of 198.51.100.3')
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('Deep scan now asks once, with the warning about the load on the router or firewall in front of the target; Cancel starts nothing', async () => {
    renderApp('/exposure/xt-14', { role: 'operator' })
    await userEvent.click(await screen.findByRole('button', { name: 'Deep scan now' }))
    const dialog = await screen.findByRole('dialog', { name: 'Deep scan 198.51.100.2' })
    expect(dialog).toHaveTextContent('A deep scan can put a heavy load on the router or firewall in front of the target (for example a CPU spike) while it runs.')
    expect(dialog).toHaveAccessibleDescription('Deep scan: the testing terms of this IP are accepted. Disruptive checks are included.')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(screen.queryByRole('tab', { name: 'Scanning' })).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Deep scan now' }))
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Start deep scan' }))
    expect(await screen.findByRole('tab', { name: 'Scanning' })).toBeInTheDocument()
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(screen.queryAllByText(/heavy load on the router or firewall/)).toHaveLength(0) // shown at that moment only, not on the page
  })

  it('a deep scan of a domain says which addresses get the disruptive checks: only the box\'s own; a domain on hosting gets no "included" claim', async () => {
    exposureTreeStore.update((l) => l.map((n) => (n.id === 'xt-11' ? { ...n, terms: { ...n.terms!, version: TERMS_VERSION, disruptive: true } } : n)))
    const { unmount } = renderApp('/exposure/xt-11', { role: 'operator' })
    await userEvent.click(await screen.findByRole('button', { name: 'Deep scan now' }))
    const dialog = await screen.findByRole('dialog', { name: 'Deep scan example.com' })
    await waitFor(() => expect(dialog).toHaveAccessibleDescription('Deep scan: the testing terms of this domain are accepted. Disruptive checks run only on 198.51.100.2 (this box\'s own address); the other addresses get the deep scan without them.'))
    unmount()
    // the same domain on a hosting provider: none of its addresses is the box's own
    exposureTreeRowsStore.update((r) => ({ ...r, addresses: { ...r.addresses, 'xt-11': (r.addresses['xt-11'] ?? []).filter((a) => a.class !== 'box') } }))
    renderApp('/exposure/xt-11', { role: 'operator' })
    await userEvent.click(await screen.findByRole('button', { name: 'Deep scan now' }))
    const hosted = await screen.findByRole('dialog', { name: 'Deep scan example.com' })
    await waitFor(() => expect(hosted).toHaveAccessibleDescription(/Disruptive checks are not included: none of this domain's addresses is this box's own public IP/))
    expect(hosted).not.toHaveAccessibleDescription(/included\./)
    expect(screen.queryByText(/Disruptive checks are included/)).toBeNull()
  })

  it('a domain pointing at a verified typed-in IP: the dialog never calls that address this box\'s own (the disruptive checks never go there)', async () => {
    exposureTreeStore.update((l) => l.map((n) => {
      if (n.id === 'xt-11') return { ...n, terms: { ...n.terms!, version: TERMS_VERSION, disruptive: true } }
      if (n.id === 'xt-15') return { ...n, method: 'ip_file' as const, verified_at: n.created_at } // a VPS the owner added and proved
      return n
    }))
    // the box may port-scan the typed IP, so the domain's scan lists it as kind "box", but it is not the box's own public IP
    exposureTreeRowsStore.update((r) => ({ ...r, addresses: { ...r.addresses, 'xt-11': (r.addresses['xt-11'] ?? []).map((a) => (a.class === 'box' ? { ...a, ip: '198.51.100.3' } : a)) } }))
    renderApp('/exposure/xt-11', { role: 'operator' })
    await userEvent.click(await screen.findByRole('button', { name: 'Deep scan now' }))
    const dialog = await screen.findByRole('dialog', { name: 'Deep scan example.com' })
    await waitFor(() => expect(dialog).toHaveAccessibleDescription(/Disruptive checks are not included: none of this domain's addresses is this box's own public IP/))
    expect(dialog).not.toHaveAccessibleDescription(/this box's own address/)
    expect(screen.queryByText(/198\.51\.100\.3 \(this box's own address/)).toBeNull()
  })
})

describe('exposure screens: issues', () => {
  it('accepting a risk needs a note and a last day; the handled view shows the shared badge and who handled it; reopen brings it back', async () => {
    renderApp('/exposure/xt-11')
    const table = await screen.findByRole('table', { name: 'Issues of example.com' })
    await userEvent.click(within(table).getByRole('button', { name: 'Mark as handled: Content Security Policy (CSP) header not set' }))
    const dialog = await screen.findByRole('dialog', { name: 'Mark the issue as handled' })
    await userEvent.click(within(dialog).getByRole('radio', { name: /Risk accepted/ }))
    await userEvent.click(within(dialog).getByRole('button', { name: 'Mark as handled' }))
    expect(within(dialog).getByText('Write why (at least 3 characters), so the next person understands.')).toBeInTheDocument()
    await userEvent.type(within(dialog).getByRole('textbox', { name: 'Note (required)' }), 'Only reachable through the VPN')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Mark as handled' }))
    expect(within(dialog).getByText('Choose a last day from tomorrow up to one year ahead.')).toBeInTheDocument()
    await userEvent.click(within(dialog).getByRole('button', { name: '90 days' }))
    await userEvent.click(within(dialog).getByRole('button', { name: 'Mark as handled' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    await userEvent.click(screen.getByRole('button', { name: 'Handled (2)' }))
    const handled = await screen.findByRole('table', { name: 'Issues of example.com' })
    const row = within(handled).getByRole('button', { name: 'Content Security Policy (CSP) header not set' }).closest('tr')!
    expect(row.querySelector('[data-status="accepted"]')).toHaveTextContent(/^Risk accepted until \d{1,2} \w{3,4} 20\d\d$/)
    expect(row).toHaveTextContent(/by admin@acme\.example \(\d{1,2} \w{3,4}\): Only reachable through the VPN/)
    await userEvent.click(within(row).getByRole('button', { name: 'Reopen Content Security Policy (CSP) header not set' }))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Open (2)' })).toBeInTheDocument())
  })

  it('several issues are handled at once; the CVEs of an issue show their severity; the details are one click away', async () => {
    renderApp('/exposure/xt-12')
    const table = await screen.findByRole('table', { name: 'Issues of git.example.com' })
    expect(within(table).getByRole('list', { name: 'CVEs of Vulnerable JS library: DOMPurify 3.2.3' })).toHaveTextContent('CVE-2025-26791Medium4.5')
    await userEvent.click(within(table).getByRole('button', { name: 'Vulnerable JS library: DOMPurify 3.2.3' }))
    const detail = await screen.findByRole('dialog', { name: 'Vulnerable JS library: DOMPurify 3.2.3' })
    expect(detail).toHaveTextContent('Update GitLab, which ships the library.')
    expect(detail).toHaveTextContent('https://git.example.com:10443/assets/webpack/main.chunk.js')
    await userEvent.click(within(detail).getByRole('button', { name: 'Close' }))
    await userEvent.click(within(table).getByRole('checkbox', { name: 'Select all 2 issues shown' }))
    await userEvent.click(screen.getByRole('button', { name: 'Mark 2 as handled…' }))
    const dialog = await screen.findByRole('dialog', { name: 'Mark 2 issues as handled' })
    await userEvent.click(within(dialog).getByRole('radio', { name: /Mitigated/ }))
    await userEvent.click(within(dialog).getByRole('button', { name: 'Mark as handled' }))
    expect(await screen.findByText('Marked 2 issues as handled.')).toBeInTheDocument()
    expect(await screen.findByRole('button', { name: 'Handled (2)' })).toBeInTheDocument()
  })

  it('a viewer sees the issues but cannot handle them', async () => {
    renderApp('/exposure/xt-11', { role: 'viewer' })
    const table = await screen.findByRole('table', { name: 'Issues of example.com' })
    expect(within(table).queryByRole('checkbox')).not.toBeInTheDocument()
    expect(within(table).getAllByRole('button', { name: /^Mark as handled: / })[0]).toBeDisabled()
  })
})

describe('exposure screens: deep scan settings', () => {
  const settingsOf = (id: string) => exposureTreeStore.get().find((n) => n.id === id)?.deep_settings
  const openSettings = async () => {
    await userEvent.click(await screen.findByRole('button', { name: 'Deep scan settings' }))
    return screen.findByRole('dialog', { name: /^Deep scan settings: / })
  }
  const base = { dos: false, logins: true, web_active: true, data_change: true, openvas: true, speed: 'normal' as const, skip_ports: [], skip_paths: [], updated_at: null, updated_by: null, problem: null }

  it('a target without saved settings opens with the denial-of-service checks off and everything else on; the Deep scan dialog says so in one line', async () => {
    renderApp('/exposure/xt-14')
    const dialog = await openSettings()
    expect(within(dialog).getByRole('switch', { name: 'Denial-of-service checks' })).not.toBeChecked()
    for (const name of ['Password guessing and default logins', 'Active web attacks', 'Exploit checks that may change data']) expect(within(dialog).getByRole('switch', { name })).toBeChecked()
    expect(within(dialog).getByRole('button', { name: 'Normal' })).toHaveAttribute('aria-pressed', 'true')
    expect(within(dialog).getByText('May slow down or crash a service or device. Off unless you turn it on.')).toBeInTheDocument()
    await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    await userEvent.click(screen.getByRole('button', { name: 'Deep scan now' }))
    expect(await screen.findByTestId('deep-summary')).toHaveTextContent('Denial-of-service checks: off · Normal Change')
  })

  it('Save sends the whole object: speed, ports and paths typed into their own lists', async () => {
    renderApp('/exposure/xt-14')
    const dialog = await openSettings()
    await userEvent.click(within(dialog).getByRole('button', { name: 'Gentle' }))
    await userEvent.type(within(dialog).getByRole('textbox', { name: 'Ports to skip' }), '3389, 22{Enter}')
    await userEvent.type(within(dialog).getByRole('textbox', { name: 'Web paths to skip' }), '/admin/delete')
    await userEvent.click(within(dialog).getByRole('switch', { name: 'Active web attacks' }))
    expect(within(dialog).getByText('Its web checks also need Active web attacks, which is off.')).toBeInTheDocument()
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save settings' })) // the path still in the box is added by Save
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(settingsOf('xt-14')).toMatchObject({ dos: false, logins: true, web_active: false, data_change: true, openvas: true, speed: 'gentle', skip_ports: [22, 3389], skip_paths: ['/admin/delete'] })
    await userEvent.click(screen.getByRole('button', { name: 'Deep scan now' }))
    expect(await screen.findByTestId('deep-summary')).toHaveTextContent('Denial-of-service checks: off · Active web attacks: off · Gentle · 2 ports skipped · 1 path skipped')
  })

  it('the summary line has Change, which closes the confirmation and opens the settings', async () => {
    exposureTreeStore.update((l) => l.map((n) => (n.id === 'xt-14' ? { ...n, deep_settings: { ...base, speed: 'gentle' as const, skip_ports: [22, 80], logins: false } } : n)))
    renderApp('/exposure/xt-14', { role: 'operator' })
    await userEvent.click(await screen.findByRole('button', { name: 'Deep scan now' }))
    const confirm = await screen.findByRole('dialog', { name: 'Deep scan 198.51.100.2' })
    expect(within(confirm).getByTestId('deep-summary')).toHaveTextContent('Denial-of-service checks: off · Password guessing: off · Gentle · 2 ports skipped')
    await userEvent.click(within(confirm).getByRole('button', { name: 'Change' }))
    const dialog = await screen.findByRole('dialog', { name: 'Deep scan settings: 198.51.100.2' })
    expect(screen.queryByRole('dialog', { name: 'Deep scan 198.51.100.2' })).toBeNull()
    expect(within(dialog).getByRole('button', { name: 'Gentle' })).toHaveAttribute('aria-pressed', 'true')
    expect(within(dialog).getByText('22')).toBeInTheDocument()
  })

  it('turning the denial-of-service checks on needs two-step sign-in, with the way there; with it, the change is saved', async () => {
    usersStore.update((l) => l.map((x) => (x.id === 'u-admin' ? { ...x, twofa: false } : x)))
    renderApp('/exposure/xt-14')
    const dialog = await openSettings()
    await userEvent.click(within(dialog).getByRole('switch', { name: 'Denial-of-service checks' }))
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save settings' }))
    const alert = await within(dialog).findByRole('alert')
    expect(alert).toHaveTextContent('Turn on two-step sign-in for your account first')
    expect(within(alert).getByRole('link', { name: 'Turn on two-step sign-in' })).toHaveAttribute('href', '/settings/account?tab=sign-in#two-step')
    expect(settingsOf('xt-14')?.dos ?? false).toBe(false)
    usersStore.update((l) => l.map((x) => (x.id === 'u-admin' ? { ...x, twofa: true } : x)))
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save settings' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(settingsOf('xt-14')?.dos).toBe(true)
  })

  it('a port or path the box would refuse is refused under its field, and nothing is saved', async () => {
    renderApp('/exposure/xt-14')
    const dialog = await openSettings()
    await userEvent.type(within(dialog).getByRole('textbox', { name: 'Ports to skip' }), '70000{Enter}')
    expect(await within(dialog).findByText('"70000" is not a port number (1 to 65535).')).toBeInTheDocument()
    await userEvent.type(within(dialog).getByRole('textbox', { name: 'Web paths to skip' }), 'admin{Enter}')
    expect(await within(dialog).findByText('"admin" does not start with /.')).toBeInTheDocument()
    await userEvent.clear(within(dialog).getByRole('textbox', { name: 'Web paths to skip' }))
    await userEvent.type(within(dialog).getByRole('textbox', { name: 'Web paths to skip' }), '/a*{Enter}')
    expect(await within(dialog).findByText(/holds a character a path cannot have here/)).toBeInTheDocument()
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save settings' }))
    expect(screen.getByRole('dialog', { name: /^Deep scan settings: / })).toBeInTheDocument()
    expect(settingsOf('xt-14')).toBeUndefined()
  })

  it('groups the target cannot run at all are off-limits with the scan bar\'s own reason; OpenVAS says the box switch is off', async () => {
    exposureTreeStore.update((l) => l.map((n) => (n.id === 'xt-14' ? { ...n, origin: 'person' as const } : n))) // a typed-in IP
    renderApp('/exposure/xt-14')
    const dialog = await openSettings()
    for (const name of ['Denial-of-service checks', 'Password guessing and default logins', 'Exploit checks that may change data']) expect(within(dialog).getByRole('switch', { name })).toBeDisabled()
    expect(within(dialog).getAllByText('Disruptive checks are not included: they run only on this box\'s own public IP, and this address was typed in.')).toHaveLength(3)
    expect(within(dialog).getByRole('switch', { name: 'Active web attacks' })).toBeEnabled()
    expect(await within(dialog).findByText(/OpenVAS is turned off for the whole box/)).toBeInTheDocument()
    expect(within(dialog).getByRole('switch', { name: 'OpenVAS for this target' })).toBeDisabled()
  })

  it('a target without accepted testing terms says so, and the disruptive groups are off-limits', async () => {
    renderApp('/exposure/xt-13')
    const dialog = await openSettings()
    expect(within(dialog).getAllByText(/Deep scans need the testing terms of this target to be accepted/).length).toBeGreaterThan(0)
    expect(within(dialog).getByRole('switch', { name: 'Denial-of-service checks' })).toBeDisabled()
  })

  it('anyone but an administrator reads the settings and cannot change them', async () => {
    renderApp('/exposure/xt-14', { role: 'operator' })
    const dialog = await openSettings()
    expect(within(dialog).getByRole('switch', { name: 'Active web attacks' })).toBeDisabled()
    expect(within(dialog).queryByRole('button', { name: 'Save settings' })).toBeNull()
    expect(within(dialog).getByText('Requires Admin role')).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: 'Close' })).toBeInTheDocument()
  })
})
