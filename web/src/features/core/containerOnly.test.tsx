// A container-only install (no vedette-host, D-168) as the GUI sees it (D-381, the 2026-11-12 walk on Docker Desktop):
// install comes from GET /modules, host pages show what the customer does instead and never call the host endpoints,
// the honeypot cannot be turned on and its page claims no coverage, the setup code hint names vedette-core.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp } from '@/test/render'
import { server } from '@/test/server'
import { installStore, modulesStore, sessionStore } from '@/mocks/stores'
import { containerSensorStore } from '@/features/inventory/mocks'
import { MOCK_SETUP_CODE } from './mocks'

const HOST_PATHS = ['/core/updates/os', '/core/data/backups', '/core/data/restore/run', '/core/network']
let calls: string[] = []
beforeEach(() => {
  installStore.set({ kind: 'container' })
  calls = []
  const real = globalThis.fetch
  vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => { calls.push(String(input instanceof Request ? input.url : input)); return real(input, init) })
})
afterEach(() => vi.restoreAllMocks())
const hostCalls = () => calls.filter((u) => HOST_PATHS.some((p) => new URL(u, location.origin).pathname === `/api/v1${p}`))

describe('container-only install (D-381)', () => {
  it('Updates shows the compose commands and no appliance control; Data shows the volume backup; neither calls the host', async () => {
    renderApp('/settings/updates')
    expect(await screen.findByText('Update Vedette')).toBeInTheDocument()
    expect(screen.getAllByText(/docker compose --env-file vedette.env pull/)).not.toHaveLength(0)
    expect(screen.queryByRole('button', { name: /Check for releases|Export|Import/ })).toBeNull()
    renderApp('/settings/data')
    expect(await screen.findAllByText(/vedette_data/)).not.toHaveLength(0)
    expect(screen.queryByRole('button', { name: 'Download backup' })).toBeNull()
    expect(screen.queryByText('Backups on this box')).toBeNull()
    renderApp('/settings/network')
    expect(await screen.findByText(/Prepare the SPAN card on this machine yourself/)).toBeInTheDocument()
    expect(hostCalls()).toEqual([])
  })

  it('Data backup and restore follow the Docker / Podman switch, with the SELinux note for Podman (S-CORE-9 G2)', async () => {
    const u = userEvent.setup()
    renderApp('/settings/data')
    expect(await screen.findByText(/^docker compose --env-file vedette.env stop core/)).toBeInTheDocument()
    expect(screen.queryByText(/SELinux/)).toBeNull()
    await u.click(screen.getByRole('button', { name: 'Podman' }))
    expect(screen.getByText(/^podman compose --env-file vedette.env stop core/)).toBeInTheDocument()
    expect(screen.getByText(/^podman compose --env-file vedette.env create core/)).toBeInTheDocument()
    expect(screen.queryByText(/docker (run|compose)/)).toBeNull()
    expect(screen.getByText(/SELinux/)).toBeInTheDocument()
  })

  it('Updates names the offered release and its notes, with the update and cosign blocks for Docker or Podman and no Apply (S-CORE-9 G4)', async () => {
    const u = userEvent.setup()
    renderApp('/settings/updates')
    expect(await screen.findByText('Vedette 0.9.4 is available. This machine runs 0.9.3.')).toBeInTheDocument()
    expect(screen.getByText(/oversized syslog packets/)).toBeInTheDocument()
    // in the order that is safe: keep, download + minisign, cosign + the digests of vedette.env, and only then pull and up -d
    const items = within(screen.getByRole('list')).getAllByRole('listitem')
    // the list keeps its numbers: the grid is on an inner element, not on the li (QA L3)
    for (const li of items) expect(li.className).toBe('')
    const steps = items.map((li) => li.querySelector('code')!.textContent!)
    expect(steps.map((c) => c.split(/[ =]/)[0])).toEqual(['mkdir', 'u', 'cosign', 'docker'])
    // all four files of the running release go to a NEW folder named after it: mkdir without -p refuses an existing one (D-451)
    const four = 'vedette.env compose.yaml compose.sensors.yaml compose.syslog.yaml'
    expect(steps[0]).toBe(`mkdir vedette-0.9.3 && mv -n ${four} vedette-0.9.3/`)
    // a kept folder already there holds the good files: put them back before moving it aside (QA r2), never rename it alone
    const keep = [...items[0]!.querySelectorAll('code')].map((c) => c.textContent)
    expect(keep[1]).toBe('cp vedette-0.9.3/* .\nmv vedette-0.9.3 vedette-0.9.3-before')
    expect(within(items[0]!).getByText(/If vedette-0\.9\.3 is already there .*first put its files back, then rename it, and run this step again/)).toBeInTheDocument()
    expect(within(items[0]!).getByText('Only if vedette-0.9.3 is already there')).toBeInTheDocument()
    // the four files and their signatures of the offered version, from the release assets; the loop stops at the first failure
    expect(steps[1]).toBe(`u=https://github.com/KNT048/vedette/releases/download/v0.9.4\nfor f in ${four}; do curl -fsSLO "$u/$f" && curl -fsSLO "$u/$f.minisig" || { echo "download failed: $f"; break; }; done`)
    // each file's signed comment must be exactly "file:<that file> version:<offered>" (minisign -VQm prints only that comment)
    const fetch = items[1]!
    const codes = [...fetch.querySelectorAll('code')].map((c) => c.textContent)
    expect(codes[1]).toBe(`for f in ${four}; do [ "$(minisign -VQm "$f" -p vedette.pub)" = "file:$f version:0.9.4" ] && echo "$f ok" || { echo "$f FAILED: stop"; break; }; done`)
    expect(within(fetch).getByText(/the vedette\.pub you kept from the install \(in this folder, not one taken from the release page\)/)).toBeInTheDocument()
    expect(within(fetch).getByText(/At the first FAILED, stop/)).toBeInTheDocument()
    // every block has a label (QA L4)
    for (const name of ['Keep the files you run now', 'Download the files', 'Check the signatures', 'Check that vedette.env names these images', 'Pull the new images and start them', 'Put the files of vedette-0.9.3 back and start them']) {
      expect(screen.getByText(name, { selector: 'span' })).toBeInTheDocument()
    }
    // the -f files of the add-ons are said before the pull block, in the exact form
    expect(within(items[3]!).getByText(/add -f compose\.yaml -f compose\.sensors\.yaml -f compose\.syslog\.yaml after --env-file vedette\.env in both commands/)).toBeInTheDocument()
    // one line per image this install runs (not the honeypot), by the digest of the release information
    const lines = screen.getByText(/^cosign verify/).textContent!.split('\n')
    expect(lines.map((l) => /vedette-(\w+)@/.exec(l)?.[1])).toEqual(['core', 'sensor', 'scan'])
    for (const l of lines) expect(l).toMatch(/^cosign verify --key cosign\.pub ghcr\.io\/knt048\/vedette-\w+@sha256:[0-9a-f]{64}$/)
    const grep = screen.getByText(/^grep -cF/).textContent!
    for (const l of lines) expect(grep).toContain(`-e '${l.split(' ').at(-1)!}'`)
    expect(screen.getByText(/it must print 3, or do not go on/)).toBeInTheDocument()
    // if a check fails, or later: the way back is a block of its own, copied as it is
    expect(screen.getByText('If any check fails, stop and put your files back.')).toBeInTheDocument()
    expect(screen.getByText(/^cp vedette-0\.9\.3\/\* \. docker compose/).textContent).toBe('cp vedette-0.9.3/* .\ndocker compose --env-file vedette.env pull\ndocker compose --env-file vedette.env up -d')
    expect(screen.getByText(/from vedette-0\.9\.3\/vedette\.env into the new vedette\.env/)).toBeInTheDocument()
    // the only address is the release assets of the offered version
    expect(screen.getAllByText(/https?:\/\//).map((e) => e.textContent!.match(/https?:\/\/\S+/g)).flat()).toEqual(['https://github.com/KNT048/vedette/releases/download/v0.9.4'])
    expect(screen.queryByRole('button', { name: /Apply|Roll back|Check for releases/ })).toBeNull()
    expect(screen.queryByText(/System helper/)).toBeNull()
    await u.click(screen.getByRole('button', { name: 'Podman' }))
    expect(screen.getByText(/^podman compose --env-file vedette.env pull/).textContent).toBe('podman compose --env-file vedette.env pull\npodman compose --env-file vedette.env up -d')
    expect(screen.queryByText(/docker compose/)).toBeNull()
    expect(screen.getByText(/^cp vedette-0\.9\.3\/\* \. podman compose/).textContent).toBe('cp vedette-0.9.3/* .\npodman compose --env-file vedette.env pull\npodman compose --env-file vedette.env up -d')
  })

  const offerState = (version: string, running: string, images: { service: string; digest: string }[]) => ({
    channel: 'stable', mode: 'manual', check_enabled: true, last_check: '2026-11-12T00:00:00Z',
    components: [{ id: 'software', kind: 'software', version: running, previous: null, installed_at: '2026-11-01T00:00:00Z', signature: 'unsigned', rollback_restores_data: false }],
    available: [{ component: 'software', version, channel: 'stable', size_kb: 1, note: '', images }],
    history: [], advisories: [], run: null, managed: [], running_revoked: null, stale_since: null,
  })
  const good = (s: string) => ({ service: s, digest: `sha256:${(s === 'core' ? 'c' : 'd').repeat(64)}` })

  it.each([
    ['an offered version with a shell character', '0.9.4;rm', '0.9.3', /The version offered \(0\.9\.4;rm\) or the version this machine runs \(0\.9\.3\) cannot be put into a command as it is/],
    ['a running version that cannot name a folder', '0.9.4', '0.9.3 beta', /or the version this machine runs \(0\.9\.3 beta\) cannot be put into a command/],
    ['an unknown running version', '0.9.4', '', /^This machine's version is not known, so no commands are shown here/],
  ])('Updates shows no command at all for %s, only where the steps are (D-451)', async (_, version, running, said) => {
    server.use(http.get('*/api/v1/core/updates', () => HttpResponse.json(offerState(version, running, [good('core')]))))
    renderApp('/settings/updates')
    expect(await screen.findByText(said)).toBeInTheDocument()
    // an unknown version is said in words, never as "runs ." or "()" (QA r2)
    if (!running) {
      expect(screen.getByText('Vedette 0.9.4 is available. This machine\'s version is not known.')).toBeInTheDocument()
      expect(screen.getByText(/^This machine's version is not known\. Update information last read/)).toBeInTheDocument()
      expect(screen.queryByText(/runs \.|\(\)/)).toBeNull()
    }
    expect(screen.queryByRole('list')).toBeNull()
    expect(screen.queryByText(/mkdir|curl|minisign|cosign verify|grep -cF/)).toBeNull()
  })

  it('Updates puts only a known service with a well-formed digest into a command (D-451)', async () => {
    const images = [good('core'), good('sensor'), { service: 'scan', digest: "sha256:x' ; rm -rf ~ '" }, { service: 'evil', digest: `sha256:${'e'.repeat(64)}` }]
    server.use(http.get('*/api/v1/core/updates', () => HttpResponse.json(offerState('0.9.4', '0.9.3', images))))
    renderApp('/settings/updates')
    const lines = (await screen.findByText(/^cosign verify/)).textContent!.split('\n')
    expect(lines.map((l) => /vedette-(\w+)@/.exec(l)?.[1])).toEqual(['core', 'sensor'])
    expect(screen.getByText(/^grep -cF/).textContent).not.toMatch(/rm -rf|evil/)
    expect(screen.getByText(/it must print 2, or do not go on/)).toBeInTheDocument()
  })

  it.each([
    ['no check has succeeded', { last_check: null }, /No release information yet/],
    ['the check is off', { check_enabled: false }, /The update check is off/],
    ['nothing newer', { last_check: '2026-11-12T00:00:00Z' }, /No newer release is offered to this install\./],
  ])('Updates without a newer release says why (%s) and keeps the general pull and up -d block', async (_, over, said) => {
    const state = { channel: 'stable', mode: 'manual', check_enabled: true, last_check: null, components: [{ id: 'software', kind: 'software', version: '0.9.3', previous: null, installed_at: '2026-11-01T00:00:00Z', signature: 'unsigned', rollback_restores_data: false }], available: [], history: [], advisories: [], run: null, managed: [], running_revoked: null, stale_since: null, last_check_error: null, ...over }
    server.use(http.get('*/api/v1/core/updates', () => HttpResponse.json(state)))
    renderApp('/settings/updates')
    expect(await screen.findByText(said)).toBeInTheDocument()
    expect(screen.getByText(/Running version 0\.9\.3\. (Update information last read|Update information has never been read)/)).toBeInTheDocument()
    expect(screen.getByText(/docker compose --env-file vedette.env pull/)).toBeInTheDocument()
    expect(screen.queryByText(/minisign|cosign verify/)).toBeNull()
    // the block says what it does and does not do; no "kept files" that this state never made (QA M3)
    expect(screen.getByText(/They do not move you to a new release: the image digests are fixed in vedette\.env/)).toBeInTheDocument()
    expect(screen.queryByText(/kept|go back/)).toBeNull()
  })

  it('Updates: a failed check says when and why, without guessing the cause (S-CORE-2 D-392)', async () => {
    const message = "The update information did not pass Vedette's signature checks, so nothing new is offered and nothing was installed. The details are in the box log."
    const state = { channel: 'stable', mode: 'manual', check_enabled: true, last_check: null, last_check_error: { at: new Date(Date.now() - 3600e3).toISOString(), code: 'update_check_failed', message }, components: [{ id: 'software', kind: 'software', version: '0.9.3', previous: null, installed_at: '2026-11-01T00:00:00Z', signature: 'unsigned', rollback_restores_data: false }], available: [], history: [], advisories: [], run: null, managed: [], running_revoked: null, stale_since: null }
    server.use(http.get('*/api/v1/core/updates', () => HttpResponse.json(state)))
    renderApp('/settings/updates')
    expect(await screen.findByText(`Last check failed 1 hour ago: ${message}`)).toBeInTheDocument()
    expect(screen.queryByText(/has never been read/)).toBeNull()
    expect(screen.getByText('No release information yet: no update check has succeeded on this install. Vedette tries again every 6 hours.')).toBeInTheDocument()
    expect(screen.queryByText(/cannot reach github\.com/)).toBeNull() // the failure line says the real reason
  })

  it('Updates: when the update state cannot be read, the error has Try again and the general block stays', async () => {
    server.use(http.get('*/api/v1/core/updates', () => HttpResponse.json({ error: { code: 'x', message: 'The settings server is not responding.' } }, { status: 503 })))
    renderApp('/settings/updates')
    expect(await screen.findByRole('button', { name: /Try again/ })).toBeInTheDocument()
    expect(screen.getByText(/docker compose --env-file vedette.env pull/)).toBeInTheDocument()
  })

  it('Modules: what needs the host is not on this install; off it cannot be turned on, on (sample data) it can be turned off', async () => {
    renderApp('/settings/modules')
    const off = await screen.findByRole('switch', { name: 'Turn on module Credentialed scan' })
    expect(off).toBeDisabled()
    expect(within(off.closest('tr')!).getByText('Not on this install')).toBeInTheDocument()
    const on = screen.getByRole('switch', { name: 'Turn off module Internal traps' })
    expect(on).toBeEnabled()
    expect(within(on.closest('tr')!).getByText('Not on this install')).toBeInTheDocument()
  })

  it('Modules: the active sensor does not claim nmap here; the response gallery cannot clone a trap template', async () => {
    renderApp('/settings/modules')
    expect(await screen.findByText('Light scans of your network inside the allowed time window.')).toBeInTheDocument()
    expect(screen.queryByText(/nmap/)).toBeNull()
    renderApp('/response')
    const clone = await screen.findByRole('button', { name: /^Clone Trap touched: block the source on FortiGate/ })
    expect(clone).toBeDisabled()
    expect(within(clone.closest('li')!).getByText(/Not available on this install/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^Clone Known-bad connection: add the destination to the block list/ })).toBeEnabled()
  })

  it('Response: Add a rule does not offer the honeypot trigger and Recent events does not promise honeypot touches (D-390)', async () => {
    const u = userEvent.setup()
    renderApp('/response')
    expect(await screen.findByText(/^What the triggers watch for: known-bad connections/)).toBeInTheDocument()
    expect(screen.queryByText(/honeypot touches/)).toBeNull()
    await u.click(screen.getByRole('button', { name: 'Add a rule' }))
    const trigger = await within(await screen.findByRole('dialog')).findByLabelText('When this happens')
    const names = within(trigger).getAllByRole('option').map((o) => o.textContent)
    expect(names).toContain('A device connects to a known-bad address')
    expect(names.some((n) => /honeypot/.test(n ?? ''))).toBe(false)
  })

  it('setup: the code hint names vedette-core and the bundles leave the honeypot out', async () => {
    const u = userEvent.setup()
    renderApp('/setup', { role: null, setupComplete: false })
    expect(await screen.findByText(/docker logs vedette-core/)).toBeInTheDocument()
    await u.type(screen.getByLabelText('Setup code'), MOCK_SETUP_CODE)
    await u.type(screen.getByLabelText('Organization name'), 'ABC Company')
    await u.type(screen.getByLabelText('Administrator name'), 'Lan')
    await u.type(screen.getByLabelText('Sign-in email'), 'lan@abc.example')
    await u.type(screen.getByLabelText('Password'), 'a long enough sentence')
    await u.type(screen.getByLabelText('Repeat password'), 'a long enough sentence')
    await u.click(screen.getByRole('button', { name: 'Continue' }))
    await u.type(await screen.findByLabelText('Range 1'), '192.168.10.0/24')
    await u.click(screen.getByRole('checkbox', { name: /I confirm these ranges belong to my company/ }))
    await u.click(screen.getByRole('button', { name: 'Continue' }))
    const small = (await screen.findByRole('radio', { name: /Small business/ })).closest('div')!
    expect(within(small).getByText(/Reports/)).toBeInTheDocument()
    expect(within(small).queryByText(/internal traps/i)).toBeNull()
    expect(screen.getByText(/Not on this install: .*Internal traps/)).toBeInTheDocument()
  })
  it('Scans, Credentialed scan: says it is not on this install, never invites turning it on (S-CORE-9 G5, D-420)', async () => {
    renderApp('/scans?tab=credentialed')
    expect(await screen.findByText('Credentialed scan is not on this install')).toBeInTheDocument()
    expect(screen.getByText(/needs the appliance install/)).toBeInTheDocument()
    expect(screen.queryByText(/Turn the module on/)).toBeNull()
    expect(screen.queryByRole('link', { name: 'Open module settings' })).toBeNull()
  })

  it('MCP: on the localhost of the machine that runs the container, an SSH tunnel to that machine, update an older compose.yaml (S-MCP-1, D-395)', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'mcp-server' ? { ...m, enabled: true } : m)))
    renderApp('/settings/mcp')
    expect(await screen.findByText(/publishes the port on 127\.0\.0\.1 of the machine that runs Docker or Podman, never on the LAN/)).toBeInTheDocument()
    expect(screen.getByText(/with an older compose\.yaml no tool can connect until you update it/)).toBeInTheDocument()
    expect(screen.getByText(/must go through an SSH tunnel to that machine/)).toBeInTheDocument()
    expect(screen.getByText('Listening inside the vedette-core container. The compose.yaml of this release publishes it on the localhost of the machine that runs the container only.')).toBeInTheDocument()
    expect(screen.queryByText(/not published/)).toBeNull()
  })

  it('SIEM forwarding: "Honeypot touches" cannot be ticked and says why (S-LOG-3, D-420)', async () => {
    renderApp('/settings/siem')
    const box = await screen.findByRole('checkbox', { name: 'Honeypot touches' })
    expect(box).toBeDisabled()
    expect(box).not.toBeChecked()
    expect(screen.getByText('Not on this install: the honeypot needs the appliance install.')).toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: 'Alerts sent' })).toBeEnabled()
  })

  // The setup page re-mounts its sections once right after first paint (inventory.test.tsx clickUntil): click again until the dialog shows.
  const openSensorDialog = async (u: ReturnType<typeof userEvent.setup>) => {
    await screen.findByRole('button', { name: 'Configure sensor vedette-hq' }, { timeout: 5000 })
    await waitFor(async () => { await u.click(screen.getByRole('button', { name: 'Configure sensor vedette-hq' })); screen.getByRole('dialog') }, { timeout: 8000 })
  }
  // S-CORE-8 G6, D-387, D-393: the card is chosen under Sensors among the cards the sensor reported; Box network has no SPAN here.
  it('Sensors: Configure picks the SPAN card among the reported cards; the box refuses SPAN on a card with an address', async () => {
    const u = userEvent.setup()
    renderApp('/devices/setup')
    await openSensorDialog(u)
    const dlg = screen.getByRole('dialog')
    expect(within(dlg).queryByRole('link', { name: /Box network/ })).toBeNull()
    const pick = within(dlg).getByRole('combobox', { name: 'Listen on' })
    expect(within(pick).getAllByRole('option').map((o) => o.textContent)).toEqual(['Automatic (eno1)', 'eno1', 'eno2', 'wlp2s0'])
    const spanBox = within(dlg).getByRole('checkbox', { name: /SPAN port/ })
    expect(spanBox).toBeDisabled() // Automatic: no SPAN, and the hint says why (walk 4)
    expect(spanBox).toHaveAccessibleDescription(/Choose a card under Listen on first/)
    await u.selectOptions(pick, 'eno1')
    expect(spanBox).toHaveAccessibleDescription(/Prepare the card on this machine first/)
    await u.click(spanBox)
    await u.click(within(dlg).getByRole('button', { name: 'Save' }))
    // the refusal sits under the SPAN tick it is about, not in a toast (walk 4)
    expect(await within(dlg).findByRole('alert')).toHaveTextContent('"eno1" has an IP address; a SPAN port has none.')
    expect(spanBox).toHaveAttribute('aria-invalid', 'true')
    expect(spanBox).toHaveAccessibleDescription(/"eno1" has an IP address; a SPAN port has none\./)
    await u.selectOptions(pick, 'eno2') // another card: SPAN is decided again for it
    expect(spanBox).not.toBeChecked()
    await u.click(spanBox)
    await u.click(within(dlg).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(containerSensorStore.get()).toMatchObject({ chosen: 'eno2', span: true })
    await waitFor(() => expect(screen.getByRole('cell', { name: /eno2/ })).toBeInTheDocument())
    // Reopened on the stored SPAN choice; Automatic no longer names a card it cannot know (the default is not computed for a choice).
    await openSensorDialog(u)
    const again = within(screen.getByRole('dialog'))
    expect(again.getByRole('combobox', { name: 'Listen on' })).toHaveValue('eno2')
    expect(again.getByRole('checkbox', { name: /SPAN port/ })).toBeChecked()
    expect(again.getAllByRole('option')[0]).toHaveTextContent('Automatic (the one card of this machine with an address)')
    await u.click(again.getByRole('button', { name: 'Cancel' }))
    expect(calls.some((u) => new URL(u, location.origin).pathname.startsWith('/api/v1/core/network'))).toBe(false)
  })

  it('Sensors: a refused card shows under Listen on; an answer that is not about a field stays under the form (walk 4)', async () => {
    let answer = { status: 400, code: 'bad_interface', message: 'The sensor has not reported its network cards in the last 90 seconds.' }
    server.use(http.patch('*/api/v1/inventory/sensors/:id', () => HttpResponse.json({ error: { code: answer.code, message: answer.message } }, { status: answer.status })))
    const u = userEvent.setup()
    renderApp('/devices/setup')
    await openSensorDialog(u)
    const dlg = screen.getByRole('dialog')
    const pick = within(dlg).getByRole('combobox', { name: 'Listen on' })
    await u.selectOptions(pick, 'eno2')
    await u.click(within(dlg).getByRole('button', { name: 'Save' }))
    expect(await within(dlg).findByRole('alert')).toHaveTextContent('has not reported its network cards')
    expect(pick).toHaveAttribute('aria-invalid', 'true')
    expect(pick).toHaveAccessibleDescription(/has not reported its network cards/)
    answer = { status: 409, code: 'module_off', message: 'The passive sensor module is off.' }
    await u.click(within(dlg).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(within(dlg).getByRole('alert')).toHaveTextContent('The passive sensor module is off.'))
    expect(pick).not.toHaveAttribute('aria-invalid')
  })

  // D-399 (3), walk 4: a rootless sensor reports, but its capture socket cannot open; the row must not look healthy.
  it('Sensors: a sensor that reports but cannot capture says so and why, in the row and in Configure', async () => {
    containerSensorStore.set({ ...containerSensorStore.get(), capture_error: 'no_permission' })
    const u = userEvent.setup()
    renderApp('/devices/setup')
    expect((await screen.findAllByText('Reporting, not capturing', undefined, { timeout: 5000 })).length).toBeGreaterThan(0)
    expect(screen.getAllByText(/capturing needs root and CAP_NET_RAW, which a rootless Docker or Podman does not give/).length).toBeGreaterThan(0)
    expect(screen.queryAllByText('Reporting')).toHaveLength(0)
    await openSensorDialog(u)
    expect(within(screen.getByRole('dialog')).getByText(/Reporting, not capturing: It cannot open the network card/)).toBeInTheDocument()
    containerSensorStore.set({ ...containerSensorStore.get(), connected: false }) // a sensor not online says nothing about its capture now
    expect((await (await fetch(`${location.origin}/api/v1/inventory/sensors`)).json()).sensors[0].capture_error).toBeNull()
  })

  it('Sensors: a sensor never started says Not connected yet and how to start it; no card reported yet, no Save', async () => {
    containerSensorStore.set({ connected: false, cards: [], chosen: null, span: false })
    const u = userEvent.setup()
    renderApp('/devices/setup')
    await waitFor(() => {
      expect(screen.getByText('Not connected yet')).toBeInTheDocument()
      expect(screen.getByText('Start it with compose.sensors.yaml on this machine.')).toBeInTheDocument()
    }, { timeout: 5000 })
    expect(screen.queryByText('Lost contact')).toBeNull()
    await openSensorDialog(u)
    const dlg = screen.getByRole('dialog')
    expect(within(dlg).getByRole('status')).toHaveTextContent('No card reported yet: start the sensor with compose.sensors.yaml.')
    expect(within(dlg).queryByRole('button', { name: 'Save' })).toBeNull()
  })

  // D-393 (M3): two cards with an address and no SPAN card: no default (D-380), so the admin picks the card to listen on.
  it('Sensors: two cards with an address: the dialog says the sensor is not listening, the admin picks one, then back to Automatic', async () => {
    containerSensorStore.set({ connected: true, chosen: null, span: false, cards: [{ name: 'eno1', ipv4: '192.168.10.20/24', link: true }, { name: 'eno2', ipv4: '10.0.0.2/24', link: true }, { name: 'eno3', ipv4: null, link: true }] })
    const u = userEvent.setup()
    renderApp('/devices/setup')
    await openSensorDialog(u)
    let dlg = screen.getByRole('dialog')
    expect(within(dlg).getByRole('status')).toHaveTextContent('The sensor is not listening on any card')
    let pick = within(dlg).getByRole('combobox', { name: 'Listen on' })
    expect(within(pick).getAllByRole('option')[0]).toHaveTextContent('Automatic (no card now)')
    await u.selectOptions(pick, 'eno2')
    await u.click(within(dlg).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(containerSensorStore.get()).toMatchObject({ chosen: 'eno2', span: false })
    await waitFor(() => expect(screen.getByRole('cell', { name: 'eno2' })).toBeInTheDocument())
    // Reopened, it shows the stored choice, not Automatic; Automatic stores no card again.
    await openSensorDialog(u)
    dlg = screen.getByRole('dialog')
    pick = within(dlg).getByRole('combobox', { name: 'Listen on' })
    expect(pick).toHaveValue('eno2')
    expect(within(dlg).getByRole('button', { name: 'Save' })).toBeDisabled()
    await u.selectOptions(pick, '')
    await u.click(within(dlg).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(containerSensorStore.get()).toMatchObject({ chosen: null, span: false })
  })

  it('PATCH /inventory/sensors/{id} on an appliance is 409 set_in_box_network', async () => {
    installStore.set({ kind: 'appliance' })
    sessionStore.set({ userId: 'u-admin' })
    const r = await fetch(`${location.origin}/api/v1/inventory/sensors/sn-local`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ interface: 'eth1', span: true }) })
    expect(r.status).toBe(409)
    expect(((await r.json()) as { error: { code: string } }).error.code).toBe('set_in_box_network')
  })
})
