import { describe, expect, it } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { http, HttpResponse } from 'msw'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { eachOption } from '@/test/formMatrix'
import { server } from '@/test/server'
import { aiConfigStore, aiRunsStore, assetsStore, auditStore, findingsStore, modulesStore, sessionStore } from '@/mocks/stores'
import { inventorySettingsStore } from '@/features/inventory/mocks'
import { accepted } from './mocks'
import { AiOutput, FixedInNote } from './Recommendation'
import { dayAfter, untilBounds, untilOk } from './accept'
import { SeverityBadge, bandOf as cvssBand, fromCvss } from '@/components/common/status'
import type { FindingDetail } from './types'

const FORTI = 'show firewall vip | grep -f 192.168.10.21'
const MIKROTIK_RULE = '/ip firewall filter add chain=forward action=drop in-interface-list=WAN connection-state=new connection-nat-state=dstnat dst-address=192.168.10.21 comment="Vedette: block Internet access to NAS" place-before=0'

describe('findings: danh sách (S-MIT-1)', () => {

  it('an API error shows a message and a retry button', async () => {
    server.use(http.get('*/api/v1/findings/devices', () => HttpResponse.json({ error: { code: 'x', message: 'The findings store is busy.' } }, { status: 503 })))
    renderApp('/findings')
    expect(await screen.findByText('The findings store is busy.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument()
  })

  it('shows ModuleOff when the findings module is off', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'findings' ? { ...m, enabled: false } : m)))
    renderApp('/findings?tab=open')
    expect(await screen.findByText('Findings module is off')).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 1, name: 'Findings' })).toBeInTheDocument() // #892: the page keeps its h1
    expect(screen.getByRole('link', { name: 'Open module settings' })).toHaveAttribute('href', '/settings/modules#module-findings')
    cleanup()
    renderApp('/findings/f-1')
    expect(await screen.findByText('Findings module is off')).toBeInTheDocument()
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1)
  })

  it('mitigation module off: findings remain, only the "What to do" part says the module is off', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'mitigation' ? { ...m, enabled: false } : m)))
    renderApp('/findings/f-1')
    expect(await screen.findByRole('heading', { level: 1, name: /NAS-PHOTOS has a confirmed vulnerability/ })).toBeInTheDocument()
    expect(await screen.findByText('Mitigation module is off')).toBeInTheDocument()
    expect(screen.queryByText('Confirmed by Vedette maintainers')).not.toBeInTheDocument()
  })

  it('modules: findings depends on inventory and feeds; mitigation depends on findings; reports depends on notify', () => {
    const dep = (id: string) => modulesStore.get().find((m) => m.id === id)?.depends
    expect(dep('findings')).toEqual(expect.arrayContaining(['inventory', 'feeds']))
    expect(dep('mitigation')).toEqual(['findings'])
    expect(dep('reports')).toContain('notify')
  })
})

describe('findings: f-1 has a confirmed Vedette recommendation (S-MIT-1, S-SCAN-3)', () => {
  it('shows the Vedette-confirmed label, who, the date, drafted with AI and the QNAP advisory link; no a11y violations', async () => {
    renderApp('/findings/f-1')
    expect(await screen.findByRole('heading', { level: 1, name: /NAS-PHOTOS has a confirmed vulnerability \(CVE-2022-27593\)/ })).toBeInTheDocument()
    expect(screen.getByText('Confirmed by Vedette maintainers')).toBeInTheDocument()
    expect(screen.getByText(/^on .+, drafted with AI help\.$/)).toBeInTheDocument()
    expect(screen.queryByText('AI-generated, needs human review')).not.toBeInTheDocument() // one status: a maintainer reviewed it
    expect(screen.getAllByText(/drafted with AI/i).length).toBeGreaterThan(0)
    expect(screen.queryByText('No confirmed recommendation yet')).not.toBeInTheDocument()
    expect(screen.queryByText('Your AI')).not.toBeInTheDocument()
    const advisories = screen.getAllByRole('link', { name: /QSA-22-24|Open the vendor advisory/ })
    expect(advisories.some((a) => a.getAttribute('href') === 'https://www.qnap.com/en/security-advisory/qsa-22-24')).toBe(true)
    await expectNoA11yViolations()
  })

  it('evidence: summary, sample, request/response, how to re-check by hand and the rescan button', async () => {
    renderApp('/findings/f-1')
    const ev = (await screen.findByRole('heading', { name: 'Evidence' })).closest('section')!
    expect(within(ev).getByText(/The nuclei-templates safe scan template/)).toBeInTheDocument()
    expect(within(ev).getByText('http/cves/2022/CVE-2022-27593.yaml')).toBeInTheDocument()
    expect(within(ev).getByText(/GET http:\/\/192\.168\.10\.21\/photo/)).toBeInTheDocument()
    expect(within(ev).getByText('curl -sI http://192.168.10.21/photo/')).toBeInTheDocument()
    expect(within(ev).getByRole('link', { name: 'Rescan this device' })).toHaveAttribute('href', '/devices/a-nas02') // #850: the device page, with its scan buttons
  })

  it('FortiGate is preselected; one box per step, using the real IP of the NAS, with side effects and a check', async () => {
    renderApp('/findings/f-1')
    const fw = (await screen.findByRole('heading', { name: '3. Firewall configuration to cut off access' })).closest('section')!
    expect(await within(fw).findByRole('button', { name: 'FortiGate (FortiOS) (your firewall)' })).toHaveAttribute('aria-pressed', 'true')
    const codes = [...fw.querySelectorAll('pre code')].map((c) => c.textContent)
    expect(codes).toContain(FORTI)
    expect(codes).toContain('show firewall policy | grep -f "<VIP-NAME>"')
    expect(codes).toContain('config firewall policy\nedit <ID>\nset status disable\nnext\nend')
    expect(codes).toContain('config firewall address\nedit "geo-VN"\nset type geography\nset country "VN"\nnext\nend')
    expect(codes.every((c) => !/^\s*#/m.test(c ?? ''))).toBe(true)
    expect(within(fw).getAllByText('Side effects:').length).toBeGreaterThan(0)
    expect(within(fw).getByText(/Access to the NAS from the Internet stops immediately/)).toBeInTheDocument()
    expect(within(fw).getByText('Check after applying')).toBeInTheDocument()
    expect(within(fw).getByText('Undo')).toBeInTheDocument()
  })

  it('switching to MikroTik: correct command syntax, an explanation of the WAN list', async () => {
    renderApp('/findings/f-1')
    const fw = (await screen.findByRole('heading', { name: '3. Firewall configuration to cut off access' })).closest('section')!
    await userEvent.click(await within(fw).findByRole('button', { name: 'MikroTik (RouterOS)' }))
    const codes = [...fw.querySelectorAll('pre code')].map((c) => c.textContent)
    expect(codes).toContain('/ip firewall nat print where to-addresses=192.168.10.21')
    expect(codes).toContain(MIKROTIK_RULE)
    expect(within(fw).getByText(/default RouterOS WAN interface list/)).toBeInTheDocument()
    await userEvent.click(within(fw).getByRole('button', { name: 'Other device' }))
    expect(within(fw).getByText(/Find the port forwarding section/)).toBeInTheDocument()
  })

  it('"Applied" writes a log entry (history + audit) and does not change the status by itself', async () => {
    renderApp('/findings/f-1')
    const patch = (await screen.findByRole('heading', { name: '1. Install the patch' })).closest('section')!
    await userEvent.click(within(patch).getByRole('button', { name: 'Applied' }))
    expect(await within(patch).findByText(/Recorded as applied by admin@acme.example/)).toBeInTheDocument()
    const f = findingsStore.get().find((x) => x.id === 'f-1')!
    expect(f.status).toBe('confirmed')
    expect(f.history.at(-1)!.action).toBe('applied:patch')
    expect(auditStore.get().some((a) => a.action === 'findings.applied' && a.target === 'f-1')).toBe(true)
    expect(await screen.findByText('Applied: patch')).toBeInTheDocument()
  })

  // A role query by name matches a part of the name, as a browser test or a voice-control "click Applied" does: every control so
  // named must be an "Applied" action, so the last one is the firewall guide's and it answers with the confirmation.
  it('every control named "Applied" is the action; the firewall guide\'s logs with "Logged. Rescan to confirm."', async () => {
    renderApp('/findings/f-1')
    await screen.findByRole('heading', { name: 'Evidence' })
    await screen.findByRole('button', { name: 'FortiGate (FortiOS) (your firewall)' }) // the firewall step shows once the firewalls are read
    const all = await screen.findAllByRole('button', { name: /applied/i })
    expect(all.map((b) => b.textContent)).toEqual(['Applied', 'Applied', 'Applied'])
    await userEvent.click(all.at(-1)!)
    expect(await screen.findByText('Logged. Rescan to confirm.')).toBeInTheDocument()
    expect(await screen.findByText(/Recorded as applied by admin@acme.example/)).toBeInTheDocument()
  })

  it('"Have I been hit?" names the .deadbolt file and the replaced login page', async () => {
    renderApp('/findings/f-1')
    const c = (await screen.findByRole('heading', { name: 'Have I been hit?' })).closest('section')!
    expect(within(c).getAllByText(/Deadbolt/).length).toBeGreaterThan(0)
    expect(within(c).getByText('Files with a .deadbolt extension')).toBeInTheDocument()
    expect(within(c).getByText('QTS login page replaced')).toBeInTheDocument()
    expect(within(c).getByText('curl -s http://192.168.10.21:8080/ | grep -i deadbolt')).toBeInTheDocument()
    expect(within(c).getByText(/find -L \/share/)).toBeInTheDocument()
    expect(within(c).getByText('If you see signs')).toBeInTheDocument()
  })
})

describe('findings: f-2, f-3 have no confirmed recommendation yet', () => {
  it('shows "no confirmed recommendation yet", the CISA requirement and the vendor link, and no confirmed label', async () => {
    renderApp('/findings/f-2')
    expect(await screen.findByText('No confirmed recommendation yet')).toBeInTheDocument()
    expect(screen.queryByText('Confirmed by Vedette maintainers')).not.toBeInTheDocument()
    expect(screen.getByText(/Apply mitigations in accordance with vendor instructions/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Vendor advisory (wordpress.org)' })).toHaveAttribute('href', 'https://wordpress.org/news/2026/10/wordpress-7-1-4')
    // the same four steps a confirmed pack has, from the box's data
    expect(screen.getAllByRole('heading', { level: 3 }).map((h) => h.textContent)).toEqual(expect.arrayContaining(['1. Install the patch', '2. Temporary workaround if you cannot update yet', '3. Firewall configuration to cut off access', '4. Check that it is fixed']))
    expect(screen.queryByText(/No confirmed exploitation signs/)).not.toBeInTheDocument() // general checks instead (INV-8)
    expect(screen.getByTestId('general-checks')).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('"What to do" names the fixed version for exactly this device and branch, and invents nothing when NVD gives none', () => {
    const note = (fixed_in: FindingDetail['fixed_in']) => render(<FixedInNote finding={{ asset: { name: 'FortiGate-60F' }, fixed_in } as FindingDetail} />)
    const src = { source: 'NVD affected versions', more: 0, no_fix: 0, distro: '', branches: [], distro_fixed: '', distro_release: '', distro_pro: false }
    const a = note({ ...src, kind: 'fixed', version: '7.4.1', fixed: '7.4.3' })
    expect(screen.getByText('Fixed in 7.4.3: upgrade FortiGate-60F from 7.4.1 to 7.4.3 or later.')).toBeInTheDocument()
    expect(screen.getByText(/Source: NVD affected versions/)).toBeInTheDocument()
    a.unmount()
    // ranges from the CVE.org record name that source, not NVD
    const o = note({ ...src, source: "CVE.org affected versions (from the CVE record's CNA)", kind: 'fixed', version: '10.2.5', fixed: '10.2.9-h1' })
    expect(screen.getByText(/Source: CVE\.org affected versions \(from the CVE record's CNA\)\. Check the vendor advisory/)).toBeInTheDocument()
    expect(screen.queryByText(/NVD/)).not.toBeInTheDocument()
    o.unmount()
    const b = note({ ...src, kind: 'up_to', version: '5.6.8', fixed: '5.6.10' })
    expect(screen.getByText(/Versions up to 5\.6\.10 are affected, and FortiGate-60F runs 5\.6\.8: upgrade to a release after 5\.6\.10\./)).toBeInTheDocument()
    expect(screen.queryByText(/Fixed in/)).not.toBeInTheDocument()
    b.unmount()
    const c = note({ ...src, kind: 'branches', version: '', fixed: '', more: 3, branches: [{ branch: '7.4', fixed: '7.4.3' }, { branch: '7.2', fixed: '7.2.7' }, { branch: '', fixed: '22.4R2' }] })
    expect(screen.getByText(/7\.4 \u2192 7\.4\.3, 7\.2 \u2192 7\.2\.7, 22\.4R2, and 3 more/)).toBeInTheDocument()
    c.unmount()
    const d = note({ ...src, kind: 'distro', version: '1.9.4-1ubuntu2', fixed: '', distro: 'Ubuntu' })
    expect(screen.getByText(/runs the software 1\.9\.4-1ubuntu2 from Ubuntu's packages, in the affected range: install Ubuntu's security updates/)).toBeInTheDocument()
    expect(screen.queryByText(/Fixed in|backports|If you installed/)).not.toBeInTheDocument()
    d.unmount()
    // An agent row read from the package database: the distribution's updates, the upstream number only as a reference.
    const p = render(<FixedInNote finding={{ asset: { name: 'web-01' }, kev: { display: 'OpenSSL' }, fixed_in: { ...src, kind: 'distro', version: '3.0.2', fixed: '3.0.7', distro: 'Ubuntu' } } as unknown as FindingDetail} />)
    expect(screen.getByText("web-01 runs OpenSSL 3.0.2 from Ubuntu's packages, in the affected range: install Ubuntu's security updates for it (for example apt upgrade) and check Ubuntu's notice for this CVE.")).toBeInTheDocument()
    expect(screen.getByText("Ubuntu backports fixes, so the package's version number may stay below 3.0.7, the upstream release that fixes it.")).toBeInTheDocument()
    expect(screen.queryByText(/Fixed in|If you installed/)).not.toBeInTheDocument()
    p.unmount()
    const r = note({ ...src, kind: 'distro', version: '3.0.7-27.el9', fixed: '3.0.8', distro: '' })
    expect(screen.getByText(/from its distribution's packages, in the affected range: install the distribution's security updates/)).toBeInTheDocument()
    expect(screen.getByText(/The distribution backports fixes, so .* below 3\.0\.8/)).toBeInTheDocument()
    r.unmount()
    const g = note({ ...src, kind: 'fixed', version: '8.2.0', fixed: '8.3.3', distro: 'Ubuntu' })
    expect(screen.getByText('Fixed in 8.3.3: upgrade FortiGate-60F from 8.2.0 to 8.3.3 or later.')).toBeInTheDocument()
    expect(screen.getByText(/If you installed .* from Ubuntu's packages, install its security updates instead/)).toBeInTheDocument()
    g.unmount()
    const e = note({ ...src, kind: 'branches', version: '7.0.x', fixed: '', no_fix: 4, branches: [{ branch: '7.0', fixed: '7.0.9' }] })
    expect(screen.getByText(/cannot read the version "7\.0\.x" of FortiGate-60F.*7\.0 \u2192 7\.0\.9, no fixed release named for 4 more line\(s\)/)).toBeInTheDocument()
    expect(screen.queryByText(/has no version yet/)).not.toBeInTheDocument()
    e.unmount()
    // The distribution's own fixed package for the device's release, with its source
    const u = render(<FixedInNote finding={{ asset: { name: 'web-01' }, kev: { display: 'OpenSSH' }, fixed_in: { ...src, kind: 'distro', version: '1:9.6p1-3ubuntu13.4', fixed: '', distro: 'Ubuntu', distro_fixed: '1:9.6p1-3ubuntu13.5', distro_release: '24.04', source: 'Ubuntu security data' } } as unknown as FindingDetail} />)
    expect(screen.getByText("Fixed in 1:9.6p1-3ubuntu13.5 for Ubuntu 24.04: web-01 has OpenSSH 1:9.6p1-3ubuntu13.4 from Ubuntu's packages. Install Ubuntu's security updates for it (for example apt upgrade).")).toBeInTheDocument()
    expect(screen.getByText('Source: Ubuntu security data.')).toBeInTheDocument()
    expect(screen.queryByText(/backports|If you installed|Ubuntu Pro/)).not.toBeInTheDocument()
    u.unmount()
    // A kernel whose fixed release is installed but not running yet: the restart, not another install
    const k = render(<FixedInNote finding={{ asset: { name: 'boxanna' }, kev: { display: 'Linux kernel' }, fixed_in: { ...src, kind: 'distro', version: '7.0.0-43.43', fixed: '', distro: 'Ubuntu', distro_fixed: '7.0.0-44.44', distro_release: '26.04', restart_into: '7.0.0-44.44', source: 'Ubuntu security data' } } as unknown as FindingDetail} />)
    expect(screen.getByText('Fixed in 7.0.0-44.44 for Ubuntu 26.04: the fixed kernel 7.0.0-44.44 is already installed on boxanna, but it still runs Linux kernel 7.0.0-43.43. Restart boxanna so it runs the installed kernel.')).toBeInTheDocument()
    expect(screen.queryByText(/apt upgrade/)).not.toBeInTheDocument()
    k.unmount()
    const pro = note({ ...src, kind: 'distro', version: '1:2.25.1-1ubuntu3.14', fixed: '', distro: 'Ubuntu', distro_fixed: '1:2.25.1-1ubuntu3.14+esm6', distro_release: '20.04', distro_pro: true, source: 'Ubuntu security data' })
    expect(screen.getByText(/Only Ubuntu Pro \(ESM\) has this fixed package.*sudo pro attach.*accept the risk or remove the package/)).toBeInTheDocument()
    pro.unmount()
    // A Windows release Microsoft no longer updates is told to take a feature update, never a build it cannot get
    const fu = note({ ...src, kind: 'feature_update', version: '10.0.22621.6060', fixed: '10.0.22631.6199', branches: [{ branch: 'Windows 11 23H2', fixed: '10.0.22631.6199' }] })
    expect(screen.getByText(/^NVD names the fix for Windows 11 23H2 \(10\.0\.22631\.6199\), not for the Windows release FortiGate-60F runs \(10\.0\.22621\.6060\).*a feature update/)).toBeInTheDocument()
    expect(screen.queryByText(/upgrade FortiGate-60F from/)).not.toBeInTheDocument()
    fu.unmount()
    const esu = note({ ...src, kind: 'esu', version: '10.0.19045.6456', fixed: '10.0.19045.6575', branches: [{ branch: 'Windows 10 22H2', fixed: '10.0.19045.6575' }] })
    expect(screen.getByText(/^Fixed in 10\.0\.19045\.6575, an Extended Security Update: Microsoft updates Windows 10 22H2 past the end of its support only for devices enrolled/)).toBeInTheDocument()
    esu.unmount()
    note(null)
    expect(screen.queryByTestId('fixed-in')).not.toBeInTheDocument()
  })

  // #897: an honest "no rule helps" answer shows its reason, repeated titles both render, a shortened answer says so
  it('Ask my AI: the reason when no config helps, repeated titles, shortened', () => {
    const base = { skill: 'mitigation-config' as const, ts: '2026-11-16T00:00:00Z', model: 'm', tokens: { input: 1, output: 1 }, paragraphs: ['A local flaw.'], steps: ['Patch.'], citations: [] }
    const a = render(<AiOutput r={{ ...base, configs: [], no_config_reason: 'The attack is local: no firewall rule helps.', shortened: true }} />)
    expect(screen.getByText('Why there is no firewall rule')).toBeInTheDocument()
    expect(screen.getByText('The attack is local: no firewall rule helps.')).toBeInTheDocument()
    expect(screen.queryByText('Configuration to review before pasting')).not.toBeInTheDocument()
    expect(screen.getByText(/^Vedette shortened or left out part of this answer/)).toBeInTheDocument()
    a.unmount()
    render(<AiOutput r={{ ...base, configs: [{ title: 'Configuration', code: 'set a 203.0.113.9', check: ['203.0.113.9'] }, { title: 'Configuration', code: 'set b' }], no_config_reason: 'Only the device needs a change.' }} />)
    // #897: every AI block carries the fixed caution; an address the box does not know is named above its block
    expect(screen.getAllByText(/^AI-generated: read every line before pasting/)).toHaveLength(2)
    expect(screen.getAllByText((_, el) => el?.tagName === 'P' && /^Check these addresses: .* 203\.0\.113\.9$/.test(el.textContent ?? ''))).toHaveLength(1)
    expect(screen.getByText('Note from the AI')).toBeInTheDocument()
    expect(screen.getByText('set a 203.0.113.9')).toBeInTheDocument()
    expect(screen.getByText('set b')).toBeInTheDocument()
    expect(screen.queryByText(/^Vedette shortened/)).not.toBeInTheDocument()
  })

  it('f-3 is the same, with the MSRC link', async () => {
    renderApp('/findings/f-3')
    expect(await screen.findByText('No confirmed recommendation yet')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Vendor advisory (msrc.microsoft.com)' })).toHaveAttribute('href', 'https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2026-96951')
  })

  it('"Ask my AI" answers inside the customer AiBlock, records the run and survives a reload', async () => {
    const view = renderApp('/findings/f-2')
    await userEvent.click(await screen.findByRole('button', { name: 'Ask my AI' }))
    const label = await screen.findByText('Your AI')
    const block = label.closest('[data-ai="true"]') as HTMLElement
    expect(within(block).getByText('AI-generated, needs human review')).toBeInTheDocument()
    // four short answers under the page's own headings, in a fixed order, instead of free paragraphs
    expect(within(block).getAllByRole('heading', { level: 4 }).map((h) => h.textContent)).toEqual(['Am I affected?', 'How do I fix it?', 'What if I cannot patch yet?', 'How urgent is it?'])
    expect(within(block).getByText(/^Attackers use it in real attacks: on CISA KEV since/)).toBeInTheDocument()
    expect(within(block).queryByText(/Update WordPress to the latest release/)).not.toBeInTheDocument()
    // the config skill answers with a config block to copy, with its source and side effect
    expect(within(block).getByText('Configuration to review before pasting')).toBeInTheDocument()
    expect(within(block).getByText(/^nft add rule inet filter forward/)).toBeInTheDocument()
    expect(within(block).getByText('Based on: general practice, no source in the data names it')).toBeInTheDocument()
    expect(within(block).getByRole('button', { name: 'Copy' })).toBeInTheDocument()
    expect(within(block).queryByText('Drafted by Vedette with AI')).not.toBeInTheDocument()
    expect(screen.queryByText('Confirmed by Vedette maintainers')).not.toBeInTheDocument()
    const runs = aiRunsStore.get()
    expect(runs).toHaveLength(1)
    expect(runs[0]!.skill).toBe('mitigation-config')
    view.unmount()
    renderApp('/findings/f-2')
    expect(await screen.findByText('Your AI')).toBeInTheDocument()
  })

  // The button went grey for 10–20 s with no sign of work. While the AI answers it spins, says "Asking…", and a note under
  // it says what is happening and how long it can take.
  it('Ask my AI shows the busy state and the waiting note while the AI answers', async () => {
    let release!: () => void
    const held = new Promise<void>((r) => { release = r })
    server.use(http.post('*/api/v1/findings/:id/ai', async () => { await held; return HttpResponse.json({ error: { code: 'ai_timeout', message: 'late' } }, { status: 504 }) }))
    renderApp('/findings/f-2')
    await userEvent.click(await screen.findByRole('button', { name: 'Ask my AI' }))
    const busy = await screen.findByRole('button', { name: 'Asking…' })
    expect(busy).toHaveAttribute('aria-busy', 'true')
    expect(busy).toBeDisabled()
    expect(screen.getByText('Asking your AI… this can take up to a minute.')).toBeInTheDocument()
    release()
    expect(await screen.findByRole('button', { name: 'Ask my AI' })).not.toHaveAttribute('aria-busy')
    expect(screen.queryByText('Asking your AI… this can take up to a minute.')).toBeNull()
  })

  // beta 0.1.0-beta.1: Explain on Haiku 5.5 failed with a cut answer, and the page said "No AI profile is assigned". Each failure of the
  // AI shows the box's own message for it, never the "not set up" one.
  it.each([
    ['ai_cut_off', 502, "The AI's answer was cut off at the output limit (12,000 tokens), so it was not used. Try again; if it keeps happening, use a model for explaining findings that writes shorter answers."],
    ['ai_bad_format', 502, 'The AI answered, but not in the format Vedette needs, so the answer was discarded. Try again, or use a stronger model for this job.'],
    ['provider_error', 502, 'The AI provider returned an error for explaining findings (Claude: provider refused the request (HTTP 400): bad model).'],
    ['blocked_by_hook', 409, 'The AI was not asked: a hook stopped the data sent with it (the device of the finding). The text contains an ID number.'],
    ['budget_reached', 429, "This month's AI budget of 6,000,000 tokens is used up, so AI jobs are stopped until it renews on 1 December 2026. An administrator can raise the budget in Settings, AI assistant."],
    ['ai_timeout', 504, 'The AI provider did not answer explaining findings in time (Claude: provider did not answer in time).'],
  ])('Ask my AI failing with %s shows that failure', async (code, status, message) => {
    server.use(http.post('*/api/v1/findings/:id/ai', () => HttpResponse.json({ error: { code, message } }, { status })))
    renderApp('/findings/f-2')
    await userEvent.click(await screen.findByRole('button', { name: 'Ask my AI' }))
    expect(await screen.findByText(message)).toBeInTheDocument()
    expect(screen.queryByText(/No AI profile is assigned to this job/)).toBeNull()
  })

  it('AI not configured: the button is disabled, says what to do and links to the settings', async () => {
    aiConfigStore.update((c) => ({ ...c, configured: false }))
    renderApp('/findings/f-2')
    expect(await screen.findByRole('button', { name: 'Ask my AI' })).toBeDisabled()
    expect(screen.getAllByText('The AI assistant is off, or no AI profile is assigned to this job.').length).toBeGreaterThan(0)
    expect(screen.getAllByRole('link', { name: 'Open AI assistant settings' })[0]).toHaveAttribute('href', '/settings/ai#ai-profiles') // the exact section (docs/UI.md §0)
    expect(screen.getByRole('button', { name: 'Explain' })).toBeDisabled()
    const res = await fetch(`${location.origin}/api/v1/findings/f-2/ai`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ skill: 'explain' }) })
    expect(res.status).toBe(409)
  })

  it('"Explain" (S-AI-2) shows in an AiBlock with tokens and sources', async () => {
    renderApp('/findings/f-1')
    await userEvent.click(await screen.findByRole('button', { name: 'Explain' }))
    // f-1 is Critical, so the page also has a response-plan block (response module); pick the "Explain" block
    const block = (await screen.findByText(/ransomware groups have used it/)).closest('[data-ai="true"]') as HTMLElement
    expect(within(block).getByText(/tokens in/)).toBeInTheDocument()
    expect(within(block).getByText(/Model claude-sonnet-5-5 \(Claude Sonnet\)/)).toBeInTheDocument()
    expect(within(block).getByText('Sources:')).toBeInTheDocument()
    expect(within(block).getByText(/ransomware groups have used it/)).toBeInTheDocument()
    expect(aiRunsStore.get()[0]!.skill).toBe('explain-finding')
    // the project's recommendation stays separate, not mixed into the customer's AI block
    expect(within(block).queryByText('Confirmed by Vedette maintainers')).toBeNull()
    expect(screen.getAllByText('Confirmed by Vedette maintainers')).toHaveLength(1)
  })
})

describe('findings: status changes and permissions', () => {
  it('marking as patched with a note: stores the status, history and audit, and survives a reload', async () => {
    // The inventory mock adds the box, and its finding, on its first read ("I updated", reads the device); this test counts the seed only.
    server.use(http.get('*/api/v1/inventory/devices/:id', () => HttpResponse.json({ asset: { software: [] } })))
    renderApp('/findings/f-1')
    await userEvent.click(await screen.findByRole('button', { name: 'Mark as handled' }))
    const dlg = await screen.findByRole('dialog', { name: 'Mark as handled' })
    await userEvent.click(within(dlg).getByRole('radio', { name: /Patched/ }))
    await userEvent.type(within(dlg).getByLabelText('Note (optional)'), 'Đã lên Photo Station 6.1.2')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Mark 1 finding' }))
    expect(await screen.findByRole('heading', { level: 1, name: /CVE-2022-27593 is patched/ })).toBeInTheDocument()
    const f = findingsStore.get().find((x) => x.id === 'f-1')!
    expect(f.status).toBe('patched')
    expect(f.resolution_note).toBe('Đã lên Photo Station 6.1.2')
    expect(f.resolved_by).toBe('admin@acme.example')
    expect(auditStore.get().some((a) => a.action === 'findings.status')).toBe(true)
    // the note leads the page (closed notice) and stays in History
    expect(screen.getAllByText('Đã lên Photo Station 6.1.2')).toHaveLength(2)
  })

  it('a false-positive report requires a note, and the error says what to fix', async () => {
    renderApp('/findings/f-2')
    await userEvent.click(await screen.findByRole('button', { name: 'Mark as handled' }))
    const dlg = await screen.findByRole('dialog')
    await userEvent.click(within(dlg).getByRole('radio', { name: /False positive/ }))
    await userEvent.click(within(dlg).getByRole('button', { name: 'Mark 1 finding' }))
    expect(await within(dlg).findByText(/^Say why \(at least 3 characters\)/)).toBeInTheDocument()
    expect(findingsStore.get().find((x) => x.id === 'f-2')!.status).toBe('suspected')
    await userEvent.type(within(dlg).getByLabelText('Note: why (required)'), 'WordPress đã là 7.2')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Mark 1 finding' }))
    await waitFor(() => expect(findingsStore.get().find((x) => x.id === 'f-2')!.status).toBe('false_positive'))
  })

  it('a handled finding has a reopen button', async () => {
    findingsStore.update((l) => l.map((f) => (f.id === 'f-1' ? { ...f, status: 'mitigated' as const } : f)))
    renderApp('/findings/f-1')
    await userEvent.click(await screen.findByRole('button', { name: 'Reopen finding' }))
    await waitFor(() => expect(findingsStore.get().find((x) => x.id === 'f-1')!.status).toBe('confirmed'))
    expect(findingsStore.get().find((x) => x.id === 'f-1')!.resolved_by).toBeNull()
  })

  it('a view-only role can read but not write', async () => {
    renderApp('/findings/f-1', { role: 'viewer' })
    expect(await screen.findByRole('button', { name: 'Mark as handled' })).toBeDisabled()
    await screen.findByRole('button', { name: 'FortiGate (FortiOS) (your firewall)' }) // the firewall step shows once the firewalls are read
    const applied = screen.getAllByRole('button', { name: /applied/i })
    expect(applied).toHaveLength(3)
    for (const b of applied) {
      expect(b).toBeDisabled()
      expect(b).toHaveAttribute('title', 'Requires Operator role')
    }
    expect(screen.getByRole('button', { name: 'Explain' })).toBeDisabled()
    const res = await fetch(`${location.origin}/api/v1/findings/handle`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ids: ['f-1'], resolution: 'patched', note: '' }) })
    expect(res.status).toBe(403)
  })

  it('the API validates at the edge: unknown action, a note that is too long, reopening a finding that is open', async () => {
    renderApp('/findings/f-1')
    await screen.findByRole('heading', { name: 'Evidence' })
    const post = (path: string, b: unknown) => fetch(`${location.origin}/api/v1/findings/${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) })
    expect((await post('handle', { ids: ['f-1'], resolution: 'xoa', note: '' })).status).toBe(400)
    expect((await post('handle', { ids: ['f-1'], resolution: 'patched', note: 'x'.repeat(501) })).status).toBe(400)
    expect((await post('f-1/reopen', { note: '' })).status).toBe(409)
    expect((await post('handle', { ids: ['f-9'], resolution: 'patched', note: '' })).status).toBe(404)
    expect((await post('f-2/applied', { item: 'patch' })).status).toBe(400)
    expect((await post('f-1/applied', { item: 'rm -rf' })).status).toBe(400)
  })

  it('the page says so when the finding does not exist', async () => {
    renderApp('/findings/f-404')
    expect(await screen.findByText(/No such finding/)).toBeInTheDocument()
  })
})

/** Findings are collapsed until clicked: opens every closed toggle inside `root`. */
async function expandAll(root: HTMLElement = document.body) {
  for (const b of within(root).queryAllByRole('button').filter((x) => x.getAttribute('aria-expanded') === 'false')) await userEvent.click(b)
}

describe('findings: the device page\'s Findings tab', () => {
  it('shows this device\'s card only: its fix blocks, each CVE a link to its finding, Mark as handled… in place', async () => {
    sessionStore.set({ userId: 'u-admin' })
    renderApp('/devices/a-nas02?tab=findings')
    expect(await screen.findByRole('region', { name: 'Findings on this device' })).toBeInTheDocument()
    const card = await screen.findByRole('article', { name: 'NAS-PHOTOS' })
    await expandAll(card)
    expect(within(card).getByRole('link', { name: 'CVE-2022-27593' })).toHaveAttribute('href', '/findings/fv-nas02-ps-1')
    expect(within(card).queryByRole('link', { name: 'NAS-PHOTOS' })).toBeNull() // the page names the device already
    expect(within(card).getAllByRole('button', { name: /^Mark as handled: CVE-/ }).length).toBeGreaterThan(0)
    expect(screen.queryByText('CVE-2026-119977')).not.toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Recommended updates' })).toBeNull()
    await expectNoA11yViolations()
  })

  it('the finding page says when Vedette last matched it and, apart, when its source last gave the version', async () => {
    sessionStore.set({ userId: 'u-admin' })
    renderApp('/findings/f-1')
    expect(await screen.findByText(/^Found .+, last matched .+\.$/)).toBeInTheDocument()
    expect(screen.getByText(/^QNAP Photo Station 6\.0\.20: listed by the latest network scan, on \d{1,2} \w{3} \d{4}, \d{2}:\d{2}\.$/)).toBeInTheDocument()
    expect(screen.queryByText(/^First seen|, last seen /)).not.toBeInTheDocument()
  })

  it('is searched like every other list: the CVE id or the software narrows the card, a search that finds nothing says so', async () => {
    sessionStore.set({ userId: 'u-admin' })
    const u = userEvent.setup()
    renderApp('/devices/a-fw01?tab=findings')
    await expandAll(await screen.findByRole('article', { name: 'FW-HQ' }))
    expect(await screen.findByRole('link', { name: 'CVE-2026-123159' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'CVE-2024-21762' })).toBeInTheDocument()
    const search = screen.getByRole('searchbox', { name: "Search this device's findings" })
    await u.type(search, 'CVE-2024-21762')
    await waitFor(() => expect(screen.queryByRole('link', { name: 'CVE-2026-123159' })).toBeNull())
    expect(screen.getByRole('link', { name: 'CVE-2024-21762' })).toBeInTheDocument()
    await u.clear(search)
    await u.type(search, 'no-such-thing')
    expect(await screen.findByText('No open finding of this device matches “no-such-thing”.')).toBeInTheDocument()
  })

  it('a device with no open finding says so', async () => {
    sessionStore.set({ userId: 'u-admin' })
    renderApp('/devices/a-srvfile?tab=findings')
    expect(await screen.findByText('No open findings on this device.')).toBeInTheDocument()
    // only a question waits: the badge says so and leads to it, as the line under the card does
    expect(await screen.findByRole('link', { name: '1 item needs your input' })).toHaveAttribute('href', '/findings?tab=input&device=a-srvfile')
    expect(screen.getByRole('link', { name: 'Needs your input' })).toHaveAttribute('href', '/findings?tab=input&device=a-srvfile')
  })
})

describe('findings: Mark as handled form matrix', () => {
  it('Cancel drops the draft: the next opening starts with nothing chosen and an empty note', async () => {
    renderApp('/findings/f-1')
    const open = async () => { await userEvent.click(await screen.findByRole('button', { name: 'Mark as handled' })); return screen.findByRole('dialog', { name: 'Mark as handled' }) }
    let dlg = await open()
    await eachOption([
      { option: 'False positive', shown: ['Note: why (required)'], hidden: ['Note (optional)'] },
      { option: 'Cancel, open again', shown: ['Note (optional)'], hidden: ['Note: why (required)'] },
    ], async (o) => {
      if (o === 'False positive') { await userEvent.click(within(dlg).getByRole('radio', { name: /False positive/ })); fireEvent.change(within(dlg).getByRole('textbox'), { target: { value: 'not ours' } }); return }
      await userEvent.click(within(dlg).getByRole('button', { name: 'Cancel' }))
      dlg = await open()
    })
    for (const r of within(dlg).getAllByRole('radio')) expect(r).not.toBeChecked()
    expect(within(dlg).getByRole('textbox')).toHaveValue('')
  })
})

describe('findings: CVSS score (#825)', () => {
  it('FIRST bands for 3.x and 4.0 (0.0 None … 9.0–10.0 Critical); NVD\'s v2 bands for 2.0 (Low, Medium, High; no Critical)', () => {
    expect([0, 0.1, 3.9, 4, 6.9, 7, 8.9, 9, 10].map((s) => cvssBand(s, '3.1'))).toEqual(['none', 'low', 'low', 'medium', 'medium', 'high', 'high', 'critical', 'critical'])
    expect([0, 3.9, 4, 6.9, 7, 9.3, 10].map((s) => cvssBand(s, '2.0'))).toEqual(['low', 'low', 'medium', 'medium', 'high', 'high', 'high'])
  })

  it('a CVSS 2.0 score (only score NVD has) shows its v2 band and says "2.0" behind the ⓘ', async () => {
    render(<MemoryRouter><SeverityBadge severity={fromCvss({ score: 9.3, version: '2.0', vector: 'AV:N/AC:M/Au:N/C:C/I:C/A:C' })} detail /></MemoryRouter>)
    await userEvent.click(screen.getByRole('button', { name: 'About High 9.3' }))
    const tip = await screen.findByRole('dialog', { name: 'About High 9.3' })
    expect(tip).toHaveTextContent('CVSS 2.0 base score 9.3')
    expect(tip).toHaveTextContent('AV:N/AC:M/Au:N/C:C/I:C/A:C')
  })

  it('the finding page shows "Critical 9.8" in its first line, with the version and vector behind the ⓘ; no score says so', async () => {
    renderApp('/findings/f-1')
    const about = await screen.findByRole('button', { name: 'About Critical 9.8' })
    await userEvent.click(about)
    const tip = await screen.findByRole('dialog', { name: 'About Critical 9.8' })
    expect(tip).toHaveTextContent('CVSS 3.1 base score 9.8')
    // FIRST's terms of use: the vector with the score, and the attribution
    expect(tip).toHaveTextContent('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
    expect(tip).toHaveTextContent('CVSS is owned by FIRST and used by permission.')
    await expectNoA11yViolations()
    cleanup()
    renderApp('/findings/f-3')
    // no CVSS score: the band the exploited list gives, with no score and no ⓘ, never 0
    expect(await screen.findByRole('heading', { level: 1 })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^About (Critical|High|Medium|Low) \d/ })).toBeNull()
    expect(screen.queryByText(/^0\.0$/)).toBeNull()
  })
})

describe('findings: as a customer', () => {

  it('a device with no IP is named, says "No IP address" and offers no rescan', async () => {
    assetsStore.update((l) => l.map((a) => (a.id === 'a-web01' ? { ...a, ip: '—', hostname: null } : a)))
    renderApp('/findings/f-2')
    expect(await screen.findByRole('heading', { level: 1, name: /^Ubuntu may be affected/ })).toBeInTheDocument()
    expect(screen.getAllByText('No IP address').length).toBeGreaterThan(0)
    expect(screen.queryByRole('link', { name: 'Rescan this device' })).not.toBeInTheDocument()
    expect(screen.queryByText(/a-web01/)).not.toBeInTheDocument()
  })
})

describe('findings: accept risk until a day (S-MIT-1)', () => {
  it('the day runs from tomorrow to a year ahead, on the local calendar', () => {
    const today = new Date(2026, 10, 13, 23, 30)
    expect(untilBounds(today)).toEqual({ min: '2026-11-14', max: '2027-11-13' })
    expect(dayAfter(new Date(2026, 1, 28), 1)).toBe('2026-03-01')
    for (const [d, ok] of [['2026-11-13', false], ['2026-11-14', true], ['2027-11-13', true], ['2027-11-14', false], ['', false], ['14/11/2026', false]] as const) expect([d, untilOk(d, today)]).toEqual([d, ok])
  })

  it('needs a note and a day; a preset fills the day; the page says until when and by whom', async () => {
    renderApp('/findings/f-2')
    await userEvent.click(await screen.findByRole('button', { name: 'Mark as handled' }))
    const dlg = await screen.findByRole('dialog', { name: 'Mark as handled' })
    await userEvent.click(within(dlg).getByRole('radio', { name: /Accept the risk until/ }))
    await userEvent.click(within(dlg).getByRole('button', { name: 'Mark 1 finding' }))
    expect(await within(dlg).findByText(/^Say why \(at least 3 characters\)/)).toBeInTheDocument()
    expect(within(dlg).getByText('Choose a date from tomorrow up to one year from today.')).toBeInTheDocument()
    const date = within(dlg).getByLabelText('Accept until')
    expect(date).toHaveFocus() // the first field to fix takes the focus, so its reason is in view in a long dialog
    expect(date).toHaveAttribute('min', untilBounds().min)
    expect(date).toHaveAttribute('max', untilBounds().max)
    await userEvent.click(within(dlg).getByRole('button', { name: '90 days' }))
    expect(date).toHaveValue(dayAfter(new Date(), 90))
    await userEvent.type(within(dlg).getByLabelText('Note: why (required)'), 'No patch window before March')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Mark 1 finding' }))
    expect(await screen.findByRole('heading', { level: 1, name: /risk accepted until/ })).toBeInTheDocument()
    // the toast says the status as its badge does, with the day: not the option's "Accept the risk until…."
    expect(screen.getByText(/^Marked 1 finding: Risk accepted until \d{1,2} [A-Z][a-z]{2} \d{4}\.$/)).toBeInTheDocument()
    // said once, in the notice under the title: until when, by whom and why (the header no longer repeats it)
    expect(screen.getByTestId('closed-notice')).toHaveTextContent(/Risk accepted until .* by admin@acme\.example/)
    expect(screen.getByTestId('closed-notice')).toHaveTextContent('No patch window before March')
    expect(screen.queryByText(/^Risk accepted until .* by admin@acme\.example\. No patch window before March$/)).toBeNull()
    expect(findingsStore.get().find((x) => x.id === 'f-2')!.history.at(-1)?.action).toBe('risk_accepted')
  })
})

describe('findings: "I updated <software>" (S-MIT-1, item 14)', () => {
  const device = (source: 'manual' | 'nmap' | 'agent', version = '7.2.0') => http.get('*/api/v1/inventory/devices/:id', () => HttpResponse.json({ asset: { id: 'a-srvad', software: [
    { id: 's-srvad', display: 'FortiOS', vendor: 'Fortinet', product: 'FortiOS', version, source, confidence: 1, kev_cves: ['CVE-2026-96951'] },
  ] } }))

  it('hand-added software: the new version is sent once, the re-match closes what it fixes, the dialog says how many', async () => {
    let sent: unknown = null
    server.use(device('manual'), http.patch('*/api/v1/inventory/devices/:id/software/:sid', async ({ params, request }) => {
      sent = { sid: params.sid, ...(await request.json() as object) }
      // The backend re-match: the version is outside every range, so the finding closes by itself.
      findingsStore.update((l) => l.map((f) => (f.id === 'f-3' ? { ...f, status: 'not_relevant' as const, resolved_by: 'system' } : f)))
      return HttpResponse.json({ ok: true })
    }))
    renderApp('/findings/f-3')
    await userEvent.click(await screen.findByRole('button', { name: 'I updated FortiOS' }))
    const dlg = await screen.findByRole('dialog', { name: 'I updated FortiOS' })
    expect(within(dlg).getByText('Vedette has 7.2.0.')).toBeInTheDocument()
    const box = within(dlg).getByLabelText('New version')
    await userEvent.clear(box)
    await userEvent.type(box, '7.2.0')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Save and check' }))
    expect(await within(dlg).findByText(/^Vedette already has 7\.2\.0\./)).toBeInTheDocument()
    expect(sent).toBeNull()
    await userEvent.clear(box)
    await userEvent.type(box, '7.4.5')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Save and check' }))
    expect(await within(dlg).findByRole('status')).toHaveTextContent('Version 7.4.5 saved. 1 finding on SRV-AD no longer applies and was closed. None still match this version.')
    expect(sent).toEqual({ sid: 's-srvad', version: '7.4.5' })
    // The page re-reads the finding (now closed); the dialog and its answer stay until the person closes it.
    expect(await screen.findByRole('heading', { level: 1, name: 'SRV-AD: CVE-2026-96951 marked as not relevant', hidden: true })).toBeInTheDocument()
    expect(within(screen.getByRole('dialog', { name: 'I updated FortiOS' })).getByRole('status')).toHaveTextContent(/^Version 7\.4\.5 saved\./)
  })

  it('a refused version reads as a plain sentence', async () => {
    server.use(device('manual'), http.patch('*/api/v1/inventory/devices/:id/software/:sid', () => HttpResponse.json({ error: { code: 'duplicate_software', message: 'x' } }, { status: 409 })))
    renderApp('/findings/f-3')
    await userEvent.click(await screen.findByRole('button', { name: 'I updated FortiOS' }))
    const dlg = await screen.findByRole('dialog', { name: 'I updated FortiOS' })
    await userEvent.type(within(dlg).getByLabelText('New version'), '7.4.5')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Save and check' }))
    expect(await within(dlg).findByText('FortiOS 7.4.5 is already on SRV-AD. Remove the older FortiOS on the device page instead.')).toBeInTheDocument()
  })

  it('a version the device itself states otherwise is said back once, and "Save anyway" keeps it', async () => {
    const sent: unknown[] = []
    server.use(device('manual'), http.patch('*/api/v1/inventory/devices/:id/software/:sid', async ({ request }) => {
      const body = await request.json() as { confirm?: boolean }
      sent.push(body)
      if (!body.confirm) return HttpResponse.json({ error: { code: 'contradicts_device', message: 'The device itself reports FortiOS 7.2.0 (its SNMP answer, 27 Nov 2026), not 7.4.5.' } }, { status: 409 })
      findingsStore.update((l) => l.map((f) => (f.id === 'f-3' ? { ...f, status: 'not_relevant' as const, resolved_by: 'system' } : f)))
      return HttpResponse.json({ ok: true, changed: true })
    }))
    renderApp('/findings/f-3')
    await userEvent.click(await screen.findByRole('button', { name: 'I updated FortiOS' }))
    const dlg = await screen.findByRole('dialog', { name: 'I updated FortiOS' })
    await userEvent.type(within(dlg).getByLabelText('New version'), '7.4.5')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Save and check' }))
    expect(await within(dlg).findByText(/^The device itself reports FortiOS 7\.2\.0/)).toBeInTheDocument()
    await userEvent.click(within(dlg).getByRole('button', { name: 'Save anyway' }))
    expect(await within(dlg).findByRole('status')).toHaveTextContent(/^Version 7\.4\.5 saved\./)
    expect(sent).toEqual([{ version: '7.4.5' }, { version: '7.4.5', confirm: true }])
  })

  it('software a scan reads: the button is "Check this device now" itself, with its busy state, no detour', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'sensor-active' ? { ...m, enabled: true } : m)))
    inventorySettingsStore.update((st) => ({ ...st, active: { ...st.active, enabled: true }, scope_confirmed_at: st.scope_confirmed_at ?? '2026-11-01T00:00:00.000Z' }))
    let sent: unknown = null
    let release!: () => void
    const held = new Promise<void>((r) => { release = r })
    server.use(device('nmap'), http.post('*/api/v1/scanning/engines/nmap-discovery/run', async ({ request }) => {
      sent = await request.json()
      await held
      return HttpResponse.json({ engine: 'nmap-discovery', id: 'sar-g12', label: 'Check 192.168.10.20', target_id: 'a-srvad', started_at: new Date().toISOString(), progress: null }, { status: 202 })
    }))
    renderApp('/findings/f-3')
    const btn = await screen.findByRole('button', { name: 'Check this device now' })
    await waitFor(() => expect(btn).toBeEnabled())
    await userEvent.click(btn)
    expect(await screen.findByRole('button', { name: 'Scanning…' })).toHaveAttribute('aria-busy', 'true')
    expect(sent).toEqual({ targets: ['a-srvad'] })
    expect(screen.queryByRole('dialog')).toBeNull() // no detour through an explanation
    release()
  })

  it('a viewer sees the check refused with the role it needs, as on the device page', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'sensor-active' ? { ...m, enabled: true } : m)))
    inventorySettingsStore.update((st) => ({ ...st, active: { ...st.active, enabled: true }, scope_confirmed_at: st.scope_confirmed_at ?? '2026-11-01T00:00:00.000Z' }))
    server.use(device('nmap'))
    renderApp('/findings/f-3', { role: 'viewer' })
    expect(await screen.findByRole('button', { name: 'Check this device now' })).toBeDisabled()
    expect(screen.getByText('Requires Admin role')).toBeInTheDocument()
  })

  it('#944: scan-read software on a device Vedette may not scan now: the reason, no button (one rule with the device page)', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'sensor-active' ? { ...m, enabled: true } : m)))
    inventorySettingsStore.update((st) => ({ ...st, active: { ...st.active, enabled: true }, scope_confirmed_at: st.scope_confirmed_at ?? '2026-11-01T00:00:00.000Z' }))
    sessionStore.set({ userId: 'u-admin' })
    expect((await fetch(`${location.origin}/api/v1/inventory/devices/a-srvad/sources`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ scan: 'off' }) })).status).toBe(200)
    server.use(device('nmap'))
    renderApp('/findings/f-3')
    expect(await screen.findByText('Set to never scan, or its network scan is off under Sources: network discovery does not check it.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Check this device now' })).toBeNull()
  })

  it('#944: an unknown source gets no control', async () => {
    server.use(http.get('*/api/v1/inventory/devices/:id', () => HttpResponse.json({ asset: { id: 'a-srvad', software: [
      { id: 's-srvad', display: 'FortiOS', vendor: 'Fortinet', product: 'FortiOS', version: '7.2.0', source: 'some-new-sensor', confidence: 1, kev_cves: ['CVE-2026-96951'] },
    ] } })))
    renderApp('/findings/f-3')
    expect(await screen.findByRole('heading', { level: 1 })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^I updated|^Check this device now$/ })).toBeNull()
  })

  // S-MIT-1 (agent-intake INV-23): "I updated it" on software an agent reads.
  const agentOn = () => modulesStore.update((l) => l.map((m) => (m.id === 'agent-intake' ? { ...m, enabled: true } : m)))
  type Report = { agent: 'osquery' | 'wazuh' | 'none' | 'box'; asked_at?: string | null; ask_again_at?: string | null; last_seen?: string | null; stale?: boolean; wazuh_interval_minutes?: number | null }
  const reportOf = (r: Report) => ({ asked_at: null, ask_again_at: null, last_seen: null, stale: false, wazuh_interval_minutes: null, ...r })
  const report = (r: Report) => http.get('*/api/v1/inventory/agents/devices/:id/report', () => HttpResponse.json(reportOf(r)))
  const asked = (r: Report = { agent: 'osquery' }) => http.post('*/api/v1/inventory/agents/devices/:id/report', () =>
    HttpResponse.json(reportOf({ asked_at: '2026-11-17T09:05:00Z', ask_again_at: '2026-11-17T09:15:00Z', last_seen: new Date().toISOString(), ...r })))
  const kernel = http.get('*/api/v1/inventory/devices/:id', () => HttpResponse.json({ asset: { id: 'a-srvad', software: [
    { id: 's-srvad', display: 'Linux Kernel', vendor: 'Linux', product: 'Kernel', version: '7.0.0', source: 'agent', confidence: 1, kev_cves: ['CVE-2026-96951'] },
  ] } }))
  const windows = http.get('*/api/v1/inventory/devices/:id', () => HttpResponse.json({ asset: { id: 'a-srvad', software: [
    { id: 's-srvad', display: 'Windows Server 2025', vendor: 'microsoft', product: 'Windows Server 2025', version: '10.0.26100.1742', source: 'agent', confidence: 1, kev_cves: ['CVE-2026-96951'] },
  ] } }))

  it('S-MIT-1: an osquery app row: "ask the agent now", its busy state, then the ask in words (no restart for an app)', async () => {
    agentOn()
    let asked = 0
    let release!: () => void
    const held = new Promise<void>((r) => { release = r })
    server.use(device('agent'), report({ agent: 'osquery' }), http.post('*/api/v1/inventory/agents/devices/:id/report', async ({ params }) => {
      asked++
      expect(params.id).toBe('a-srvad')
      await held
      return HttpResponse.json(reportOf({ agent: 'osquery', asked_at: '2026-11-17T09:05:00Z', ask_again_at: '2026-11-17T09:15:00Z' }))
    }))
    renderApp('/findings/f-3')
    const btn = await screen.findByRole('button', { name: 'I updated it: ask the agent now' })
    expect(screen.queryByText(/restart/i)).toBeNull()
    await userEvent.click(btn)
    expect(await screen.findByRole('button', { name: 'Asking…' })).toHaveAttribute('aria-busy', 'true')
    release()
    const status = await screen.findByText(/^Asked at \d\d:\d\d\. SRV-AD sends its software list within about 5 minutes; the findings this update fixes then close by themselves\.$/)
    expect(status).toHaveAttribute('role', 'status')
    expect(asked).toBe(1)
    expect(screen.queryByRole('button', { name: 'I updated it: ask the agent now' })).toBeNull()
  })

  it('S-MIT-1: an osquery OS row (Windows cumulative update) says the build changes only after the restart, before and after the ask', async () => {
    agentOn()
    server.use(windows, report({ agent: 'osquery' }), asked())
    renderApp('/findings/f-3')
    expect(await screen.findByText('Restart SRV-AD first if the update asks for it: the new build shows only after the restart.')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'I updated it: ask the agent now' }))
    // #953: "ask again" names the time a new ask is possible
    expect(await screen.findByText(/^Asked at \d\d:\d\d\. SRV-AD sends its software list within about 5 minutes\. The new build shows only after the restart the update needs: if SRV-AD has not restarted yet, restart it; its agent then reports the new build within the hour, or ask again from \d\d:\d\d\.$/)).toBeInTheDocument()
  })

  it('#953: a Linux kernel row is an OS row too: the restart wording', async () => {
    agentOn()
    server.use(kernel, report({ agent: 'osquery' }))
    renderApp('/findings/f-3')
    expect(await screen.findByText('Restart SRV-AD first if the update asks for it: the new build shows only after the restart.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'I updated it: ask the agent now' })).toBeEnabled()
  })

  it('#953: before a new ask is possible, the button waits with the time it comes back', async () => {
    agentOn()
    const at = new Date(Date.now() + 5 * 60_000).toISOString()
    server.use(device('agent'), report({ agent: 'osquery', ask_again_at: at }))
    renderApp('/findings/f-3')
    expect(await screen.findByRole('button', { name: 'I updated it: ask the agent now' })).toBeDisabled()
    expect(screen.getAllByText(/^You can ask again from \d\d:\d\d\.$/).length).toBeGreaterThan(0)
  })

  it('#953: an agent that has not called for a while: said before the ask, and the ask promises no 5 minutes', async () => {
    agentOn()
    server.use(device('agent'), report({ agent: 'osquery', stale: true, last_seen: '2026-11-15T08:00:00Z' }), asked({ agent: 'osquery', stale: true, last_seen: '2026-11-15T08:00:00Z' }))
    renderApp('/findings/f-3')
    expect(await screen.findByText(/^The agent on SRV-AD has not called Vedette since 15 Nov 2026, \d\d:\d\d: an ask reaches it only when it is back on\.$/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'I updated it: ask the agent now' }))
    expect(await screen.findByText(/^Asked at \d\d:\d\d\. The agent on SRV-AD has not called Vedette since 15 Nov 2026, \d\d:\d\d: it gets the ask only if it is back on within 15 minutes/)).toBeInTheDocument()
    expect(screen.queryByText(/within about 5 minutes/)).toBeNull()
  })

  it('S-MIT-1: an ask already open shows as such after a reload; a refused ask reads as the box\'s sentence', async () => {
    agentOn()
    server.use(device('agent'), report({ agent: 'osquery', asked_at: '2026-11-17T09:05:00Z' }))
    renderApp('/findings/f-3')
    expect(await screen.findByText(/^Asked at \d\d:\d\d\. SRV-AD sends its software list/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'I updated it: ask the agent now' })).toBeNull()
    cleanup()
    server.use(report({ agent: 'osquery' }), http.post('*/api/v1/inventory/agents/devices/:id/report', () =>
      HttpResponse.json({ error: { code: 'rate_limited', message: 'Vedette asked this agent less than 10 minutes ago and its list came. Ask again in 4 minutes.', retry_after: 240 } }, { status: 429 })))
    renderApp('/findings/f-3')
    await userEvent.click(await screen.findByRole('button', { name: 'I updated it: ask the agent now' }))
    expect(await screen.findByText('Vedette asked this agent less than 10 minutes ago and its list came. Ask again in 4 minutes.')).toHaveAttribute('role', 'alert')
  })

  it('S-MIT-1: a viewer sees the ask refused with the role it needs', async () => {
    agentOn()
    server.use(device('agent'), report({ agent: 'osquery' }))
    renderApp('/findings/f-3', { role: 'viewer' })
    expect(await screen.findByRole('button', { name: 'I updated it: ask the agent now' })).toBeDisabled()
    expect(screen.getAllByText('Requires Operator role').length).toBeGreaterThan(0)
  })

  it('S-MIT-1: a device only Wazuh reads: no button, a line with Vedette\'s pull interval', async () => {
    agentOn()
    server.use(device('agent'), report({ agent: 'wazuh', wazuh_interval_minutes: 60 }))
    renderApp('/findings/f-3')
    expect(await screen.findByText('Vedette cannot ask Wazuh to read SRV-AD now. Wazuh reads its software on its own schedule (hourly by default) and Vedette pulls from Wazuh every hour; the findings this update fixes then close by themselves.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^I updated/ })).toBeNull()
  })

  it('#953: agent-intake off, or no agent of this box reads the device: no button and no promise that one reports', async () => {
    const none = /^No agent reports the software of SRV-AD to Vedette now: its last list stays until an agent reports again\./
    server.use(device('agent'))
    renderApp('/findings/f-3')
    expect(await screen.findByText(none)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^I updated/ })).toBeNull()
    cleanup()
    agentOn()
    server.use(windows, report({ agent: 'none' }))
    renderApp('/findings/f-3')
    expect(await screen.findByText(none)).toBeInTheDocument()
    expect(screen.queryByText(/within the hour/)).toBeNull()
  })

  it('the Vedette box reads its own packages: a line with its hourly read, no button', async () => {
    agentOn()
    server.use(kernel, report({ agent: 'box' }))
    renderApp('/findings/f-3')
    expect(await screen.findByText('Restart SRV-AD if the update asks for it: the new build shows only after the restart. Vedette reads its own packages every hour, and these findings then close on their own.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^I updated/ })).toBeNull()
  })
})

describe('findings: a closed finding opens with why it was closed (S-MIT-1)', () => {
  const close = (patch: Partial<Pick<FindingDetail, 'resolved_by' | 'resolved_at' | 'resolution_note'>> & { status: 'not_relevant' | 'false_positive' }) => findingsStore.update((l) => l.map((f) => (f.id === 'f-2' ? { ...f, ...patch } : f)))
  const AT = '2026-11-12T09:00:00Z'

  it('closed by Vedette from distro data: the reason leads, the open-finding blocks sit under "Before it was closed"', async () => {
    close({ status: 'not_relevant', resolved_by: 'system', resolved_at: AT, resolution_note: 'Ubuntu 24.04 fixed it in 1:9.6p1-3ubuntu13.14; this device has 1:9.6p1-3ubuntu13.14.' })
    renderApp('/findings/f-2')
    const n = await screen.findByTestId('closed-notice')
    expect(n).toHaveTextContent(/^Vedette closed this as not relevant on /)
    expect(n).toHaveTextContent('Ubuntu 24.04 fixed it in 1:9.6p1-3ubuntu13.14')
    expect(within(n).getByRole('button', { name: 'Reopen finding' })).toBeEnabled()
    const before = screen.getByTestId('before-closed')
    expect(before).not.toHaveAttribute('open')
    expect(within(before).getByText('Before it was closed: evidence, how to check, what to do')).toBeInTheDocument()
    expect(before).toContainElement(screen.getByRole('heading', { name: 'Evidence' }))
    // the notice comes before the blocks in the page
    expect(n.compareDocumentPosition(before) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  })

  it('closed by a person: name, day and note', async () => {
    close({ status: 'false_positive', resolved_by: 'admin@acme.example', resolved_at: AT, resolution_note: 'Lab network, not ours' })
    renderApp('/findings/f-2')
    const n = await screen.findByTestId('closed-notice')
    expect(n).toHaveTextContent(/^Closed as a false positive by admin@acme\.example on /)
    expect(n).toHaveTextContent('Lab network, not ours')
    await userEvent.click(within(n).getByRole('button', { name: 'Reopen finding' }))
    await waitFor(() => expect(screen.queryByTestId('closed-notice')).not.toBeInTheDocument())
  })

  it('risk accepted: the end day, who and the reason', async () => {
    accepted.update((m) => ({ ...m, 'f-2': '2027-02-12' }))
    close({ status: 'not_relevant', resolved_by: 'admin@acme.example', resolved_at: AT, resolution_note: 'No patch window before March' })
    renderApp('/findings/f-2')
    const n = await screen.findByTestId('closed-notice')
    expect(n).toHaveTextContent(/^Risk accepted until 12 Feb 2027 by admin@acme\.example on /)
    expect(n).toHaveTextContent('No patch window before March')
    expect(n).toHaveTextContent('It reopens by itself after that day.')
  })

  it('an open finding is unchanged: no notice, blocks not folded', async () => {
    renderApp('/findings/f-2')
    expect(await screen.findByRole('heading', { name: 'Evidence' })).toBeInTheDocument()
    expect(screen.queryByTestId('closed-notice')).not.toBeInTheDocument()
    expect(screen.queryByTestId('before-closed')).not.toBeInTheDocument()
  })
})

describe('findings: one update, one item; the agent\'s build is a detection (TUNE-5b W-1/W-3)', () => {
  const agentWindows = () => {
    const ev = (cve: string) => ({ summary: `The agent on SRV-AD reports Windows Server 2025 build 26100.1742. Microsoft fixed ${cve} in build 26100.2314.`, checked_at: new Date().toISOString(), agent: true })
    findingsStore.update((l) => [...l.map((f) => (f.id === 'f-3' ? { ...f, evidence: ev(f.cve) } : f)),
      { ...l.find((f) => f.id === 'f-3')!, id: 'f-9', cve: 'CVE-2024-43451', evidence: ev('CVE-2024-43451') }])
  }

  it('the finding says the agent detected it and asks nothing to look up', async () => {
    agentWindows()
    // agent-intake on and the device's osquery agent calls: an agent reports the version now
    modulesStore.update((l) => l.map((m) => (m.id === 'agent-intake' ? { ...m, enabled: true } : m)))
    assetsStore.update((l) => l.map((a) => (a.id === 'a-srvad' ? { ...a, software: a.software.map((x) => ({ ...x, source: 'agent' as const })) } : a)))
    const reportIs = (agent: string, stale = false) => server.use(http.get('*/api/v1/inventory/agents/devices/:id/report', () =>
      HttpResponse.json({ agent, asked_at: null, ask_again_at: null, last_seen: '2026-11-10T08:00:00Z', stale, wazuh_interval_minutes: null })))
    reportIs('osquery')
    renderApp('/findings/f-9')
    expect(await screen.findByRole('heading', { level: 1, name: 'SRV-AD has CVE-2024-43451: its agent reports an affected version' })).toBeInTheDocument()
    expect(screen.getByText(/^Nothing to look up: the agent on SRV-AD reports the installed version/)).toBeInTheDocument()
    expect(screen.queryByText(/About screen/)).toBeNull()
    cleanup()
    // no agent reports the device now: no agent bound, the node silent past its limit, or agent-intake off. The title says the version
    // is the last one an agent reported, as the "I updated it" line beside it does.
    for (const set of [() => reportIs('none'), () => reportIs('osquery', true), () => modulesStore.update((l) => l.map((m) => (m.id === 'agent-intake' ? { ...m, enabled: false } : m)))]) {
      set()
      renderApp('/findings/f-9')
      expect(await screen.findByRole('heading', { level: 1, name: 'SRV-AD has CVE-2024-43451: an agent last reported an affected version' })).toBeInTheDocument()
      cleanup()
    }
    // agent-intake off (the last case): "How to check" says the same, and promises no new version by itself
    renderApp('/findings/f-9')
    expect(await screen.findByText(/^Nothing to look up: an agent last reported the installed version of .* on SRV-AD/)).toBeInTheDocument()
    expect(screen.queryByText(/usually within two hours/)).toBeNull()
  })
})
