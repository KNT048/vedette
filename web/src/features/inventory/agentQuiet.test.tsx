import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AgentQuietNote } from './AgentQuiet'
import { renderApp } from '@/test/render'
import { assetsStore, modulesStore } from '@/mocks/stores'
import { ensureBox } from './mocks'

// A Windows Server with an osquery agent reported once, then went silent. The person opens the device and Settings > Agents and is told
// that the agent is quiet, since when, and the exact commands to check and restart the service.
vi.setConfig({ testTimeout: 30_000 })
beforeEach(() => ensureBox())

const T = { timeout: 5000 }
const hoursAgo = (h: number) => new Date(Date.now() - h * 3_600_000).toISOString()
// the machine's software comes from its osquery agent, which last called at `at`
const setSeen = (id: string, at: string) => assetsStore.update((l) => l.map((a) => (a.id === id
  ? { ...a, last_seen: at, software: a.software.map((x, i) => (i === 0 ? { ...x, source: 'agent' as const } : x)) } : a)))
const on = () => modulesStore.update((l) => l.map((m) => (m.id === 'agent-intake' ? { ...m, enabled: true } : m)))

describe('A quiet agent is shown where the person looks', () => {
  it('the device page: the agent row says since when it is quiet, no "last report" beside it; Check gives the Windows commands', async () => {
    on()
    const since = hoursAgo(72)
    setSeen('a-srvacc', since)
    const user = userEvent.setup()
    renderApp('/devices/a-srvacc', { role: 'admin' })
    const list = await screen.findByRole('list', { name: 'Sources' }, T)
    const row = await waitFor(() => { const li = list.querySelector<HTMLElement>('li[data-source="agent"]')!; expect(li).toHaveAttribute('data-state', 'quiet'); return li }, T)
    expect(row).toHaveTextContent(/Quiet since 3 days ago/)
    expect(row).not.toHaveTextContent(/last report/)
    // the steps are behind Check, never on the page by default
    expect(within(list).queryByTestId('agent-quiet')).toBeNull()
    await user.click(within(row).getByRole('button', { name: 'Check' }))
    const dlg = await screen.findByRole('dialog', { name: 'Agent on SRV-ACCOUNTS' }, T)
    const note = await within(dlg).findByTestId('agent-quiet', undefined, T)
    expect(note).toHaveTextContent(/^Agent quiet since .* — check the service on the device/)
    expect(note).toHaveTextContent(new Date(since).getFullYear().toString())
    expect(within(note).getByText('Get-Service osqueryd')).toBeInTheDocument()
    expect(within(note).getByText('Restart-Service osqueryd')).toBeInTheDocument()
    expect(note).toHaveTextContent('PowerShell as Administrator')
    // the other common cause has its own text and command: the service runs but cannot reach the box
    expect(note).toHaveTextContent('If the service is stopped')
    expect(note).toHaveTextContent('If the service is running')
    expect(note).toHaveTextContent(/firewall or proxy/)
    expect(await within(note).findByText(/^Test-NetConnection .* -Port \d+$/, undefined, T)).toBeInTheDocument()
  })

  it('an agent that called a minute ago reads Reporting with its last report, and no warning', async () => {
    on()
    setSeen('a-srvacc', hoursAgo(0))
    renderApp('/devices/a-srvacc', { role: 'admin' })
    const list = await screen.findByRole('list', { name: 'Sources' }, T)
    const row = await waitFor(() => { const li = list.querySelector<HTMLElement>('li[data-source="agent"]')!; expect(li).toHaveAttribute('data-state', 'reporting'); return li }, T)
    expect(row).toHaveTextContent('Reporting (osquery)')
    expect(row).toHaveTextContent(/last report/)
    expect(within(list).queryByTestId('agent-quiet')).toBeNull()
  })

  it('Settings > Agents lists the quiet machine first with its state, time and commands', async () => {
    on()
    setSeen('a-srvacc', hoursAgo(72))
    renderApp('/devices/setup#agents', { role: 'admin' })
    const table = await screen.findByRole('table', { name: 'Machines with an osquery agent' }, T)
    const rows = within(table).getAllByRole('row').slice(1)
    expect(rows[0]).toHaveTextContent('SRV-ACCOUNTS')
    expect(rows[0]).toHaveTextContent('Windows')
    expect(rows[0]).toHaveTextContent('Quiet')
    expect(rows[0]).toHaveTextContent(/Quiet since/)
    expect(rows[0]).toHaveTextContent('Restart-Service osqueryd')
  })
})

describe('The other cases get their own text', () => {
  it('a Linux agent that never reported is running: no restart command, its own sentence', () => {
    render(<AgentQuietNote state="never_reported" since={null} os="linux" box="https://10.0.0.5:8443" />)
    const note = screen.getByTestId('agent-never-reported')
    expect(note).toHaveTextContent('Agent running, but it has not reported anything yet')
    expect(screen.queryByText(/systemctl restart/)).toBeNull()
  })

  it('a quiet Linux agent gets the systemctl commands and a reachability check against the box address it uses', () => {
    render(<AgentQuietNote state="quiet" since={hoursAgo(5)} os="linux" box="https://10.0.0.5:8443" />)
    const note = screen.getByTestId('agent-quiet')
    expect(within(note).getByText('sudo systemctl restart osqueryd')).toBeInTheDocument()
    expect(within(note).getByText("timeout 5 bash -c '</dev/tcp/10.0.0.5/8443' && echo reachable")).toBeInTheDocument()
    expect(note).toHaveTextContent('10.0.0.5:8443')
    expect(note).toHaveTextContent('/etc/init.d/osqueryd')
  })
})

describe('A stale agent record is cleared in Settings without revoking the token', () => {
  it('Remove takes the machine off the list and the device page stops saying quiet', async () => {
    on()
    setSeen('a-srvacc', hoursAgo(72))
    const user = userEvent.setup()
    renderApp('/devices/setup#agents', { role: 'admin' })
    const table = await screen.findByRole('table', { name: 'Machines with an osquery agent' }, T)
    await user.click(await within(table).findByRole('button', { name: 'Remove the record of SRV-ACCOUNTS' }, T))
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Remove the record of SRV-ACCOUNTS' })).toBeNull(), T)
    expect(screen.getByRole('table', { name: 'Enrollment tokens' })).toBeInTheDocument()
  })
})
