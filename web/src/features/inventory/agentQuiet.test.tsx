import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
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
  it('the device page says since when and gives the Windows commands once the agent is past its schedule', async () => {
    on()
    const since = hoursAgo(72)
    setSeen('a-srvacc', since)
    renderApp('/devices/a-srvacc', { role: 'admin' })
    const list = await screen.findByRole('list', { name: 'Sources' }, T)
    const note = await within(list).findByTestId('agent-quiet', undefined, T)
    expect(note).toHaveTextContent(/^Agent quiet since .* — check the service on the device/)
    expect(note).toHaveTextContent(new Date(since).getFullYear().toString())
    expect(within(note).getByText('Get-Service osqueryd')).toBeInTheDocument()
    expect(within(note).getByText('Restart-Service osqueryd')).toBeInTheDocument()
    expect(note).toHaveTextContent('PowerShell as Administrator')
  })

  it('an agent that called a minute ago shows no warning', async () => {
    on()
    setSeen('a-srvacc', hoursAgo(0))
    renderApp('/devices/a-srvacc', { role: 'admin' })
    const list = await screen.findByRole('list', { name: 'Sources' }, T)
    await within(list).findByText('Agent (osquery or Wazuh)', undefined, T)
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
