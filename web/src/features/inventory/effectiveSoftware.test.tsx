import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { assetsStore } from '@/mocks/stores'
import { ensureBox } from './mocks'

// The Software tab shows one line per software (inventory INV-50): the strongest source's value, the other sources under it, and
// one notice only when another source reads another release.
vi.setConfig({ testTimeout: 30_000 })
beforeEach(() => ensureBox())
const T = { timeout: 5000 }

const row = async (name: string) => {
  const table = await screen.findByRole('table', { name: /software/i }, T)
  const rows = within(table).getAllByRole('row').filter((r) => within(r).queryAllByText(name).length > 0)
  return rows
}

describe('the device Software tab, one line per software', () => {
  it('three sources of OpenSSH are one line with the agent\'s value, the others listed, and no notice', async () => {
    renderApp('/devices/a-fw01?tab=software')
    await screen.findByRole('table', { name: /software/i }, T)
    await waitFor(async () => expect(await row('OpenSSH')).toHaveLength(1), T)
    const [ssh] = await row('OpenSSH')
    // the agent's package row says the package release the match compares, the upstream version under it
    expect(within(ssh!).getByTestId('software-package-release')).toHaveTextContent('10.2_p1-r1Upstream version 10.2p1')
    expect(within(ssh!).getByTestId('software-also-seen').textContent).toMatch(/Also seen by: 10\.2 \(Manual.*; 10\.2 \(Active scan/)
    expect(within(ssh!).queryByTestId('software-differs')).toBeNull()
  })

  it('an entry and a newer banner of another release: one line, the entry stays, one notice; Use takes the reading', async () => {
    const user = userEvent.setup()
    renderApp('/devices/a-fw01?tab=software')
    await waitFor(async () => expect(await row('nginx')).toHaveLength(1), T)
    const [web] = await row('nginx')
    expect(within(web!).getByText('1.24.0')).toBeInTheDocument()
    expect(within(web!).getByTestId('software-differs').textContent).toMatch(/Active scan reads 1\.26\.1/)
    await user.click(within(web!).getByRole('button', { name: 'Use version 1.26.1 for nginx' }))
    await waitFor(() => expect(assetsStore.get().find((a) => a.id === 'a-fw01')!.software.find((s) => s.id === 's-fw01-web-entry')!.version).toBe('1.26.1'), T)
    await waitFor(async () => expect(within((await row('nginx'))[0]!).queryByTestId('software-differs')).toBeNull(), T)
  })

  it('an entry and a banner of the same release give no notice', async () => {
    assetsStore.update((l) => l.map((a) => (a.id === 'a-fw01' ? { ...a, software: a.software.filter((s) => s.id !== 's-fw01-ssh-agent') } : a)))
    renderApp('/devices/a-fw01?tab=software')
    await waitFor(async () => expect(await row('OpenSSH')).toHaveLength(1), T)
    const [ssh] = await row('OpenSSH')
    expect(within(ssh!).getByTestId('software-also-seen').textContent).toMatch(/Active scan/)
    expect(within(ssh!).queryByTestId('software-differs')).toBeNull()
  })

  it('an entry and a later SNMP reading of another release: the notice names the SNMP reading', async () => {
    assetsStore.update((l) => l.map((a) => (a.id === 'a-fw01' ? { ...a, software: [...a.software.filter((s) => s.id !== 's-fw01-ssh-agent'), { id: 's-fw01-ssh-snmp', display: 'OpenSSH', vendor: 'OpenBSD', product: 'OpenSSH', version: '9.8', kev: [], source: 'snmp' as const, confidence: 0.8 }] } : a)))
    renderApp('/devices/a-fw01?tab=software')
    await waitFor(async () => expect(await row('OpenSSH')).toHaveLength(1), T)
    const [ssh] = await row('OpenSSH')
    expect(within(ssh!).getByTestId('software-differs').textContent).toMatch(/SNMP reads 9\.8/)
  })

  it('an agent line with an outranked entry of another release: no notice for the entry', async () => {
    assetsStore.update((l) => l.map((a) => (a.id === 'a-fw01' ? { ...a, software: [...a.software.filter((s) => !s.id.startsWith('s-fw01-ssh')),
      { id: 's-fw01-ssh-agent', display: 'OpenSSH', vendor: 'OpenBSD', product: 'OpenSSH', version: '10.2p1', kev: [], source: 'agent' as const, confidence: 0.95 },
      { id: 's-fw01-ssh-hand', display: 'OpenSSH', vendor: 'OpenBSD', product: 'OpenSSH', version: '9.0', kev: [], source: 'manual' as const, confidence: 1 }] } : a)))
    renderApp('/devices/a-fw01?tab=software')
    await waitFor(async () => expect(await row('OpenSSH')).toHaveLength(1), T)
    const [ssh] = await row('OpenSSH')
    expect(within(ssh!).getByText('10.2p1')).toBeInTheDocument()
    expect(within(ssh!).getByTestId('software-also-seen').textContent).toMatch(/9\.0 \(Manual/)
    expect(within(ssh!).queryByTestId('software-differs')).toBeNull()
  })
})
