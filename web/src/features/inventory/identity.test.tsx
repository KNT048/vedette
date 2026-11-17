import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { assetsStore } from '@/mocks/stores'
import { ensureBox } from './mocks'

// The device page says what the device is (maker, model, OS or firmware) the same way everywhere, each value with where it came
// from and how sure: a network scan's OS fingerprint reads as a guess, an OS the device announces over LLDP says so.
vi.setConfig({ testTimeout: 30_000 })
beforeEach(() => ensureBox())

const T = { timeout: 5000 }
const overviewRow = async (label: string) => {
  const term = await screen.findByText(label, { selector: 'dt' }, T)
  return term.nextElementSibling as HTMLElement
}

describe('Device page: maker, model and OS with their source', () => {
  it('General information lists Maker, Model and OS or firmware; a scan OS reads as a guess, never as a confidence level', async () => {
    const { container } = renderApp('/devices/a-srvad')
    expect(await overviewRow('Maker')).toHaveTextContent(/^Dell\s*Passive\s*\(high confidence\)$/)
    expect(await overviewRow('Model')).toHaveTextContent(/^PowerEdge T140\s*SNMP\s*\(high confidence\)$/)
    const os = await overviewRow('OS or firmware')
    expect(os).toHaveTextContent('Windows Server 2016')
    expect(within(os).getByText('Network scan guess')).toBeInTheDocument()
    expect(os).not.toHaveTextContent(/confidence/)
    await expectNoA11yViolations(container)
  })

  it('a value nobody reported says so', async () => {
    renderApp('/devices/a-srvfile')
    expect(await overviewRow('Model')).toHaveTextContent('Not known yet')
  })

  it('an OS the device announces about itself: the Overview and the Software tab show it with that source', async () => {
    assetsStore.update((l) => l.map((a) => (a.id === 'a-sw01' ? { ...a, os: { value: 'JUNOS 15.1R7.9', source: 'passive' as const, confidence: 0.5, seen_at: a.last_seen, basis: 'stated' as const } } : a)))
    const user = userEvent.setup()
    renderApp('/devices/a-sw01')
    const os = await overviewRow('OS or firmware')
    expect(os).toHaveTextContent(/^JUNOS 15\.1R7\.9\s*Announced by the device \(LLDP\)$/)
    await user.click(screen.getByRole('tab', { name: /Software/ }))
    const line = await screen.findByTestId('software-os', undefined, T)
    expect(line).toHaveTextContent('Operating system or firmware')
    expect(line).toHaveTextContent('JUNOS 15.1R7.9')
    expect(line).toHaveTextContent('Announced by the device (LLDP)')
  })
})
