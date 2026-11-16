import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { assetsStore } from '@/mocks/stores'
import { adminNetwork } from './Hardening'

const code = (label: RegExp) => screen.getAllByLabelText(label)[0]!.textContent ?? ''

describe('M2-1: general hardening when no confirmed pack exists (mitigation INV-8)', () => {
  it('labels it as not a Vedette recommendation, selects the firewall in Devices and fills in the admin network the person types', async () => {
    renderApp('/findings/f-2')
    const block = await screen.findByRole('region', { name: 'General hardening' })
    expect(within(block).getByText('Not a Vedette recommendation for this CVE')).toBeInTheDocument()
    expect(within(block).queryByText(/Vedette confirmed/)).toBeNull()
    const vendors = within(block).getByRole('group', { name: 'Firewall vendor' })
    expect(within(vendors).getByRole('button', { name: 'FortiGate (in Devices)' })).toHaveAttribute('aria-pressed', 'true')
    let fg = code(/FortiGate CLI/)
    expect(fg).toContain('set subnet 192.168.1.0/24')
    expect(fg).toContain('set subnet 192.168.10.12/32')
    expect(fg).toContain('set tcp-portrange 80 443')
    expect(within(block).getByText('Example')).toBeInTheDocument()

    const field = within(block).getByRole('textbox', { name: /Your admin network/ })
    await userEvent.clear(field)
    await userEvent.type(field, '10.20.0.0/16')
    fg = code(/FortiGate CLI/)
    expect(fg).toContain('set subnet 10.20.0.0/16')
    expect(within(block).queryByText('Example')).toBeNull()
    await userEvent.clear(field)
    await userEvent.type(field, '10.20.0.0/40')
    expect(await within(block).findByText(/Type a network such as/)).toBeInTheDocument()
    expect(code(/FortiGate CLI/)).toContain('set subnet <ADMIN-NETWORK>')

    // "Have I been hit?" shows the general checks of the software family, labelled the same way
    const checks = screen.getByTestId('general-checks')
    expect(within(checks).getByRole('heading', { name: 'General checks (Web server on Linux)' })).toBeInTheDocument()
    expect(within(checks).getByText(/not specific to CVE-2026-119977/)).toBeInTheDocument()
  })

  it('no firewall in Devices: the Linux config, and "+ New firewall" adds one in place, whose tab is then selected', async () => {
    localStorage.clear()
    const saved = assetsStore.get()
    assetsStore.set(saved.filter((a) => a.kind !== 'firewall' && a.kind !== 'router'))
    renderApp('/findings/f-2')
    const block = await screen.findByRole('region', { name: 'General hardening' })
    expect(within(block).getByText(/No firewall in Devices/)).toBeInTheDocument()
    expect(within(block).getByRole('button', { name: 'Linux (nftables)' })).toHaveAttribute('aria-pressed', 'true')
    expect(code(/nftables: drop/)).toContain('ip daddr 192.168.10.12 ip saddr != 192.168.1.0/24 tcp dport { 80, 443 } drop')

    await userEvent.click(within(block).getByRole('button', { name: 'New firewall' }))
    const dialog = await screen.findByRole('dialog', { name: 'Add a device' })
    // the person adds their FortiGate in the dialog (the inventory's own form; its tests cover it), then closes it
    assetsStore.set(saved)
    await userEvent.click(within(dialog).getByRole('button', { name: 'Close' }))
    await waitFor(() => expect(within(block).getByRole('button', { name: 'FortiGate (in Devices)' })).toHaveAttribute('aria-pressed', 'true'))
    expect(within(block).queryByRole('button', { name: 'New firewall' })).toBeNull()
  })

  it('takes a network or one address, never other text', () => {
    expect(adminNetwork(' 192.168.5.0/24 ', false)).toBe('192.168.5.0/24')
    expect(adminNetwork('10.0.0.7', false)).toBe('10.0.0.7/32')
    expect(adminNetwork('fd00::/64', true)).toBe('fd00::/64')
    for (const bad of ['10.0.0.0/33', '300.1.1.1', '10.0.0.0/24; reboot', '$(id)', '', 'fd00::/64']) expect(adminNetwork(bad, false)).toBeNull()
    expect(adminNetwork('fd00:::1', true)).toBeNull()
  })
})
