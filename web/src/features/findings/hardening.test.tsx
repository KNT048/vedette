import { describe, expect, it } from 'vitest'
import { screen, within } from '@testing-library/react'
import { renderApp } from '@/test/render'

// "remove the General hardening feature that tells the user to allow traffic from the box to devices; it is
// useless". The generated firewall configs and their admin network field are gone; what still helps stays: the general compromise
// checks of the software family, and the vendor and CISA steps.
describe('a finding without a confirmed pack: no firewall config, the compromise checks and the vendor steps stay', () => {
  it('shows no generated firewall config and no admin network field, but the general checks and the steps from the box\'s data', async () => {
    renderApp('/findings/f-2')
    const checks = await screen.findByTestId('general-checks')
    // what stays
    expect(within(checks).getByRole('heading', { name: 'General checks (Web server)' })).toBeInTheDocument()
    expect(within(checks).getByText(/not specific to CVE-2026-119977/)).toBeInTheDocument()
    expect(within(checks).getByText('Not a Vedette recommendation for this CVE')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '4. Check that it is fixed' })).toBeInTheDocument()
    // the firewall step says plainly that no configuration is published and offers the customer's own AI
    expect(within(screen.getByTestId('firewall-step')).getByText(/^No firewall configuration is published for CVE-2026-119977/)).toBeInTheDocument()
    // what is gone
    expect(screen.queryByTestId('general-hardening')).toBeNull()
    expect(screen.queryByRole('region', { name: 'General hardening' })).toBeNull()
    expect(screen.queryByRole('textbox', { name: /admin network/i })).toBeNull()
    expect(screen.queryByRole('group', { name: 'Firewall vendor' })).toBeNull()
    expect(screen.queryByRole('button', { name: /New firewall/ })).toBeNull()
    expect(screen.queryAllByLabelText(/FortiGate CLI|RouterOS terminal|nftables/)).toHaveLength(0)
  })
})
