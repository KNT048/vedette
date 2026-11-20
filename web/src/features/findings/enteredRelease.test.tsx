import { describe, expect, it } from 'vitest'
import { screen, within } from '@testing-library/react'
import { renderApp } from '@/test/render'
import { softwareRowIds } from './EnteredRelease'

// A version or package release a person entered shows on the device's Software tab, with who entered it and when.
const T = { timeout: 5000 }

describe('An entered package release', () => {
  it('software a person declared says "Entered by hand", as no author or time is on record', async () => {
    renderApp('/devices/a-srvfile?tab=software')
    const table = await screen.findByRole('table', { name: 'Software on the device' }, T)
    const notes = await within(table).findAllByTestId('entered-note', undefined, T)
    expect(notes.some((n) => /Entered by hand/.test(n.textContent ?? ''))).toBe(true)
  })

  it('every row of the software counts: the effective row, the other sources, and a second install of the same product', () => {
    const eff = [
      { id: 's-agent-1', vendor: 'OpenBSD', product: 'OpenSSH', also_seen: [{ id: 's-nmap' }] },
      { id: 's-agent-2', vendor: 'OpenBSD', product: 'OpenSSH', also_seen: [] }, // another install, another version
      { id: 's-nginx', vendor: 'F5', product: 'nginx', also_seen: [] },
    ]
    expect(softwareRowIds(['s-nmap'], eff).sort()).toEqual(['s-agent-1', 's-agent-2', 's-nmap'])
    expect(softwareRowIds(['s-nmap'], undefined)).toEqual(['s-nmap'])
  })
})
