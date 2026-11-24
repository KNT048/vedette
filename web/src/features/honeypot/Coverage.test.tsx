import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import CoverageSection from './Coverage'

const row = (move: string) => screen.getByText(move).closest('li') as HTMLElement

// Without a listening Trap IP the box still answers URL tokens, so bait is partly covered, not "Not covered".
// A row is covered only when what fires it listens: SMB for shares, a login service for credentials, two Trap IPs for a sweep alert.
describe('CoverageSection', () => {
  it('keeps URL tokens covered when no Trap IP listens', () => {
    render(<MemoryRouter><CoverageSection services={[]} listeningIps={0} /></MemoryRouter>)
    expect(within(row('Opening or following bait')).getByText('Partly')).toBeTruthy()
    expect(within(row('Opening or following bait')).getByText(/URL tokens alert when opened. Decoy files need a listening Trap IP/)).toBeTruthy()
    expect(within(row('Scanning the network for targets')).getByText('Not covered')).toBeTruthy()
    expect(screen.getByText(/only URL tokens can alert/)).toBeTruthy()
  })
  it('shows each row covered once what fires it listens', () => {
    render(<MemoryRouter><CoverageSection services={['smb', 'ssh']} listeningIps={2} /></MemoryRouter>)
    for (const move of ['Opening or following bait', 'Moving sideways to file shares', 'Using stolen or guessed credentials', 'Scanning the network for targets']) {
      expect(within(row(move)).getByText('Covered')).toBeTruthy()
    }
  })
  it('claims nothing that cannot fire: no SMB, no login service, one Trap IP', () => {
    render(<MemoryRouter><CoverageSection services={['tftp', 'ntp']} listeningIps={1} /></MemoryRouter>)
    expect(within(row('Moving sideways to file shares')).getByText('Not covered')).toBeTruthy()
    expect(within(row('Moving sideways to file shares')).getByText(/No listening Trap IP has SMB/)).toBeTruthy()
    expect(within(row('Using stolen or guessed credentials')).getByText('Not covered')).toBeTruthy()
    expect(within(row('Scanning the network for targets')).getByText('Partly')).toBeTruthy()
    expect(within(row('Scanning the network for targets')).getByText(/needs two or more listening Trap IPs/)).toBeTruthy()
  })
  it('bait is not covered while no decoy file or URL token exists, and says how to add one', () => {
    render(<MemoryRouter><CoverageSection services={['smb', 'ssh']} listeningIps={2} bait={0} admin /></MemoryRouter>)
    expect(within(row('Opening or following bait')).getByText('Not covered')).toBeTruthy()
    expect(within(row('Opening or following bait')).getByRole('link', { name: 'Add a token' })).toHaveAttribute('href', '/?tab=tokens&add=token#tokens')
  })
  it('every gap a person can close carries its action, for an administrator only', () => {
    const { unmount } = render(<MemoryRouter><CoverageSection services={['tftp']} listeningIps={1} bait={1} admin /></MemoryRouter>)
    expect(within(row('Moving sideways to file shares')).getByRole('link', { name: /Add a file server Trap IP/ })).toHaveAttribute('href', '/?tab=trap-ips&add=file_server#trap-ips')
    expect(within(row('Using stolen or guessed credentials')).getByRole('link', { name: /Add a Linux server Trap IP/ })).toHaveAttribute('href', '/?tab=trap-ips&add=linux#trap-ips')
    expect(within(row('Scanning the network for targets')).getByRole('link', { name: 'Add a second Trap IP' })).toHaveAttribute('href', '/?tab=trap-ips&add=suggested#trap-ips')
    expect(within(row('Opening or following bait')).queryByRole('link')).toBeNull()
    unmount()
    render(<MemoryRouter><CoverageSection services={['tftp']} listeningIps={1} bait={0} /></MemoryRouter>)
    expect(screen.queryByRole('link', { name: /Add/ })).toBeNull()
  })
})
