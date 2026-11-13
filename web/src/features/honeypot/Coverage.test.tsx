import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import CoverageSection from './Coverage'

const row = (move: string) => screen.getByText(move).closest('li') as HTMLElement

// W6-2: without a listening Trap IP the box still answers URL tokens, so bait is partly covered, not "Not covered".
// D-467: a row is covered only when what fires it listens: SMB for shares, a login service for credentials, two Trap IPs for a sweep alert.
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
})
