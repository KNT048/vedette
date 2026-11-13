import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import CoverageSection from './Coverage'

const row = (move: string) => screen.getByText(move).closest('li') as HTMLElement

// W6-2: without a listening Trap IP the box still answers URL tokens, so bait is partly covered, not "Not covered".
describe('CoverageSection', () => {
  it('keeps URL tokens covered when no Trap IP listens', () => {
    render(<MemoryRouter><CoverageSection listening={false} /></MemoryRouter>)
    expect(within(row('Opening or following bait')).getByText('Partly')).toBeTruthy()
    expect(within(row('Opening or following bait')).getByText(/URL tokens alert when opened. Decoy files need a listening Trap IP/)).toBeTruthy()
    expect(within(row('Scanning the network for targets')).getByText('Not covered')).toBeTruthy()
    expect(screen.getByText(/only URL tokens can alert/)).toBeTruthy()
  })
  it('shows bait covered once a Trap IP listens', () => {
    render(<MemoryRouter><CoverageSection listening /></MemoryRouter>)
    expect(within(row('Opening or following bait')).getByText('Covered')).toBeTruthy()
  })
})
