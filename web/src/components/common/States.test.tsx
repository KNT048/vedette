import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api'
import { ErrorState } from './States'

const show = (status: number) => render(<MemoryRouter><ErrorState error={new ApiError(status, 'x', 'Server said no.')} /></MemoryRouter>)

describe('ErrorState and the sample-data hint', () => {
  it('says a 501 is not available yet and never offers to restore sample data', () => {
    vi.stubEnv('VITE_API_MOCK', 'on')
    show(501)
    expect(screen.getByText('This part is not available in this version yet.')).toBeInTheDocument()
    expect(screen.queryByText('Restore sample data')).toBeNull()
    expect(screen.queryByText(/older version of the app/)).toBeNull()
    vi.unstubAllEnvs()
  })

  it('keeps the restore hint for other 5xx while the preview mock runs, and drops it with the mock off', () => {
    vi.stubEnv('VITE_API_MOCK', 'on')
    const { unmount } = show(500)
    expect(screen.getByText('Restore sample data')).toBeInTheDocument()
    expect(screen.queryByText('This part is not available in this version yet.')).toBeNull()
    unmount()
    vi.stubEnv('VITE_API_MOCK', 'off')
    show(500)
    expect(screen.queryByText('Restore sample data')).toBeNull()
    vi.unstubAllEnvs()
  })
})
