import { afterEach, describe, expect, it, vi } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'

// Its own file: the choice falls back to memory for the life of the page, and that memory must not leak into other tests.
describe('report include switches without browser storage', () => {
  afterEach(() => vi.restoreAllMocks())

  it('still switch when storage throws (blocked or full), for as long as the page is open', async () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new Error('blocked') })
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('blocked') })
    renderApp('/reports')
    const nr = await screen.findByRole('switch', { name: 'Include not relevant' })
    expect(nr).not.toBeChecked()
    await userEvent.click(nr)
    expect(nr).toBeChecked()
    const dev = screen.getByRole('switch', { name: 'Include devices not in the Devices list' })
    await userEvent.click(dev)
    expect(dev).not.toBeChecked()
    expect(await screen.findByText(/devices not in the Devices list \(awaiting approval\) are left out/)).toBeInTheDocument()
  })
})
