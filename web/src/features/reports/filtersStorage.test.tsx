import { afterEach, describe, expect, it, vi } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'

// Its own file: the choice falls back to memory for the life of the page, and that memory must not leak into other tests.
describe('assessment include switch without browser storage', () => {
  afterEach(() => vi.restoreAllMocks())

  it('still switches when storage throws (blocked or full), for as long as the page is open', async () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new Error('blocked') })
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('blocked') })
    renderApp('/reports/print/pdpl')
    const dev = await screen.findByRole('switch', { name: 'Include devices not in the Devices list' })
    expect(dev).toBeChecked()
    await userEvent.click(dev)
    expect(dev).not.toBeChecked()
  })
})
