import { describe, expect, it } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import { useCooldown } from './useCooldown'

// start(0) means "no pause": the button must be free at once, whatever the clock does between the reads inside start().
describe('useCooldown', () => {
  it('a pause of zero seconds never leaves the button waiting', async () => {
    let stuck = 0
    for (let i = 0; i < 300; i++) {
      const { result, unmount } = renderHook(() => useCooldown())
      act(() => { result.current.start(0) })
      await act(async () => { await new Promise((r) => setTimeout(r, 20)) })
      if (result.current.left > 0) stuck++
      unmount()
    }
    expect(stuck).toBe(0)
  }, 60_000)

  it('a short pause counts down to free even when it ends before the first tick', async () => {
    const { result } = renderHook(() => useCooldown())
    act(() => { result.current.start(1) })
    expect(result.current.left).toBe(1)
    await act(async () => { await new Promise((r) => setTimeout(r, 1400)) })
    expect(result.current.left).toBe(0)
  })
})
