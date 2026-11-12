import { describe, expect, it } from 'vitest'
import { isNever } from './format'

describe('isNever', () => {
  it('treats empty and Go zero time as never', () => {
    expect(isNever(null)).toBe(true)
    expect(isNever('0001-01-01T00:00:00Z')).toBe(true)
    expect(isNever('2026-11-12T08:00:00Z')).toBe(false)
  })
})
