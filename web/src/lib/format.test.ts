import { describe, expect, it } from 'vitest'
import { fmtDate, fmtDateTime, isNever } from './format'

describe('isNever', () => {
  it('treats empty and Go zero time as never', () => {
    expect(isNever(null)).toBe(true)
    expect(isNever('0001-01-01T00:00:00Z')).toBe(true)
    expect(isNever('2026-11-12T08:00:00Z')).toBe(false)
  })
})

describe('one date format (D-389)', () => {
  it('writes the month as a word, never 12/11/2026', () => {
    expect(fmtDate('2026-11-12')).toBe('12 Nov 2026')
    expect(fmtDateTime(new Date(2026, 10, 12, 20, 51).toISOString())).toBe('12 Nov 2026, 20:51')
  })
})
