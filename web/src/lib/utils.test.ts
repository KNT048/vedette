import { describe, expect, it } from 'vitest'
import { cn } from './utils'

describe('cn knows the named sizes of docs/UI.md', () => {
  it('keeps a named size next to a colour', () => {
    expect(cn('text-meta', 'text-muted')).toBe('text-meta text-muted')
    expect(cn('text-caption', 'text-danger')).toBe('text-caption text-danger')
  })
  it('a later size wins over a named one, and the other way round', () => {
    expect(cn('text-meta', 'text-sm')).toBe('text-sm')
    expect(cn('text-sm', 'text-caption')).toBe('text-caption')
  })
  it('a later colour still wins over an earlier colour', () => {
    expect(cn('text-meta text-muted', 'text-ink')).toBe('text-meta text-ink')
  })
})
