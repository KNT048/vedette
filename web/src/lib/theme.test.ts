import { describe, expect, it } from 'vitest'
import { initTheme, setTheme } from './theme'

describe('theme', () => {
  it('a choice made in another tab applies to this one', () => {
    initTheme()
    setTheme('light')
    expect(document.documentElement.dataset.theme).toBe('light')
    // another tab stores its choice; this tab hears it through the storage event
    localStorage.setItem('vedette-theme', 'dark')
    window.dispatchEvent(new StorageEvent('storage', { key: 'vedette-theme', newValue: 'dark' }))
    expect(document.documentElement.dataset.theme).toBe('dark')
    setTheme('light')
  })
})
