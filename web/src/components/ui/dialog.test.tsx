import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { Dialog, DialogContent } from './dialog'

describe('DialogContent title', () => {
  it('without a description the title is in the dialog once and the dialog has no description', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    render(<Dialog open><DialogContent title="Add a token"><p>Body</p></DialogContent></Dialog>)
    const dialog = screen.getByRole('dialog', { name: 'Add a token' })
    expect(dialog.textContent!.split('Add a token')).toHaveLength(2)
    expect(dialog).not.toHaveAttribute('aria-describedby')
    // Radix warns when a dialog has neither a description nor aria-describedby={undefined}
    expect(warn.mock.calls.flat().join(' ')).not.toMatch(/Description/)
    warn.mockRestore()
  })

  it('with a description the dialog is described by it and the title is still there once', () => {
    render(<Dialog open><DialogContent title="Add a token" description="A fake key that alerts when used."><p>Body</p></DialogContent></Dialog>)
    const dialog = screen.getByRole('dialog', { name: 'Add a token' })
    expect(dialog).toHaveAccessibleDescription('A fake key that alerts when used.')
    expect(dialog.textContent!.split('Add a token')).toHaveLength(2)
  })
})
