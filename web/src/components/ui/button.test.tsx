import { act, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Trash2 } from 'lucide-react'
import { expectNoA11yViolations } from '@/test/render'
import { BusyNote } from '@/components/common/BusyNote'
import { Button } from './button'

describe('Button busy state (docs/UI.md §8)', () => {
  it('busy: disabled, aria-busy, a spinner and the busy label; the idle label stays in the cell but hidden', async () => {
    const { rerender } = render(<Button busy={false} busyLabel="Saving…">Save</Button>)
    const idle = screen.getByRole('button', { name: 'Save' })
    expect(idle).toBeEnabled()
    expect(idle).not.toHaveAttribute('aria-busy')
    expect(idle.querySelector('.animate-spin')).toBeNull()

    rerender(<Button busy busyLabel="Saving…">Save</Button>)
    const busy = screen.getByRole('button', { name: 'Saving…' })
    expect(busy).toBeDisabled()
    expect(busy).toHaveAttribute('aria-busy', 'true')
    expect(busy.querySelector('svg.animate-spin')).toHaveAttribute('aria-hidden', 'true')
    expect(screen.getByText('Save').closest('[aria-hidden="true"]')).not.toBeNull()
    await expectNoA11yViolations()
  })

  it('keeps its width: the label, the busy content and the busy label share one grid cell', () => {
    render(<Button busy busyLabel="Deleting…">Delete</Button>)
    const cell = screen.getByRole('button').firstElementChild as HTMLElement
    expect(cell).toHaveClass('grid')
    expect(cell).toHaveAttribute('data-busy-label', 'Deleting…')
    expect(cell.className).toContain('after:content-[attr(data-busy-label)]')
    for (const child of Array.from(cell.children)) expect(child).toHaveClass('col-start-1', 'row-start-1')
  })

  it('an icon button keeps its aria-label as its name while busy; disabled stays disabled when not busy', () => {
    render(<><Button size="icon" busy aria-label="Delete rule"><Trash2 /></Button><Button busy={false} disabled>Save</Button></>)
    expect(screen.getByRole('button', { name: 'Delete rule' })).toHaveAttribute('aria-busy', 'true')
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
  })

  it('a row button named by aria-label starts its name with the busy label while busy (WCAG 2.5.3)', () => {
    const { rerender } = render(<Button busy={false} busyLabel="Testing…" aria-label="Test connection File server">Test</Button>)
    expect(screen.getByRole('button', { name: 'Test connection File server' })).toBeEnabled()
    rerender(<Button busy busyLabel="Testing…" aria-label="Test connection File server">Test</Button>)
    expect(screen.getByRole('button', { name: 'Testing… Test connection File server' })).toHaveAttribute('aria-busy', 'true')
  })

  it('asChild keeps disabled on its child', () => {
    render(<Button asChild disabled><button type="button">Go</button></Button>)
    expect(screen.getByRole('button', { name: 'Go' })).toBeDisabled()
  })

  it('a button without busy renders its children as they are (no wrapper)', () => {
    render(<Button>Open</Button>)
    expect(screen.getByRole('button', { name: 'Open' }).firstChild).toBeInstanceOf(Text)
  })
})

describe('BusyNote', () => {
  afterEach(() => { vi.useRealTimers() })

  it('says what a long wait does in a polite status region, and counts seconds from 3 s on', () => {
    vi.useFakeTimers()
    const { rerender } = render(<BusyNote busy={false}>Asking your AI… this can take up to a minute.</BusyNote>)
    const note = screen.getByRole('status')
    expect(note).toBeEmptyDOMElement()
    expect(note).toHaveClass('sr-only') // in the accessibility tree while idle (never display:none), so the text is announced

    rerender(<BusyNote busy>Asking your AI… this can take up to a minute.</BusyNote>)
    expect(note).toHaveTextContent('Asking your AI… this can take up to a minute.')
    expect(note).not.toHaveTextContent(' s')
    act(() => { vi.advanceTimersByTime(12_000) })
    expect(note).toHaveTextContent('· 12 s')

    rerender(<BusyNote busy={false}>Asking your AI… this can take up to a minute.</BusyNote>)
    expect(note).toBeEmptyDOMElement()
  })
})
