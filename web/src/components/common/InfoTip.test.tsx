import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { expectNoA11yViolations } from '@/test/render'
import { Dialog, DialogContent } from '@/components/ui/dialog'
import { InfoTip } from './InfoTip'

const show = () => render(<><InfoTip topic="Zalo sign-in">Scan the QR code with the Zalo app on a phone.</InfoTip><button type="button">Elsewhere</button></>)

describe('InfoTip (#824)', () => {
  it('keeps the guidance hidden until asked, and gives it to screen readers as the button description', () => {
    show()
    const btn = screen.getByRole('button', { name: 'About Zalo sign-in' })
    expect(btn).toHaveAccessibleDescription('Scan the QR code with the Zalo app on a phone.')
    expect(btn).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('the open popover is a dialog named like its button, so axe passes with it open (aria-dialog-name, #825)', async () => {
    const user = userEvent.setup()
    render(<><InfoTip topic="Zalo sign-in">Scan the QR code.</InfoTip><InfoTip topic="2 users sign in with email codes and will be locked out.">b</InfoTip></>)
    await user.click(screen.getByRole('button', { name: 'About Zalo sign-in' }))
    expect(screen.getByRole('dialog', { name: 'About Zalo sign-in' })).toHaveTextContent('Scan the QR code.')
    await expectNoA11yViolations()
    await user.keyboard('{Escape}')
    await user.click(screen.getByRole('button', { name: 'More about this' }))
    expect(screen.getByRole('dialog', { name: 'More about this' })).toBeInTheDocument()
  })

  it('opens on click and closes on a click outside', async () => {
    const user = userEvent.setup()
    show()
    await user.click(screen.getByRole('button', { name: 'About Zalo sign-in' }))
    expect(screen.getByRole('dialog')).toHaveTextContent('Scan the QR code')
    await user.click(screen.getByRole('button', { name: 'Elsewhere' }))
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('opens with Enter and Space and closes with Esc, focus back on the button', async () => {
    const user = userEvent.setup()
    show()
    const btn = screen.getByRole('button', { name: 'About Zalo sign-in' })
    btn.focus()
    await user.keyboard('{Enter}')
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    await user.keyboard('{Escape}')
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(btn).toHaveFocus()
    await user.keyboard(' ')
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(btn).toHaveAttribute('aria-expanded', 'true')
  })

  it('inside a dialog, Esc closes only the open ⓘ; a second Esc closes the dialog', async () => {
    const user = userEvent.setup()
    // A controlled dialog: count its close requests.
    const onOpenChange = vi.fn()
    render(<Dialog open onOpenChange={onOpenChange}><DialogContent title="Email channel" info="Pick the provider first."><p>Form</p></DialogContent></Dialog>)
    const btn = screen.getByRole('button', { name: 'About Email channel' })
    await user.click(btn)
    expect(screen.getAllByRole('dialog')).toHaveLength(2)
    await user.keyboard('{Escape}')
    expect(screen.getAllByRole('dialog')).toHaveLength(1)
    expect(screen.getByRole('dialog', { name: 'Email channel' })).toBeInTheDocument()
    expect(btn).toHaveFocus()
    expect(onOpenChange).not.toHaveBeenCalled()
    await user.keyboard('{Escape}')
    expect(onOpenChange).toHaveBeenCalledWith(false)
  })

  it('a sentence title is not repeated as the ⓘ name (more than 6 words reads "More about this")', () => {
    render(<><InfoTip topic="Alert content">a</InfoTip><InfoTip topic="2 users sign in with email codes and will be locked out.">b</InfoTip></>)
    expect(screen.getByRole('button', { name: 'About Alert content' })).toHaveAccessibleDescription('a')
    expect(screen.getByRole('button', { name: 'More about this' })).toHaveAccessibleDescription('b')
  })
})
