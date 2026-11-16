import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
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
})
