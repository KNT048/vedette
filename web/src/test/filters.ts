import { screen } from '@testing-library/react'
import type userEvent from '@testing-library/user-event'

/** Turns a filter of a list's Filters menu on or off by its name ("Fragile 4"), then closes the menu. */
export async function toggleFilter(user: ReturnType<typeof userEvent.setup>, name: RegExp | string) {
  await user.click(screen.getByRole('button', { name: /^Filters/ }))
  await user.click(await screen.findByRole('menuitemcheckbox', { name }))
  await user.keyboard('{Escape}')
}
