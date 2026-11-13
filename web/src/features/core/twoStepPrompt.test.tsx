// S-CORE-3 criterion D-405 (walk 4): Home asks an administrator without two-step sign-in to turn it on, until it is on or snoozed.
import { describe, expect, it } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { usersStore } from '@/mocks/stores'

const prompt = () => screen.queryByText('Turn on two-step sign-in for this administrator account')

describe('two-step sign-in prompt on Home (D-405)', () => {
  it('an administrator without two-step sign-in sees it, with a link to My account; Remind me later hides it in this browser', async () => {
    localStorage.removeItem('vedette-two-step-later:u-admin')
    const u = userEvent.setup()
    renderApp('/')
    expect(await screen.findByText('Turn on two-step sign-in for this administrator account')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Turn on two-step sign-in' })).toHaveAttribute('href', '/account#two-step')
    await u.click(screen.getByRole('button', { name: 'Remind me in 30 days' }))
    expect(prompt()).toBeNull()
    const until = Number(localStorage.getItem('vedette-two-step-later:u-admin'))
    expect(Math.round((until - Date.now()) / 86_400_000)).toBe(30)
    localStorage.removeItem('vedette-two-step-later:u-admin')
  })

  it('not shown to an operator', async () => {
    renderApp('/', { role: 'operator' })
    expect(await screen.findByRole('heading', { level: 1 })).toBeInTheDocument()
    expect(prompt()).toBeNull()
  })

  it('not shown once two-step sign-in is on', async () => {
    usersStore.update((l) => l.map((x) => (x.id === 'u-admin' ? { ...x, twofa: true } : x)))
    renderApp('/')
    expect(await screen.findByRole('heading', { level: 1 })).toBeInTheDocument()
    expect(prompt()).toBeNull()
  })
})
