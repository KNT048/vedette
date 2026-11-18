import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { sessionStore } from '@/mocks/stores'

const api = (path: string, init?: RequestInit) => fetch(`${location.origin}/api/v1${path}`, { headers: { 'Content-Type': 'application/json' }, ...init })
const ask = (question: string) => api('/ai/ask', { method: 'POST', body: JSON.stringify({ question }) })

describe('assistant: suggested questions are folded, past questions have their own tab', () => {
  it('Ask tab: suggestions are one line until opened, and the old chip list of recent questions is gone', async () => {
    renderApp('/assistant')
    const summary = await screen.findByText('Suggested questions')
    expect(summary.closest('details')).not.toHaveAttribute('open')
    await userEvent.click(summary)
    expect(summary.closest('details')).toHaveAttribute('open')
    expect(within(summary.closest('details')!).getByRole('button', { name: 'Which machines still expose RDP?' })).toBeInTheDocument()
    expect(screen.queryByText('Recent questions', { selector: 'p' })).toBeNull()
  })

  it('Recent questions tab: empty says so in one line', async () => {
    renderApp('/assistant?tab=history')
    expect(await screen.findByText('No questions asked yet.')).toBeInTheDocument()
  })

  it('Recent questions tab lists past questions newest first; one opens with its answer; the search narrows the list', async () => {
    sessionStore.set({ userId: 'u-admin' })
    expect((await ask('Which machines still expose RDP?')).ok).toBe(true)
    expect((await ask('Which devices are not approved yet?')).ok).toBe(true)
    renderApp('/assistant?tab=history')
    const list = await screen.findByRole('list')
    const names = () => within(list).getAllByRole('button').map((b) => b.textContent ?? '')
    await waitFor(() => expect(names()).toHaveLength(2))
    expect(names()[0]).toMatch(/^Which devices are not approved yet\?/) // newest first
    expect(names()[1]).toMatch(/^Which machines still expose RDP\?/)
    expect(screen.queryByRole('region', { name: /Answer to:/ })).toBeNull()

    await userEvent.click(within(list).getByRole('button', { name: /Which machines still expose RDP\?/ }))
    const answer = await screen.findByRole('region', { name: 'Answer to: Which machines still expose RDP?' })
    expect(within(answer).getByText('AI-generated, needs human review')).toBeInTheDocument()

    await userEvent.type(screen.getByRole('searchbox', { name: 'Search your questions' }), 'approved')
    expect(within(screen.getByRole('list')).getAllByRole('button')).toHaveLength(1)
    await userEvent.clear(screen.getByRole('searchbox', { name: 'Search your questions' }))
    await userEvent.type(screen.getByRole('searchbox', { name: 'Search your questions' }), 'zzz')
    expect(await screen.findByText('No question contains "zzz".')).toBeInTheDocument()
  })

  it('a half-typed question survives a look at Recent questions', async () => {
    renderApp('/assistant')
    const box = await screen.findByRole('textbox', { name: /question/i })
    await waitFor(() => expect(box).toBeEnabled())
    await userEvent.type(box, 'which cameras')
    await userEvent.click(screen.getByRole('tab', { name: 'Recent questions' }))
    await userEvent.click(await screen.findByRole('tab', { name: 'Ask' }))
    expect(await screen.findByRole('textbox', { name: /question/i })).toHaveValue('which cameras')
  })
})
