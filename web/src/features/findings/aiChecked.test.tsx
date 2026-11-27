// A finding or an answer a person confirmed from an AI proposal says "AI checked", with the AI's check (its pages and model) behind
// the info icon.
import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { records } from './modelMocks'

const T = { timeout: 8000 }

describe('AI checked', () => {
  it('a finding confirmed from an AI proposal says so on its page, with the pages and the model', async () => {
    renderApp('/findings?tab=proposals')
    const row = await screen.findByRole('article', { name: 'AI proposal for CVE-2026-245501 on SRV-ACCOUNTS' }, T)
    await userEvent.click(within(row).getByRole('button', { name: 'Confirm that CVE-2026-245501 affects SRV-ACCOUNTS' }))
    const id = await waitFor(() => { const r = records.get().find((x) => x.cve === 'CVE-2026-245501'); if (!r) throw new Error('no finding'); return r.id }, T)
    renderApp(`/findings/${id}`)
    const badge = await screen.findByTestId('ai-checked', {}, T)
    expect(badge).toHaveTextContent('AI checked')
    await userEvent.click(within(badge).getByRole('button', { name: /How the AI checked it/ }))
    expect((await screen.findAllByText(/Model: qwen3:8b/, {}, T)).length).toBeGreaterThan(0)
    expect(screen.getAllByRole('link', { name: /MikroTik security advisory/ }).length).toBeGreaterThan(0)
  })

  it('an answer confirmed from an AI proposal is marked in the Answered list; a person\'s own answer is not', async () => {
    renderApp('/findings?tab=proposals')
    const row = await screen.findByRole('article', { name: 'AI proposal for CVE-2026-240102 on RT-BACKUP' }, T)
    await userEvent.click(within(row).getByRole('button', { name: 'Confirm that CVE-2026-240102 does not affect RT-BACKUP' }))
    await waitFor(() => expect(screen.queryByRole('article', { name: 'AI proposal for CVE-2026-240102 on RT-BACKUP' })).toBeNull(), T)
    renderApp('/devices/a-rt02?tab=findings')
    await userEvent.click(await screen.findByRole('button', { name: 'Answered not affected: 1' }, T))
    const item = (await screen.findByRole('button', { name: /^Ask again: CVE-2026-240102/ }, T)).closest('li')!
    expect(within(item).getByTestId('ai-checked')).toHaveTextContent('AI checked')
  })
})
