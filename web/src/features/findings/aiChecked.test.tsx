// A finding or an answer a person confirmed from an AI proposal says "AI checked", with the AI's check (its pages and model) behind
// the info icon; a finding the AI's reading of the vendor's statement opened says "Read by AI from <host>" and has its Reject.
import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { checkKeyOf } from '@/mocks/seed/findings'
import { questions, records } from './modelMocks'
import { checks, openByReading } from './possibleMocks'
import type { PossibleCheck } from './types'

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

describe('Read by AI', () => {
  it('a finding the AI\'s reading of the vendor\'s statement opened says where it was read, and a person rejects it in one click', async () => {
    const q = questions.get().find((x) => x.cve === 'CVE-2026-240103')!
    const key = checkKeyOf(q, q.cve!)
    const check: PossibleCheck = {
      key, decided_by: 'ai', verdict: 'affected', confidence: 'confident', reason: 'The vendor states the fix of the 7 line.', quote: 'All RouterOS 7 releases before 7.15.3 are affected.',
      sources: [{ url: 'https://mikrotik.example.com/security/advisories/routeros-2026-07', status: 'ok', cited: true }], model: 'qwen3:8b', checked_by: 'system',
      checked_at: new Date().toISOString(), rejected: false,
      reading: { status: 'fixed', line: '7.14', stated_line: '7', introduced: null, fixed_in: '7.15.3', last_affected: null, host: 'mikrotik.example.com', vendor_page: true, quote_found: true, research: null },
    }
    checks.update((m) => ({ ...m, [key]: check }))
    openByReading(key, check)
    const id = records.get().find((r) => r.cve === 'CVE-2026-240103' && r.state === 'open')!.id
    renderApp(`/findings/${id}`)
    const badge = await screen.findByTestId('ai-read', {}, T)
    expect(badge).toHaveTextContent('Read by AI from mikrotik.example.com')
    // the evidence names the vendor's page the AI read, not NVD's data
    const source = await screen.findByTestId('ai-read-source', {}, T)
    expect(source).toHaveTextContent('The vendor\'s page read by AI')
    expect(within(source).getByRole('link', { name: /mikrotik\.example\.com/ })).toHaveAttribute('href', 'https://mikrotik.example.com/security/advisories/routeros-2026-07')
    expect(screen.queryByText(/NVD vulnerability data/)).toBeNull()
    // What to do names the release the quote states as the fix, its source the vendor's page with the sentence
    const fix = await screen.findByTestId('stored-fix', {}, T)
    expect(fix).toHaveTextContent(/^Fixed in 7\.15\.3: update .* to 7\.15\.3 or later\./)
    const cited = within(fix).getByTestId('ai-read-fix-source')
    expect(cited).toHaveTextContent('Source: the vendor\'s page read by AI, mikrotik.example.com: “All RouterOS 7 releases before 7.15.3 are affected.”')
    expect(within(cited).getByRole('link', { name: /mikrotik\.example\.com/ })).toHaveAttribute('href', 'https://mikrotik.example.com/security/advisories/routeros-2026-07')
    expect(screen.getByText('The vendor\'s fix, read by AI')).toBeInTheDocument()
    expect(screen.queryByText('No confirmed recommendation yet')).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Reject the AI\'s reading from mikrotik.example.com' }))
    await waitFor(() => expect(records.get().find((r) => r.id === id)?.state).toBe('handled'), T)
    expect(questions.get().some((x) => x.cve === 'CVE-2026-240103' && !x.answered)).toBe(true)
  })
})
