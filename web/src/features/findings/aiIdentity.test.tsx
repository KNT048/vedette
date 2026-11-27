// A finding opened through the AI's identification of its software (no standard data names the program) says "Identified by AI as
// <title>", with the AI's reason and model behind the info icon, and a person's "Not this product" closes it in one click.
import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { records } from './modelMocks'

const T = { timeout: 8000 }

describe('Identified by AI', () => {
  it('says which product the AI chose, why, and closes on Not this product', async () => {
    renderApp('/findings/fv-pc01-ptracer-1')
    const badge = await screen.findByTestId('ai-identity', {}, T)
    expect(badge).toHaveTextContent('Identified by AI as Cisco Packet Tracer')
    await userEvent.click(within(badge).getByRole('button', { name: /How the AI identified this software/ }))
    expect((await screen.findAllByText(/cisco:packet_tracer/, {}, T)).length).toBeGreaterThan(0)
    expect(screen.getAllByText(/The AI: The publisher is Cisco/).length).toBeGreaterThan(0)
    await userEvent.keyboard('{Escape}')
    await userEvent.click(screen.getByRole('button', { name: 'Cisco Packet Tracer is not this software' }))
    await waitFor(() => expect(records.get().find((r) => r.id === 'fv-pc01-ptracer-1')?.state).toBe('handled'), T)
    expect(records.get().find((r) => r.id === 'fv-pc01-ptracer-1')?.resolved_by).not.toBe('system') // the person's close, not Vedette's
    expect(await screen.findByText(/this software is not Cisco Packet Tracer/, {}, T)).toBeInTheDocument()
  })

  it('a finding the AI did not identify has neither', async () => {
    renderApp('/findings/fv-pc01-java21-2')
    await screen.findByRole('heading', { level: 1 }, T)
    await waitFor(() => expect(screen.queryByTestId('ai-identity')).toBeNull(), T)
    expect(screen.queryByRole('button', { name: /is not this software/ })).toBeNull()
  })
})
