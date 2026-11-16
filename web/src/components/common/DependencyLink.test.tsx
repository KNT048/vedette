// docs/UI.md §0 "Need → place → action is obvious": a missing dependency links to the exact field, and the field gets focus.
import { describe, expect, it } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router'
import { DependencyLink, useDeepLinkTarget } from './DependencyLink'

function Target() {
  useDeepLinkTarget()
  return <div id="channels"><h2>Alert channels</h2><input aria-label="Channel name" /></div>
}

describe('DependencyLink', () => {
  it('one short reason and a link to the exact tab and field, which is focused on arrival', async () => {
    const u = userEvent.setup()
    render(
      <MemoryRouter initialEntries={['/devices']}>
        <Routes>
          <Route path="/devices" element={<DependencyLink reason="No alert channel yet." to="/settings/notify?tab=channels#channels" label="Add one in Settings, Alert channels" />} />
          <Route path="/settings/notify" element={<Target />} />
        </Routes>
      </MemoryRouter>,
    )
    const link = screen.getByRole('link', { name: 'Add one in Settings, Alert channels' })
    expect(link).toHaveAttribute('href', '/settings/notify?tab=channels#channels')
    expect(screen.getByText(/No alert channel yet\./)).toBeInTheDocument()
    await u.click(link)
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Channel name' })).toHaveFocus())
  })
})
