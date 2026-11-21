// The CVE page of a CVE on no exploited list: its devices, from the recommended updates.
import { describe, expect, it } from 'vitest'
import { screen } from '@testing-library/react'
import { renderApp } from '@/test/render'

describe('a CVE on no exploited list', () => {
  it('the CVE page answers for it, with its devices from the recommended updates', async () => {
    renderApp('/cve/CVE-2026-31001')
    expect(await screen.findByRole('heading', { level: 1, name: 'CVE-2026-31001' })).toBeInTheDocument()
    expect(screen.queryByText('Update recommended')).toBeNull() // no list, no exploit signal: no status without a device
    expect(screen.getByText('F5 nginx')).toBeInTheDocument()
    expect(await screen.findByRole('link', { name: 'WEB01' })).toHaveAttribute('href', '/devices/a-web01')
  })
})
