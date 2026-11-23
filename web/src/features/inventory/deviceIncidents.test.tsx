import { describe, expect, it, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import { renderApp } from '@/test/render'
import { ensureBox } from './mocks'
import { openIncidentsOf } from './DeviceIncidents'
import type { Incident } from '@/features/notify/types'

vi.setConfig({ testTimeout: 30_000 })
const T = { timeout: 5000 }

describe('a device page lists the open incidents that name the device', () => {
  it('shows the open incident with its severity and a link to it, whether or not a finding matched', async () => {
    ensureBox()
    renderApp('/devices/a-pc07')
    const section = await screen.findByRole('region', { name: '1 open incident' }, T)
    const open = within(section).getByRole('link', { name: 'PC-HR-01 touched the SMB trap on FILESRV-OLD' })
    expect(open).toHaveAttribute('href', '/incidents/al-4')
    expect(section).toHaveTextContent('Critical')
    expect(within(section).getByRole('link', { name: 'All incidents' })).toHaveAttribute('href', '/incidents')
  })

  it('says nothing for a device whose incidents are all resolved', async () => {
    ensureBox()
    renderApp('/devices/a-nas01')
    await screen.findByRole('heading', { level: 1 }, T)
    await screen.findByText('Device type', undefined, T)
    expect(screen.queryByRole('region', { name: /open incidents?$/ })).toBeNull()
  })

  it('keeps the open ones that name the device, the most severe first', () => {
    const inc = (id: string, severity: Incident['severity'], status: Incident['status'], ids: string[]) =>
      ({ id, severity, status, devices: ids.map((x) => ({ id: x, name: x })), last_seen: '2026-11-20T10:00:00Z' }) as Incident
    const got = openIncidentsOf([inc('a', 'medium', 'new', ['d']), inc('b', 'critical', 'acknowledged', ['d', 'e']), inc('c', 'high', 'resolved', ['d']), inc('x', 'high', 'new', ['e'])], 'd')
    expect(got.map((i) => i.id)).toEqual(['b', 'a'])
  })
})
