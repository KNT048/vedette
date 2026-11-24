import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { assetsStore } from '@/mocks/stores'
import type { Asset } from '@/lib/types'
import { ensureBox } from './mocks'

// A firewall whose SNMP read fails and whose scan sees only port 22 has no software line: no exploited vulnerability can match it,
// and "no findings" read as safe. Its page says it cannot be checked yet and how to get it checked.
vi.setConfig({ testTimeout: 30_000 })
const T = { timeout: 5000 }
const now = new Date().toISOString()
const fw = (p: Partial<Asset> & { id: string }): Asset => ({
  site: 'hq', ip: '192.0.2.251', mac: '70:4c:a5:00:00:01', hostname: null, kind: 'unknown', vendor: { value: 'Fortinet', source: 'nmap', confidence: 0.6, seen_at: now },
  model: null, os: null, software: [], services: [{ port: 22, proto: 'tcp', name: 'ssh', source: 'nmap', confidence: 0.8 }],
  first_seen: now, last_seen: now, approved: true, fragile: false, origin: 'discovered', ...p,
})

beforeEach(() => {
  ensureBox()
  assetsStore.update((l) => [...l.filter((a) => !a.id.startsWith('a-unc')), fw({ id: 'a-unc1' }), fw({ id: 'a-unc2', ip: '192.0.2.252', mac: '70:4c:a5:00:00:02', approved: false }),
    fw({ id: 'a-unc3', ip: '192.0.2.253', mac: '70:4c:a5:00:00:03', software: [{ display: 'FortiOS', vendor: 'Fortinet', product: 'FortiOS', version: '7.2.8', source: 'manual', confidence: 1, kev: [] } as unknown as Asset['software'][number]] })])
})

describe('Device page: a device Vedette cannot check says how to get it checked', () => {
  it('names what the scan saw and the ways in; Add its firmware opens the software form', async () => {
    const user = userEvent.setup()
    renderApp('/devices/a-unc1', { role: 'operator' })
    const box = await screen.findByTestId('uncheckable', undefined, T)
    expect(screen.getByRole('heading', { level: 1, name: 'Fortinet device' })).toBeInTheDocument() // the card's maker is a weak name
    expect(box).toHaveTextContent('Vedette cannot check this device yet')
    expect(box).toHaveTextContent('a network scan saw 1 open port but no version it can match')
    expect(within(box).getByRole('link', { name: 'Sources' })).toHaveAttribute('href', expect.stringContaining('#sources'))
    await user.click(within(box).getByRole('button', { name: 'Add its firmware' }))
    expect(await screen.findByRole('dialog', undefined, T)).toBeInTheDocument()
  })
  it('is not shown on a device with a software line', async () => {
    renderApp('/devices/a-unc3', { role: 'operator' })
    expect(await screen.findByRole('heading', { level: 1 }, T)).toBeInTheDocument()
    expect(screen.queryByTestId('uncheckable')).toBeNull()
  })
  it('is not shown on a device waiting for review', async () => {
    renderApp('/devices/a-unc2', { role: 'operator' })
    expect(await screen.findByRole('heading', { level: 1 }, T)).toBeInTheDocument()
    expect(screen.queryByTestId('uncheckable')).toBeNull()
  })
})
