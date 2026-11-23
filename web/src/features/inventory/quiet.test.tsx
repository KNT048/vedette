import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen } from '@testing-library/react'
import { renderApp } from '@/test/render'
import { assetsStore, sessionStore } from '@/mocks/stores'
import type { Asset } from '@/lib/types'
import { ensureBox, isPrivateMac } from './mocks'

// A phone with a private (randomised) Wi-Fi address that shows nothing to look at is listed, but is not a To review item.
vi.setConfig({ testTimeout: 30_000 })

const T = { timeout: 5000 }
const BASE = `${location.origin}/api/v1/inventory`
const now = new Date().toISOString()
const dev = (p: Partial<Asset> & { id: string }): Asset => ({
  site: 'hq', ip: '192.168.10.170', mac: null, hostname: 'Johns-iPhone', kind: 'smartphone', vendor: null, model: null, os: null, software: [], services: [],
  first_seen: now, last_seen: now, approved: false, fragile: false, origin: 'discovered', ...p,
})

beforeEach(() => {
  ensureBox()
  assetsStore.update((l) => [...l.filter((a) => !a.id.startsWith('a-q')), dev({ id: 'a-q1', mac: '6a:b2:19:00:00:02' }),
    dev({ id: 'a-q2', ip: '192.168.10.171', hostname: 'winlab01', kind: 'server', mac: '52:54:00:76:6e:02' }),
    dev({ id: 'a-q3', ip: '192.168.10.172', hostname: 'gym-tablet', mac: '6a:b2:19:00:00:03', services: [{ id: 'sv1', port: 22, proto: 'tcp', name: 'ssh', product: null, version: null, source: 'nmap', confidence: 0.9, seen_at: now } as never] })])
})

describe('private (randomised) MAC addresses', () => {
  it('knows a private address from a stable virtual one', () => {
    expect(isPrivateMac('6a:b2:19:00:00:02')).toBe(true)
    expect(isPrivateMac('3c:22:fb:00:00:01')).toBe(false)
    for (const stable of ['52:54:00:76:6e:02', '02:42:ac:11:00:02', '0a:00:27:00:00:05']) expect(isPrivateMac(stable)).toBe(false)
  })

  it('To review keeps the virtual machine and the phone with a service; the quiet phone is listed with the devices', async () => {
    sessionStore.set({ userId: 'u-admin' })
    const review = await (await fetch(`${BASE}/devices?approved=false`)).json() as { items: { id: string }[]; counts: { pending: number } }
    expect(review.items.map((d) => d.id).filter((id) => id.startsWith('a-q')).sort()).toEqual(['a-q2', 'a-q3'])
    const listed = await (await fetch(`${BASE}/devices?approved=true`)).json() as { items: { id: string; quiet: boolean; private_mac: boolean }[] }
    const q1 = listed.items.find((d) => d.id === 'a-q1')
    expect(q1).toMatchObject({ quiet: true, private_mac: true })
    const all = await (await fetch(`${BASE}/devices`)).json() as { items: { id: string }[] }
    expect(all.items.map((d) => d.id)).toContain('a-q1')
  })

  it('the device page says plainly that the address is private', async () => {
    renderApp('/devices/a-q1', { role: 'admin' })
    expect(await screen.findByTestId('private-mac-note', undefined, T)).toHaveTextContent('private (randomised) MAC address')
    expect(await screen.findByText('This device uses a private address and is not added yet', undefined, T)).toBeInTheDocument()
  })
})
