// Home's "devices watched" tile counts what the Devices list it links to holds: the added devices, by the one state rule. Devices
// waiting in To review are its "not added yet" line, and the quiet ones in Seen briefly are in neither.
import { describe, expect, it } from 'vitest'
import { screen, within } from '@testing-library/react'
import { renderApp } from '@/test/render'
import { api } from '@/lib/api'
import { sessionStore } from '@/mocks/stores'
import type { DevicesResponse } from '@/features/inventory/types'

describe('Home: the devices tile', () => {
  it('counts the devices of the Devices list, and its To review line the devices waiting there', async () => {
    sessionStore.set({ userId: 'u-admin' })
    const list = await api.get<DevicesResponse>('/inventory/devices') // first: the sample box exists once the inventory answered
    renderApp('/')
    const strip = await screen.findByRole('list', { name: 'Today at a glance' })
    const tile = within(strip).getAllByRole('listitem').find((li) => /devices? watched/.test(li.textContent ?? ''))!
    const watched = Number(tile.textContent!.match(/(\d+)\s*devices? watched/)![1])
    const added = list.items.filter((d) => d.state === 'added').length
    const review = list.items.filter((d) => d.state === 'review').length
    expect(list.items.some((d) => d.state === 'seen')).toBe(true) // the sample data has devices in Seen briefly
    expect(watched).toBe(added)
    expect(watched).toBeLessThan(list.items.length)
    expect(tile.textContent).toContain(`${review} not added yet`)
  })
})
