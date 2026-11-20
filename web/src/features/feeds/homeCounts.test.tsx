// Home and the Findings screen are two views of one status model: the open count Home shows is the one the Findings screen
// shows, and it equals the sum over By device and over By fix. Reruns on the sample box like any test.
import { describe, expect, it } from 'vitest'
import { cleanup, screen, within } from '@testing-library/react'
import { renderApp } from '@/test/render'
import { api } from '@/lib/api'
import type { DeviceCards, FixCards, Overview } from '@/features/findings/types'

describe('home counts agree with the findings screen', () => {
  it('open on Home = open on Findings = sum by device = sum by fix', async () => {
    renderApp('/')
    const strip = await screen.findByRole('list', { name: 'Today at a glance' })
    const home = Number(within(within(strip).getAllByRole('listitem')[0]!).getAllByRole('link')[0]!.textContent!.match(/^\d+/)![0])
    cleanup()
    renderApp('/findings')
    const heading = await screen.findByRole('heading', { level: 1, name: /^\d+ open findings?$/ })
    const findings = Number(heading.textContent!.match(/^\d+/)![0])
    const [overview, devices, fixes] = await Promise.all([
      api.get<Overview>('/findings/overview'), api.get<DeviceCards>('/findings/devices?limit=1'), api.get<FixCards>('/findings/fixes?limit=1'),
    ])
    expect(home).toBe(findings)
    expect([overview.open.findings, devices.findings, fixes.findings]).toEqual([findings, findings, findings])
  })
})
