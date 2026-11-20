import { describe, expect, it } from 'vitest'
import { screen } from '@testing-library/react'
import { renderApp } from '@/test/render'
import { assetsStore, findingsStore } from '@/mocks/stores'

const T = { timeout: 5000 }

/** A finding of a device nobody approved (the first device, marked not approved). */
function unapprovedDevice() {
  const f = findingsStore.get().find((x) => x.status === 'suspected' || x.status === 'confirmed')!
  assetsStore.set(assetsStore.get().map((a) => (a.id === f.asset_id ? { ...a, approved: false } : a)))
  return f
}

describe('findings of a device that is not added yet', () => {

  it('the finding page says "Device not added yet" once, with Add device and Ignore', async () => {
    const f = unapprovedDevice()
    renderApp(`/findings/${f.id}`)
    expect(await screen.findByText(/Nobody approved this device yet/, undefined, T)).toBeInTheDocument()
    expect(screen.getAllByText('Device not added yet')).toHaveLength(1)
    expect(screen.getByRole('button', { name: /^Add device/ })).toBeInTheDocument()
  })

})
