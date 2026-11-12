// The system helper updates with Vedette (S-CORE-2 criterion D-316): the mock run and what the Updates page shows for it.
// No real-clock wait (D-376): Date.now is moved past the host step instead of sleeping.
import { afterEach, describe, expect, it, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import { renderApp } from '@/test/render'
import { orgStore, sessionStore } from '@/mocks/stores'
import { hostScenario, RUN_STEP_MS, type HostOutcome } from './mocks'
import type { UpdatesState } from './types'

const realNow = Date.now
const later = () => vi.spyOn(Date, 'now').mockImplementation(() => realNow.call(Date) + RUN_STEP_MS + 1) // past the host step
afterEach(() => vi.restoreAllMocks())

const call = async (method: string, path = '', b?: unknown) => (await fetch(`${location.origin}/api/v1/core/updates${path}`, { method, headers: { 'Content-Type': 'application/json' }, body: b ? JSON.stringify(b) : undefined })).json() as Promise<UpdatesState>
const signIn = () => { orgStore.update((o) => ({ ...o, setup_complete: true })); sessionStore.set({ userId: 'u-admin' }) }
const version = (s: UpdatesState, id: string) => s.components.find((c) => c.id === id)?.version
const helperRow = () => within(screen.getByRole('table', { name: 'Versions in use' })).getByRole('row', { name: /System helper/ })

const REVERTED = 'The new system helper 0.9.4 did not start correctly, so the box went back to 0.9.3 by itself. Nothing else was changed.'
const HALF_WAY = 'The system helper update stopped half way and could not be undone. Vedette keeps running; follow the runbook section "vedette-host self-update stopped half way".'
// [code, end, helper version in the release (null: 0.9.4), the story's sentence]
const ENDS: [HostOutcome, 'reverted' | 'failed', string | null, string][] = [
  ['self_update_unhealthy', 'reverted', null, REVERTED],
  ['install_failed', 'reverted', null, REVERTED],
  ['signature_invalid', 'failed', null, 'The system helper in this update is not signed by the Vedette release key. Nothing was installed.'],
  ['checksum_mismatch', 'failed', null, 'The downloaded system helper does not match the signed release. Nothing was installed.'],
  ['downgrade_not_allowed', 'failed', '0.9.2', 'System helper 0.9.2 is older than the one running (0.9.3). The helper is never taken back by an update.'],
  ['test_version_refused', 'failed', '0.9.4-test.1', '0.9.4-test.1 is a test build. It is never installed on a real box.'],
  ['dependencies_unavailable', 'failed', null, "The new system helper needs operating system packages that the box's package sources do not offer. Nothing was installed."],
  ['dpkg_locked', 'failed', null, 'The box is installing operating system packages. Try again in a few minutes.'],
  ['rollback_failed', 'failed', null, HALF_WAY],
  ['self_update_interrupted', 'failed', null, HALF_WAY],
  ['host_too_old', 'failed', null, "This box's system helper (0.9.3) is too old to update itself. Run install.sh of release 0.9.4 on the box (it upgrades the helper and keeps your data), then apply again."],
]

describe('core: system helper update (S-CORE-2 criterion D-316)', () => {
  it('the release says it includes the helper; the System helper row has its version and sentence, and no Rollback', async () => {
    renderApp('/settings/updates')
    expect(await screen.findByText('Includes system helper 0.9.4.')).toBeInTheDocument()
    const row = helperRow()
    expect(row).toHaveTextContent('0.9.3')
    expect(row).toHaveTextContent('Updated together with Vedette. If a new version does not start, the box goes back to the one before by itself.')
    expect(within(row).queryByRole('button')).toBeNull() // no Apply of its own, no Rollback
  })

  it('while the helper updates: step 1 is the helper with its sentence, Apply and Rollback are off', async () => {
    signIn()
    expect((await call('POST', '/apply', { component: 'software' })).run?.steps).toEqual(['host', 'download', 'start', 'restart'])
    renderApp('/settings/updates')
    expect(await screen.findAllByText('Step 1 of 4: update the system helper')).not.toHaveLength(0)
    expect(screen.getAllByText('Updating the system helper. Vedette keeps running; settings that need the helper may not answer for up to a minute.')).not.toHaveLength(0)
    for (const b of screen.getAllByRole('button', { name: /^Back to .*Vedette software/ })) expect(b).toBeDisabled()
    expect(within(helperRow()).queryByRole('button')).toBeNull()
  })

  it('success: the helper is on the new version, history has a host row, the run goes on to the images', async () => {
    signIn()
    await call('POST', '/apply', { component: 'software' })
    later()
    const s = await call('GET')
    expect(s.run).toMatchObject({ status: 'running', step: 'download' })
    expect(version(s, 'host')).toBe('0.9.4')
    expect(s.components.find((c) => c.id === 'host')?.previous).toBeNull()
    expect(s.history[0]).toMatchObject({ component: 'host', from: '0.9.3', to: '0.9.4', action: 'update' })
    expect(s.available[0]?.host_version).toBeUndefined()
  })

  it('a software rollback never has a host step, even when a newer helper is offered', async () => {
    signIn()
    expect((await call('POST', '/rollback', { component: 'software' })).run?.steps).toEqual(['start', 'restart'])
  })

  it('no newer helper in the release: no "Includes system helper", no host step', async () => {
    hostScenario.set({ code: null, version: '0.9.3' })
    signIn()
    expect((await call('GET')).available[0]?.host_version).toBeUndefined()
    expect((await call('POST', '/apply', { component: 'software' })).run?.steps).toEqual(['download', 'start', 'restart'])
  })

  it.each(ENDS)('%s: the run ends %s with the story sentence; the helper and the images are unchanged', async (code, end, v, sentence) => {
    hostScenario.set({ code, version: v })
    signIn()
    await call('POST', '/apply', { component: 'software' })
    later()
    const s = await call('GET')
    expect(s.run).toMatchObject({ status: end, step: null, error: sentence })
    expect(s.run?.steps[0]).toBe('host')
    expect([version(s, 'host'), version(s, 'software')]).toEqual(['0.9.3', '0.9.3'])
    expect(s.history.some((h) => h.component === 'host')).toBe(false)
    renderApp('/settings/updates')
    expect(await screen.findAllByText(sentence)).not.toHaveLength(0)
  })
})
