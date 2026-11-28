// CVEs an update their line already needs covers: kept out of the Not decided list and out of "still unknown", shown as one closed
// row per device and software that says what the update is, and listed under that update in By fix. Each CVE is still answered.
import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { possibleCounts, reviewCount } from './possibleMocks'

const T = { timeout: 8000 }
const section = () => screen.findByRole('region', { name: 'Not decided' }, T)

describe('CVEs an update covers', () => {
  it('are counted apart and are not in the main list', async () => {
    expect(possibleCounts().deferred).toBe(8)
    renderApp('/findings?tab=possible')
    const s = await section()
    await within(s).findAllByTestId('covered-line', {}, T)
    // a covered CVE shows only once its group is opened
    expect(s.textContent).not.toContain('CVE-2026-900301')
    expect(within(s).queryAllByTestId('possible-row').some((r) => r.textContent?.includes('CVE-2026-900301'))).toBe(false)
  })

  it('a group with an update target says what it is, and opens to its CVEs with Research deeper and the answers', async () => {
    renderApp('/findings?tab=possible')
    const s = await section()
    const line = (await within(s).findAllByTestId('covered-line', {}, T)).find((r) => r.textContent?.includes('WordPress website'))!
    expect(line).toHaveTextContent('5 more CVEs not checked one by one. WordPress website already needs an update to 7.1.5; Vedette checks again after it.')
    await userEvent.click(within(line).getByRole('button', { name: /^Show the CVEs of WordPress website/ }))
    const rows = within(line).getAllByTestId('possible-row')
    expect(rows).toHaveLength(5)
    expect(await within(rows[0]!).findByRole('button', { name: /^Research CVE-.* deeper$/ }, T)).toBeInTheDocument()
    expect(within(rows[0]!).getByRole('button', { name: /^Answer/ })).toBeInTheDocument()
  })

  it('a group with no fix on its release line says to move to a supported release', async () => {
    renderApp('/findings?tab=possible')
    const s = await section()
    const line = (await within(s).findAllByTestId('covered-line', {}, T)).find((r) => r.textContent?.includes('Video Recorder Firmware'))!
    expect(line).toHaveTextContent('3 more CVEs not checked one by one. Video Recorder Firmware has no fix on this release line: move to a supported release.')
    expect(line.textContent).not.toContain('already needs an update to')
  })

  it('are listed under their update in By fix, not as a number of their own', async () => {
    renderApp('/findings?tab=fix')
    const covered = await screen.findByTestId('fix-covered', {}, T)
    expect(covered).toHaveTextContent('+ 5 CVEs not checked one by one')
    await userEvent.click(within(covered.closest('article')!).getByRole('button', { name: /^Update WordPress/ }))
    const line = await screen.findByTestId('covered-line', {}, T)
    expect(line).toHaveTextContent('WordPress website')
  })

  it('stay out of Home\'s "still unknown"', async () => {
    const c = possibleCounts()
    renderApp('/')
    const line = await screen.findByTestId('home-undecided', {}, T)
    const unknown = c.possible + c.older_build + c.distro_pending - reviewCount()
    await waitFor(() => expect(line).toHaveTextContent(new RegExp(`${unknown} still unknown`, 'i')), T)
  })

  it('a device page shows its covered CVEs as the same closed group', async () => {
    renderApp('/devices/a-web01?tab=findings')
    const s = await section()
    expect(await within(s).findByTestId('covered-line', {}, T)).toHaveTextContent('5 more CVEs not checked one by one')
  })
})
