import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'

const T = { timeout: 5000 }
const blocks = () => screen.findByRole('list', { name: 'Devices that need your input, the most urgent first' }, T)
const open = async (device: string) => {
  await userEvent.click(within(await blocks()).getByRole('button', { name: new RegExp(`^${device}`) }))
  return screen.findByRole('list', { name: `What Vedette could not check on ${device}` }, T)
}

describe('#910 phase 1: exploited CVEs that could not be checked, in their device block', () => {
  it('each device block counts them; open, each reason is in plain words with advisory or NVD links, and no finding is made', async () => {
    renderApp('/findings?tab=input')
    const list = await blocks()
    // the count is in the block's toggle, collapsed: nothing of the list is drawn yet
    expect(within(list).getByRole('button', { name: /^SRV-ACCOUNTS.*2 CVEs could not be checked/ })).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByText(/NVD has not published/)).toBeNull()

    const srv = await open('SRV-ACCOUNTS')
    expect(within(srv).getByText(/NVD has not published which products this CVE affects yet/)).toBeInTheDocument()
    expect(within(srv).getByRole('link', { name: 'CVE-2026-20001: open the advisory' })).toHaveAttribute('href', expect.stringContaining('msrc.microsoft.com'))
    expect(within(srv).getByRole('link', { name: 'CVE-2026-20002: open the NVD page' })).toHaveAttribute('href', 'https://nvd.nist.gov/vuln/detail/CVE-2026-20002')
    expect(within(srv).getAllByText('Ransomware').length).toBeGreaterThan(0)
    expect(screen.getByText(/created no finding/)).toBeInTheDocument()
    expect(within(await open('WEB01')).getByText(/NVD names WordPress website but not which versions are affected/)).toBeInTheDocument()
    expect(within(await open('RT-BACKUP')).getByText(/NVD's data for this CVE names other products, not MikroTik router/)).toBeInTheDocument()
    const nas = await open('NAS-BACKUP')
    expect(within(nas).getByText(/Vedette cannot compare version .* with NVD's ranges/)).toBeInTheDocument()
    // more than three CVEs: collapsed
    expect(within(nas).queryByText('CVE-2026-20007')).toBeNull()
    await userEvent.click(within(nas).getByRole('button', { name: 'Show 1 more' }))
    expect(within(nas).getByText('CVE-2026-20007')).toBeInTheDocument()
  })

  it('Home links the count to the Findings block', async () => {
    renderApp('/')
    const link = await screen.findByRole('link', { name: /You have 9 exploited CVEs Vedette could not check on 5 devices/ })
    expect(link).toHaveAttribute('href', '/findings?tab=input#unchecked')
    // review r1 of #943: the link lands on the list (Needs your input), not on a tab without it
    await userEvent.click(link)
    expect(await screen.findByRole('tab', { name: /Needs your input/, selected: true })).toBeInTheDocument()
    await waitFor(() => expect(document.getElementById('unchecked')).not.toBeNull())
  })
})
