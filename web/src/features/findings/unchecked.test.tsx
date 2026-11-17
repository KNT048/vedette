import { describe, expect, it } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'

describe('#910 phase 1: exploited CVEs that could not be checked', () => {
  it('Findings lists each reason in plain words, with advisory or NVD links, and says no finding is made', async () => {
    renderApp('/findings')
    const box = (await screen.findByText(/exploited CVEs could not be checked automatically/)).closest('section')!
    const b = within(box)
    expect(b.getByText(/created no finding/)).toBeInTheDocument()
    expect(b.getByText(/NVD has not published which products this CVE affects yet/)).toBeInTheDocument()
    expect(b.getByText(/NVD names WordPress website but not which versions are affected/)).toBeInTheDocument()
    expect(b.getByText(/NVD's data for this CVE names other products, not MikroTik router/)).toBeInTheDocument()
    expect(b.getByText(/Vedette cannot compare version .* with NVD's ranges/)).toBeInTheDocument()
    expect(b.getByRole('link', { name: 'CVE-2026-20001: open the advisory' })).toHaveAttribute('href', expect.stringContaining('msrc.microsoft.com'))
    expect(b.getByRole('link', { name: 'CVE-2026-20002: open the NVD page' })).toHaveAttribute('href', 'https://nvd.nist.gov/vuln/detail/CVE-2026-20002')
    expect(b.getAllByText('Ransomware').length).toBeGreaterThan(0)
    // more than three CVEs: collapsed
    expect(b.queryByText('CVE-2026-20007')).toBeNull()
    await userEvent.click(b.getByRole('button', { name: 'Show 1 more' }))
    expect(b.getByText('CVE-2026-20007')).toBeInTheDocument()
  })

  it('"Add the version" opens the version dialog in place, only where it can help', async () => {
    renderApp('/findings')
    const box = (await screen.findByText(/exploited CVEs could not be checked automatically/)).closest('section')!
    const add = within(box).getAllByRole('button', { name: 'Add the version' })
    expect(add).toHaveLength(1)
    await userEvent.click(add[0]!)
    expect(await screen.findByRole('dialog')).toBeInTheDocument()
  })

  it('Home links the count to the Findings block', async () => {
    renderApp('/')
    const link = await screen.findByRole('link', { name: /You have 8 exploited CVEs Vedette could not check on 4 devices/ })
    expect(link).toHaveAttribute('href', '/findings?tab=open#unchecked')
  })
})
