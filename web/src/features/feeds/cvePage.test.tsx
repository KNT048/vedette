// The CVE page reads the brief for any CVE the catalogue holds: affected and fixed versions, what to do, the description, the
// tagged sources, and the facts with who scored the CVE.
import { describe, expect, it } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp, expectNoA11yViolations } from '@/test/render'

describe('the CVE page of a full brief', () => {
  it('CVE-2025-22225: the sentence, the affected versions behind one click, what to do, the sources by tag, the facts', async () => {
    renderApp('/cve/CVE-2025-22225')
    expect(await screen.findByRole('heading', { level: 1, name: 'CVE-2025-22225' })).toBeInTheDocument()
    expect(screen.getByTestId('cve-sentence')).toHaveTextContent(/^VMware ESXi hypervisor has a flaw of type “Out-of-bounds Write” \(CWE-787\)/)
    const affected = screen.getByRole('heading', { name: 'Affected and fixed' }).closest('section')!
    expect(within(affected).getByText(/^The version data names no fixed release/)).toBeInTheDocument()
    await userEvent.click(within(affected).getByText('All affected versions (55 rows)'))
    expect(within(affected).getByText(/^7\.0, 7\.0 beta, 7\.0 update_1,/)).toBeInTheDocument()
    const todo = screen.getByRole('heading', { name: 'What to do' }).closest('section')!
    expect(within(todo).getByText('No workaround is published: install the fix.')).toBeInTheDocument()
    expect(within(todo).getByText('CISA KEV asks:')).toBeInTheDocument()
    const sources = screen.getByRole('heading', { name: 'Sources' }).closest('section')!
    expect(within(sources).getByText('Vendor advisory')).toBeInTheDocument()
    expect(within(sources).getByText('Government')).toBeInTheDocument()
    expect(screen.getByText('CVSS 3.1 by NVD')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'CWE-787: Out-of-bounds Write' })).toHaveAttribute('href', 'https://cwe.mitre.org/data/definitions/787.html')
    await expectNoA11yViolations()
  })
})
