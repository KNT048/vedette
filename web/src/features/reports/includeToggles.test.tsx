import { beforeEach, describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { assetsStore, findingsStore } from '@/mocks/stores'
import { buildWeekly } from './weekly'
import { buildPdpl } from './pdpl'
import { DEFAULT_FILTERS, FILTERS_KEY, pdplView, weeklyView } from './filters'
import type { PdplOrg } from './types'

// Two switches over a report: devices not in the Devices list (not approved yet; in by default) and findings closed as not
// relevant (out by default). They change the totals and the lists, persist per browser, and the print view follows them.

function seed(rows: { id: string; asset: string; status: 'not_relevant' | 'confirmed' }[]) {
  const tpl = findingsStore.get()[0]!
  const now = new Date().toISOString()
  findingsStore.set([...findingsStore.get(), ...rows.map((r, i) => ({ ...tpl, id: r.id, asset_id: r.asset, cve: `CVE-2026-7100${i}`, status: r.status, first_seen: now, resolved_at: null }))])
}
const approvedAsset = () => assetsStore.get().find((a) => a.approved)!.id
const unapprovedAsset = () => assetsStore.get().find((a) => !a.approved)!.id
const stat = (doc: HTMLElement, label: string) => within(doc).getByText(label).nextElementSibling!

beforeEach(() => { try { localStorage.removeItem(FILTERS_KEY) } catch { /* none */ } })

describe('report include switches: the view', () => {
  it('leaves out not relevant by default and subtracts them with the counts the box gives', () => {
    seed([{ id: 'nr-1', asset: approvedAsset(), status: 'not_relevant' }, { id: 'nr-2', asset: approvedAsset(), status: 'not_relevant' }])
    const full = buildWeekly()
    expect(full.counts.not_relevant).toBe(2)
    const { report, left } = weeklyView(full, DEFAULT_FILTERS)
    expect(report.counts.new_findings).toBe(full.counts.new_findings - 2)
    expect(report.new_findings.some((f) => f.status === 'not_relevant')).toBe(false)
    expect(left).toEqual({ devices: null, notRelevant: 2 })
    expect(weeklyView(full, { unapproved: true, notRelevant: true }).report).toBe(full)
  })

  it('leaves out the devices not approved yet with the approved-only counts, top risks and actions', () => {
    seed([{ id: 'un-1', asset: unapprovedAsset(), status: 'confirmed' }])
    const full = buildWeekly()
    const { report, left } = weeklyView(full, { unapproved: false, notRelevant: true })
    expect(left.devices).toBe(full.counts.devices_unapproved)
    expect(report.counts).toEqual(full.approved_only!.counts)
    expect(report.counts.devices).toBe(full.counts.devices - full.counts.devices_unapproved)
    expect([...report.new_findings, ...report.open, ...report.resolved].every((f) => f.device_approved !== false)).toBe(true)
    expect(full.open.some((f) => f.id === 'un-1') && !report.open.some((f) => f.id === 'un-1')).toBe(true)
    expect(report.actions.some((a) => a.kind === 'review_devices')).toBe(false)
  })

  it('a report sent before the choice keeps its devices and hides not relevant by its rows', () => {
    seed([{ id: 'nr-old', asset: approvedAsset(), status: 'not_relevant' }])
    const { approved_only: _a, ...old } = buildWeekly()
    const legacy = { ...old, counts: { ...old.counts, not_relevant: undefined, not_relevant_new: undefined, not_relevant_resolved: undefined } }
    const { report, left } = weeklyView(legacy, { unapproved: false, notRelevant: false })
    expect(left).toEqual({ devices: null, notRelevant: 1 })
    expect(report.counts.devices).toBe(old.counts.devices)
    expect(report.counts.new_findings).toBe(old.counts.new_findings - 1)
  })

  it('the assessment leaves the devices out of its inventory and risks; its unapproved measure stays', () => {
    const org: PdplOrg = { name: 'Acme', tax_code: '', address: '', sector: '', employees: 5, data_volume: 'lt1k', size: 'micro', processing_service: false,
      contact_name: '', contact_email: '', contact_phone: '', sensitive: false, cross_border: false, processors: false, level: '' }
    seed([{ id: 'un-2', asset: unapprovedAsset(), status: 'confirmed' }])
    const full = buildPdpl(org)
    const { report, left } = pdplView(full, { unapproved: false, notRelevant: false })
    expect(left).toEqual({ devices: full.inventory.unapproved })
    expect(report.inventory.total).toBe(full.inventory.approved)
    expect(report.risks.some((f) => f.id === 'un-2')).toBe(false)
    expect(report.measures.find((m) => m.id === 'unapproved')).toEqual(full.measures.find((m) => m.id === 'unapproved'))
    expect(pdplView(full, DEFAULT_FILTERS).report).toBe(full)
  })
})

describe('report include switches: the page', () => {
  it('not relevant: out by default, the switch brings them back into lists and totals and is remembered', async () => {
    const before = buildWeekly().counts.new_findings
    seed([{ id: 'nr-a', asset: approvedAsset(), status: 'not_relevant' }, { id: 'nr-b', asset: approvedAsset(), status: 'not_relevant' }])
    const first = renderApp('/reports')
    const doc = await screen.findByRole('article', { name: 'Weekly security report' })
    expect(within(within(doc).getByRole('table', { name: 'What is new' })).queryByText('CVE-2026-71000')).toBeNull()
    expect(stat(doc, 'New this week')).toHaveTextContent(String(before))
    expect(within(doc).getByText('2 findings closed as not relevant are left out of these totals and lists.')).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: 'Include devices not in the Devices list' })).toBeChecked()

    await userEvent.click(screen.getByRole('switch', { name: 'Include not relevant' }))
    expect(within(within(doc).getByRole('table', { name: 'What is new' })).getAllByText('CVE-2026-71000').length).toBeGreaterThan(0)
    expect(stat(doc, 'New this week')).toHaveTextContent(String(before + 2))
    expect(within(doc).getByText('Findings closed as not relevant are included.')).toBeInTheDocument()
    first.unmount()

    renderApp('/reports') // the choice is kept in this browser
    expect(await screen.findByRole('switch', { name: 'Include not relevant' })).toBeChecked()
  })

  it('devices not in the Devices list: the switch takes them and their findings out of the figures and lists', async () => {
    seed([{ id: 'un-a', asset: unapprovedAsset(), status: 'confirmed' }])
    const full = buildWeekly()
    renderApp('/reports')
    const doc = await screen.findByRole('article', { name: 'Weekly security report' })
    expect(within(within(doc).getByRole('table', { name: 'What is new' })).getAllByText('CVE-2026-71000').length).toBeGreaterThan(0)
    await userEvent.click(screen.getByRole('switch', { name: 'Include devices not in the Devices list' }))
    expect(within(within(doc).getByRole('table', { name: 'What is new' })).queryByText('CVE-2026-71000')).toBeNull()
    expect(stat(doc, 'Devices')).toHaveTextContent(String(full.counts.devices - full.counts.devices_unapproved))
    expect(within(doc).getByText(`${full.counts.devices_unapproved} devices not in the Devices list (awaiting approval) are left out, with their findings.`)).toBeInTheDocument()
  })

  it('the print view follows the choice and says which one it used', async () => {
    localStorage.setItem(FILTERS_KEY, JSON.stringify({ unapproved: false, notRelevant: true }))
    const full = buildWeekly()
    renderApp('/reports/print/weekly')
    const doc = await screen.findByRole('article', { name: 'Weekly security report' })
    await waitFor(() => expect(within(doc).getByText(/devices not in the Devices list \(awaiting approval\) are left out/)).toBeInTheDocument())
    expect(within(doc).getByText('Findings closed as not relevant are included.')).toBeInTheDocument()
    expect(stat(doc, 'Devices')).toHaveTextContent(String(full.counts.devices - full.counts.devices_unapproved))
    expect(screen.getByRole('switch', { name: 'Include devices not in the Devices list' })).not.toBeChecked()
  })
})
