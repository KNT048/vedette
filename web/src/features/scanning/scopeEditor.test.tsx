// The one scan-scope editor (Settings › Scanning › Safety): ranges and exclusions added and edited in a dialog, the cost of a pass
// where a range is added, Save off with the reason while the box would refuse the save.
import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { auditStore } from '@/mocks/stores'
import { inventorySettingsStore } from '@/features/inventory/mocks'

const T = { timeout: 4000 }
const PAGE = '/settings/scanning?tab=safety'
type User = ReturnType<typeof userEvent.setup>
/** Opens Add range and gives back the dialog's field. */
const openAdd = async (user: User) => { await user.click(await screen.findByRole('button', { name: 'Add range' }, T)); return screen.findByLabelText('Network range') }
const submitDialog = (user: User) => user.click(within(screen.getByRole('dialog')).getByRole('button', { name: /^(Add range|Save range|Add exclusion)$/ }))
const save = (user: User) => user.click(screen.getByRole('button', { name: 'Save settings' }))
const saved = () => screen.findByText(/^Safety settings saved/, undefined, T)
const confirm = () => screen.getByRole('checkbox', { name: /I confirm these network ranges/ })

describe('scan scope: one editor, ranges in a dialog', () => {
  it('the ranges are a list with Edit and Remove, the dialog title is said once and its field is "Network range"; no a11y errors', async () => {
    const user = userEvent.setup()
    renderApp(PAGE)
    expect(await screen.findByRole('button', { name: 'Edit range 192.168.10.0/24' }, T)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Remove range 192.168.20.0/24' })).toBeInTheDocument()
    expect(screen.queryByRole('textbox', { name: /one per line/ })).toBeNull() // no in-page text area
    await expectNoA11yViolations()
    await openAdd(user)
    const dlg = screen.getByRole('dialog', { name: 'Add a network range' })
    expect(within(dlg).getAllByRole('heading', { name: 'Add a network range' })).toHaveLength(1)
    expect(within(dlg).queryByText('Add range', { selector: 'label' })).toBeNull()
    expect(within(dlg).getByRole('button', { name: 'Add range' })).toBeInTheDocument()
  })

  it('a bare address is refused, never turned into /24; host bits are cut with a note; duplicates, overlaps and public ranges are refused', async () => {
    const user = userEvent.setup()
    renderApp(PAGE)
    const input = await openAdd(user)
    await submitDialog(user)
    expect(await screen.findByText(/Type a range first/, undefined, T)).toBeInTheDocument()
    await user.type(input, '10.142.0.0')
    await submitDialog(user)
    expect(await screen.findByText(/"10\.142\.0\.0" has no prefix length/, undefined, T)).toBeInTheDocument()
    await user.clear(input)
    await user.type(input, '192.168.10.0/24')
    await submitDialog(user)
    expect(await screen.findByText('192.168.10.0/24 is already in the list.', undefined, T)).toBeInTheDocument()
    await user.clear(input)
    await user.type(input, '192.168.10.0/25')
    await submitDialog(user)
    expect(await screen.findByText(/overlaps 192\.168\.10\.0\/24/, undefined, T)).toBeInTheDocument()
    await user.clear(input)
    await user.type(input, '8.8.8.0/24')
    await submitDialog(user)
    expect(await screen.findByText(/is not an internal range/, undefined, T)).toBeInTheDocument()
    await user.clear(input)
    await user.type(input, '192.168.30.77/23')
    await submitDialog(user)
    expect(screen.getByRole('button', { name: 'Remove range 192.168.30.0/23' })).toBeInTheDocument()
    expect(screen.getByText('192.168.30.77/23 was added as 192.168.30.0/23, the first address of its range.')).toBeInTheDocument()
  })

  it('Edit opens the range filled in; a changed set of ranges asks for the confirmation again; the save stores it', async () => {
    const user = userEvent.setup()
    renderApp(PAGE)
    await user.click(await screen.findByRole('button', { name: 'Edit range 192.168.20.0/24' }, T))
    const input = await screen.findByLabelText('Network range')
    expect(input).toHaveValue('192.168.20.0/24')
    await user.clear(input)
    await user.type(input, '192.168.20.0/25')
    await submitDialog(user)
    await user.click(screen.getByRole('button', { name: 'Remove range 192.168.10.0/24' }))
    expect(confirm()).not.toBeChecked()
    expect(screen.getByText('The ranges changed: tick the confirmation again to save.')).toBeInTheDocument()
    await user.click(confirm())
    await save(user)
    await saved()
    expect(inventorySettingsStore.get().lan_ranges).toEqual(['192.168.20.0/25'])
  })

  it('a stored range that is not valid shows its error on its row, turns Save off with the reason, and never blocks the others', async () => {
    inventorySettingsStore.update((s) => ({ ...s, lan_ranges: ['192.168.10.0/24', '10.142.0.0'] }))
    const user = userEvent.setup()
    renderApp(PAGE)
    const bad = (await screen.findByRole('button', { name: 'Remove range 10.142.0.0' }, T)).closest('li')!
    expect(within(bad).getByRole('alert')).toHaveTextContent('"10.142.0.0" has no prefix length')
    expect(screen.getByRole('button', { name: 'Save settings' })).toBeDisabled()
    expect(screen.getByText('Fix or remove the range marked in red to save.')).toBeInTheDocument()
    const input = await openAdd(user)
    await user.type(input, '10.9.0.0/16')
    await submitDialog(user)
    await user.click(screen.getByRole('button', { name: 'Edit range 10.142.0.0' }))
    await user.type(await screen.findByLabelText('Network range'), '/24')
    await submitDialog(user)
    expect(screen.queryByText(/marked in red/)).toBeNull()
    await user.click(confirm())
    await save(user)
    await saved()
    expect(inventorySettingsStore.get().lan_ranges).toEqual(['192.168.10.0/24', '10.142.0.0/24', '10.9.0.0/16'])
  })

  it('the Add range dialog shows what one pass costs with the range as typed', async () => {
    const user = userEvent.setup()
    renderApp(PAGE)
    expect(await screen.findByText(/^One pass: [0-9,]+ addresses, at least/, undefined, T)).toBeInTheDocument() // the saved ranges, under the list
    const input = await openAdd(user)
    await user.type(input, '10.40.0.0/16')
    const dlg = screen.getByRole('dialog', { name: 'Add a network range' })
    expect(await within(dlg).findByText(/^One pass: 66,048 addresses/, undefined, T)).toBeInTheDocument() // 2 × 256 + 65,536
  })

  it('the Add range dialog keeps Add off while its cost panel says the save would be refused, and on again once the range fits', async () => {
    const user = userEvent.setup()
    renderApp(PAGE)
    await user.selectOptions(await screen.findByLabelText('Discovery and SNMP', undefined, T), '10')
    const input = await openAdd(user)
    await user.type(input, '10.0.0.0/8')
    const dlg = screen.getByRole('dialog', { name: 'Add a network range' })
    expect(await within(dlg).findByText(/Saving is refused: raise the scan rate/, undefined, T)).toBeInTheDocument()
    await waitFor(() => expect(within(dlg).getByRole('button', { name: 'Add range' })).toBeDisabled(), T)
    await user.click(within(dlg).getByRole('button', { name: 'Add range' }))
    expect(screen.queryByRole('button', { name: 'Remove range 10.0.0.0/8' })).toBeNull()
    await user.clear(input)
    await user.type(input, '10.40.0.0/24')
    await waitFor(() => expect(within(dlg).getByRole('button', { name: 'Add range' })).toBeEnabled(), T)
  })

  it('a scope too large for a week turns Save off with the reason, offers a faster speed that fits, and shows long passes in days', async () => {
    const user = userEvent.setup()
    inventorySettingsStore.update((s) => ({ ...s, lan_ranges: [...s.lan_ranges, '10.0.0.0/8'] })) // stored before the dialog refused it
    renderApp(PAGE)
    await user.selectOptions(await screen.findByLabelText('Discovery and SNMP', undefined, T), '10')
    expect(await screen.findByText(/Saving is refused: raise the scan rate/, undefined, T)).toBeInTheDocument()
    expect(screen.getByText(/at least \d+ days at 10 packets\/s/)).toBeInTheDocument()
    await user.click(confirm())
    expect(screen.getByRole('button', { name: 'Save settings' })).toBeDisabled()
    expect(screen.getByText('Saving is refused: one pass of this scope does not fit a week of scan windows.')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Remove range 10.0.0.0/8' }))
    await user.click(confirm())
    await waitFor(() => expect(screen.getByRole('button', { name: 'Save settings' })).toBeEnabled(), T)
  })

  it('exclusions are added in a dialog and removed from their chip; window, speed and fragile types save with them', async () => {
    const user = userEvent.setup()
    renderApp(PAGE)
    const from = await screen.findByLabelText('From', undefined, T)
    await user.clear(from)
    await user.type(from, '22:30')
    await user.selectOptions(screen.getByLabelText('Discovery and SNMP'), '10')
    await user.click(screen.getByRole('button', { name: 'Add exclusion' }))
    const dlg = screen.getByRole('dialog', { name: 'Add an exclusion' })
    await user.type(within(dlg).getByLabelText('IP address or network'), '192.168.10.300')
    await submitDialog(user)
    expect(await within(dlg).findByText(/Enter one IP/)).toBeInTheDocument()
    await user.clear(within(dlg).getByLabelText('IP address or network'))
    await user.type(within(dlg).getByLabelText('IP address or network'), '192.168.10.10')
    await submitDialog(user)
    expect(screen.getByRole('button', { name: 'Remove exclusion 192.168.10.10' })).toBeInTheDocument()
    await save(user)
    await saved()
    expect(inventorySettingsStore.get().active).toMatchObject({ from: '22:30', rate: 10, exclusions: expect.arrayContaining(['192.168.10.10']) })
    expect(auditStore.get().some((e) => e.action === 'inventory.settings')).toBe(true)
  })

  it('what the engines never do is one line, the list behind its info icon', async () => {
    renderApp(PAGE)
    expect(await screen.findByRole('button', { name: /What Vedette never does/ }, T)).toBeInTheDocument()
    expect(screen.queryByRole('listitem', { name: /exploit/i })).toBeNull()
  })
})
