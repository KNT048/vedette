import { useState } from 'react'
import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import '@/lib/i18n'
import { expectNoA11yViolations } from '@/test/render'
import { hasToken, parseQuery, toggleToken, TokenSearch, type TokenKey } from './TokenSearch'

const KEYS: TokenKey[] = [
  { key: 'type', label: 'Device type', values: [{ value: 'switch', label: 'Switch', count: 3 }, { value: 'firewall', label: 'Firewall', count: 1 }, { value: 'ip phone', label: 'IP phone', count: 2 }] },
  { key: 'source', label: 'What reports on it', values: [{ value: 'snmp', label: 'SNMP', count: 5 }] },
  { key: 'fragile', label: 'Fragile devices' },
]

function Harness({ initial = '' }: { initial?: string }) {
  const [q, setQ] = useState(initial)
  return (
    <>
      <TokenSearch value={q} onChange={setQ} keys={KEYS} label="Search devices" chips={[{ token: 'fragile', label: 'Fragile', count: 4 }, { token: 'source:snmp', label: 'SNMP' }]} />
      <output data-testid="q">{q}</output>
    </>
  )
}
const box = () => screen.getByRole('combobox', { name: 'Search devices' })
const q = () => screen.getByTestId('q').textContent

describe('parseQuery / toggleToken (#849)', () => {
  it('splits free text from tokens of known keys; an unknown key is free text; a key still being typed (type:, or type at the end) filters nothing', () => {
    expect(parseQuery('Cisco type:Switch fragile foo:bar type:', KEYS)).toEqual({ text: ['cisco', 'foo:bar'], tokens: [{ key: 'type', value: 'switch' }, { key: 'fragile', value: null }] })
    expect(parseQuery('cisco type', KEYS).text).toEqual(['cisco'])
    expect(parseQuery('type cisco', KEYS).text).toEqual(['type', 'cisco']) // only the word being typed
    expect(parseQuery('cisco ty', KEYS).text).toEqual(['cisco', 'ty']) // a partial word may be a name
  })
  it('a quoted run is one word, inside a value too', () => {
    expect(parseQuery('"core sw" type:"ip phone"', KEYS)).toEqual({ text: ['core sw'], tokens: [{ key: 'type', value: 'ip phone' }] })
  })
  it('a flag key with a value, or a value key without one, is not a token', () => {
    expect(parseQuery('fragile:yes source', KEYS).tokens).toEqual([])
  })
  it('toggleToken adds a token once and removes it, whatever the case', () => {
    expect(toggleToken('cisco', 'fragile')).toBe('cisco fragile')
    expect(toggleToken('cisco FRAGILE', 'fragile')).toBe('cisco')
    expect(hasToken('a source:snmp', 'source:SNMP')).toBe(true)
  })
})

describe('TokenSearch (#849)', () => {
  it('offers the keys, then the values of a key with their counts; an arrow key highlights, Enter picks; the list is a listbox the input controls', async () => {
    const user = userEvent.setup()
    render(<Harness />)
    await user.tab()
    expect(screen.queryByRole('listbox')).toBeNull() // Tab into the box does not open the list
    await user.click(box())
    const list = screen.getByRole('listbox')
    expect(box()).toHaveAttribute('aria-expanded', 'true')
    expect(box()).toHaveAttribute('aria-controls', list.id)
    expect(within(list).getAllByRole('option').map((o) => o.textContent)).toEqual(['type:Device type', 'source:What reports on it', 'fragileFragile devices'])
    await user.type(box(), 'ty')
    expect(within(list).getAllByRole('option')).toHaveLength(1)
    await user.keyboard('{Enter}') // nothing highlighted: Enter keeps what was typed and closes the list
    expect(q()).toBe('ty')
    await user.click(box())
    await user.keyboard('{ArrowDown}{Enter}')
    expect(q()).toBe('type:')
    const values = within(screen.getByRole('listbox')).getAllByRole('option')
    expect(values.map((o) => o.textContent)).toEqual(['type:switchSwitch3', 'type:firewallFirewall1', 'type:ip phoneIP phone2'])
    await user.keyboard('{ArrowDown}{ArrowDown}{Enter}')
    expect(q()).toBe('type:firewall ')
    await user.type(box(), 'type:ip')
    await user.keyboard('{ArrowDown}{Enter}')
    expect(q()).toBe('type:firewall type:"ip phone" ') // a value with a space is quoted
    await expectNoA11yViolations()
  })

  it('a value already in the query is not offered again', async () => {
    const user = userEvent.setup()
    render(<Harness initial="type:switch fragile " />)
    await user.click(box())
    await user.type(box(), 'type:')
    const names = within(screen.getByRole('listbox')).getAllByRole('option').map((o) => o.textContent)
    expect(names.some((n) => n?.startsWith('type:switch'))).toBe(false)
    await user.clear(box())
    await user.type(box(), 'type:switch fr')
    expect(screen.getByRole('listbox')).toBeVisible()
    expect(within(screen.getByRole('listbox')).getAllByRole('option').map((o) => o.textContent)).toEqual(['fragileFragile devices'])
  })

  it('the first Escape closes the list, the second clears the box; the clear button clears it too', async () => {
    const user = userEvent.setup()
    render(<Harness initial="cisco" />)
    await user.click(box())
    await user.keyboard('{End} ')
    expect(screen.getByRole('listbox')).toBeVisible()
    await user.keyboard('{Escape}')
    expect(screen.queryByRole('listbox')).toBeNull()
    expect(q()).toBe('cisco ')
    await user.keyboard('{Escape}')
    expect(q()).toBe('')
    await user.type(box(), 'nas')
    await user.click(screen.getByRole('button', { name: 'Clear search' }))
    expect(q()).toBe('')
    expect(box()).toHaveFocus()
  })

  it('chips toggle their token and say whether they are on', async () => {
    const user = userEvent.setup()
    render(<Harness initial="cisco" />)
    const filters = screen.getByRole('button', { name: 'Filters' })
    await user.click(filters)
    await user.click(await screen.findByRole('menuitemcheckbox', { name: 'Fragile 4' }))
    expect(q()).toBe('cisco fragile')
    expect(screen.getByRole('menuitemcheckbox', { name: 'Fragile 4' })).toBeChecked() // the menu stays open for a second pick
    await user.keyboard('{Escape}')
    expect(screen.queryByRole('menu')).toBeNull()
    expect(filters).toHaveFocus()
    expect(screen.getByRole('button', { name: 'Filters 1' })).toBeInTheDocument()
    // the active filter is a removable chip
    await user.click(screen.getByRole('button', { name: 'Remove filter Fragile' }))
    expect(q()).toBe('cisco')
    expect(screen.queryByRole('button', { name: /^Remove filter/ })).toBeNull()
  })

  it('Clear filters shows with two or more filters on and removes only the filters, not the typed words', async () => {
    const user = userEvent.setup()
    render(<Harness initial="cisco fragile source:snmp" />)
    expect(screen.getAllByRole('button', { name: /^Remove filter/ })).toHaveLength(2)
    await user.click(screen.getByRole('button', { name: 'Clear filters' }))
    expect(q()).toBe('cisco')
    expect(screen.queryByRole('button', { name: 'Clear filters' })).toBeNull()
  })
})
