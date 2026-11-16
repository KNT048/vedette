// docs/UI.md §8 (review r1 M6): a Field ties its hint or error to the control it labels.
import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Field, Input, Select } from './input'

describe('Field aria', () => {
  it('the hint describes the input; no aria-invalid without an error', () => {
    render(<Field label="Name" htmlFor="n" hint="As on the label"><Input id="n" /></Field>)
    const box = screen.getByRole('textbox', { name: 'Name' })
    expect(box).toHaveAccessibleDescription('As on the label')
    expect(box).not.toHaveAttribute('aria-invalid')
  })
  it('an error replaces the hint and marks the control invalid', () => {
    render(<Field label="Port" htmlFor="p" hint="1 to 65535" error="Use a number"><Select id="p"><option>1</option></Select></Field>)
    const box = screen.getByRole('combobox', { name: 'Port' })
    expect(box).toHaveAccessibleDescription('Use a number')
    expect(box).toHaveAttribute('aria-invalid', 'true')
  })
  it('the call site wins, and a second control inside the Field is left alone', () => {
    render(<Field label="IP" htmlFor="ip" error="Bad"><Input id="ip" aria-describedby="own" aria-invalid={false} /><Input id="other" aria-label="Other" /><p id="own">Own words</p></Field>)
    const ip = screen.getByRole('textbox', { name: 'IP' })
    expect(ip).toHaveAccessibleDescription('Own words')
    expect(ip).toHaveAttribute('aria-invalid', 'false')
    expect(screen.getByRole('textbox', { name: 'Other' })).not.toHaveAttribute('aria-describedby')
  })
})
