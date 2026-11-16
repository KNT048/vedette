// docs/UI.md §0 "Do it where you are": the missing item is created from the select itself and selected on save.
import { useState } from 'react'
import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import '@/lib/i18n'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Field, Input } from '@/components/ui/input'
import { CreatableSelect, type CreateDialogProps } from './CreatableSelect'
import { expectNoA11yViolations } from '@/test/render'

/** The caller's dialog: its own form and save call (here: instant). */
function NewCredential({ open, onOpenChange, onCreated }: CreateDialogProps) {
  const [name, setName] = useState('')
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {open ? (
        <DialogContent title="New SNMP credential">
          <Field label="Name" htmlFor="cred-name"><Input id="cred-name" value={name} onChange={(e) => setName(e.target.value)} /></Field>
          <DialogFooter>
            <Button onClick={() => onOpenChange(false)}>Cancel</Button>
            <Button variant="primary" onClick={() => onCreated({ value: 'c-9', label: name })}>Save</Button>
          </DialogFooter>
        </DialogContent>
      ) : null}
    </Dialog>
  )
}

function Form({ canCreate = true }: { canCreate?: boolean }) {
  const [v, setV] = useState('c-1')
  return (
    <>
      <Field label="SNMP credential" htmlFor="cred" hint="Used to read the device's model and firmware">
        <CreatableSelect id="cred" value={v} onChange={setV} options={[{ value: 'c-1', label: 'Office switches' }]} newLabel="New SNMP credential" canCreate={canCreate} renderCreate={(p) => <NewCredential {...p} />} />
      </Field>
      <span data-testid="value">{v}</span>
    </>
  )
}

describe('CreatableSelect', () => {
  it('"+ New …" is an option; saving the dialog selects the new item, gives focus back and says so', async () => {
    const u = userEvent.setup()
    render(<Form />)
    const select = screen.getByRole('combobox', { name: 'SNMP credential' })
    expect(screen.getByRole('option', { name: '+ New SNMP credential' })).toBeInTheDocument()
    await u.selectOptions(select, '+ New SNMP credential')
    const dialog = await screen.findByRole('dialog', { name: 'New SNMP credential' })
    expect(screen.getByTestId('value')).toHaveTextContent('c-1') // nothing chosen yet
    await u.type(screen.getByRole('textbox', { name: 'Name' }), 'Core switch v3')
    await u.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(dialog).not.toBeInTheDocument())
    expect(screen.getByTestId('value')).toHaveTextContent('c-9')
    expect(select).toHaveDisplayValue('Core switch v3')
    expect(select).toHaveFocus()
    expect(screen.getByRole('status')).toHaveTextContent('Core switch v3 added and selected.')
    expect(select).toHaveAccessibleDescription("Used to read the device's model and firmware")
    await expectNoA11yViolations()
  })

  it('Cancel keeps the previous value', async () => {
    const u = userEvent.setup()
    render(<Form />)
    const select = screen.getByRole('combobox', { name: 'SNMP credential' })
    await u.selectOptions(select, '+ New SNMP credential')
    await u.click(await screen.findByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(select).toHaveDisplayValue('Office switches')
    expect(screen.getByTestId('value')).toHaveTextContent('c-1')
  })

  it('canCreate=false: no "+ New …" option; with a reason, the option is there, disabled, and says why', () => {
    const { unmount } = render(<Form canCreate={false} />)
    expect(screen.queryByRole('option', { name: /New SNMP credential/ })).toBeNull()
    unmount()
    render(<CreatableSelect aria-label="Credential" value="c-1" onChange={() => {}} options={[{ value: 'c-1', label: 'Office switches' }]} newLabel="New SNMP credential" canCreate={false} createDisabledReason="8 credentials at most" renderCreate={(p) => <NewCredential {...p} />} />)
    expect(screen.getByRole('option', { name: '+ New SNMP credential (8 credentials at most)' })).toBeDisabled()
  })

  it("saving the create dialog's own form never submits the form the select sits in (portal, React bubbling)", async () => {
    const u = userEvent.setup()
    const outer = vi.fn((e: React.FormEvent) => e.preventDefault())
    const inner = vi.fn()
    function InnerForm({ open, onOpenChange, onCreated }: CreateDialogProps) {
      return (
        <Dialog open={open} onOpenChange={onOpenChange}>
          {open ? (
            <DialogContent title="New SNMP credential">
              <form onSubmit={(e) => { e.preventDefault(); inner(); onCreated({ value: 'c-9', label: 'Core' }) }}>
                <Button type="submit" variant="primary">Save</Button>
              </form>
            </DialogContent>
          ) : null}
        </Dialog>
      )
    }
    function Outer() {
      const [v, setV] = useState('c-1')
      return (
        <form onSubmit={outer}>
          <CreatableSelect aria-label="Credential" value={v} onChange={setV} options={[{ value: 'c-1', label: 'Office switches' }]} newLabel="New SNMP credential" renderCreate={(p) => <InnerForm {...p} />} />
          <Button type="submit">Read now</Button>
        </form>
      )
    }
    render(<Outer />)
    await u.selectOptions(screen.getByRole('combobox', { name: 'Credential' }), '+ New SNMP credential')
    await u.click(await screen.findByRole('button', { name: 'Save' }))
    expect(inner).toHaveBeenCalledTimes(1)
    expect(outer).not.toHaveBeenCalled()
    expect(screen.getByRole('combobox', { name: 'Credential' })).toHaveDisplayValue('Core')
  })
})
