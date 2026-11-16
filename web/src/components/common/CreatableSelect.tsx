import { useId, useState, type ComponentProps, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Select } from '@/components/ui/input'

export type SelectOption = { value: string; label: string; disabled?: boolean }

/** What the caller's create dialog gets: whether it is open, how to close it, and what to call with the saved item. */
export type CreateDialogProps = { open: boolean; onOpenChange: (open: boolean) => void; onCreated: (item: SelectOption) => void }

const NEW = '__vedette_create_new__' // a value no real option has

/**
 * "Do it where you are" (docs/UI.md §0): a select whose last option is "+ New …". Choosing it opens the caller's small create
 * dialog (`renderCreate`, a DialogContent with its own form and save call); on save the new item is selected, focus is back on
 * the select (DialogContent returns it to the opener) and a polite status line says "<name> added and selected". Cancel keeps
 * the previous value. The native select keeps keyboard and screen-reader use as everywhere else; inside a Field it gets the
 * Field's aria-describedby and aria-invalid like any Select. `canCreate=false` (a viewer, a cap reached) hides the option, or, with
 * `createDisabledReason`, shows it disabled with the reason ("+ New SNMP credential (8 credentials at most)"), so a limit is never silent.
 * The create dialog is portalled, but React events bubble up the React tree: its form's submit is stopped here, so saving it never
 * submits the form this select sits in.
 */
export function CreatableSelect({ value, onChange, options, placeholder, newLabel, renderCreate, canCreate = true, createDisabledReason, ...rest }: Omit<ComponentProps<'select'>, 'value' | 'onChange' | 'children'> & {
  value: string
  onChange: (value: string) => void
  options: SelectOption[]
  /** First, empty choice ("Choose a credential"); shown while nothing is selected. */
  placeholder?: string
  /** "New SNMP credential": the option reads "+ New SNMP credential" and names the dialog's purpose. */
  newLabel: string
  renderCreate: (p: CreateDialogProps) => ReactNode
  canCreate?: boolean
  /** Why "+ New …" is not available (with canCreate=false): shown in the disabled option. */
  createDisabledReason?: string
}) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  // The created item, shown until the caller's list (refetched after the save) contains it.
  const [added, setAdded] = useState<SelectOption | null>(null)
  const [said, setSaid] = useState('')
  const status = useId()
  const list = added && !options.some((o) => o.value === added.value) ? [...options, added] : options
  return (
    <>
      <Select
        {...rest}
        value={value}
        onChange={(e) => {
          if (e.target.value === NEW) { setSaid(''); setOpen(true); return } // controlled: the shown value stays the old one
          onChange(e.target.value)
        }}
      >
        {placeholder !== undefined ? <option value="" disabled={value !== ''}>{placeholder}</option> : null}
        {list.map((o) => <option key={o.value} value={o.value} disabled={o.disabled}>{o.label}</option>)}
        {canCreate ? <option value={NEW}>{`+ ${newLabel}`}</option> : createDisabledReason ? <option value={NEW} disabled>{`+ ${newLabel} (${createDisabledReason})`}</option> : null}
      </Select>
      {/* Mounted when the dialog opens, so it exists before its text arrives (announced), and absent on an untouched page. */}
      {open || said ? <span id={status} role="status" className="sr-only">{said}</span> : null}
      {/* A wrapper in the React tree only (display: contents): the portalled dialog's submit stops here (review #849 H3). */}
      {canCreate ? <span className="contents" onSubmit={(e) => e.stopPropagation()}>{renderCreate({
        open,
        onOpenChange: setOpen,
        onCreated: (item) => {
          setAdded(item)
          onChange(item.value)
          setOpen(false)
          setSaid(t('creatable.added', { label: item.label }))
        },
      })}</span> : null}
    </>
  )
}
