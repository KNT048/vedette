import { createContext, useContext, type ComponentProps } from 'react'
import { cn } from '@/lib/utils'
import { InfoTip } from '@/components/common/InfoTip'

// docs/UI.md §1, §8: the edge is `control` (3:1 on surface); `rule` (1.3:1) is for decoration only.
const field = 'w-full min-w-0 rounded-md border border-control bg-surface px-3 text-base text-ink sm:text-sm placeholder:text-muted disabled:opacity-60 aria-[invalid=true]:border-danger'

/** What a Field tells its control (docs/UI.md §8, review r1 M6): the id it labels, the id of its error or hint, and whether it is invalid. */
const FieldCtx = createContext<{ htmlFor: string; describedBy?: string; invalid: boolean } | null>(null)

/** aria-describedby and aria-invalid for the control a Field labels (the one whose id is the Field's htmlFor). The call site's own
 *  aria-describedby is kept and the Field's error or hint is added to it; the call site's aria-invalid wins. */
function useFieldAria(id: string | undefined, props: { 'aria-describedby'?: string; 'aria-invalid'?: ComponentProps<'input'>['aria-invalid'] }) {
  const f = useContext(FieldCtx)
  if (!f || !id || id !== f.htmlFor) return {}
  return {
    'aria-describedby': [...new Set([...(props['aria-describedby']?.split(/\s+/) ?? []), ...(f.describedBy ? [f.describedBy] : [])])].filter(Boolean).join(' ') || undefined,
    'aria-invalid': props['aria-invalid'] ?? (f.invalid ? true : undefined),
  }
}

export function Input({ className, ...props }: ComponentProps<'input'>) {
  const aria = useFieldAria(props.id, props)
  return <input className={cn(field, 'h-10 sm:h-9', className)} {...props} {...aria} />
}

export function Textarea({ className, ...props }: ComponentProps<'textarea'>) {
  const aria = useFieldAria(props.id, props)
  return <textarea className={cn(field, 'min-h-24 py-2 leading-relaxed', className)} {...props} {...aria} />
}

/** The browser's native select: reachable by keyboard and screen reader, needs no JS. */
export function Select({ className, ...props }: ComponentProps<'select'>) {
  const aria = useFieldAria(props.id, props)
  return <select className={cn(field, 'h-10 pr-8 sm:h-9', className)} {...props} {...aria} />
}

export function Label({ className, ...props }: ComponentProps<'label'>) {
  return <label className={cn('text-sm font-medium text-ink', className)} {...props} />
}

/** The one line of help or state under a control or a group of controls (a hint, a limit, a zone note): `text-meta`, muted unless
 *  `tone` says otherwise, wrapping anywhere. Field draws its hint with it; a page puts it under the control row instead of a bare <p>. */
export function FieldHint({ tone = 'muted', className, ...props }: ComponentProps<'p'> & { tone?: 'muted' | 'warn' | 'danger' }) {
  return <p className={cn('text-meta [overflow-wrap:anywhere]', tone === 'muted' ? 'text-muted' : tone === 'warn' ? 'text-warn' : 'text-danger', className)} {...props} />
}

/** An input with a label, hint and error, used for every form. `hint` is only a one-line example/format; explanation goes into `info` (ⓘ next to the label, #824).
 *  The Input, Select or Textarea whose id is `htmlFor` gets aria-describedby (the error, else the hint) and aria-invalid (WCAG 1.3.1, 3.3.1). */
export function Field({ label, hint, info, error, htmlFor, children, className }: { label: string; hint?: string; info?: React.ReactNode; error?: string; htmlFor: string; children: React.ReactNode; className?: string }) {
  const describedBy = error ? `${htmlFor}-error` : hint ? `${htmlFor}-hint` : undefined
  return (
    <div className={cn('grid content-start gap-1.5', className)}>
      {info ? (
        <div className="flex items-center gap-1">
          <Label htmlFor={htmlFor}>{label}</Label>
          <InfoTip topic={label}>{info}</InfoTip>
        </div>
      ) : <Label htmlFor={htmlFor}>{label}</Label>}
      <FieldCtx.Provider value={{ htmlFor, describedBy, invalid: !!error }}>{children}</FieldCtx.Provider>
      {error ? <FieldHint tone="danger" id={`${htmlFor}-error`}>{error}</FieldHint> : hint ? <FieldHint id={`${htmlFor}-hint`}>{hint}</FieldHint> : null}
    </div>
  )
}
