import { useEffect, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Pencil, Plus, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input } from '@/components/ui/input'
import { cidrRange, CIDR_RE_UI, hasHostBits, IPV4_RE_UI, normalizeRange, rangeProblem } from '@/features/inventory/validate'

// The ranges and the exclusions of the scan scope: a list with Edit and Remove on each row, and Add / Edit in a dialog over the page
// (an add or edit form never opens inside the page). The Add range dialog shows what one pass costs with the range as typed.

type Checked = { error: string } | { value: string; note?: string }

/** A value as typed, settled for a moment (a cost asked of the box on every key press would be a request per key). */
export function useSettled<T>(value: T, ms = 300): T {
  const [v, setV] = useState(value)
  const key = JSON.stringify(value)
  useEffect(() => {
    const id = setTimeout(() => setV(value), ms)
    return () => clearTimeout(id)
  }, [key, ms]) // eslint-disable-line react-hooks/exhaustive-deps -- keyed by value
  return v
}

/** Add or edit one entry in a dialog. Its form stops the submit from reaching the page's own form behind it. `below` renders under
 *  the field with the text as typed (the cost of a range). */
function EntryDialog({ title, label, hint, info, initial, placeholder, submitLabel, check, onSave, onClose, below, blocked }: {
  title: string; label: string; hint: string; info?: string; initial: string; placeholder: string; submitLabel: string
  check: (raw: string) => Checked; onSave: (value: string, note?: string) => void; onClose: () => void; below?: (draft: string) => ReactNode
  /** Why the entry cannot be added as it is (the scope would be refused on save): the submit button is off and says why. */
  blocked?: string | null
}) {
  const { t } = useTranslation()
  const [draft, setDraft] = useState(initial)
  const [error, setError] = useState<string | undefined>()
  function submit(e: React.FormEvent) {
    e.preventDefault()
    e.stopPropagation()
    if (blocked) return
    const r = check(draft.trim())
    if ('error' in r) { setError(r.error); return }
    onSave(r.value, r.note)
    onClose()
  }
  return (
    <DialogContent title={title}>
      <form onSubmit={submit} noValidate className="grid gap-4">
        <Field label={label} htmlFor="entry-input" hint={hint} info={info} error={error}>
          <Input id="entry-input" value={draft} placeholder={placeholder} autoComplete="off" spellCheck={false} aria-invalid={error ? true : undefined}
            aria-describedby={error ? 'entry-input-error' : 'entry-input-hint'} onChange={(e) => { setDraft(e.target.value); setError(undefined) }} />
        </Field>
        {below?.(draft)}
        {blocked ? <p id="entry-blocked" className="sr-only">{blocked}</p> : null}
        <DialogFooter>
          <Button type="button" onClick={onClose}>{t('common:cancel')}</Button>
          <Button type="submit" variant="primary" disabled={!!blocked} title={blocked ?? undefined} aria-describedby={blocked ? 'entry-blocked' : undefined}>{submitLabel}</Button>
        </DialogFooter>
      </form>
    </DialogContent>
  )
}

/**
 * The network ranges: "10.142.0.5/24" becomes 10.142.0.0/24 and says so; a bare address is refused (the size of the network is
 * not guessed); every range can be edited or removed; a range stored wrongly (an older version) shows its error on its row without
 * blocking the others. `cost` renders the cost of the ranges with the one typed in the dialog (null: none typed or not valid yet).
 */
export function RangeList({ items, onChange, disabled, cost }: {
  items: string[]; onChange: (v: string[]) => void; disabled: boolean
  /** The cost of `ranges`; it calls `onRefused` with whether a scope of them would be refused on save. */
  cost: (ranges: string[], onRefused: (refused: boolean) => void) => ReactNode
}) {
  const { t } = useTranslation('scanning')
  const [dlg, setDlg] = useState<{ old: string | null } | null>(null)
  // the scope with the range typed in the dialog would be refused on save ("Saving is refused"): Add / Save stays off until it fits
  const [refused, setRefused] = useState(false)
  const [note, setNote] = useState<string | undefined>()
  const open = (old: string | null) => { setNote(undefined); setRefused(false); setDlg({ old }) }
  const problemText = (v: string, others: string[]) => {
    const p = rangeProblem(v, others)
    if (!p) return null
    const other = others.find((o) => o !== v && rangeProblem(v, [o]) === 'overlap')
    return t(`safety.range.problem.${p}`, { value: v, net: CIDR_RE_UI.test(v) ? cidrRange(v).network : '', other })
  }
  function check(raw: string, old: string | null): Checked {
    if (!raw) return { error: t('safety.range.problem.empty') }
    const n = normalizeRange(raw)
    const others = old === null ? items : items.filter((x) => x !== old)
    if (others.includes(n.value)) return { error: t('safety.range.duplicate', { value: n.value }) }
    const err = problemText(n.value, others)
    if (err) return { error: err }
    return { value: n.value, note: n.note ? t('safety.range.note', { from: raw, to: n.value }) : undefined }
  }
  /** The ranges as they would be with the draft: only a draft that would be accepted counts. */
  const withDraft = (draft: string, old: string | null) => {
    const r = check(draft.trim(), old)
    if ('error' in r) return null
    return old === null ? [...items, r.value] : items.map((x) => (x === old ? r.value : x))
  }
  return (
    <div className="grid gap-2">
      <div className="flex flex-wrap items-center gap-3">
        <p className="text-sm font-medium">{t('safety.range.title')}</p>
        <Button id="range-input" disabled={disabled || items.length >= 16} onClick={() => open(null)}><Plus />{t('safety.range.add')}</Button>
      </div>
      {note ? <p role="status" className="max-w-2xl text-meta text-ok">{note}</p> : null}
      {items.length ? (
        <ul className="grid max-w-2xl gap-2" aria-label={t('safety.range.list')}>
          {items.map((it) => {
            const err = problemText(it, items)
            return (
              <li key={it} className={err ? 'grid gap-1 rounded-md border border-danger/50 bg-danger-soft px-3 py-2' : 'rounded-md border border-rule bg-surface px-3 py-1.5'}>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-sm font-medium [overflow-wrap:anywhere]">{it}</span>
                  {disabled ? null : (
                    <span className="flex gap-1">
                      <Button size="sm" variant="ghost" aria-label={t('safety.range.editNamed', { value: it })} onClick={() => open(it)}><Pencil />{t('safety.range.edit')}</Button>
                      <Button size="sm" variant="ghost" aria-label={t('safety.range.removeNamed', { value: it })} onClick={() => onChange(items.filter((x) => x !== it))}><X />{t('safety.range.remove')}</Button>
                    </span>
                  )}
                </div>
                {err ? <p role="alert" className="text-meta text-danger">{err}</p> : null}
              </li>
            )
          })}
        </ul>
      ) : <p className="text-meta text-muted">{t('safety.range.none')}</p>}
      <Dialog open={!!dlg} onOpenChange={(o) => { if (!o) setDlg(null) }}>
        {dlg ? (
          <EntryDialog title={dlg.old === null ? t('safety.range.addTitle') : t('safety.range.editNamed', { value: dlg.old })} label={t('safety.range.label')}
            hint={t('safety.range.hint')} info={t('safety.range.hintInfo')} initial={dlg.old ?? ''} placeholder="192.168.10.0/24"
            submitLabel={dlg.old === null ? t('safety.range.add') : t('safety.range.save')} onClose={() => setDlg(null)}
            check={(raw) => check(raw, dlg.old)} below={(draft) => <DraftCost ranges={withDraft(draft, dlg.old)} cost={cost} onRefused={setRefused} />}
            blocked={refused ? t('safety.range.refused') : null}
            onSave={(v, n) => { onChange(dlg.old === null ? [...items, v] : items.map((x) => (x === dlg.old ? v : x))); setNote(n) }} />
        ) : null}
      </Dialog>
    </div>
  )
}

/** The cost of the ranges with the draft, once the draft is a range that would be accepted and has settled for a moment. */
function DraftCost({ ranges, cost, onRefused }: { ranges: string[] | null; cost: (ranges: string[], onRefused: (refused: boolean) => void) => ReactNode; onRefused: (refused: boolean) => void }) {
  const settled = useSettled(ranges)
  useEffect(() => { if (!settled) onRefused(false) }, [settled, onRefused]) // no range to cost: nothing refuses it
  return settled ? <>{cost(settled, onRefused)}</> : null
}

/** IPv4 addresses or ranges no engine touches: chips with Remove, and Add in a dialog. */
export function ExclusionList({ items, onChange, disabled }: { items: string[]; onChange: (v: string[]) => void; disabled: boolean }) {
  const { t } = useTranslation('scanning')
  const [open, setOpen] = useState(false)
  return (
    <div className="grid gap-2">
      <div><Button id="excl" disabled={disabled} onClick={() => setOpen(true)}><Plus />{t('safety.excl.add')}</Button></div>
      {items.length ? (
        <ul className="flex flex-wrap gap-2" aria-label={t('safety.excl.list')}>
          {items.map((it) => (
            <li key={it} className="inline-flex h-8 items-center gap-1 rounded-md border border-rule bg-surface pl-3 pr-1 text-sm">
              {it}
              {disabled ? null : <button type="button" className="grid size-6 place-items-center rounded text-muted hover:bg-sunken hover:text-ink" aria-label={t('safety.excl.removeNamed', { value: it })} onClick={() => onChange(items.filter((x) => x !== it))}><X className="size-3.5" /></button>}
            </li>
          ))}
        </ul>
      ) : <p className="text-meta text-muted">{t('safety.excl.none')}</p>}
      <Dialog open={open} onOpenChange={setOpen}>
        {open ? (
          <EntryDialog title={t('safety.excl.addTitle')} label={t('safety.excl.label')} hint={t('safety.exclHint')} info={t('safety.exclInfo')} initial="" placeholder="192.168.10.10"
            submitLabel={t('safety.excl.add')} onClose={() => setOpen(false)}
            check={(raw) => {
              const v = raw.trim()
              if (!(IPV4_RE_UI.test(v) || (CIDR_RE_UI.test(v) && !hasHostBits(v)))) return { error: t('safety.excl.bad') }
              return items.includes(v) ? { error: t('safety.range.duplicate', { value: v }) } : { value: v }
            }}
            onSave={(v) => onChange([...items, v])} />
        ) : null}
      </Dialog>
    </div>
  )
}
