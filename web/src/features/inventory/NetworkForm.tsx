import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Pencil, Plus, X } from 'lucide-react'
import { Notice, Section, Panel } from '@/components/common/PageHeader'
import { ModuleOff, RequireModule } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Checkbox } from '@/components/ui/checkbox'
import { Field, Input, Label, Select } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { cidrRange, CIDR_RE_UI, hasHostBits, IPV4_RE_UI, normalizeRange, rangeProblem } from './validate'
import { fmtDateTime } from '@/lib/format'
import { useSaveSettings } from './api'
import { errMsg } from './kinds'
import { BEHAVIOUR_KINDS, type InventorySettings } from './types'
import { kindLabel } from '@/lib/deviceTypes'

const RATES = [10, 50, 200, 500]

type Checked = { error: string } | { value: string; note?: string }

/** Add or edit one entry of a list in a dialog over the page. Its form stops the submit from reaching the page's own form behind it. */
function EntryDialog({ title, label, hint, info, initial, placeholder, submitLabel, check, onSave, onClose }: {
  title: string; label: string; hint: string; info?: string; initial: string; placeholder: string; submitLabel: string
  check: (raw: string) => Checked; onSave: (value: string, note?: string) => void; onClose: () => void
}) {
  const { t } = useTranslation()
  const [draft, setDraft] = useState(initial)
  const [error, setError] = useState<string | undefined>()
  function submit(e: React.FormEvent) {
    e.preventDefault()
    e.stopPropagation()
    const r = check(draft.trim())
    if ('error' in r) { setError(r.error); return }
    onSave(r.value, r.note)
    onClose()
  }
  return (
    <DialogContent title={title}>
      <form onSubmit={submit} noValidate className="grid gap-4">
        <Field label={label} htmlFor="entry-input" hint={hint} info={info} error={error}>
          <Input id="entry-input" value={draft} placeholder={placeholder} autoComplete="off" spellCheck={false} aria-invalid={error ? true : undefined} aria-describedby={error ? 'entry-input-error' : 'entry-input-hint'}
            onChange={(e) => { setDraft(e.target.value); setError(undefined) }} />
        </Field>
        <DialogFooter>
          <Button type="button" onClick={onClose}>{t('common:cancel')}</Button>
          <Button type="submit" variant="primary">{submitLabel}</Button>
        </DialogFooter>
      </form>
    </DialogContent>
  )
}

function ListEditor({ id, label, listLabel, hint, info, items, onChange, validate, placeholder, addLabel, removeLabel, emptyText }: {
  id: string; label: string; listLabel: string; hint: string; info?: string; items: string[]; onChange: (v: string[]) => void; validate: (v: string) => string | null
  placeholder: string; addLabel: string; removeLabel: (v: string) => string; emptyText: string
}) {
  const [open, setOpen] = useState(false)
  return (
    <div className="grid gap-2">
      <div className="flex flex-wrap items-center gap-3">
        <p className="text-sm font-medium">{label}</p>
        <Button id={id} onClick={() => setOpen(true)}><Plus />{addLabel}</Button>
      </div>
      {items.length ? (
        <ul className="flex flex-wrap gap-2" aria-label={listLabel}>
          {items.map((it) => (
            <li key={it} className="inline-flex h-8 items-center gap-1 rounded-md border border-rule bg-surface pl-3 pr-1 text-sm">
              {it}
              <button type="button" className="grid size-6 place-items-center rounded text-muted hover:bg-sunken hover:text-ink" aria-label={removeLabel(it)} onClick={() => onChange(items.filter((x) => x !== it))}><X className="size-3.5" /></button>
            </li>
          ))}
        </ul>
      ) : <p className="text-meta text-muted">{emptyText}</p>}
      <Dialog open={open} onOpenChange={setOpen}>
        {open ? (
          <EntryDialog title={addLabel} label={label} hint={hint} info={info} initial="" placeholder={placeholder} submitLabel={addLabel} onClose={() => setOpen(false)}
            check={(v) => { const err = validate(v); return err ? { error: err } : { value: v } }}
            onSave={(v) => { if (!items.includes(v)) onChange([...items, v]) }} />
        ) : null}
      </Dialog>
    </div>
  )
}

/**
 * Scan network ranges: typing "192.168.18.0" becomes 192.168.18.0/24 by itself and says plainly that it was changed; every saved range can be edited/deleted;
 * a wrongly saved range (from an older version or typed by hand) shows an error right on its row, without blocking adding/editing/deleting other ranges.
 * Add and edit open in a dialog over the list.
 */
function RangeEditor({ items, onChange }: { items: string[]; onChange: (v: string[]) => void }) {
  const { t } = useTranslation('inventory')
  const [dlg, setDlg] = useState<{ old: string | null } | null>(null)
  const [note, setNote] = useState<string | undefined>()
  const problemText = (v: string, others: string[]) => {
    const p = rangeProblem(v, others)
    if (!p) return null
    const other = others.find((o) => o !== v && rangeProblem(v, [o]) === 'overlap')
    return t(`network.problem.${p}`, { value: v, net: CIDR_RE_UI.test(v) ? cidrRange(v).network : '', other })
  }
  function check(raw: string, old: string | null): Checked {
    if (!raw) return { error: t('network.problem.empty') }
    const n = normalizeRange(raw)
    const others = old === null ? items : items.filter((x) => x !== old)
    if (others.includes(n.value)) return { error: t('network.duplicate', { value: n.value }) }
    const err = problemText(n.value, others)
    if (err) return { error: err }
    return { value: n.value, note: n.note ? t(`network.note.${n.note}`, { from: raw, to: n.value }) : undefined }
  }
  return (
    <div className="grid gap-2">
      <div className="flex flex-wrap items-center gap-3">
        <p className="text-sm font-medium">{t('network.title')}</p>
        <Button id="range-input" onClick={() => { setNote(undefined); setDlg({ old: null }) }}><Plus />{t('network.addRange')}</Button>
      </div>
      {note ? <p role="status" className="max-w-2xl text-meta text-ok">{note}</p> : null}
      {items.length ? (
        <ul className="grid max-w-2xl gap-2" aria-label={t('network.rangeList')}>
          {items.map((it) => {
            const err = problemText(it, items)
            return (
              <li key={it} className={err ? 'grid gap-1 rounded-md border border-danger/50 bg-danger-soft px-3 py-2' : 'rounded-md border border-rule bg-surface px-3 py-1.5'}>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-sm font-medium [overflow-wrap:anywhere]">{it}</span>
                  <span className="flex gap-1">
                    <Button size="sm" variant="ghost" aria-label={t('network.editRange', { value: it })} onClick={() => { setNote(undefined); setDlg({ old: it }) }}><Pencil />{t('network.edit')}</Button>
                    <Button size="sm" variant="ghost" aria-label={t('network.removeRange', { value: it })} onClick={() => onChange(items.filter((x) => x !== it))}><X />{t('network.remove')}</Button>
                  </span>
                </div>
                {err ? <p role="alert" className="text-meta text-danger">{err}</p> : null}
              </li>
            )
          })}
        </ul>
      ) : <p className="text-meta text-muted">{t('network.noRanges')}</p>}
      <Dialog open={!!dlg} onOpenChange={(o) => { if (!o) setDlg(null) }}>
        {dlg ? (
          <EntryDialog title={dlg.old === null ? t('network.addRange') : t('network.editRange', { value: dlg.old })} label={t('network.rangeLabel')} hint={t('network.rangeHint')} info={t('network.rangeHintInfo')}
            initial={dlg.old ?? ''} placeholder="192.168.10.0/24" submitLabel={dlg.old === null ? t('network.addRange') : t('network.saveRange')} onClose={() => setDlg(null)}
            check={(raw) => check(raw, dlg.old)}
            onSave={(v, n) => { onChange(dlg.old === null ? [...items, v] : items.map((x) => (x === dlg.old ? v : x))); setNote(n) }} />
        ) : null}
      </Dialog>
    </div>
  )
}

/** LAN network ranges, the active scan window, exclusions, fragile devices passive only (S-INV-1). Confirm the scope before scanning (LEGAL §3). */
export function NetworkForm({ settings }: { settings: InventorySettings }) {
  const { t } = useTranslation('inventory')
  const save = useSaveSettings()
  const [draft, setDraft] = useState<InventorySettings>(settings)
  const [confirmed, setConfirmed] = useState(settings.scope_confirmed_at !== null)
  const [error, setError] = useState<string | null>(null)
  const dirty = JSON.stringify(draft) !== JSON.stringify(settings) || confirmed !== (settings.scope_confirmed_at !== null)
  const set = (p: Partial<InventorySettings>) => setDraft((d) => ({ ...d, ...p }))
  const setActive = (p: Partial<InventorySettings['active']>) => setDraft((d) => ({ ...d, active: { ...d.active, ...p } }))
  const rates = RATES.includes(draft.active.rate) ? RATES : [...RATES, draft.active.rate].sort((a, b) => a - b)
  const badRanges = draft.lan_ranges.filter((r) => rangeProblem(r, draft.lan_ranges) !== null).length
  const rangesChanged = JSON.stringify([...draft.lan_ranges].sort()) !== JSON.stringify([...settings.lan_ranges].sort())

  function submit() {
    setError(null)
    save.mutate({ ...draft, scope_confirmed: confirmed }, { onError: (e) => setError(errMsg(e)) })
  }

  return (
    <form onSubmit={(e) => { e.preventDefault(); submit() }} noValidate>
      <Section id="ranges" title={t('network.title')} description={t('network.description')} info={t('network.descriptionInfo')} stories={['S-INV-1']}>
        <Panel className="p-4">
          <RangeEditor items={draft.lan_ranges} onChange={(v) => { set({ lan_ranges: v }); setConfirmed(false) }} />
        </Panel>
      </Section>

      <Section id="active" title={t('active.title')} description={t('active.description')} info={t('active.descriptionInfo')}>
        <RequireModule module="sensor-active" fallback={<ModuleOff module="sensor-active">{t('active.off')}</ModuleOff>}>
          <Panel className="grid gap-5 p-4">
            <div className="flex flex-wrap items-center gap-3">
              <Switch id="active-enabled" checked={draft.active.enabled} onCheckedChange={(v) => setActive({ enabled: v })} />
              <Label htmlFor="active-enabled">{t('active.enabled')}</Label>
            </div>
            <fieldset className="grid gap-2" disabled={!draft.active.enabled}>
              <legend className="mb-1 text-sm font-medium">{t('active.days')}</legend>
              <div className="flex flex-wrap gap-x-4 gap-y-2">
                {[1, 2, 3, 4, 5, 6, 7].map((d) => (
                  <span key={d} className="inline-flex items-center gap-2">
                    <Checkbox id={`day-${d}`} checked={draft.active.days.includes(d)} onCheckedChange={(v) => setActive({ days: v === true ? [...draft.active.days, d].sort() : draft.active.days.filter((x) => x !== d) })} />
                    <Label htmlFor={`day-${d}`} className="font-normal">{t(`active.day.${d}`)}</Label>
                  </span>
                ))}
              </div>
              <div className="mt-2 flex flex-wrap gap-4">
                <Field label={t('active.from')} htmlFor="active-from"><Input id="active-from" type="time" className="w-32" value={draft.active.from} onChange={(e) => setActive({ from: e.target.value })} /></Field>
                <Field label={t('active.to')} htmlFor="active-to" info={t('active.crossMidnight')}><Input id="active-to" type="time" className="w-32" value={draft.active.to} onChange={(e) => setActive({ to: e.target.value })} /></Field>
                <Field label={t('active.rate')} htmlFor="active-rate" hint={t('active.rateHint')} className="max-w-xs">
                  <Select id="active-rate" value={draft.active.rate} onChange={(e) => setActive({ rate: Number(e.target.value) })} aria-describedby="active-rate-hint">
                    {rates.map((r) => <option key={r} value={r}>{t('active.rateOption', { rate: r, name: t(`active.rateName.${r}`, { defaultValue: t('active.rateCustom') }) })}</option>)}
                  </Select>
                </Field>
              </div>
            </fieldset>
            <ListEditor id="excl-input" label={t('active.exclusions')} listLabel={t('active.exclusionsList')} hint={t('active.exclusionsHint')} info={t('active.exclusionsHintInfo')} items={draft.active.exclusions} placeholder="192.168.10.10"
              addLabel={t('active.addExclusion')} removeLabel={(v) => t('active.removeExclusion', { value: v })} emptyText={t('active.noExclusions')}
              validate={(v) => (IPV4_RE_UI.test(v) || (CIDR_RE_UI.test(v) && !hasHostBits(v)) ? null : t('active.badExclusion'))}
              onChange={(v) => setActive({ exclusions: v })} />
            <p className="text-sm">{t('active.safety')}</p>
          </Panel>
        </RequireModule>
      </Section>

      <Section id="fragile" title={t('fragile.title')} description={t('fragile.description')} info={<><p>{t('fragile.descriptionInfo')}</p><p>{t('fragile.note')}</p></>}>
        <Panel className="p-4">
          <fieldset>
            <legend className="sr-only">{t('fragile.title')}</legend>
            <div className="grid grid-cols-2 gap-x-6 gap-y-2 sm:grid-cols-3 lg:grid-cols-4">
              {BEHAVIOUR_KINDS.map((k) => (
                <span key={k} className="grid gap-1">
                  <span className="inline-flex items-center gap-2">
                    <Checkbox id={`fragile-${k}`} checked={draft.fragile_kinds.includes(k)} onCheckedChange={(v) => set(v === true ? { fragile_kinds: [...draft.fragile_kinds, k] } : { fragile_kinds: draft.fragile_kinds.filter((x) => x !== k), regular_scan_kinds: draft.regular_scan_kinds.filter((x) => x !== k) })} />
                    <Label htmlFor={`fragile-${k}`} className="font-normal">{kindLabel(k)}</Label>
                  </span>
                  {draft.fragile_kinds.includes(k) ? (
                    <span className="ml-6 inline-flex items-center gap-2">
                      <Switch id={`regular-${k}`} aria-label={t('fragile.allowRegularFor', { kind: kindLabel(k) })} checked={draft.regular_scan_kinds.includes(k)}
                        onCheckedChange={(v) => set({ regular_scan_kinds: v ? [...draft.regular_scan_kinds, k] : draft.regular_scan_kinds.filter((x) => x !== k) })} />
                      <span className="text-meta text-muted" aria-hidden>{t('fragile.allowRegular')}</span>
                    </span>
                  ) : null}
                </span>
              ))}
            </div>
          </fieldset>
        </Panel>
      </Section>

      {error ? <Notice tone="danger" role="alert" className="mb-4 max-w-2xl" title={error} /> : null}
      {/* The commitment sits right above the Save button: it must be ticked again only when the set of ranges changes; changing other settings keeps the old confirmation. */}
      <div id="scope" className="mb-10 grid max-w-3xl gap-3 rounded-md border border-rule bg-surface p-4">
        <div className="flex items-start gap-2">
          <Checkbox id="scope-confirm" className="mt-0.5" checked={confirmed} aria-describedby="scope-status" onCheckedChange={(v) => setConfirmed(v === true)} />
          <Label htmlFor="scope-confirm" className="font-normal">{t('scope.confirm')}</Label>
        </div>
        <p id="scope-status" role="status" className={!confirmed && (rangesChanged || draft.active.enabled) ? 'text-meta text-warn' : 'text-meta text-muted'}>
          {confirmed
            ? (settings.scope_confirmed_at && !rangesChanged ? t('scope.confirmedAt', { when: fmtDateTime(settings.scope_confirmed_at), who: settings.scope_confirmed_by ?? '' }) : t('scope.willConfirm'))
            : rangesChanged ? t('scope.rangesChanged') : t('scope.notConfirmed')}
        </p>
        <p className="text-meta text-muted">{t('scope.asIs')}</p>
        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" variant="primary" disabled={!dirty || badRanges > 0} busy={save.isPending} busyLabel={t('common:busy.saving')}>{t('network.save')}</Button>
          {badRanges > 0 ? <span role="status" className="text-meta text-danger">{t('network.fixFirst', { count: badRanges })}</span> : dirty ? <span className="text-meta text-muted">{t('network.unsaved')}</span> : null}
        </div>
      </div>
    </form>
  )
}
