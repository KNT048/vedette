import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Pencil, Plus, X } from 'lucide-react'
import { Section, Panel } from '@/components/common/PageHeader'
import { ModuleOff, RequireModule } from '@/components/common/States'
import { Button } from '@/components/ui/button'
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

function ListEditor({ id, label, listLabel, hint, items, onChange, validate, placeholder, addLabel, removeLabel, emptyText }: {
  id: string; label: string; listLabel: string; hint: string; items: string[]; onChange: (v: string[]) => void; validate: (v: string) => string | null
  placeholder: string; addLabel: string; removeLabel: (v: string) => string; emptyText: string
}) {
  const [draft, setDraft] = useState('')
  const [error, setError] = useState<string | undefined>()
  function add() {
    const v = draft.trim()
    if (!v) return
    const err = validate(v)
    if (err) { setError(err); return }
    if (items.includes(v)) { setError(undefined); setDraft(''); return }
    onChange([...items, v]); setDraft(''); setError(undefined)
  }
  return (
    <div className="grid gap-2">
      <Field label={label} htmlFor={id} hint={hint} error={error}>
        <div className="flex max-w-md gap-2">
          <Input id={id} value={draft} placeholder={placeholder} aria-invalid={error ? true : undefined} aria-describedby={error ? `${id}-error` : `${id}-hint`}
            onChange={(e) => setDraft(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); add() } }} />
          <Button onClick={add}><Plus />{addLabel}</Button>
        </div>
      </Field>
      {items.length ? (
        <ul className="flex flex-wrap gap-2" aria-label={listLabel}>
          {items.map((it) => (
            <li key={it} className="inline-flex h-8 items-center gap-1 rounded-md border border-rule bg-surface pl-3 pr-1 text-sm">
              {it}
              <button type="button" className="grid size-6 place-items-center rounded text-muted hover:bg-sunken hover:text-ink" aria-label={removeLabel(it)} onClick={() => onChange(items.filter((x) => x !== it))}><X className="size-3.5" /></button>
            </li>
          ))}
        </ul>
      ) : <p className="text-[13px] text-muted">{emptyText}</p>}
    </div>
  )
}

/**
 * Dải mạng quét: gõ "192.168.18.0" thì tự thành 192.168.18.0/24 và nói rõ đã đổi; mỗi dải đã lưu đều sửa/xoá được;
 * dải lưu sai (từ phiên bản cũ hoặc nhập tay) hiện lỗi ngay trên dòng của nó, không chặn thêm/sửa/xoá dải khác.
 */
function RangeEditor({ items, onChange }: { items: string[]; onChange: (v: string[]) => void }) {
  const { t } = useTranslation('inventory')
  const [draft, setDraft] = useState('')
  const [error, setError] = useState<string | undefined>()
  const [note, setNote] = useState<string | undefined>()
  const problemText = (v: string, others: string[]) => {
    const p = rangeProblem(v, others)
    if (!p) return null
    const other = others.find((o) => o !== v && rangeProblem(v, [o]) === 'overlap')
    return t(`network.problem.${p}`, { value: v, net: CIDR_RE_UI.test(v) ? cidrRange(v).network : '', other })
  }
  function add() {
    const raw = draft.trim()
    if (!raw) { setError(t('network.problem.empty')); setNote(undefined); return }
    const n = normalizeRange(raw)
    if (items.includes(n.value)) { setError(t('network.duplicate', { value: n.value })); setNote(undefined); return }
    const err = problemText(n.value, items)
    if (err) { setError(err); setNote(undefined); return }
    onChange([...items, n.value]); setDraft(''); setError(undefined)
    setNote(n.note ? t(`network.note.${n.note}`, { from: raw, to: n.value }) : undefined)
  }
  return (
    <div className="grid gap-2">
      <Field label={t('network.rangeLabel')} htmlFor="range-input" hint={t('network.rangeHint')} error={error}>
        <div className="flex max-w-md gap-2">
          <Input id="range-input" value={draft} placeholder="192.168.10.0/24" aria-invalid={error ? true : undefined} aria-describedby={error ? 'range-input-error' : 'range-input-hint'}
            onChange={(e) => setDraft(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); add() } }} />
          <Button onClick={add}><Plus />{t('network.addRange')}</Button>
        </div>
      </Field>
      {note ? <p role="status" className="max-w-2xl text-[13px] text-ok">{note}</p> : null}
      {items.length ? (
        <ul className="grid max-w-2xl gap-2" aria-label={t('network.rangeList')}>
          {items.map((it) => {
            const err = problemText(it, items)
            return (
              <li key={it} className={err ? 'grid gap-1 rounded-md border border-danger/50 bg-danger-soft px-3 py-2' : 'rounded-md border border-rule bg-surface px-3 py-1.5'}>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-sm font-medium [overflow-wrap:anywhere]">{it}</span>
                  <span className="flex gap-1">
                    <Button size="sm" variant="ghost" aria-label={t('network.editRange', { value: it })} onClick={() => { setDraft(it); setError(undefined); setNote(undefined); onChange(items.filter((x) => x !== it)); document.getElementById('range-input')?.focus() }}><Pencil />{t('network.edit')}</Button>
                    <Button size="sm" variant="ghost" aria-label={t('network.removeRange', { value: it })} onClick={() => onChange(items.filter((x) => x !== it))}><X />{t('network.remove')}</Button>
                  </span>
                </div>
                {err ? <p role="alert" className="text-[13px] text-danger">{err}</p> : null}
              </li>
            )
          })}
        </ul>
      ) : <p className="text-[13px] text-muted">{t('network.noRanges')}</p>}
    </div>
  )
}

/** Dải mạng LAN, cửa sổ quét chủ động, loại trừ, thiết bị mỏng manh chỉ thụ động (S-INV-1). Xác nhận phạm vi trước khi quét (LEGAL §3). */
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
      <Section id="ranges" title={t('network.title')} description={t('network.description')} stories={['S-INV-1']}>
        <Panel className="p-4">
          <RangeEditor items={draft.lan_ranges} onChange={(v) => { set({ lan_ranges: v }); setConfirmed(false) }} />
        </Panel>
      </Section>

      <Section id="active" title={t('active.title')} description={t('active.description')}>
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
                <Field label={t('active.to')} htmlFor="active-to"><Input id="active-to" type="time" className="w-32" value={draft.active.to} onChange={(e) => setActive({ to: e.target.value })} /></Field>
                <Field label={t('active.rate')} htmlFor="active-rate" hint={t('active.rateHint')} className="max-w-xs">
                  <Select id="active-rate" value={draft.active.rate} onChange={(e) => setActive({ rate: Number(e.target.value) })} aria-describedby="active-rate-hint">
                    {rates.map((r) => <option key={r} value={r}>{t('active.rateOption', { rate: r, name: t(`active.rateName.${r}`, { defaultValue: t('active.rateCustom') }) })}</option>)}
                  </Select>
                </Field>
              </div>
              <p className="text-[13px] text-muted">{t('active.crossMidnight')}</p>
            </fieldset>
            <ListEditor id="excl-input" label={t('active.exclusions')} listLabel={t('active.exclusionsList')} hint={t('active.exclusionsHint')} items={draft.active.exclusions} placeholder="192.168.10.10"
              addLabel={t('active.addExclusion')} removeLabel={(v) => t('active.removeExclusion', { value: v })} emptyText={t('active.noExclusions')}
              validate={(v) => (IPV4_RE_UI.test(v) || (CIDR_RE_UI.test(v) && !hasHostBits(v)) ? null : t('active.badExclusion'))}
              onChange={(v) => setActive({ exclusions: v })} />
            <p className="text-sm">{t('active.safety')}</p>
          </Panel>
        </RequireModule>
      </Section>

      <Section id="fragile" title={t('fragile.title')} description={t('fragile.description')}>
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
                      <span className="text-[13px] text-muted" aria-hidden>{t('fragile.allowRegular')}</span>
                    </span>
                  ) : null}
                </span>
              ))}
            </div>
          </fieldset>
          <p className="mt-3 text-[13px] text-muted">{t('fragile.note')}</p>
        </Panel>
      </Section>

      {error ? <p role="alert" className="mb-4 max-w-2xl rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-danger">{error}</p> : null}
      {/* Cam kết nằm ngay trên nút Lưu: chỉ phải tick lại khi tập dải mạng đổi; đổi cài đặt khác thì giữ xác nhận cũ. */}
      <div id="scope" className="mb-10 grid max-w-3xl gap-3 rounded-md border border-rule bg-surface p-4">
        <div className="flex items-start gap-2">
          <Checkbox id="scope-confirm" className="mt-0.5" checked={confirmed} aria-describedby="scope-status" onCheckedChange={(v) => setConfirmed(v === true)} />
          <Label htmlFor="scope-confirm" className="font-normal">{t('scope.confirm')}</Label>
        </div>
        <p id="scope-status" role="status" className={!confirmed && (rangesChanged || draft.active.enabled) ? 'text-[13px] text-warn' : 'text-[13px] text-muted'}>
          {confirmed
            ? (settings.scope_confirmed_at && !rangesChanged ? t('scope.confirmedAt', { when: fmtDateTime(settings.scope_confirmed_at), who: settings.scope_confirmed_by ?? '' }) : t('scope.willConfirm'))
            : rangesChanged ? t('scope.rangesChanged') : t('scope.notConfirmed')}
        </p>
        <p className="text-[13px] text-muted">{t('scope.asIs')}</p>
        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" variant="primary" disabled={!dirty || save.isPending || badRanges > 0}>{t('network.save')}</Button>
          {badRanges > 0 ? <span role="status" className="text-[13px] text-danger">{t('network.fixFirst', { count: badRanges })}</span> : dirty ? <span className="text-[13px] text-muted">{t('network.unsaved')}</span> : null}
        </div>
      </div>
    </form>
  )
}
