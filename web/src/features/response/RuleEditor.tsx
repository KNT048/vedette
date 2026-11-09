import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { ArrowDown, ArrowUp, FlaskConical, Plus, Trash2 } from 'lucide-react'
import { Panel } from '@/components/common/PageHeader'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input, Select } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { useCan } from '@/lib/session'
import { errText, useCatalog, useSaveRule, useSimulate, useTriggers } from './api'
import { ActionDialog } from './CatalogEditor'
import { ChangeView, RiskChip } from './parts'
import { refsIn, type ParamType } from './logic'
import type { Catalog, CatalogAction, Condition, Op, Rule, RuleAction, RuleInput, Simulation, TriggerInfo } from './types'

const OPS: Op[] = ['eq', 'in', 'in_cidr', 'gte', 'lte', 'device_type', 'count_window', 'first_time']
const KINDS = ['firewall', 'router', 'switch', 'ap', 'nas', 'server', 'pc', 'printer', 'camera', 'nvr', 'iot', 'web', 'unknown']
export const BLANK: RuleInput = { name: '', enabled: false, live: false, trigger: 'ioc_connection', match: 'all', conditions: [], actions: [], pre_approved: false, max_per_hour: 5, schedule_min: null }
const compatible = (p: ParamType, ft: string) => ft === p || p === 'text'

/** Mirror of the server rule: pre-approved only for low-risk, reversible actions with an undo time of 24 hours or less. The server enforces it too. */
export function preApprovedReason(actions: RuleAction[], cat: CatalogAction[]): string | null {
  for (const a of actions) {
    const c = cat.find((x) => x.id === a.action_id)
    if (!c) return 'missing'
    if (c.risk !== 'low') return `risk:${c.name}`
    if (!c.reversible) return `undo:${c.name}`
    if (a.ttl_min === null || a.ttl_min > 1440) return `ttl:${c.name}`
  }
  return null
}

export function SimResult({ s }: { s: Simulation }) {
  const { t } = useTranslation('response')
  return (
    <div className="grid gap-3 rounded-md border border-dashed border-accent/50 bg-surface p-3 text-sm" role="region" aria-label={t('sim.title')}>
      <div className="flex flex-wrap items-center gap-2"><h4 className="font-semibold">{t('sim.title')}</h4><Chip tone="off">{t('sim.nothing')}</Chip><Chip tone={s.matched ? 'ok' : 'warn'}>{s.matched ? t('sim.matched') : t('sim.notMatched')}</Chip></div>
      {s.event ? <p className="text-[13px]"><span className="text-muted">{t('sim.event')}</span> {s.event.summary}</p> : null}
      {s.conditions.length ? <ul className="text-[13px]">{s.conditions.map((c) => <li key={c.text}>{c.ok ? '✓' : '✗'} {c.text}</li>)}</ul> : null}
      <ol className="grid gap-2">
        {s.steps.map((st, i) => (
          <li key={i} className="grid gap-1.5 rounded-md border border-rule bg-paper p-3">
            <p className="flex flex-wrap items-center gap-2 font-medium">{i + 1}. {st.action} <RiskChip risk={st.risk} /></p>
            {st.error ? <p role="alert" className="text-[13px] text-danger">{t('sim.refused')} {st.error}</p> : st.change ? <ChangeView change={st.change} /> : null}
          </li>
        ))}
      </ol>
      <ul className="ml-5 list-disc text-[13px] text-muted">{s.notes.map((n) => <li key={n}>{n}</li>)}</ul>
      <p className="text-[13px]">{t('sim.approvals', { count: s.approvals })}</p>
    </div>
  )
}

function defaultParams(c: CatalogAction, trig: TriggerInfo | undefined): Record<string, string> {
  const out: Record<string, string> = {}
  for (const p of c.params) { const f = trig?.fields.find((x) => x.type === p); out[p] = f ? `{{trigger.${f.key}}}` : '' }
  return out
}

function ActionRow({ a, i, n, cat, trig, onChange, onMove, onRemove }: { a: RuleAction; i: number; n: number; cat: Catalog; trig: TriggerInfo | undefined; onChange: (a: RuleAction) => void; onMove: (d: -1 | 1) => void; onRemove: () => void }) {
  const { t } = useTranslation('response')
  const c = cat.items.find((x) => x.id === a.action_id)
  const readOnly = (x: CatalogAction) => !!x.connection_id && !!cat.connections.find((k) => k.id === x.connection_id)?.read_only
  return (
    <li className="grid gap-3 rounded-md border border-rule bg-paper p-3">
      <div className="flex flex-wrap items-end gap-2">
        <Field htmlFor={`ra-${i}`} label={t('editor.actionN', { n: i + 1 })} className="min-w-64 flex-1">
          <Select id={`ra-${i}`} value={a.action_id} onChange={(e) => { const x = cat.items.find((k) => k.id === e.target.value)!; onChange({ action_id: x.id, params: defaultParams(x, trig), ttl_min: x.reversible ? 1440 : null }) }}>
            {cat.items.map((x) => <option key={x.id} value={x.id} disabled={readOnly(x)}>{x.name}{readOnly(x) ? ` (${t('catalog.readOnly')})` : x.enabled ? '' : ` (${t('rules.disabled')})`}</option>)}
          </Select>
        </Field>
        <Button size="icon" variant="ghost" aria-label={t('editor.up')} disabled={i === 0} onClick={() => onMove(-1)}><ArrowUp className="size-4" aria-hidden /></Button>
        <Button size="icon" variant="ghost" aria-label={t('editor.down')} disabled={i === n - 1} onClick={() => onMove(1)}><ArrowDown className="size-4" aria-hidden /></Button>
        <Button size="icon" variant="ghost" aria-label={t('editor.removeAction')} disabled={n === 1} onClick={onRemove}><Trash2 className="size-4" aria-hidden /></Button>
      </div>
      {c ? (
        <>
          <p className="flex flex-wrap items-center gap-2 text-[13px] text-muted"><RiskChip risk={c.risk} /> {c.description}</p>
          {!c.available ? <p className="text-[13px] text-warn">{c.unavailable_reason}</p> : null}
          <div className="grid gap-3 sm:grid-cols-2">
            {c.params.map((p) => (
              <Field key={p} htmlFor={`rp-${i}-${p}`} label={t('editor.param', { p: t(`editor.types.${p}`) })} hint={t('editor.paramHint')}>
                <div className="grid gap-1.5">
                  <Input id={`rp-${i}-${p}`} spellCheck={false} value={a.params[p] ?? ''} onChange={(e) => onChange({ ...a, params: { ...a.params, [p]: e.target.value } })} placeholder={`{{trigger.${trig?.fields.find((f) => compatible(p, f.type))?.key ?? 'field'}}}`} />
                  <Select aria-label={t('editor.useField', { p })} value="" onChange={(e) => e.target.value && onChange({ ...a, params: { ...a.params, [p]: `{{trigger.${e.target.value}}}` } })}>
                    <option value="">{t('editor.insertField')}</option>
                    {(trig?.fields ?? []).filter((f) => compatible(p, f.type)).map((f) => <option key={f.key} value={f.key}>{f.label} ({f.key})</option>)}
                  </Select>
                </div>
              </Field>
            ))}
            <Field htmlFor={`rt-${i}`} label={t('editor.undoAfter')} hint={c.reversible ? t('editor.undoHint') : t('editor.noUndoHint')}>
              <Input id={`rt-${i}`} type="number" min={5} max={43200} disabled={!c.reversible} value={a.ttl_min ?? ''} placeholder={t('editor.never')} onChange={(e) => onChange({ ...a, ttl_min: e.target.value === '' ? null : Number(e.target.value) })} />
            </Field>
          </div>
          {c.verify.cli || c.verify.path ? <p className="text-[12px] text-muted">{t('editor.verifies')}</p> : null}
        </>
      ) : null}
    </li>
  )
}

export function RuleDialog({ rule, onClose }: { rule: Rule | null; onClose: () => void }) {
  const { t } = useTranslation('response')
  const admin = useCan('admin')
  const trigQ = useTriggers()
  const catQ = useCatalog()
  const save = useSaveRule()
  const sim = useSimulate()
  const [r, setR] = useState<RuleInput>(rule ? { name: rule.name, enabled: rule.enabled, live: rule.live, trigger: rule.trigger, match: rule.match, conditions: rule.conditions, actions: rule.actions, pre_approved: rule.pre_approved, max_per_hour: rule.max_per_hour, schedule_min: rule.schedule_min } : BLANK)
  const [error, setError] = useState<string | undefined>()
  const [result, setResult] = useState<Simulation | null>(null)
  const [custom, setCustom] = useState(false)
  const triggers = trigQ.data?.items ?? [], cat = catQ.data
  const seeded = useRef(false)
  // A new rule starts with one sensible action: the first enabled one that can run.
  useEffect(() => {
    if (rule || seeded.current || !cat || !trigQ.data) return
    seeded.current = true
    const c = cat.items.find((x) => x.enabled && x.available) ?? cat.items[0]
    const tr = trigQ.data.items.find((x) => x.id === BLANK.trigger)
    if (c) setR((p) => ({ ...p, actions: [{ action_id: c.id, params: defaultParams(c, tr), ttl_min: c.reversible ? 1440 : null }] }))
  }, [rule, cat, trigQ.data])
  const trig = triggers.find((x) => x.id === r.trigger)
  const set = (p: Partial<RuleInput>) => { setR({ ...r, ...p }); setError(undefined); setResult(null) }
  if (!cat || !trigQ.data) return <Dialog open onOpenChange={(v) => { if (!v) onClose() }}><DialogContent title={t('rules.addTitle')}><p className="text-sm text-muted">{t('common:loading')}</p></DialogContent></Dialog>
  const addAction = (c: CatalogAction) => set({ actions: [...r.actions, { action_id: c.id, params: defaultParams(c, trig), ttl_min: c.reversible ? 1440 : null }] })
  const first = cat.items.find((c) => c.enabled && c.available) ?? cat.items[0]!
  const actions = r.actions.length ? r.actions : []
  const input = (): RuleInput => ({ ...r, schedule_min: r.trigger === 'schedule' ? r.schedule_min ?? 10080 : null })
  const why = r.pre_approved ? preApprovedReason(r.actions, cat.items) : null
  const eligible = preApprovedReason(r.actions, cat.items) === null && r.actions.length > 0
  const changeTrigger = (id: RuleInput['trigger']) => {
    const nt = triggers.find((x) => x.id === id)
    const keep = (a: RuleAction) => ({ ...a, params: Object.fromEntries(Object.entries(a.params).map(([k, v]) => [k, refsIn(v).every((x) => nt?.fields.some((f) => f.key === x)) ? v : ''])) })
    set({ trigger: id, conditions: [], actions: r.actions.map(keep), schedule_min: id === 'schedule' ? 10080 : null })
  }
  const cond = (i: number, p: Partial<Condition>) => set({ conditions: r.conditions.map((c, j) => (j === i ? { ...c, ...p } : c)) })
  return (
    <>
      <Dialog open onOpenChange={(v) => { if (!v) onClose() }}>
        <DialogContent title={rule ? t('rules.editTitle') : t('rules.addTitle')} description={t('editor.hint')} wide>
          <form className="grid gap-5" onSubmit={(e) => { e.preventDefault()
            if (!r.actions.length) { setError(t('editor.needAction')); return }
            save.mutate({ id: rule?.id, rule: input() }, { onSuccess: () => { toast.success(rule ? t('common:saved') : t('editor.savedDry')); onClose() }, onError: (er) => setError(errText(er)) }) }}>
            <Field htmlFor="rule-name" label={t('rules.name')}><Input id="rule-name" value={r.name} maxLength={80} onChange={(e) => set({ name: e.target.value })} /></Field>

            <section className="grid gap-3" aria-label={t('editor.when')}>
              <h3 className="text-sm font-semibold">{t('editor.when')}</h3>
              <Field htmlFor="rule-trigger" label={t('rules.trigger')} hint={trig?.description}>
                <Select id="rule-trigger" value={r.trigger} onChange={(e) => changeTrigger(e.target.value as RuleInput['trigger'])}>{triggers.map((x) => <option key={x.id} value={x.id}>{x.name}</option>)}</Select>
              </Field>
              {r.trigger === 'schedule' ? <Field htmlFor="rule-sched" label={t('editor.scheduleMin')} hint={t('editor.scheduleHint')}><Input id="rule-sched" type="number" min={15} max={10080} value={r.schedule_min ?? 10080} onChange={(e) => set({ schedule_min: Number(e.target.value) })} /></Field> : null}
              <details className="text-[13px]"><summary className="cursor-pointer text-accent">{t('editor.fields')}</summary>
                <ul className="mt-2 grid gap-1">{trig?.fields.map((f) => <li key={f.key}><code className="rounded bg-sunken px-1">{`{{trigger.${f.key}}}`}</code> {f.label}, <span className="text-muted">{t('editor.fieldType', { type: f.type, example: f.example })}</span></li>)}</ul>
              </details>
            </section>

            <section className="grid gap-3" aria-label={t('editor.if')}>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h3 className="text-sm font-semibold">{t('editor.if')}</h3>
                <div className="flex items-center gap-2 text-sm"><label htmlFor="rule-match">{t('editor.match')}</label>
                  <Select id="rule-match" className="w-auto" value={r.match} onChange={(e) => set({ match: e.target.value as 'all' | 'any' })}><option value="all">{t('editor.all')}</option><option value="any">{t('editor.any')}</option></Select></div>
              </div>
              {!r.conditions.length ? <p className="text-[13px] text-muted">{t('editor.noConditions')}</p> : null}
              {r.conditions.map((c, i) => (
                <div key={i} className="grid gap-2 rounded-md border border-rule p-2 sm:grid-cols-[1fr_1fr_1.4fr_auto]">
                  {c.op === 'device_type' ? <div className="self-center text-sm text-muted">{t('editor.deviceType')}</div> : (
                    <Select aria-label={t('editor.field')} value={c.field} onChange={(e) => cond(i, { field: e.target.value })}><option value="">{t('editor.pickField')}</option>{trig?.fields.map((f) => <option key={f.key} value={f.key}>{f.label}</option>)}</Select>
                  )}
                  <Select aria-label={t('editor.test')} value={c.op} onChange={(e) => { const op = e.target.value as Op; cond(i, { op, n: op === 'count_window' ? 3 : op === 'first_time' ? 24 : null, window_min: op === 'count_window' ? 10 : null, field: op === 'device_type' ? '' : c.field }) }}>{OPS.map((o) => <option key={o} value={o}>{t(`editor.ops.${o}`)}</option>)}</Select>
                  {c.op === 'count_window' ? (
                    <div className="flex items-center gap-1.5 text-sm"><Input aria-label={t('editor.atLeast')} type="number" min={1} value={c.n ?? 3} onChange={(e) => cond(i, { n: Number(e.target.value) })} /><span className="whitespace-nowrap">{t('editor.within')}</span><Input aria-label={t('editor.minutes')} type="number" min={1} value={c.window_min ?? 10} onChange={(e) => cond(i, { window_min: Number(e.target.value) })} /><span>min</span></div>
                  ) : c.op === 'first_time' ? (
                    <div className="flex items-center gap-1.5 text-sm"><span className="whitespace-nowrap">{t('editor.inLast')}</span><Input aria-label={t('editor.hours')} type="number" min={1} value={c.n ?? 24} onChange={(e) => cond(i, { n: Number(e.target.value) })} /><span>h</span></div>
                  ) : (
                    <Input aria-label={t('editor.value')} value={c.value} spellCheck={false} placeholder={c.op === 'device_type' ? KINDS.slice(7, 11).join(',') : c.op === 'in_cidr' ? '192.168.10.0/24' : c.op === 'in' ? 'a,b,c' : ''} onChange={(e) => cond(i, { value: e.target.value })} />
                  )}
                  <Button size="icon" variant="ghost" aria-label={t('editor.removeCondition')} onClick={() => set({ conditions: r.conditions.filter((_, j) => j !== i) })}><Trash2 className="size-4" aria-hidden /></Button>
                </div>
              ))}
              <div><Button size="sm" onClick={() => set({ conditions: [...r.conditions, { field: trig?.fields[0]?.key ?? '', op: 'eq', value: '', n: null, window_min: null }] })}><Plus className="size-4" aria-hidden />{t('editor.addCondition')}</Button></div>
            </section>

            <section className="grid gap-3" aria-label={t('editor.then')}>
              <h3 className="text-sm font-semibold">{t('editor.then')}</h3>
              <p role="note" className="rounded-md border border-warn/60 bg-warn-soft/60 px-3 py-2 text-[13px]">{t('editor.attacker')}</p>
              <ol className="grid gap-3">
                {actions.map((a, i) => <ActionRow key={`${a.action_id}-${i}`} a={a} i={i} n={actions.length} cat={cat} trig={trig}
                  onChange={(x) => set({ actions: r.actions.map((y, j) => (j === i ? x : y)) })} onMove={(d) => { const l = [...r.actions]; const [m] = l.splice(i, 1); l.splice(i + d, 0, m!); set({ actions: l }) }} onRemove={() => set({ actions: r.actions.filter((_, j) => j !== i) })} />)}
              </ol>
              <div className="flex flex-wrap gap-2">
                <Button size="sm" onClick={() => addAction(first)}><Plus className="size-4" aria-hidden />{t('editor.addAction')}</Button>
                {admin ? <Button size="sm" onClick={() => setCustom(true)}><Plus className="size-4" aria-hidden />{t('editor.newCustom')}</Button> : null}
              </div>
              <p className="text-[13px] text-muted">{t('editor.approvalDefault')}</p>
            </section>

            <section className="grid gap-3" aria-label={t('editor.limits')}>
              <h3 className="text-sm font-semibold">{t('editor.limits')}</h3>
              <Field htmlFor="rule-hour" label={t('rules.perHour')} hint={t('rules.perHourHint')} className="max-w-xs"><Input id="rule-hour" type="number" min={1} max={100} value={r.max_per_hour} onChange={(e) => set({ max_per_hour: Number(e.target.value) })} /></Field>
              <Panel className="grid gap-2 p-3">
                <div className="flex items-center gap-2.5">
                  <Switch id="rule-pre" checked={r.pre_approved} disabled={!admin || (!r.pre_approved && !eligible)} onCheckedChange={(v) => set({ pre_approved: v })} />
                  <label htmlFor="rule-pre" className="grid text-sm"><span className="font-medium">{t('editor.pre')}</span><span className="text-[13px] text-muted">{t('editor.preHint')}</span></label>
                </div>
                {!admin ? <p className="text-[13px] text-muted">{t('editor.preAdmin')}</p> : !eligible && !r.pre_approved ? <p className="text-[13px] text-muted">{t('editor.preNotEligible')}</p> : null}
                {r.pre_approved ? <p role="alert" className="rounded-md border border-danger/50 bg-danger-soft px-3 py-2 text-sm font-medium">{t('editor.preWarning')}</p> : null}
                {why ? <p role="alert" className="text-[13px] text-danger">{t('editor.preBad')}</p> : null}
              </Panel>
            </section>

            {result ? <SimResult s={result} /> : null}
            {error ? <p role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm">{error}</p> : null}
            <DialogFooter>
              <Button type="button" disabled={sim.isPending || !r.actions.length} onClick={() => sim.mutate(input(), { onSuccess: setResult, onError: (er) => setError(errText(er)) })}><FlaskConical className="size-4" aria-hidden />{t('editor.simulate')}</Button>
              <Button type="button" onClick={onClose}>{t('common:cancel')}</Button>
              <Button type="submit" variant="primary" disabled={save.isPending}>{t('common:save')}</Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
      {custom ? <ActionDialog action={null} cat={cat} onClose={() => setCustom(false)} onSaved={(a) => addAction(a)} /> : null}
    </>
  )
}
