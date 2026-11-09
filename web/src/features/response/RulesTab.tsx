import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Copy, FlaskConical, Pencil, Play, Plus, Trash2 } from 'lucide-react'
import { Panel, Section } from '@/components/common/PageHeader'
import { ErrorState, Loading } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Select } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { fmtDateTime } from '@/lib/format'
import { useCan } from '@/lib/session'
import { errText, useCatalog, useCloneTemplate, useDeleteRule, useEvents, useRules, useRunManual, useRunRules, useSaveRule, useSimulate, useTemplates, useTriggers } from './api'
import { condText } from './logic'
import { RiskChip } from './parts'
import { RuleDialog, SimResult } from './RuleEditor'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { Rule, RuleInput, Simulation } from './types'

const toInput = (r: Rule): RuleInput => ({ name: r.name, enabled: r.enabled, live: r.live, trigger: r.trigger, match: r.match, conditions: r.conditions, actions: r.actions, pre_approved: r.pre_approved, max_per_hour: r.max_per_hour, schedule_min: r.schedule_min })
const mins = (m: number) => (m >= 1440 && m % 1440 === 0 ? `${m / 1440} d` : m >= 60 ? `${Math.round((m / 60) * 10) / 10} h` : `${m} min`)

function LiveDialog({ rule, onClose }: { rule: Rule; onClose: () => void }) {
  const { t } = useTranslation('response')
  const save = useSaveRule()
  const toLive = !rule.live
  return (
    <Dialog open onOpenChange={(v) => { if (!v) onClose() }}>
      <DialogContent title={toLive ? t('rules.liveTitle') : t('rules.dryTitle')} description={rule.name}>
        <p className="text-sm">{toLive ? t('rules.liveBody') : t('rules.dryBody')}</p>
        {toLive && rule.pre_approved ? <p role="alert" className="rounded-md border border-danger/50 bg-danger-soft px-3 py-2 text-sm font-medium">{t('editor.preWarning')}</p> : null}
        <DialogFooter>
          <Button onClick={onClose}>{t('common:cancel')}</Button>
          <Button variant={toLive ? 'danger' : 'primary'} disabled={save.isPending} onClick={() => save.mutate({ id: rule.id, rule: { ...toInput(rule), live: toLive } }, { onSuccess: () => { toast.success(toLive ? t('rules.nowLive') : t('rules.nowDry')); onClose() }, onError: (e) => toast.error(errText(e)) })}>{toLive ? t('rules.goLive') : t('rules.backToDry')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function ManualRun({ rule }: { rule: Rule }) {
  const { t } = useTranslation('response')
  const operator = useCan('operator')
  const assets = useQuery({ queryKey: ['inventory', 'devices', 'pick'], queryFn: () => api.get<{ items: { id: string; ip: string; hostname: string | null }[] }>('/inventory/devices') })
  const run = useRunManual()
  const [asset, setAsset] = useState('')
  return (
    <div className="flex flex-wrap items-end gap-2">
      <Field htmlFor={`man-${rule.id}`} label={t('rules.manualPick')} className="min-w-56">
        <Select id={`man-${rule.id}`} value={asset} onChange={(e) => setAsset(e.target.value)}><option value="">{t('rules.manualChoose')}</option>{(assets.data?.items ?? []).map((a) => <option key={a.id} value={a.id}>{a.hostname ?? a.ip} ({a.ip})</option>)}</Select>
      </Field>
      <Button disabled={!operator || !asset || !rule.enabled || run.isPending} title={!rule.enabled ? t('rules.manualOff') : undefined}
        onClick={() => run.mutate({ id: rule.id, asset_id: asset }, { onSuccess: (r) => toast.success(t('det.ran', r)), onError: (e) => toast.error(errText(e)) })}><Play className="size-4" aria-hidden />{t('rules.manualRun')}</Button>
    </div>
  )
}

function RuleCard({ rule, onEdit }: { rule: Rule; onEdit: () => void }) {
  const { t } = useTranslation('response')
  const admin = useCan('admin')
  const operator = useCan('operator')
  const save = useSaveRule()
  const del = useDeleteRule()
  const sim = useSimulate()
  const cat = useCatalog()
  const trig = useTriggers()
  const [live, setLive] = useState(false)
  const [result, setResult] = useState<Simulation | null>(null)
  const name = (id: string) => cat.data?.items.find((a) => a.id === id)?.name ?? id
  const tname = trig.data?.items.find((x) => x.id === rule.trigger)?.name ?? rule.trigger
  return (
    <Panel className="grid gap-3 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-3">
          <Switch id={`rs-${rule.id}`} checked={rule.enabled} disabled={!admin || save.isPending} aria-label={t('rules.enabledLabel', { name: rule.name })}
            onCheckedChange={(v) => save.mutate({ id: rule.id, rule: { ...toInput(rule), enabled: v } }, { onError: (e) => toast.error(errText(e)) })} />
          <h3 className="text-sm font-semibold">{rule.name}</h3>
          <Chip tone={rule.live ? 'warn' : 'off'}>{rule.live ? t('rules.live') : t('rules.dryRun')}</Chip>
          {rule.pre_approved ? <Chip tone="danger">{t('request.preApproved')}</Chip> : <Chip tone="ok">{t('rules.needsApproval')}</Chip>}
          {rule.template_id ? <Chip tone="off">{t('rules.fromTemplate')}</Chip> : null}
        </div>
        <div className="flex flex-wrap gap-1">
          <Button size="sm" variant="ghost" disabled={!operator || sim.isPending} aria-label={t('rules.simulate', { name: rule.name })}
            onClick={() => sim.mutate(toInput(rule), { onSuccess: setResult, onError: (e) => toast.error(errText(e)) })}><FlaskConical className="size-4" aria-hidden />{t('rules.simulateShort')}</Button>
          {admin ? (
            <>
              <Button size="sm" variant="ghost" onClick={() => setLive(true)} aria-label={t(rule.live ? 'rules.backToDryFor' : 'rules.goLiveFor', { name: rule.name })}>{rule.live ? t('rules.backToDry') : t('rules.goLive')}</Button>
              <Button size="sm" variant="ghost" onClick={onEdit} aria-label={t('rules.edit', { name: rule.name })}><Pencil className="size-4" aria-hidden />{t('common:edit')}</Button>
              <Button size="sm" variant="ghost" disabled={del.isPending} aria-label={t('rules.delete', { name: rule.name })} onClick={() => del.mutate(rule.id, { onSuccess: () => toast.success(t('rules.deleted')), onError: (e) => toast.error(errText(e)) })}><Trash2 className="size-4" aria-hidden />{t('common:delete')}</Button>
            </>
          ) : null}
        </div>
      </div>
      <dl className="grid gap-1.5 text-sm">
        <div className="flex gap-2"><dt className="w-12 shrink-0 text-muted">{t('rules.when')}</dt><dd>{tname}{rule.trigger === 'schedule' && rule.schedule_min ? `, ${t('rules.every', { time: mins(rule.schedule_min) })}` : ''}</dd></div>
        <div className="flex gap-2"><dt className="w-12 shrink-0 text-muted">{t('rules.if')}</dt><dd>{rule.conditions.length ? rule.conditions.map((c) => condText(c)).join(rule.match === 'all' ? '; and ' : '; or ') : t('rules.always')}</dd></div>
        <div className="flex gap-2"><dt className="w-12 shrink-0 text-muted">{t('rules.then')}</dt>
          <dd><ol className="grid gap-0.5">{rule.actions.map((a, i) => <li key={i}>{i + 1}. {name(a.action_id)} <span className="text-muted">({a.ttl_min ? t('rules.undoIn', { time: mins(a.ttl_min) }) : t('rules.noUndoTime')})</span></li>)}</ol></dd></div>
      </dl>
      <p className="text-[12px] text-muted">{t('rules.limit', { n: rule.max_per_hour })} {rule.last_fired ? t('rules.lastFired', { time: fmtDateTime(rule.last_fired) }) : t('rules.neverFired')}</p>
      {!rule.live && rule.enabled ? <p className="text-[13px] text-muted">{t('rules.dryNote')}</p> : null}
      {rule.trigger === 'manual' ? <ManualRun rule={rule} /> : null}
      {result ? <SimResult s={result} /> : null}
      {live ? <LiveDialog rule={rule} onClose={() => setLive(false)} /> : null}
    </Panel>
  )
}

function Templates() {
  const { t } = useTranslation('response')
  const admin = useCan('admin')
  const q = useTemplates()
  const clone = useCloneTemplate()
  return (
    <Section id="templates" title={t('templates.title')} description={t('templates.description')} stories={['S-RESP-3']}>
      {q.isPending ? <Loading /> : q.error ? <ErrorState error={q.error} onRetry={() => void q.refetch()} /> : (
        <ul className="grid gap-3 md:grid-cols-2">
          {q.data.items.map((tp) => (
            <li key={tp.id}>
              <Panel className="grid h-full content-start gap-2 p-4">
                <div className="flex flex-wrap items-start justify-between gap-2"><h3 className="text-sm font-semibold">{tp.name}</h3><div className="flex gap-2"><RiskChip risk={tp.risk} />{tp.approvals > 1 ? <Chip tone="warn">{t('request.twoApprovers')}</Chip> : null}</div></div>
                <p className="text-[13px] text-muted">{tp.description}</p>
                <div><Button size="sm" disabled={!admin || clone.isPending} title={!admin ? t('common:needRole', { role: t('common:role.admin') }) : undefined} aria-label={t('templates.cloneFor', { name: tp.name })}
                  onClick={() => clone.mutate(tp.id, { onSuccess: () => toast.success(t('templates.cloned')), onError: (e) => toast.error(errText(e)) })}><Copy className="size-4" aria-hidden />{t('templates.clone')}</Button></div>
              </Panel>
            </li>
          ))}
        </ul>
      )}
    </Section>
  )
}

function Events() {
  const { t } = useTranslation('response')
  const operator = useCan('operator')
  const q = useEvents()
  const run = useRunRules()
  return (
    <Section title={t('det.title')} description={t('det.description')} stories={['S-RESP-3']}
      actions={import.meta.env.VITE_API_MOCK !== 'off' ? <Button disabled={!operator || run.isPending} title={!operator ? t('common:needRole', { role: t('common:role.operator') }) : undefined}
        onClick={() => run.mutate(undefined, { onSuccess: (r) => toast.success(t('det.ran', r)), onError: (e) => toast.error(errText(e)) })}>{t('det.run')}</Button> : undefined}>
      {q.isPending ? <Loading /> : q.error ? <ErrorState error={q.error} onRetry={() => void q.refetch()} /> : q.data.items.length ? (
        <>
          <Panel>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <caption className="sr-only">{t('det.title')}</caption>
                <thead><tr className="border-b border-rule text-left text-[12px] text-muted"><th scope="col" className="px-3 py-2 font-medium">{t('det.time')}</th><th scope="col" className="px-3 py-2 font-medium">{t('det.what')}</th><th scope="col" className="px-3 py-2 font-medium">{t('det.handled')}</th></tr></thead>
                <tbody className="divide-y divide-rule">
                  {q.data.items.map((d) => (
                    <tr key={d.id} className="align-top">
                      <td className="whitespace-nowrap px-3 py-2">{fmtDateTime(d.ts)}</td>
                      <td className="px-3 py-2">{d.summary} <span className="text-muted">({t(`rules.triggerShort.${d.trigger}`)})</span></td>
                      <td className="px-3 py-2">{d.handled_by.length ? d.handled_by.join(', ') : <span className="text-muted">{t('det.notYet')}</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
          {import.meta.env.VITE_API_MOCK !== 'off' ? <p className="mt-2 text-[13px] text-muted">{t('det.previewNote')}</p> : null}
        </>
      ) : <p className="text-sm text-muted">{t('det.empty')}</p>}
    </Section>
  )
}

export function RulesTab() {
  const { t } = useTranslation('response')
  const admin = useCan('admin')
  const rules = useRules()
  const [edit, setEdit] = useState<Rule | 'new' | null>(null)
  if (rules.isPending) return <Loading />
  if (rules.error) return <ErrorState error={rules.error} onRetry={() => void rules.refetch()} />
  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-2">
      <Section title={t('rules.title')} description={t('rules.description')} stories={['S-RESP-3']}
        actions={admin ? <Button variant="primary" onClick={() => setEdit('new')}><Plus className="size-4" aria-hidden />{t('rules.add')}</Button> : undefined}>
        <div className="grid gap-4">
          <p className="rounded-md border border-rule bg-surface px-4 py-3 text-sm">{t('rules.safetyNote')} {admin ? <Link className="text-accent underline underline-offset-4" to="/settings/response">{t('blocked.toSettings')}</Link> : null}</p>
          {rules.data.items.length ? rules.data.items.map((r) => <RuleCard key={r.id} rule={r} onEdit={() => setEdit(r)} />) : <p className="text-sm text-muted">{t('rules.empty')}</p>}
        </div>
      </Section>
      <Templates />
      <Events />
      {edit ? <RuleDialog key={edit === 'new' ? 'new' : edit.id} rule={edit === 'new' ? null : edit} onClose={() => setEdit(null)} /> : null}
    </div>
  )
}
