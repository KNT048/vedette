import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { AiBlock } from '@/components/common/AiBlock'
import { Panel, Section } from '@/components/common/PageHeader'
import { ErrorState, Loading } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Field, Input, Select } from '@/components/ui/input'
import { fmtDateTime, fmtPercent } from '@/lib/format'
import { useCan } from '@/lib/session'
import { errText, useAi, useCatalog, useEvents, useMetrics, usePropose, useResumeAi } from './api'
import type { Stat } from './types'

function Tile({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return <div className="rounded-md border border-rule bg-paper px-3 py-2"><dt className="text-[12px] text-muted">{label}</dt><dd className="text-xl font-semibold tabular-nums">{value}</dd>{hint ? <dd className="text-[12px] text-muted">{hint}</dd> : null}</div>
}
function StatBlock({ title, s }: { title: string; s: Stat }) {
  const { t } = useTranslation('response')
  return (
    <Panel className="grid gap-3 p-4">
      <h3 className="text-sm font-semibold">{title}</h3>
      <dl className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <Tile label={t('metrics.sent')} value={String(s.sent)} />
        <Tile label={t('metrics.acceptance')} value={s.acceptance_rate === null ? '-' : fmtPercent(s.acceptance_rate * 100, 0)} hint={t('metrics.acceptanceHint', { approved: s.approved, rejected: s.rejected })} />
        <Tile label={t('metrics.median')} value={s.median_approve_min === null ? '-' : `${s.median_approve_min} min`} />
        <Tile label={t('metrics.expired')} value={String(s.expired)} hint={t('metrics.pendingNow', { count: s.pending })} />
      </dl>
    </Panel>
  )
}

/** Preview build: stands in for the AI agent sending a request, so every server-side gate can be tried. */
function TryProposal() {
  const { t } = useTranslation('response')
  const cat = useCatalog()
  const ev = useEvents()
  const propose = usePropose()
  const ioc = ev.data?.items.find((e) => e.trigger === 'ioc_connection' && e.fields.dest_kind === 'ip' && e.fields.dest_ip !== '1.1.1.1' && !e.handled_by.length) ?? ev.data?.items.find((e) => e.trigger === 'ioc_connection' && e.fields.dest_kind === 'ip')
  const [f, setF] = useState({ action: 'blocklist_add', value: '', confidence: '0.9', kind: 'ioc_hit', evidence: '', why: 'The device keeps talking to an address that two feeds list.' })
  const [out, setOut] = useState<string | null>(null)
  const actions = (cat.data?.items ?? []).filter((a) => a.ai_may_propose && a.enabled)
  const chosen = actions.find((a) => a.id === f.action)
  const type = chosen?.params[0] ?? 'ip'
  const preset = (p: 'good' | 'low' | 'fake') => { setOut(null); setF({ ...f, action: 'blocklist_add', value: ioc?.fields.dest_ip ?? '203.0.113.5', confidence: p === 'low' ? '0.6' : '0.9', kind: 'ioc_hit', evidence: p === 'fake' ? 'hit-does-not-exist' : ioc?.id ?? '' }) }
  return (
    <Section title={t('try.title')} description={t('try.description')} stories={['S-RESP-2']}>
      <Panel className="grid gap-4 p-4">
        <div className="flex flex-wrap gap-2"><Button size="sm" onClick={() => preset('good')}>{t('try.good')}</Button><Button size="sm" onClick={() => preset('low')}>{t('try.low')}</Button><Button size="sm" onClick={() => preset('fake')}>{t('try.fake')}</Button></div>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field htmlFor="try-action" label={t('try.action')}><Select id="try-action" value={f.action} onChange={(e) => setF({ ...f, action: e.target.value, value: '' })}>{actions.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}</Select></Field>
          <Field htmlFor="try-value" label={t('try.value', { type: t(`editor.types.${type}`) })}><Input id="try-value" value={f.value} spellCheck={false} onChange={(e) => setF({ ...f, value: e.target.value })} /></Field>
          <Field htmlFor="try-conf" label={t('try.confidence')}><Input id="try-conf" type="number" step={0.05} min={0} max={1} value={f.confidence} onChange={(e) => setF({ ...f, confidence: e.target.value })} /></Field>
          <div className="grid grid-cols-[8rem_1fr] gap-2">
            <Field htmlFor="try-kind" label={t('try.evidenceKind')}><Select id="try-kind" value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })}><option value="ioc_hit">ioc_hit</option><option value="finding">finding</option><option value="config_read">config_read</option></Select></Field>
            <Field htmlFor="try-ev" label={t('try.evidenceId')}><Input id="try-ev" value={f.evidence} spellCheck={false} onChange={(e) => setF({ ...f, evidence: e.target.value })} /></Field>
          </div>
        </div>
        <Field htmlFor="try-why" label={t('try.why')}><Input id="try-why" value={f.why} maxLength={400} onChange={(e) => setF({ ...f, why: e.target.value })} /></Field>
        {out ? <p role="status" className="rounded-md border border-rule bg-surface px-3 py-2 text-sm">{out}</p> : null}
        <div><Button variant="primary" disabled={propose.isPending || !chosen}
          onClick={() => propose.mutate({ trigger: 'ioc_connection', action_id: f.action, params: { [type]: f.value }, confidence: Number(f.confidence), evidence: [{ kind: f.kind, id: f.evidence }], why: f.why },
            { onSuccess: (r) => { setOut(r.note); toast.success(t(`try.outcome.${r.outcome}`)) }, onError: (e) => setOut(errText(e)) })}>{t('try.send')}</Button></div>
      </Panel>
    </Section>
  )
}

export function MetricsTab() {
  const { t } = useTranslation('response')
  const admin = useCan('admin')
  const m = useMetrics()
  const ai = useAi()
  const resume = useResumeAi()
  if (m.isPending || ai.isPending) return <Loading />
  if (m.error || ai.error) return <ErrorState error={m.error ?? ai.error} onRetry={() => { void m.refetch(); void ai.refetch() }} />
  const s = ai.data
  return (
    <div className="grid gap-2">
      <Section title={t('metrics.title')} description={t('metrics.description')} stories={['S-RESP-2', 'S-AI-8']}>
        <div className="grid gap-4 lg:grid-cols-2"><StatBlock title={t('metrics.aiTitle')} s={m.data.ai} /><StatBlock title={t('metrics.rulesTitle')} s={m.data.rules} /></div>
      </Section>
      <Section title={t('ai.title')} description={t('ai.description', { conf: s.min_confidence, days: s.repeat_days })} stories={['S-RESP-2']}>
        <div className="grid gap-4">
          {s.quality.paused || s.gates.paused_at ? (
            <div role="alert" className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-danger/50 bg-danger-soft px-4 py-3 text-sm">
              <span><span className="font-medium">{t('ai.paused')}</span> {s.gates.paused_reason}. {t('ai.pausedBody')}</span>
              {admin ? <Button disabled={resume.isPending} onClick={() => resume.mutate(undefined, { onSuccess: () => toast.success(t('ai.resumed')), onError: (e) => toast.error(errText(e)) })}>{t('ai.resume')}</Button> : null}
            </div>
          ) : null}
          <dl className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            <Tile label={t('ai.budgetHour')} value={`${s.usage.hour} / ${s.gates.budget_hour}`} />
            <Tile label={t('ai.budgetDay')} value={`${s.usage.day} / ${s.gates.budget_day}`} />
            <Tile label={t('ai.quality')} value={`${s.quality.rejected} / ${s.quality.decided}`} hint={t('ai.qualityHint')} />
            <Tile label={t('ai.triggers')} value={String(s.gates.triggers.length)} hint={s.gates.triggers.join(', ') || t('ai.noTriggers')} />
          </dl>
          <div className="grid gap-4 lg:grid-cols-2">
            <Panel className="grid content-start gap-2 p-4">
              <h3 className="text-sm font-semibold">{t('ai.notes')}</h3>
              {s.notes.length ? <ul className="grid gap-3">{s.notes.map((n) => (
                <li key={n.id}><AiBlock><p className="flex flex-wrap items-center gap-2 font-medium">{n.title} <Chip tone="off">{t(`ai.kind.${n.kind}`)}</Chip></p><p className="text-[13px]">{n.why}</p><p className="text-[12px] text-muted">{t('request.confidence', { n: n.confidence.toFixed(2) })} · {fmtDateTime(n.ts)}</p></AiBlock></li>
              ))}</ul> : <p className="text-sm text-muted">{t('ai.noNotes')}</p>}
            </Panel>
            <Panel className="grid content-start gap-2 p-4">
              <h3 className="text-sm font-semibold">{t('ai.hints')}</h3>
              {s.hints.length ? <ul className="grid gap-2 text-sm">{s.hints.map((h) => <li key={h.id}><Chip tone="accent">{t(`ai.hintKind.${h.kind}`)}</Chip> {h.text} <span className="text-[12px] text-muted">{fmtDateTime(h.ts)}</span></li>)}</ul> : <p className="text-sm text-muted">{t('ai.noHints')}</p>}
            </Panel>
          </div>
        </div>
      </Section>
      <Section title={t('metrics.rejectedTitle')} description={t('metrics.rejectedDescription')} stories={['S-RESP-2']}>
        {m.data.rejected.length ? (
          <Panel><ul className="divide-y divide-rule">{m.data.rejected.map((r) => (
            <li key={r.id} className="grid gap-0.5 px-3 py-2 text-sm"><span className="font-medium">{r.title} <Chip tone="off">{r.source === 'ai' ? t('action.fromAi') : r.source === 'person' ? t('action.fromPerson') : t('action.fromRule')}</Chip></span><span className="text-muted">{r.reason} · {fmtDateTime(r.at)}</span></li>
          ))}</ul></Panel>
        ) : <p className="text-sm text-muted">{t('metrics.noneRejected')}</p>}
      </Section>
      {import.meta.env.VITE_API_MOCK !== 'off' ? <TryProposal /> : null}
    </div>
  )
}
