import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { PageHeader, Panel, Section } from '@/components/common/PageHeader'
import { KpiStrip, PageTabs, type PageTab } from '@/components/common/PageFrame'
import { AiBlock } from '@/components/common/AiBlock'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { EmptyState, ModuleOff, QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Field, Input } from '@/components/ui/input'
import { fmtDate, fmtDateTime, fmtNumber } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useAiConfig, useAsk, useAsks, useRuns, useUsage } from './api'
import ActivityPanel from './ActivityPanel'
import { ActionError, ToSettings, useAiGate } from './parts'
import { budgetPct } from './Budget'
import type { AiRun, AskResult, Usage } from './types'

// The box's limit for a question (modules/ai ask.go askQuestionMax; POST /ai/ask refuses longer with invalid_question).
const ASK_MAX = 500
const SUGGESTED = ['rdp', 'unapproved', 'confirmed', 'nas', 'camera', 'oldOs'] as const

export default function AssistantPage() {
  const { t } = useTranslation('ai')
  const gate = useAiGate('operator', 'ask-my-data')
  const on = gate.state !== 'off' && gate.state !== 'loading' // the module off: its routes are 404, nothing below is asked
  const usage = useUsage(on)
  const cfg = useAiConfig(on)
  const u = usage.data
  const title = gate.state === 'off' ? t('page.titleOff')
    : gate.state === 'unconfigured' ? t('page.titleUnconfigured')
      : u ? t('page.title', { used: fmtNumber(u.month.total), cap: fmtNumber(u.monthly_budget) }) : t('page.titleLoading')
  const tabs: PageTab[] = [{ id: 'ask', label: t('page.tabAsk'), panel: <Ask /> }]
  // Chưa nối AI và chưa từng chạy: đồng hồ 0/trần và nhật ký trống chỉ gây nhiễu; màn trống ở tab Ask đã nói việc cần làm.
  // Trong lúc tải vẫn có tab Usage: số tab đổi 1 → 2 sẽ dựng lại tab Ask và mất chữ người dùng đang gõ.
  if (gate.state !== 'off' && !(gate.state === 'unconfigured' && u && u.month.total === 0)) {
    tabs.push({ id: 'usage', label: t('page.tabUsage'), panel: <><Meter query={usage} renews={cfg.data?.renews_on} /><RunLog /><ActivityPanel /></> })
  }
  return (
    <>
      <PageHeader title={title} meta={cfg.data?.configured ? t('page.meta', { tier: t(`settings.tier.${cfg.data.tier}.name`) }) : undefined} stories={['S-AI-4', 'S-AI-5', 'S-AI-6', 'S-AI-8']} />
      {/* S-UI-1: the meter is a KPI only when a person acts on it (80 % of the month's budget or more); below that the title already says it. */}
      {on && u && budgetPct(u.month.total, u.monthly_budget) >= 80 ? (
        <KpiStrip label={t('page.kpiLabel')} items={[{ value: `${fmtNumber(u.month.total)} / ${fmtNumber(u.monthly_budget)}`, label: t('page.kpiTokens'), to: '?tab=usage' }]} />
      ) : null}
      <PageTabs label={t('page.tabs')} tabs={tabs} />
    </>
  )
}

function Ask() {
  const { t } = useTranslation('ai')
  const gate = useAiGate('operator', 'ask-my-data')
  const ask = useAsk()
  const asks = useAsks(gate.state !== 'off' && gate.state !== 'loading')
  const [q, setQ] = useState('')
  const [shown, setShown] = useState<AskResult | null>(null)
  const result = shown ?? ask.data ?? asks.data?.items[0] ?? null
  // A failed Ask is said where its answer would be, with the question, not above it with an older answer below (walk 3 G13).
  const failed = !shown && !ask.isPending && ask.error ? ask.error : null
  const long = q.length > ASK_MAX

  function run(text: string) {
    if (!text.trim() || text.length > ASK_MAX) return
    setShown(null)
    ask.mutate(text)
  }

  if (gate.state === 'off') return <Section title={t('ask.title')}><ModuleOff module="ai" /></Section>
  return (
    <Section title={t('ask.title')} description={t('ask.description')} stories={['S-AI-5']}>
      {gate.state === 'unconfigured' || gate.state === 'unassigned' ? (
        <EmptyState title={t(`gate.${gate.state}`)}>{t(`gate.${gate.state}Body`)} <ToSettings /></EmptyState>
      ) : (
        <div className="grid grid-cols-[minmax(0,1fr)] gap-4">
          <form className="grid grid-cols-[minmax(0,1fr)] gap-3" onSubmit={(e) => { e.preventDefault(); run(q) }}>
            <Field label={t('ask.label')} htmlFor="ai-q" hint={t('ask.hint')} error={long ? t('ask.tooLong', { max: ASK_MAX, n: q.length }) : undefined}>
              <div className="flex flex-wrap gap-2">
                <Input id="ai-q" className="min-w-0 flex-1 basis-72" value={q} onChange={(e) => setQ(e.target.value)} maxLength={ASK_MAX} placeholder={t('ask.placeholder')} disabled={!gate.canRun} aria-invalid={long ? true : undefined} aria-describedby={long ? 'ai-q-error' : q.length >= ASK_MAX * 0.8 ? 'ai-q-hint ai-q-count' : 'ai-q-hint'} />
                <Button type="submit" variant="primary" disabled={!gate.canRun || ask.isPending || q.trim().length < 3 || long} title={gate.reason}>{ask.isPending ? t('ask.asking') : t('ask.submit')}</Button>
              </div>
            </Field>
            {q.length >= ASK_MAX * 0.8 && !long ? <p id="ai-q-count" className="-mt-2 text-[12px] text-muted">{t('ask.count', { n: q.length, max: ASK_MAX })}</p> : null}
            <div role="group" aria-label={t('ask.suggested')} className="flex flex-wrap items-center gap-2">
              <span className="text-[13px] text-muted">{t('ask.suggested')}</span>
              {SUGGESTED.map((k) => (
                <Button key={k} size="sm" className="h-auto min-h-8 whitespace-normal py-1 text-left" disabled={!gate.canRun || ask.isPending} title={gate.reason} onClick={() => { setQ(t(`ask.q.${k}`)); run(t(`ask.q.${k}`)) }}>{t(`ask.q.${k}`)}</Button>
              ))}
            </div>
          </form>
          {ask.isPending ? <p role="status" className="text-sm text-muted">{t('ask.working')}</p> : null}
          {failed ? (
            <div className="grid gap-2" role="region" aria-label={t('ask.answerFor', { q: ask.variables ?? '' })}>
              <p className="text-sm"><span className="text-muted">{t('ask.you')}</span> {ask.variables}</p>
              <p className="text-sm font-medium">{t('ask.failed')}</p>
              <ActionError error={failed} />
            </div>
          ) : null}
          {result && !ask.isPending && !failed ? <Answer r={result} /> : null}
          {!result && !ask.isPending && !failed ? <p className="text-sm text-muted">{t('ask.empty')}</p> : null}
          {asks.data && asks.data.items.length > 1 ? (
            <div className="text-[13px]">
              <p className="mb-1 text-muted">{t('ask.history')}</p>
              <ul className="flex flex-wrap gap-2">
                {asks.data.items.map((a) => <li key={a.id}><button type="button" className="rounded-md border border-rule px-2 py-1 text-left hover:bg-sunken" onClick={() => setShown(a)}>{a.question}</button></li>)}
              </ul>
            </div>
          ) : null}
        </div>
      )}
    </Section>
  )
}

function Answer({ r }: { r: AskResult }) {
  const { t } = useTranslation('ai')
  const admin = useCan('admin') // the Memory tab is the administrator's (S-AI-7)
  const cols: ColumnDef<{ href?: string; cells: string[] }>[] = (r.table?.columns ?? []).map((c, i) => ({
    id: `c${i}`, header: c, accessorFn: (row: { cells: string[] }) => row.cells[i] ?? '',
    cell: ({ row }: { row: { original: { href?: string; cells: string[] } } }) => (i === 0 && row.original.href ? <Link to={row.original.href} className="text-accent underline-offset-4 hover:underline">{row.original.cells[0]}</Link> : row.original.cells[i]),
  }))
  const hooks = r.hooks ?? []
  // Only a stopped question means the AI was not asked; a stopped answer means it answered and the answer was held back. A tool result
  // a hook held back is not either: the AI answered without it (beta 0.1.0-beta.1 item 19).
  const stopped = (step: string) => hooks.some((h) => h.step === step && h.action !== 'mask')
  const refused = stopped('question') ? 'refused' : stopped('answer') ? 'answerHeld' : null
  const blocked = hooks.some((h) => h.action !== 'mask')
  return (
    <div className="grid gap-4" aria-label={t('ask.answerFor', { q: r.question })} role="region">
      <p className="text-sm"><span className="text-muted">{t('ask.you')}</span> {r.question}</p>
      {refused ? (
        <div role="alert" className="rounded-md border border-warn/50 bg-warn-soft px-4 py-3 text-sm">
          <p className="mb-1 font-medium">{t(`ask.${refused}`)}</p>
          {r.answer.map((p, i) => <p key={i}>{p}</p>)}
        </div>
      ) : (
        <AiBlock model={`${r.model} (${r.profile})`} tokens={r.tokens} citations={r.citations}>
          {r.answer.map((p, i) => <p key={i}>{p}</p>)}
        </AiBlock>
      )}
      {r.memories_suggested > 0 ? <p className="text-[13px]">{t('logs.suggested', { count: r.memories_suggested })} {admin ? <Link to="/settings/ai?tab=memory" className="text-accent underline underline-offset-4">{t('logs.suggestedLink')}</Link> : null}</p> : null}
      {hooks.length ? (
        <div className="rounded-md border border-rule bg-surface p-3 text-sm">
          <h3 className="mb-1 text-sm font-medium">{t('ask.hooksTitle')}</h3>
          <ul aria-label={t('ask.hooksTitle')} className="grid gap-1.5">
            {hooks.map((h, i) => <li key={i} className="flex flex-wrap items-center gap-2"><Chip tone={h.action === 'block' ? 'danger' : h.action === 'mask' ? 'warn' : 'accent'}>{t(`harness.hooks.action.${h.action}`)}</Chip><span className="font-medium">{h.name}</span><span className="text-muted">{t(`ask.step.${h.step}`, { tool: h.tool ?? '' })}</span><span className="text-muted">{h.message}</span></li>)}
          </ul>
          {blocked ? <p className="mt-2 text-[13px] text-muted">{t('ask.hooksHint')} {admin ? <Link to="/settings/ai?tab=hooks" className="text-accent underline underline-offset-4">{t('ask.hooksLink')}</Link> : null}</p> : null}
        </div>
      ) : null}
      {r.table ? (
        <div>
          <h3 className="mb-1 text-sm font-medium">{t('ask.tableTitle', { n: r.table.rows.length })}</h3>
          <p className="mb-2 text-[13px] text-muted">{t('ask.tableNote')}</p>
          <DataTable caption={t('ask.tableCaption', { q: r.question })} data={r.table.rows} columns={cols} pageSize={20} />
        </div>
      ) : null}
      {refused === 'refused' ? null : <div>
        <h3 className="mb-1 text-sm font-medium">{t('ask.toolsTitle')}</h3>
        <p className="mb-2 text-[13px] text-muted">{t('ask.toolsNote')}</p>
        <ul className="grid gap-1 rounded-md border border-rule bg-surface p-3 text-[13px]">
          {r.tool_calls.map((c, i) => <li key={i} className="flex flex-wrap gap-x-2"><code className="font-mono text-[12.5px]">{c.tool}({c.args})</code><span className="text-muted">{t('ask.toolResult', { result: c.result })}</span></li>)}
        </ul>
      </div>}
    </div>
  )
}

function Meter({ query, renews }: { query: { data: Usage | undefined; error: unknown; isPending: boolean; refetch: () => unknown }; renews: string | undefined }) {
  const { t } = useTranslation('ai')
  return (
    <Section title={t('meter.title')} description={t('meter.description')} stories={['S-AI-4']}>
      <QueryState query={query}>
        {(u) => {
          // D-531: the bar is this month against the monthly budget (the box's count, rounded down like its 80 % and 100 % alerts)
          const pct = Math.min(100, budgetPct(u.month.total, u.monthly_budget))
          const date = fmtDate(renews)
          const tone = u.month.total >= u.monthly_budget ? 'bg-danger' : pct >= 80 ? 'bg-warn' : 'bg-accent'
          return (
            <div className="grid gap-5">
              <Panel className="grid gap-3 p-4">
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                  <p className="text-sm">{t('meter.today', { used: fmtNumber(u.month.total), cap: fmtNumber(u.monthly_budget) })}</p>
                  <p className="text-[13px] text-muted">{t('meter.tier', { tier: t(`settings.tier.${u.tier}.name`) })}</p>
                </div>
                <div role="progressbar" aria-label={t('meter.barLabel')} aria-valuemin={0} aria-valuemax={u.monthly_budget} aria-valuenow={Math.min(u.month.total, u.monthly_budget)} aria-valuetext={t('meter.percent', { pct })} className="h-2 overflow-hidden rounded-full bg-sunken">
                  <div className={`h-full ${tone}`} style={{ width: `${pct}%` }} />
                </div>
                <p className="text-[13px] text-muted">{t('meter.split', { input: fmtNumber(u.today.input), output: fmtNumber(u.today.output), month: fmtNumber(u.month.total), date })}</p>
                {pct >= 80 ? <p className={`text-sm ${u.month.total >= u.monthly_budget ? 'text-danger' : 'text-warn'}`}>{u.month.total >= u.monthly_budget ? t('meter.over', { date }) : t('meter.near')}</p> : null}
              </Panel>
              <DataTable caption={t('meter.skillCaption')} data={u.by_skill} pageSize={20}
                columns={[
                  { id: 'skill', header: t('meter.col.skill'), accessorFn: (r: Usage['by_skill'][number]) => t(`skill.${r.skill}`, { defaultValue: r.skill }) },
                  { id: 'runs', header: t('meter.col.runs'), accessorKey: 'runs' },
                  { id: 'tokens', header: t('meter.col.tokens'), accessorKey: 'tokens', cell: ({ getValue }: { getValue: () => unknown }) => fmtNumber(getValue() as number) },
                ]} empty={t('meter.skillEmpty')} />
              {u.by_skill.length ? <p className="-mt-3 text-[13px] text-muted">{t('meter.callsNote')}</p> : null}
              <div>
                <h3 className="mb-1 text-sm font-medium">{t('meter.downgrades')}</h3>
                {u.downgrades.length === 0 ? <p className="text-sm text-muted">{t('meter.noDowngrades')}</p> : (
                  <ul className="grid gap-1 text-sm">
                    {u.downgrades.map((d) => <li key={d.id}>{t('meter.downgrade', { time: fmtDateTime(d.ts), from: t(`settings.tier.${d.from}.name`), to: t(`settings.tier.${d.to}.name`), reason: d.reason })}</li>)}
                  </ul>
                )}
              </div>
            </div>
          )
        }}
      </QueryState>
    </Section>
  )
}

function RunLog() {
  const { t } = useTranslation('ai')
  const runs = useRuns()
  const statusTone = { ok: 'ok', schema_error: 'warn', capped: 'warn', failed: 'danger' } as const
  const num = ({ getValue }: { getValue: () => unknown }) => fmtNumber(getValue() as number)
  return (
    <Section title={t('runs.title')} description={t('runs.description')} stories={['S-AI-4']}>
      <QueryState query={runs}>
        {(r) => (
          <DataTable<AiRun> caption={t('runs.caption')} data={r.items} filterPlaceholder={t('runs.filter')} initialSort={[{ id: 'ts', desc: true }]} empty={t('runs.empty')}
            columns={[
              { id: 'ts', header: t('runs.col.time'), accessorKey: 'ts', cell: ({ getValue }: { getValue: () => unknown }) => fmtDateTime(getValue() as string) },
              { id: 'skill', header: t('runs.col.skill'), accessorFn: (x: AiRun) => t(`skill.${x.skill}`, { defaultValue: x.skill }) },
              { id: 'target', header: t('runs.col.target'), accessorFn: (x: AiRun) => x.target ?? '–' },
              { id: 'profile', header: t('runs.col.profile'), accessorFn: (x: AiRun) => x.profile ?? '–', cell: ({ row }: { row: { original: AiRun } }) => <span className="grid"><span>{row.original.profile ?? '–'}</span>{row.original.fallback ? <span className="text-[12px] text-warn">{t('runs.fallback')}</span> : null}</span> },
              { id: 'model', header: t('runs.col.model'), accessorKey: 'model', cell: ({ getValue }: { getValue: () => unknown }) => <span className="whitespace-nowrap">{String(getValue())}</span> },
              { id: 'tin', header: t('runs.col.in'), accessorKey: 'tokens_in', cell: num },
              { id: 'tout', header: t('runs.col.out'), accessorKey: 'tokens_out', cell: num },
              { id: 'status', header: t('runs.col.status'), accessorKey: 'status', cell: ({ row }: { row: { original: AiRun } }) => <Chip tone={statusTone[row.original.status]}>{t(`runs.status.${row.original.status}`)}</Chip> },
            ]} />
        )}
      </QueryState>
    </Section>
  )
}
