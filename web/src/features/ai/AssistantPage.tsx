import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Card } from '@/components/common/Card'
import { Notice, PageHeader, Section } from '@/components/common/PageHeader'
import { KpiStrip, PageTabs, type PageTab } from '@/components/common/PageFrame'
import { AiBlock } from '@/components/common/AiBlock'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { EmptyState, ModuleOff, QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { BusyNote } from '@/components/common/BusyNote'
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
  const [q, setQ] = useState('') // held here: switching tabs unmounts a tab, and a half-typed question must survive a look at History
  const title = gate.state === 'off' ? t('page.titleOff')
    : gate.state === 'unconfigured' ? t(gate.text === 'keyLost' ? 'page.titleKeyLost' : 'page.titleUnconfigured')
      : u ? t('page.title', { used: fmtNumber(u.month.total), cap: fmtNumber(u.monthly_budget) }) : t('page.titleLoading')
  const tabs: PageTab[] = [{ id: 'ask', label: t('page.tabAsk'), panel: <Ask q={q} setQ={setQ} /> }]
  if (on) tabs.push({ id: 'history', label: t('page.tabHistory'), panel: <History /> })
  // AI not connected and never run: a 0/cap gauge and an empty log only add noise; the empty screen in the Ask tab already says what to do.
  // While loading the Usage tab is still there: the tab count changing 1 → 2 would rebuild the Ask tab and lose what the user is typing.
  if (gate.state !== 'off' && !(gate.state === 'unconfigured' && u && u.month.total === 0)) {
    tabs.push({ id: 'usage', label: t('page.tabUsage'), panel: <><Meter query={usage} renews={cfg.data?.renews_on} /><RunLog /><ActivityPanel /></> })
  }
  return (
    <>
      <PageHeader title={title} info={t('page.info')} meta={cfg.data?.configured ? t('page.meta', { tier: t(`settings.tier.${cfg.data.tier}.name`) }) : undefined} stories={['S-AI-4', 'S-AI-5', 'S-AI-6', 'S-AI-8']} />
      {/* S-UI-1: the meter is a KPI only when a person acts on it (80 % of the month's budget or more); below that the title already says it. */}
      {on && u && budgetPct(u.month.total, u.monthly_budget) >= 80 ? (
        <KpiStrip label={t('page.kpiLabel')} items={[{ value: `${fmtNumber(u.month.total)} / ${fmtNumber(u.monthly_budget)}`, label: t('page.kpiTokens'), to: '?tab=usage' }]} />
      ) : null}
      <PageTabs label={t('page.tabs')} tabs={tabs} />
    </>
  )
}

function Ask({ q, setQ }: { q: string; setQ: (v: string) => void }) {
  const { t } = useTranslation('ai')
  const gate = useAiGate('operator', 'ask-my-data')
  const ask = useAsk()
  const asks = useAsks(gate.state !== 'off' && gate.state !== 'loading')
  const result = ask.data ?? asks.data?.items[0] ?? null
  // A failed Ask is said where its answer would be, with the question, not above it with an older answer below.
  const failed = !ask.isPending && ask.error ? ask.error : null
  const long = q.length > ASK_MAX

  function run(text: string) {
    if (!text.trim() || text.length > ASK_MAX) return
    ask.mutate(text)
  }

  if (gate.state === 'off') return <Section title={t('ask.title')}><ModuleOff module="ai" /></Section>
  return (
    <Section title={t('ask.title')} description={t('ask.description')} info={t('ask.descriptionInfo')} stories={['S-AI-5']}>
      {gate.state === 'unconfigured' || gate.state === 'unassigned' ? (
        <EmptyState title={t(`gate.${gate.text}`)} info={t(`gate.${gate.text}Info`, { defaultValue: '' }) || undefined}>{t(`gate.${gate.text}Body`)} <ToSettings state={gate.text} job="ask-my-data" /></EmptyState>
      ) : (
        <div className="grid grid-cols-[minmax(0,1fr)] gap-4">
          <form className="grid grid-cols-[minmax(0,1fr)] gap-3" onSubmit={(e) => { e.preventDefault(); run(q) }}>
            <Field label={t('ask.label')} htmlFor="ai-q" hint={t('ask.hint')} info={t('ask.hintInfo')} error={long ? t('ask.tooLong', { max: ASK_MAX, n: q.length }) : undefined}>
              <div className="flex flex-wrap gap-2">
                <Input id="ai-q" className="min-w-0 flex-1 basis-72" value={q} onChange={(e) => setQ(e.target.value)} maxLength={ASK_MAX} placeholder={t('ask.placeholder')} disabled={!gate.canRun} aria-invalid={long ? true : undefined} aria-describedby={long ? 'ai-q-error' : q.length >= ASK_MAX * 0.8 ? 'ai-q-hint ai-q-count' : 'ai-q-hint'} />
                <Button type="submit" variant="primary" disabled={!gate.canRun || q.trim().length < 3 || long} busy={ask.isPending} busyLabel={t('common:busy.asking')} title={gate.reason}>{t('ask.submit')}</Button>
              </div>
            </Field>
            {q.length >= ASK_MAX * 0.8 && !long ? <p id="ai-q-count" className="-mt-2 text-caption text-muted">{t('ask.count', { n: q.length, max: ASK_MAX })}</p> : null}
            {/* Folded: one line to open the suggestions, so the page starts with the question box. */}
            <details className="group text-meta">
              <summary className="w-fit cursor-pointer text-muted hover:text-ink">{t('ask.suggested')}</summary>
              <div role="group" aria-label={t('ask.suggested')} className="mt-2 flex flex-wrap items-center gap-2">
                {SUGGESTED.map((k) => (
                  <Button key={k} size="sm" className="h-auto min-h-8 whitespace-normal py-1 text-left" disabled={!gate.canRun || ask.isPending} busy={ask.isPending && ask.variables === t(`ask.q.${k}`)} busyLabel={t('common:busy.asking')} title={gate.reason} onClick={() => { setQ(t(`ask.q.${k}`)); run(t(`ask.q.${k}`)) }}>{t(`ask.q.${k}`)}</Button>
                ))}
              </div>
            </details>
          </form>
          {/* A question can take up to two minutes (modules/ai askDefaultTimeout); say so while it runs */}
          <BusyNote busy={ask.isPending}>{t('ask.working')}</BusyNote>
          {failed ? (
            <div className="grid gap-2" role="region" aria-label={t('ask.answerFor', { q: ask.variables ?? '' })}>
              <p className="text-sm"><span className="text-muted">{t('ask.you')}</span> {ask.variables}</p>
              <p className="text-sm font-medium">{t('ask.failed')}</p>
              <ActionError error={failed} />
            </div>
          ) : null}
          {result && !ask.isPending && !failed ? <Answer r={result} /> : null}
          {!result && !ask.isPending && !failed ? <p className="text-sm text-muted">{t('ask.empty')}</p> : null}
        </div>
      )}
    </Section>
  )
}

/** Past questions, newest first, each opens with its answer; a text filter narrows the list (the box keeps the last few it answered). */
function History() {
  const { t } = useTranslation('ai')
  const gate = useAiGate('operator', 'ask-my-data')
  const asks = useAsks(gate.state !== 'off' && gate.state !== 'loading')
  const [filter, setFilter] = useState('')
  const [openId, setOpenId] = useState<string | null>(null)
  return (
    <Section title={t('history.title')} description={t('history.description')}>
      <QueryState query={asks}>
        {(d) => {
          const items = [...d.items].sort((a, b) => b.asked_at.localeCompare(a.asked_at))
          if (!items.length) return <p className="text-sm text-muted">{t('history.empty')}</p>
          const needle = filter.trim().toLowerCase()
          const rows = needle ? items.filter((a) => a.question.toLowerCase().includes(needle)) : items
          return (
            <div className="grid grid-cols-[minmax(0,1fr)] gap-3">
              <Field label={t('history.filter')} htmlFor="ai-history-filter">
                <Input id="ai-history-filter" type="search" value={filter} onChange={(e) => setFilter(e.target.value)} />
              </Field>
              {rows.length ? (
                <ul className="grid gap-2">
                  {rows.map((a) => {
                    const open = openId === a.id
                    return (
                      <li key={a.id} className="grid gap-3 rounded-md border border-rule p-2">
                        <button type="button" aria-expanded={open} className="flex flex-wrap items-baseline justify-between gap-x-3 text-left text-sm" onClick={() => setOpenId(open ? null : a.id)}>
                          <span className="font-medium">{a.question}</span><span className="text-meta text-muted">{fmtDateTime(a.asked_at)}</span>
                        </button>
                        {open ? <Answer r={a} /> : null}
                      </li>
                    )
                  })}
                </ul>
              ) : <p className="text-sm text-muted">{t('history.noMatch', { q: filter.trim() })}</p>}
            </div>
          )
        }}
      </QueryState>
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
        <Notice tone="warn" role="alert" className="mb-0" title={t(`ask.${refused}`)}>
          {r.answer.map((p, i) => <p key={i} className="text-ink">{p}</p>)}
        </Notice>
      ) : (
        <AiBlock model={`${r.model} (${r.profile})`} tokens={r.tokens} citations={r.citations}>
          {r.answer.map((p, i) => <p key={i}>{p}</p>)}
        </AiBlock>
      )}
      {r.memories_suggested > 0 ? <p className="text-meta">{t('logs.suggested', { count: r.memories_suggested })} {admin ? <Link to="/settings/ai?tab=memory" className="text-accent underline underline-offset-4">{t('logs.suggestedLink')}</Link> : null}</p> : null}
      {hooks.length ? (
        <Card level={3} title={t('ask.hooksTitle')} className="text-sm">
          <ul aria-label={t('ask.hooksTitle')} className="grid gap-1.5">
            {hooks.map((h, i) => <li key={i} className="flex flex-wrap items-center gap-2"><Chip tone={h.action === 'block' ? 'danger' : h.action === 'mask' ? 'warn' : 'accent'}>{t(`harness.hooks.action.${h.action}`)}</Chip><span className="font-medium">{h.name}</span><span className="text-muted">{t(`ask.step.${h.step}`, { tool: h.tool ?? '' })}</span><span className="text-muted">{h.message}</span></li>)}
          </ul>
          {blocked ? <p className="mt-2 text-meta text-muted">{t('ask.hooksHint')} {admin ? <Link to="/settings/ai?tab=hooks" className="text-accent underline underline-offset-4">{t('ask.hooksLink')}</Link> : null}</p> : null}
        </Card>
      ) : null}
      {r.table ? (
        <div>
          <h3 className="mb-1 text-sm font-medium">{t('ask.tableTitle', { n: r.table.rows.length })}</h3>
          <p className="mb-2 text-meta text-muted">{t('ask.tableNote')}</p>
          <DataTable urlKey="ask-answer" caption={t('ask.tableCaption', { q: r.question })} data={r.table.rows} columns={cols} pageSize={20} />
        </div>
      ) : null}
      {refused === 'refused' ? null : <Card level={3} title={t('ask.toolsTitle')}>
        <p className="mb-2 text-meta text-muted">{t('ask.toolsNote')}</p>
        <ul className="grid gap-1 text-meta">
          {r.tool_calls.map((c, i) => <li key={i} className="flex flex-wrap gap-x-2"><code className="font-mono text-meta">{c.tool}({c.args})</code><span className="text-muted">{t('ask.toolResult', { result: c.result })}</span></li>)}
        </ul>
      </Card>}
    </div>
  )
}

function Meter({ query, renews }: { query: { data: Usage | undefined; error: unknown; isPending: boolean; refetch: () => unknown }; renews: string | undefined }) {
  const { t } = useTranslation('ai')
  const admin = useCan('admin') // the budget is the administrator's (Settings, AI assistant)
  return (
    <Section title={t('meter.title')} description={t('meter.description')} info={<><p>{t('meter.callsNote')}</p><p>{t('meter.noDowngradesInfo')}</p></>} stories={['S-AI-4']}>
      <QueryState query={query}>
        {(u) => {
          // The bar is this month against the monthly budget (the box's count, rounded down like its 80 % and 100 % alerts)
          const pct = Math.min(100, budgetPct(u.month.total, u.monthly_budget))
          const date = fmtDate(renews)
          const tone = u.month.total >= u.monthly_budget ? 'bg-danger' : pct >= 80 ? 'bg-warn' : 'bg-accent'
          return (
            <div className="grid gap-5">
              <Card className="grid gap-3">
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                  <p className="text-sm">{t('meter.today', { used: fmtNumber(u.month.total), cap: fmtNumber(u.monthly_budget) })}</p>
                  <p className="text-meta text-muted">{t('meter.tier', { tier: t(`settings.tier.${u.tier}.name`) })}</p>
                </div>
                <div role="progressbar" aria-label={t('meter.barLabel')} aria-valuemin={0} aria-valuemax={u.monthly_budget} aria-valuenow={Math.min(u.month.total, u.monthly_budget)} aria-valuetext={t('meter.percent', { pct })} className="h-2 overflow-hidden rounded-full bg-sunken">
                  <div className={`h-full ${tone}`} style={{ width: `${pct}%` }} />
                </div>
                <p className="text-meta text-muted">{t('meter.split', { input: fmtNumber(u.today.input), output: fmtNumber(u.today.output), month: fmtNumber(u.month.total), date })}</p>
                {pct >= 80 ? <p className={`text-sm ${u.month.total >= u.monthly_budget ? 'text-danger' : 'text-warn'}`}>{u.month.total >= u.monthly_budget ? t('meter.over', { date }) : t('meter.near')}</p> : null}
                {pct >= 80 && admin ? <Link to="/settings/ai#ai-cap" className="text-sm font-medium text-accent underline underline-offset-4">{t('budget.home.raise')}</Link> : null}
              </Card>
              <DataTable urlKey="ai-usage-skills" caption={t('meter.skillCaption')} data={u.by_skill} pageSize={20}
                columns={[
                  { id: 'skill', header: t('meter.col.skill'), accessorFn: (r: Usage['by_skill'][number]) => t(`skill.${r.skill}`, { defaultValue: r.skill }) },
                  { id: 'runs', header: t('meter.col.runs'), accessorKey: 'runs' },
                  { id: 'tokens', header: t('meter.col.tokens'), accessorKey: 'tokens', cell: ({ getValue }: { getValue: () => unknown }) => fmtNumber(getValue() as number) },
                ]} empty={t('meter.skillEmpty')} />
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
    <Section title={t('runs.title')} description={t('runs.description')} info={t('runs.descriptionInfo')} stories={['S-AI-4']}>
      <QueryState query={runs}>
        {(r) => (
          <DataTable<AiRun> urlKey="ai-runs" caption={t('runs.caption')} data={r.items} filterPlaceholder={t('runs.filter')} initialSort={[{ id: 'ts', desc: true }]} empty={t('runs.empty')}
            columns={[
              { id: 'ts', header: t('runs.col.time'), accessorKey: 'ts', cell: ({ getValue }: { getValue: () => unknown }) => fmtDateTime(getValue() as string) },
              { id: 'skill', header: t('runs.col.skill'), accessorFn: (x: AiRun) => t(`skill.${x.skill}`, { defaultValue: x.skill }) },
              { id: 'target', header: t('runs.col.target'), accessorFn: (x: AiRun) => x.target ?? '–' },
              { id: 'profile', header: t('runs.col.profile'), accessorFn: (x: AiRun) => x.profile ?? '–', cell: ({ row }: { row: { original: AiRun } }) => <span className="grid"><span>{row.original.profile ?? '–'}</span>{row.original.fallback ? <span className="text-caption text-warn">{t('runs.fallback')}</span> : null}</span> },
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
