import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Section } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { QueryState } from '@/components/common/States'
import { Chip, type Tone } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent } from '@/components/ui/dialog'
import { Field, Select, Input } from '@/components/ui/input'
import { fmtDateTime, fmtNumber } from '@/lib/format'
import { useActivity, useVerifyChain, type ActivityFilter } from './api'
import type { ActivityEntry, ActivityResult } from './types'

const RESULTS: ActivityResult[] = ['ok', 'blocked_by_hook', 'fallback_used', 'error']
const TONE: Record<ActivityResult, Tone> = { ok: 'ok', blocked_by_hook: 'warn', fallback_used: 'accent', error: 'danger' }
const JOBS = ['ask-my-data', 'explain-finding', 'cve-news', 'log-digest', 'log-investigate', 'mitigation-config', 'weekly-report', 'pdpl-assessment', 'translate-advisory', 'response-plan', 'connection-test']
// a proposal and a request are both in the inbox (D-513), named so the link does not depend on which tab opens first
const LINK_TO: Record<string, string> = { proposal: '/response?tab=requests', action: '/response?tab=requests' }

/** Assistant, Activity (S-AI-8): everything the AI did, newest first. Read only; the chain check shows whether anything was changed. */
export default function ActivityPanel() {
  const { t } = useTranslation('ai')
  const [f, setF] = useState<ActivityFilter>({ job: '', result: '', from: '', to: '' })
  const [open, setOpen] = useState<ActivityEntry | null>(null)
  const list = useActivity(f)
  const verify = useVerifyChain()
  const v = verify.data
  const job = (j: string) => t(`skill.${j}`, { defaultValue: j })
  const cols: ColumnDef<ActivityEntry>[] = [
    { id: 'ts', header: t('activity.col.time'), accessorKey: 'ts', cell: ({ getValue }) => fmtDateTime(getValue() as string) },
    { id: 'job', header: t('activity.col.job'), accessorFn: (e) => job(e.job) },
    { id: 'trigger', header: t('activity.col.trigger'), accessorKey: 'trigger' },
    { id: 'model', header: t('activity.col.model'), accessorFn: (e) => (e.model ? `${e.model} (${e.profile})` : '–') },
    { id: 'tokens', header: t('activity.col.tokens'), accessorFn: (e) => e.tokens_in + e.tokens_out, cell: ({ getValue }) => fmtNumber(getValue() as number) },
    { id: 'result', header: t('activity.col.result'), accessorKey: 'result', cell: ({ row }) => <Chip tone={TONE[row.original.result]}>{t(`activity.result.${row.original.result}`)}</Chip> },
    { id: 'open', header: t('activity.col.details'), enableSorting: false, cell: ({ row }) => <Button size="sm" onClick={() => setOpen(row.original)} aria-label={t('activity.openFor', { job: job(row.original.job), time: fmtDateTime(row.original.ts) })}>{t('activity.open')}</Button> },
  ]
  return (
    <Section title={t('activity.title')} description={t('activity.description')} stories={['S-AI-8']}>
      <div className="grid gap-4">
        <p role="status" className={`rounded-md border px-3 py-2 text-sm ${v && !v.ok ? 'border-danger/50 bg-danger-soft' : 'border-rule bg-surface'}`}>
          {!v ? t('activity.verifying') : v.ok ? t('activity.verified', { n: fmtNumber(v.count) }) : t('activity.broken', { n: v.broken_at })}
        </p>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Field label={t('activity.filter.job')} htmlFor="act-job">
            <Select id="act-job" value={f.job} onChange={(e) => setF({ ...f, job: e.target.value })}>
              <option value="">{t('activity.filter.any')}</option>
              {JOBS.map((j) => <option key={j} value={j}>{job(j)}</option>)}
            </Select>
          </Field>
          <Field label={t('activity.filter.result')} htmlFor="act-result">
            <Select id="act-result" value={f.result} onChange={(e) => setF({ ...f, result: e.target.value as ActivityResult | '' })}>
              <option value="">{t('activity.filter.any')}</option>
              {RESULTS.map((r) => <option key={r} value={r}>{t(`activity.result.${r}`)}</option>)}
            </Select>
          </Field>
          <Field label={t('activity.filter.from')} htmlFor="act-from"><Input id="act-from" type="date" value={f.from} onChange={(e) => setF({ ...f, from: e.target.value })} /></Field>
          <Field label={t('activity.filter.to')} htmlFor="act-to"><Input id="act-to" type="date" value={f.to} onChange={(e) => setF({ ...f, to: e.target.value })} /></Field>
        </div>
        <QueryState query={list}>
          {(r) => <DataTable<ActivityEntry> caption={t('activity.caption')} data={r.items} columns={cols} initialSort={[{ id: 'ts', desc: true }]} empty={t('activity.empty')} pageSize={20} />}
        </QueryState>
        <p className="text-[13px] text-muted">{t('activity.readOnly', { days: list.data?.retention_days ?? 365 })}</p>
      </div>
      <Dialog open={!!open} onOpenChange={(o) => { if (!o) setOpen(null) }}>
        {open ? <Detail e={open} job={job(open.job)} /> : null}
      </Dialog>
    </Section>
  )
}

function Detail({ e, job }: { e: ActivityEntry; job: string }) {
  const { t } = useTranslation('ai')
  const row = (k: string, v: React.ReactNode) => <div className="grid gap-0.5 sm:grid-cols-[9rem_minmax(0,1fr)]"><dt className="text-muted">{k}</dt><dd className="min-w-0 break-words">{v}</dd></div>
  const mono = (s: string) => <code className="break-all font-mono text-[12px]">{s}</code>
  return (
    <DialogContent wide title={t('activity.detail.title', { job })} description={fmtDateTime(e.ts)}>
      <dl className="grid gap-2 text-sm">
        {row(t('activity.col.result'), <Chip tone={TONE[e.result]}>{t(`activity.result.${e.result}`)}</Chip>)}
        {row(t('activity.detail.summary'), e.summary)}
        {row(t('activity.col.trigger'), e.trigger)}
        {row(t('activity.col.model'), e.model ? `${e.model} (${e.profile})` : '–')}
        {row(t('activity.detail.tokens'), t('activity.detail.tokensBody', { in: fmtNumber(e.tokens_in), out: fmtNumber(e.tokens_out) }))}
        {row(t('activity.detail.hooks'), e.hooks.length ? e.hooks.join(', ') : t('activity.detail.none'))}
        {row(t('activity.detail.tools'), e.tools.length ? <ul className="grid gap-1">{e.tools.map((x, i) => <li key={i}><Chip tone={x.access === 'write' ? 'warn' : 'off'}>{t(`activity.access.${x.access}`)}</Chip> {mono(`${x.name}(${x.args})`)}</li>)}</ul> : t('activity.detail.none'))}
        {row(t('activity.detail.links'), e.links?.length ? <ul className="grid gap-1">{e.links.map((l) => <li key={l.id}><Link className="text-accent underline underline-offset-4" to={LINK_TO[l.kind] ?? '/response'}>{t(`activity.link.${l.kind}`)} {l.id}</Link></li>)}</ul> : t('activity.detail.none'))}
        {row(t('activity.detail.inHash'), mono(e.input_hash))}
        {row(t('activity.detail.outHash'), mono(e.output_hash))}
        {row(t('activity.detail.prev'), mono(e.prev_hash))}
        {row(t('activity.detail.hash'), mono(e.hash))}
      </dl>
      <p className="text-[13px] text-muted">{t('activity.detail.note')}</p>
    </DialogContent>
  )
}
